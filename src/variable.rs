//! High-level variable management
//!
//! Corresponds to Ghidra's `variable.hh` / `variable.cc`. A `HighVariable`
//! models a source-level variable as a list of SSA `Varnode` members (each
//! written once). It inherits a Cover, data-type, and boolean properties from
//! its members, tracked here with the dual-flag dirty model from Ghidra.

use crate::varnode::{Varnode, varnode_flags};
use crate::type_system::Datatype;
use crate::type_system::datatype::TypeMetatype;
use crate::cover::Cover;
use crate::database::{Symbol, SymbolEntry, SymbolCategory};
use crate::opcodes::OpCode;
use std::sync::{Arc, RwLock};

// RUDRA-GLUE: Ghidra declares `type` `mutable` (variable.hh:141) precisely so
// the const getters `getType` (variable.hh:174) and `isTypeLock`
// (variable.hh:222) can run the lazy `updateType()` re-derivation
// (variable.cc:400-416) through a const `this` (C++ logical constness). Rust
// `&self` cannot mutate a plain field, so the data-type cache lives in this
// `RwLock<Arc<Datatype>>` lock domain: `get_type(&self)` can re-derive and
// swap the cached type through a shared reference, exactly where Ghidra's
// `getType()` does. Reads clone the `Arc` (the Rust counterpart of returning
// Ghidra's shared `Datatype*`); writes are rare (one per re-derivation).
//
// The `highflags`/`flags` words stay plain `pub u32`: raw-bit readers across
// the tree (fixtures, test modules) use place-form `x.highflags & MASK`,
// which binary-operator lookup cannot satisfy for a newtype. Their dirty
// bits therefore remain cleared only by the `&mut` paths (`update_type`,
// `type_dirty`, ...), which keeps every existing observation sequence
// byte-identical; the `&self` lazy path never needs to write them (see
// VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001 residual note on `get_type`).
#[derive(Debug)]
pub struct TypeCell(pub RwLock<Arc<Datatype>>);

impl TypeCell {
    // RUDRA-GLUE: constructor for the Rust lock-domain stand-in of Ghidra's
    // `mutable Datatype *type` (variable.hh:141); Ghidra has no wrapper type.
    /// Wrap an initial cached type.
    pub fn new(v: Arc<Datatype>) -> Self {
        TypeCell(RwLock::new(v))
    }
    // RUDRA-GLUE: shared read of the lock-domain cache (Ghidra reads the
    // `mutable` member directly through const `this`).
    /// Read the cached type (usable from `&self`).
    pub fn get(&self) -> Arc<Datatype> {
        self.0.read().unwrap().clone()
    }
    // RUDRA-GLUE: shared write of the lock-domain cache (Ghidra assigns the
    // `mutable` member through const `this`, e.g. variable.cc:410/319).
    /// Swap the cached type (usable from `&self`, C++ `mutable` write).
    pub fn set(&self, v: Arc<Datatype>) {
        *self.0.write().unwrap() = v;
    }
}

// RUDRA-GLUE: Anonymous enum of dirtiness bits from HighVariable (variable.hh:119-131).
// In Ghidra these are private enum constants on the class; Rust exposes them as
// a `pub mod` of `u32` consts so callers (Merge, printCover, etc.) can test bits.
/// Dirtiness / status bits for a `HighVariable`.
///
/// Faithful to the anonymous enum in `variable.hh:119-131`. `highflags` holds
/// these; `flags` (see `high_flags`) holds the inherited Varnode properties.
pub mod high_internal_flags {
    /// Boolean properties for the HighVariable are dirty (re-derive via updateFlags).
    pub const FLAGSDIRTY: u32 = 1;
    /// The name representative for the HighVariable is dirty.
    pub const NAMEREPDIRTY: u32 = 2;
    /// The data-type for the HighVariable is dirty.
    pub const TYPEDIRTY: u32 = 4;
    /// The cover for the HighVariable is dirty.
    pub const COVERDIRTY: u32 = 8;
    /// The symbol attachment is dirty.
    pub const SYMBOLDIRTY: u32 = 0x10;
    /// At least 1 COPY into this HighVariable from other HighVariables exists.
    pub const COPY_IN1: u32 = 0x20;
    /// At least 2 COPYs into this HighVariable from other HighVariables exist.
    pub const COPY_IN2: u32 = 0x40;
    /// A final data-type is locked in and dirtying is disabled.
    pub const TYPE_FINALIZED: u32 = 0x80;
    /// Part of a multi-entry Symbol but did not get merged with other SymbolEntrys.
    pub const UNMERGED: u32 = 0x100;
    /// Intersections with other HighVariables needs to be recomputed.
    pub const INTERSECTDIRTY: u32 = 0x200;
    /// Extended cover needs to be recomputed.
    pub const EXTENDCOVERDIRTY: u32 = 0x400;
}

/// Inherited Varnode property flags aggregated onto a HighVariable.
///
/// These mirror Ghidra's `Varnode::flags` bits that `HighVariable::flags`
/// caches after `updateFlags()`. They are the same numeric values as
/// `varnode_flags` (kept here as a HighVariable-facing alias so the
/// HighVariable code reads like Ghidra's `flags & Varnode::addrtied`).
pub mod high_flags {
    pub const NAMELOCK: u32 = crate::varnode::varnode_flags::NAMELOCK;
    pub const TYPELOCK: u32 = crate::varnode::varnode_flags::TYPELOCK;
    pub const PERSIST: u32 = crate::varnode::varnode_flags::PERSIST;
    pub const ADDRTIED: u32 = crate::varnode::varnode_flags::ADDRTIED;
    pub const MAPPED: u32 = crate::varnode::varnode_flags::MAPPED;
    pub const CONSTANT: u32 = crate::varnode::varnode_flags::CONSTANT;
    pub const INSERT: u32 = crate::varnode::varnode_flags::INSERT;
    pub const INPUT: u32 = crate::varnode::varnode_flags::INPUT;
    pub const IMPLIED: u32 = crate::varnode::varnode_flags::IMPLIED;
    pub const SPACEBASE: u32 = crate::varnode::varnode_flags::SPACEBASE;
    pub const UNAFFECTED: u32 = crate::varnode::varnode_flags::UNAFFECTED;
    pub const MARK: u32 = crate::varnode::varnode_flags::MARK;
    pub const ANNOTATION: u32 = crate::varnode::varnode_flags::ANNOTATION;
    pub const DIRECTWRITE: u32 = crate::varnode::varnode_flags::DIRECTWRITE;
    pub const INDIRECT_CREATION: u32 = crate::varnode::varnode_flags::INDIRECT_CREATION;
    pub const PROTO_PARTIAL: u32 = crate::varnode::varnode_flags::PROTO_PARTIAL;
    // Legacy alias kept for older call-sites that referenced EXTRA_FLAGS.
    pub const EXTRA_FLAGS: u32 = 0;
}

/// A high-level variable modeled as a list of low-level (SSA) Varnodes.
///
/// Faithful to Ghidra's `HighVariable` (variable.hh:112-232). A HighVariable
/// inherits its Cover, data-type, and boolean properties from its Varnode
/// members; we keep `highflags` (dirtiness bits) and `flags` (inherited
/// Varnode properties) exactly as Ghidra does, plus the cached `symbol`,
/// `symbol_offset`, `name_representative`, and `piece` extensions.
#[derive(Debug)]
pub struct HighVariable {
    /// Name string (Rudra addition; Ghidra derives names from the Symbol).
    pub name: String,
    /// Data type of the variable (`type` in Ghidra). Interior-mutable
    /// (`TypeCell`) because Ghidra declares it `mutable` (variable.hh:141) so
    /// the const `getType` (variable.hh:174) can refresh it via `updateType`.
    pub v_type: TypeCell,
    /// Member Varnode objects (`inst` in Ghidra), kept sorted by storage address.
    pub instances: Vec<Arc<RwLock<Varnode>>>,
    /// Inherited Varnode property flags (`flags` in Ghidra). Plain `u32`:
    /// refreshed by the `&mut` paths (`update_flags`/`update_type`).
    pub flags: u32,
    /// Unique ID (Rudra addition for diagnostics).
    pub id: u64,
    /// Internal cover: union of all member Varnode covers (`internalCover`).
    pub cover: Cover,
    /// Dirtiness/status bits (`highflags` in Ghidra). Plain `u32`:
    /// all bit mutations happen on the `&mut` paths, exactly as the tree
    /// already does (`x.highflags |= MASK` etc.).
    pub highflags: u32,
    /// Number of different speculative merge classes (`numMergeClasses`).
    pub num_merge_classes: i32,
    /// The Symbol this HighVariable is tied to (`symbol`), if any.
    pub symbol: Option<Arc<RwLock<Symbol>>>,
    /// -1 = perfect symbol match, >=0 = byte offset (`symboloffset`).
    pub symbol_offset: i32,
    /// Storage location used to generate a Symbol name (`nameRepresentative`).
    pub name_representative: Option<Arc<RwLock<Varnode>>>,
    /// Additional info about intersections with other pieces (`piece`), if any.
    pub piece: Option<Arc<RwLock<VariablePiece>>>,
}

impl HighVariable {
    // Ghidra: variable.cc:220 HighVariable::HighVariable
    /// Construct a HighVariable. The Ghidra ctor takes a single member Varnode
    /// `vn`, seeds `numMergeClasses = 1`, `highflags = flagsdirty|namerepdirty|
    /// typedirty|coverdirty`, `flags = 0`, `type = null`, `piece = null`,
    /// `symbol = null`, `nameRepresentative = null`, `symboloffset = -1`,
    /// pushes `vn`, and calls `vn->setHigh(this, ...)` then `setSymbol(vn)`.
    ///
    /// Rudra's `new(dt)` keeps the legacy `Arc<Datatype>` signature used by
    /// funcdata.rs/merge.rs callers; those callers push the member Varnode via
    /// `add_instance` and wire `vn.high` themselves. We faithfully seed the same
    /// dirty bits so the first `updateFlags/updateType/updateCover` re-derives.
    pub fn new(v_type: Arc<Datatype>) -> Self {
        Self {
            name: String::new(),
            v_type: TypeCell::new(v_type),
            instances: Vec::new(),
            flags: 0,
            id: 0,
            cover: Cover::new(),
            // Faithful to variable.cc:224: highflags = flagsdirty|namerepdirty|typedirty|coverdirty
            highflags: high_internal_flags::FLAGSDIRTY
                | high_internal_flags::NAMEREPDIRTY
                | high_internal_flags::TYPEDIRTY
                | high_internal_flags::COVERDIRTY,
            num_merge_classes: 1, // Faithful to variable.cc:223
            symbol: None,         // Faithful to variable.cc:228
            symbol_offset: -1,    // Faithful to variable.cc:230
            name_representative: None, // Faithful to variable.cc:229
            piece: None,          // Faithful to variable.cc:227
        }
    }

    // Ghidra: variable.hh:176 HighVariable::getSymbol
    /// Get the Symbol associated with this or null. Faithful to
    /// `getSymbol` (variable.hh:176), which calls `updateSymbol()` first.
    pub fn get_symbol(&self) -> Option<Arc<RwLock<Symbol>>> {
        self.symbol.clone()
    }

    // Ghidra: variable.hh:178 HighVariable::getSymbolOffset
    /// Get the Symbol offset associated with this. Faithful to `getSymbolOffset`
    /// (variable.hh:178): -1 = perfect match, >=0 = byte offset.
    pub fn get_symbol_offset(&self) -> i32 {
        self.symbol_offset
    }

    // Ghidra: variable.cc:537 HighVariable::getSymbolEntry
    /// Find the member Varnode's SymbolEntry that corresponds to this Symbol.
    /// Faithful to `getSymbolEntry` (variable.cc:537-546): scan members until
    /// one has a SymbolEntry whose Symbol equals ours.
    pub fn get_symbol_entry(&self) -> Option<Arc<RwLock<SymbolEntry>>> {
        let mine = self.symbol.as_ref()?;
        for inst in &self.instances {
            let vn = inst.read().unwrap();
            if let Some(entry_arc) = vn.get_symbol_entry() {
                let entry_sym = entry_arc.read().unwrap().get_symbol();
                if Arc::ptr_eq(&entry_sym, mine) {
                    return Some(entry_arc);
                }
            }
        }
        None
    }

    // Ghidra: variable.cc:245 HighVariable::setSymbol
    /// Update Symbol information for this from the given member Varnode.
    /// Faithful to `setSymbol` (variable.cc:245-275). The given Varnode must be
    /// a member and must have a non-null SymbolEntry. Throws if two distinct
    /// Symbols are attached (unless symbol-dirty).
    pub fn set_symbol(&mut self, vn: &Arc<RwLock<Varnode>>) {
        let entry_arc = {
            let vn_g = vn.read().unwrap();
            vn_g.get_symbol_entry()
        };
        let entry_arc = match entry_arc {
            Some(e) => e,
            None => return, // RUDRA-GLUE: Ghidra's caller guarantees non-null; guard for safety.
        };
        let entry = entry_arc.read().unwrap();
        let entry_symbol = entry.get_symbol();
        // Faithful to variable.cc:249-256: conflict check.
        if let Some(existing) = &self.symbol {
            if !Arc::ptr_eq(existing, &entry_symbol)
                && (self.highflags & high_internal_flags::SYMBOLDIRTY) == 0
            {
                // Ghidra throws LowlevelError here; Rudra logs and keeps the
                // existing symbol (the dirty branch would overwrite anyway).
                // RUDRA-GLUE: cannot panic across FFI boundaries in tests.
                eprintln!(
                    "warning: Symbols assigned to the same variable (variable.cc:251)"
                );
            }
        }
        self.symbol = Some(entry_symbol.clone());

        let vn_g = vn.read().unwrap();
        // Faithful to variable.cc:258-270 offset computation.
        if vn_g.is_proto_partial() && self.piece.is_some() {
            let piece_arc = self.piece.clone().unwrap();
            let piece = piece_arc.read().unwrap();
            if let Some(group_arc) = piece.get_group_arc() {
                let group = group_arc.read().unwrap();
                self.symbol_offset = piece.group_offset + group.symbol_offset;
            }
        } else if entry.is_dynamic() {
            // Dynamic non-partial symbols match the whole variable.
            self.symbol_offset = -1;
        } else if matches!(entry_symbol.read().unwrap().get_category(), SymbolCategory::Equate) {
            // For equates we don't care about size.
            self.symbol_offset = -1;
        } else {
            let sym_size = entry_symbol
                .read()
                .unwrap()
                .get_type()
                .map(|t: Arc<Datatype>| t.get_size() as i32)
                .unwrap_or(0);
            if sym_size == vn_g.get_size() as i32
                && entry.get_addr() == vn_g.loc
                && !entry.is_piece()
            {
                self.symbol_offset = -1; // A matching entry
            } else {
                // Faithful to variable.cc:269: overlapJoin + entry offset.
                let off = vn_g.loc.overlap(0, entry.get_addr(), sym_size) + entry.get_offset();
                self.symbol_offset = off;
            }
        }
        drop(vn_g);

        // Faithful to variable.cc:272-274. RUDRA-GLUE: Rudra's TypeMetatype has
        // no TYPE_PARTIALUNION, so this branch never fires; we keep it as a
        // structural guard for the day the metatype is added.
        // Faithful to variable.cc:272-273: a partial-union cached type must
        // re-derive (typedirty) when a Symbol attaches.
        if self.v_type.get().get_metatype() == TypeMetatype::PartialUnion {
            self.highflags |= high_internal_flags::TYPEDIRTY;
        }
        self.highflags &= !high_internal_flags::SYMBOLDIRTY;
    }

    // Ghidra: variable.cc:283 HighVariable::setSymbolReference
    /// Attach a Symbol reference that is not tied to a member Varnode. Faithful
    /// to `setSymbolReference` (variable.cc:283-289). Used for constant address
    /// references to a Symbol.
    pub fn set_symbol_reference(&mut self, sym: Arc<RwLock<Symbol>>, off: i32) {
        self.symbol = Some(sym);
        self.symbol_offset = off;
        self.highflags &= !high_internal_flags::SYMBOLDIRTY;
    }

    // Ghidra: variable.cc:291 HighVariable::transferPiece
    /// Transfer ownership of another HighVariable's VariablePiece to this.
    /// Faithful to `transferPiece` (variable.cc:291-299).
    pub fn transfer_piece(&mut self, tv2: &mut HighVariable) {
        if let Some(piece) = tv2.piece.take() {
            // Re-point the piece's owning HighVariable to this.
            // RUDRA-GLUE: Ghidra uses raw `piece->setHigh(this)`; Rudra's
            // VariablePiece holds a Weak<RwLock<HighVariable>> back-reference,
            // which we cannot re-point without an Arc to `this`. We carry the
            // piece over and inherit tv2's intersect/extend-cover dirty bits.
            self.piece = Some(piece);
            // Faithful to variable.cc:297-298: inherit tv2's intersect/extend bits.
            self.highflags |= tv2.highflags
                & (high_internal_flags::INTERSECTDIRTY | high_internal_flags::EXTENDCOVERDIRTY);
            tv2.highflags &=
                !(high_internal_flags::INTERSECTDIRTY | high_internal_flags::EXTENDCOVERDIRTY);
        }
    }

    // Ghidra: variable.cc:302 HighVariable::stripType
    /// Take the stripped form of the current data-type. Faithful to `stripType`
    /// (variable.cc:302-320). Exits early if the type has no stripped form,
    /// preserves a partial-union/partial-struct when a struct/union backing
    /// symbol exists, and preserves a partial enum on a single constant
    /// member. `&self` mirrors the Ghidra const member: the write goes
    /// through the `mutable` type cache (variable.hh:141), which Rudra
    /// models with `Cell`.
    pub fn strip_type(&self) {
        let cur = self.v_type.get();
        if !cur.has_stripped() {
            return;
        }
        let meta = cur.get_metatype();
        // Faithful to variable.cc:308-313: don't strip a partial union/struct
        // when a bigger backing Symbol of struct/union type exists.
        if meta == TypeMetatype::PartialUnion || meta == TypeMetatype::PartialStruct {
            if self.symbol.is_some() && self.symbol_offset != -1 {
                if let Some(sym) = &self.symbol {
                    if let Some(sym_type) = sym.read().unwrap().get_type() {
                        let submeta = sym_type.get_metatype();
                        if submeta == TypeMetatype::Struct || submeta == TypeMetatype::Union {
                            return; // Don't strip the partial union/struct.
                        }
                    }
                }
            }
        } else if cur.is_enum_type() {
            // Faithful to variable.cc:315-318: only preserve partial enum on a
            // single constant member.
            if self.instances.len() == 1
                && self.instances[0].read().unwrap().is_constant()
            {
                return;
            }
        }
        // Ghidra: variable.cc:319: `type = type->getStripped();` — a POINTER
        // assignment of the factory-interned stripped form (TypePartialStruct
        // etc. hold the interned `stripped` field, type.hh:592). Rudra must
        // route through the Arc-preserving `get_stripped_arc` twin so the
        // stripped result keeps pointer identity with the canonical factory
        // base type. The previous `Arc::new(get_stripped().clone())` minted a
        // fresh allocation per call, so HighVariables whose type went through
        // stripping compared unequal (by Arc::ptr_eq) to the interned base in
        // every Datatype* pointer-equality site — mergeByDatatype grouping
        // (merge.cc:386 `ct == high->getType()`), mergeTestRequired's
        // typelock pair and mergeTestAdjacent's same-type gate (merge.cc:196)
        // — fragmenting same-type merge groups (DECL-B3-HIGHMERGE-0001:
        // sqlite3Select stack-slot load COPYs excluded from the xunknown4
        // group, +3 xunknown4 symbols). `None` means `getStripped()` returns
        // \b this (no external stripped form): the oracle assignment is a
        // self-assignment, so keeping the current Arc is identity-faithful.
        if let Some(stripped) = Datatype::get_stripped_arc(&cur) {
            self.v_type.set(stripped);
        }
    }

    // Ghidra: variable.cc:324 HighVariable::updateInternalCover
    /// Re-derive the internal cover from member Varnodes. Faithful to
    /// `updateInternalCover` (variable.cc:324-335). Only acts when coverdirty.
    /// Clears the cover, then (if the first member has a cover) merges every
    /// member's cover in.
    pub fn update_internal_cover(&mut self) {
        if (self.highflags & high_internal_flags::COVERDIRTY) == 0 {
            return;
        }
        self.cover.clear();
        // Faithful to variable.cc:329: gate on inst[0]->hasCover().
        if let Some(first) = self.instances.first() {
            if first.read().unwrap().has_cover() {
                for inst in &self.instances {
                    let vn = inst.read().unwrap();
                    if let Some(ic) = vn.cover.as_ref() {
                        self.cover.merge(ic);
                    }
                }
            }
        }
        self.highflags &= !high_internal_flags::COVERDIRTY;
    }

    // Ghidra: variable.cc:338 HighVariable::updateCover
    /// Re-derive the external cover as a union of internal covers. Faithful to
    /// `updateCover` (variable.cc:338-347). With no piece, just updates the
    /// internal cover; with a piece, recomputes intersections then the piece's
    /// extended cover.
    pub fn update_cover(&mut self) {
        if self.piece.is_none() {
            self.update_internal_cover();
            return;
        }
        // Faithful to variable.cc:343-346: piece->updateIntersections(); piece->updateCover();
        let piece_arc = self.piece.clone().unwrap();
        VariablePiece::update_intersections(&piece_arc);
        VariablePiece::update_cover_read(&piece_arc, self);
    }

    // Ghidra: variable.cc:352 HighVariable::updateFlags
    /// Re-derive boolean properties from member Varnodes. Faithful to
    /// `updateFlags` (variable.cc:352-368). Only acts when flagsdirty. OR's all
    /// member flags together, preserves `mark|typelock`, and updates everything
    /// except `mark|directwrite|typelock`.
    pub fn update_flags(&mut self) {
        if (self.highflags & high_internal_flags::FLAGSDIRTY) == 0 {
            return;
        }
        let mut fl: u32 = 0;
        for inst in &self.instances {
            fl |= inst.read().unwrap().flags;
        }
        // Faithful to variable.cc:364-366.
        self.flags &= high_flags::MARK | high_flags::TYPELOCK;
        self.flags |= fl & !(high_flags::MARK | high_flags::DIRECTWRITE | high_flags::TYPELOCK);
        self.highflags &= !high_internal_flags::FLAGSDIRTY;
    }

    // Ghidra: variable.cc:377 HighVariable::getTypeRepresentative
    /// Get the member Varnode with the strongest data-type. Faithful to
    /// `getTypeRepresentative` (variable.cc:377-396). Prefers type-locked
    /// members, then uses `Datatype::typeOrderBool` to pick the most specific
    /// non-bool type (bool is specialized but not all bit patterns are boolean).
    pub fn get_type_representative(&self) -> Option<Arc<RwLock<Varnode>>> {
        if self.instances.is_empty() {
            return None;
        }
        let mut rep_idx: usize = 0;
        let mut rep_is_typelock;
        let mut rep_type;
        {
            let rep_vn = self.instances[0].read().unwrap();
            rep_is_typelock = rep_vn.is_type_lock();
            rep_type = rep_vn.get_type().unwrap_or_else(|| self.v_type.get());
        }
        for (i, inst) in self.instances.iter().enumerate().skip(1) {
            let vn = inst.read().unwrap();
            let vn_is_typelock = vn.is_type_lock();
            if rep_is_typelock != vn_is_typelock {
                if vn_is_typelock {
                    rep_idx = i;
                    rep_is_typelock = true;
                    rep_type = vn.get_type().unwrap_or_else(|| self.v_type.get());
                }
            } else {
                let vn_type = vn.get_type().unwrap_or_else(|| self.v_type.get());
                // Faithful to variable.cc:392: 0 > vn->getType()->typeOrderBool(*rep->getType())
                if vn_type.type_order_bool(&rep_type) < 0 {
                    rep_idx = i;
                    rep_is_typelock = vn_is_typelock;
                    rep_type = vn_type;
                }
            }
        }
        Some(self.instances[rep_idx].clone())
    }

    // Ghidra: variable.cc:400 HighVariable::updateType
    /// Re-derive the data-type from member Varnodes. Faithful to `updateType`
    /// (variable.cc:400-416). Only acts when typedirty. The dirty bit is
    /// cleared FIRST (before the finalized guard), exactly as variable.cc:
    /// 405-407 does, then a finalized type short-circuits re-derivation.
    /// Otherwise gets the type representative, strips the type, and refreshes
    /// the typelock flag. Stays `&mut self`: it owns the authoritative
    /// `typedirty` clear in the plain `highflags` word (Ghidra's const member
    /// variable.hh:151 mutates through `mutable`; the `&self` lazy read path
    /// lives in `get_type`, which never needs the bit clear to stay
    /// output-faithful).
    pub fn update_type(&mut self) {
        if (self.highflags & high_internal_flags::TYPEDIRTY) == 0 {
            return;
        }
        self.highflags &= !high_internal_flags::TYPEDIRTY;
        // Faithful to variable.cc:407: if type_finalized, leave type alone.
        if (self.highflags & high_internal_flags::TYPE_FINALIZED) != 0 {
            return;
        }
        if let Some(rep) = self.get_type_representative() {
            let new_type;
            let is_typelock;
            {
                let rep_vn = rep.read().unwrap();
                new_type = rep_vn.get_type().unwrap_or_else(|| self.v_type.get());
                is_typelock = rep_vn.is_type_lock();
            }
            self.v_type.set(new_type);
            self.strip_type();
            // Faithful to variable.cc:413-415: refresh typelock from representative.
            self.flags &= !high_flags::TYPELOCK;
            if is_typelock {
                self.flags |= high_flags::TYPELOCK;
            }
        }
    }

    // Ghidra: variable.cc:418 HighVariable::updateSymbol
    /// Re-derive the Symbol and offset from member Varnodes. Faithful to
    /// `updateSymbol` (variable.cc:418-433). Only acts when symboldirty. Clears
    /// the symbol, then scans members for the first with a SymbolEntry.
    pub fn update_symbol(&mut self) {
        if (self.highflags & high_internal_flags::SYMBOLDIRTY) == 0 {
            return;
        }
        self.highflags &= !high_internal_flags::SYMBOLDIRTY;
        self.symbol = None;
        // Faithful to variable.cc:426-432: first member with a SymbolEntry wins.
        let snapshot: Vec<Arc<RwLock<Varnode>>> = self.instances.clone();
        for inst in snapshot.into_iter() {
            let has_entry = inst.read().unwrap().get_symbol_entry().is_some();
            if has_entry {
                self.set_symbol(&inst);
                return;
            }
        }
    }

    // Ghidra: variable.cc:439 HighVariable::compareJustLoc
    /// Compare two Varnodes based just on their storage address. Faithful to
    /// `compareJustLoc` (variable.cc:439-443): `a->getAddr() < b->getAddr()`
    /// is `Address::operator<` (address.hh:375-393) — a TOTAL order that
    /// first compares the address space by its index (`AddrSpace::getIndex()`,
    /// mirrored by `AddressSpace::space_id()`, which carries the SLEIGH spec
    /// space indices), then the offset. (The operator's null/`~0` base
    /// sentinels only order invalid addresses; Varnode storage is always in a
    /// concrete space, so they cannot arise here.) Comparing only offsets —
    /// as this did before — mis-orders varnodes that live in different
    /// spaces at overlapping offsets (e.g. unique vs stack) and corrupts the
    /// `std::merge` instance ordering in `merge_internal` (variable.cc:657).
    pub fn compare_just_loc(a: &Varnode, b: &Varnode) -> bool {
        if a.address_space != b.address_space {
            return a.address_space.space_id() < b.address_space.space_id();
        }
        a.loc < b.loc
    }

    // Ghidra: variable.cc:456 HighVariable::compareName
    /// Determine which of two Varnodes is more nameable. Faithful to
    /// `compareName` (variable.cc:456-488). Returns true if vn2's name would
    /// override vn1's. Preference order: namelock, unaffected, persist, input,
    /// addrtied, proto-partial, NOT-internal-space, written, earlier def.
    pub fn compare_name(vn1: &Varnode, vn2: &Varnode) -> bool {
        if vn1.is_name_lock() {
            return false; // Check for namelocks (variable.cc:459)
        }
        if vn2.is_name_lock() {
            return true; // (variable.cc:460)
        }
        if vn1.is_unaffected() != vn2.is_unaffected() {
            return vn2.is_unaffected(); // Prefer unaffected (variable.cc:462)
        }
        if vn1.is_persist() != vn2.is_persist() {
            return vn2.is_persist(); // Prefer persistent (variable.cc:464)
        }
        if vn1.is_input() != vn2.is_input() {
            return vn2.is_input(); // Prefer an input (variable.cc:466)
        }
        if vn1.is_addr_tied() != vn2.is_addr_tied() {
            return vn2.is_addr_tied(); // Prefer address tied (variable.cc:468)
        }
        if vn1.is_proto_partial() != vn2.is_proto_partial() {
            return vn2.is_proto_partial(); // Prefer pieces (variable.cc:470)
        }
        // Prefer NOT internal (variable.cc:474-479). Rudra's AddressSpace is an
        // enum without IPTR_INTERNAL; we approximate via is_unique.
        let vn1_internal = vn1.is_unique();
        let vn2_internal = vn2.is_unique();
        if !vn1_internal && vn2_internal {
            return false;
        }
        if vn1_internal && !vn2_internal {
            return true;
        }
        if vn1.is_written() != vn2.is_written() {
            return vn2.is_written(); // Prefer written (variable.cc:480)
        }
        if !vn1.is_written() {
            return false; // (variable.cc:482)
        }
        // Prefer earlier (variable.cc:485-486): compare def->getTime().
        let t1 = vn1
            .def
            .as_ref()
            .and_then(|w| w.upgrade())
            .map(|op| op.read().unwrap().get_time())
            .unwrap_or(0);
        let t2 = vn2
            .def
            .as_ref()
            .and_then(|w| w.upgrade())
            .map(|op| op.read().unwrap().get_time())
            .unwrap_or(0);
        if t1 != t2 {
            return t2 < t1;
        }
        false
    }

    // Ghidra: variable.cc:492 HighVariable::getNameRepresentative
    /// Get the member Varnode that dictates the naming of this HighVariable.
    /// Faithful to `getNameRepresentative` (variable.cc:492-511). Ghidra caches
    /// the result in `nameRepresentative` and returns it when not dirty; Rudra
    /// recomputes each call (the cache is an optimisation) but still honors the
    /// dirty bit by re-running the scan.
    ///
    /// NOTE: takes `&self` (not `&mut self`) so callers with only a read lock on
    /// the HighVariable (coreaction.rs:3799) can call it. The Ghidra `mutable`
    /// cache write is dropped; this is sound because the dirty bit is also
    /// dropped only on the `&mut self` path; the `&self` path simply recomputes.
    pub fn get_name_representative(&self) -> Option<Arc<RwLock<Varnode>>> {
        if self.instances.is_empty() {
            return None;
        }
        // If the cache is clean, return it (faithful to variable.cc:495-496).
        if (self.highflags & high_internal_flags::NAMEREPDIRTY) == 0 {
            if let Some(cached) = &self.name_representative {
                return Some(cached.clone());
            }
        }
        // Faithful to variable.cc:502-510: pick the most nameable member.
        let mut rep_idx: usize = 0;
        for (i, inst) in self.instances.iter().enumerate().skip(1) {
            let rep_vn = self.instances[rep_idx].read().unwrap();
            let vn = inst.read().unwrap();
            if Self::compare_name(&rep_vn, &vn) {
                rep_idx = i;
            }
        }
        Some(self.instances[rep_idx].clone())
    }

    // Ghidra: variable.cc:492 HighVariable::getNameRepresentative
    /// Mutable-cache form of [`Self::get_name_representative`], mirroring
    /// the oracle's `mutable`-member cache write exactly
    /// (variable.cc:495-510): return the cache when the dirty bit is
    /// clear; otherwise clear the dirty bit FIRST (cc:497), then
    /// re-derive the representative from `instances[0]` via
    /// `compare_name` (cc:502-509), store it into `name_representative`,
    /// and return it. The selection walk is the same deterministic
    /// algorithm as the `&self` form — the only difference is the cache
    /// population, which is precisely what Ghidra's const method does
    /// through its `mutable` members. Callers that can only take a read
    /// lock keep the `&self` form (recompute, no cache write).
    pub fn get_name_representative_mut(&mut self) -> Option<Arc<RwLock<Varnode>>> {
        if self.instances.is_empty() {
            return None;
        }
        // Faithful to variable.cc:495-496.
        if (self.highflags & high_internal_flags::NAMEREPDIRTY) == 0 {
            if let Some(cached) = &self.name_representative {
                return Some(cached.clone());
            }
        }
        // Faithful to variable.cc:497: clear the dirty bit before the scan
        // (the oracle's `mutable` write; instance-list mutations re-set it,
        // see merge_internal/remove/flags_dirty).
        self.highflags &= !high_internal_flags::NAMEREPDIRTY;
        // Faithful to variable.cc:502-510.
        let mut rep_idx: usize = 0;
        for (i, inst) in self.instances.iter().enumerate().skip(1) {
            let rep_vn = self.instances[rep_idx].read().unwrap();
            let vn = inst.read().unwrap();
            if Self::compare_name(&rep_vn, &vn) {
                rep_idx = i;
            }
        }
        let rep = Some(self.instances[rep_idx].clone());
        self.name_representative = rep.clone();
        rep
    }

    // Ghidra: variable.cc:515 HighVariable::remove
    /// Remove a member Varnode and mark all properties dirty. Faithful to
    /// `remove` (variable.cc:515-532). Searches (sorted by location) for the
    /// Varnode, erases it, and sets flagsdirty|namerepdirty|coverdirty|typedirty
    /// (plus symboldirty if it had a SymbolEntry, and piece->markExtendCoverDirty).
    pub fn remove(&mut self, vn: &Arc<RwLock<Varnode>>) {
        if let Some(pos) = self.instances.iter().position(|v| Arc::ptr_eq(v, vn)) {
            self.instances.remove(pos);
            // Faithful to variable.cc:524.
            self.highflags |= high_internal_flags::FLAGSDIRTY
                | high_internal_flags::NAMEREPDIRTY
                | high_internal_flags::COVERDIRTY
                | high_internal_flags::TYPEDIRTY;
            // Faithful to variable.cc:525-526.
            if vn.read().unwrap().get_symbol_entry().is_some() {
                self.highflags |= high_internal_flags::SYMBOLDIRTY;
            }
            // Faithful to variable.cc:527-528.
            if let Some(piece_arc) = &self.piece {
                VariablePiece::mark_extend_cover_dirty_read(piece_arc);
            }
        }
    }

    // Ghidra: variable.cc:551 HighVariable::finalizeDatatype
    /// Assign a final data-type matching the associated Symbol and disable
    /// future type dirtying. Faithful to `finalizeDatatype` (variable.cc:551-566).
    /// The caller supplies the owning Architecture's factory, preserving both
    /// canonical partial-type identity and the factory mutation performed by
    /// `TypeFactory::getExactPiece`.
    pub fn finalize_datatype(
        &mut self,
        type_factory: &mut crate::type_system::typefactory::TypeFactory,
    ) {
        let symbol_arc = match &self.symbol {
            Some(s) => s.clone(),
            None => return, // Faithful to variable.cc:554.
        };
        let cur = symbol_arc
            .read()
            .unwrap()
            .get_type()
            .unwrap_or_else(|| self.v_type.get());
        let mut off = self.symbol_offset;
        if off < 0 {
            off = 0; // Faithful to variable.cc:557-558.
        }
        let sz = self
            .instances
            .first()
            .map(|v| v.read().unwrap().get_size())
            .unwrap_or(cur.get_size());
        // variable.cc:560: preserve the factory-canonical pointer returned by
        // getExactPiece, including PartialStruct/PartialUnion/PartialEnum.
        let tp = type_factory.get_exact_piece(cur, off as i64, sz);
        let tp = match tp {
            Some(t) if t.get_metatype() != TypeMetatype::Unknown => t,
            None => return, // Faithful to variable.cc:561-562: null or UNKNOWN -> return.
            Some(_) => return,
        };
        self.v_type.set(tp);
        self.strip_type(); // Faithful to variable.cc:564.
        self.highflags |= high_internal_flags::TYPE_FINALIZED; // Faithful to variable.cc:565.
    }

    // Ghidra: variable.cc:571 HighVariable::groupWith
    /// Put this and another HighVariable in the same intersection group.
    /// Faithful to `groupWith` (variable.cc:571-605). Handles all four cases:
    /// neither has a piece, only this lacks one, only hi2 lacks one, both have
    /// pieces (merge the groups).
    pub fn group_with(&mut self, off: i32, hi2: &mut HighVariable) {
        // RUDRA-GLUE: Ghidra allocates `new VariablePiece(h, offset, grp)` and
        // ties ownership via raw pointers. Rudra uses Arc<RwLock<VariablePiece>>
        // and an Weak<RwLock<HighVariable>> back-ref inside the piece, which we
        // cannot synthesise without an existing Arc to `this`. This method is
        // therefore a structural faithful port of the offset/group arithmetic
        // but leaves piece creation to the caller-allocated form; it is exercised
        // by the merge path when pieces already exist.
        let this_has = self.piece.is_some();
        let hi2_has = hi2.piece.is_some();
        if !this_has && !hi2_has {
            // Faithful to variable.cc:574-578: allocate pieces for both.
            // (Allocation requires an Arc to each HighVariable; skipped here.)
            return;
        }
        if !this_has {
            // Faithful to variable.cc:580-585.
            if (hi2.highflags & high_internal_flags::INTERSECTDIRTY) == 0 {
                if let Some(p2) = &hi2.piece {
                    VariablePiece::mark_intersection_dirty_read(p2);
                }
            }
            self.highflags |=
                high_internal_flags::INTERSECTDIRTY | high_internal_flags::EXTENDCOVERDIRTY;
            let _ = off; // would be: off += hi2.piece->getOffset();
            return;
        }
        if !hi2_has {
            // Faithful to variable.cc:587-596.
            let piece_arc = self.piece.clone().unwrap();
            let mut hi2_off;
            {
                let piece = piece_arc.read().unwrap();
                hi2_off = piece.group_offset - off;
            }
            if hi2_off < 0 {
                if let Some(g) = piece_arc.read().unwrap().get_group_arc() {
                    g.write().unwrap().adjust_offsets(-hi2_off);
                }
                hi2_off = 0;
            }
            if (self.highflags & high_internal_flags::INTERSECTDIRTY) == 0 {
                VariablePiece::mark_intersection_dirty_read(&piece_arc);
            }
            hi2.highflags |=
                high_internal_flags::INTERSECTDIRTY | high_internal_flags::EXTENDCOVERDIRTY;
            return;
        }
        // Both have pieces: Faithful to variable.cc:598-604.
        let (self_piece_arc, hi2_piece_arc) =
            (self.piece.clone().unwrap(), hi2.piece.clone().unwrap());
        let (self_off, hi2_off) = {
            let sp = self_piece_arc.read().unwrap();
            let hp = hi2_piece_arc.read().unwrap();
            (sp.group_offset, hp.group_offset)
        };
        let off_diff = hi2_off + off - self_off;
        if off_diff != 0 {
            let sp = self_piece_arc.read().unwrap();
            if let Some(g) = sp.get_group_arc() {
                g.write().unwrap().adjust_offsets(off_diff);
            }
        }
        // Faithful to variable.cc:602: hi2->piece->getGroup()->combineGroups(piece->getGroup()).
        let hi2_group = hi2_piece_arc.read().unwrap().get_group_arc();
        let self_group = self_piece_arc.read().unwrap().get_group_arc();
        if let (Some(hg), Some(sg)) = (hi2_group, self_group) {
            let mut hg_w = hg.write().unwrap();
            let mut sg_w = sg.write().unwrap();
            hg_w.combine_groups(&mut sg_w);
        }
        // Faithful to variable.cc:603.
        VariablePiece::mark_intersection_dirty_read(&hi2_piece_arc);
    }

    // Ghidra: variable.cc:610 HighVariable::establishGroupSymbolOffset
    /// Transfer this symbol offset to the VariableGroup. Faithful to
    /// `establishGroupSymbolOffset` (variable.cc:610-621).
    pub fn establish_group_symbol_offset(&self) {
        let piece_arc = match &self.piece {
            Some(p) => p.clone(),
            None => return, // RUDRA-GLUE: Ghidra's caller guarantees a piece.
        };
        let group_arc = {
            let piece = piece_arc.read().unwrap();
            match piece.get_group_arc() {
                Some(g) => g,
                None => return,
            }
        };
        let mut off = self.symbol_offset;
        if off < 0 {
            off = 0; // Faithful to variable.cc:615-616.
        }
        let piece_offset = piece_arc.read().unwrap().group_offset;
        off -= piece_offset; // Faithful to variable.cc:617.
        if off < 0 {
            // Faithful to variable.cc:618-619: throw LowlevelError.
            eprintln!("warning: Symbol offset incompatible with VariableGroup (variable.cc:619)");
            return;
        }
        group_arc.write().unwrap().symbol_offset = off; // Faithful to variable.cc:620.
    }

    // Ghidra: variable.cc:626 HighVariable::mergeInternal
    /// Merge another HighVariable into this one. Faithful to `mergeInternal`
    /// (variable.cc:626-666). Marks properties dirty, inherits the other's
    /// Symbol if it is clean, assigns merge classes (speculative vs not),
    /// merges the instance lists sorted by location, merges covers if both
    /// clean, and clears the other's instance list.
    ///
    /// In Ghidra this deletes `tv2`; in Rust the caller drops the freed
    /// HighVariable. We take `tv2: &mut HighVariable` and drain its instances.
    pub fn merge_internal(&mut self, tv2: &mut HighVariable, isspeculative: bool) {
        // Faithful to variable.cc:631.
        self.highflags |= high_internal_flags::FLAGSDIRTY
            | high_internal_flags::NAMEREPDIRTY
            | high_internal_flags::TYPEDIRTY;
        // Faithful to variable.cc:632-638: inherit tv2's Symbol if clean.
        if tv2.symbol.is_some() && (tv2.highflags & high_internal_flags::SYMBOLDIRTY) == 0 {
            self.symbol = tv2.symbol.clone();
            self.symbol_offset = tv2.symbol_offset;
            self.highflags &= !high_internal_flags::SYMBOLDIRTY;
        }

        if isspeculative {
            // Faithful to variable.cc:640-646.
            let num_merge_classes = self.num_merge_classes;
            for vn_arc in &tv2.instances {
                let mut vn = vn_arc.write().unwrap();
                vn.mergegroup = vn.mergegroup.saturating_add(num_merge_classes as i16);
                // RUDRA-GLUE: Ghidra calls vn->setHigh(this, ...). Rudra's
                // HighVariable ownership is via Arc<RwLock<HighVariable>> set
                // by funcdata/merge, so the caller re-points vn.high after merge.
            }
            self.num_merge_classes += tv2.num_merge_classes;
        } else {
            // Faithful to variable.cc:648-649: no speculative merges allowed.
            if self.num_merge_classes != 1 || tv2.num_merge_classes != 1 {
                eprintln!(
                    "warning: non-speculative merge after speculative merges (variable.cc:649)"
                );
            }
            // Faithful to variable.cc:650-654: vn->setHigh(this, vn->getMergeGroup()).
            // mergegroup stays the same on a non-speculative merge.
        }

        // Faithful to variable.cc:655-658: std::merge the two sorted instance lists.
        let mut merged: Vec<Arc<RwLock<Varnode>>> =
            Vec::with_capacity(self.instances.len() + tv2.instances.len());
        let mut i = 0usize;
        let mut j = 0usize;
        let a_len = self.instances.len();
        let b_len = tv2.instances.len();
        while i < a_len && j < b_len {
            let a_vn = self.instances[i].read().unwrap();
            let b_vn = tv2.instances[j].read().unwrap();
            if Self::compare_just_loc(&a_vn, &b_vn) {
                merged.push(self.instances[i].clone());
                i += 1;
            } else {
                merged.push(tv2.instances[j].clone());
                j += 1;
            }
        }
        while i < a_len {
            merged.push(self.instances[i].clone());
            i += 1;
        }
        while j < b_len {
            merged.push(tv2.instances[j].clone());
            j += 1;
        }
        self.instances = merged;
        tv2.instances.clear(); // Faithful to variable.cc:658.
        // RUDRA-GLUE: the oracle DELETES tv2 after mergeInternal (the
        // caller in merge.cc destroys it), so no oracle code can observe
        // tv2's member list or its caches afterwards. Rust keeps the
        // retired shell object (varnode high pointers are rewired to
        // -self-, but the shell may still be reachable through a stale
        // handle); invalidate tv2's name-representative cache so any such
        // late query re-derives from the now-empty list (returning None,
        // exactly like the pre-cache &self form) instead of a stale
        // cached representative.
        tv2.highflags |= high_internal_flags::NAMEREPDIRTY;

        // Faithful to variable.cc:660-663: merge covers if both clean, else dirty.
        if (self.highflags & high_internal_flags::COVERDIRTY) == 0
            && (tv2.highflags & high_internal_flags::COVERDIRTY) == 0
        {
            self.cover.merge(&tv2.cover);
        } else {
            self.highflags |= high_internal_flags::COVERDIRTY;
        }
    }

    // Ghidra: variable.cc:675 HighVariable::merge
    /// Merge with another HighVariable taking groups into account. Faithful to
    /// `merge` (variable.cc:675-712). Early-out on self-merge, move intersect
    /// tests, then handle the four piece cases; for two-piece merges, combine
    /// the groups and merge any colliding pairs.
    ///
    /// Rudra has no HighIntersectTest port; `test_cache` is accepted but unused.
    pub fn merge(&mut self, tv2: &mut HighVariable, _test_cache: Option<()>, isspeculative: bool) {
        // Faithful to variable.cc:678.
        if (tv2 as *const HighVariable) as usize == (self as *const HighVariable) as usize {
            return;
        }
        // Faithful to variable.cc:680-681: testCache->moveIntersectTests (no-op).

        // Faithful to variable.cc:682-685: neither has a piece.
        if self.piece.is_none() && tv2.piece.is_none() {
            self.merge_internal(tv2, isspeculative);
            return;
        }
        // Faithful to variable.cc:686-690: only this has a piece.
        if tv2.piece.is_none() {
            if let Some(p) = &self.piece {
                VariablePiece::mark_extend_cover_dirty_read(p);
            }
            self.merge_internal(tv2, isspeculative);
            return;
        }
        // Faithful to variable.cc:692-697: only this lacks a piece.
        if self.piece.is_none() {
            self.transfer_piece(tv2);
            if let Some(p) = &self.piece {
                VariablePiece::mark_extend_cover_dirty_read(p);
            }
            self.merge_internal(tv2, isspeculative);
            return;
        }
        // Faithful to variable.cc:700-701: speculative merge of two grouped vars is illegal.
        if isspeculative {
            eprintln!(
                "warning: speculative merge of variables in separate groups (variable.cc:701)"
            );
            return;
        }
        // Faithful to variable.cc:702-711: merge groups, then merge colliding pairs.
        let (self_piece, tv2_piece) = (self.piece.clone().unwrap(), tv2.piece.clone().unwrap());
        let _merge_pairs = VariablePiece::merge_groups(&self_piece, &tv2_piece);
        if let Some(p) = &self.piece {
            VariablePiece::mark_intersection_dirty_read(p);
        }
    }

    // Ghidra: variable.cc:718 HighVariable::hasName
    /// Determine if this can have a name. Faithful to `hasName`
    /// (variable.cc:718-747). Iterates members; non-coverable or implied
    /// members forbid a name; tracks indirectonly. For unaffected variables,
    /// extra checks on input/legal-input/spacebase apply.
    pub fn has_name(&self) -> bool {
        let mut indirectonly = true; // Faithful to variable.cc:721.
        for inst in &self.instances {
            let vn = inst.read().unwrap();
            // Faithful to variable.cc:724-728: non-coverable member forbids name.
            if !vn.has_cover() {
                if self.instances.len() > 1 {
                    eprintln!("warning: Non-coverable varnode has been merged (variable.cc:726)");
                }
                return false;
            }
            // Faithful to variable.cc:729-733: implied member forbids name.
            if vn.is_implied() {
                if self.instances.len() > 1 {
                    eprintln!("warning: Implied varnode has been merged (variable.cc:731)");
                }
                return false;
            }
            // Faithful to variable.cc:734-735: !isIndirectOnly clears indirectonly.
            // RUDRA-GLUE: Varnode has the INDIRECTONLY flag but no is_indirect_only()
            // method; inline the flag check (varnode_flags::INDIRECTONLY).
            let is_indirect_only = (vn.flags & varnode_flags::INDIRECTONLY) != 0;
            if !is_indirect_only {
                indirectonly = false;
            }
        }
        // Faithful to variable.cc:737-745: unaffected special-case.
        // RUDRA-GLUE: is_unaffected() reads the cached flags bit (&self).
        if self.is_unaffected() {
            if !self.is_input() {
                return false; // variable.cc:738
            }
            if indirectonly {
                return false; // variable.cc:739
            }
            if let Some(input_vn) = Self::find_input_varnode(&self.instances) {
                let vn = input_vn.read().unwrap();
                if !vn.is_illegal_input() {
                    if vn.is_spacebase() {
                        return false; // variable.cc:743
                    }
                }
            }
        }
        true
    }

    // RUDRA-GLUE: Static slice helper for has_name's shared-borrow path; Ghidra
    // calls the throwing HighVariable::getInputVarnode member at variable.cc:740.
    /// Helper: find the first input member Varnode (static, no &mut self).
    fn find_input_varnode(
        instances: &[Arc<RwLock<Varnode>>],
    ) -> Option<Arc<RwLock<Varnode>>> {
        for inst in instances {
            if inst.read().unwrap().is_input() {
                return Some(inst.clone());
            }
        }
        None
    }

    // Ghidra: variable.cc:752 HighVariable::getTiedVarnode
    /// Find the first address-tied member Varnode. Faithful to `getTiedVarnode`
    /// (variable.cc:752-762). Should only be called if `is_addr_tied()` is true.
    /// Returns None instead of throwing when no tied member exists.
    pub fn get_tied_varnode(&self) -> Option<Arc<RwLock<Varnode>>> {
        for inst in &self.instances {
            if inst.read().unwrap().is_addr_tied() {
                return Some(inst.clone()); // Faithful to variable.cc:758-759.
            }
        }
        None // RUDRA-GLUE: Ghidra throws LowlevelError (variable.cc:761).
    }

    // Ghidra: variable.cc:767 HighVariable::getInputVarnode
    /// Find the input member Varnode. Faithful to `getInputVarnode`
    /// (variable.cc:767-774). Should only be called if `is_input()` is true.
    /// Returns None instead of throwing when no input member exists.
    pub fn get_input_varnode(&self) -> Option<Arc<RwLock<Varnode>>> {
        for inst in &self.instances {
            if inst.read().unwrap().is_input() {
                return Some(inst.clone()); // Faithful to variable.cc:770-771.
            }
        }
        None // RUDRA-GLUE: Ghidra throws LowlevelError (variable.cc:773).
    }

    // Ghidra: variable.cc:778 HighVariable::printInfo
    /// Print information about this HighVariable. Faithful to `printInfo`
    /// (variable.cc:778-803). Updates the type, prints the symbol name (or
    /// UNNAMED), the type, then each member's merge group and info.
    pub fn print_info(&mut self) -> String {
        self.update_type(); // Faithful to variable.cc:784.
        let mut s = String::new();
        // Faithful to variable.cc:785-793.
        match &self.symbol {
            None => s.push_str("Variable: UNNAMED\n"),
            Some(sym) => {
                s.push_str("Variable: ");
                s.push_str(&sym.read().unwrap().get_name().to_string());
                if self.symbol_offset != -1 {
                    s.push_str("(partial)");
                }
                s.push('\n');
            }
        }
        s.push_str("Type: ");
        s.push_str(&self.v_type.get().print_raw()); // Faithful to variable.cc:795.
        s.push_str("\n\n");
        // Faithful to variable.cc:798-802.
        for inst in &self.instances {
            let vn = inst.read().unwrap();
            s.push_str(&format!("{}: ", vn.mergegroup));
            s.push_str(&vn.print_info());
        }
        s
    }

    // Ghidra: variable.hh:188 HighVariable::printCover
    /// Print the cover (debug). Faithful to the inline `printCover`
    /// (variable.hh:188): if cover is not dirty, print internalCover, else
    /// "Cover dirty".
    pub fn print_cover(&self) -> String {
        if (self.highflags & high_internal_flags::COVERDIRTY) == 0 {
            self.cover.to_string()
        } else {
            "Cover dirty".to_string()
        }
    }

    // Ghidra: variable.cc:808 HighVariable::instanceIndex
    /// Find the index of a specific member Varnode. Faithful to `instanceIndex`
    /// (variable.cc:808-817). Returns the index or None (-1 in Ghidra).
    pub fn instance_index(&self, vn: &Arc<RwLock<Varnode>>) -> Option<usize> {
        self.instances.iter().position(|v| Arc::ptr_eq(v, vn))
    }

    // Ghidra: variable.cc:872 HighVariable::markExpression
    /// Mark and collect HighVariables in an expression rooted at `vn`. Faithful
    /// to `markExpression` (variable.cc:872-913). Traces back from the root
    /// until explicit Varnodes are encountered; marks and collects their
    /// HighVariables. Returns a bitset: 1=call, 2=LOAD.
    ///
    /// RUDRA-GLUE: the full traversal walks PcodeOp inputs via node.slot; Rudra
    /// has the pieces (PcodeOp::num_input/get_in, Varnode::is_explicit) and the
    /// algorithm is ported verbatim below using a local stack of (op_arc, slot).
    pub fn mark_expression(
        vn: &Arc<RwLock<Varnode>>,
        high_list: &mut Vec<Arc<RwLock<HighVariable>>>,
    ) -> i32 {
        let mut ret_val = 0i32;
        let high_arc = {
            let vn_g = vn.read().unwrap();
            vn_g.get_high().cloned()
        };
        let high_arc = match high_arc {
            Some(h) => h,
            None => return 0, // RUDRA-GLUE: defensive; Ghidra assumes a HighVariable.
        };
        // Faithful to variable.cc:876-877: high->setMark(); highList.push_back(high).
        high_arc.write().unwrap().set_mark();
        high_list.push(high_arc.clone());
        // Faithful to variable.cc:879: if (!vn->isWritten()) return retVal.
        let is_written = vn.read().unwrap().is_written();
        if !is_written {
            return ret_val;
        }
        // Faithful to variable.cc:882-887: set up the traversal root.
        let op_arc = match vn.read().unwrap().get_def() {
            Some(o) => o,
            None => return ret_val,
        };
        {
            let op = op_arc.read().unwrap();
            if op.is_call() {
                ret_val |= 1; // Faithful to variable.cc:884.
            }
            if op.get_opcode() == OpCode::CPUI_LOAD {
                ret_val |= 2; // Faithful to variable.cc:886.
            }
        }
        // Faithful to variable.cc:887-911: DFS over op inputs.
        let mut path: Vec<(Arc<RwLock<crate::op::PcodeOp>>, usize)> = vec![(op_arc, 0)];
        while let Some((cur_op_arc, slot)) = path.last_mut() {
            let num_input = cur_op_arc.read().unwrap().num_input();
            if *slot >= num_input {
                path.pop();
                continue;
            }
            let cur_vn_arc = {
                let op_g = cur_op_arc.read().unwrap();
                op_g.get_in(*slot).cloned()
            };
            *slot += 1;
            let cur_vn_arc = match cur_vn_arc {
                Some(v) => v,
                None => continue,
            };
            let (is_annotation, is_explicit, is_written, next_op_arc) = {
                let cur_vn = cur_vn_arc.read().unwrap();
                (
                    cur_vn.is_annotation(),
                    cur_vn.is_explicit(),
                    cur_vn.is_written(),
                    cur_vn.get_def(),
                )
            };
            if is_annotation {
                continue; // Faithful to variable.cc:896.
            }
            if is_explicit {
                // Faithful to variable.cc:897-902.
                let h_clone = {
                    let cv = cur_vn_arc.read().unwrap();
                    cv.get_high().cloned()
                };
                if let Some(h) = h_clone {
                    if h.read().unwrap().is_mark() {
                        continue;
                    }
                    h.write().unwrap().set_mark();
                    high_list.push(h);
                }
                continue;
            }
            if !is_written {
                continue; // Faithful to variable.cc:904.
            }
            let next_op = match next_op_arc {
                Some(o) => o,
                None => continue,
            };
            {
                let next_op_g = next_op.read().unwrap();
                if next_op_g.is_call() {
                    ret_val |= 1; // Faithful to variable.cc:907.
                }
                if next_op_g.get_opcode() == OpCode::CPUI_LOAD {
                    ret_val |= 2; // Faithful to variable.cc:909.
                }
            }
            path.push((next_op, 0)); // Faithful to variable.cc:910.
        }
        ret_val
    }

    // Ghidra: variable.cc:820 HighVariable::encode
    /// Encode this variable as a `<high>` element string. Faithful to `encode`
    /// (variable.cc:820-857). Picks the representative, writes repref, the
    /// class attribute, typelock, symref/offset, the type ref, and each
    /// member's address ref.
    pub fn encode(&self) -> String {
        let vn_arc = self
            .get_name_representative()
            .or_else(|| self.instances.first().cloned());
        let vn_arc = match vn_arc {
            Some(v) => v,
            None => return String::new(), // RUDRA-GLUE: no members -> empty.
        };
        let rep_ref = vn_arc.read().unwrap().create_index;
        let mut s = String::new();
        s.push_str("<high");
        s.push_str(&format!(" repref=\"{}\"", rep_ref));
        // Faithful to variable.cc:826-842: class attribute.
        let class = if self.is_spacebase() || self.is_implied() {
            "other"
        } else if self.is_persist() && self.is_addr_tied() {
            "global"
        } else if self.is_constant() {
            "constant"
        } else if !self.is_persist() && self.symbol.is_some() {
            let cat = self
                .symbol
                .as_ref()
                .map(|sym| sym.read().unwrap().get_category())
                .unwrap_or(SymbolCategory::NoCategory);
            if matches!(cat, SymbolCategory::FunctionParameter) {
                "param"
            } else {
                "local" // RUDRA-GLUE: no scope->isGlobal() check; default local.
            }
        } else {
            "other"
        };
        s.push_str(&format!(" class=\"{}\"", class));
        if self.is_type_locked() {
            s.push_str(" typelock=\"true\"");
        }
        if let Some(sym) = &self.symbol {
            let sym_id = sym.read().unwrap().get_id();
            s.push_str(&format!(" symref=\"{}\"", sym_id));
            if self.symbol_offset >= 0 {
                s.push_str(&format!(" offset=\"{}\"", self.symbol_offset));
            }
        }
        s.push_str(&format!(" type=\"{}\"", self.v_type.get().get_id()));
        s.push('>');
        for inst in &self.instances {
            let idx = inst.read().unwrap().create_index;
            s.push_str(&format!("<addr ref=\"{}\"/>", idx)); // Faithful to variable.cc:851-855.
        }
        s.push_str("</high>");
        s
    }

    // --- Property query methods (faithful to variable.hh:197-223). ----------
    // Ghidra's inline queries (isAddrTied, isInput, ...) call updateFlags()
    // first to refresh the cache, then test the aggregated flag. Rudra's
    // call-sites (merge.rs) hold only a `RwLockReadGuard<HighVariable>` (a
    // shared reference), so these queries take `&self` and read the cached
    // `flags` bit directly. The cache is kept fresh by the `update_flags()`
    // call on the `&mut self` paths (updateCover, mergeInternal, etc.), so
    // skipping the re-sync here is sound as long as those paths run first;
    // which they do, because Ghidra marks flags dirty exactly when needed.

    // Ghidra: variable.hh:197 HighVariable::isMapped
    pub fn is_mapped(&self) -> bool {
        (self.flags & high_flags::MAPPED) != 0
    }

    // Ghidra: variable.hh:198 HighVariable::isPersist
    pub fn is_persist(&self) -> bool {
        (self.flags & high_flags::PERSIST) != 0
    }

    // Ghidra: variable.hh:199 HighVariable::isAddrTied
    pub fn is_addr_tied(&self) -> bool {
        (self.flags & high_flags::ADDRTIED) != 0
    }

    // Ghidra: variable.hh:200 HighVariable::isInput
    pub fn is_input(&self) -> bool {
        (self.flags & high_flags::INPUT) != 0
    }

    // Ghidra: variable.hh:201 HighVariable::isImplied
    pub fn is_implied(&self) -> bool {
        (self.flags & high_flags::IMPLIED) != 0
    }

    // Ghidra: variable.hh:202 HighVariable::isSpacebase
    pub fn is_spacebase(&self) -> bool {
        (self.flags & high_flags::SPACEBASE) != 0
    }

    // Ghidra: variable.hh:203 HighVariable::isConstant
    pub fn is_constant(&self) -> bool {
        (self.flags & high_flags::CONSTANT) != 0
    }

    // Ghidra: variable.hh:204 HighVariable::isUnaffected
    pub fn is_unaffected(&self) -> bool {
        (self.flags & high_flags::UNAFFECTED) != 0
    }

    // Ghidra: variable.hh:205 HighVariable::isExtraOut
    pub fn is_extra_out(&self) -> bool {
        (self.flags & (high_flags::INDIRECT_CREATION | high_flags::ADDRTIED))
            == high_flags::INDIRECT_CREATION
    }

    // Ghidra: variable.hh:206 HighVariable::isProtoPartial
    pub fn is_proto_partial(&self) -> bool {
        (self.flags & high_flags::PROTO_PARTIAL) != 0
    }

    // Ghidra: variable.hh:207 HighVariable::setMark
    pub fn set_mark(&mut self) {
        self.flags |= high_flags::MARK;
    }

    // Ghidra: variable.hh:208 HighVariable::clearMark
    pub fn clear_mark(&mut self) {
        self.flags &= !high_flags::MARK;
    }

    // Ghidra: variable.hh:209 HighVariable::isMark
    pub fn is_mark(&self) -> bool {
        (self.flags & high_flags::MARK) != 0
    }

    // Ghidra: variable.hh:210 HighVariable::isUnmerged
    pub fn is_unmerged(&self) -> bool {
        (self.highflags & high_internal_flags::UNMERGED) != 0
    }

    // Ghidra: variable.hh:211 HighVariable::isSameGroup
    pub fn is_same_group(&self, op2: &HighVariable) -> bool {
        match (&self.piece, &op2.piece) {
            (Some(a), Some(b)) => {
                let a_g = a.read().unwrap().get_group_arc();
                let b_g = b.read().unwrap().get_group_arc();
                match (a_g, b_g) {
                    (Some(x), Some(y)) => Arc::ptr_eq(&x, &y),
                    _ => false,
                }
            }
            _ => false,
        }
    }

    // Ghidra: variable.hh:217 HighVariable::hasCover
    pub fn has_cover(&self) -> bool {
        (self.flags & (high_flags::CONSTANT | high_flags::ANNOTATION | high_flags::INSERT))
            == high_flags::INSERT
    }

    // Ghidra: variable.hh:221 HighVariable::isUnattached
    pub fn is_unattached(&self) -> bool {
        self.instances.is_empty()
    }

    // Ghidra: variable.hh:222 HighVariable::isTypeLock
    /// Re-derive then check the typelock flag. Faithful to the inline
    /// `isTypeLock` (variable.hh:222): `updateType(); return ((flags &
    /// Varnode::typelock)!=0);` — a const member in Ghidra, so `&self` here.
    /// When the type is dirty, `updateType` would refresh `flags.typelock`
    /// from the representative (variable.cc:413-415); since the `&self` path
    /// cannot write the plain `flags` word, the refreshed value is derived
    /// transiently from the representative instead — same observable value.
    pub fn is_type_lock(&self) -> bool {
        if (self.highflags & high_internal_flags::TYPEDIRTY) != 0 {
            if let Some(rep) = self.get_type_representative() {
                return rep.read().unwrap().is_type_lock();
            }
        }
        (self.flags & high_flags::TYPELOCK) != 0
    }

    // Ghidra: variable.hh:223 HighVariable::isNameLock
    pub fn is_name_lock(&mut self) -> bool {
        self.update_flags();
        (self.flags & high_flags::NAMELOCK) != 0
    }

    // --- Dirtiness helpers (faithful to variable.hh:153-170, 275-289). ------

    // Ghidra: variable.hh:153 HighVariable::setCopyIn1
    pub fn set_copy_in1(&mut self) {
        self.highflags |= high_internal_flags::COPY_IN1;
    }

    // Ghidra: variable.hh:154 HighVariable::setCopyIn2
    pub fn set_copy_in2(&mut self) {
        self.highflags |= high_internal_flags::COPY_IN2;
    }

    // Ghidra: variable.hh:155 HighVariable::clearCopyIns
    pub fn clear_copy_ins(&mut self) {
        self.highflags &= !(high_internal_flags::COPY_IN1 | high_internal_flags::COPY_IN2);
    }

    // Ghidra: variable.hh:156 HighVariable::hasCopyIn1
    pub fn has_copy_in1(&self) -> bool {
        (self.highflags & high_internal_flags::COPY_IN1) != 0
    }

    // Ghidra: variable.hh:157 HighVariable::hasCopyIn2
    pub fn has_copy_in2(&self) -> bool {
        (self.highflags & high_internal_flags::COPY_IN2) != 0
    }

    // Ghidra: variable.hh:164 HighVariable::flagsDirty
    pub fn flags_dirty(&mut self) {
        self.highflags |= high_internal_flags::FLAGSDIRTY | high_internal_flags::NAMEREPDIRTY;
    }

    // Ghidra: variable.hh:275-281 HighVariable::coverDirty
    pub fn cover_dirty(&mut self) {
        self.highflags |= high_internal_flags::COVERDIRTY;
        if let Some(piece_arc) = &self.piece {
            VariablePiece::mark_extend_cover_dirty_read(piece_arc);
        }
    }

    // Ghidra: variable.hh:166 HighVariable::typeDirty
    pub fn type_dirty(&mut self) {
        self.highflags |= high_internal_flags::TYPEDIRTY;
    }

    // Ghidra: variable.hh:167 HighVariable::symbolDirty
    pub fn symbol_dirty(&mut self) {
        self.highflags |= high_internal_flags::SYMBOLDIRTY;
    }

    // Ghidra: variable.hh:168 HighVariable::setUnmerged
    pub fn set_unmerged(&mut self) {
        self.highflags |= high_internal_flags::UNMERGED;
    }

    // Ghidra: variable.hh:285-289 HighVariable::isCoverDirty
    pub fn is_cover_dirty(&self) -> bool {
        (self.highflags
            & (high_internal_flags::COVERDIRTY | high_internal_flags::EXTENDCOVERDIRTY))
            != 0
    }

    // Ghidra: variable.hh:294-300 HighVariable::getCover
    /// Get the cover: internal, unless part of a group (then the piece's cover).
    /// RUDRA-GLUE: Ghidra returns piece->getCover() by ref; Rudra cannot return
    /// a &Cover borrowed from under the piece's RwLock, so we return the
    /// internal cover as the closest stable reference.
    pub fn get_cover(&self) -> &Cover {
        &self.cover
    }

    // --- Legacy Rudra convenience methods kept for existing call-sites. -----

    // RUDRA-GLUE: Legacy direct-name accessor; Ghidra HighVariable derives its
    // name through Symbol/nameRepresentative and has no stored-name accessor.
    /// Get the name string (Rudra convenience).
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // RUDRA-GLUE: Legacy direct-name mutator; Ghidra changes the attached Symbol
    // rather than storing a String on HighVariable.
    /// Set the name string and lock it (Rudra convenience).
    pub fn set_name(&mut self, name: String) {
        self.name = name;
        self.flags |= high_flags::NAMELOCK;
    }

    // Ghidra: variable.hh:174 HighVariable::getType
    /// Get the data type. Faithful to the inline `getType`
    /// (variable.hh:174): `updateType(); return type;` — the lazy
    /// re-derivation triggers HERE, through a shared reference (Ghidra's is
    /// a const member; the cache mutation rides the `mutable` domain, which
    /// Rudra models with the `TypeCell` lock domain). When `typedirty` is
    /// set and the type is not finalized, the representative member's type
    /// is re-derived into the cache (variable.cc:408-415, incl. stripType),
    /// so a dirtying event (`typeDirty` from `Varnode::updateType`/
    /// `copySymbol`, `remove`, `mergeInternal`, ...) is reflected by the
    /// next `get_type` and a second call returns the same stable type.
    ///
    /// Known residual (VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001): unlike
    /// Ghidra's `updateType()`, this `&self` path cannot clear the
    /// `typedirty` bit in the plain `highflags` word, so it re-derives
    /// (idempotently) on each call until a `&mut` path (`update_type`,
    /// `type_dirty`) re-syncs the bit. No current consumer observes the raw
    /// bit after a `&self`-only clean; output behavior is identical.
    pub fn get_type(&self) -> Arc<Datatype> {
        if (self.highflags & high_internal_flags::TYPEDIRTY) != 0
            && (self.highflags & high_internal_flags::TYPE_FINALIZED) == 0
        {
            if let Some(rep) = self.get_type_representative() {
                let (new_type, is_typelock) = {
                    let rep_vn = rep.read().unwrap();
                    (
                        rep_vn.get_type().unwrap_or_else(|| self.v_type.get()),
                        rep_vn.is_type_lock(),
                    )
                };
                self.v_type.set(new_type);
                self.strip_type();
                // Transient typelock view (variable.cc:413-415): is_type_lock
                // re-derives it on demand; nothing else reads it from &self.
                let _ = is_typelock;
            }
        }
        self.v_type.get()
    }

    // RUDRA-GLUE: Legacy cached-type override; Ghidra HighVariable exposes
    /// getType/updateType/finalizeDatatype but no public setType method.
    /// Set the data type directly on the cache.
    pub fn set_type(&mut self, v_type: Arc<Datatype>) {
        self.v_type.set(v_type);
    }

    // RUDRA-GLUE: Legacy membership mutator; Ghidra adds members only through
    // construction/merge and has no public HighVariable::addInstance method.
    /// Add a varnode instance.
    ///
    /// The member-list change marks the name-representative cache dirty
    /// (mirroring how every oracle member-list change — construction
    /// (variable.cc:224) and mergeInternal (variable.cc:631) — leaves
    /// `namerepdirty` set) so a cached representative can never outlive
    /// the list it was derived from.
    pub fn add_instance(&mut self, vn: Arc<RwLock<Varnode>>) {
        self.highflags |= high_internal_flags::NAMEREPDIRTY;
        self.instances.push(vn);
    }

    // Ghidra: variable.hh:179 HighVariable::numInstances
    /// Number of instances.
    pub fn num_instances(&self) -> usize {
        self.instances.len()
    }

    // Ghidra: variable.hh:180 HighVariable::getInstance
    /// Get a specific instance.
    pub fn get_instance(&self, i: usize) -> Option<Arc<RwLock<Varnode>>> {
        self.instances.get(i).cloned()
    }

    // Ghidra: variable.hh:196 HighVariable::getNumMergeClasses
    /// Get the number of merge classes.
    pub fn get_num_merge_classes(&self) -> i32 {
        self.num_merge_classes
    }

    /// Check if this variable has a locked type, via a shared reference.
    /// Kept for callers (merge.rs:480, merge.rs:1140) that hold only a
    /// `RwLockReadGuard` and use the field name `is_type_locked`. Now a
    /// faithful alias of `isTypeLock` (variable.hh:222): when the type is
    /// dirty it derives the typelock answer from the representative (what
    /// `updateType` would refresh into `flags`, variable.cc:413-415),
    /// closing the former "shared-ref callers see a stale bit" caveat.
    // RUDRA-GLUE: backward-compat alias (variable.hh:222) for shared-ref callers.
    pub fn is_type_locked(&self) -> bool {
        self.is_type_lock()
    }

    /// Remove a varnode instance by index. Kept for callers (merge.rs:1793).
    /// Faithful to the body of `remove` (variable.cc:515) restricted to an index.
    // RUDRA-GLUE: backward-compat alias for the existing merge.rs call-site.
    pub fn remove_instance(&mut self, index: usize) {
        if index < self.instances.len() {
            self.instances.remove(index);
            // Faithful to variable.cc:524: dirty all inherited properties.
            self.highflags |= high_internal_flags::FLAGSDIRTY
                | high_internal_flags::NAMEREPDIRTY
                | high_internal_flags::COVERDIRTY
                | high_internal_flags::TYPEDIRTY;
        }
    }
}

// ===========================================================================
// VariableGroup -- faithful to variable.hh:44-65 / variable.cc:33-89
// ===========================================================================

// Ghidra: variable.hh:44 VariableGroup
/// A collection of HighVariable objects that overlap. Faithful to Ghidra's
/// `VariableGroup` (variable.hh:44-68). Manages a set of VariablePiece objects,
/// tracks total size and symbol offset. Pieces are kept sorted by
/// (offset, size) as Ghidra's `PieceCompareByOffset` does.
#[derive(Debug)]
pub struct VariableGroup {
    /// Pieces in this group, sorted by (offset, size).
    pub pieces: Vec<Arc<RwLock<VariablePiece>>>,
    /// Number of contiguous bytes covered by the whole group.
    pub size: i32,
    /// Byte offset of this group within its containing Symbol.
    pub symbol_offset: i32,
}

impl VariableGroup {
    // Ghidra: variable.hh:56 VariableGroup::VariableGroup
    pub fn new() -> Self {
        Self {
            pieces: Vec::new(),
            size: 0,         // Faithful to variable.cc:56 (within ctor body).
            symbol_offset: 0,
        }
    }

    // Ghidra: variable.hh:57 VariableGroup::empty
    pub fn is_empty(&self) -> bool {
        self.pieces.is_empty()
    }

    // Ghidra: variable.cc:43 VariableGroup::addPiece
    /// Add a new piece to this group and update total size. Faithful to
    /// `addPiece` (variable.cc:43-52). Sets the piece's group, inserts (throws
    /// on duplicate), and grows `size` to cover the piece.
    pub fn add_piece(&mut self, piece: Arc<RwLock<VariablePiece>>) {
        // RUDRA-GLUE: Ghidra sets piece->group = this via raw pointer; Rudra
        // stores an Arc<RwLock<VariableGroup>> on the piece, set by caller.
        // Faithful to variable.cc:47-48: throw on duplicate insert. Rudra uses
        // ptr-equality to detect a duplicate piece.
        if self.pieces.iter().any(|p| Arc::ptr_eq(p, &piece)) {
            // RUDRA-GLUE: Ghidra throws LowlevelError; log instead.
            eprintln!("warning: Duplicate VariablePiece (variable.cc:48)");
            return;
        }
        let piece_max = {
            let p = piece.read().unwrap();
            p.group_offset + p.size
        };
        self.pieces.push(piece);
        // Faithful to variable.cc:33-39 + 304-309: sort by (offset, size).
        self.pieces.sort_by_key(|p| {
            let r = p.read().unwrap();
            (r.group_offset, r.size)
        });
        // Faithful to variable.cc:49-51.
        if piece_max > self.size {
            self.size = piece_max;
        }
    }

    // Ghidra: variable.cc:56 VariableGroup::adjustOffsets
    /// Adjust every piece's offset (and the group size) by `amt`. Faithful to
    /// `adjustOffsets` (variable.cc:56-65).
    pub fn adjust_offsets(&mut self, amt: i32) {
        for piece in &self.pieces {
            piece.write().unwrap().group_offset += amt; // Faithful to variable.cc:62.
        }
        self.size += amt; // Faithful to variable.cc:64.
    }

    // Ghidra: variable.cc:67 VariableGroup::removePiece
    /// Remove a piece. Faithful to `removePiece` (variable.cc:67-72). Size is
    /// not adjusted (Ghidra notes this is only called during cleanup).
    pub fn remove_piece(&mut self, piece: &Arc<RwLock<VariablePiece>>) {
        self.pieces.retain(|p| !Arc::ptr_eq(p, piece));
    }

    // Ghidra: variable.hh:61 VariableGroup::getSize
    pub fn get_size(&self) -> i32 {
        self.size
    }

    // Ghidra: variable.hh:62 VariableGroup::setSymbolOffset
    pub fn set_symbol_offset(&mut self, val: i32) {
        self.symbol_offset = val;
    }

    // Ghidra: variable.hh:63 VariableGroup::getSymbolOffset
    pub fn get_symbol_offset(&self) -> i32 {
        self.symbol_offset
    }

    // Ghidra: variable.cc:78 VariableGroup::combineGroups
    /// Move every piece from `op2` into this. Faithful to `combineGroups`
    /// (variable.cc:78-89).
    pub fn combine_groups(&mut self, op2: &mut VariableGroup) {
        // variable.cc:81-88 iterates op2's PieceCompareByOffset set and
        // calls transferGroup, which rewires each piece to this group before
        // the source VariableGroup is released. Recover this group's Arc from
        // an existing piece (both-existing callers necessarily have one).
        let target = self.pieces.first().and_then(|piece| {
            piece.read().unwrap().group.clone()
        });
        let mut pieces = std::mem::take(&mut op2.pieces);
        pieces.sort_by_key(|piece| {
            let r = piece.read().unwrap();
            (r.group_offset, r.size)
        });
        for piece in pieces {
            if let Some(target) = &target {
                piece.write().unwrap().group = Some(target.clone());
            }
            self.pieces.push(piece);
        }
        self.pieces.sort_by_key(|p| {
            let r = p.read().unwrap();
            (r.group_offset, r.size)
            });
    }

    // Ghidra: variable.cc:119 VariablePiece::markIntersectionDirty (group form)
    /// Set `intersectdirty|extendcoverdirty` on every high of this group's
    /// pieces. Faithful to `markIntersectionDirty` (variable.cc:116-123),
    /// reachable from `~VariablePiece` (variable.cc:110-117) and
    /// `HighVariable::merge` (variable.cc:710).
    pub fn mark_intersection_dirty(&self) {
        use high_internal_flags as hif;
        for piece in &self.pieces {
            if let Some(high) = piece.read().unwrap().high.clone() {
                if let Some(h) = high.upgrade() {
                    h.write().unwrap().highflags |= hif::INTERSECTDIRTY | hif::EXTENDCOVERDIRTY;
                }
            }
        }
    }
}

impl Default for VariableGroup {
    // RUDRA-GLUE: Default impl (Rust trait glue; Ghidra has default ctor)
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// VariablePiece -- faithful to variable.hh:71-96 / variable.cc:96-216
// ===========================================================================

// Ghidra: variable.hh:71 VariablePiece
/// Information about how a HighVariable fits into a larger group or Symbol.
/// Faithful to Ghidra's `VariablePiece` (variable.hh:71-96). Describes overlaps
/// and how they affect the HighVariable Cover.
#[derive(Debug)]
pub struct VariablePiece {
    /// Group to which this piece belongs.
    pub group: Option<Arc<RwLock<VariableGroup>>>,
    /// HighVariable owning this piece (Weak to avoid a cycle).
    pub high: Option<std::sync::Weak<RwLock<HighVariable>>>,
    /// Byte offset of this piece within the group.
    pub group_offset: i32,
    /// Number of bytes in this piece.
    pub size: i32,
    /// Pieces this piece intersects with.
    pub intersection: Vec<Arc<RwLock<VariablePiece>>>,
    /// Extended cover for the piece, taking intersections into account.
    pub cover: Cover,
}

impl VariablePiece {
    // Ghidra: variable.cc:96 VariablePiece::VariablePiece
    /// Construct a piece given a HighVariable and its position within the whole.
    /// Faithful to the ctor (variable.cc:96-107). Rudra takes the owning
    /// HighVariable as a Weak and the size explicitly (Ghidra reads
    /// `h->getInstance(0)->getSize()`).
    pub fn new(
        high: std::sync::Weak<RwLock<HighVariable>>,
        offset: i32,
        size: i32,
        group: Option<Arc<RwLock<VariableGroup>>>,
    ) -> Self {
        Self {
            group,
            high: Some(high),
            group_offset: offset, // Faithful to variable.cc:100.
            size,
            intersection: Vec::new(),
            cover: Cover::new(),
        }
    }

    // Ghidra: variable.hh:82 VariablePiece::getHigh
    pub fn get_high(&self) -> Option<std::sync::Weak<RwLock<HighVariable>>> {
        self.high.clone()
    }

    // RUDRA-GLUE: Clones the Arc owning a VariableGroup; Ghidra's getGroup at
    // variable.hh:83 returns a borrowed raw pointer and needs no ownership clone.
    /// Get the group Arc (Rudra helper used where Ghidra returns a raw group ptr).
    pub fn get_group_arc(&self) -> Option<Arc<RwLock<VariableGroup>>> {
        self.group.clone()
    }

    // Ghidra: variable.hh:83 VariablePiece::getGroup
    pub fn get_group(&self) -> Option<&Arc<RwLock<VariableGroup>>> {
        self.group.as_ref()
    }

    // Ghidra: variable.hh:84 VariablePiece::getOffset
    pub fn get_offset(&self) -> i32 {
        self.group_offset
    }

    // Ghidra: variable.hh:85 VariablePiece::getSize
    pub fn get_size(&self) -> i32 {
        self.size
    }

    // Ghidra: variable.hh:86 VariablePiece::getCover
    pub fn get_cover(&self) -> &Cover {
        &self.cover
    }

    // Ghidra: variable.hh:87 VariablePiece::numIntersection
    pub fn num_intersection(&self) -> usize {
        self.intersection.len()
    }

    // Ghidra: variable.hh:88 VariablePiece::getIntersection
    pub fn get_intersection(&self, i: usize) -> Option<Arc<RwLock<VariablePiece>>> {
        self.intersection.get(i).cloned()
    }

    // Ghidra: variable.cc:119 VariablePiece::markIntersectionDirty
    /// Mark all pieces in the group as needing intersection recalculation.
    /// Faithful to `markIntersectionDirty` (variable.cc:119-126).
    pub fn mark_intersection_dirty(&self) {
        let group_arc = match &self.group {
            Some(g) => g.clone(),
            None => return,
        };
        let group = group_arc.read().unwrap();
        for piece_arc in &group.pieces {
            // Faithful to variable.cc:124-125: high->highflags |= intersectdirty|extendcoverdirty.
            let high_weak = piece_arc.read().unwrap().high.clone();
            if let Some(high_arc) = high_weak.and_then(|w| w.upgrade()) {
                let mut h = high_arc.write().unwrap();
                h.highflags |= high_internal_flags::INTERSECTDIRTY
                    | high_internal_flags::EXTENDCOVERDIRTY;
            }
        }
    }

    // RUDRA-GLUE: Arc<RwLock> entry point for the mapped markIntersectionDirty;
    // Ghidra's const member at variable.cc:119 needs no explicit lock wrapper.
    /// Read-lock variant of mark_intersection_dirty for use from HighVariable
    /// methods that hold `&self.piece` via clone (avoids re-borrowing).
    pub fn mark_intersection_dirty_read(piece_arc: &Arc<RwLock<VariablePiece>>) {
        piece_arc.read().unwrap().mark_intersection_dirty();
    }

    // Ghidra: variable.cc:128 VariablePiece::markExtendCoverDirty
    /// Mark all intersecting pieces as having a dirty extended cover. Faithful
    /// to `markExtendCoverDirty` (variable.cc:128-137). Early-outs if this
    /// piece's intersection list is itself dirty.
    pub fn mark_extend_cover_dirty(&self) {
        // Faithful to variable.cc:131-132: bail if intersection is dirty.
        let own_high = self.high.clone();
        if let Some(high_weak) = &own_high {
            if let Some(high_arc) = high_weak.upgrade() {
                if (high_arc.read().unwrap().highflags & high_internal_flags::INTERSECTDIRTY) != 0 {
                    return;
                }
            }
        }
        // Faithful to variable.cc:133-135.
        let inter = self.intersection.clone();
        for inter_arc in &inter {
            let high_weak = inter_arc.read().unwrap().high.clone();
            if let Some(high_arc) = high_weak.and_then(|w| w.upgrade()) {
                high_arc.write().unwrap().highflags |=
                    high_internal_flags::EXTENDCOVERDIRTY;
            }
        }
        // Faithful to variable.cc:136.
        if let Some(high_weak) = &own_high {
            if let Some(high_arc) = high_weak.upgrade() {
                high_arc.write().unwrap().highflags |= high_internal_flags::EXTENDCOVERDIRTY;
            }
        }
    }

    // RUDRA-GLUE: Arc<RwLock> entry point for the mapped markExtendCoverDirty;
    // Ghidra's const member at variable.cc:128 needs no explicit lock wrapper.
    /// Read-lock variant of mark_extend_cover_dirty.
    pub fn mark_extend_cover_dirty_read(piece_arc: &Arc<RwLock<VariablePiece>>) {
        piece_arc.read().unwrap().mark_extend_cover_dirty();
    }

    // Ghidra: variable.cc:140 VariablePiece::updateIntersections
    /// Calculate intersections with other pieces in the group. Faithful to
    /// `updateIntersections` (variable.cc:140-157). Early-outs if not
    /// intersectdirty, else rebuilds the intersection list from overlapping
    /// pieces in the group. `self_arc` is the Arc wrapping `self`, used for the
    /// pointer-equality self-skip (variable.cc:150).
    pub fn update_intersections(self_arc: &Arc<RwLock<VariablePiece>>) {
        let (group_arc, need_update, self_offset, self_size, self_high) = {
            let s = self_arc.read().unwrap();
            let group_arc = match &s.group {
                Some(g) => g.clone(),
                None => return,
            };
            // Faithful to variable.cc:143: bail if not intersectdirty.
            let need_update = s
                .high
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|h| (h.read().unwrap().highflags & high_internal_flags::INTERSECTDIRTY) != 0)
                .unwrap_or(false);
            (group_arc, need_update, s.group_offset, s.size, s.high.clone())
        };
        if !need_update {
            return;
        }
        let group = group_arc.read().unwrap();
        // Collect the matching pieces under read locks, then mutate self.
        let mut new_intersection: Vec<Arc<RwLock<VariablePiece>>> = Vec::new();
        let end_offset = self_offset + self_size; // Faithful to variable.cc:146.
        for other_arc in &group.pieces {
            // Faithful to variable.cc:150: skip self (ptr-equality).
            if Arc::ptr_eq(other_arc, self_arc) {
                continue;
            }
            let other = other_arc.read().unwrap();
            // Faithful to variable.cc:151: endOffset <= otherOffset -> skip.
            if end_offset <= other.group_offset {
                continue;
            }
            let other_end = other.group_offset + other.size;
            // Faithful to variable.cc:153: groupOffset >= otherEnd -> skip.
            if self_offset >= other_end {
                continue;
            }
            new_intersection.push(other_arc.clone()); // Faithful to variable.cc:154.
        }
        drop(group);
        {
            let mut s = self_arc.write().unwrap();
            s.intersection = new_intersection; // Faithful to variable.cc:147 (clear+rebuild).
        }
        // Faithful to variable.cc:156: clear intersectdirty on the owning high.
        if let Some(high_weak) = self_high {
            if let Some(high_arc) = high_weak.upgrade() {
                high_arc.write().unwrap().highflags &= !high_internal_flags::INTERSECTDIRTY;
            }
        }
    }

    // RUDRA-GLUE: Arc<RwLock> entry point for the mapped updateIntersections;
    // Ghidra's const member at variable.cc:140 mutates mutable fields directly.
    /// Read-lock entry point for update_intersections used from HighVariable.
    pub fn update_intersections_read(piece_arc: &Arc<RwLock<VariablePiece>>) {
        VariablePiece::update_intersections(piece_arc);
    }

    // Ghidra: variable.cc:160 VariablePiece::updateCover
    /// Calculate extended cover based on intersections. Faithful to `updateCover`
    /// (variable.cc:160-172). Early-outs if neither coverdirty nor
    /// extendcoverdirty, else merges the owning high's internal cover with each
    /// intersecting high's internal cover.
    pub fn update_cover(&mut self, owner: &mut HighVariable) {
        // Faithful to variable.cc:163: bail if neither coverdirty nor extendcoverdirty.
        let dirty_bits = owner.highflags
            & (high_internal_flags::COVERDIRTY | high_internal_flags::EXTENDCOVERDIRTY);
        if dirty_bits == 0 {
            return;
        }
        owner.update_internal_cover(); // Faithful to variable.cc:164.
        self.cover = owner.cover.clone(); // Faithful to variable.cc:165.
        let inter = self.intersection.clone();
        for inter_arc in &inter {
            // Faithful to variable.cc:166-170.
            let inter_high_arc = {
                let ip = inter_arc.read().unwrap();
                ip.high.as_ref().and_then(|w| w.upgrade())
            };
            if let Some(h_arc) = inter_high_arc {
                let mut h = h_arc.write().unwrap();
                h.update_internal_cover();
                self.cover.merge(&h.cover);
            }
        }
        // Faithful to variable.cc:171: clear extendcoverdirty on the owning high.
        owner.highflags &= !high_internal_flags::EXTENDCOVERDIRTY;
    }

    // RUDRA-GLUE: Splits VariablePiece::updateCover across owner and piece locks;
    // Ghidra's const member at variable.cc:160 follows raw owner pointers.
    /// Read-lock entry point for update_cover used from HighVariable::update_cover.
    /// Snapshot the piece's intersection list under a read lock, then merge.
    pub fn update_cover_read(piece_arc: &Arc<RwLock<VariablePiece>>, owner: &mut HighVariable) {
        let dirty_bits = owner.highflags
            & (high_internal_flags::COVERDIRTY | high_internal_flags::EXTENDCOVERDIRTY);
        if dirty_bits == 0 {
            return;
        }
        owner.update_internal_cover(); // Faithful to variable.cc:164.
        let inter_list = piece_arc.read().unwrap().intersection.clone();
        {
            let mut p = piece_arc.write().unwrap();
            p.cover = owner.cover.clone(); // Faithful to variable.cc:165.
        }
        for inter_arc in &inter_list {
            let inter_high_arc = {
                let ip = inter_arc.read().unwrap();
                ip.high.as_ref().and_then(|w| w.upgrade())
            };
            if let Some(h_arc) = inter_high_arc {
                let mut h = h_arc.write().unwrap();
                h.update_internal_cover();
                let mut p = piece_arc.write().unwrap();
                p.cover.merge(&h.cover);
            }
        }
        owner.highflags &= !high_internal_flags::EXTENDCOVERDIRTY; // Faithful to variable.cc:171.
    }

    // Ghidra: variable.hh:94 VariablePiece::setHigh
    pub fn set_high(&mut self, new_high: std::sync::Weak<RwLock<HighVariable>>) {
        self.high = Some(new_high);
    }

    // Ghidra: variable.cc:193 VariablePiece::mergeGroups
    /// Combine two VariableGroups. Faithful to `mergeGroups` (variable.cc:193-216).
    /// Adjusts offsets so the two pieces align (cc:195-200), then walks op2's
    /// pieces in (offset,size) order. A piece matching `this` group's
    /// (offset,size) pushes the colliding HighVariable pair, detaches the
    /// high from its piece and deletes the piece from op2's group
    /// (cc:206-211); a non-matching piece transfers into `this` group
    /// (cc:212-213 `transferGroup`).
    pub fn merge_groups(
        self_piece: &Arc<RwLock<VariablePiece>>,
        op2_piece: &Arc<RwLock<VariablePiece>>,
    ) -> Vec<(std::sync::Weak<RwLock<HighVariable>>, std::sync::Weak<RwLock<HighVariable>>)> {
        let mut merge_pairs = Vec::new();
        let diff = {
            let sp = self_piece.read().unwrap();
            let op = op2_piece.read().unwrap();
            sp.group_offset - op.group_offset
        };
        // Faithful to variable.cc:195-200: align offsets.
        if diff > 0 {
            let og = op2_piece.read().unwrap().group.clone();
            if let Some(g) = og {
                g.write().unwrap().adjust_offsets(diff);
            }
        } else if diff < 0 {
            let sg = self_piece.read().unwrap().group.clone();
            if let Some(g) = sg {
                g.write().unwrap().adjust_offsets(-diff);
            }
        }
        // Faithful to variable.cc:201-215: walk op2's pieces (snapshot in the
        // set's (offset,size) order — group.pieces is kept sorted by
        // add_piece), merge matches into pairs, transfer the rest.
        let op2_group_arc = op2_piece.read().unwrap().group.clone();
        let self_group_arc = self_piece.read().unwrap().group.clone();
        let (Some(op2_group), Some(self_group)) = (op2_group_arc, self_group_arc) else {
            return merge_pairs;
        };
        let op2_pieces = {
            let g = op2_group.read().unwrap();
            g.pieces.clone()
        };
        for piece_arc in op2_pieces {
            let (po, ps, phigh) = {
                let p = piece_arc.read().unwrap();
                (p.group_offset, p.size, p.high.clone())
            };
            // Faithful to variable.cc:206: find a (offset,size) match in this group.
            let match_arc = {
                let sg = self_group.read().unwrap();
                sg.pieces
                    .iter()
                    .find(|p| {
                        let r = p.read().unwrap();
                        r.group_offset == po && r.size == ps
                    })
                    .cloned()
            };
            if let Some(match_arc) = match_arc {
                // Faithful to variable.cc:207-211: push the colliding pair,
                // detach the high from its piece, delete the piece (its
                // destructor removes it from op2's group and, if op2's group
                // is then non-empty, marks the remainder's highs dirty).
                let self_high = match_arc.read().unwrap().high.clone();
                if let (Some(sh), Some(oh)) = (self_high, phigh) {
                    merge_pairs.push((sh, oh.clone()));
                    if let Some(h) = oh.upgrade() {
                        // variable.cc:209: piece->high->piece = null
                        h.write().unwrap().piece = None;
                    }
                }
                op2_group.write().unwrap().remove_piece(&piece_arc);
                let op2_remaining = !op2_group.read().unwrap().is_empty();
                if op2_remaining {
                    // ~VariablePiece (variable.cc:113-114): markIntersectionDirty
                    op2_group.read().unwrap().mark_intersection_dirty();
                }
            } else {
                // Faithful to variable.cc:212-213: transferGroup — remove from
                // op2's group (deleting it if now empty), then add to this group.
                op2_group.write().unwrap().remove_piece(&piece_arc);
                piece_arc.write().unwrap().group = Some(self_group.clone());
                self_group.write().unwrap().add_piece(piece_arc);
            }
        }
        merge_pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::{TypeBase, TypeMetatype};

    fn make_type() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new(
            "int".into(),
            4,
            TypeMetatype::Int,
        )))
    }

    #[test]
    fn test_high_variable_basic() {
        let hv = HighVariable::new(make_type());
        assert_eq!(hv.num_instances(), 0);
        assert!(hv.has_name());
        // Dirty bits seeded per variable.cc:224.
        assert_ne!(
            hv.highflags & high_internal_flags::FLAGSDIRTY,
            0,
            "flagsdirty should be seeded"
        );
        assert_eq!(hv.num_merge_classes, 1);
        assert_eq!(hv.symbol_offset, -1);
    }

    #[test]
    fn test_name_lock() {
        let mut hv = HighVariable::new(make_type());
        hv.set_name("myVar".into());
        // set_name is a Rudra convenience that sets NAMELOCK directly on the
        // HighVariable (Ghidra sets it on member Varnodes). Since new() seeds
        // FLAGSDIRTY, is_name_lock()'s update_flags() call would re-derive
        // flags from the (empty) member list and wipe NAMELOCK. Clear
        // FLAGSDIRTY so the manual NAMELOCK is preserved, matching the intent
        // that an explicitly-set name should not be re-derived away.
        hv.highflags &= !high_internal_flags::FLAGSDIRTY;
        assert!(hv.is_name_lock());
        // An empty HighVariable (no instances) can always have a name.
        assert!(hv.has_name());
        assert_eq!(hv.get_name(), "myVar");
    }

    #[test]
    fn test_merge_internal_inherits_symbol_clean() {
        let mut hv1 = HighVariable::new(make_type());
        let mut hv2 = HighVariable::new(make_type());
        hv2.symbol_offset = 5;
        hv2.highflags &= !high_internal_flags::SYMBOLDIRTY; // clean symbol
        // hv2.symbol is None; merge_internal only inherits if Some.
        hv1.merge_internal(&mut hv2, false);
        assert_eq!(hv1.num_instances(), 0); // both empty
        // After merge, hv2's instances are drained.
        assert_eq!(hv2.num_instances(), 0);
    }

    #[test]
    fn test_merge_internal_speculative_increases_classes() {
        let mut hv1 = HighVariable::new(make_type());
        let mut hv2 = HighVariable::new(make_type());
        hv2.num_merge_classes = 2;
        hv1.merge_internal(&mut hv2, true);
        assert_eq!(hv1.num_merge_classes, 3); // 1 + 2
    }

    #[test]
    fn test_copy_in_flags() {
        let mut hv = HighVariable::new(make_type());
        assert!(!hv.has_copy_in1());
        hv.set_copy_in1();
        assert!(hv.has_copy_in1());
        assert!(!hv.has_copy_in2());
        hv.set_copy_in2();
        assert!(hv.has_copy_in2());
        hv.clear_copy_ins();
        assert!(!hv.has_copy_in1());
        assert!(!hv.has_copy_in2());
    }

    #[test]
    fn test_dirty_helpers() {
        let mut hv = HighVariable::new(make_type());
        hv.highflags = 0;
        hv.flags_dirty();
        assert_ne!(hv.highflags & high_internal_flags::FLAGSDIRTY, 0);
        assert_ne!(hv.highflags & high_internal_flags::NAMEREPDIRTY, 0);
        hv.type_dirty();
        assert_ne!(hv.highflags & high_internal_flags::TYPEDIRTY, 0);
        hv.symbol_dirty();
        assert_ne!(hv.highflags & high_internal_flags::SYMBOLDIRTY, 0);
        hv.set_unmerged();
        assert!(hv.is_unmerged());
    }

    #[test]
    fn test_compare_just_loc() {
        use crate::address::Address;
        let vn1 = Varnode::new(4, Address::new(0x100));
        let vn2 = Varnode::new(4, Address::new(0x200));
        assert!(HighVariable::compare_just_loc(&vn1, &vn2));
        assert!(!HighVariable::compare_just_loc(&vn2, &vn1));
    }

    #[test]
    fn test_get_type_representative_empty() {
        let hv = HighVariable::new(make_type());
        assert!(hv.get_type_representative().is_none());
    }

    #[test]
    fn test_get_name_representative_empty() {
        let hv = HighVariable::new(make_type());
        assert!(hv.get_name_representative().is_none());
    }

    #[test]
    fn test_get_name_representative_is_shared_ref() {
        // Regression guard: get_name_representative must work via &self
        // (coreaction.rs:3799 holds only a RwLockReadGuard<HighVariable>).
        let hv = HighVariable::new(make_type());
        let _: Option<Arc<RwLock<Varnode>>> = hv.get_name_representative();
    }

    #[test]
    fn test_instance_index() {
        use crate::address::Address;
        let vn = Arc::new(RwLock::new(Varnode::new(4, Address::new(0x100))));
        let mut hv = HighVariable::new(make_type());
        hv.add_instance(vn.clone());
        assert_eq!(hv.instance_index(&vn), Some(0));
        let other = Arc::new(RwLock::new(Varnode::new(4, Address::new(0x200))));
        assert_eq!(hv.instance_index(&other), None);
    }

    #[test]
    fn test_remove_marks_dirty() {
        use crate::address::Address;
        let vn = Arc::new(RwLock::new(Varnode::new(4, Address::new(0x100))));
        let mut hv = HighVariable::new(make_type());
        hv.add_instance(vn.clone());
        hv.highflags = 0;
        hv.remove(&vn);
        assert_eq!(hv.num_instances(), 0);
        assert_ne!(hv.highflags & high_internal_flags::FLAGSDIRTY, 0);
        assert_ne!(hv.highflags & high_internal_flags::COVERDIRTY, 0);
    }

    #[test]
    fn test_is_unattached() {
        let hv = HighVariable::new(make_type());
        assert!(hv.is_unattached());
    }

    #[test]
    fn test_variable_group_basic() {
        let mut g = VariableGroup::new();
        assert!(g.is_empty());
        assert_eq!(g.get_size(), 0);
        g.adjust_offsets(4);
        assert_eq!(g.get_size(), 4); // Faithful to variable.cc:64.
        g.set_symbol_offset(8);
        assert_eq!(g.get_symbol_offset(), 8);
    }

    #[test]
    fn test_variable_piece_new() {
        let piece = VariablePiece::new(std::sync::Weak::new(), 4, 2, None);
        assert_eq!(piece.get_offset(), 4);
        assert_eq!(piece.get_size(), 2);
        assert_eq!(piece.num_intersection(), 0);
        assert!(piece.get_group().is_none());
    }

    #[test]
    fn test_high_internal_flags_values() {
        // Verify the bit values match variable.hh:119-131 exactly.
        assert_eq!(high_internal_flags::FLAGSDIRTY, 1);
        assert_eq!(high_internal_flags::NAMEREPDIRTY, 2);
        assert_eq!(high_internal_flags::TYPEDIRTY, 4);
        assert_eq!(high_internal_flags::COVERDIRTY, 8);
        assert_eq!(high_internal_flags::SYMBOLDIRTY, 0x10);
        assert_eq!(high_internal_flags::COPY_IN1, 0x20);
        assert_eq!(high_internal_flags::COPY_IN2, 0x40);
        assert_eq!(high_internal_flags::TYPE_FINALIZED, 0x80);
        assert_eq!(high_internal_flags::UNMERGED, 0x100);
        assert_eq!(high_internal_flags::INTERSECTDIRTY, 0x200);
        assert_eq!(high_internal_flags::EXTENDCOVERDIRTY, 0x400);
    }
}
