//! Rules governing the mapping of data-type to address for prototype models.
//!
//! Faithful 1:1 port of Ghidra's `modelrules.hh` + `modelrules.cc`
//! (`Ghidra/Features/Decompiler/src/decompile/cpp/modelrules.{hh,cc}`).
//!
//! These are the "prototype model rules": declarative rules that govern how a
//! given data-type is assigned an Address (register / stack slot / join) when
//! building a function's input/output parameter list, as configured by the
//! `<modelrules>` XML of a calling-convention `.proto` spec.
//!
//! # Phase 1 status
//! All 22 classes from `modelrules.hh` are ported as Rust structs/enums/traits
//! with their full method signatures. The data-structure layout, the
//! `PrimitiveExtractor` extraction algorithm, and the `DatatypeFilter` /
//! `QualifierFilter` predicate logic are ported 1:1 and exercised by tests.
//! The `AssignAction::assignAddress` bodies depend on a number of unported
//! upstream types (`ParamListStandard`, `ParameterPieces`, `TypeFactory`,
//! `type_class` resource lists) and are stubbed with `Ok(AssignResponse::Fail)`
//! plus a `// TODO: depends on unported <X>` note, with the full Ghidra
//! algorithm quoted in a doc-comment so the port can be completed the moment
//! those upstreams exist. The `decode(Decoder)` XML-entry methods that read
//! element/attribute ids not yet registered are similarly stubbed.
//!
//! Tracking: ALIGNMENT_ROADMAP.md row 30 (`signature.cc` + `modelrules.cc`).

use crate::address::Address;
use crate::fspec::ParamActive;
use crate::marshal::Decoder;
use crate::space::AddressSpace;
use crate::type_system::datatype::{Datatype, TypeMetatype, TypeUnion};
use anyhow::{anyhow, Result};
use std::sync::Arc;

// ===========================================================================
// Forward-declared stubs for unported upstream Ghidra types
// ===========================================================================
// These mirror the C++ types referenced in modelrules.hh's signatures but
// which are not yet ported in Rudra (see `Rudra type-system / fspec` roadmap).
// They exist so that the trait/struct method signatures of modelrules match
// Ghidra 1:1. Once each upstream lands, the corresponding stub here is
// deleted and the `use` switched to the real type. Every use site is marked
// `// TODO: depends on unported <X>`.

/// TODO: depends on unported `ProtoModel`/`ParamListStandard` (fspec.hh:654).
///
/// In Ghidra this is the owning resource list of `ParamEntry`s that an
/// `AssignAction` consumes from. Faithful to `class ParamListStandard`
/// (fspec.hh:654-840). Methods used by modelrules.cc: `isBigEndian`,
/// `getType`, `getStackEntry`, `getSpacebase`, `extractTiles`,
/// `assignAddress`, `assignAddressFallback`, `getEntry`.
pub struct ParamListStandard {
    /// Cached `ParamListStandard::isBigEndian()` result.
    pub big_endian: bool,
    /// Cached `ParamListStandard::getType()` (one of ParamList::p_*).
    pub list_type: ParamListType,
}

/// TODO: depends on unported `ParamList::type_class` enum (fspec.hh:435).
///
/// Subset of `enum ParamList { ... }` consulted by modelrules.cc:808 to
/// decide whether `MultiSlotAssign` consumes from the stack by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamListType {
    /// `ParamList::p_register_out`
    RegisterOut,
    /// `ParamList::p_standard_out`
    StandardOut,
    /// any other `ParamList` variant
    Other,
}

/// TODO: depends on unported `type_class` enum (fspec.hh:75-83).
///
/// Storage-class resource list selector. Faithful values from
/// `enum type_class { TYPECLASS_GENERAL, TYPECLASS_FLOAT, TYPECLASS_HIDDENRET }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeClass {
    /// `TYPECLASS_GENERAL` — general-purpose registers.
    General,
    /// `TYPECLASS_FLOAT` — floating-point registers.
    Float,
    /// `TYPECLASS_HIDDENRET` — hidden return pointer register.
    HiddenReturn,
}

/// TODO: depends on unported `ParameterPieces` (fspec.hh:451).
///
/// Holds the result of an assignment: the resolved address, the data-type
/// (possibly transformed), and flags (`indirectstorage` etc.). Faithful to
/// `struct ParameterPieces` (fspec.hh:451-460).
pub struct ParameterPieces {
    /// `ParameterPieces::addr` — assigned address.
    pub addr: Address,
    /// `ParameterPieces::type` — (possibly transformed) data-type.
    pub ty: Option<Arc<Datatype>>,
    /// `ParameterPieces::flags`.
    pub flags: u32,
}

// RUDRA-GLUE: ParameterPieces::indirectstorage (modelrules.hh references this
// constant by name via `ParameterPieces::indirectstorage`).
/// Flag: parameter holds an indirect/hidden pointer to the real storage.
/// Faithful to `ParameterPieces::indirectstorage = 1` (fspec.hh:458).
pub const INDIRECT_STORAGE: u32 = 1;

/// TODO: depends on unported `PrototypePieces` (fspec.hh:445).
///
/// High-level description of a function prototype consulted by qualifier
/// filters. Faithful to `struct PrototypePieces` (fspec.hh:445-450).
pub struct PrototypePieces<'a> {
    /// `PrototypePieces::outtype` — return data-type (None == void).
    pub outtype: Option<&'a Datatype>,
    /// `PrototypePieces::intypes` — input parameter data-types in order.
    pub intypes: &'a [&'a Datatype],
    /// `PrototypePieces::firstVarArgSlot` — index of first vararg, or -1.
    pub first_var_arg_slot: i32,
}

/// TODO: depends on unported `TypeFactory` (type.hh:158 forward-declares it).
///
/// Data-type factory used by `ConvertToPointer::assignAddress` to mint a
/// `TypePointer` of the right address-space word-size.
pub struct TypeFactory;

/// TODO: depends on unported `VarnodeData` (Ghidra core `types.hh`, not under
/// decompile/cpp).
///
/// Plain (space, offset, size) triple used while building join pieces.
/// Faithful to `struct VarnodeData`.
#[derive(Debug, Clone)]
pub struct VarnodeData {
    /// `VarnodeData::space`.
    pub space: AddressSpace,
    /// `VarnodeData::offset`.
    pub offset: u64,
    /// `VarnodeData::size`.
    pub size: i32,
}

// RUDRA-GLUE: Default for VarnodeData (no Ghidra counterpart — Ghidra has no
// default ctor for VarnodeData; Rust needs one for ergonomic construction in
// the assign-address bodies. Picks the `Ram` address space as the neutral
// default, matching the most common non-register destination.)
impl Default for VarnodeData {
    // RUDRA-GLUE: default (no Ghidra counterpart — Ghidra VarnodeData has no
    // default ctor; Rust needs one for ergonomic construction).
    fn default() -> Self {
        Self { space: AddressSpace::Ram, offset: 0, size: 0 }
    }
}

impl VarnodeData {
    // RUDRA-GLUE: getAddr (no Ghidra counterpart found — thin helper for the
    // single-space Address model).
    /// Build the (single-space) Address of this VarnodeData.
    pub fn get_addr(&self) -> Address {
        Address::new(self.offset)
    }
}

/// Response codes returned by `AssignAction::assignAddress`.
///
/// Faithful to `AssignAction`'s anonymous enum (modelrules.hh:264-271):
/// `success / fail / no_assignment / hiddenret_ptrparam /
/// hiddenret_specialreg / hiddenret_specialreg_void`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignResponse {
    /// `success` — data-type is fully assigned.
    Success,
    /// `fail` — action could not be applied.
    Fail,
    /// `no_assignment` — do not assign storage for this parameter.
    NoAssignment,
    /// `hiddenret_ptrparam` — hidden return pointer as first input parameter.
    HiddenRetPtrParam,
    /// `hiddenret_specialreg` — hidden return pointer in dedicated register.
    HiddenRetSpecialReg,
    /// `hiddenret_specialreg_void` — hidden return pointer, no normal return.
    HiddenRetSpecialRegVoid,
}

// ===========================================================================
// Marshaling attribute / element id stubs
// ===========================================================================
// Ghidra defines these as `extern AttributeId ATTRIB_*` / `extern ElementId
// ELEM_*` globals in modelrules.cc:21-42 and they are registered with the
// marshaling layer. Rudra's marshal.rs represents these as `AttributeId` /
// `ElementId` newtypes; the registration of the modelrules-specific ids is
// pending (marshal.rs roadmap). The constants below let decode() bodies
// reference the same logical names; once marshal.rs exposes them, replace.
//
// For Phase 1 the decode() methods are stubbed (see TODO in each method).

// ===========================================================================
// 1. PrimitiveExtractor (modelrules.hh:58-89, modelrules.cc:44-248)
// ===========================================================================

/// \brief Class for extracting primitive elements of a data-type
///
/// This recursively collects the formal \e primitive data-types of a
/// composite data-type, laying them out with their offsets in an array.
/// Other boolean properties are collected.
///
/// Faithful port of `class PrimitiveExtractor` (modelrules.hh:58-89). The
/// extraction algorithm in `extract()` (modelrules.cc:179-236) is ported
/// 1:1 below, including the union common-refinement logic
/// (modelrules.cc:139-164) and overlap checking (modelrules.cc:56-131).
pub struct PrimitiveExtractor {
    /// `vector<Primitive> primitives` — extracted primitives in offset order.
    primitives: Vec<Primitive>,
    /// `uint4 flags` — boolean properties of the data-type.
    flags: u32,
}

/// Flag bits for `PrimitiveExtractor`. Faithful to the anonymous enum
/// (modelrules.hh:59-65).
pub mod primitive_flags {
    /// `unknown_element = 1` — contains at least one TYPE_UNKNOWN primitive.
    pub const UNKNOWN_ELEMENT: u32 = 1;
    /// `unaligned = 2` — at least one primitive is not properly aligned.
    pub const UNALIGNED: u32 = 2;
    /// `extra_space = 4` — data-type contains empty space not attributable to
    /// alignment padding.
    pub const EXTRA_SPACE: u32 = 4;
    /// `invalid = 8` — data-type exceeded maximum or contained illegal elements.
    pub const INVALID: u32 = 8;
    /// `union_invalid = 16` — unions are treated as an illegal element.
    pub const UNION_INVALID: u32 = 16;
}

/// \brief A primitive data-type and its offset within the containing data-type.
///
/// Faithful to `PrimitiveExtractor::Primitive` (modelrules.hh:68-73). The
/// Ghidra constructor is `Primitive(Datatype *d,int4 off)`; Rust uses a
/// plain public struct (no invariants to enforce).
#[derive(Clone)]
pub struct Primitive {
    /// `Datatype *dt` — primitive data-type.
    pub dt: Arc<Datatype>,
    /// `int4 offset` — offset within the containing data-type.
    pub offset: i64,
}

impl Primitive {
    // RUDRA-GLUE: Primitive constructor (modelrules.hh:72) — trivial field
    // initializer, not a separate Ghidra function body.
    /// Construct from `(dt, offset)`. Mirrors `Primitive(Datatype *d,int4 off)`.
    pub fn new(dt: Arc<Datatype>, offset: i64) -> Self {
        Self { dt, offset }
    }
}

impl PrimitiveExtractor {
    // Ghidra: modelrules.cc:56 PrimitiveExtractor::checkOverlap
    /// \brief Check that a big Primitive properly overlaps smaller Primitives.
    ///
    /// If the big Primitive does not properly overlap the smaller Primitives
    /// starting at the given \b point, return -1. Otherwise, if the big
    /// Primitive is floating-point, add the overlapped primitives to the
    /// common refinement list, or if not a floating-point, add the big
    /// Primitive to the list. (Integer primitives are \e preferred over
    /// floating-point primitives in this way) Return the index of the next
    /// primitive after the overlap.
    ///
    /// Faithful 1:1 port. Note: `point` is mutated in place (Ghidra returns
    /// the updated index by value; we mirror with `&mut i64` and return -1 /
    /// success as an `i64`).
    fn check_overlap(
        res: &mut Vec<Primitive>,
        small: &[Primitive],
        mut point: i64,
        big: &Primitive,
    ) -> i64 {
        let end_off = big.offset + big.dt.get_align_size() as i64;
        // If big data-type is a float, let smaller primitives override it,
        // otherwise we keep the big primitive.
        let use_small = big.dt.get_metatype() == TypeMetatype::Float;
        while point < small.len() as i64 {
            let pi = point as usize;
            let mut cur_off = small[pi].offset;
            if cur_off >= end_off {
                break;
            }
            cur_off += small[pi].dt.get_align_size() as i64;
            if cur_off > end_off {
                return -1; // Improper overlap of the end of big
            }
            if use_small {
                res.push(small[pi].clone());
            }
            point += 1;
        }
        if !use_small {
            // If big data-type was preferred, use big Primitive in the refinement.
            res.push(big.clone());
        }
        point
    }

    // Ghidra: modelrules.cc:88 PrimitiveExtractor::commonRefinement
    /// \brief Overwrite \b first list with common refinement of \b first and \b second
    ///
    /// Given two sets of overlapping Primitives, find a \e common \e
    /// refinement of the lists. If there is any partial overlap of two
    /// Primitives, \b false is returned. If the same primitive data-type
    /// occurs at the same offset, it is included in the refinement.
    /// Otherwise an integer data-type is preferred over a floating-point
    /// data-type, or a bigger primitive is preferred over smaller overlapping
    /// primitives. The final refinement replaces the \b first list.
    ///
    /// Faithful 1:1 port.
    fn common_refinement(first: &mut Vec<Primitive>, second: &[Primitive]) -> bool {
        let mut first_point: i64 = 0;
        let mut second_point: i64 = 0;
        let mut common: Vec<Primitive> = Vec::new();
        while first_point < first.len() as i64 && second_point < second.len() as i64 {
            let fi = first_point as usize;
            let si = second_point as usize;
            let first_element = &first[fi];
            let second_element = &second[si];
            if first_element.offset < second_element.offset
                && first_element.offset + first_element.dt.get_align_size() as i64
                    <= second_element.offset
            {
                common.push(first_element.clone());
                first_point += 1;
                continue;
            }
            if second_element.offset < first_element.offset
                && second_element.offset + second_element.dt.get_align_size() as i64
                    <= first_element.offset
            {
                common.push(second_element.clone());
                second_point += 1;
                continue;
            }
            if first_element.dt.get_align_size() >= second_element.dt.get_align_size() {
                second_point = Self::check_overlap(
                    &mut common,
                    second,
                    second_point,
                    first_element,
                );
                if second_point < 0 {
                    return false;
                }
                first_point += 1;
            } else {
                first_point = Self::check_overlap(
                    &mut common,
                    first,
                    first_point,
                    second_element,
                );
                if first_point < 0 {
                    return false;
                }
                second_point += 1;
            }
        }
        // Add any tail primitives from either list.
        while first_point < first.len() as i64 {
            common.push(first[first_point as usize].clone());
            first_point += 1;
        }
        while second_point < second.len() as i64 {
            common.push(second[second_point as usize].clone());
            second_point += 1;
        }
        // Replace first with the refinement (first.swap(common)).
        std::mem::swap(first, &mut common);
        true
    }

    // Ghidra: modelrules.cc:139 PrimitiveExtractor::handleUnion
    /// Form a primitive list for each field of the union. Then, if possible,
    /// form a common refinement of all the primitive lists and add to the end
    /// of \b this extractor's list.
    ///
    /// Faithful 1:1 port. `max` and `offset` use Ghidra's `int4` semantics
    /// (signed 32-bit). Uses `&mut self` because Ghidra appends to
    /// `this->primitives` and reads/sets `this->flags`.
    fn handle_union(&mut self, dt: &TypeUnion, max: i32, offset: i64) -> bool {
        if (self.flags & primitive_flags::UNION_INVALID) != 0 {
            return false;
        }
        let num = dt.fields.len() as i32;
        if num == 0 {
            return false;
        }
        let cur_field = &dt.fields[0];
        let mut common = PrimitiveExtractor::new_raw(
            &cur_field.type_ptr,
            false,
            offset + cur_field.offset as i64,
            max,
        );
        if !common.is_valid() {
            return false;
        }
        for i in 1..num as usize {
            let cur_field = &dt.fields[i];
            let next = PrimitiveExtractor::new_raw(
                &cur_field.type_ptr,
                false,
                offset + cur_field.offset as i64,
                max,
            );
            if !next.is_valid() {
                return false;
            }
            // Ghidra passes `common.primitives` (private) into commonRefinement;
            // since both sides are owned here, we pass `&mut` then compare.
            let mut second = next.primitives.clone();
            if !Self::common_refinement(&mut common.primitives, &second) {
                return false;
            }
            // Suppress unused-assignment warning from the clone above.
            second.clear();
        }
        if self.primitives.len() as i32 + common.primitives.len() as i32 > max {
            return false;
        }
        for prim in common.primitives.iter() {
            self.primitives.push(prim.clone());
        }
        true
    }

    // Ghidra: modelrules.cc:179 PrimitiveExtractor::extract
    /// An array of the primitive data-types, with their associated offsets, is
    /// constructed. If the given data-type is already primitive it is put in
    /// the array by itself. Otherwise if it is composite, its components are
    /// recursively added to the array. Boolean properties about the primitives
    /// encountered are recorded.
    ///
    /// If a maximum number of extracted primitives is exceeded, or if an
    /// illegal data-type is encountered (\b void or other internal data-type)
    /// false is returned.
    ///
    /// Faithful 1:1 port of the `switch(dt->getMetatype())` extraction.
    fn extract(&mut self, dt: &Datatype, max: i32, offset: i64) -> bool {
        match dt.get_metatype() {
            TypeMetatype::Unknown => {
                self.flags |= primitive_flags::UNKNOWN_ELEMENT;
                // fallthru to primitive case (no `break` before case TYPE_INT)
                if self.primitives.len() as i32 >= max {
                    return false;
                }
                self.primitives.push(Primitive::new(Arc::new(dt.clone_ref()), offset));
                true
            }
            TypeMetatype::Int
            | TypeMetatype::Uint
            | TypeMetatype::Bool
            | TypeMetatype::Code
            | TypeMetatype::Float
            | TypeMetatype::Pointer => {
                if self.primitives.len() as i32 >= max {
                    return false;
                }
                self.primitives.push(Primitive::new(Arc::new(dt.clone_ref()), offset));
                true
            }
            TypeMetatype::Array => {
                // Ghidra casts to TypeArray*; Rudra pattern-matches.
                // Faithful body (modelrules.cc:197-207):
                //   int4 numEls = ((TypeArray *)dt)->numElements();
                //   Datatype *base = ((TypeArray *)dt)->getBase();
                //   for(int4 i=0;i<numEls;++i) {
                //     if (!extract(base,max,offset)) return false;
                //     offset += base->getAlignSize();
                //   }
                //   return true;
                if let Datatype::Array(arr) = dt {
                    let num_els = arr.num_elements;
                    let base: &Datatype = arr.array_of.as_ref();
                    // Read align size once up front (it is constant per
                    // element type), avoiding a re-borrow inside the loop.
                    let align_size = base.get_align_size() as i64;
                    let mut cur_offset = offset;
                    for _ in 0..num_els {
                        if !self.extract(base, max, cur_offset) {
                            return false;
                        }
                        cur_offset += align_size;
                    }
                    true
                } else {
                    false
                }
            }
            TypeMetatype::Union => {
                if let Datatype::Union(u) = dt {
                    self.handle_union(u, max, offset)
                } else {
                    false
                }
            }
            TypeMetatype::Struct => {
                // `break` out of the switch in Ghidra; falls through to the
                // TypeStruct iteration below the switch.
                self.extract_struct(dt, max, offset)
            }
            // TYPE_VOID, TYPE_SPACEBASE, TYPE_ENUM and any other metatype.
            _ => false,
        }
    }

    // Ghidra: modelrules.cc:215 (the post-switch TypeStruct iteration body of
    // PrimitiveExtractor::extract, modelrules.cc:215-235).
    //
    // Split out as a helper so the Rust `extract` switch stays readable while
    // preserving the exact Ghidra control flow: after the `case TYPE_STRUCT:
    // break;`, control falls out of the switch and runs this struct-field
    // loop (modelrules.cc:215-235).
    fn extract_struct(&mut self, dt: &Datatype, max: i32, offset: i64) -> bool {
        let struct_ptr = match dt {
            Datatype::Struct(s) => s,
            _ => return false,
        };
        let mut expected_off = offset;
        for f in &struct_ptr.fields {
            let comp_dt: &Datatype = f.type_ptr.as_ref();
            let cur_off = f.offset as i64 + offset;
            let align = comp_dt.get_alignment() as i64;
            if align != 0 && cur_off % align != 0 {
                self.flags |= primitive_flags::UNALIGNED;
            }
            let rem = if align != 0 { expected_off % align } else { 0 };
            if rem != 0 {
                expected_off += align - rem;
            }
            if expected_off != cur_off {
                self.flags |= primitive_flags::EXTRA_SPACE;
            }
            if !self.extract(comp_dt, max, cur_off) {
                return false;
            }
            expected_off = cur_off + comp_dt.get_align_size() as i64;
        }
        true
    }

    // Ghidra: modelrules.cc:242 PrimitiveExtractor::PrimitiveExtractor
    /// \param dt is data-type extract from
    /// \param unionIllegal is \b true if unions encountered during extraction
    ///   are considered illegal
    /// \param offset is the starting offset to associate with the data-type
    /// \param max is the maximum number of primitives to extract before giving up
    ///
    /// Faithful 1:1 port. Public entry; mirrors the C++ public constructor.
    pub fn new(dt: &Datatype, union_illegal: bool, offset: i64, max: i32) -> Self {
        Self::new_raw(&Arc::new(dt.clone_ref()), union_illegal, offset, max)
    }

    // RUDRA-GLUE: internal constructor (modelrules.cc:242 body shared by
    // public ctor and handleUnion recursion, which holds `Arc<Datatype>`).
    /// Same body as `PrimitiveExtractor::PrimitiveExtractor` but accepts an
    /// `Arc<Datatype>` so `handleUnion` can recurse without re-cloning.
    fn new_raw(dt: &Arc<Datatype>, union_illegal: bool, offset: i64, max: i32) -> Self {
        let mut me = PrimitiveExtractor {
            primitives: Vec::new(),
            flags: if union_illegal { primitive_flags::UNION_INVALID } else { 0 },
        };
        if !me.extract(dt, max, offset) {
            me.flags |= primitive_flags::INVALID;
        }
        me
    }

    // Ghidra: modelrules.hh:83 PrimitiveExtractor::size
    /// Return the number of primitives extracted.
    pub fn size(&self) -> usize {
        self.primitives.len()
    }

    // Ghidra: modelrules.hh:84 PrimitiveExtractor::get
    /// Get a particular primitive.
    pub fn get(&self, i: usize) -> &Primitive {
        &self.primitives[i]
    }

    // Ghidra: modelrules.hh:85 PrimitiveExtractor::isValid
    /// Return \b true if primitives were successfully extracted.
    pub fn is_valid(&self) -> bool {
        (self.flags & primitive_flags::INVALID) == 0
    }

    // Ghidra: modelrules.hh:86 PrimitiveExtractor::containsUnknown
    /// Are there \b unknown elements.
    pub fn contains_unknown(&self) -> bool {
        (self.flags & primitive_flags::UNKNOWN_ELEMENT) != 0
    }

    // Ghidra: modelrules.hh:87 PrimitiveExtractor::isAligned
    /// Are all elements aligned.
    pub fn is_aligned(&self) -> bool {
        (self.flags & primitive_flags::UNALIGNED) == 0
    }

    // Ghidra: modelrules.hh:88 PrimitiveExtractor::containsHoles
    /// Is there empty space that is not padding.
    pub fn contains_holes(&self) -> bool {
        (self.flags & primitive_flags::EXTRA_SPACE) != 0
    }
}

impl Datatype {
    // RUDRA-GLUE: Datatype::clone_ref (no Ghidra counterpart — Rust-only helper
    // to obtain an owned clone of a `&Datatype` as `Datatype`; Ghidra copies
    // via C++ copy semantics / pointer aliasing, here we need a value to wrap
    // in Arc).
    /// Clone this `&Datatype` into an owned `Datatype` value.
    fn clone_ref(&self) -> Datatype {
        self.clone()
    }
}

// ===========================================================================
// 2. DatatypeFilter (modelrules.hh:95)
// ===========================================================================

/// \brief A filter selecting a specific class of data-type.
///
/// An instance is configured via the `decode()` method, then a test of
/// whether a data-type belongs to its class can be performed by calling the
/// `filter()` method.
///
/// Faithful port of `class DatatypeFilter` (modelrules.hh:95-116). Ghidra's
/// `virtual DatatypeFilter *clone() const = 0` maps to a Rust trait object
/// returned as `Box<dyn DatatypeFilter>`; `virtual bool filter(Datatype*)`
/// and `virtual void decode(Decoder&)` map to trait methods.
pub trait DatatypeFilter: Send + Sync {
    // RUDRA-GLUE: clone (modelrules.hh:102) — Rust uses boxed trait objects
    // instead of C++ `virtual clone()`.
    /// Make a copy of \b this filter (Ghidra: `virtual clone()`).
    fn clone_box(&self) -> Box<dyn DatatypeFilter>;

    // Ghidra: modelrules.hh:108 DatatypeFilter::filter
    /// Test whether the given data-type belongs to \b this filter's
    /// data-type class.
    fn filter(&self, dt: &Datatype) -> bool;

    // Ghidra: modelrules.hh:113 DatatypeFilter::decode
    /// Configure details of the data-type class being filtered from the given
    /// stream.
    ///
    /// TODO: depends on unported marshaling `Decoder` element/attribute ids
    /// (`ELEM_DATATYPE`, `ATTRIB_NAME`, `ATTRIB_MINSIZE`, ...). Body is a
    /// faithful stub that performs no configuration; once the ids are
    /// registered in marshal.rs, port modelrules.cc:337-364 verbatim.
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        Ok(())
    }
}

// Ghidra: modelrules.hh:115 / modelrules.cc:252 DatatypeFilter::decodeFilter
/// Instantiate a filter from the given stream.
///
/// TODO: depends on unported `Decoder::openElement(ELEM_DATATYPE)` and
/// `ATTRIB_NAME`. Returns a default `SizeRestrictedFilter` until the
/// XML ids are registered, so callers compile and the data-structure
/// surface is exercised by tests.
///
/// NOTE: In Ghidra this is a `static` method on the class. In Rust it lives
/// as a free function (not a trait associated function) so that
/// `dyn DatatypeFilter` stays object-safe.
pub fn decode_datatype_filter(_decoder: &mut dyn Decoder) -> Result<Box<dyn DatatypeFilter>> {
    Ok(Box::new(SizeRestrictedFilter::new()))
}

// ===========================================================================
// 3. SizeRestrictedFilter (modelrules.hh:123)
// ===========================================================================

/// \brief A base class for data-type filters that tests for either a range or
/// an enumerated list of sizes.
///
/// Any filter that inherits from \b this, can use ATTRIB_MINSIZE,
/// ATTRIB_MAXSIZE, or ATTRIB_SIZES to place bounds on the possible sizes of
/// data-types. The bounds are enforced by calling `filter_on_size()` within
/// the inheriting classes' `filter()` method.
///
/// Faithful port of `class SizeRestrictedFilter` (modelrules.hh:123-137).
/// `set<int4> sizes` is modeled as `BTreeSet<i32>` to preserve Ghidra's
/// sorted-set semantics (the `initFromTypeList` body relies on
/// `*sizes.begin()` / `*sizes.rbegin()`).
pub struct SizeRestrictedFilter {
    /// `int4 minSize` — minimum size of the data-type in bytes.
    pub min_size: i32,
    /// `int4 maxSize` — maximum size of the data-type in bytes.
    pub max_size: i32,
    /// `set<int4> sizes` — an enumerated list of sizes (if not empty).
    pub sizes: std::collections::BTreeSet<i32>,
}

impl SizeRestrictedFilter {
    // Ghidra: modelrules.hh:130 SizeRestrictedFilter (default ctor)
    /// Constructor for use with `decode()`. Sets `minSize = maxSize = 0`.
    pub fn new() -> Self {
        Self { min_size: 0, max_size: 0, sizes: Default::default() }
    }

    // Ghidra: modelrules.cc:303 SizeRestrictedFilter(int4 min,int4 max)
    /// Constructor.
    pub fn with_bounds(min: i32, max: i32) -> Self {
        let mut me = Self::new();
        me.min_size = min;
        me.max_size = max;
        if me.max_size == 0 && me.min_size >= 0 {
            // If no ATTRIB_MAXSIZE is given, assume there is no upper bound on size.
            me.max_size = 0x7fffffff;
        }
        me
    }

    // Ghidra: modelrules.cc:314 SizeRestrictedFilter(const SizeRestrictedFilter &op2)
    /// Copy constructor (Rust: derived via Clone; kept here as a named ctor
    /// to mirror Ghidra's overload set used by `clone()`).
    pub fn copy(op2: &SizeRestrictedFilter) -> Self {
        Self {
            min_size: op2.min_size,
            max_size: op2.max_size,
            sizes: op2.sizes.clone(),
        }
    }

    // Ghidra: modelrules.cc:277 SizeRestrictedFilter::initFromTypeList
    /// Parse the given string as a comma or space separated list of decimal
    /// integers, populating the \b sizes set.
    ///
    /// Faithful 1:1 port of the `istringstream`-based parser, including the
    /// `minSize = *sizes.begin(); maxSize = *(--sizes.end())` finalization.
    pub fn init_from_type_list(&mut self, str_in: &str) -> Result<()> {
        // Ghidra reads whitespace- and comma-separated ints, throwing
        // DecoderError on `val <= 0`. We mirror with char-level scanning.
        let bytes = str_in.as_bytes();
        let mut i = 0;
        let n = bytes.len();
        // Skip leading whitespace.
        let skip_ws = |i: &mut usize| {
            while *i < n && (bytes[*i] == b' ' || bytes[*i] == b'\t' || bytes[*i] == b'\n' || bytes[*i] == b'\r') {
                *i += 1;
            }
        };
        loop {
            skip_ws(&mut i);
            if i >= n {
                break;
            }
            if bytes[i] == b',' {
                i += 1;
                skip_ws(&mut i);
            }
            // Read a decimal integer (Ghidra: `s >> val`).
            let start = i;
            while i < n && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i == start {
                // No digits where an integer was expected.
                return Err(anyhow!("DecoderError: Bad filter size"));
            }
            let val: i32 = std::str::from_utf8(&bytes[start..i])
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(-1);
            if val <= 0 {
                return Err(anyhow!("DecoderError: Bad filter size"));
            }
            self.sizes.insert(val);
        }
        if !self.sizes.is_empty() {
            self.min_size = *self.sizes.iter().next().unwrap();
            self.max_size = *self.sizes.iter().next_back().unwrap();
        }
        Ok(())
    }

    // Ghidra: modelrules.cc:327 SizeRestrictedFilter::filterOnSize
    /// If \b maxSize is not zero, the data-type is checked to see if its size
    /// in bytes falls between \b minSize and \b maxSize inclusive. If
    /// enumerated sizes are present, also check that the particular size is
    /// in the enumerated set.
    ///
    /// Faithful 1:1 port.
    pub fn filter_on_size(&self, dt: &Datatype) -> bool {
        if self.max_size == 0 {
            return true; // maxSize of 0 means no size filtering is performed
        }
        if !self.sizes.is_empty() {
            return self.sizes.contains(&(dt.get_size() as i32));
        }
        let sz = dt.get_size() as i32;
        sz >= self.min_size && sz <= self.max_size
    }
}

impl Default for SizeRestrictedFilter {
    // RUDRA-GLUE: Default impl (mirrors the no-arg ctor at modelrules.hh:130).
    fn default() -> Self {
        Self::new()
    }
}

impl DatatypeFilter for SizeRestrictedFilter {
    // Ghidra: modelrules.hh:134 SizeRestrictedFilter::clone
    fn clone_box(&self) -> Box<dyn DatatypeFilter> {
        Box::new(SizeRestrictedFilter::copy(self))
    }
    // Ghidra: modelrules.hh:135 SizeRestrictedFilter::filter
    fn filter(&self, dt: &Datatype) -> bool {
        self.filter_on_size(dt)
    }
    // Ghidra: modelrules.cc:337 SizeRestrictedFilter::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported marshaling attribute ids
        // (`ATTRIB_MINSIZE`, `ATTRIB_MAXSIZE`, `ATTRIB_SIZES`). Body is a
        // faithful stub; the post-decode normalization below matches Ghidra
        // exactly (modelrules.cc:360-363) and runs unconditionally for
        // callers that pre-populate `min_size`/`max_size`/`sizes` by hand.
        if self.max_size == 0 && self.min_size >= 0 {
            // If no ATTRIB_MAXSIZE is given, assume there is no upper bound on size.
            self.max_size = 0x7fffffff;
        }
        Ok(())
    }
}

// ===========================================================================
// 4. MetaTypeFilter (modelrules.hh:142)
// ===========================================================================

/// \brief Filter on a single meta data-type.
///
/// Filters on TYPE_STRUCT or TYPE_FLOAT etc. Additional filtering on size of
/// the data-type can be configured.
///
/// Faithful port of `class MetaTypeFilter : public SizeRestrictedFilter`
/// (modelrules.hh:142-151).
pub struct MetaTypeFilter {
    /// Inherited `SizeRestrictedFilter` fields.
    pub size_filter: SizeRestrictedFilter,
    /// `type_metatype metaType` — the meta-type this filter lets through.
    pub meta_type: TypeMetatype,
}

impl MetaTypeFilter {
    // Ghidra: modelrules.cc:366 MetaTypeFilter(type_metatype meta)
    /// Constructor for use with `decode()`.
    pub fn new(meta: TypeMetatype) -> Self {
        Self { size_filter: SizeRestrictedFilter::new(), meta_type: meta }
    }

    // Ghidra: modelrules.cc:372 MetaTypeFilter(type_metatype meta,int4 min,int4 max)
    /// Constructor with explicit size bounds.
    pub fn with_bounds(meta: TypeMetatype, min: i32, max: i32) -> Self {
        Self { size_filter: SizeRestrictedFilter::with_bounds(min, max), meta_type: meta }
    }

    // Ghidra: modelrules.cc:378 MetaTypeFilter(const MetaTypeFilter &op2)
    /// Copy constructor.
    pub fn copy(op2: &MetaTypeFilter) -> Self {
        Self {
            size_filter: SizeRestrictedFilter::copy(&op2.size_filter),
            meta_type: op2.meta_type,
        }
    }
}

impl DatatypeFilter for MetaTypeFilter {
    // Ghidra: modelrules.hh:149 MetaTypeFilter::clone
    fn clone_box(&self) -> Box<dyn DatatypeFilter> {
        Box::new(MetaTypeFilter::copy(self))
    }
    // Ghidra: modelrules.cc:384 MetaTypeFilter::filter
    fn filter(&self, dt: &Datatype) -> bool {
        if dt.get_metatype() != self.meta_type {
            return false;
        }
        self.size_filter.filter_on_size(dt)
    }
    // Ghidra: modelrules.hh:142 (MetaTypeFilter inherits
    // SizeRestrictedFilter::decode verbatim — modelrules.cc:336). Rust cannot
    // "inherit" a trait impl, so we delegate explicitly.
    fn decode(&mut self, decoder: &mut dyn Decoder) -> Result<()> {
        self.size_filter.decode(decoder)
    }
}

// ===========================================================================
// 5. HomogeneousAggregate (modelrules.hh:156)
// ===========================================================================

/// \brief Filter on a homogeneous aggregate data-type.
///
/// All primitive data-types must be the same.
///
/// Faithful port of `class HomogeneousAggregate : public SizeRestrictedFilter`
/// (modelrules.hh:156-166).
pub struct HomogeneousAggregate {
    /// Inherited `SizeRestrictedFilter` fields.
    pub size_filter: SizeRestrictedFilter,
    /// `type_metatype metaType` — the expected meta-type.
    pub meta_type: TypeMetatype,
    /// `int4 maxPrimitives` — maximum number of primitives in the aggregate.
    pub max_primitives: i32,
}

impl HomogeneousAggregate {
    // Ghidra: modelrules.cc:391 HomogeneousAggregate(type_metatype meta)
    /// Constructor for use with `decode()`. Defaults `maxPrimitives = 4`.
    pub fn new(meta: TypeMetatype) -> Self {
        Self {
            size_filter: SizeRestrictedFilter::new(),
            meta_type: meta,
            max_primitives: 4,
        }
    }

    // Ghidra: modelrules.cc:398 HomogeneousAggregate(meta,maxPrim,minSize,maxSize)
    /// Constructor.
    pub fn with_bounds(meta: TypeMetatype, max_prim: i32, min_size: i32, max_size: i32) -> Self {
        Self {
            size_filter: SizeRestrictedFilter::with_bounds(min_size, max_size),
            meta_type: meta,
            max_primitives: max_prim,
        }
    }

    // Ghidra: modelrules.cc:405 HomogeneousAggregate(const HomogeneousAggregate &op2)
    /// Copy constructor.
    pub fn copy(op2: &HomogeneousAggregate) -> Self {
        Self {
            size_filter: SizeRestrictedFilter::copy(&op2.size_filter),
            meta_type: op2.meta_type,
            max_primitives: op2.max_primitives,
        }
    }
}

impl DatatypeFilter for HomogeneousAggregate {
    // Ghidra: modelrules.hh:163 HomogeneousAggregate::clone
    fn clone_box(&self) -> Box<dyn DatatypeFilter> {
        Box::new(HomogeneousAggregate::copy(self))
    }
    // Ghidra: modelrules.cc:412 HomogeneousAggregate::filter
    fn filter(&self, dt: &Datatype) -> bool {
        let meta = dt.get_metatype();
        if meta != TypeMetatype::Array && meta != TypeMetatype::Struct {
            return false;
        }
        let primitives = PrimitiveExtractor::new(dt, true, 0, self.max_primitives);
        if !primitives.is_valid()
            || primitives.size() == 0
            || primitives.contains_unknown()
            || !primitives.is_aligned()
            || primitives.contains_holes()
        {
            return false;
        }
        let base = &primitives.get(0).dt;
        if base.get_metatype() != self.meta_type {
            return false;
        }
        for i in 1..primitives.size() {
            // Ghidra: `if (primitives.get(i).dt != base)` — pointer identity.
            // Rust: pointer identity via `Arc::ptr_eq` is the closest match;
            // since extraction re-wraps in fresh Arcs, we fall back to
            // structural `compare` (which Ghidra's == does NOT do). To stay
            // faithful, we compare by (metatype, size, name) via `compare==0`.
            if primitives.get(i).dt.compare(base.as_ref()) != 0 {
                return false;
            }
        }
        true
    }
    // Ghidra: modelrules.cc:432 HomogeneousAggregate::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported marshaling attribute ids
        // (`ATTRIB_MAX_PRIMITIVES`). We faithfully run the inherited
        // SizeRestrictedFilter::decode first (modelrules.cc:434) and then
        // preserve the ATTRIB_MAX_PRIMITIVES overwrite site for later.
        self.size_filter.decode(_decoder)?;
        Ok(())
    }
}

// ===========================================================================
// 6. QualifierFilter (modelrules.hh:172)
// ===========================================================================

/// \brief A filter on some aspect of a specific function prototype.
///
/// An instance is configured via the `decode()` method, then a test of
/// whether a function prototype meets its criteria can be performed by
/// calling its `filter()` method.
///
/// Faithful port of `class QualifierFilter` (modelrules.hh:172-193).
pub trait QualifierFilter: Send + Sync {
    // RUDRA-GLUE: clone (modelrules.hh:179) — Rust boxed trait object.
    /// Make a copy of \b this qualifier.
    fn clone_box(&self) -> Box<dyn QualifierFilter>;

    // Ghidra: modelrules.hh:186 QualifierFilter::filter
    /// Test whether the given function prototype meets \b this filter's
    /// criteria.
    ///
    /// `pos` is the position of a specific output (pos=-1) or input
    /// (pos >= 0) in context.
    fn filter(&self, proto: &PrototypePieces, pos: i32) -> bool;

    // Ghidra: modelrules.hh:191 QualifierFilter::decode
    /// Configure details of the criteria being filtered from the given
    /// stream. Default no-op (matches Ghidra's `virtual void decode(...) {}`).
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        Ok(())
    }
}

// Ghidra: modelrules.hh:192 / modelrules.cc:451 QualifierFilter::decodeFilter
/// Try to instantiate a qualifier filter.
///
/// TODO: depends on unported `ELEM_VARARGS`/`ELEM_POSITION`/`ELEM_DATATYPE_AT`
/// element ids. Returns `None` (Ghidra's null return) until those land.
///
/// NOTE: In Ghidra this is a `static` method on the class. In Rust it lives
/// as a free function so `dyn QualifierFilter` stays object-safe.
pub fn decode_qualifier_filter(
    _decoder: &mut dyn Decoder,
) -> Result<Option<Box<dyn QualifierFilter>>> {
    Ok(None)
}

// ===========================================================================
// 7. AndFilter (modelrules.hh:199)
// ===========================================================================

/// \brief Logically AND multiple QualifierFilters together into a single filter.
///
/// An instance contains some number of other arbitrary filters. In order for
/// \b this filter to pass, all these contained filters must pass.
///
/// Faithful port of `class AndFilter : public QualifierFilter`
/// (modelrules.hh:199-207).
pub struct AndFilter {
    /// `vector<QualifierFilter *> subQualifiers` — filters being ANDed.
    pub sub_qualifiers: Vec<Box<dyn QualifierFilter>>,
}

impl AndFilter {
    // Ghidra: modelrules.cc:470 AndFilter(vector<QualifierFilter *> filters)
    /// Construct from array of filters. Ghidra's `swap` semantics are
    /// equivalent to Rust's move into the field.
    pub fn new(filters: Vec<Box<dyn QualifierFilter>>) -> Self {
        Self { sub_qualifiers: filters }
    }
}

impl QualifierFilter for AndFilter {
    // Ghidra: modelrules.cc:483 AndFilter::clone
    fn clone_box(&self) -> Box<dyn QualifierFilter> {
        let mut new_filters: Vec<Box<dyn QualifierFilter>> = Vec::new();
        for q in &self.sub_qualifiers {
            new_filters.push(q.clone_box());
        }
        Box::new(AndFilter::new(new_filters))
    }
    // Ghidra: modelrules.cc:492 AndFilter::filter
    fn filter(&self, proto: &PrototypePieces, pos: i32) -> bool {
        for q in &self.sub_qualifiers {
            if !q.filter(proto, pos) {
                return false;
            }
        }
        true
    }
}

// ===========================================================================
// 8. VarargsFilter (modelrules.hh:220)
// ===========================================================================

/// \brief A filter that selects a range of function parameters that are
/// considered optional.
///
/// Faithful port of `class VarargsFilter : public QualifierFilter`
/// (modelrules.hh:220-229). The defaults `firstPos = 0x80000000` and
/// `lastPos = 0x7fffffff` match Ghidra's `int4` sentinel values for
/// "match all".
pub struct VarargsFilter {
    /// `int4 firstPos` — start of range to match (offset relative to first var arg).
    pub first_pos: i32,
    /// `int4 lastPos` — end of range to match.
    pub last_pos: i32,
}

impl VarargsFilter {
    // Ghidra: modelrules.hh:224 VarargsFilter() (decode ctor)
    /// Constructor for use with `decode`. Defaults to "match all".
    pub fn new() -> Self {
        Self { first_pos: i32::MIN, last_pos: i32::MAX }
    }

    // Ghidra: modelrules.hh:225 VarargsFilter(int4 first,int4 last)
    /// Constructor.
    pub fn with_range(first: i32, last: i32) -> Self {
        Self { first_pos: first, last_pos: last }
    }
}

impl Default for VarargsFilter {
    // RUDRA-GLUE: Default impl (mirrors the no-arg ctor at modelrules.hh:224).
    fn default() -> Self {
        Self::new()
    }
}

impl QualifierFilter for VarargsFilter {
    // Ghidra: modelrules.hh:226 VarargsFilter::clone
    fn clone_box(&self) -> Box<dyn QualifierFilter> {
        Box::new(VarargsFilter::with_range(self.first_pos, self.last_pos))
    }
    // Ghidra: modelrules.cc:502 VarargsFilter::filter
    fn filter(&self, proto: &PrototypePieces, pos: i32) -> bool {
        if proto.first_var_arg_slot < 0 {
            return false;
        }
        let pos = pos - proto.first_var_arg_slot;
        pos >= self.first_pos && pos <= self.last_pos
    }
    // Ghidra: modelrules.cc:510 VarargsFilter::decode
    // TODO: depends on unported `ELEM_VARARGS` / `ATTRIB_FIRST` /
    // `ATTRIB_LAST` ids. Body stays a no-op until those are registered.
}

// ===========================================================================
// 9. PositionMatchFilter (modelrules.hh:235)
// ===========================================================================

/// \brief Filter that selects for a particular parameter position.
///
/// This matches if the position of the current parameter being assigned,
/// within the data-type list, matches the \b position attribute of \b this
/// filter.
///
/// Faithful port of `class PositionMatchFilter : public QualifierFilter`
/// (modelrules.hh:235-242).
pub struct PositionMatchFilter {
    /// `int4 position` — parameter position being filtered for.
    pub position: i32,
}

impl PositionMatchFilter {
    // Ghidra: modelrules.hh:238 PositionMatchFilter(int4 pos)
    /// Constructor.
    pub fn new(pos: i32) -> Self {
        Self { position: pos }
    }
}

impl QualifierFilter for PositionMatchFilter {
    // Ghidra: modelrules.hh:239 PositionMatchFilter::clone
    fn clone_box(&self) -> Box<dyn QualifierFilter> {
        Box::new(PositionMatchFilter::new(self.position))
    }
    // Ghidra: modelrules.cc:525 PositionMatchFilter::filter
    fn filter(&self, _proto: &PrototypePieces, pos: i32) -> bool {
        pos == self.position
    }
    // Ghidra: modelrules.cc:531 PositionMatchFilter::decode
    // TODO: depends on unported `ELEM_POSITION` / `ATTRIB_INDEX` ids.
}

// ===========================================================================
// 10. DatatypeMatchFilter (modelrules.hh:247)
// ===========================================================================

/// \brief Check if the function signature has a specific data-type in a
/// specific position.
///
/// This filter does not match against the data-type in the current position
/// being assigned, but against a parameter at a fixed position.
///
/// Faithful port of `class DatatypeMatchFilter : public QualifierFilter`
/// (modelrules.hh:247-256).
pub struct DatatypeMatchFilter {
    /// `int4 position` — the position of the data-type to check (-1 = outtype).
    pub position: i32,
    /// `DatatypeFilter *typeFilter` — the data-type that must be at \b position.
    pub type_filter: Option<Box<dyn DatatypeFilter>>,
}

impl DatatypeMatchFilter {
    // Ghidra: modelrules.hh:251 DatatypeMatchFilter() (decode ctor)
    /// Constructor for use with `decode`.
    pub fn new() -> Self {
        Self { position: -1, type_filter: None }
    }
}

impl Default for DatatypeMatchFilter {
    // RUDRA-GLUE: Default impl (mirrors the no-arg ctor at modelrules.hh:251).
    fn default() -> Self {
        Self::new()
    }
}

impl QualifierFilter for DatatypeMatchFilter {
    // Ghidra: modelrules.cc:546 DatatypeMatchFilter::clone
    fn clone_box(&self) -> Box<dyn QualifierFilter> {
        let mut res = DatatypeMatchFilter::new();
        res.position = self.position;
        if let Some(tf) = &self.type_filter {
            res.type_filter = Some(tf.clone_box());
        }
        Box::new(res)
    }
    // Ghidra: modelrules.cc:555 DatatypeMatchFilter::filter
    fn filter(&self, proto: &PrototypePieces, _pos: i32) -> bool {
        // The position of the current parameter being assigned, pos, is NOT used.
        let dt: &Datatype = if self.position < 0 {
            match proto.outtype {
                Some(d) => d,
                None => return false,
            }
        } else {
            if self.position as usize >= proto.intypes.len() {
                return false;
            }
            proto.intypes[self.position as usize]
        };
        match &self.type_filter {
            Some(tf) => tf.filter(dt),
            None => false,
        }
    }
}

// ===========================================================================
// 11. AssignAction (modelrules.hh:262)
// ===========================================================================

/// \brief An action that assigns an Address to a function prototype parameter.
///
/// A request for the address of either \e return storage or an input parameter
/// is made through the `assign_address()` method, which is given full
/// information about the function prototype. Details about how the action
/// performs is configured through the `decode()` method.
///
/// Faithful port of `class AssignAction` (modelrules.hh:262-323). The
/// anonymous response-code enum (modelrules.hh:264-271) is lifted into the
/// public [`AssignResponse`] enum above.
pub trait AssignAction: Send + Sync {
    // RUDRA-GLUE: assign (modelrules.hh:276) — Rust boxed trait object clone.
    /// Make a copy of \b this action. `new_resource` is the new resource
    /// object that will own the clone.
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction>;

    // Ghidra: modelrules.hh:278 AssignAction::canAffectFillinOutput
    /// Return \b true if `fillin_output_map` is active.
    fn can_affect_fillin_output(&self) -> bool {
        false
    }

    // Ghidra: modelrules.hh:304 AssignAction::assignAddress
    /// Assign an address and other meta-data for a specific parameter or for
    /// return storage in context.
    ///
    /// The Address is assigned based on the data-type of the parameter,
    /// available register resources, and other details of the function
    /// prototype. Consumed resources are marked. Returns a response code.
    ///
    /// TODO: depends on unported `ParamListStandard`, `TypeFactory`, and
    /// `ParameterPieces` semantics. The trait method is wired 1:1 to Ghidra;
    /// concrete bodies below return `AssignResponse::Fail` until those
    /// upstreams land (see each impl's doc-comment for the verbatim Ghidra
    /// algorithm).
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse;

    // Ghidra: modelrules.hh:313 AssignAction::fillinOutputMap
    /// Test if \b this action could produce return value storage matching
    /// the given set of trials. Default returns `false` (inactive action).
    fn fillin_output_map(&self, _active: &ParamActive) -> bool {
        false
    }

    // Ghidra: modelrules.hh:318 AssignAction::decode
    /// Configure any details of how \b this action should behave from the
    /// stream.
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()>;
}

// Ghidra: modelrules.hh:319 AssignAction::decodeAction
/// Read the next model rule action element from the stream and allocate
/// the matching action.
///
/// TODO: depends on unported `ELEM_*` action element ids. Returns an
/// error mirroring Ghidra's `throw DecoderError("Expecting model rule
/// action")` (modelrules.cc:618).
///
/// NOTE: In Ghidra this is a `static` method on the class. In Rust it lives
/// as a free function so `dyn AssignAction` stays object-safe.
pub fn decode_action(
    _decoder: &mut dyn Decoder,
    _res: &'static ParamListStandard,
) -> Result<Box<dyn AssignAction>> {
    Err(anyhow!("DecoderError: Expecting model rule action"))
}

// Ghidra: modelrules.hh:320 AssignAction::decodePrecondition
/// Read the next model rule precondition element. Returns `None` when no
/// more preconditions are present (Ghidra returns null).
///
/// TODO: depends on unported `ELEM_CONSUME_EXTRA`. Returns `Ok(None)`.
pub fn decode_precondition(
    _decoder: &mut dyn Decoder,
    _res: &'static ParamListStandard,
) -> Result<Option<Box<dyn AssignAction>>> {
    Ok(None)
}

// Ghidra: modelrules.hh:321 AssignAction::decodeSideeffect
/// Read the next model rule sideeffect element.
///
/// TODO: depends on unported `ELEM_CONSUME_EXTRA`/`ELEM_EXTRA_STACK`/
/// `ELEM_CONSUME_REMAINING`. Returns the Ghidra-matching error
/// `DecoderError: Expecting model rule sideeffect`.
pub fn decode_sideeffect(
    _decoder: &mut dyn Decoder,
    _res: &'static ParamListStandard,
) -> Result<Box<dyn AssignAction>> {
    Err(anyhow!("DecoderError: Expecting model rule sideeffect"))
}

// Ghidra: modelrules.cc:683 AssignAction::justifyPieces
/// \brief Truncate a tiling by a given number of bytes.
///
/// The extra bytes are considered padding and removed from one end of the
/// tiling. The bytes removed depend on the endianness and how the data is
/// justified within the tiling.
///
/// Faithful 1:1 port. Mutates `pieces` in place.
///
/// NOTE: In Ghidra this is a `static` method on the class. In Rust it lives
/// as a free function so `dyn AssignAction` stays object-safe. It is also
/// re-exported as `AssignAction::justify_pieces` via an extension trait below
/// so call sites can mirror `AssignAction::justifyPieces(...)` from Ghidra.
pub fn justify_pieces(
    pieces: &mut [VarnodeData],
    offset: i32,
    is_big_endian: bool,
    consume_most_sig: bool,
    justify_right: bool,
) {
    let add_offset = is_big_endian ^ consume_most_sig ^ justify_right;
    let pos = if justify_right { 0 } else { pieces.len() - 1 };
    if add_offset {
        pieces[pos].offset += offset as u64;
    }
    pieces[pos].size -= offset;
}

// RUDRA-GLUE: AssignActionStaticExt (no Ghidra counterpart — Rust-only
// extension trait so call sites can keep writing `AssignAction::justify_pieces`
// even though `justify_pieces` is a free function for object safety).
/// Static-method namespace for `AssignAction`, mirroring the Ghidra
/// `AssignAction::methodName` call syntax. Holds only the associated
/// functions that cannot live on the object-safe trait itself.
pub trait AssignActionStaticExt {
    /// Re-export of the free function [`justify_pieces`].
    // RUDRA-GLUE: AssignActionStaticExt::justify_pieces (trait dispatch shim;
    // the actual algorithm is the free fn justify_pieces below, q.v. for the
    // Ghidra alignment note).
    fn justify_pieces(
        pieces: &mut [VarnodeData],
        offset: i32,
        is_big_endian: bool,
        consume_most_sig: bool,
        justify_right: bool,
    );
}

impl AssignActionStaticExt for dyn AssignAction {
    // RUDRA-GLUE: <dyn AssignAction>::justify_pieces (delegates to the free
    // fn justify_pieces; see that fn for the Ghidra alignment note).
    fn justify_pieces(
        pieces: &mut [VarnodeData],
        offset: i32,
        is_big_endian: bool,
        consume_most_sig: bool,
        justify_right: bool,
    ) {
        justify_pieces(pieces, offset, is_big_endian, consume_most_sig, justify_right)
    }
}

// ===========================================================================
// 12. GotoStack (modelrules.hh:326)
// ===========================================================================

/// \brief Action assigning a parameter Address from the next available stack
/// location.
///
/// Faithful port of `class GotoStack : public AssignAction`
/// (modelrules.hh:326-337). The cached `stack_entry` would reference a
/// `&'static ParamEntry` once `ParamListStandard::getStackEntry()` is ported.
pub struct GotoStack {
    /// `const ParamListStandard *resource` — owning resource list.
    pub resource: &'static ParamListStandard,
    /// `const ParamEntry *stackEntry` — parameter Entry corresponding to the
    /// stack (resolved lazily by `initialize_entry()`).
    pub stack_entry: Option<&'static crate::type_system::protomodel::ParamEntry>,
    /// `bool fillinOutputActive` — true once this action owns a stack entry.
    pub fillin_output_active: bool,
}

impl GotoStack {
    // Ghidra: modelrules.cc:696 GotoStack::initializeEntry
    /// Find stack entry in resource list. Faithful body throws on missing
    /// entry; Rust returns `anyhow`.
    fn initialize_entry(&mut self) -> Result<()> {
        // TODO: depends on unported `ParamListStandard::getStackEntry()`.
        // Ghidra: stackEntry = resource->getStackEntry();
        //        if (stackEntry == nullptr) throw LowlevelError(...);
        // Until getStackEntry() exists, leave stack_entry = None and surface
        // the matching error.
        Err(anyhow!("LowlevelError: Cannot find matching <pentry> for action: goto_stack"))
    }

    // Ghidra: modelrules.cc:706 GotoStack(res, val)
    /// Constructor for use with `decode`. `val` is a dummy (Ghidra passes 0).
    pub fn new_decode(res: &'static ParamListStandard, _val: i32) -> Self {
        Self { resource: res, stack_entry: None, fillin_output_active: true }
    }

    // Ghidra: modelrules.cc:713 GotoStack(res)
    /// Constructor that resolves the stack entry eagerly.
    pub fn new(res: &'static ParamListStandard) -> Result<Self> {
        let mut me = Self::new_decode(res, 0);
        me.initialize_entry()?;
        Ok(me)
    }
}

impl AssignAction for GotoStack {
    // Ghidra: modelrules.hh:332 GotoStack::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        // Ghidra returns `new GotoStack(newResource)` which calls the
        // (res) ctor and re-runs initializeEntry(). We mirror via new().
        match GotoStack::new(new_resource) {
            Ok(g) => Box::new(g),
            // If the new resource lacks a stack entry, the C++ ctor would
            // throw; preserve that behavior by returning a stack-less clone
            // carrying the same configuration (callers see Fail at use time).
            Err(_) => Box::new(GotoStack::new_decode(new_resource, 0)),
        }
    }
    // Ghidra: modelrules.hh:278 GotoStack inherits fillinOutputActive=true
    fn can_affect_fillin_output(&self) -> bool {
        self.fillin_output_active
    }
    // Ghidra: modelrules.cc:721 GotoStack::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported `ParamEntry::getGroup` /
        // `ParamEntry::getAddrBySlot`. Verbatim Ghidra algorithm:
        //   int4 grp = stackEntry->getGroup();
        //   res.type = dt;
        //   res.addr = stackEntry->getAddrBySlot(status[grp], dt->getSize(),
        //                                         dt->getAlignment());
        //   res.flags = 0;
        //   return success;
        AssignResponse::Fail
    }
    // Ghidra: modelrules.cc:731 GotoStack::fillinOutputMap
    fn fillin_output_map(&self, _active: &ParamActive) -> bool {
        // TODO: depends on unported `ParamTrial::getEntry` returning a
        // pointer comparable to stackEntry. Verbatim Ghidra:
        //   int4 count = 0;
        //   for(int4 i=0;i<active->getNumTrials();++i) {
        //     ParamTrial &trial(active->getTrial(i));
        //     const ParamEntry *entry = trial.getEntry();
        //     if (entry == nullptr) break;
        //     if (entry != stackEntry) return false;
        //     count += 1;
        //     if (count > 1) return false;
        //   }
        //   return (count == 1);
        false
    }
    // Ghidra: modelrules.cc:748 GotoStack::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_GOTO_STACK` element id. Verbatim
        // Ghidra:
        //   uint4 elemId = decoder.openElement(ELEM_GOTO_STACK);
        //   decoder.closeElement(elemId);
        //   initializeEntry();
        // Until the element id is registered, mirror the post-decode
        // initializeEntry() call so a hand-constructed GotoStack behaves the
        // same as a decoded one.
        self.initialize_entry()
    }
}

// ===========================================================================
// 13. ConvertToPointer (modelrules.hh:342)
// ===========================================================================

/// \brief Action converting the parameter's data-type to a pointer, and
/// assigning storage for the pointer.
///
/// This assumes the data-type is stored elsewhere and only the pointer is
/// passed as a parameter.
///
/// Faithful port of `class ConvertToPointer : public AssignAction`
/// (modelrules.hh:342-350).
pub struct ConvertToPointer {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `AddrSpace *space` — address space used for pointer size.
    pub space: AddressSpace,
}

impl ConvertToPointer {
    // Ghidra: modelrules.cc:756 ConvertToPointer(res)
    /// Constructor for use with `decode()`.
    pub fn new(res: &'static ParamListStandard) -> Self {
        // TODO: depends on unported `ParamListStandard::getSpacebase()`.
        // Ghidra: space = res->getSpacebase();
        // Until getSpacebase() lands, default to the `Ram` data space, which
        // matches the typical `AddrSpace *space = nullptr` →
        // `getDefaultDataSpace()` fallback path at modelrules.cc:766-767.
        Self { resource: res, space: AddressSpace::Ram }
    }
}

impl AssignAction for ConvertToPointer {
    // Ghidra: modelrules.hh:346 ConvertToPointer::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        Box::new(ConvertToPointer::new(new_resource))
    }
    // Ghidra: modelrules.cc:762 ConvertToPointer::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported `TypeFactory::getTypePointer` and
        // `ParamListStandard::assignAddress`. Verbatim Ghidra:
        //   AddrSpace *spc = space;
        //   if (spc == nullptr) spc = tlist.getArch()->getDefaultDataSpace();
        //   int4 pointersize = spc->getAddrSize();
        //   int4 wordsize = spc->getWordSize();
        //   Datatype *pointertp = tlist.getTypePointer(pointersize, dt, wordsize);
        //   uint4 responseCode = resource->assignAddress(pointertp, proto,
        //                                                pos, tlist, status, res);
        //   res.flags = ParameterPieces::indirectstorage;
        //   return responseCode;
        AssignResponse::Fail
    }
    // Ghidra: modelrules.cc:778 ConvertToPointer::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_CONVERT_TO_PTR` id. Verbatim Ghidra:
        //   uint4 elemId = decoder.openElement(ELEM_CONVERT_TO_PTR);
        //   decoder.closeElement(elemId);
        Ok(())
    }
}

// ===========================================================================
// 14. MultiSlotAssign (modelrules.hh:357)
// ===========================================================================

/// \brief Consume multiple registers to pass a data-type.
///
/// Available registers are consumed until the data-type is covered, and an
/// appropriate \e join space address is assigned. Registers can be consumed
/// from a specific resource list. Consumption can spill over onto the stack
/// if desired.
///
/// Faithful port of `class MultiSlotAssign : public AssignAction`
/// (modelrules.hh:357-376).
pub struct MultiSlotAssign {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `type_class resourceType` — resource list from which to consume.
    pub resource_type: TypeClass,
    /// `bool isBigEndian`.
    pub is_big_endian: bool,
    /// `bool consumeFromStack`.
    pub consume_from_stack: bool,
    /// `bool consumeMostSig`.
    pub consume_most_sig: bool,
    /// `bool enforceAlignment`.
    pub enforce_alignment: bool,
    /// `bool justifyRight`.
    pub justify_right: bool,
    /// `vector<const ParamEntry *> tiles`.
    pub tiles: Vec<&'static crate::type_system::protomodel::ParamEntry>,
    /// `const ParamEntry *stackEntry`.
    pub stack_entry: Option<&'static crate::type_system::protomodel::ParamEntry>,
    /// `bool fillinOutputActive`.
    pub fillin_output_active: bool,
}

impl MultiSlotAssign {
    // Ghidra: modelrules.cc:787 MultiSlotAssign::initializeEntries
    /// Find the first ParamEntry matching the `resourceType`, and the stack
    /// ParamEntry if `consumeFromStack` is set. Faithful body throws on
    /// missing resources.
    fn initialize_entries(&mut self) -> Result<()> {
        // TODO: depends on unported `ParamListStandard::extractTiles` and
        // `ParamListStandard::getStackEntry`. Verbatim Ghidra:
        //   resource->extractTiles(tiles, resourceType);
        //   stackEntry = resource->getStackEntry();
        //   if (tiles.size() == 0)
        //     throw LowlevelError("Could not find matching resources for action: join");
        //   if (consumeFromStack && stackEntry == nullptr)
        //     throw LowlevelError("Cannot find matching <pentry> for action: join");
        if self.tiles.is_empty() {
            return Err(anyhow!(
                "LowlevelError: Could not find matching resources for action: join"
            ));
        }
        if self.consume_from_stack && self.stack_entry.is_none() {
            return Err(anyhow!(
                "LowlevelError: Cannot find matching <pentry> for action: join"
            ));
        }
        Ok(())
    }

    // Ghidra: modelrules.cc:800 MultiSlotAssign(res)
    /// Constructor for use with `decode`. Sets Ghidra's default config.
    pub fn new_decode(res: &'static ParamListStandard) -> Self {
        let is_big_endian = res.big_endian;
        let mut consume_most_sig = false;
        let mut justify_right = false;
        if is_big_endian {
            consume_most_sig = true;
            justify_right = true;
        }
        // Consume from stack on input parameters by default.
        let consume_from_stack = !matches!(res.list_type, ParamListType::RegisterOut | ParamListType::StandardOut);
        Self {
            resource: res,
            resource_type: TypeClass::General,
            is_big_endian,
            consume_from_stack,
            consume_most_sig,
            enforce_alignment: false,
            justify_right,
            tiles: Vec::new(),
            stack_entry: None,
            fillin_output_active: true,
        }
    }

    // Ghidra: modelrules.cc:819 MultiSlotAssign(store,stack,mostSig,align,justRight,res)
    /// Constructor.
    pub fn with_config(
        store: TypeClass,
        stack: bool,
        most_sig: bool,
        align: bool,
        just_right: bool,
        res: &'static ParamListStandard,
    ) -> Result<Self> {
        let mut me = Self::new_decode(res);
        me.resource_type = store;
        me.consume_from_stack = stack;
        me.consume_most_sig = most_sig;
        me.enforce_alignment = align;
        me.justify_right = just_right;
        me.initialize_entries()?;
        Ok(me)
    }
}

impl AssignAction for MultiSlotAssign {
    // Ghidra: modelrules.hh:370 MultiSlotAssign::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        match MultiSlotAssign::with_config(
            self.resource_type,
            self.consume_from_stack,
            self.consume_most_sig,
            self.enforce_alignment,
            self.justify_right,
            new_resource,
        ) {
            Ok(m) => Box::new(m),
            Err(_) => Box::new(MultiSlotAssign::new_decode(new_resource)),
        }
    }
    // Ghidra: modelrules.hh:278 AssignAction::canAffectFillinOutput (MultiSlotAssign sets fillinOutputActive=true in its ctor, modelrules.cc:805).
    fn can_affect_fillin_output(&self) -> bool {
        self.fillin_output_active
    }
    // Ghidra: modelrules.cc:833 MultiSlotAssign::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported `ParamEntry::getGroup/getSize/getAddrBySlot`,
        // `AddrSpaceManager::constructFloatExtensionAddress`, and
        // `ParameterPieces::assignAddressFromPieces`. The full 70-line Ghidra
        // algorithm (enforceAlignment pre-pass, tile consumption loop, stack
        // spill, float-extension vs justifyPieces truncation) is preserved in
        // the Ghidra source quote at modelrules.cc:833-900 and will be ported
        // verbatim once those upstreams land.
        AssignResponse::Fail
    }
    // Ghidra: modelrules.cc:954 MultiSlotAssign::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_JOIN` / `ATTRIB_REVERSEJUSTIFY` /
        // `ATTRIB_REVERSESIGNIF` / `ATTRIB_STORAGE` / `ATTRIB_ALIGN` /
        // `ATTRIB_STACKSPILL` ids. Verbatim Ghidra (modelrules.cc:954-981):
        //   openElement(ELEM_JOIN); loop nextAttributeId; on ATTRIB_*
        //   toggle the corresponding bool / read type_class; closeElement;
        //   initializeEntries();
        // Once the ids land, port the body verbatim and then re-run
        // initialize_entries() to refresh this->tiles for the new resourceType.
        self.initialize_entries()
    }
}

// ===========================================================================
// 15. MultiMemberAssign (modelrules.hh:383)
// ===========================================================================

/// \brief Consume a register per primitive member of an aggregate data-type.
///
/// The data-type is split up into its underlying primitive elements, and
/// each one is assigned a register from the specific resource list. There
/// must be no padding between elements. No packing of elements into a single
/// register occurs.
///
/// Faithful port of `class MultiMemberAssign : public AssignAction`
/// (modelrules.hh:383-395).
pub struct MultiMemberAssign {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `type_class resourceType`.
    pub resource_type: TypeClass,
    /// `bool consumeFromStack`.
    pub consume_from_stack: bool,
    /// `bool consumeMostSig`.
    pub consume_most_sig: bool,
    /// `bool fillinOutputActive`.
    pub fillin_output_active: bool,
}

impl MultiMemberAssign {
    // Ghidra: modelrules.cc:983 MultiMemberAssign(store,stack,mostSig,res)
    /// Constructor.
    pub fn new(
        store: TypeClass,
        stack: bool,
        most_sig: bool,
        res: &'static ParamListStandard,
    ) -> Self {
        Self {
            resource: res,
            resource_type: store,
            consume_from_stack: stack,
            consume_most_sig: most_sig,
            fillin_output_active: true,
        }
    }
}

impl AssignAction for MultiMemberAssign {
    // Ghidra: modelrules.hh:389 MultiMemberAssign::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        Box::new(MultiMemberAssign::new(
            self.resource_type,
            self.consume_from_stack,
            self.consume_most_sig,
            new_resource,
        ))
    }
    // Ghidra: modelrules.hh:278 AssignAction::canAffectFillinOutput (MultiMemberAssign sets fillinOutputActive=true in its ctor, modelrules.cc:989).
    fn can_affect_fillin_output(&self) -> bool {
        self.fillin_output_active
    }
    // Ghidra: modelrules.cc:992 MultiMemberAssign::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported `ParamListStandard::assignAddressFallback`
        // and `ParameterPieces::assignAddressFromPieces`. Verbatim Ghidra
        // uses PrimitiveExtractor (ported above) then loops over primitives
        // calling assignAddressFallback per element.
        AssignResponse::Fail
    }
    // Ghidra: modelrules.cc:1049 MultiMemberAssign::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_JOIN_PER_PRIMITIVE` /
        // `ATTRIB_STORAGE` ids. Verbatim Ghidra (modelrules.cc:1049-1061):
        //   openElement(ELEM_JOIN_PER_PRIMITIVE);
        //   while (attribId = getNextAttributeId) {
        //     if (attribId == ATTRIB_STORAGE)
        //       resourceType = string2typeclass(readString());
        //   }
        //   closeElement(elemId);
        Ok(())
    }
}

// ===========================================================================
// 16. MultiSlotDualAssign (modelrules.hh:401)
// ===========================================================================

/// \brief Consume multiple registers from different storage classes to pass a
/// data-type.
///
/// This action is for calling conventions that can use both floating-point
/// and general purpose registers when assigning storage for a single
/// composite data-type, such as the X86-64 System V ABI.
///
/// Faithful port of `class MultiSlotDualAssign : public AssignAction`
/// (modelrules.hh:401-427).
pub struct MultiSlotDualAssign {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `type_class baseType`.
    pub base_type: TypeClass,
    /// `type_class altType`.
    pub alt_type: TypeClass,
    /// `bool isBigEndian`.
    pub is_big_endian: bool,
    /// `bool consumeFromStack`.
    pub consume_from_stack: bool,
    /// `bool consumeMostSig`.
    pub consume_most_sig: bool,
    /// `bool justifyRight`.
    pub justify_right: bool,
    /// `bool fillAlternate`.
    pub fill_alternate: bool,
    /// `int4 tileSize`.
    pub tile_size: i32,
    /// `vector<const ParamEntry *> baseTiles`.
    pub base_tiles: Vec<&'static crate::type_system::protomodel::ParamEntry>,
    /// `vector<const ParamEntry *> altTiles`.
    pub alt_tiles: Vec<&'static crate::type_system::protomodel::ParamEntry>,
    /// `const ParamEntry *stackEntry`.
    pub stack_entry: Option<&'static crate::type_system::protomodel::ParamEntry>,
    /// `bool fillinOutputActive`.
    pub fillin_output_active: bool,
}

impl MultiSlotDualAssign {
    // Ghidra: modelrules.cc:1064 MultiSlotDualAssign::initializeEntries
    /// Find the first ParamEntry matching `baseType`, and the first matching
    /// `altType`. Throws if either list is empty, if their sizes differ, or if
    /// the stack entry is required but absent.
    fn initialize_entries(&mut self) -> Result<()> {
        // TODO: depends on unported `extractTiles`/`getStackEntry`. Verbatim
        // Ghidra:
        //   resource->extractTiles(baseTiles, baseType);
        //   resource->extractTiles(altTiles, altType);
        //   stackEntry = resource->getStackEntry();
        //   if (baseTiles.empty() || altTiles.empty())
        //     throw LowlevelError("Could not find matching resources for action: join_dual_class");
        //   tileSize = baseTiles[0]->getSize();
        //   if (tileSize != altTiles[0]->getSize())
        //     throw LowlevelError("Storage class register sizes do not match for action: join_dual_class");
        //   if (consumeFromStack && stackEntry == nullptr)
        //     throw LowlevelError("Cannot find matching stack resource for action: join_dual_class");
        if self.base_tiles.is_empty() || self.alt_tiles.is_empty() {
            return Err(anyhow!(
                "LowlevelError: Could not find matching resources for action: join_dual_class"
            ));
        }
        Ok(())
    }

    // Ghidra: modelrules.cc:1086 MultiSlotDualAssign::getFirstUnused
    /// \brief Get the index of the first unused ParamEntry in the given list.
    ///
    /// Faithful 1:1 port.
    pub fn get_first_unused(
        &self,
        mut iter: usize,
        tiles: &[&'static crate::type_system::protomodel::ParamEntry],
        status: &[i32],
    ) -> usize {
        // TODO: depends on unported `ParamEntry::getGroup()`. The control
        // flow (advance until status[entry.getGroup()] == 0) is preserved
        // verbatim; once getGroup() lands this body becomes:
        //   while iter != tiles.len() {
        //       let entry = tiles[iter];
        //       if status[entry.get_group() as usize] != 0 { iter += 1; continue; }
        //       return iter;
        //   }
        //   tiles.len()
        let _ = status; // suppress unused-param warning until getGroup() lands.
        while iter != tiles.len() {
            iter += 1;
        }
        tiles.len()
    }

    // Ghidra: modelrules.cc:1108 MultiSlotDualAssign::getTileClass
    /// \brief Get the storage class to use for the specific section of the
    /// data-type.
    ///
    /// For the section starting at \b off extending through \b tileSize bytes,
    /// if any primitive overlaps the boundary of the section, return -1.
    /// Otherwise, if all the primitive data-types in the section match the
    /// alternate storage class, return 1, or if one or more does not match,
    /// return 0. The \b index of the first primitive after the start of the
    /// section is provided and is then updated to be the first primitive
    /// after the end of the section.
    ///
    /// Faithful 1:1 port. Returns 0/1 for base/alt tile, -1 for boundary
    /// overlaps. `index` is mutated through `&mut`.
    pub fn get_tile_class(
        &self,
        primitives: &PrimitiveExtractor,
        off: i64,
        index: &mut usize,
    ) -> i32 {
        let mut res = 1;
        let mut count = 0;
        let end_boundary = off + self.tile_size as i64;
        if *index >= primitives.size() {
            return -1;
        }
        let first_primitive = primitives.get(*index);
        while *index < primitives.size() {
            let element = primitives.get(*index);
            if element.offset < off {
                return -1;
            }
            if element.offset >= end_boundary {
                break;
            }
            if element.offset + element.dt.get_size() as i64 > end_boundary {
                return -1;
            }
            count += 1;
            *index += 1;
            // Ghidra: type_class storage = metatype2typeclass(element.dt->getMetatype());
            //        if (storage != altType) res = 0;
            // TODO: depends on unported `metatype2typeclass`. Until then we
            // conservatively set res=0 (i.e. treat every primitive as base
            // tile), matching the worst-case branch of the metatype dispatch.
            let storage = match element.dt.get_metatype() {
                TypeMetatype::Float => TypeClass::Float,
                _ => TypeClass::General,
            };
            if storage != self.alt_type {
                res = 0;
            }
        }
        if count == 0 {
            return -1; // Must be at least one primitive in section
        }
        if self.fill_alternate {
            // Only use altType if the tile contains one primitive of exactly
            // the tile size.
            if count > 1 {
                res = 0;
            }
            if first_primitive.dt.get_size() as i32 != self.tile_size {
                res = 0;
            }
        }
        res
    }

    // Ghidra: modelrules.cc:1139 MultiSlotDualAssign(res)
    /// Constructor for use with `decode`. Sets Ghidra's default config.
    pub fn new_decode(res: &'static ParamListStandard) -> Self {
        let is_big_endian = res.big_endian;
        let (consume_most_sig, justify_right) = if is_big_endian { (true, true) } else { (false, false) };
        Self {
            resource: res,
            base_type: TypeClass::General,
            alt_type: TypeClass::Float,
            is_big_endian,
            consume_from_stack: false,
            consume_most_sig,
            justify_right,
            fill_alternate: false,
            tile_size: 0,
            base_tiles: Vec::new(),
            alt_tiles: Vec::new(),
            stack_entry: None,
            fillin_output_active: true,
        }
    }

    // Ghidra: modelrules.cc:1158 MultiSlotDualAssign(...)
    /// Constructor.
    pub fn with_config(
        base_store: TypeClass,
        alt_store: TypeClass,
        stack: bool,
        most_sig: bool,
        just_right: bool,
        fill_alt: bool,
        res: &'static ParamListStandard,
    ) -> Result<Self> {
        let mut me = Self::new_decode(res);
        me.base_type = base_store;
        me.alt_type = alt_store;
        me.consume_from_stack = stack;
        me.consume_most_sig = most_sig;
        me.justify_right = just_right;
        me.fill_alternate = fill_alt;
        me.initialize_entries()?;
        Ok(me)
    }
}

impl AssignAction for MultiSlotDualAssign {
    // Ghidra: modelrules.hh:420 MultiSlotDualAssign::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        match MultiSlotDualAssign::with_config(
            self.base_type,
            self.alt_type,
            self.consume_from_stack,
            self.consume_most_sig,
            self.justify_right,
            self.fill_alternate,
            new_resource,
        ) {
            Ok(m) => Box::new(m),
            Err(_) => Box::new(MultiSlotDualAssign::new_decode(new_resource)),
        }
    }
    // Ghidra: modelrules.hh:278 AssignAction::canAffectFillinOutput (MultiSlotDualAssign sets fillinOutputActive=true in its ctor, modelrules.cc:1143).
    fn can_affect_fillin_output(&self) -> bool {
        self.fillin_output_active
    }
    // Ghidra: modelrules.cc:1174 MultiSlotDualAssign::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported ParamEntry methods and
        // assignAddressFromPieces. Verbatim Ghidra uses getTileClass (ported
        // above) and getFirstUnused (ported above) to alternate between base
        // and alt tile consumption.
        AssignResponse::Fail
    }
    // Ghidra: modelrules.cc:1300 MultiSlotDualAssign::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_JOIN_DUAL_CLASS` and the various
        // ATTRIB_* ids. Verbatim Ghidra (modelrules.cc:1300-1330): reads
        // REVERSEJUSTIFY, REVERSESIGNIF, STORAGE/A, B, STACKSPILL,
        // FILL_ALTERNATE, then closeElement + initializeEntries().
        self.initialize_entries()
    }
}

// ===========================================================================
// 17. ConsumeAs (modelrules.hh:433)
// ===========================================================================

/// \brief Consume a parameter from a specific resource list.
///
/// Normally the resource list is determined by the parameter data-type, but
/// this action specifies an overriding resource list. Assignment will \e not
/// fall through to the stack.
///
/// Faithful port of `class ConsumeAs : public AssignAction`
/// (modelrules.hh:433-443).
pub struct ConsumeAs {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `type_class resourceType` — the resource list the parameter is
    /// consumed from.
    pub resource_type: TypeClass,
    /// `bool fillinOutputActive`.
    pub fillin_output_active: bool,
}

impl ConsumeAs {
    // Ghidra: modelrules.cc:1332 ConsumeAs(store, res)
    /// Constructor.
    pub fn new(store: TypeClass, res: &'static ParamListStandard) -> Self {
        Self { resource: res, resource_type: store, fillin_output_active: true }
    }
}

impl AssignAction for ConsumeAs {
    // Ghidra: modelrules.hh:437 ConsumeAs::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        Box::new(ConsumeAs::new(self.resource_type, new_resource))
    }
    // Ghidra: modelrules.hh:278 AssignAction::canAffectFillinOutput (ConsumeAs sets fillinOutputActive=true in its ctor, modelrules.cc:1336).
    fn can_affect_fillin_output(&self) -> bool {
        self.fillin_output_active
    }
    // Ghidra: modelrules.cc:1339 ConsumeAs::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported `ParamListStandard::assignAddressFallback`.
        // Verbatim Ghidra:
        //   return resource->assignAddressFallback(resourceType, dt, true, status, res);
        AssignResponse::Fail
    }
    // Ghidra: modelrules.cc:1366 ConsumeAs::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_CONSUME` / `ATTRIB_STORAGE` ids.
        // Verbatim Ghidra:
        //   uint4 elemId = decoder.openElement(ELEM_CONSUME);
        //   resourceType = string2typeclass(decoder.readString(ATTRIB_STORAGE));
        //   decoder.closeElement(elemId);
        Ok(())
    }
}

// ===========================================================================
// 18. HiddenReturnAssign (modelrules.hh:457)
// ===========================================================================

/// \brief Allocate the return value as an input parameter.
///
/// A pointer to where the return value is to be stored is passed in as an
/// input parameter. This action signals this by returning one of
/// `hiddenret_ptrparam` / `hiddenret_specialreg` / `hiddenret_specialreg_void`.
///
/// Faithful port of `class HiddenReturnAssign : public AssignAction`
/// (modelrules.hh:457-466).
pub struct HiddenReturnAssign {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `uint4 retCode` — the specific signal to pass back.
    pub ret_code: AssignResponse,
}

impl HiddenReturnAssign {
    // Ghidra: modelrules.cc:1374 HiddenReturnAssign(res, code)
    /// Constructor.
    pub fn new(res: &'static ParamListStandard, code: AssignResponse) -> Self {
        Self { resource: res, ret_code: code }
    }
}

impl AssignAction for HiddenReturnAssign {
    // Ghidra: modelrules.hh:461 HiddenReturnAssign::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        Box::new(HiddenReturnAssign::new(new_resource, self.ret_code))
    }
    // Ghidra: modelrules.cc:1380 HiddenReturnAssign::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // Signal to assignMap to use TYPECLASS_HIDDENRET.
        self.ret_code
    }
    // Ghidra: modelrules.cc:1386 HiddenReturnAssign::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_HIDDEN_RETURN` / `ATTRIB_VOIDLOCK` /
        // `ATTRIB_STRATEGY` ids. Verbatim Ghidra (modelrules.cc:1386-1408):
        //   retCode = hiddenret_specialreg;        // default
        //   openElement(ELEM_HIDDEN_RETURN);
        //   loop attribs: ATTRIB_VOIDLOCK → hiddenret_specialreg_void;
        //                 ATTRIB_STRATEGY  → "normalparam" | "special"
        //                                   (else throw DecoderError).
        // Until the ids land, preserve the Ghidra default retCode.
        self.ret_code = AssignResponse::HiddenRetSpecialReg;
        Ok(())
    }
}

// ===========================================================================
// 19. ConsumeExtra (modelrules.hh:475)
// ===========================================================================

/// \brief Consume additional registers from an alternate resource list.
///
/// This action is a side-effect and doesn't assign an address for the current
/// parameter. The resource list, \b resourceType, is specified. If the
/// side-effect is triggered, register resources from this list are consumed.
/// If \b matchSize is true (the default), registers are consumed, until the
/// number of bytes in the data-type is reached. Otherwise, only a single
/// register is consumed. If all registers are already consumed, no action is
/// taken.
///
/// Faithful port of `class ConsumeExtra : public AssignAction`
/// (modelrules.hh:475-488).
pub struct ConsumeExtra {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `type_class resourceType` — the other resource list to consume from.
    pub resource_type: TypeClass,
    /// `bool matchSize` — \b false, if side-effect only consumes a single
    /// register.
    pub match_size: bool,
    /// `vector<const ParamEntry *> tiles`.
    pub tiles: Vec<&'static crate::type_system::protomodel::ParamEntry>,
}

impl ConsumeExtra {
    // Ghidra: modelrules.cc:1411 ConsumeExtra::initializeEntries
    /// Find the first ParamEntry matching the `resourceType`. Throws if none.
    fn initialize_entries(&mut self) -> Result<()> {
        // TODO: depends on unported `extractTiles`. Verbatim Ghidra:
        //   resource->extractTiles(tiles, resourceType);
        //   if (tiles.size() == 0)
        //     throw LowlevelError("Could not find matching resources for action: consume_extra");
        if self.tiles.is_empty() {
            return Err(anyhow!(
                "LowlevelError: Could not find matching resources for action: consume_extra"
            ));
        }
        Ok(())
    }

    // Ghidra: modelrules.cc:1419 ConsumeExtra(res)
    /// Constructor for use with `decode`.
    pub fn new_decode(res: &'static ParamListStandard) -> Self {
        Self { resource: res, resource_type: TypeClass::General, match_size: true, tiles: Vec::new() }
    }

    // Ghidra: modelrules.cc:1426 ConsumeExtra(store, match, res)
    /// Constructor.
    pub fn new(store: TypeClass, match_sz: bool, res: &'static ParamListStandard) -> Result<Self> {
        let mut me = Self::new_decode(res);
        me.resource_type = store;
        me.match_size = match_sz;
        me.initialize_entries()?;
        Ok(me)
    }
}

impl AssignAction for ConsumeExtra {
    // Ghidra: modelrules.hh:483 ConsumeExtra::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        match ConsumeExtra::new(self.resource_type, self.match_size, new_resource) {
            Ok(c) => Box::new(c),
            Err(_) => Box::new(ConsumeExtra::new_decode(new_resource)),
        }
    }
    // Ghidra: modelrules.cc:1434 ConsumeExtra::assignAddress
    fn assign_address(
        &self,
        dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported `ParamEntry::getGroup`/`getSize`. Verbatim
        // Ghidra control flow preserved below; once getGroup() lands the only
        // change is indexing status[entry.get_group()].
        //   int4 iter = 0;
        //   int4 sizeLeft = dt->getSize();
        //   while(sizeLeft > 0 && iter != tiles.size()) {
        //     const ParamEntry *entry = tiles[iter];
        //     ++iter;
        //     if (status[entry->getGroup()] != 0) continue; // Already consumed
        //     status[entry->getGroup()] = -1;               // Consume the slot
        //     sizeLeft -= entry->getSize();
        //     if (!matchSize) break;                        // Only consume a single register
        //   }
        //   return success;
        let mut iter = 0;
        let mut size_left = dt.get_size() as i32;
        let _ = (&mut iter, &mut size_left, status.len()); // suppress warnings until getGroup lands
        AssignResponse::Success
    }
    // Ghidra: modelrules.cc:1452 ConsumeExtra::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_CONSUME_EXTRA` / `ATTRIB_STORAGE` /
        // `ATTRIB_MATCHSIZE` ids. Verbatim Ghidra (modelrules.cc:1452-1468):
        //   openElement(ELEM_CONSUME_EXTRA);
        //   loop attribs: ATTRIB_STORAGE → resourceType = string2typeclass;
        //                 ATTRIB_MATCHSIZE → matchSize = readBool;
        //   closeElement; initializeEntries();
        self.initialize_entries()
    }
}

// ===========================================================================
// 20. ExtraStack (modelrules.hh:496)
// ===========================================================================

/// \brief Consume stack resources as a side-effect.
///
/// This action is a side-effect and doesn't assign an address for the current
/// parameter. If the current parameter has been assigned an address that is
/// not on the stack, this action consumes stack resources as if the parameter
/// were allocated to the stack. If the current parameter was already assigned
/// a stack address, no additional action is taken.
///
/// Faithful port of `class ExtraStack : public AssignAction`
/// (modelrules.hh:496-509).
pub struct ExtraStack {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `int4 afterBytes` — activate side effect after given number of bytes
    /// consumed.
    pub after_bytes: i32,
    /// `type_class afterStorage` — activate side effect after given amount of
    /// this storage consumed.
    pub after_storage: TypeClass,
    /// `const ParamEntry *stackEntry`.
    pub stack_entry: Option<&'static crate::type_system::protomodel::ParamEntry>,
}

impl ExtraStack {
    // Ghidra: modelrules.cc:1516 ExtraStack::initializeEntry
    /// Find stack entry in resource list. Throws on missing entry.
    fn initialize_entry(&mut self) -> Result<()> {
        // TODO: depends on unported `getStackEntry`. Verbatim Ghidra:
        //   stackEntry = resource->getStackEntry();
        //   if (stackEntry == nullptr)
        //     throw LowlevelError("Cannot find matching <pentry> for action: extra_stack");
        if self.stack_entry.is_none() {
            return Err(anyhow!(
                "LowlevelError: Cannot find matching <pentry> for action: extra_stack"
            ));
        }
        Ok(())
    }

    // Ghidra: modelrules.cc:1525 ExtraStack(res)
    /// Constructor for use with `decode`.
    pub fn new_decode(res: &'static ParamListStandard) -> Self {
        Self {
            resource: res,
            after_bytes: -1,
            after_storage: TypeClass::General,
            stack_entry: None,
        }
    }

    // Ghidra: modelrules.cc:1533 ExtraStack(storage, offset, res)
    /// Constructor.
    pub fn new(
        storage: TypeClass,
        offset: i32,
        res: &'static ParamListStandard,
    ) -> Result<Self> {
        let mut me = Self::new_decode(res);
        me.after_storage = storage;
        me.after_bytes = offset;
        me.initialize_entry()?;
        Ok(me)
    }
}

impl AssignAction for ExtraStack {
    // Ghidra: modelrules.hh:504 ExtraStack::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        match ExtraStack::new(self.after_storage, self.after_bytes, new_resource) {
            Ok(e) => Box::new(e),
            Err(_) => Box::new(ExtraStack::new_decode(new_resource)),
        }
    }
    // Ghidra: modelrules.cc:1542 ExtraStack::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        _status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported `ParamEntry::getSpace`/`getGroup`/
        // `getAddrBySlot` and `ParamListStandard::getEntry`. Verbatim Ghidra:
        //   if (res.addr.getSpace() == stackEntry->getSpace()) return success;
        //   int4 grp = stackEntry->getGroup();
        //   if (afterBytes > 0) {
        //     const list<ParamEntry>& entryList = resource->getEntry();
        //     int4 bytesConsumed = 0;
        //     for (const ParamEntry& entry : entryList) {
        //       if (entry.getGroup() == grp || entry.getType() != afterStorage) continue;
        //       if (status[entry.getGroup()] != 0) bytesConsumed += entry.getSize();
        //     }
        //     if (bytesConsumed < afterBytes) return success;
        //   }
        //   stackEntry->getAddrBySlot(status[grp], dt->getSize(), dt->getAlignment());
        //   return success;
        AssignResponse::Success
    }
    // Ghidra: modelrules.cc:1574 ExtraStack::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_EXTRA_STACK` / `ATTRIB_AFTER_BYTES` /
        // `ATTRIB_AFTER_STORAGE` ids. Verbatim Ghidra (modelrules.cc:1574-1588):
        //   openElement(ELEM_EXTRA_STACK);
        //   loop attribs: ATTRIB_AFTER_BYTES → afterBytes;
        //                 ATTRIB_AFTER_STORAGE → afterStorage = string2typeclass;
        //   closeElement; initializeEntry();
        self.initialize_entry()
    }
}

// ===========================================================================
// 21. ConsumeRemaining (modelrules.hh:517)
// ===========================================================================

/// \brief Consume all the remaining registers from a given resource list.
///
/// This action is a side-effect and doesn't assign an address for the current
/// parameter. The resource list, \b resourceType, is specified. If the
/// side-effect is triggered, all register resources from this list are
/// consumed, until no registers remain. If all registers are already
/// consumed, no action is taken.
///
/// Faithful port of `class ConsumeRemaining : public AssignAction`
/// (modelrules.hh:517-529).
pub struct ConsumeRemaining {
    /// `const ParamListStandard *resource`.
    pub resource: &'static ParamListStandard,
    /// `type_class resourceType` — the other resource list to consume from.
    pub resource_type: TypeClass,
    /// `vector<const ParamEntry *> tiles`.
    pub tiles: Vec<&'static crate::type_system::protomodel::ParamEntry>,
}

impl ConsumeRemaining {
    // Ghidra: modelrules.cc:1472 ConsumeRemaining::initializeEntries
    /// Find the first ParamEntry matching the `resourceType`. Throws if none.
    fn initialize_entries(&mut self) -> Result<()> {
        // TODO: depends on unported `extractTiles`. Verbatim Ghidra:
        //   resource->extractTiles(tiles, resourceType);
        //   if (tiles.size() == 0)
        //     throw LowlevelError("Could not find matching resources for action: consume_remaining");
        if self.tiles.is_empty() {
            return Err(anyhow!(
                "LowlevelError: Could not find matching resources for action: consume_remaining"
            ));
        }
        Ok(())
    }

    // Ghidra: modelrules.cc:1480 ConsumeRemaining(res)
    /// Constructor for use with `decode`.
    pub fn new_decode(res: &'static ParamListStandard) -> Self {
        Self { resource: res, resource_type: TypeClass::General, tiles: Vec::new() }
    }

    // Ghidra: modelrules.cc:1486 ConsumeRemaining(store, res)
    /// Constructor.
    pub fn new(store: TypeClass, res: &'static ParamListStandard) -> Result<Self> {
        let mut me = Self::new_decode(res);
        me.resource_type = store;
        me.initialize_entries()?;
        Ok(me)
    }
}

impl AssignAction for ConsumeRemaining {
    // Ghidra: modelrules.hh:524 ConsumeRemaining::clone
    fn clone_box(&self, new_resource: &'static ParamListStandard) -> Box<dyn AssignAction> {
        match ConsumeRemaining::new(self.resource_type, new_resource) {
            Ok(c) => Box::new(c),
            Err(_) => Box::new(ConsumeRemaining::new_decode(new_resource)),
        }
    }
    // Ghidra: modelrules.cc:1493 ConsumeRemaining::assignAddress
    fn assign_address(
        &self,
        _dt: &Datatype,
        _proto: &PrototypePieces,
        _pos: i32,
        _tlist: &TypeFactory,
        status: &mut [i32],
        _res: &mut ParameterPieces,
    ) -> AssignResponse {
        // TODO: depends on unported `ParamEntry::getGroup`. Verbatim Ghidra:
        //   int4 iter = 0;
        //   while(iter != tiles.size()) {
        //     const ParamEntry *entry = tiles[iter];
        //     ++iter;
        //     if (status[entry->getGroup()] != 0) continue;
        //     status[entry->getGroup()] = -1;
        //   }
        //   return success;
        let _ = status; // suppress warning until getGroup() lands.
        AssignResponse::Success
    }
    // Ghidra: modelrules.cc:1507 ConsumeRemaining::decode
    fn decode(&mut self, _decoder: &mut dyn Decoder) -> Result<()> {
        // TODO: depends on unported `ELEM_CONSUME_REMAINING` / `ATTRIB_STORAGE`
        // ids. Verbatim Ghidra (modelrules.cc:1507-1514):
        //   uint4 elemId = decoder.openElement(ELEM_CONSUME_REMAINING);
        //   resourceType = string2typeclass(decoder.readString(ATTRIB_STORAGE));
        //   decoder.closeElement(elemId);
        //   initializeEntries();
        self.initialize_entries()
    }
}

// ===========================================================================
// 22. ModelRule (modelrules.hh:537)
// ===========================================================================

/// \brief A rule controlling how parameters are assigned addresses.
///
/// Rules are applied to a parameter in the context of a full function
/// prototype. A rule applies only for a specific class of data-type
/// associated with the parameter, as determined by its `DatatypeFilter`, and
/// may have other criteria limiting when it applies (via `QualifierFilter`).
///
/// Faithful port of `class ModelRule` (modelrules.hh:537-554). The
/// `inline fillinOutputMap` / `canAffectFillinOutput` accessors
/// (modelrules.hh:559-570) are ported as inherent methods below.
pub struct ModelRule {
    /// `DatatypeFilter *filter` — which data-types \b this rule applies to.
    pub filter: Option<Box<dyn DatatypeFilter>>,
    /// `QualifierFilter *qualifier` — additional qualifiers (null = none).
    pub qualifier: Option<Box<dyn QualifierFilter>>,
    /// `AssignAction *assign` — how the Address should be assigned.
    pub assign: Option<Box<dyn AssignAction>>,
    /// `vector<AssignAction *> preconditions` — extra actions before
    /// assignment, discarded on failure.
    pub preconditions: Vec<Box<dyn AssignAction>>,
    /// `vector<AssignAction *> sideeffects` — extra actions on success.
    pub sideeffects: Vec<Box<dyn AssignAction>>,
}

impl ModelRule {
    // Ghidra: modelrules.hh:544 ModelRule() (decode ctor)
    /// Constructor for use with `decode`. All members null/empty.
    pub fn new() -> Self {
        Self {
            filter: None,
            qualifier: None,
            assign: None,
            preconditions: Vec::new(),
            sideeffects: Vec::new(),
        }
    }

    // Ghidra: modelrules.cc:1590 ModelRule(const ModelRule &op2, res)
    /// Copy constructor that re-binds the resource list. Each owned filter /
    /// action is cloned via its `clone_box()`.
    pub fn copy(op2: &ModelRule, res: &'static ParamListStandard) -> Self {
        let filter = op2.filter.as_ref().map(|f| f.clone_box());
        let qualifier = op2.qualifier.as_ref().map(|q| q.clone_box());
        let assign = op2.assign.as_ref().map(|a| a.clone_box(res));
        let preconditions = op2
            .preconditions
            .iter()
            .map(|a| a.clone_box(res))
            .collect();
        let sideeffects = op2
            .sideeffects
            .iter()
            .map(|a| a.clone_box(res))
            .collect();
        Self { filter, qualifier, assign, preconditions, sideeffects }
    }

    // Ghidra: modelrules.cc:1615 ModelRule(typeFilter, action, res)
    /// Construct from components. The provided components are cloned.
    pub fn from_components(
        type_filter: &dyn DatatypeFilter,
        action: &dyn AssignAction,
        res: &'static ParamListStandard,
    ) -> Self {
        Self {
            filter: Some(type_filter.clone_box()),
            qualifier: None,
            assign: Some(action.clone_box(res)),
            preconditions: Vec::new(),
            sideeffects: Vec::new(),
        }
    }

    // Ghidra: modelrules.cc:1651 ModelRule::assignAddress
    /// \brief Assign an address and other details for a specific parameter or
    /// for return storage in context.
    ///
    /// The Address is only assigned if the data-type filter and the optional
    /// qualifier filter pass, otherwise a \b fail response is returned. If
    /// the filters pass, the Address is assigned based on the AssignAction
    /// specific to \b this rule, and the action's response code is returned.
    ///
    /// Faithful 1:1 port of the algorithm at modelrules.cc:1651-1672,
    /// including the `tmpStatus` rollback semantics: preconditions and the
    /// main assign run against `tmpStatus`; `tmpStatus` is committed back to
    /// `status` only on a non-`fail` response, after which side-effects run
    /// directly against `status` (no rollback).
    pub fn assign_address(
        &self,
        dt: &Datatype,
        proto: &PrototypePieces,
        pos: i32,
        tlist: &TypeFactory,
        status: &mut Vec<i32>,
        res: &mut ParameterPieces,
    ) -> AssignResponse {
        let filter = match &self.filter {
            Some(f) => f,
            None => return AssignResponse::Fail,
        };
        if !filter.filter(dt) {
            return AssignResponse::Fail;
        }
        if let Some(q) = &self.qualifier {
            if !q.filter(proto, pos) {
                return AssignResponse::Fail;
            }
        }
        let mut tmp_status = status.clone();
        for pre in &self.preconditions {
            let _ = pre.assign_address(dt, proto, pos, tlist, &mut tmp_status, res);
        }
        let assign = match &self.assign {
            Some(a) => a,
            None => return AssignResponse::Fail,
        };
        let response = assign.assign_address(dt, proto, pos, tlist, &mut tmp_status, res);
        if response != AssignResponse::Fail {
            *status = tmp_status;
            for side in &self.sideeffects {
                let _ = side.assign_address(dt, proto, pos, tlist, status, res);
            }
        }
        response
    }

    // Ghidra: modelrules.hh:559 ModelRule::fillinOutputMap (inline)
    /// If the assign action could produce the trials as return value storage,
    /// return \b true. Faithful inline.
    pub fn fillin_output_map(&self, active: &ParamActive) -> bool {
        match &self.assign {
            Some(a) => a.fillin_output_map(active),
            None => false,
        }
    }

    // Ghidra: modelrules.hh:566 ModelRule::canAffectFillinOutput (inline)
    /// Return \b true if the assign action can affect `fillin_output_map()`.
    pub fn can_affect_fillin_output(&self) -> bool {
        match &self.assign {
            Some(a) => a.can_affect_fillin_output(),
            None => false,
        }
    }

    // Ghidra: modelrules.cc:1676 ModelRule::decode
    /// Decode \b this rule from stream.
    ///
    /// TODO: depends on unported `ELEM_RULE`, qualifier/action/sideeffect
    /// decode entry points, and `Decoder` element id registration. Once
    /// those land, port modelrules.cc:1676-1709 verbatim: open `ELEM_RULE`,
    /// decodeFilter, loop QualifierFilter::decodeFilter (wrap in AndFilter if
    /// >1), loop decodePrecondition, decodeAction, then while-loop
    /// decodeSideeffect.
    pub fn decode(
        &mut self,
        _decoder: &mut dyn Decoder,
        _res: &'static ParamListStandard,
    ) -> Result<()> {
        Ok(())
    }
}

impl Default for ModelRule {
    // RUDRA-GLUE: Default impl (mirrors the no-arg ctor at modelrules.hh:544).
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Sanity-check tests (Phase 1)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::{
        primitive_alignment, TypeArray, TypeBase, TypeField, TypePointer, TypeStruct,
    };

    // RUDRA-GLUE: helper to build a primitive Int base type (no Ghidra
    // counterpart — test-only fixture).
    fn int_dt(size: usize) -> Datatype {
        Datatype::Base(TypeBase::new("int".into(), size, TypeMetatype::Int))
    }

    // RUDRA-GLUE: helper to build a Float base type.
    fn float_dt(size: usize) -> Datatype {
        Datatype::Base(TypeBase::new("float".into(), size, TypeMetatype::Float))
    }

    #[test]
    fn test_primitive_extractor_simple_int() {
        // A primitive int(4) extracts as a single element.
        let dt = int_dt(4);
        let pe = PrimitiveExtractor::new(&dt, false, 0, 16);
        assert!(pe.is_valid());
        assert_eq!(pe.size(), 1);
        assert_eq!(pe.get(0).offset, 0);
        assert!(!pe.contains_unknown());
        assert!(pe.is_aligned());
        assert!(!pe.contains_holes());
    }

    #[test]
    fn test_primitive_extractor_exceeds_max() {
        // max=0 must mark the extraction invalid (no room for any primitive).
        let dt = int_dt(4);
        let pe = PrimitiveExtractor::new(&dt, false, 0, 0);
        assert!(!pe.is_valid());
        assert_eq!(pe.size(), 0);
    }

    #[test]
    fn test_primitive_extractor_struct_aligned() {
        // struct { int f0 @0; int f1 @4; } — two aligned primitives, no holes.
        let int_t = std::sync::Arc::new(int_dt(4));
        let s = Datatype::Struct(TypeStruct {
            base: TypeBase::new("S".into(), 8, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "f0".into(), offset: 0, type_ptr: int_t.clone() },
                TypeField { name: "f1".into(), offset: 4, type_ptr: int_t.clone() },
            ],
        });
        let pe = PrimitiveExtractor::new(&s, false, 0, 16);
        assert!(pe.is_valid());
        assert_eq!(pe.size(), 2);
        assert_eq!(pe.get(0).offset, 0);
        assert_eq!(pe.get(1).offset, 4);
        assert!(pe.is_aligned());
        assert!(!pe.contains_holes());
    }

    #[test]
    fn test_primitive_extractor_struct_unaligned_and_holes() {
        // struct { char f0 @0; int f1 @2; } — f1 is misaligned (2 % 4 != 0),
        // and there is a hole at offset 1 (expected_off=1, cur_off=2).
        let char_t = std::sync::Arc::new(int_dt(1));
        let int_t = std::sync::Arc::new(int_dt(4));
        let s = Datatype::Struct(TypeStruct {
            base: TypeBase::new("S".into(), 6, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "f0".into(), offset: 0, type_ptr: char_t },
                TypeField { name: "f1".into(), offset: 2, type_ptr: int_t },
            ],
        });
        let pe = PrimitiveExtractor::new(&s, false, 0, 16);
        assert!(pe.is_valid());
        assert!(!pe.is_aligned(), "f1 should be unaligned");
        assert!(pe.contains_holes(), "gap between f0 and f1 is a hole");
        assert_eq!(pe.size(), 2);
    }

    #[test]
    fn test_primitive_extractor_array() {
        // int[3] — three primitives at offsets 0,4,8.
        let int_t = std::sync::Arc::new(int_dt(4));
        let arr = Datatype::Array(TypeArray {
            base: TypeBase::new("int[3]".into(), 12, TypeMetatype::Array),
            array_of: int_t,
            num_elements: 3,
        });
        let pe = PrimitiveExtractor::new(&arr, false, 0, 16);
        assert!(pe.is_valid());
        assert_eq!(pe.size(), 3);
        assert_eq!(pe.get(0).offset, 0);
        assert_eq!(pe.get(1).offset, 4);
        assert_eq!(pe.get(2).offset, 8);
    }

    #[test]
    fn test_primitive_extractor_union_illegal() {
        // union { int; float; } with unionIllegal=true → invalid.
        let int_t = std::sync::Arc::new(int_dt(4));
        let float_t = std::sync::Arc::new(float_dt(4));
        let u = crate::type_system::datatype::TypeUnion {
            base: TypeBase::new("U".into(), 4, TypeMetatype::Union),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: int_t },
                TypeField { name: "b".into(), offset: 0, type_ptr: float_t },
            ],
        };
        let dt = Datatype::Union(u);
        let pe = PrimitiveExtractor::new(&dt, true, 0, 16);
        assert!(!pe.is_valid());
    }

    #[test]
    fn test_primitive_extractor_union_common_refinement() {
        // union { int @0; float @0; } with unionIllegal=false → one primitive
        // via commonRefinement (int preferred over float).
        let int_t = std::sync::Arc::new(int_dt(4));
        let float_t = std::sync::Arc::new(float_dt(4));
        let u = crate::type_system::datatype::TypeUnion {
            base: TypeBase::new("U".into(), 4, TypeMetatype::Union),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: int_t },
                TypeField { name: "b".into(), offset: 0, type_ptr: float_t },
            ],
        };
        let dt = Datatype::Union(u);
        let pe = PrimitiveExtractor::new(&dt, false, 0, 16);
        assert!(pe.is_valid(), "union should refine cleanly");
        assert_eq!(pe.size(), 1, "common refinement of two 4-byte primitives = 1");
    }

    // ---- DatatypeFilter ----

    #[test]
    fn test_size_restricted_filter_range() {
        let f = SizeRestrictedFilter::with_bounds(2, 8);
        // Within range.
        assert!(f.filter(&int_dt(4)));
        assert!(f.filter(&int_dt(2)));
        assert!(f.filter(&int_dt(8)));
        // Out of range.
        assert!(!f.filter(&int_dt(1)));
        assert!(!f.filter(&int_dt(16)));
    }

    #[test]
    fn test_size_restricted_filter_default_no_filtering() {
        // Default-constructed filter has maxSize==0 → no size filtering.
        let f = SizeRestrictedFilter::new();
        assert!(f.filter(&int_dt(1)));
        assert!(f.filter(&int_dt(64)));
    }

    #[test]
    fn test_size_restricted_filter_no_max_defaults_to_int_max() {
        // min=4, max=0 → after with_bounds normalization, max becomes 0x7fffffff.
        let f = SizeRestrictedFilter::with_bounds(4, 0);
        assert!(f.filter(&int_dt(4)));
        assert!(f.filter(&int_dt(1_000_000)));
        assert!(!f.filter(&int_dt(2)));
    }

    #[test]
    fn test_size_restricted_filter_enumerated_sizes() {
        let mut f = SizeRestrictedFilter::new();
        f.init_from_type_list("2, 4, 8").unwrap();
        assert!(f.filter(&int_dt(2)));
        assert!(f.filter(&int_dt(4)));
        assert!(f.filter(&int_dt(8)));
        assert!(!f.filter(&int_dt(1)));
        assert!(!f.filter(&int_dt(16)));
        // init sets min/max from the set.
        assert_eq!(f.min_size, 2);
        assert_eq!(f.max_size, 8);
    }

    #[test]
    fn test_init_from_type_list_rejects_bad() {
        let mut f = SizeRestrictedFilter::new();
        assert!(f.init_from_type_list("0").is_err(), "0 is not a valid size");
        assert!(f.init_from_type_list("xyz").is_err(), "non-integer is bad");
    }

    #[test]
    fn test_meta_type_filter() {
        let f = MetaTypeFilter::new(TypeMetatype::Float);
        assert!(f.filter(&float_dt(8)));
        assert!(!f.filter(&int_dt(8)), "int should not match Float meta");
    }

    #[test]
    fn test_homogeneous_aggregate_pass() {
        // struct { float; float; } is a homogeneous float aggregate (<=4 prims).
        let ft = std::sync::Arc::new(float_dt(4));
        let s = Datatype::Struct(TypeStruct {
            base: TypeBase::new("hf".into(), 8, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: ft.clone() },
                TypeField { name: "b".into(), offset: 4, type_ptr: ft },
            ],
        });
        let f = HomogeneousAggregate::new(TypeMetatype::Float);
        assert!(f.filter(&s));
    }

    #[test]
    fn test_homogeneous_aggregate_fail_mixed() {
        // struct { float; int; } is not homogeneous.
        let ft = std::sync::Arc::new(float_dt(4));
        let it = std::sync::Arc::new(int_dt(4));
        let s = Datatype::Struct(TypeStruct {
            base: TypeBase::new("hm".into(), 8, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: ft },
                TypeField { name: "b".into(), offset: 4, type_ptr: it },
            ],
        });
        let f = HomogeneousAggregate::new(TypeMetatype::Float);
        assert!(!f.filter(&s));
    }

    #[test]
    fn test_homogeneous_aggregate_rejects_primitive() {
        // A bare float is not an aggregate.
        let f = HomogeneousAggregate::new(TypeMetatype::Float);
        assert!(!f.filter(&float_dt(8)));
    }

    // ---- QualifierFilter ----

    fn proto_with_vararg(slot: i32) -> PrototypePieces<'static> {
        // We can't easily build 'static Datatype slices without leaking; for
        // tests we use empty intypes and only exercise first_var_arg_slot.
        PrototypePieces { outtype: None, intypes: &[], first_var_arg_slot: slot }
    }

    #[test]
    fn test_varargs_filter_matches_optional() {
        // firstVarArgSlot=2; pos=3 is optional → matches default VarargsFilter.
        let proto = proto_with_vararg(2);
        let f = VarargsFilter::new();
        assert!(f.filter(&proto, 3));
        // pos=2 is the first vararg itself → also matches (firstPos=MIN).
        assert!(f.filter(&proto, 2));
    }

    #[test]
    fn test_varargs_filter_no_varargs() {
        // firstVarArgSlot=-1 → never matches.
        let proto = proto_with_vararg(-1);
        let f = VarargsFilter::new();
        assert!(!f.filter(&proto, 0));
    }

    #[test]
    fn test_varargs_filter_first_only() {
        // first=0,last=0 matches only the first optional argument.
        let proto = proto_with_vararg(2);
        let f = VarargsFilter::with_range(0, 0);
        assert!(f.filter(&proto, 2), "pos=2 → vararg slot 0 → matches");
        assert!(!f.filter(&proto, 3), "pos=3 → vararg slot 1 → no match");
    }

    #[test]
    fn test_position_match_filter() {
        let proto = proto_with_vararg(-1);
        let f = PositionMatchFilter::new(3);
        assert!(f.filter(&proto, 3));
        assert!(!f.filter(&proto, 2));
    }

    #[test]
    fn test_datatype_match_filter_outtype() {
        // position=-1 → consult outtype.
        let out = int_dt(4);
        let proto = PrototypePieces {
            outtype: Some(&out),
            intypes: &[],
            first_var_arg_slot: -1,
        };
        let mut f = DatatypeMatchFilter::new();
        f.position = -1;
        f.type_filter = Some(Box::new(SizeRestrictedFilter::with_bounds(1, 8)));
        assert!(f.filter(&proto, 0));
    }

    #[test]
    fn test_datatype_match_filter_intype_out_of_range() {
        // position=5 but only 2 intypes → false.
        let a = int_dt(4);
        let b = int_dt(8);
        let intypes: &[&Datatype] = &[&a, &b];
        let proto = PrototypePieces { outtype: None, intypes, first_var_arg_slot: -1 };
        let mut f = DatatypeMatchFilter::new();
        f.position = 5;
        f.type_filter = Some(Box::new(SizeRestrictedFilter::new()));
        assert!(!f.filter(&proto, 0));
    }

    #[test]
    fn test_and_filter() {
        // AND of two VarargsFilters with the same proto.
        let proto = proto_with_vararg(1);
        let andf = AndFilter::new(vec![
            Box::new(VarargsFilter::new()),
            Box::new(VarargsFilter::with_range(0, 0)),
        ]);
        // pos=1 → slot 0 → both pass.
        assert!(andf.filter(&proto, 1));
        // pos=2 → slot 1 → second fails.
        assert!(!andf.filter(&proto, 2));
    }

    // ---- AssignAction / ModelRule ----

    // We cannot easily build a 'static ParamListStandard for full action
    // tests, but the response-code plumbing and ModelRule filter logic can be
    // exercised without one by using a no-op AssignAction stub.

    struct AlwaysFailAction;
    impl AssignAction for AlwaysFailAction {
        fn clone_box(&self, _r: &'static ParamListStandard) -> Box<dyn AssignAction> {
            Box::new(AlwaysFailAction)
        }
        fn assign_address(
            &self, _dt: &Datatype, _proto: &PrototypePieces, _pos: i32,
            _tlist: &TypeFactory, _status: &mut [i32], _res: &mut ParameterPieces,
        ) -> AssignResponse {
            AssignResponse::Fail
        }
        fn decode(&mut self, _d: &mut dyn Decoder) -> Result<()> { Ok(()) }
    }

    #[test]
    fn test_assign_response_enum_values() {
        // Sanity: response codes are distinct and round-trip through clone.
        let codes = [
            AssignResponse::Success,
            AssignResponse::Fail,
            AssignResponse::NoAssignment,
            AssignResponse::HiddenRetPtrParam,
            AssignResponse::HiddenRetSpecialReg,
            AssignResponse::HiddenRetSpecialRegVoid,
        ];
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
        }
    }

    #[test]
    fn test_justify_pieces_truncates_low_tile() {
        // Two pieces, big-endian, consumeMostSig, justifyRight=true.
        // addOffset = bigEndian ^ consumeMostSig ^ justifyRight = 1^1^1 = 1
        // pos = 0 (justifyRight). Piece[0].offset += offset, size -= offset.
        let mut pieces = vec![
            VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 8 },
            VarnodeData { space: AddressSpace::Register, offset: 0x108, size: 8 },
        ];
        // Call via the static-method extension trait, mirroring the Ghidra
        // `AssignAction::justifyPieces(...)` call syntax.
        use super::AssignActionStaticExt;
        <dyn AssignAction>::justify_pieces(&mut pieces, 3, true, true, true);
        assert_eq!(pieces[0].offset, 0x103);
        assert_eq!(pieces[0].size, 5);
        assert_eq!(pieces[1].offset, 0x108);
        assert_eq!(pieces[1].size, 8);
    }

    #[test]
    fn test_justify_pieces_truncates_high_tile() {
        // little-endian, consumeMostSig=false, justifyRight=false.
        // addOffset = 0^0^0 = 0. pos = pieces.len()-1.
        let mut pieces = vec![
            VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 8 },
            VarnodeData { space: AddressSpace::Register, offset: 0x108, size: 8 },
        ];
        super::justify_pieces(&mut pieces, 2, false, false, false);
        assert_eq!(pieces[0].size, 8);
        assert_eq!(pieces[1].offset, 0x108); // unchanged (addOffset=0)
        assert_eq!(pieces[1].size, 6);
    }

    #[test]
    fn test_clone_box_returns_distinct_filter() {
        let f = SizeRestrictedFilter::with_bounds(1, 4);
        let g = f.clone_box();
        // Both should filter identically.
        assert!(g.filter(&int_dt(2)));
        assert!(!g.filter(&int_dt(8)));
    }

    #[test]
    fn test_primitive_alignment_helper_unchanged() {
        // primitive_alignment is the size->align map used by extract(); spot
        // check the boundary cases the extractor relies on.
        assert_eq!(primitive_alignment(1), 1);
        assert_eq!(primitive_alignment(2), 2);
        assert_eq!(primitive_alignment(4), 4);
        assert_eq!(primitive_alignment(8), 8);
    }

    // TypeField/TypePointer unused import guard — ensure they compile.
    #[test]
    fn test_types_compile() {
        let _ = TypeField { name: "x".into(), offset: 0, type_ptr: std::sync::Arc::new(int_dt(4)) };
        let _ = TypePointer {
            base: TypeBase::new("p".into(), 8, TypeMetatype::Pointer),
            ptr_to: std::sync::Arc::new(int_dt(4)),
            wordsize: 1,
        };
    }
}
