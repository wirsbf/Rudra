//! Type casting and promotion strategies
//!
//! Corresponds to Ghidra's `cast.hh`. This module defines the rules
//! for when explicit casts are required in the output C code and how
//! types are promoted during arithmetic operations.

use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use crate::type_system::typefactory::TypeFactory;
use crate::varnode::Varnode;
use std::sync::Arc;

// Ghidra: cast.cc:394 CastStrategyC::arithmeticOutputStandard
/// The arithmetic typing rule: the output type of an arithmetic op is the
/// input HIGH (read-facing) type that orders earliest under
/// `Datatype::typeOrder` (bigger/more specific wins — unsigned over signed
/// of equal size, bigger size first, pointers over base types), with BOOL
/// inputs demoted to a base int of the same size (and skipped as
/// competitors). Faithful to `CastStrategyC::arithmeticOutputStandard`
/// (cast.cc:394-409); Ghidra reaches it through the TypeOp getOutputToken
/// overrides (typeop.cc:1175/1326/1388/1402/1416/1449/1482/1625).
// RUDRA-GLUE: free function instead of a CastStrategyC method — Rugra's
// CastStrategyC carries no TypeFactory member (tlst), so the factory is
// passed in by the caller.
pub fn arithmetic_output_standard(
    op: &PcodeOp,
    tlst: &Arc<std::sync::RwLock<TypeFactory>>,
) -> Option<Arc<Datatype>> {
    // cc:397-399: res1 = in(0) high read-facing; BOOL → base int of its size.
    let in0 = op.get_in(0)?;
    let mut res1 = in0
        .read()
        .unwrap()
        .get_high_type_read_facing(op, 0)
        .or_else(|| in0.read().unwrap().v_type.clone())?;
    if res1.get_metatype() == TypeMetatype::Bool {
        res1 = tlst
            .read()
            .unwrap()
            .get_base(res1.get_size(), TypeMetatype::Int)?;
    }
    // cc:402-407: each later input replaces res1 when it orders strictly
    // earlier (0 > res2->typeOrder(*res1), i.e. typeOrder < 0); BOOL skips.
    for i in 1..op.num_input() {
        let Some(vn) = op.get_in(i) else { continue };
        let Some(res2) = vn
            .read()
            .unwrap()
            .get_high_type_read_facing(op, i as i32)
            .or_else(|| vn.read().unwrap().v_type.clone())
        else {
            continue;
        };
        if res2.get_metatype() == TypeMetatype::Bool {
            continue;
        }
        if res2.type_order(&res1) < 0 {
            res1 = res2;
        }
    }
    Some(res1)
}

// RUDRA-GLUE: base_type_for (no Ghidra counterpart found)
/// Build a base integer/unsigned type for a given size and metatype.
/// Faithful to Ghidra `TypeFactory::getBase(size, metatype)` (type.cc) for
/// the integer cases: size 1→char/byte, 2→short, 4→int, 8→long (signed) /
/// ulong (unsigned). Used by input-type-local to derive the type an op
/// expects for its input slot (`TypeOpBinary::getInputLocal`,
/// typeop.cc:329-333).
pub fn base_type_for(size: usize, meta: TypeMetatype) -> Arc<Datatype> {
    let name = match (meta, size) {
        (TypeMetatype::Int, 1) => "byte",
        (TypeMetatype::Int, 2) => "short",
        (TypeMetatype::Int, 4) => "int",
        (TypeMetatype::Int, 8) => "long",
        (TypeMetatype::Uint, 1) => "undefined",
        (TypeMetatype::Uint, 2) => "ushort",
        (TypeMetatype::Uint, 4) => "uint",
        (TypeMetatype::Uint, 8) => "ulong",
        // Ghidra's comparison/boolean ops produce the TypeFactory's interned
        // `bool` base type (TypeOpFunc::getOutputLocal, typeop.cc:365-380);
        // the old fall-through labeled 1-byte bools as "long".
        (TypeMetatype::Bool, 1) => "bool",
        (TypeMetatype::Bool, _) => "bool",
        _ => "long",
    };
    Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, meta)))
}

/// Interface for determining when a cast is necessary
///
/// Corresponds to Ghidra's `CastStrategy` class.
pub trait CastStrategy {
    // RUDRA-GLUE: is_cast_implied (no Ghidra counterpart found)
    /// Decide if an explicit cast is required between two types
    fn is_cast_implied(&self, out_type: &Datatype, in_type: &Datatype) -> bool;

    // RUDRA-GLUE: cast_standard (no Ghidra counterpart found)
    /// Get the type of a constant, given a specific size and output requirement
    fn cast_standard(&self, out_type: &Datatype, in_type: &Datatype) -> Option<Arc<Datatype>>;

    // RUDRA-GLUE: check_int_promotion_for_extension (no Ghidra counterpart found)
    /// Determine if an integer promotion is required for an extension
    fn check_int_promotion_for_extension(&self, op_type: &Datatype) -> bool;

    // Ghidra: cast.cc:107 CastStrategyC::checkIntPromotionForCompare
    /// Determine if integer promotion requires a cast for one comparison slot.
    fn check_int_promotion_for_compare(&self, op: &PcodeOp, slot: usize) -> bool;
}

/// Standard C-language casting strategy
///
/// Corresponds to Ghidra's `CastStrategyC` class.
pub struct CastStrategyC {
    /// The size of an 'int' in the target architecture
    promote_size: usize,
}

impl CastStrategyC {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    pub fn new(promote_size: usize) -> Self {
        Self { promote_size }
    }

    // RUDRA-GLUE: get_promote_size (Ghidra reads the protected field directly)
    /// Size of the `int` data-type (size that integers get promoted to).
    ///
    /// Ghidra `CastStrategy::promoteSize` (cast.hh:57) is a protected field
    /// assigned once in `CastStrategy::setTypeFactory`
    /// (`promoteSize = tlst->getSizeOfInt()`, cast.cc:27); every consumer
    /// (cast.cc:86/182/284) is a strategy member function reading the field
    /// directly, so Ghidra has no accessor. Rugra's ported consumer
    /// `CastStrategyC::isExtensionCastImplied` (cast.cc:284) lives on
    /// `PrintC` (printc.rs `is_extension_cast_implied`), and the field is
    /// private to this module — cross-module reads need this accessor.
    /// Pure Rust visibility glue: no behavior of its own.
    pub fn get_promote_size(&self) -> usize {
        self.promote_size
    }

    // Ghidra: cast.cc:140 CastStrategyC::localExtensionType
    /// Determine the signed/unsigned extension implied by local properties of
    /// `vn` as it is read by `op`.
    fn local_extension_type(&self, vn: &Varnode, op: &PcodeOp) -> i32 {
        const UNKNOWN_PROMOTION: i32 = 0;
        const UNSIGNED_EXTENSION: i32 = 1;
        const SIGNED_EXTENSION: i32 = 2;
        const EITHER_EXTENSION: i32 = 3;

        let Some(slot) = vn.self_arc().and_then(|vn_arc| op.slot_of_input(&vn_arc)) else {
            return UNKNOWN_PROMOTION;
        };
        let Some(read_type) = vn.get_high_type_read_facing(op, slot as i32) else {
            return UNKNOWN_PROMOTION;
        };
        let natural = match read_type.get_metatype() {
            TypeMetatype::Uint
            | TypeMetatype::Bool
            | TypeMetatype::Unknown
            | TypeMetatype::PartialStruct
            | TypeMetatype::PartialUnion
            | TypeMetatype::Enum
            | TypeMetatype::PartialEnum => UNSIGNED_EXTENSION,
            TypeMetatype::Int => SIGNED_EXTENSION,
            _ => return UNKNOWN_PROMOTION,
        };
        if vn.is_constant() {
            if !crate::address::signbit_negative(vn.get_offset(), vn.get_size()) {
                return EITHER_EXTENSION;
            }
            return natural;
        }
        if vn.is_explicit() {
            return natural;
        }
        if !vn.is_written() {
            return UNKNOWN_PROMOTION;
        }
        let Some(definition) = vn.get_def() else {
            return UNKNOWN_PROMOTION;
        };
        let definition = definition.read().unwrap();
        if definition.is_bool_output() {
            return EITHER_EXTENSION;
        }
        if definition.opcode == OpCode::CPUI_CAST
            || definition.opcode == OpCode::CPUI_LOAD
            || definition.is_call()
        {
            return natural;
        }
        if definition.opcode == OpCode::CPUI_INT_AND {
            if let Some(mask) = definition.get_in(1) {
                let mask = mask.read().unwrap();
                if mask.is_constant() {
                    if !crate::address::signbit_negative(mask.get_offset(), mask.get_size()) {
                        return EITHER_EXTENSION;
                    }
                    return natural;
                }
            }
        }
        UNKNOWN_PROMOTION
    }

    // Ghidra: cast.cc:178 CastStrategyC::intPromotionType
    /// Calculate the integer-promotion extension code for `vn`.
    pub fn int_promotion_type(&self, vn: &Varnode) -> i32 {
        const NO_PROMOTION: i32 = -1;
        const UNKNOWN_PROMOTION: i32 = 0;
        const UNSIGNED_EXTENSION: i32 = 1;
        const SIGNED_EXTENSION: i32 = 2;

        if vn.get_size() >= self.promote_size {
            return NO_PROMOTION;
        }
        if vn.is_constant() {
            let Some(reader) = vn.lone_descend() else {
                return UNKNOWN_PROMOTION;
            };
            return self.local_extension_type(vn, &reader.read().unwrap());
        }
        if vn.is_explicit() {
            return NO_PROMOTION;
        }
        if !vn.is_written() {
            return UNKNOWN_PROMOTION;
        }
        let Some(definition) = vn.get_def() else {
            return UNKNOWN_PROMOTION;
        };
        let definition = definition.read().unwrap();
        let local_input = |slot: usize| {
            definition
                .get_in(slot)
                .map(|input| self.local_extension_type(&input.read().unwrap(), &definition))
                .unwrap_or(UNKNOWN_PROMOTION)
        };
        match definition.opcode {
            OpCode::CPUI_INT_AND => {
                if local_input(1) & UNSIGNED_EXTENSION != 0 {
                    return UNSIGNED_EXTENSION;
                }
                if local_input(0) & UNSIGNED_EXTENSION != 0 {
                    return UNSIGNED_EXTENSION;
                }
            }
            OpCode::CPUI_INT_RIGHT => {
                let extension = local_input(0);
                if extension & UNSIGNED_EXTENSION != 0 {
                    return extension;
                }
            }
            OpCode::CPUI_INT_SRIGHT => {
                let extension = local_input(0);
                if extension & SIGNED_EXTENSION != 0 {
                    return extension;
                }
            }
            OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_DIV
            | OpCode::CPUI_INT_REM => {
                if local_input(0) & UNSIGNED_EXTENSION == 0
                    || local_input(1) & UNSIGNED_EXTENSION == 0
                {
                    return UNKNOWN_PROMOTION;
                }
                return UNSIGNED_EXTENSION;
            }
            OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_SREM => {
                if local_input(0) & SIGNED_EXTENSION == 0 || local_input(1) & SIGNED_EXTENSION == 0
                {
                    return UNKNOWN_PROMOTION;
                }
                return SIGNED_EXTENSION;
            }
            OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_2COMP => {
                if local_input(0) & SIGNED_EXTENSION != 0 {
                    return SIGNED_EXTENSION;
                }
            }
            OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB
            | OpCode::CPUI_INT_LEFT
            | OpCode::CPUI_INT_MULT => {}
            _ => return NO_PROMOTION,
        }
        UNKNOWN_PROMOTION
    }

    // Ghidra: cast.cc:107 CastStrategyC::checkIntPromotionForCompare
    /// Check the two operands' promotion extensions exactly as the C casting
    /// strategy does for a comparison.
    pub fn check_int_promotion_for_compare_op(&self, op: &PcodeOp, slot: usize) -> bool {
        const NO_PROMOTION: i32 = -1;
        const UNKNOWN_PROMOTION: i32 = 0;

        let Some(first) = op.get_in(slot) else {
            return false;
        };
        let extension_first = self.int_promotion_type(&first.read().unwrap());
        if extension_first == NO_PROMOTION {
            return false;
        }
        if extension_first == UNKNOWN_PROMOTION {
            return true;
        }
        let other_slot = if slot == 0 { 1 } else { 0 };
        let Some(second) = op.get_in(other_slot) else {
            return true;
        };
        let extension_second = self.int_promotion_type(&second.read().unwrap());
        if extension_first & extension_second != 0 {
            return false;
        }
        if extension_second == NO_PROMOTION {
            return false;
        }
        true
    }

    // RUDRA-GLUE: is_char_type (no Ghidra counterpart found)
    /// Check if the type is a character type
    pub fn is_char_type(&self, dt: &Datatype) -> bool {
        // In Rugra, this would check the CHARTYPE flag in TypeBase
        (dt.get_flags() & crate::type_system::datatype::type_flags::CHARTYPE) != 0
    }

    // RUDRA-GLUE: is_enum_type (no Ghidra counterpart found)
    /// Check if the type is an enumeration type
    pub fn is_enum_type(&self, dt: &Datatype) -> bool {
        matches!(dt.get_metatype(), TypeMetatype::Enum)
    }
    // Ghidra: cast.cc:411 CastStrategyC::isSubpieceCast
    /// Check if a SUBPIECE op should be rendered as a cast.
    /// Faithful to Ghidra CastStrategyC::isSubpieceCast (cast.cc:411-432):
    ///
    /// ```text
    /// if (offset != 0) return false;
    /// type_metatype inmeta = intype->getMetatype();
    /// if (inmeta!=TYPE_INT && inmeta!=TYPE_UINT && inmeta!=TYPE_UNKNOWN && inmeta!=TYPE_PTR &&
    ///     inmeta!=TYPE_PARTIALSTRUCT && inmeta!=TYPE_PARTIALUNION)
    ///   return false;
    /// ```
    ///
    /// The input whitelist carries the PartialStruct/PartialUnion arms
    /// (cast.cc:417, PRINTC-SUBPIECE-FIELDEXTRACT-0001 gap (c)).
    ///
    /// Enum mapping note: Ghidra `TypeEnum` constructors (type.hh:489-494)
    /// normalize the stored metatype to TYPE_INT/TYPE_UINT
    /// (`metatype = (m==TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT`), so a Ghidra
    /// TypeEnum input/output passes these whitelists as UINT/INT.
    /// `TypePartialEnum` (type.cc:2255-2262) delegates to that same TypeEnum
    /// constructor with TYPE_PARTIALENUM, which the ternary also maps to
    /// TYPE_UINT — so Ghidra partial-enums pass the whitelists identically
    /// (verified against the locked oracle: cast.int_partialenum_0=1 /
    /// cast.partialenum_out_0=1). Rugra's `TypeMetatype::Enum` and
    /// `TypeMetatype::PartialEnum` are those same TypeEnum surfaces, so both
    /// are listed in the three whitelists to preserve the observable
    /// decision — same convention as
    /// `check_int_promotion_for_extension/compare` above (cast.rs:186/197),
    /// and consistent with the is_piece_structured doc (datatype.rs).
    pub fn is_subpiece_cast(&self, out_type: &Datatype, in_type: &Datatype, offset: u32) -> bool {
        if offset != 0 { return false; }
        // cast.cc:415-418: input metatype whitelist.
        let in_meta = in_type.get_metatype();
        if !matches!(
            in_meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Unknown
            | TypeMetatype::Pointer | TypeMetatype::PartialStruct | TypeMetatype::PartialUnion
            | TypeMetatype::Enum | TypeMetatype::PartialEnum
        )
        { return false; }
        // cast.cc:419-422: output metatype whitelist.
        let out_meta = out_type.get_metatype();
        if !matches!(
            out_meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Unknown
            | TypeMetatype::Pointer | TypeMetatype::Float | TypeMetatype::Enum
            | TypeMetatype::PartialEnum
        )
        { return false; }
        // cast.cc:423-430: pointer-input special cases.
        if in_meta == TypeMetatype::Pointer {
            if out_meta == TypeMetatype::Pointer {
                if out_type.get_size() < in_type.get_size() { return true; }
            }
            if !matches!(
                out_meta, TypeMetatype::Int | TypeMetatype::Uint
                | TypeMetatype::Enum | TypeMetatype::PartialEnum
            ) { return false; }
        }
        true
    }

    // Ghidra: cast.cc:434 CastStrategyC::isSubpieceCastEndian
    /// Check if a SUBPIECE with endianness should be rendered as a cast.
    /// Faithful to Ghidra CastStrategyC::isSubpieceCastEndian (cast.cc:434).
    pub fn is_subpiece_cast_endian(
        &self, out_type: &Datatype, in_type: &Datatype, offset: u32, is_bigend: bool,
    ) -> bool {
        let tmpoff = if is_bigend { in_type.get_size() as u32 - 1 - offset } else { offset };
        self.is_subpiece_cast(out_type, in_type, tmpoff)
    }

    // Ghidra: cast.cc:443 CastStrategyC::isSextCast
    /// Check if INT_SEXT should be rendered as a cast.
    /// Faithful to Ghidra CastStrategyC::isSextCast (cast.cc:443).
    pub fn is_sext_cast(&self, out_type: &Datatype, in_type: &Datatype) -> bool {
        let metaout = out_type.get_metatype();
        if !matches!(metaout, TypeMetatype::Uint | TypeMetatype::Int) { return false; }
        let metain = in_type.get_metatype();
        // Input must be signed for SEXT to be a cast
        matches!(metain, TypeMetatype::Int | TypeMetatype::Bool)
    }

    // Ghidra: cast.cc:457 CastStrategyC::isZextCast
    /// Check if INT_ZEXT should be rendered as a cast.
    /// Faithful to Ghidra CastStrategyC::isZextCast (cast.cc:457).
    pub fn is_zext_cast(&self, out_type: &Datatype, in_type: &Datatype) -> bool {
        let metaout = out_type.get_metatype();
        if !matches!(metaout, TypeMetatype::Uint | TypeMetatype::Int) { return false; }
        let metain = in_type.get_metatype();
        // Input must be unsigned for ZEXT to be a cast
        matches!(metain, TypeMetatype::Uint | TypeMetatype::Bool)
    }
}

impl CastStrategy for CastStrategyC {
    // RUDRA-GLUE: is_cast_implied (no Ghidra counterpart found)
    fn is_cast_implied(&self, out_type: &Datatype, in_type: &Datatype) -> bool {
        if Arc::ptr_eq(&Arc::new(out_type.clone()), &Arc::new(in_type.clone())) {
            return true;
        }

        let out_meta = out_type.get_metatype();
        let in_meta = in_type.get_metatype();

        if out_meta == in_meta {
            match out_meta {
                TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool => {
                    // Implied if output is at least as large as input
                    return out_type.get_size() >= in_type.get_size();
                }
                TypeMetatype::Pointer => {
                    // Pointers usually need explicit casts unless they are the same
                    // or one is void* (not fully implemented here)
                    return false;
                }
                _ => return false,
            }
        }

        // C allows implicit conversion from array to pointer
        if out_meta == TypeMetatype::Pointer && in_meta == TypeMetatype::Array {
            return true;
        }

        // Pointer to boolean (e.g. if (ptr))
        if out_meta == TypeMetatype::Bool && in_meta == TypeMetatype::Pointer {
            return true;
        }

        false
    }

    // Ghidra: cast.cc:300 CastStrategyC::castStandard
    fn cast_standard(&self, out_type: &Datatype, in_type: &Datatype) -> Option<Arc<Datatype>> {
        if self.is_cast_implied(out_type, in_type) {
            return None;
        }
        Some(Arc::new(out_type.clone()))
    }

    // Ghidra: cast.cc:126 CastStrategyC::checkIntPromotionForExtension
    fn check_int_promotion_for_extension(&self, op_type: &Datatype) -> bool {
        let size = op_type.get_size();
        if size >= self.promote_size {
            return false;
        }
        let meta = op_type.get_metatype();
        // Small integers, booleans, and enums are promoted in C
        matches!(
            meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool | TypeMetatype::Enum
        )
    }

    // Ghidra: cast.cc:107 CastStrategyC::checkIntPromotionForCompare
    fn check_int_promotion_for_compare(&self, op: &PcodeOp, slot: usize) -> bool {
        self.check_int_promotion_for_compare_op(op, slot)
    }
}

// Mirror of the oracle's TypeFactory::findAdd interning invariant for the
// cast.cc identity short-circuits (cast.cc:304 `curtype == reqtype` /
// :329 `curbase == reqbase`). Ghidra compares interned Datatype pointers,
// and findAdd guarantees that compare is structural: a name+id hit whose
// `compareDependency` is equal returns the EXISTING factory object
// (type.cc:3423-3427), so two distinct Datatype objects with the same
// (name, size, sub-metatype) can never meet inside the decompiler.
// compareDependency for base scalars is exactly (submeta, size)
// (type.cc:227-233), and id is hashName(name) on both sides of a name hit,
// so the findAdd-equal key reduces to (name, size, sub-metatype) —
// base_submeta folds the chartype/enum/UTF flags the same way. Rugra's
// import/seed layers can mint structurally equal base scalars outside the
// factory (observed: non-core "bool"/"byte" clones), so the cast decision
// must compare that key for Base variants instead of bare Arc identity;
// every other variant keeps Arc identity, matching the oracle's pointer
// compare for composites.
//
// Locked-oracle witnesses (ghidra_curl_1204.c vs the pre-fix canon):
// `if (aliases[iVar15].extraparam != false)` / `*usedarg == false` /
// `pbVar1 = buffer;` — the golden's bare forms require this equality at
// the LOAD-address / comparison / COPY cast decisions, where the pre-fix
// run inserted `*(bool *)&…` / `*(bool *)…` / `(bool *)…` casts because a
// mint bool and the factory core bool are distinct Arcs.
// Ghidra: type.cc:3412 TypeFactory::findAdd
fn findadd_equal(a: &Arc<Datatype>, b: &Arc<Datatype>) -> bool {
    if Arc::ptr_eq(a, b) {
        return true;
    }
    match (a.as_ref(), b.as_ref()) {
        (Datatype::Base(x), Datatype::Base(y)) => {
            x.name == y.name && x.size == y.size && a.get_submeta() == b.get_submeta()
        }
        _ => false,
    }
}

impl CastStrategyC {
    // RUDRA-GLUE: cast_standard_full (no Ghidra counterpart found)
    /// Faithful 1:1 port of Ghidra `CastStrategyC::castStandard`
    /// (cast.cc:300-392). Determines whether an explicit cast is required
    /// when a varnode of `curtype` feeds an op expecting `reqtype`.
    ///
    /// Returns `Some(reqtype)` if a cast IS needed (the caller inserts a
    /// CPUI_CAST emitting `(reqtype)expr`), or `None` if no cast is needed.
    ///
    /// `care_uint_int` — if true, distinguish signed/unsigned (used under
    ///   pointers, where the distinction matters); if false, treat int/uint
    ///   interchangeably (most arithmetic ops).
    /// `care_ptr_uint` — if true, casting a pointer to an integer DOES need a
    ///   cast (e.g. STORE value slot); if false, it's implied.
    ///
    /// Partial types (TYPE_PARTIALSTRUCT/TYPE_PARTIALUNION) never take a
    /// cast: as the cast-request they return no-cast unconditionally
    /// (cast.cc:341-343, "As they are ultimately stripped, treat partials as
    /// undefined"), and as the current type they ride every curmeta
    /// whitelist that admits TYPE_UNKNOWN (cast.cc:348-349/356 uint arms,
    /// cast.cc:366-367/374 int arms).
    ///
    /// Typedef chains strip through the per-type `typedef_imm` channel
    /// (cast.cc:325-328, type.hh:196/244). Rugra's Datatype still lacks
    /// variable-length arrays and per-pointer AddrSpace; those branches are
    /// faithfully no-ops (a cast decision is never wrong in their absence —
    /// at worst slightly more conservative).
    pub fn cast_standard_full(
        &self,
        reqtype: &Arc<Datatype>,
        curtype: &Arc<Datatype>,
        mut care_uint_int: bool,
        care_ptr_uint: bool,
    ) -> Option<Arc<Datatype>> {
        // Types equal → no cast. Ghidra compares the interned Datatype
        // pointers (cast.cc:302 `curtype == reqtype`); that pointer compare
        // rides the TypeFactory::findAdd interning invariant — a name+id
        // hit whose compareDependency is equal returns the EXISTING
        // factory object (type.cc:3423-3427), so two distinct Datatype
        // objects with the same (name, size, sub-metatype) can never meet
        // inside the decompiler. Rugra's import/seed layers can mint
        // structurally equal base scalars outside the factory (observed:
        // non-core "bool" clones meeting the factory core bool at
        // ActionSetCasts, printing `*(bool *)&aliases[V].extraparam` /
        // `*(bool *)usedarg` in getparameter where the locked golden
        // prints the bare field/deref form), so an Arc::ptr_eq-only
        // mirror would insert casts the oracle never produces.
        // `findadd_equal` restores the oracle-equivalent decision: the
        // findAdd-equal key (name, size, sub-metatype — compareDependency,
        // type.cc:227-233) for Base variants, Arc identity for everything
        // else (composites keep the oracle's pointer compare).
        if findadd_equal(reqtype, curtype) {
            return None;
        }
        // From void → always cast. Returned Arc preserves reqtype identity
        // (Ghidra returns the same interned Datatype*), so downstream
        // pointer-identity comparisons (e.g. castOutput's
        // `tokenct == outHighType`, coreaction.cc:2544) behave as in the
        // oracle.
        let req_arc = Arc::clone(reqtype);
        if curtype.get_metatype() == TypeMetatype::Void {
            return Some(req_arc);
        }
        // Peel matching pointer layers (cast.cc:310-324).
        let mut reqbase = reqtype;
        let mut curbase = curtype;
        let mut isptr = false;
        while reqbase.get_metatype() == TypeMetatype::Pointer
            && curbase.get_metatype() == TypeMetatype::Pointer
        {
            // Rugra TypePointer has no separate AddrSpace/wordsize comparison
            // beyond wordsize==1 default; skip the space-mismatch cast branch
            // (would need AddrSpace wiring). Wordsize equality is implicitly
            // handled by size equality below.
            reqbase = match reqbase.as_ref() { Datatype::Pointer(p) => &p.ptr_to, _ => break ,
            };
            curbase = match curbase.as_ref() { Datatype::Pointer(p) => &p.ptr_to, _ => break ,
            };
            care_uint_int = true;
            isptr = true;
        }
        // cast.cc:325-328: strip the typedef chains on both bases —
        // `while(reqbase->getTypedef() != 0) reqbase = reqbase->getTypedef();`
        // (and the curbase twin) — "Different typedefs could point to the
        // same type" (cast.cc:329). Rugra walks the per-type `typedef_imm`
        // channel (type.hh:196/244), set only by factory get_typedef
        // (type.cc:3834), so non-typedef bases stop immediately exactly as
        // the oracle's null typedefImm does.
        let mut reqbase = reqbase.clone();
        while let Some(target) = reqbase.get_typedef() {
            reqbase = target.clone();
        }
        let mut curbase = curbase.clone();
        while let Some(target) = curbase.get_typedef() {
            curbase = target.clone();
        }
        // The peeled bases are compared with the same findAdd-equal key that
        // backs the oracle's interned `curbase == reqbase` (cast.cc:329):
        // (name, size, sub-metatype) for Base variants, Arc identity
        // otherwise. This is the arm that resolves pointer-layer splits —
        // e.g. ptr(factory-bool) vs ptr(mint-bool) peels to equal bases —
        // keeping the locked golden's bare `V = buffer;` COPY form free
        // of a spurious `(bool *)` cast.
        if findadd_equal(&reqbase, &curbase) {
            return None;
        }
        // Ghidra's TypeEnum stores TYPE_INT/TYPE_UINT as its metatype —
        // every construction path runs
        // `metatype = (m==TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT` (inline
        // ctors type.hh:491-494; decode path type.cc:1475 "Use TYPE_INT or
        // TYPE_UINT internally") — so cast.cc:339-389's switch never sees a
        // distinct enum metatype; enum-ness rides the ENUMTYPE flag (see
        // the "meta can be TYPE_UINT ... if typedef/enumerated" comments
        // at cast.cc:347/363). Rugra carries a distinct `Enum` metatype
        // (signedness untracked → signed default, cf. get_submeta's
        // IntEnum mapping) plus `PartialEnum`; normalize both to the
        // internal Ghidra presentation: Enum → Int, PartialEnum → Uint
        // (TYPE_PARTIALENUM is "a specialization of TYPE_UINT",
        // type.hh:96, and the type.hh:491 ternary maps it to TYPE_UINT).
        let ghidra_meta = |m: TypeMetatype| match m {
            TypeMetatype::Enum => TypeMetatype::Int,
            TypeMetatype::PartialEnum => TypeMetatype::Uint,
            other => other,
        };
        let reqmeta = ghidra_meta(reqbase.get_metatype());
        let curmeta = ghidra_meta(curbase.get_metatype());
        // Don't cast to/from a void pointer.
        if reqmeta == TypeMetatype::Void || curmeta == TypeMetatype::Void {
            return None;
        }
        // Size change → always cast (cast.cc:333-337).
        if reqbase.get_size() != curbase.get_size() {
            return Some(req_arc);
        }
        // Same size: metatype-specific rules (cast.cc:339-389).
        // cast.cc:340-343: a partial type as the cast request is never cast —
        // "As they are ultimately stripped, treat partials as undefined".
        match reqmeta {
            TypeMetatype::Unknown
            | TypeMetatype::PartialStruct
            | TypeMetatype::PartialUnion => return None,
            _ => {}
        }
        match reqmeta {
            TypeMetatype::Uint => {
                if !care_uint_int {
                    // cast.cc:348-349: partial cur-types ride the unknown list.
                    if matches!(
                        curmeta,
                        TypeMetatype::Unknown | TypeMetatype::Int | TypeMetatype::Uint
                        | TypeMetatype::Bool | TypeMetatype::PartialStruct
                        | TypeMetatype::PartialUnion
                    ) {
                        return None;
                    }
                } else {
                    if matches!(curmeta, TypeMetatype::Uint | TypeMetatype::Bool) {
                        return None;
                    }
                    // cast.cc:356-357: don't cast pointers to unknown/partials.
                    if isptr
                        && matches!(
                            curmeta,
                            TypeMetatype::Unknown | TypeMetatype::PartialStruct
                            | TypeMetatype::PartialUnion
                        )
                    {
                        return None; // Don't cast pointers to unknown
                    }
                }
                if !care_ptr_uint && curmeta == TypeMetatype::Pointer {
                    return None;
                }
            }
            TypeMetatype::Int => {
                if !care_uint_int {
                    // cast.cc:366-367: partial cur-types ride the unknown list.
                    if matches!(
                        curmeta,
                        TypeMetatype::Unknown | TypeMetatype::Int | TypeMetatype::Uint
                        | TypeMetatype::Bool | TypeMetatype::PartialStruct
                        | TypeMetatype::PartialUnion
                    ) {
                        return None;
                    }
                } else {
                    if matches!(curmeta, TypeMetatype::Int | TypeMetatype::Bool) {
                        return None;
                    }
                    // cast.cc:374-375: don't cast pointers to unknown/partials.
                    if isptr
                        && matches!(
                            curmeta,
                            TypeMetatype::Unknown | TypeMetatype::PartialStruct
                            | TypeMetatype::PartialUnion
                        )
                    {
                        return None;
                    }
                }
            }
            // TYPE_CODE / default → fall through to "cast needed".
            _ => {}
        }
        Some(req_arc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

    #[test]
    fn test_c_implied_cast() {
        let strategy = CastStrategyC::new(4);

        let int4 = Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int));
        let int2 = Datatype::Base(TypeBase::new("short".to_string(), 2, TypeMetatype::Int));

        // short to int is implied
        assert!(strategy.is_cast_implied(&int4, &int2));
        // int to short requires cast
        assert!(!strategy.is_cast_implied(&int2, &int4));
    }

    #[test]
    fn test_c_promotion() {
        let strategy = CastStrategyC::new(4);

        let int1 = Datatype::Base(TypeBase::new("char".to_string(), 1, TypeMetatype::Int));
        let int4 = Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int));

        // char is promoted
        assert!(strategy.check_int_promotion_for_extension(&int1));
        // int is not promoted (already at promote size)
        assert!(!strategy.check_int_promotion_for_extension(&int4));
    }

    #[test]
    fn test_is_subpiece_cast() {
        let s = CastStrategyC::new(4);
        let int4 = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        let int8 = Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int));
        // offset 0, int→int subpiece is a cast
        assert!(s.is_subpiece_cast(&int4, &int8, 0));
        // offset != 0 → not a cast
        assert!(!s.is_subpiece_cast(&int4, &int8, 4));
    }

    // Ghidra: cast.cc:413-418 — PartialStruct/PartialUnion input arms.
    #[test]
    fn test_is_subpiece_cast_partial_inputs() {
        use crate::type_system::datatype::{
            TypePartialStruct, TypePartialUnion, TypeStruct, TypeUnion,
        };
        let s = CastStrategyC::new(4);
        let int4 = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        let int8 = Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int));
        let struct8 = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("pair".into(), 8, TypeMetatype::Struct),
            fields: vec![],
        }));
        let union8 = Arc::new(Datatype::Union(TypeUnion {
            base: TypeBase::new("alt".into(), 8, TypeMetatype::Union),
            fields: vec![],
        }));
        let ps = Datatype::PartialStruct(TypePartialStruct::new(struct8.clone(), 4, 4, None));
        let pu = Datatype::PartialUnion(TypePartialUnion::new(union8, 0, 4, None));
        // cast.cc:417: TYPE_PARTIALSTRUCT input at offset 0 → cast.
        assert!(s.is_subpiece_cast(&int4, &ps, 0));
        // cast.cc:417: TYPE_PARTIALUNION input at offset 0 → cast.
        assert!(s.is_subpiece_cast(&int4, &pu, 0));
        // offset != 0 still rejects partial inputs (cast.cc:414).
        assert!(!s.is_subpiece_cast(&int4, &ps, 4));
        assert!(!s.is_subpiece_cast(&int4, &pu, 2));
        // PartialStruct output is NOT whitelisted (cast.cc:419-422).
        assert!(!s.is_subpiece_cast(&ps, &int8, 0));
        // Struct input is NOT whitelisted (cast.cc:416).
        assert!(!s.is_subpiece_cast(&int4, struct8.as_ref(), 0));
    }

    // Ghidra: type.hh:489-494 TypeEnum ctor normalizes metatype to INT/UINT,
    // so a Ghidra enum passes the cast.cc:416 whitelist as UINT/INT; Rugra's
    // TypeMetatype::Enum is that same surface (see is_subpiece_cast doc).
    // TypePartialEnum (type.cc:2255-2262) delegates to the same ctor and so
    // passes as TYPE_UINT too (audit-verified: cast.int_partialenum_0=1 /
    // cast.partialenum_out_0=1 against the locked oracle).
    #[test]
    fn test_is_subpiece_cast_enum_mapping() {
        use crate::type_system::datatype::TypePartialEnum;
        let s = CastStrategyC::new(4);
        let enum4 = Datatype::Base(TypeBase::new("mode".into(), 4, TypeMetatype::Enum));
        let int8 = Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int));
        let int4 = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        assert!(s.is_subpiece_cast(&int4, &enum4, 0));
        assert!(s.is_subpiece_cast(&enum4, &int8, 0));
        // PartialEnum in-arm and out-arm (REWORK #2).
        let partial_enum =
            Datatype::PartialEnum(TypePartialEnum::new(Arc::new(enum4.clone()), 0, 2, None));
        assert!(s.is_subpiece_cast(&int4, &partial_enum, 0));
        assert!(s.is_subpiece_cast(&partial_enum, &int8, 0));
        // offset != 0 still rejects.
        assert!(!s.is_subpiece_cast(&int4, &partial_enum, 2));
    }

    #[test]
    fn test_is_sext_cast() {
        let s = CastStrategyC::new(4);
        let int2 = Datatype::Base(TypeBase::new("short".into(), 2, TypeMetatype::Int));
        let int4 = Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int));
        // signed input → sext is a cast
        assert!(s.is_sext_cast(&int4, &int2));
    }

    #[test]
    fn test_is_zext_cast() {
        let s = CastStrategyC::new(4);
        let uint2 = Datatype::Base(TypeBase::new("ushort".into(), 2, TypeMetatype::Uint));
        let uint4 = Datatype::Base(TypeBase::new("uint".into(), 4, TypeMetatype::Uint));
        // unsigned input → zext is a cast
        assert!(s.is_zext_cast(&uint4, &uint2));
        // signed input → zext is NOT a cast
        let int2 = Datatype::Base(TypeBase::new("short".into(), 2, TypeMetatype::Int));
        assert!(!s.is_zext_cast(&uint4, &int2));
    }

    // Ghidra: cast.hh:57 / cast.cc:27 — promoteSize is assigned once from
    // tlst->getSizeOfInt() and read by strategy members (cast.cc:86/182/284).
    // printc.rs's is_extension_cast_implied (the cast.cc:284 consumer) reads
    // it through this accessor; pin the accessor to the constructor value so
    // the PrintC::new(4) construction and the comparison stay wired to the
    // same field (PRINTC-PTRCONST-DAT-SYMBOL-0001 M4).
    #[test]
    fn test_get_promote_size_matches_constructor() {
        assert_eq!(CastStrategyC::new(4).get_promote_size(), 4);
        assert_eq!(CastStrategyC::new(8).get_promote_size(), 8);
        assert_eq!(CastStrategyC::new(2).get_promote_size(), 2);
    }

    // Ghidra: cast.cc:340-343 — partial cast-requests are never cast
    // ("As they are ultimately stripped, treat partials as undefined"), and
    // cast.cc:348-349/356 (uint) + 366-367/374 (int) — partial current types
    // ride every curmeta whitelist that admits TYPE_UNKNOWN.
    // CAST-PARTIAL-REQ-NOCAST-0001: this is the STORE value-slot rule that
    // keeps `glob._296_8_ = uVar29;` free of a spurious `(undefined8)`.
    #[test]
    fn test_cast_standard_full_partial_no_cast() {
        use crate::type_system::datatype::{
            TypeBase, TypeMetatype, TypePartialStruct, TypePartialUnion, TypePointer, TypeStruct,
            TypeUnion,
        };
        let s = CastStrategyC::new(4);

        let uint4 = Arc::new(Datatype::Base(TypeBase::new(
            "undefined4".into(),
            4,
            TypeMetatype::Uint,
        )));
        let int4 = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        let struct8 = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("pair".into(), 8, TypeMetatype::Struct),
            fields: vec![],
        }));
        let union8 = Arc::new(Datatype::Union(TypeUnion {
            base: TypeBase::new("alt".into(), 8, TypeMetatype::Union),
            fields: vec![],
        }));
        // 4-byte partials of 8-byte containers (same size as uint4/int4).
        let ps4 = Arc::new(Datatype::PartialStruct(TypePartialStruct::new(
            struct8.clone(),
            0,
            4,
            None,
        )));
        let pu4 = Arc::new(Datatype::PartialUnion(TypePartialUnion::new(
            union8.clone(),
            0,
            4,
            None,
        )));

        // cast.cc:341-342: partial as the REQUEST → no cast, regardless of
        // the care flags (mirrors TypeOpStore slot-2 pointedToType when the
        // store target is a partial piece).
        assert!(
            s.cast_standard_full(&ps4, &uint4, false, true).is_none(),
            "req=PartialStruct must not cast (cc:341)"
        );
        assert!(
            s.cast_standard_full(&pu4, &uint4, false, true).is_none(),
            "req=PartialUnion must not cast (cc:342)"
        );

        // cast.cc:348-349: req=UINT !care_uint_int, cur=partial → no cast.
        assert!(s.cast_standard_full(&uint4, &ps4, false, true).is_none());
        assert!(s.cast_standard_full(&uint4, &pu4, false, true).is_none());
        // cast.cc:366-367: req=INT !care_uint_int, cur=partial → no cast.
        assert!(s.cast_standard_full(&int4, &ps4, false, true).is_none());
        assert!(s.cast_standard_full(&int4, &pu4, false, true).is_none());

        // Size gate still precedes the switch (cc:333-337): an 8-byte
        // partial vs 4-byte uint keeps its cast.
        let ps8 = Arc::new(Datatype::PartialStruct(TypePartialStruct::new(
            struct8, 0, 8, None,
        )));
        assert!(s.cast_standard_full(&uint4, &ps8, false, true).is_some());

        // cast.cc:356-357 / 374-375: under pointers (care_uint_int forced
        // true by the peel), cur=partial → no cast ("don't cast pointers to
        // unknown").
        let ptr_to_uint4 = |p: Arc<Datatype>| {
            Arc::new(Datatype::Pointer(TypePointer {
                base: TypeBase::new("ptr".into(), 8, TypeMetatype::Pointer),
                ptr_to: p,
                wordsize: 1,
            }))
        };
        let req_ptr = ptr_to_uint4(uint4.clone());
        let cur_ptr = ptr_to_uint4(ps4.clone());
        assert!(s.cast_standard_full(&req_ptr, &cur_ptr, false, true).is_none());
        let cur_ptr_u = ptr_to_uint4(pu4.clone());
        assert!(s
            .cast_standard_full(&req_ptr, &cur_ptr_u, false, true)
            .is_none());

        // Control: care_uint_int=true WITHOUT pointer peel keeps the partial
        // cast (partials only ride the isptr sub-arm of the care branch).
        assert!(s.cast_standard_full(&uint4, &ps4, true, true).is_some());
        assert!(s.cast_standard_full(&int4, &pu4, true, true).is_some());
    }
}

    #[test]
    fn test_findadd_equal_base_key() {
        // type.cc:3423-3427 findAdd: a name+id hit whose compareDependency
        // (submeta, size — type.cc:227-233) is equal returns the EXISTING
        // object, so (name, size, sub-metatype) is the oracle-equivalent of
        // the cast.cc:304/:329 pointer identity for base scalars.
        let core_bool = Arc::new(Datatype::Base(TypeBase::new(
            "bool".to_string(),
            1,
            TypeMetatype::Bool,
        )));
        let mint_bool = Arc::new(Datatype::Base(TypeBase::new(
            "bool".to_string(),
            1,
            TypeMetatype::Bool,
        )));
        assert!(!Arc::ptr_eq(&core_bool, &mint_bool));
        assert!(findadd_equal(&core_bool, &mint_bool));
        // Different name → distinct findAdd entries → not equal.
        let char1 = Arc::new(Datatype::Base(TypeBase::new(
            "char".to_string(),
            1,
            TypeMetatype::Int,
        )));
        assert!(!findadd_equal(&core_bool, &char1));
        // Same name/size but a different sub-metatype (TypeChar's IntChar
        // vs plain Int) is a compareDependency mismatch — findAdd keeps
        // them distinct, so the cast identity must too.
        let char_typed = Arc::new(Datatype::Base(TypeBase::new_char(
            "char".to_string(),
            TypeMetatype::Int,
        )));
        assert_ne!(char_typed.get_submeta(), char1.get_submeta());
        assert!(!findadd_equal(&char_typed, &char1));
        // Size is part of compareDependency.
        let int4 = Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(),
            4,
            TypeMetatype::Int,
        )));
        let int8 = Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(),
            8,
            TypeMetatype::Int,
        )));
        assert!(!findadd_equal(&int4, &int8));
    }

    // Ghidra: cast.cc:325-328 — the typedef strip loops in castStandard.
    // "Different typedefs could point to the same type" (cast.cc:329): a
    // typedef alias and its base are the same type for cast purposes, so no
    // cast may be emitted between them — including chained typedefs. The
    // channel is per-instance (type.hh:196/244), so a hand-minted look-alike
    // sharing the typedef's name does NOT strip and keeps its cast.
    #[test]
    fn test_cast_standard_full_typedef_strip() {
        use crate::type_system::datatype::TypeMetatype;
        use crate::type_system::typefactory::{SizeArchInputs, TypeFactory};
        let mut factory = TypeFactory::raw();
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let strategy = CastStrategyC::new(8);
        let f4 = factory.get_base(4, TypeMetatype::Float).expect("float4");
        let f8 = factory.get_base(8, TypeMetatype::Float).expect("float8");
        let td_f4 = factory.get_typedef("td_float", f4.clone());
        let td_td_f4 = factory.get_typedef("td_td_float", td_f4.clone());
        // The channel is set on the factory clone (type.cc:3834) and walks
        // home: alias vs base and chained alias vs base take no cast
        // (without the strip the FLOAT default arm at cast.cc:387-391
        // would emit one).
        assert!(td_f4.get_typedef().is_some());
        assert!(f4.get_typedef().is_none());
        assert!(strategy
            .cast_standard_full(&td_f4, &f4, false, true)
            .is_none());
        assert!(strategy
            .cast_standard_full(&f4, &td_f4, false, true)
            .is_none());
        assert!(strategy
            .cast_standard_full(&td_td_f4, &f4, false, true)
            .is_none());
        // Size gate still precedes everything after the strip (cc:333-337).
        assert!(strategy
            .cast_standard_full(&td_f4, &f8, false, true)
            .is_some());
        // Identity-keyed channel: a look-alike sharing the typedef's name
        // has a null channel (type.hh:215 base ctor) and keeps its cast —
        // the oracle's instance field never strips a distinct object.
        let mut lookalike_base =
            crate::type_system::datatype::TypeBase::new(
                "td_float".to_string(),
                4,
                TypeMetatype::Float,
            );
        lookalike_base.typedef_imm = None;
        let lookalike = Arc::new(Datatype::Base(lookalike_base));
        assert!(strategy
            .cast_standard_full(&lookalike, &f4, false, true)
            .is_some());
    }

    #[test]
    fn test_cast_standard_structurally_equal_base_no_cast() {
        // cast.cc:304 `curtype == reqtype` → NULL: in the oracle the two
        // bools would be the ONE interned factory object, so a structurally
        // equal non-factory clone must not take a cast either — the
        // locked-oracle witnesses are the bare `aliases[V].extraparam` /
        // `*usedarg` / `V = buffer` forms (ghidra_curl_1204.c:1755/2115,
        // the pre-fix canon printed `*(bool *)&…`/`*(bool *)…`/`(bool *)…`).
        let strategy = CastStrategyC::new(8);
        let core_bool = Arc::new(Datatype::Base(TypeBase::new(
            "bool".to_string(),
            1,
            TypeMetatype::Bool,
        )));
        let mint_bool = Arc::new(Datatype::Base(TypeBase::new(
            "bool".to_string(),
            1,
            TypeMetatype::Bool,
        )));
        assert!(strategy
            .cast_standard_full(&core_bool, &mint_bool, false, true)
            .is_none());
        assert!(strategy
            .cast_standard_full(&mint_bool, &core_bool, false, true)
            .is_none());
        // Pointer layers peel to the equal bases (cast.cc:310-329): the
        // COPY-shape `V = buffer` decision sees ptr(bool) on both sides.
        let ptr_core = Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer::new(
            8,
            core_bool.clone(),
            1,
        )));
        let ptr_mint = Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer::new(
            8,
            mint_bool.clone(),
            1,
        )));
        assert!(strategy
            .cast_standard_full(&ptr_core, &ptr_mint, false, true)
            .is_none());
        // bool vs char (same size, different findAdd entries) still casts —
        // the Bool request falls through cast.cc's switch default.
        let char1 = Arc::new(Datatype::Base(TypeBase::new(
            "char".to_string(),
            1,
            TypeMetatype::Int,
        )));
        assert!(strategy
            .cast_standard_full(&core_bool, &char1, false, true)
            .is_some());
    }
