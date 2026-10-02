//! Type operations for P-code
//!
//! Corresponds to Ghidra's `typeop.hh`

use crate::address::calc_mask;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::printc::{OpArcRef, PrintC};
use crate::printlanguage::PrintLanguage;
use crate::space::AddressSpace;
use crate::type_system::typefactory::TypeFactory;
use crate::type_system::{Datatype, TypeMetatype};
// use crate::varnode::Varnode;
use std::any::Any;
use std::sync::{Arc, RwLock};

// Forward declarations/Stubs for related modules
pub mod stubs {
    #[derive(Debug)]
    pub struct OpBehavior;
    #[derive(Debug)]
    pub struct Encoder;
}

// use stubs::*;

/// Flags for TypeOp properties (from Ghidra's TypeOp class)
pub mod typeop_flags {
    pub const INHERITS_SIGN: u32 = 1 << 0;
    pub const INHERITS_SIGN_ZERO: u32 = 1 << 1;
    pub const SHIFT_OP: u32 = 1 << 2;
    pub const ARITHMETIC_OP: u32 = 1 << 3;
    pub const LOGICAL_OP: u32 = 1 << 4;
    pub const FLOATINGPOINT_OP: u32 = 1 << 5;
}

// ---------------------------------------------------------------------------
// RUDRA-GLUE: PrintC recovery helper for `TypeOp::push` dispatch.
//
// Ghidra models per-opcode printing as virtual `TypeOp*::push(lng, op, readOp)`
// methods (typeop.hh:170) that each call a single `PrintLanguage` virtual such
// as `opCallind`, `opPtrsub`, `opCast`, ... (typeop.hh:329/837/809...). In C++
// these are virtuals on the abstract `PrintLanguage` base; `PrintC` overrides
// the ones it cares about. The Rust port keeps the corresponding emitters
// (`op_callind`, `op_ptrsub`, `op_type_cast`, `op_callother`, `op_new`,
// `op_insert`, `op_extract`, `op_cpoolref`, `op_segment`) as *inherent* methods
// on `PrintC` (see printc.rs), not as `PrintLanguage` trait methods, so a
// `&mut dyn PrintLanguage` cannot name them directly.
//
// To preserve the exact 1:1 routing Ghidra uses (CALLIND -> opCallind,
// PTRSUB -> opPtrsub, CAST -> opCast, ...) we recover the concrete `PrintC`
// behind the trait object via an `Any` down-cast and call the inherent method.
// `PrintLanguage: Any` (printlanguage.rs) is what makes this cast possible; the
// fallback `lng.op_binary(op)` mirrors Ghidra's behaviour for any future
// `PrintLanguage` implementation that is not `PrintC`.
// ---------------------------------------------------------------------------

/// Down-cast a `&mut dyn PrintLanguage` to the concrete `PrintC`.
///
/// Returns `None` for any `PrintLanguage` implementation other than `PrintC`.
/// This is the Rust equivalent of the implicit C++ up-cast from
/// `PrintLanguage*` to `PrintC*` that Ghidra relies on inside `TypeOp*::push`.
// RUDRA-GLUE: enabled by `PrintLanguage: Any` (printlanguage.rs); used by the
//   per-opcode `push` dispatchers below to reach PrintC-specific emitters.
fn as_printc_mut(lng: &mut dyn PrintLanguage) -> Option<&mut PrintC> {
    // Up-cast `&mut dyn PrintLanguage` to `&mut dyn Any` (valid because
    // PrintLanguage is declared a sub-trait of Any) then down-cast to PrintC.
    let any_ref: &mut dyn Any = lng;
    any_ref.downcast_mut::<PrintC>()
}

/// Shared canonical base lookup behind every `get*Local` implementation in
/// this file: `tlst->getBase(size, meta)` (typeop.cc:264/274 for the TypeOp
/// base-class `TYPE_UNKNOWN` defaults; typeop.cc:323/329 TypeOpBinary,
/// typeop.cc:345/351 TypeOpUnary and typeop.cc:365/371 TypeOpFunc use the same
/// shape with the metatype their subclass constructors register). `tlst` is
/// the TypeFactory every TypeOp constructor receives (typeop.cc:233-242);
/// For sizes within the architecture base limit, `getBase` returns the
/// canonical interned base type. Ghidra converts larger requests to an
/// unknown-byte array (type.cc:3652-3656); Rudra's remaining large-base
/// caller closure is tracked by `TYPEFACTORY-LOCALTYPE-CACHE-0001`.
// Ghidra: typeop.cc:261 TypeOp::getOutputLocal / typeop.cc:274 TypeOp::getInputLocal
fn base_local_type(
    type_factory: &Arc<RwLock<TypeFactory>>,
    size: usize,
    metatype: TypeMetatype,
) -> Option<Arc<Datatype>> {
    type_factory.read().unwrap().get_base(size, metatype)
}

// (The former `default_input_cast` stub — a None-returning placeholder for
// the base `TypeOp::getInputCast` — was replaced by the faithful base arm
// on the trait (typeop.cc:295-303) as part of WORKPKG-UNMAP-TYPEOP-0001.)

// Ghidra: typeop.cc:932 TypeOpEqual::getInputCast
/// Compute the input cast requested by `INT_EQUAL`/`INT_NOTEQUAL`. Both
/// operands are viewed through their HighVariable at this exact reader; the
/// more-specific type under `typeOrder` is the common requirement, subject to
/// C integer-promotion rules and then `castStandard`.
/// The three High read-facing reads (cc:935/936/941) are fd-aware — keyed
/// on each varnode's own slot — so a resolving (union) high type consults
/// the Funcdata union map exactly as the oracle's `getHighTypeReadFacing`
/// (varnode.cc:665-672) does (UNIONRESOLVE-PKG-B-0001).
pub fn comparison_input_cast(
    fd: &crate::funcdata::Funcdata,
    op_ref: &crate::op::PcodeOpRef,
    slot: usize,
    strategy: &crate::type_system::cast::CastStrategyC,
) -> Option<Arc<Datatype>> {
    if slot > 1 {
        return None;
    }
    let input_type = |input_slot: usize| -> Option<Arc<Datatype>> {
        let in_arc = op_ref.0.read().unwrap().get_in(input_slot)?.clone();
        crate::unionresolve::vn_high_type_read_facing(fd, &in_arc, op_ref, input_slot as i32)
            // Detached unit fixtures have no AssignHigh phase. Production
            // SetCasts always takes the High path above.
            .or_else(|| in_arc.read().unwrap().v_type.clone())
    };
    let mut required = input_type(0)?;
    let other = input_type(1)?;
    if other.type_order(&required) < 0 {
        required = other;
    }
    if {
        let op = op_ref.0.read().unwrap();
        strategy.check_int_promotion_for_compare_op(&op, slot)
    } {
        return Some(required);
    }
    let current = input_type(slot)?;
    if Arc::ptr_eq(&required, &current) {
        return None;
    }
    strategy
        .cast_standard_full(&required, &current, false, false)
        .map(|_| required)
}

/// The `CastStrategyC` every trait arm in this file constructs:
/// `CastStrategy::setTypeFactory` sets `promoteSize = tlst->getSizeOfInt()`
/// (cast.cc:27). Rudra's trait objects reach the factory through
/// `local_type_factory`, so the strategy is rebuilt per call from it.
// RUDRA-GLUE: strategy construction mirror of CastStrategy::setTypeFactory
//   (cast.cc:27); detached fixtures without a factory fall back to the
//   x86-64 int size 4.
fn factory_cast_strategy(
    type_factory: &Arc<RwLock<TypeFactory>>,
) -> crate::type_system::cast::CastStrategyC {
    let promote_size = type_factory
        .read()
        .unwrap()
        .get_size_of_int()
        .max(1) as usize;
    crate::type_system::cast::CastStrategyC::new(promote_size)
}

// Ghidra: typeop.cc:1023 TypeOpIntSless::getInputCast (ordering-comparison family)
/// Compute the input cast for the ordering comparisons —
/// `TypeOpIntSless::getInputCast` (typeop.cc:1023-1031),
/// `TypeOpIntSlessEqual::getInputCast` (cc:1049-1057),
/// `TypeOpIntLess::getInputCast` (cc:1075-1083) and
/// `TypeOpIntLessEqual::getInputCast` (cc:1099-1107). The required type is
/// the op's own `inputTypeLocal(slot)` base (SLESS family = TYPE_INT, LESS
/// family = TYPE_UINT); `checkIntPromotionForCompare` forces it, else
/// `castStandard(reqtype,curtype,true,care_ptr_uint)` — `care_ptr_uint` is
/// TRUE for the signed compares (cc:1030/1056) and FALSE for the unsigned
/// ones (cc:1082/1106).
pub fn ordering_compare_input_cast<T: TypeOp + ?Sized>(
    op_impl: &T,
    op_ref: &crate::op::PcodeOpRef,
    slot: usize,
    strategy: &crate::type_system::cast::CastStrategyC,
    fd: &crate::funcdata::Funcdata,
    care_ptr_uint: bool,
) -> Option<Arc<Datatype>> {
    let (in_arc, op_view) = {
        let op = op_ref.0.read().unwrap();
        (op.get_in(slot)?.clone(), op)
    };
    // cc:1027: checkIntPromotionForCompare(op,slot)
    let promo_forced = strategy.check_int_promotion_for_compare_op(&op_view, slot);
    // cc:1026: reqtype = op->inputTypeLocal(slot)
    let reqtype = op_impl.get_input_local(&op_view, slot)?;
    if promo_forced {
        return Some(reqtype);
    }
    // cc:1029: curtype = op->getIn(slot)->getHighTypeReadFacing(op)
    let curtype = crate::unionresolve::vn_high_type_read_facing(fd, &in_arc, op_ref, slot as i32)
        .or_else(|| in_arc.read().unwrap().v_type.clone())?;
    // cc:1030: castStandard(reqtype,curtype,true,care_ptr_uint)
    strategy
        .cast_standard_full(&reqtype, &curtype, true, care_ptr_uint)
        .map(|_| reqtype)
}

// Ghidra: typeop.cc:1131 TypeOpIntZext::getInputCast (extension family)
/// Compute the input cast for the zero/sign extensions —
/// `TypeOpIntZext::getInputCast` (typeop.cc:1131-1139) and
/// `TypeOpIntSext::getInputCast` (cc:1157-1165): the required type is the
/// op's own `inputTypeLocal(slot)` base (ZEXT = TYPE_UINT, SEXT = TYPE_INT);
/// `checkIntPromotionForExtension` (cast.cc:126-138: a promotion whose
/// extension direction matches the explicit extension is implied — no cast)
/// forces the base, else `castStandard(reqtype,curtype,true,false)`.
pub fn extension_input_cast<T: TypeOp + ?Sized>(
    op_impl: &T,
    op_ref: &crate::op::PcodeOpRef,
    slot: usize,
    strategy: &crate::type_system::cast::CastStrategyC,
    fd: &crate::funcdata::Funcdata,
) -> Option<Arc<Datatype>> {
    let (in_arc, opcode, op_view) = {
        let op = op_ref.0.read().unwrap();
        (op.get_in(slot)?.clone(), op.opcode, op)
    };
    // cc:1134: reqtype = op->inputTypeLocal(slot)
    let reqtype = op_impl.get_input_local(&op_view, slot)?;
    // cc:1135: checkIntPromotionForExtension(op) — cast.cc:126-138.
    let vn_guard = in_arc.read().unwrap();
    let promo_type = strategy.int_promotion_type(&vn_guard);
    drop(vn_guard);
    const NO_PROMOTION: i32 = -1;
    const UNKNOWN_PROMOTION: i32 = 0;
    const UNSIGNED_EXTENSION: i32 = 1;
    const SIGNED_EXTENSION: i32 = 2;
    let forced = match promo_type {
        NO_PROMOTION => false,
        UNKNOWN_PROMOTION => true, // cast.cc:132
        ext => {
            // cast.cc:135-136: matching extension direction is implied.
            if (ext & UNSIGNED_EXTENSION != 0) && opcode == OpCode::CPUI_INT_ZEXT {
                false
            } else if (ext & SIGNED_EXTENSION != 0) && opcode == OpCode::CPUI_INT_SEXT {
                false
            } else {
                true
            }
        }
    };
    if forced {
        return Some(reqtype);
    }
    // cc:1137: curtype = op->getIn(slot)->getHighTypeReadFacing(op)
    let curtype = crate::unionresolve::vn_high_type_read_facing(fd, &in_arc, op_ref, slot as i32)
        .or_else(|| in_arc.read().unwrap().v_type.clone())?;
    // cc:1138: castStandard(reqtype,curtype,true,false)
    strategy
        .cast_standard_full(&reqtype, &curtype, true, false)
        .map(|_| reqtype)
}

// Ghidra: typeop.cc:1543 TypeOpIntRight::getInputCast (shift slot-0 family)
/// Compute the slot-0 input cast for the right shifts —
/// `TypeOpIntRight::getInputCast` (typeop.cc:1543-1556, gate
/// UNSIGNED_EXTENSION) and `TypeOpIntSright::getInputCast` (cc:1585-1598,
/// gate SIGNED_EXTENSION): a promotion that does not carry the shift's own
/// extension direction forces the `inputTypeLocal(slot)` base, else
/// `castStandard(reqtype,curtype,true,true)`. Any other slot falls back to
/// the `TypeOpBinary` (= base `TypeOp::getInputCast`) arm.
pub fn shift_input_cast<T: TypeOp + ?Sized>(
    op_impl: &T,
    op_ref: &crate::op::PcodeOpRef,
    slot: usize,
    strategy: &crate::type_system::cast::CastStrategyC,
    fd: &crate::funcdata::Funcdata,
    gate: i32,
) -> Option<Arc<Datatype>> {
    const UNSIGNED_EXTENSION: i32 = 1;
    const SIGNED_EXTENSION: i32 = 2;
    let _ = (UNSIGNED_EXTENSION, SIGNED_EXTENSION);
    let (in_arc, op_view) = {
        let op = op_ref.0.read().unwrap();
        (op.get_in(slot)?.clone(), op)
    };
    // cc:1548/1574(mod slot): reqtype = op->inputTypeLocal(slot)
    let reqtype = op_impl.get_input_local(&op_view, slot)?;
    // cc:1550/1592: promoType = castStrategy->intPromotionType(vn)
    let vn_guard = in_arc.read().unwrap();
    let promo_type = strategy.int_promotion_type(&vn_guard);
    drop(vn_guard);
    const NO_PROMOTION: i32 = -1;
    // cc:1551/1593: promotion present without the shift's own extension
    // direction forces the base type.
    if promo_type != NO_PROMOTION && (promo_type & gate) == 0 {
        return Some(reqtype);
    }
    // cc:1549/1591: curtype = vn->getHighTypeReadFacing(op)
    let curtype = crate::unionresolve::vn_high_type_read_facing(fd, &in_arc, op_ref, slot as i32)
        .or_else(|| in_arc.read().unwrap().v_type.clone())?;
    // cc:1553/1595: castStandard(reqtype,curtype,true,true)
    strategy
        .cast_standard_full(&reqtype, &curtype, true, true)
        .map(|_| reqtype)
}

// Ghidra: typeop.cc:1639 TypeOpIntDiv::getInputCast (divide/remainder family)
/// Compute the input cast for the integer divides/remainders —
/// `TypeOpIntDiv::getInputCast` (typeop.cc:1639-1649, UNSIGNED gate),
/// `TypeOpIntSdiv::getInputCast` (cc:1659-1669, SIGNED gate),
/// `TypeOpIntRem::getInputCast` (cc:1679-1689, UNSIGNED gate) and
/// `TypeOpIntSrem::getInputCast` (cc:1699-1709, SIGNED gate): both slots
/// take the same promotion gate as the shifts against the op's
/// `inputTypeLocal(slot)` base (DIV/REM = TYPE_UINT, SDIV/SREM = TYPE_INT),
/// else `castStandard(reqtype,curtype,true,true)`.
pub fn divrem_input_cast<T: TypeOp + ?Sized>(
    op_impl: &T,
    op_ref: &crate::op::PcodeOpRef,
    slot: usize,
    strategy: &crate::type_system::cast::CastStrategyC,
    fd: &crate::funcdata::Funcdata,
    gate: i32,
) -> Option<Arc<Datatype>> {
    let (in_arc, op_view) = {
        let op = op_ref.0.read().unwrap();
        (op.get_in(slot)?.clone(), op)
    };
    // cc:1643/1663/1683/1703: reqtype = op->inputTypeLocal(slot)
    let reqtype = op_impl.get_input_local(&op_view, slot)?;
    // cc:1645/1665/1685/1705: promoType = castStrategy->intPromotionType(vn)
    let vn_guard = in_arc.read().unwrap();
    let promo_type = strategy.int_promotion_type(&vn_guard);
    drop(vn_guard);
    const NO_PROMOTION: i32 = -1;
    // cc:1646/1666/1686/1706
    if promo_type != NO_PROMOTION && (promo_type & gate) == 0 {
        return Some(reqtype);
    }
    // cc:1644/1664/1684/1704: curtype = vn->getHighTypeReadFacing(op)
    let curtype = crate::unionresolve::vn_high_type_read_facing(fd, &in_arc, op_ref, slot as i32)
        .or_else(|| in_arc.read().unwrap().v_type.clone())?;
    // cc:1648/1668/1688/1708: castStandard(reqtype,curtype,true,true)
    strategy
        .cast_standard_full(&reqtype, &curtype, true, true)
        .map(|_| reqtype)
}

// Ghidra: typeop.cc:1872 TypeOpFloatInt2Float::absorbZext
/// Return whether the given FLOAT_INT2FLOAT's input-0 is an implied
/// INT_ZEXT output — the extension the conversion absorbs
/// (typeop.cc:1864-1883): `vn0->isWritten() && vn0->isImplied()` and the
/// defining op's opcode is INT_ZEXT.
pub fn float_int2float_absorb_zext(op_ref: &crate::op::PcodeOpRef) -> bool {
    let in0 = {
        let op = op_ref.0.read().unwrap();
        match op.get_in(0) {
            Some(vn) => vn.clone(),
            None => return false,
        }
    };
    let vn = in0.read().unwrap();
    if !vn.is_written() || !vn.is_implied() {
        return false;
    }
    vn.get_def()
        .map(|def| def.read().unwrap().opcode == OpCode::CPUI_INT_ZEXT)
        .unwrap_or(false)
}

// Ghidra: typeop.cc:1847 TypeOpFloatInt2Float::getInputCast
/// Compute the input cast for `FLOAT_INT2FLOAT` (typeop.cc:1847-1862):
/// no cast at all when the conversion absorbs an INT_ZEXT
/// (`absorbZext`, cc:1850-1851); the required type is the op's
/// `inputTypeLocal(slot)` base (TYPE_INT — the conversion expects a signed
/// integer); `care_uint_int` starts TRUE and drops to FALSE when the input's
/// NZMask high bit is clear for sizes up to `sizeof(uintb)` (cc:1856-1860:
/// "If the high-bit is not set, we don't care if input is signed or
/// unsigned"); final gate `castStandard(reqtype,curtype,care_uint_int,true)`.
pub fn float_int2float_input_cast<T: TypeOp + ?Sized>(
    op_impl: &T,
    op_ref: &crate::op::PcodeOpRef,
    slot: usize,
    strategy: &crate::type_system::cast::CastStrategyC,
    fd: &crate::funcdata::Funcdata,
) -> Option<Arc<Datatype>> {
    // cc:1850-1851: no cast if we are absorbing an INT_ZEXT.
    if float_int2float_absorb_zext(op_ref) {
        return None;
    }
    let (in_arc, op_view) = {
        let op = op_ref.0.read().unwrap();
        (op.get_in(slot)?.clone(), op)
    };
    // cc:1853: reqtype = op->inputTypeLocal(slot)
    let reqtype = op_impl.get_input_local(&op_view, slot)?;
    // cc:1855-1860: care_uint_int from the NZMask high bit.
    let mut care_uint_int = true;
    let vn = in_arc.read().unwrap();
    let vn_size = vn.get_size();
    if vn_size <= std::mem::size_of::<u64>() {
        let mut val = vn.get_nz_mask();
        val >>= 8 * vn_size - 1;
        care_uint_int = (val & 1) != 0;
    }
    drop(vn);
    // cc:1854: curtype = vn->getHighTypeReadFacing(op)
    let curtype = crate::unionresolve::vn_high_type_read_facing(fd, &in_arc, op_ref, slot as i32)
        .or_else(|| in_arc.read().unwrap().v_type.clone())?;
    // cc:1861: castStandard(reqtype,curtype,care_uint_int,true)
    strategy
        .cast_standard_full(&reqtype, &curtype, care_uint_int, true)
        .map(|_| reqtype)
}

// Ghidra: typeop.cc:1518 TypeOpIntLeft::getOutputToken (shift token family)
/// Compute the output token for the shifts — `TypeOpIntLeft::getOutputToken`
/// (typeop.cc:1518-1525), `TypeOpIntRight::getOutputToken` (cc:1558-1565)
/// and `TypeOpIntSright::getOutputToken` (cc:1608-1615): the token is
/// input-0's HIGH read-facing type, with a BOOL demoted to the factory INT
/// base of the same size. The fd-aware consult is keyed on slot 0
/// (UNIONRESOLVE-PKG-B-0001).
pub fn shift_output_token_in_fd(
    op_ref: &crate::op::PcodeOpRef,
    fd: &crate::funcdata::Funcdata,
    type_factory: &Arc<RwLock<TypeFactory>>,
) -> Option<Arc<Datatype>> {
    let in0 = {
        let op = op_ref.0.read().unwrap();
        op.get_in(0)?.clone()
    };
    // cc:1521/1561/1611: res1 = op->getIn(0)->getHighTypeReadFacing(op)
    let res1 = crate::unionresolve::vn_high_type_read_facing(fd, &in0, op_ref, 0)
        .or_else(|| in0.read().unwrap().v_type.clone())?;
    // cc:1522-1523/1562-1563/1612-1613: bool -> base int of the same size.
    if res1.get_metatype() == TypeMetatype::Bool {
        let size = res1.get_size();
        return type_factory.read().unwrap().get_base(size, TypeMetatype::Int);
    }
    Some(res1)
}

// Ghidra: typeop.cc:2063 TypeOpPiece::getOutputToken
/// Compute the output token for `PIECE` (typeop.cc:2063-2072): the output's
/// HIGH def-facing type when its metatype is INT or UINT ("PIECE casts to
/// uint or int, based on output"), else the factory UINT base of the output
/// size ("If output is unknown or pointer, treat as cast to uint"). The
/// fd-aware def-facing consult is keyed on slot -1 (the def-op edge).
pub fn piece_output_token_in_fd(
    op_ref: &crate::op::PcodeOpRef,
    fd: &crate::funcdata::Funcdata,
    type_factory: &Arc<RwLock<TypeFactory>>,
) -> Option<Arc<Datatype>> {
    let out_vn = {
        let op = op_ref.0.read().unwrap();
        op.get_out()?.clone()
    };
    let out_size = out_vn.read().unwrap().get_size();
    // cc:2067: dt = vn->getHighTypeDefFacing()
    let dt = crate::unionresolve::vn_high_type_def_facing(fd, &out_vn)
        .or_else(|| out_vn.read().unwrap().v_type.clone());
    match dt {
        // cc:2069-2070
        Some(dt)
            if matches!(
                dt.get_metatype(),
                TypeMetatype::Int | TypeMetatype::Uint
            ) =>
        {
            Some(dt)
        }
        // cc:2071: tlst->getBase(vn->getSize(),TYPE_UINT)
        _ => type_factory
            .read()
            .unwrap()
            .get_base(out_size, TypeMetatype::Uint),
    }
}

// Ghidra: typeop.cc:2142 TypeOpSubpiece::getOutputToken
/// Compute the output token for `SUBPIECE` (typeop.cc:2142-2159):
/// (1) `findTruncation` of input-0's HIGH read-facing type at the
/// SUBPIECE's composite byte offset (artificial slot 1 — the facing type
/// for slot 0 is already the parent) returns a size-matching field type;
/// otherwise (2) the output's DEF-facing high type when not UNKNOWN; (3)
/// else the factory INT base. The byte offset is
/// `TypeOpSubpiece::computeByteOffsetForComposite` (cc:2195-2207).
pub fn subpiece_output_token_in_fd(
    op_ref: &crate::op::PcodeOpRef,
    fd: &crate::funcdata::Funcdata,
    type_factory: &Arc<RwLock<TypeFactory>>,
) -> Option<Arc<Datatype>> {
    let (in0, out_vn, lsb) = {
        let op = op_ref.0.read().unwrap();
        (
            op.get_in(0)?.clone(),
            op.get_out()?.clone(),
            op.get_in(1)
                .and_then(|vn| Some(vn.read().unwrap().get_offset()))
                .unwrap_or(0),
        )
    };
    let out_size = out_vn.read().unwrap().get_size();
    // cc:2147: ct = op->getIn(0)->getHighTypeReadFacing(op)
    let ct = crate::unionresolve::vn_high_type_read_facing(fd, &in0, op_ref, 0)
        .or_else(|| in0.read().unwrap().v_type.clone());
    // cc:2149 + typeop.cc:2195-2207: computeByteOffsetForComposite.
    let byte_off = {
        let in0_guard = in0.read().unwrap();
        let in_size = in0_guard.get_size();
        if in0_guard.get_space().is_big_endian() {
            in_size as i64 - out_size as i64 - (lsb as u32 as i64)
        } else {
            lsb as u32 as i64
        }
    };
    // cc:2150-2154: field arm — artificial slot 1; only a size-matching
    // field returns early (the inner `if` does not return).
    if let Some(ct) = &ct {
        let op_view = op_ref.0.read().unwrap();
        if let Some((field, _offset)) =
            ct.find_truncation(byte_off, out_size, Some(&op_view), 1, Some(&fd.union_map))
        {
            if out_size == field.type_ptr.get_size() {
                return Some(field.type_ptr.clone());
            }
        }
    }
    // cc:2155-2157: dt = outvn->getHighTypeDefFacing(); non-UNKNOWN wins.
    let dt = crate::unionresolve::vn_high_type_def_facing(fd, &out_vn)
        .or_else(|| out_vn.read().unwrap().v_type.clone());
    if let Some(dt) = dt {
        if dt.get_metatype() != TypeMetatype::Unknown {
            return Some(dt);
        }
    }
    // cc:2158: tlst->getBase(outvn->getSize(),TYPE_INT)
    type_factory
        .read()
        .unwrap()
        .get_base(out_size, TypeMetatype::Int)
}

// Ghidra: typeop.cc:2250 TypeOpPtradd::getInputCast
/// Compute the input cast for `PTRADD` slot 0 (typeop.cc:2250-2266): the
/// operation expects the VARNODE's own read-facing type, not the (possibly
/// different) HIGH read-facing type; a non-pointer on either side returns
/// the varnode type; when both sides are pointers, equal `alignSize` on the
/// one-level-down bases cancels the cast, else the varnode type is the
/// cast. Any other slot falls back to the base `TypeOp::getInputCast` arm.
pub fn ptradd_input_cast(
    op_ref: &crate::op::PcodeOpRef,
    slot: usize,
    fd: &crate::funcdata::Funcdata,
) -> Option<Arc<Datatype>> {
    if slot != 0 {
        return None;
    }
    let in0 = {
        let op = op_ref.0.read().unwrap();
        op.get_in(0)?.clone()
    };
    // cc:2255: reqtype = op->getIn(0)->getTypeReadFacing(op)
    let reqtype = crate::unionresolve::vn_type_read_facing(fd, &in0, op_ref, 0)?;
    // cc:2256: curtype = op->getIn(0)->getHighTypeReadFacing(op)
    let curtype = crate::unionresolve::vn_high_type_read_facing(fd, &in0, op_ref, 0)
        .unwrap_or_else(|| reqtype.clone());
    // cc:2257-2258
    let ptr_of = |t: &Arc<Datatype>| -> Option<Arc<Datatype>> {
        match t.as_ref() {
            Datatype::Pointer(p) => Some(p.ptr_to.clone()),
            _ => None,
        }
    };
    if reqtype.get_metatype() != TypeMetatype::Pointer {
        return Some(reqtype);
    }
    if curtype.get_metatype() != TypeMetatype::Pointer {
        return Some(reqtype);
    }
    // cc:2259-2260: go down exactly one level.
    let reqbase = ptr_of(&reqtype)?;
    let curbase = ptr_of(&curtype)?;
    // cc:2261-2262: equal align sizes on the bases cancel the cast.
    if reqbase.get_align_size() == curbase.get_align_size() {
        return None;
    }
    // cc:2263
    Some(reqtype)
}

// Ghidra: typeop.cc:963 TypeOpEqual::propagateAcrossCompare
/// Propagate a data-type across a comparison PcodeOp — the shared
/// `propagateType` body of CPUI_INT_EQUAL/INT_NOTEQUAL/INT_LESS/
/// INT_LESSEQUAL (typeop.cc:945/1009/1085/1109 call sites,
/// cc:963-986 body): propagation is input<->input only; a spacebase input
/// is rewrapped as a pointer to the unknown 1-byte base (wordsize from the
/// default data space); a PointerRel whose parent is a STRUCT with a
/// non-negative byte offset degrades to a plain pointer of the same size
/// ("the two sides of the operator are likely to be different types",
/// cc:972-979); everything else propagates unchanged.
pub fn propagate_across_compare(
    alt_type: &Arc<Datatype>,
    op: &PcodeOp,
    inslot: i32,
    outslot: i32,
    type_factory: Option<&Arc<RwLock<TypeFactory>>>,
) -> Option<Arc<Datatype>> {
    // cc:966: must propagate input <-> input.
    if inslot == -1 || outslot == -1 {
        return None;
    }
    // Ghidra receives invn/outvn from the caller (always attached in
    // production); a detached fixture op without those inputs observes the
    // same decisions by skipping the varnode-dependent checks.
    let invn = op.get_in(inslot as usize);
    let outvn = op.get_in(outslot as usize);
    if invn.is_some_and(|vn| vn.read().unwrap().is_spacebase()) {
        // cc:968-971: pointer to the unknown base, alttype-sized, wordsize
        // of the default data space (x86-64 ram wordsize 1 in the Rudra
        // driver; propagate_to_pointer_sized carries the 1).
        return Some(propagate_to_pointer_sized(alt_type, alt_type.get_size(), type_factory));
    }
    // cc:972-981: PointerRel degradation arm.
    let rel_state = match alt_type.as_ref() {
        Datatype::Pointer(p) => p.base.pointer_rel.as_ref(),
        _ => None,
    };
    if let Some(rel) = rel_state {
        if !outvn.is_some_and(|vn| vn.read().unwrap().is_constant()) {
            if rel.parent.get_metatype() == TypeMetatype::Struct && rel.offset >= 0 {
                // cc:974-979: mid-structure pointers do not propagate
                // across comparisons; degrade to a plain pointer.
                if let Some(factory) = type_factory {
                    let unknown_base =
                        factory.read().unwrap().get_base(1, TypeMetatype::Unknown)?;
                    let wordsize = match alt_type.as_ref() {
                        Datatype::Pointer(p) => p.wordsize,
                        _ => 1,
                    };
                    return Some(
                        factory
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get_type_pointer(alt_type.get_size(), unknown_base, wordsize),
                    );
                }
                // Factory-less detached fixtures observe the same shape via
                // the anonymous-pointer constructor (interning residual).
                return Some(Arc::new(Datatype::Pointer(
                    crate::type_system::datatype::TypePointer::new(
                        alt_type.get_size(),
                        Arc::new(Datatype::Base(crate::type_system::TypeBase::new(
                            "unknown".to_string(),
                            1,
                            TypeMetatype::Unknown,
                        ))),
                        1,
                    ),
                )));
            }
            return Some(alt_type.clone());
        }
    }
    // cc:983-984
    Some(alt_type.clone())
}

// Ghidra: typeop.cc:295 TypeOp::getInputCast (base arm)
/// The shared base-arm body (typeop.cc:295-303): annotations never take a
/// cast; the required type is `inputTypeLocal(slot)`; the current type is
/// the input's HIGH read-facing type; the gate is
/// `castStandard(reqtype,curtype,false,true)`. Both the trait default and
/// the subclass fallbacks (INT_RIGHT/INT_SRIGHT non-slot-0, PTRADD
/// non-slot-0 — cc:1555/1597/2265) route through this single
/// implementation, exactly as Ghidra's virtual dispatch falls back to
/// `TypeOp::getInputCast` once.
pub fn base_input_cast_arm<T: TypeOp + ?Sized>(
    op_impl: &T,
    op: &crate::op::PcodeOpRef,
    slot: usize,
    fd: &crate::funcdata::Funcdata,
) -> Option<Arc<Datatype>> {
    let type_factory = op_impl.local_type_factory()?;
    let strategy = factory_cast_strategy(type_factory);
    let (in_arc, reqtype) = {
        let op_view = op.0.read().unwrap();
        let in_arc = op_view.get_in(slot)?.clone();
        // cc:299: annotations never take a cast.
        if in_arc.read().unwrap().is_annotation() {
            return None;
        }
        // cc:300: reqtype = op->inputTypeLocal(slot)
        let reqtype = op_impl.get_input_local(&op_view, slot)?;
        (in_arc, reqtype)
    };
    // cc:301: curtype = vn->getHighTypeReadFacing(op)
    let curtype = crate::unionresolve::vn_high_type_read_facing(fd, &in_arc, op, slot as i32)
        .or_else(|| in_arc.read().unwrap().v_type.clone())?;
    // cc:302: castStandard(reqtype,curtype,false,true)
    strategy
        .cast_standard_full(&reqtype, &curtype, false, true)
        .map(|_| reqtype)
}

/// Core trait representing a P-code operation type
///
/// Corresponds to Ghidra's `TypeOp` class
pub trait TypeOp {
    /// Get the opcode for this operation
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode;

    /// Get the name of the operation
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str;

    /// Get the name of the op-code as it should be displayed in context —
    /// the default returns the bare display name; subclasses whose display
    /// token depends on the op (ZEXT/SEXT sizes, CARRY family, PIECE/
    /// SUBPIECE sizes, CALLOTHER userop) override it.
    // Ghidra: typeop.hh:183 TypeOp::getOperatorName (inline default `return name;`)
    fn get_operator_name(&self, _op: &PcodeOp) -> String {
        self.get_name().to_string()
    }

    /// Get properties/flags for this operation
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32;

    /// Print the operation in a raw textual format
    // Ghidra: typeop.hh:176 TypeOp::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String;

    /// Push the operation to a print language emitter
    // Ghidra: typeop.hh:170 TypeOp::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        // Default implementation for basic ops
        match self.get_opcode() {
            OpCode::CPUI_COPY => lng.op_copy(op),
            OpCode::CPUI_LOAD => lng.op_load(op),
            OpCode::CPUI_STORE => lng.op_store(op),
            OpCode::CPUI_MULTIEQUAL => lng.op_multiequal(op),
            OpCode::CPUI_INDIRECT => lng.op_indirect(op),
            OpCode::CPUI_CALL => lng.op_call(op),
            OpCode::CPUI_RETURN => lng.op_return(op),
            _ => {
                if (self.get_flags()
                    & (typeop_flags::ARITHMETIC_OP
                        | typeop_flags::LOGICAL_OP
                        | typeop_flags::SHIFT_OP))
                    != 0
                {
                    lng.op_binary(op);
                }
            }
        }
    }

    // Metadata methods
    /// The TypeFactory this op's TypeOp object was constructed with — the
    /// Ghidra base-class `tlst` field (typeop.cc:233-242). Every Ghidra
    /// TypeOp subclass constructor takes `TypeFactory *t` and stores it on
    /// the base; Rudra trait objects for the macro-generated opcodes are
    /// stateless unit structs, so the factory is exposed as this provider
    /// hook instead. `None` leaves the local-type defaults below without a
    /// factory to query (mirroring an op whose Rudra impl has not yet been
    /// wired to its Architecture TypeFactory).
    // RUDRA-GLUE: base-class `tlst` field access as a trait provider hook;
    //   impls that hold the constructor-injected factory override it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        None
    }

    /// Get the minimal (or suggested) data-type of an output to this op-code
    ///
    /// Canonical fallback: `tlst->getBase(op->getOut()->getSize(),
    /// TYPE_UNKNOWN)` (typeop.cc:261-268) — the base-class default subclasses
    /// with a specific metatype (TypeOpBinary/Unary/Func `metaout`) or
    /// call-specific logic override.
    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal (default at typeop.cc:261)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Unknown)
    }

    /// Get the minimal (or suggested) data-type of an input to this op-code
    ///
    /// Canonical fallback: `tlst->getBase(op->getIn(slot)->getSize(),
    /// TYPE_UNKNOWN)` (typeop.cc:271-275).
    // Ghidra: typeop.hh:152 TypeOp::getInputLocal (default at typeop.cc:271)
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_in(slot)?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Unknown)
    }

    /// Funcdata-carrying form of `getInputLocal`. In Ghidra every
    /// `PcodeOp::inputTypeLocal` caller can also reach the owning function
    /// via `op->getParent()->getFuncdata()` (op.hh:252 inlines straight to
    /// `opcode->getInputLocal(this,slot)`, but the Funcdata is one hop away
    /// for the TypeOp virtuals that need it). Rudra `PcodeOp` holds no
    /// parent-to-Funcdata chain, so the Funcdata is threaded through this
    /// entry instead. `TypeOpCallind::getInputLocal` is currently the only
    /// override that consumes it (`getCallSpecs(op)`, typeop.cc:757); every
    /// other subclass observes the identical behaviour by falling through
    /// to the fd-less form above.
    // Ghidra: typeop.hh:152 TypeOp::getInputLocal (via op.hh:252 PcodeOp::inputTypeLocal)
    fn get_input_local_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        let _ = fd;
        let op = op.0.read().unwrap();
        self.get_input_local(&op, slot)
    }

    /// Find the data-type of the output that would be assigned by a compiler.
    ///
    /// Corresponds to Ghidra's `TypeOp::getOutputToken(op, castStrategy)`.
    /// The default returns `None`, meaning the output uses its local type
    /// (`outputTypeLocal`) with no token-level override.
    // Ghidra: typeop.hh:155 TypeOp::getOutputToken
    fn get_output_token(&self, _op: &PcodeOp) -> Option<Arc<Datatype>> {
        None
    }

    /// Funcdata-carrying form of [`Self::get_output_token`] — the dispatch
    /// entry `ActionSetCasts::castOutput` consumes (coreaction.cc:2541).
    /// Overriders whose oracle body reads a facing type (COPY typeop.cc:405,
    /// PTRADD cc:2244, PTRSUB cc:2349) consult the Funcdata union map through
    /// the fd-aware facing twins (varnode.cc:626-672) in this form — the
    /// single implementation; the default delegates to the fd-less form,
    /// which mirrors Ghidra's one virtual reaching the same override.
    // Ghidra: typeop.hh:155 TypeOp::getOutputToken (fd-carrying dispatch form)
    fn get_output_token_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        let _ = fd;
        let op = op.0.read().unwrap();
        self.get_output_token(&op)
    }

    /// Find the data-type of the input to a specific PcodeOp (for casting).
    ///
    /// Corresponds to Ghidra's `TypeOp::getInputCast(op, slot, castStrategy)`.
    /// A `None` result indicates the input does not need a cast (the default).
    /// The Funcdata is threaded for the same reason as
    /// [`Self::get_input_local_in_fd`]: the fd-aware read-facing consults
    /// (union_map) need the owning function; detached fixtures observe the
    /// map-miss arm inside the canonical functions they delegate to.
    // Ghidra: typeop.cc:295 TypeOp::getInputCast (base arm, fd-carrying form)
    fn get_input_cast(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        base_input_cast_arm(self, op, slot, fd)
    }

    /// Propagate an incoming data-type across a specific PcodeOp.
    ///
    /// Corresponds to Ghidra's `TypeOp::propagateType(alttype, op, invn, outvn,
    /// inslot, outslot)`. `alt_type` is the incoming type; `inslot`/`outslot`
    /// are -1 for the output varnode and >=0 for an input slot. Returns the
    /// outgoing data-type or `None` to indicate no propagation (the default).
    // Ghidra: typeop.hh:161 TypeOp::propagateType
    fn propagate_type(
        &self,
        _alt_type: &Arc<Datatype>,
        _op: &PcodeOp,
        _inslot: i32,
        _outslot: i32,
    ) -> Option<Arc<Datatype>> {
        None
    }

    /// Helper: the metatype assigned to an op's output for printing/token
    /// purposes. Mirrors Ghidra's per-opcode `metaout` metatype. Default
    /// `None` lets the caller fall back to the output varnode's own type.
    // RUDRA-GLUE: Rust trait accessor for the per-subclass `metaout` field
    //   cached by Ghidra's TypeOpBinary/TypeOpUnary/TypeOpFunc constructors
    //   (typeop.hh:205 / :222 / :239). Ghidra has no virtual getOutputMetatype
    //   method; the field is read directly by getOutputLocal (typeop.cc:326
    //   etc.), so Rudra exposes it via this helper.
    fn get_output_metatype(&self) -> Option<TypeMetatype> {
        None
    }
}

// --- Base implementations for Categories ---

/// Base behavior for binary operations
pub struct TypeOpBinary {
    pub opcode: OpCode,
    pub name: String,
    pub flags: u32,
}

impl TypeOp for TypeOpBinary {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode (inlined accessor; TypeOpBinary inherits)
    fn get_opcode(&self) -> OpCode {
        self.opcode
    }
    // Ghidra: typeop.hh:70 TypeOp::getName (inlined accessor; TypeOpBinary inherits)
    fn get_name(&self) -> &str {
        &self.name
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags (inlined accessor; TypeOpBinary inherits)
    fn get_flags(&self) -> u32 {
        self.flags
    }

    // Ghidra: typeop.cc:335 TypeOpBinary::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} {} {}", out, in0, self.get_name(), in1)
    }

    // RUDRA-GLUE: generic binary push dispatch; Ghidra's TypeOpBinary does not
    //   override push (pure virtual at typeop.hh:170), each concrete subclass
    //   provides its own `lng->opXxx(op)`.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_binary(op);
    }
}

/// Base behavior for unary operations
pub struct TypeOpUnary {
    pub opcode: OpCode,
    pub name: String,
    pub flags: u32,
}

impl TypeOp for TypeOpUnary {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode (inlined accessor; TypeOpUnary inherits)
    fn get_opcode(&self) -> OpCode {
        self.opcode
    }
    // Ghidra: typeop.hh:70 TypeOp::getName (inlined accessor; TypeOpUnary inherits)
    fn get_name(&self) -> &str {
        &self.name
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags (inlined accessor; TypeOpUnary inherits)
    fn get_flags(&self) -> u32 {
        self.flags
    }

    // Ghidra: typeop.cc:357 TypeOpUnary::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} {}", out, self.get_name(), in0)
    }

    // RUDRA-GLUE: generic unary push dispatch; Ghidra's TypeOpUnary does not
    //   override push (pure virtual at typeop.hh:170), each concrete subclass
    //   provides its own `lng->opXxx(op)`.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_unary(op);
    }
}

// --- Concrete Opcode Implementations ---

/// Generate a TypeOpBinary subclass. `$metaout`/`$metain` are the
/// `type_metatype` pair the corresponding Ghidra constructor registers
/// (`TypeOpBinary(t,opc,name,mout,min)`, typeop.hh:211); they drive
/// `getBase(size, meta)` for the local-type defaults exactly as
/// TypeOpBinary::getOutputLocal/getInputLocal do.
/// `binary_op_ext` is the full generator: identical to `binary_op` plus a
/// trailing `{ ... }` group of extra `TypeOp` methods spliced verbatim into
/// the trait impl (used for the per-subclass getInputCast/getOperatorName
/// overrides the oracle defines on top of the TypeOpBinary defaults).
macro_rules! binary_op_ext {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr,
     $metaout:ident, $metain:ident, { $($extra:tt)* }) => {
        pub struct $struct_name {
            type_factory: Arc<RwLock<TypeFactory>>,
        }

        impl $struct_name {
            // RUDRA-GLUE: stores the base-class `tlst` field every Ghidra
            //   TypeOp subclass constructor receives (typeop.cc:233-242); the
            //   per-subclass constructor line is cited at the registration
            //   site in TypeOpManager::new.
            pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
                Self { type_factory }
            }
        }

        impl TypeOp for $struct_name {
            // Ghidra: typeop.hh:71 TypeOp::getOpcode
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            // Ghidra: typeop.hh:70 TypeOp::getName
            fn get_name(&self) -> &str {
                $name
            }
            // Ghidra: typeop.hh:72 TypeOp::getFlags
            fn get_flags(&self) -> u32 {
                $flags
            }
            // Ghidra: typeop.cc:335 TypeOpBinary::printRaw
            fn print_raw(&self, op: &PcodeOp) -> String {
                let out = op
                    .get_out()
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in0 = op
                    .get_in(0)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in1 = op
                    .get_in(1)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                format!("{} = {} {} {}", out, in0, $symbol, in1)
            }
            // RUDRA-GLUE: macro-generated generic binary push; per-subclass push
            //   is inlined in typeop.hh (e.g. TypeOpIntSub::push at :451).
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_binary(op);
            }
            // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
            //   constructor-registered metaout below resolves through it.
            fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
                Some(&self.type_factory)
            }
            // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                let type_factory = self.local_type_factory()?;
                let size = op.get_out()?.read().unwrap().get_size();
                base_local_type(type_factory, size, TypeMetatype::$metaout)
            }
            // Ghidra: typeop.cc:329 TypeOpBinary::getInputLocal
            fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
                let type_factory = self.local_type_factory()?;
                let size = op.get_in(slot)?.read().unwrap().get_size();
                base_local_type(type_factory, size, TypeMetatype::$metain)
            }
            // Ghidra: typeop.cc:1175 TypeOpIntAdd::getOutputToken (arithmetic family)
            fn get_output_token(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                macro_arith_output_token(OpCode::$opcode, op, &self.type_factory)
            }
            $($extra)*
        }
    };
}

macro_rules! binary_op {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr,
     $metaout:ident, $metain:ident) => {
        binary_op_ext!($struct_name, $opcode, $name, $flags, $symbol,
                       $metaout, $metain, {});
    };
}

/// Generate a TypeOpUnary subclass. `$metaout`/`$metain` are the
/// `type_metatype` pair the corresponding Ghidra constructor registers
/// (`TypeOpUnary(t,opc,name,mout,min)`, typeop.hh:227); they drive
/// `getBase(size, meta)` for the local-type defaults exactly as
/// TypeOpUnary::getOutputLocal/getInputLocal do.
macro_rules! unary_op {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr,
     $metaout:ident, $metain:ident) => {
        pub struct $struct_name {
            type_factory: Arc<RwLock<TypeFactory>>,
        }

        impl $struct_name {
            // RUDRA-GLUE: stores the base-class `tlst` field every Ghidra
            //   TypeOp subclass constructor receives (typeop.cc:233-242); the
            //   per-subclass constructor line is cited at the registration
            //   site in TypeOpManager::new.
            pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
                Self { type_factory }
            }
        }

        impl TypeOp for $struct_name {
            // Ghidra: typeop.hh:71 TypeOp::getOpcode
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            // Ghidra: typeop.hh:70 TypeOp::getName
            fn get_name(&self) -> &str {
                $name
            }
            // Ghidra: typeop.hh:72 TypeOp::getFlags
            fn get_flags(&self) -> u32 {
                $flags
            }
            // Ghidra: typeop.cc:357 TypeOpUnary::printRaw
            fn print_raw(&self, op: &PcodeOp) -> String {
                let out = op
                    .get_out()
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in0 = op
                    .get_in(0)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                format!("{} = {}{}", out, $symbol, in0)
            }
            // RUDRA-GLUE: macro-generated generic unary push; per-subclass push
            //   is inlined in typeop.hh (e.g. TypeOpIntNegate::push at :491).
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_unary(op);
            }
            // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
            //   constructor-registered metaout below resolves through it.
            fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
                Some(&self.type_factory)
            }
            // Ghidra: typeop.cc:345 TypeOpUnary::getOutputLocal
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                let type_factory = self.local_type_factory()?;
                let size = op.get_out()?.read().unwrap().get_size();
                base_local_type(type_factory, size, TypeMetatype::$metaout)
            }
            // Ghidra: typeop.cc:351 TypeOpUnary::getInputLocal
            fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
                let type_factory = self.local_type_factory()?;
                let size = op.get_in(slot)?.read().unwrap().get_size();
                base_local_type(type_factory, size, TypeMetatype::$metain)
            }
            // Ghidra: typeop.cc:1175 TypeOpIntAdd::getOutputToken (arithmetic family)
            fn get_output_token(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                macro_arith_output_token(OpCode::$opcode, op, &self.type_factory)
            }
        }
    };
}

/// Generate a TypeOpFunc subclass. `$metaout`/`$metain` are the
/// `type_metatype` pair the corresponding Ghidra constructor registers
/// (`TypeOpFunc(t,opc,name,mout,min)`, typeop.hh:244); they drive
/// `getBase(size, meta)` for the local-type defaults exactly as
/// TypeOpFunc::getOutputLocal/getInputLocal do.
/// `functional_unary_op_ext` is the full generator: identical to
/// `functional_unary_op` plus a trailing `{ ... }` group of extra `TypeOp`
/// methods spliced verbatim into the trait impl (per-subclass
/// getInputCast/getOperatorName overrides).
macro_rules! functional_unary_op_ext {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $func:expr,
     $metaout:ident, $metain:ident, { $($extra:tt)* }) => {
        pub struct $struct_name {
            type_factory: Arc<RwLock<TypeFactory>>,
        }

        impl $struct_name {
            // RUDRA-GLUE: stores the base-class `tlst` field every Ghidra
            //   TypeOp subclass constructor receives (typeop.cc:233-242); the
            //   per-subclass constructor line is cited at the registration
            //   site in TypeOpManager::new.
            pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
                Self { type_factory }
            }
        }

        impl TypeOp for $struct_name {
            // Ghidra: typeop.hh:71 TypeOp::getOpcode
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            // Ghidra: typeop.hh:70 TypeOp::getName
            fn get_name(&self) -> &str {
                $name
            }
            // Ghidra: typeop.hh:72 TypeOp::getFlags
            fn get_flags(&self) -> u32 {
                $flags
            }
            // Ghidra: typeop.cc:377 TypeOpFunc::printRaw
            fn print_raw(&self, op: &PcodeOp) -> String {
                let out = op
                    .get_out()
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in0 = op
                    .get_in(0)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                format!("{} = {}({})", out, $func, in0)
            }
            // RUDRA-GLUE: macro-generated generic functional push; per-subclass
            //   push is inlined in typeop.hh (e.g. TypeOpIntCarry::push at :459).
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_unary(op);
            }
            // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
            //   constructor-registered metaout below resolves through it.
            fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
                Some(&self.type_factory)
            }
            // Ghidra: typeop.cc:365 TypeOpFunc::getOutputLocal
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                let type_factory = self.local_type_factory()?;
                let size = op.get_out()?.read().unwrap().get_size();
                base_local_type(type_factory, size, TypeMetatype::$metaout)
            }
            // Ghidra: typeop.cc:371 TypeOpFunc::getInputLocal
            fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
                let type_factory = self.local_type_factory()?;
                let size = op.get_in(slot)?.read().unwrap().get_size();
                base_local_type(type_factory, size, TypeMetatype::$metain)
            }
            $($extra)*
        }
    };
}

macro_rules! functional_unary_op {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $func:expr,
     $metaout:ident, $metain:ident) => {
        functional_unary_op_ext!($struct_name, $opcode, $name, $flags, $func,
                                 $metaout, $metain, {});
    };
}

/// Generate a TypeOpFunc subclass (binary input shape). `$metaout`/`$metain`
/// are the `type_metatype` pair the corresponding Ghidra constructor registers
/// (`TypeOpFunc(t,opc,name,mout,min)`, typeop.hh:244); they drive
/// `getBase(size, meta)` for the local-type defaults exactly as
/// TypeOpFunc::getOutputLocal/getInputLocal do.
/// `functional_binary_op_ext` is the full generator: identical to
/// `functional_binary_op` plus a trailing `{ ... }` group of extra `TypeOp`
/// methods spliced verbatim into the trait impl.
macro_rules! functional_binary_op_ext {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $func:expr,
     $metaout:ident, $metain:ident, { $($extra:tt)* }) => {
        pub struct $struct_name {
            type_factory: Arc<RwLock<TypeFactory>>,
        }

        impl $struct_name {
            // RUDRA-GLUE: stores the base-class `tlst` field every Ghidra
            //   TypeOp subclass constructor receives (typeop.cc:233-242); the
            //   per-subclass constructor line is cited at the registration
            //   site in TypeOpManager::new.
            pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
                Self { type_factory }
            }
        }

        impl TypeOp for $struct_name {
            // Ghidra: typeop.hh:71 TypeOp::getOpcode
            fn get_opcode(&self) -> OpCode {
                OpCode::$opcode
            }
            // Ghidra: typeop.hh:70 TypeOp::getName
            fn get_name(&self) -> &str {
                $name
            }
            // Ghidra: typeop.hh:72 TypeOp::getFlags
            fn get_flags(&self) -> u32 {
                $flags
            }
            // Ghidra: typeop.cc:377 TypeOpFunc::printRaw
            fn print_raw(&self, op: &PcodeOp) -> String {
                let out = op
                    .get_out()
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in0 = op
                    .get_in(0)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                let in1 = op
                    .get_in(1)
                    .map(|v| format!("{}", v.read().unwrap()))
                    .unwrap_or_else(|| "_".to_string());
                format!("{} = {}({}, {})", out, $func, in0, in1)
            }
            // RUDRA-GLUE: macro-generated generic functional push; per-subclass
            //   push is inlined in typeop.hh (e.g. TypeOpIntScarry::push at :467).
            fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
                lng.op_binary(op);
            }
            // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
            //   constructor-registered metaout below resolves through it.
            fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
                Some(&self.type_factory)
            }
            // Ghidra: typeop.cc:365 TypeOpFunc::getOutputLocal
            fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
                let type_factory = self.local_type_factory()?;
                let size = op.get_out()?.read().unwrap().get_size();
                base_local_type(type_factory, size, TypeMetatype::$metaout)
            }
            // Ghidra: typeop.cc:371 TypeOpFunc::getInputLocal
            fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
                let type_factory = self.local_type_factory()?;
                let size = op.get_in(slot)?.read().unwrap().get_size();
                base_local_type(type_factory, size, TypeMetatype::$metain)
            }
            $($extra)*
        }
    };
}

// (The thin `functional_binary_op` wrapper — the no-extra-arguments form of
// `functional_binary_op_ext` — was removed by WORKPKG-UNMAP-TYPEOP-0001
// after both of its instantiations (TypeOpPiece/TypeOpSubpiece) grew
// per-subclass overrides and moved to `functional_binary_op_ext!`.)

/// CPUI_COPY implementation. Ghidra's TypeOpCopy never overrides
/// getOutputLocal/getInputLocal (typeop.hh:253-263), so both resolve through
/// the TypeOp base defaults `getBase(size, TYPE_UNKNOWN)` (typeop.cc:261-275).
pub struct TypeOpCopy {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpCopy {
    // Ghidra: typeop.cc:390 TypeOpCopy::TypeOpCopy
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpCopy {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_COPY
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "COPY"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }

    // Ghidra: typeop.cc:425 TypeOpCopy::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {}", out, in0)
    }

    // Ghidra: typeop.hh:261 TypeOpCopy::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_copy(op);
    }

    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); COPY has no
    //   get*Local override in Ghidra, so the trait defaults below resolve
    //   through this factory.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }

    /// The output token of a COPY is the HIGH read-facing type of its input
    /// (cc:408). The fd-carrying dispatch form is the single implementation:
    /// cc:408's `getHighTypeReadFacing(op)` consults the Funcdata union map
    /// keyed on slot 0 (varnode.cc:665-672). The former fd-less override
    /// read the raw `v_type` (not even the High type) and was unreachable
    /// from the production token dispatch (cast_output had no COPY arm) —
    /// UNIONRESOLVE-PKG-B-0001 replaced the read and wired the arm.
    // Ghidra: typeop.cc:405 TypeOpCopy::getOutputToken
    fn get_output_token_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        let in0 = op.0.read().unwrap().get_in(0)?.clone();
        crate::unionresolve::vn_high_type_read_facing(fd, &in0, op, 0)
            // Detached unit fixtures have no AssignHigh phase; production
            // castOutput always takes the High path above.
            .or_else(|| in0.read().unwrap().v_type.clone())
    }

    /// COPY is transparent: a type propagates across it in either direction
    /// (input<->output). One of the slots must be the output (-1). Spacebase
    /// inputs are rewrapped as a pointer to an unknown base type.
    /// Faithful to `TypeOpCopy::propagateType` (typeop.cc:411-423).
    // Ghidra: typeop.cc:411 TypeOpCopy::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot != -1 && outslot != -1 {
            return None; // Must propagate input <-> output
        }
        // If the source varnode is a spacebase, rewrap as ptr-to-unknown.
        let src_slot = if inslot == -1 { outslot } else { inslot };
        if src_slot >= 0 {
            if let Some(vn) = op.get_in(src_slot as usize) {
                if vn.read().unwrap().is_spacebase() {
                    return Some(propagate_to_pointer(&Arc::new(Datatype::Base(
                        crate::type_system::TypeBase::new(
                            "unknown".to_string(),
                            1,
                            TypeMetatype::Unknown,
                        ),
                    ))));
                }
            }
        }
        Some(alt_type.clone())
    }
}

/// CPUI_LOAD implementation
pub struct TypeOpLoad;
impl TypeOp for TypeOpLoad {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_LOAD
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "LOAD"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }

    // Ghidra: typeop.cc:502 TypeOpLoad::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Space
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Pointer
        format!("{} = *({}){}", out, in0, in1)
    }

    // Ghidra: typeop.hh:274 TypeOpLoad::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_load(op);
    }

    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal (base; Load does not override)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Output type should be the base type of the pointer input (inrefs[1])
        op.get_in(1).and_then(|vn| {
            let vn_read = vn.read().unwrap();
            if let Some(dt) = &vn_read.v_type {
                if let Datatype::Pointer(ptr) = dt.as_ref() {
                    return Some(ptr.ptr_to.clone());
                }
            }
            None
        })
    }

    /// The output token dereferences the pointer input: if in[1] is a pointer
    /// whose pointee matches the output size, the token is the pointee;
    /// otherwise fall back to the output varnode's high type.
    /// Faithful to `TypeOpLoad::getOutputToken` (typeop.cc:472-485).
    // Ghidra: typeop.cc:472 TypeOpLoad::getOutputToken
    fn get_output_token(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let out_size = op.get_out().map(|v| v.read().unwrap().get_size());
        if let Some(vn) = op.get_in(1) {
            let vn_read = vn.read().unwrap();
            if let Some(Datatype::Pointer(ptr)) = vn_read.v_type.as_ref().map(|d| d.as_ref()) {
                if Some(ptr.ptr_to.get_size()) == out_size {
                    return Some(ptr.ptr_to.clone());
                }
            }
        }
        op.get_out()
            .and_then(|vn| vn.read().unwrap().v_type.clone())
    }

    /// For LOAD, a type propagates between the value (output/slot 2) and the
    /// pointer (input 1), never along the space constant (slot 0). Output-to-
    /// input rewraps the type as a pointer (propagateToPointer); input-to-
    /// output unwraps it (propagateFromPointer).
    /// Faithful to `TypeOpLoad::propagateType` (typeop.cc:487-500).
    // Ghidra: typeop.cc:487 TypeOpLoad::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot == 0 || outslot == 0 {
            return None; // Don't propagate along the space-constant edge
        }
        // Spacebase pointers do not propagate.
        let source = if inslot < 0 {
            op.get_out()
        } else {
            op.get_in(inslot as usize)
        };
        if source.is_some_and(|vn| vn.read().unwrap().is_spacebase()) {
            return None;
        }
        if inslot == -1 {
            // output -> input : wrap value type as a pointer (propagateToPointer)
            Some(propagate_to_pointer(alt_type))
        } else {
            // input -> output : unwrap pointer to its pointee (propagateFromPointer)
            let dereference_size = attached_varnode_size(op, outslot)?;
            propagate_from_pointer(alt_type, dereference_size)
        }
    }
}

/// CPUI_STORE implementation
pub struct TypeOpStore;
impl TypeOp for TypeOpStore {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_STORE
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "STORE"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }

    // Ghidra: typeop.cc:572 TypeOpStore::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Space
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Pointer
        let in2 = op
            .get_in(2)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string()); // Value
        format!("*({}){} = {}", in0, in1, in2)
    }

    // Ghidra: typeop.hh:286 TypeOpStore::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_store(op);
    }

    // Ghidra: typeop.hh:152 TypeOp::getInputLocal (base; Store does not override)
    // TypeOpStore has NO getInputLocal override in the oracle (typeop.hh:279
    // declares it commented out); every input's local type is the base
    // default `tlst->getBase(ownSize, TYPE_UNKNOWN)` (typeop.cc:271-275).
    // The previous in-table override invented a slot-2 "pointer's pointee"
    // lookup Ghidra never performs; removed as a standing deviation. The
    // trait default resolves through local_type_factory, which this
    // table-registered unit type does not carry (returns None) — identical
    // to the pre-removal observable behavior since no dispatch site reached
    // it; the faithful coreaction dispatch seeds the base directly.

    /// For STORE, a type propagates between the value (slot 2) and the pointer
    /// (slot 1), never along the space constant (slot 0). Value-to-pointer
    /// rewraps (propagateToPointer); pointer-to-value unwraps
    /// (propagateFromPointer). Note STORE has no output varnode, so outslot is
    /// only ever an input slot.
    /// Faithful to `TypeOpStore::propagateType` (typeop.cc:557-570).
    // Ghidra: typeop.cc:557 TypeOpStore::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot == 0 || outslot == 0 {
            return None; // Don't propagate along the space-constant edge
        }
        // Spacebase pointers do not propagate.
        let source = if inslot < 0 {
            op.get_out()
        } else {
            op.get_in(inslot as usize)
        };
        if source.is_some_and(|vn| vn.read().unwrap().is_spacebase()) {
            return None;
        }
        if inslot == 2 {
            // value -> pointer : wrap value type as a pointer (propagateToPointer)
            Some(propagate_to_pointer(alt_type))
        } else {
            // pointer -> value : unwrap pointer to its pointee (propagateFromPointer)
            let dereference_size = attached_varnode_size(op, outslot)?;
            propagate_from_pointer(alt_type, dereference_size)
        }
    }
}

/// Wrap a value data-type as a pointer to it (used by LOAD/STORE output->input
/// propagation). Mirrors Ghidra's `TypeOp::propagateToPointer`
/// (typeop.cc:186-198): a pointer-to-pointer is collapsed to a pointer to an
/// unknown base of the right size to avoid creating ptr->ptr.
// Ghidra: typeop.cc:186 TypeOp::propagateToPointer
pub fn propagate_to_pointer(alt_type: &Arc<Datatype>) -> Arc<Datatype> {
    use crate::type_system::datatype::TypePointer;
    let sz = alt_type.get_size();
    let pointee = match alt_type.as_ref() {
        // If already a pointer, point at an unknown base of the pointee's size
        // so we never build ptr->ptr.
        Datatype::Pointer(_) => Arc::new(Datatype::Base(crate::type_system::TypeBase::new(
            "unknown".to_string(),
            alt_type.get_size(),
            TypeMetatype::Unknown,
        ))),
        _ => alt_type.clone(),
    };
    // cc:197: t->getTypePointer(sz,dt,wordsz) — the 3-arg overload's
    // `TypePointer tmp(s,pt,ws)` carries an EMPTY name (type.cc:3867-3875);
    // the former composed-name spelling ("char *") surfaced as a NAMED
    // single-layer pointer in every decl/cast built from this propagation,
    // diverging from Ghidra's anonymous drilled rendering (oracle
    // printc_anonymous_pointer_decl_1204 named_ptr_contrast).
    Arc::new(Datatype::Pointer(TypePointer::new(sz, pointee, 1)))
}

/// Faithful `TypeOp::propagateToPointer` (typeop.cc:186-198): the POINTER is
/// sized by the propagation edge's destination varnode (`sz` — the LOAD/STORE
/// callers pass `outvn->getSize()` at typeop.cc:495/565), NOT by the alttype,
/// and the product is factory-INTERNED via `t->getTypePointer(sz,dt,wordsz)`
/// so pointer-identity comparisons (`TypeOpStore::getInputCast` cc:546-548)
/// see the canonical instance. A pointer alttype is demoted to an unknown
/// base of its own size (never ptr->ptr); a PARTIALSTRUCT alttype resolves
/// through `getComponentForPtr` (cc:194-196).
// Ghidra: typeop.cc:186 TypeOp::propagateToPointer
pub fn propagate_to_pointer_sized(
    alt_type: &Arc<Datatype>,
    sz: usize,
    type_factory: Option<&Arc<std::sync::RwLock<crate::type_system::typefactory::TypeFactory>>>,
) -> Arc<Datatype> {
    use crate::type_system::datatype::TypePointer;
    use std::sync::Arc as ArcT;
    let unknown_base = |size: usize| -> ArcT<Datatype> {
        if let Some(factory) = type_factory {
            if let Some(base) =
                factory.read().unwrap().get_base(size, TypeMetatype::Unknown)
            {
                return base;
            }
        }
        ArcT::new(Datatype::Base(crate::type_system::TypeBase::new(
            "unknown".to_string(),
            size,
            TypeMetatype::Unknown,
        )))
    };
    let pointee = match alt_type.as_ref() {
        // cc:190-193: pointer alttype → unknown base of the pointer's size.
        Datatype::Pointer(_) => unknown_base(alt_type.get_size()),
        // cc:194-196: partial struct → its pointer component.
        Datatype::PartialStruct(ps) => ps.get_component_for_ptr().unwrap_or_else(|| alt_type.clone()),
        _ => alt_type.clone(),
    };
    if let Some(factory) = type_factory {
        return factory
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_type_pointer(sz, pointee, 1);
    }
    ArcT::new(Datatype::Pointer(TypePointer::new(sz, pointee, 1)))
}

/// Unwrap a pointer data-type to its pointee (used by LOAD/STORE input->output
/// propagation). Mirrors Ghidra's `TypeOp::propagateFromPointer`
/// (typeop.cc:206-228). Fixed-size pointees propagate only when their size is
/// exactly the dereference width. Enum/relative-pointer mismatch handling
/// requires the owning `TypeFactory::getExactPiece` and deliberately remains
/// fail-closed here instead of constructing a non-canonical replacement.
// Ghidra: typeop.cc:206 TypeOp::propagateFromPointer
pub fn propagate_from_pointer(
    alt_type: &Arc<Datatype>,
    dereference_size: usize,
) -> Option<Arc<Datatype>> {
    let pointer = match alt_type.as_ref() {
        Datatype::Pointer(pointer) => pointer,
        _ => return None,
    };
    let pointee = &pointer.ptr_to;
    if pointee.is_variable_length() {
        return None;
    }
    if pointee.get_size() == dereference_size {
        return Some(pointee.clone());
    }
    None
}

// RUDRA-GLUE: Rust slot-to-Varnode adapter for Ghidra's invn/outvn propagateType parameters.
fn attached_varnode_size(op: &PcodeOp, slot: i32) -> Option<usize> {
    if slot < 0 {
        op.get_out()
            .map(|varnode| varnode.read().unwrap().get_size())
    } else {
        op.get_in(slot as usize)
            .map(|varnode| varnode.read().unwrap().get_size())
    }
}

// Arithmetic Operations
// NOTE: TypeOpIntAdd has a hand-written impl below (it needs a custom
// get_output_token and propagate_type).
// Ghidra: typeop.cc:1318 TypeOpIntSub::TypeOpIntSub — TypeOpBinary("-",TYPE_INT,TYPE_INT)
binary_op!(
    TypeOpIntSub,
    CPUI_INT_SUB,
    "INT_SUB",
    typeop_flags::ARITHMETIC_OP,
    "-",
    Int,
    Int
);
// Ghidra: typeop.cc:1617 TypeOpIntMult::TypeOpIntMult — TypeOpBinary("*",TYPE_INT,TYPE_INT)
binary_op!(
    TypeOpIntMult,
    CPUI_INT_MULT,
    "INT_MULT",
    typeop_flags::ARITHMETIC_OP,
    "*",
    Int,
    Int
);
// Ghidra: typeop.cc:1631 TypeOpIntDiv::TypeOpIntDiv — TypeOpBinary("/",TYPE_UINT,TYPE_UINT)
binary_op_ext!(
    TypeOpIntDiv,
    CPUI_INT_DIV,
    "INT_DIV",
    typeop_flags::ARITHMETIC_OP,
    "/",
    Uint,
    Uint,
    {
        /// The divide input cast, both slots (typeop.cc:1639-1649): a
        /// promotion without the UNSIGNED extension direction forces the
        /// `inputTypeLocal(slot)` base (TYPE_UINT), else
        /// `castStandard(reqtype,curtype,TRUE,TRUE)`.
        // Ghidra: typeop.cc:1639 TypeOpIntDiv::getInputCast
        fn get_input_cast(
            &self,
            op: &crate::op::PcodeOpRef,
            slot: usize,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            let strategy = factory_cast_strategy(&self.type_factory);
            const UNSIGNED_EXTENSION: i32 = 1;
            divrem_input_cast(self, op, slot, &strategy, fd, UNSIGNED_EXTENSION)
        }
    }
);
// Ghidra: typeop.cc:1651 TypeOpIntSdiv::TypeOpIntSdiv — TypeOpBinary("/",TYPE_INT,TYPE_INT)
binary_op_ext!(
    TypeOpIntSdiv,
    CPUI_INT_SDIV,
    "INT_SDIV",
    typeop_flags::ARITHMETIC_OP,
    "s/",
    Int,
    Int,
    {
        /// The signed divide input cast, both slots (typeop.cc:1659-1669):
        /// SIGNED gate, `inputTypeLocal` base TYPE_INT.
        // Ghidra: typeop.cc:1659 TypeOpIntSdiv::getInputCast
        fn get_input_cast(
            &self,
            op: &crate::op::PcodeOpRef,
            slot: usize,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            let strategy = factory_cast_strategy(&self.type_factory);
            const SIGNED_EXTENSION: i32 = 2;
            divrem_input_cast(self, op, slot, &strategy, fd, SIGNED_EXTENSION)
        }
    }
);
// Ghidra: typeop.cc:1671 TypeOpIntRem::TypeOpIntRem — TypeOpBinary("%",TYPE_UINT,TYPE_UINT)
binary_op_ext!(
    TypeOpIntRem,
    CPUI_INT_REM,
    "INT_REM",
    typeop_flags::ARITHMETIC_OP,
    "%",
    Uint,
    Uint,
    {
        /// The remainder input cast, both slots (typeop.cc:1679-1689):
        /// UNSIGNED gate, `inputTypeLocal` base TYPE_UINT.
        // Ghidra: typeop.cc:1679 TypeOpIntRem::getInputCast
        fn get_input_cast(
            &self,
            op: &crate::op::PcodeOpRef,
            slot: usize,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            let strategy = factory_cast_strategy(&self.type_factory);
            const UNSIGNED_EXTENSION: i32 = 1;
            divrem_input_cast(self, op, slot, &strategy, fd, UNSIGNED_EXTENSION)
        }
    }
);
// Ghidra: typeop.cc:1691 TypeOpIntSrem::TypeOpIntSrem — TypeOpBinary("%",TYPE_INT,TYPE_INT)
binary_op_ext!(
    TypeOpIntSrem,
    CPUI_INT_SREM,
    "INT_SREM",
    typeop_flags::ARITHMETIC_OP,
    "s%",
    Int,
    Int,
    {
        /// The signed remainder input cast, both slots (typeop.cc:1699-1709):
        /// SIGNED gate, `inputTypeLocal` base TYPE_INT.
        // Ghidra: typeop.cc:1699 TypeOpIntSrem::getInputCast
        fn get_input_cast(
            &self,
            op: &crate::op::PcodeOpRef,
            slot: usize,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            let strategy = factory_cast_strategy(&self.type_factory);
            const SIGNED_EXTENSION: i32 = 2;
            divrem_input_cast(self, op, slot, &strategy, fd, SIGNED_EXTENSION)
        }
    }
);
// Ghidra: typeop.cc:1380 TypeOpInt2Comp::TypeOpInt2Comp — TypeOpUnary("-",TYPE_INT,TYPE_INT)
unary_op!(
    TypeOpIntNeg,
    CPUI_INT_2COMP,
    "INT_2COMP",
    typeop_flags::ARITHMETIC_OP,
    "-",
    Int,
    Int
);
// Ghidra: typeop.cc:1332 TypeOpIntCarry::TypeOpIntCarry — TypeOpFunc("CARRY",TYPE_BOOL,TYPE_UINT)
functional_binary_op_ext!(
    TypeOpIntCarry,
    CPUI_INT_CARRY,
    "INT_CARRY",
    0,
    "carry",
    Bool,
    Uint,
    {
        /// `CARRY<insize>` — the operator name carries the input-0 size.
        // Ghidra: typeop.cc:1340 TypeOpIntCarry::getOperatorName
        fn get_operator_name(&self, op: &PcodeOp) -> String {
            format!(
                "CARRY{}",
                op.get_in(0)
                    .map(|v| v.read().unwrap().get_size())
                    .unwrap_or(0)
            )
        }
    }
);
// Ghidra: typeop.cc:1348 TypeOpIntScarry::TypeOpIntScarry — TypeOpFunc("SCARRY",TYPE_BOOL,TYPE_INT)
functional_binary_op_ext!(
    TypeOpIntScarry,
    CPUI_INT_SCARRY,
    "INT_SCARRY",
    0,
    "scarry",
    Bool,
    Int,
    {
        /// `SCARRY<insize>` — the operator name carries the input-0 size.
        // Ghidra: typeop.cc:1356 TypeOpIntScarry::getOperatorName
        fn get_operator_name(&self, op: &PcodeOp) -> String {
            format!(
                "SCARRY{}",
                op.get_in(0)
                    .map(|v| v.read().unwrap().get_size())
                    .unwrap_or(0)
            )
        }
    }
);
// Ghidra: typeop.cc:1364 TypeOpIntSborrow::TypeOpIntSborrow — TypeOpFunc("SBORROW",TYPE_BOOL,TYPE_INT)
functional_binary_op_ext!(
    TypeOpIntSborrow,
    CPUI_INT_SBORROW,
    "INT_SBORROW",
    0,
    "sborrow",
    Bool,
    Int,
    {
        /// `SBORROW<insize>` — the operator name carries the input-0 size.
        // Ghidra: typeop.cc:1372 TypeOpIntSborrow::getOperatorName
        fn get_operator_name(&self, op: &PcodeOp) -> String {
            format!(
                "SBORROW{}",
                op.get_in(0)
                    .map(|v| v.read().unwrap().get_size())
                    .unwrap_or(0)
            )
        }
    }
);

// Bitwise Operations
// Ghidra: typeop.cc:1441 TypeOpIntAnd::TypeOpIntAnd — TypeOpBinary("&",TYPE_UINT,TYPE_UINT)
binary_op!(
    TypeOpIntAnd,
    CPUI_INT_AND,
    "INT_AND",
    typeop_flags::LOGICAL_OP,
    "&",
    Uint,
    Uint
);
// Ghidra: typeop.cc:1474 TypeOpIntOr::TypeOpIntOr — TypeOpBinary("|",TYPE_UINT,TYPE_UINT)
binary_op!(
    TypeOpIntOr,
    CPUI_INT_OR,
    "INT_OR",
    typeop_flags::LOGICAL_OP,
    "|",
    Uint,
    Uint
);
// Ghidra: typeop.cc:1408 TypeOpIntXor::TypeOpIntXor — TypeOpBinary("^",TYPE_UINT,TYPE_UINT)
binary_op!(
    TypeOpIntXor,
    CPUI_INT_XOR,
    "INT_XOR",
    typeop_flags::LOGICAL_OP,
    "^",
    Uint,
    Uint
);
// Ghidra: typeop.cc:1394 TypeOpIntNegate::TypeOpIntNegate — TypeOpUnary("~",TYPE_UINT,TYPE_UINT)
unary_op!(
    TypeOpIntNot,
    CPUI_INT_NEGATE,
    "INT_NEGATE",
    typeop_flags::LOGICAL_OP,
    "~",
    Uint,
    Uint
);

// Ghidra: typeop.cc:1175 TypeOpIntAdd::getOutputToken (arithmetic family)
/// Shared arithmetic-output-token dispatch backing the macro-generated
/// `get_output_token` overrides: INT_ADD/SUB/2COMP/NEGATE/XOR/AND/OR/MULT
/// each override `getOutputToken` with the identical one-liner
/// `return castStrategy->arithmeticOutputStandard(op);` (typeop.cc:1175,
/// 1326, 1388, 1402, 1416, 1449, 1482, 1625); every other macro op keeps the
/// base-class "no token override" (None) default.
fn macro_arith_output_token(
    opc: OpCode,
    op: &PcodeOp,
    factory: &Arc<RwLock<TypeFactory>>,
) -> Option<Arc<Datatype>> {
    match opc {
        OpCode::CPUI_INT_ADD
        | OpCode::CPUI_INT_SUB
        | OpCode::CPUI_INT_2COMP
        | OpCode::CPUI_INT_NEGATE
        | OpCode::CPUI_INT_XOR
        | OpCode::CPUI_INT_AND
        | OpCode::CPUI_INT_OR
        | OpCode::CPUI_INT_MULT => {
            crate::type_system::cast::arithmetic_output_standard(op, factory)
        }
        _ => None,
    }
}
// Shift Operations — hand-written instead of `binary_op!` because Ghidra's
// TypeOpIntLeft/TypeOpIntRight/TypeOpIntSright override getInputLocal
// (typeop.cc:1509/:1536/:1600): slot 1 (the shift amount) must come back as
// getBaseNoChar(size, TYPE_INT) — the size-1 no-char int — while every other
// slot uses the TypeOpBinary default getBase(size, metain).
// ---------------------------------------------------------------------------
// Ghidra: typeop.cc:1502 TypeOpIntLeft::TypeOpIntLeft — TypeOpBinary("<<",TYPE_INT,TYPE_INT)
pub struct TypeOpIntLeft {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpIntLeft {
    // RUDRA-GLUE: stores the base-class `tlst` field the Ghidra constructor
    //   receives (typeop.cc:1502).
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpIntLeft {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INT_LEFT
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "INT_LEFT"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        typeop_flags::SHIFT_OP
    }
    // Ghidra: typeop.cc:335 TypeOpBinary::printRaw (IntLeft inherits)
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} << {}", out, in0, in1)
    }
    // Ghidra: typeop.hh:529 TypeOpIntLeft::push -> lng->opIntLeft(op). Rudra's
    //   PrintLanguage does not yet expose opIntLeft (print-side emitter gap,
    //   PRINTC-CAST-OPNAME follow-up); op_binary preserves the previous
    //   routing until that emitter is ported.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_binary(op);
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242).
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal (IntLeft inherits)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Int)
    }
    // Ghidra: typeop.cc:1510 TypeOpIntLeft::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        if slot == 1 {
            let size = op.get_in(slot)?.read().unwrap().get_size();
            return type_factory
                .read()
                .unwrap()
                .get_base_no_char(size, TypeMetatype::Int);
        }
        let size = op.get_in(slot)?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Int)
    }

    /// The shift output token (typeop.cc:1518-1525): input-0's HIGH
    /// read-facing type, with BOOL demoted to the factory INT base of the
    /// same size. The fd-aware consult is keyed on slot 0.
    // Ghidra: typeop.cc:1518 TypeOpIntLeft::getOutputToken
    fn get_output_token_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        shift_output_token_in_fd(op, fd, &self.type_factory)
    }
}

// Ghidra: typeop.cc:1527 TypeOpIntRight::TypeOpIntRight — TypeOpBinary(">>",TYPE_UINT,TYPE_UINT)
pub struct TypeOpIntRight {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpIntRight {
    // RUDRA-GLUE: stores the base-class `tlst` field the Ghidra constructor
    //   receives (typeop.cc:1527).
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpIntRight {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INT_RIGHT
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "INT_RIGHT"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        typeop_flags::SHIFT_OP
    }
    // Ghidra: typeop.cc:335 TypeOpBinary::printRaw (IntRight inherits)
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} >> {}", out, in0, in1)
    }
    // Ghidra: typeop.hh:538 TypeOpIntRight::push -> lng->opIntRight(op). Rudra
    //   has no opIntRight emitter yet (print-side gap, see IntLeft note);
    //   op_binary preserves the previous routing.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_binary(op);
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242).
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal (IntRight inherits)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Uint)
    }
    // Ghidra: typeop.cc:1535 TypeOpIntRight::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        if slot == 1 {
            let size = op.get_in(slot)?.read().unwrap().get_size();
            return type_factory
                .read()
                .unwrap()
                .get_base_no_char(size, TypeMetatype::Int);
        }
        let size = op.get_in(slot)?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Uint)
    }

    /// The slot-0 input cast (typeop.cc:1543-1556): a promotion that lacks
    /// the UNSIGNED extension direction forces the `inputTypeLocal(0)`
    /// base (TYPE_UINT), else `castStandard(reqtype,curtype,TRUE,TRUE)`;
    /// every other slot falls back to the base `TypeOp::getInputCast` arm
    /// (cc:1555, via the trait default).
    // Ghidra: typeop.cc:1543 TypeOpIntRight::getInputCast
    fn get_input_cast(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        if slot != 0 {
            // cc:1555: TypeOpBinary::getInputCast — no override, the base arm.
            return base_input_cast_arm(self, op, slot, fd);
        }
        let strategy = factory_cast_strategy(&self.type_factory);
        const UNSIGNED_EXTENSION: i32 = 1;
        shift_input_cast(self, op, slot, &strategy, fd, UNSIGNED_EXTENSION)
    }

    /// The shift output token (typeop.cc:1558-1565): input-0's HIGH
    /// read-facing type, BOOL demoted to the factory INT base.
    // Ghidra: typeop.cc:1558 TypeOpIntRight::getOutputToken
    fn get_output_token_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        shift_output_token_in_fd(op, fd, &self.type_factory)
    }
}

// Ghidra: typeop.cc:1567 TypeOpIntSright::TypeOpIntSright — TypeOpBinary(">>",TYPE_INT,TYPE_INT)
pub struct TypeOpIntSright {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpIntSright {
    // RUDRA-GLUE: stores the base-class `tlst` field the Ghidra constructor
    //   receives (typeop.cc:1567).
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpIntSright {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INT_SRIGHT
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "INT_SRIGHT"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        typeop_flags::SHIFT_OP
    }
    // Ghidra: typeop.cc:1575 TypeOpIntSright::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} s>> {}", out, in0, in1)
    }
    // Ghidra: typeop.hh:548 TypeOpIntSright::push -> lng->opIntSright(op).
    //   Rudra has no opIntSright emitter yet (print-side gap, see IntLeft
    //   note); op_binary preserves the previous routing.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_binary(op);
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242).
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal (IntSright inherits)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Int)
    }
    // Ghidra: typeop.cc:1600 TypeOpIntSright::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        if slot == 1 {
            let size = op.get_in(slot)?.read().unwrap().get_size();
            return type_factory
                .read()
                .unwrap()
                .get_base_no_char(size, TypeMetatype::Int);
        }
        let size = op.get_in(slot)?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Int)
    }

    /// The slot-0 input cast (typeop.cc:1585-1598): a promotion that lacks
    /// the SIGNED extension direction forces the `inputTypeLocal(0)` base
    /// (TYPE_INT), else `castStandard(reqtype,curtype,TRUE,TRUE)`; every
    /// other slot falls back to the base arm (cc:1597).
    // Ghidra: typeop.cc:1585 TypeOpIntSright::getInputCast
    fn get_input_cast(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        if slot != 0 {
            // cc:1597: TypeOpBinary::getInputCast — the base arm.
            return base_input_cast_arm(self, op, slot, fd);
        }
        let strategy = factory_cast_strategy(&self.type_factory);
        const SIGNED_EXTENSION: i32 = 2;
        shift_input_cast(self, op, slot, &strategy, fd, SIGNED_EXTENSION)
    }

    /// The shift output token (typeop.cc:1608-1615): input-0's HIGH
    /// read-facing type, BOOL demoted to the factory INT base.
    // Ghidra: typeop.cc:1608 TypeOpIntSright::getOutputToken
    fn get_output_token_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        shift_output_token_in_fd(op, fd, &self.type_factory)
    }
}

// Comparison Operations
// NOTE: The six comparison ops (Equal, NotEqual, Less, LessEqual, Sless,
// SlessEqual) have hand-written impls below: each has bool output metaout and
// a propagate_type that flows across the two input operands.

// Extension Operations
// Ghidra: typeop.cc:1115 TypeOpIntZext::TypeOpIntZext — TypeOpFunc("ZEXT",TYPE_UINT,TYPE_UINT)
functional_unary_op_ext!(
    TypeOpIntZext,
    CPUI_INT_ZEXT,
    "INT_ZEXT",
    typeop_flags::INHERITS_SIGN_ZERO,
    "zext",
    Uint,
    Uint,
    {
        /// `ZEXT<insize><outsize>` — the operator name carries both sizes
        /// (typeop.cc:1122-1129).
        // Ghidra: typeop.cc:1122 TypeOpIntZext::getOperatorName
        fn get_operator_name(&self, op: &PcodeOp) -> String {
            let in_size = op.get_in(0).map(|v| v.read().unwrap().get_size());
            let out_size = op.get_out().map(|v| v.read().unwrap().get_size());
            format!("ZEXT{}{}", in_size.unwrap_or(0), out_size.unwrap_or(0))
        }

        /// The extension input cast (typeop.cc:1131-1139): the
        /// `inputTypeLocal(slot)` base (TYPE_UINT) forced under
        /// `checkIntPromotionForExtension` (cast.cc:126-138: an unsigned
        /// promotion into ZEXT is implied), else
        /// `castStandard(reqtype,curtype,TRUE,FALSE)`.
        // Ghidra: typeop.cc:1131 TypeOpIntZext::getInputCast
        fn get_input_cast(
            &self,
            op: &crate::op::PcodeOpRef,
            slot: usize,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            let strategy = factory_cast_strategy(&self.type_factory);
            extension_input_cast(self, op, slot, &strategy, fd)
        }
    }
);
// Ghidra: typeop.cc:1141 TypeOpIntSext::TypeOpIntSext — TypeOpFunc("SEXT",TYPE_INT,TYPE_INT)
functional_unary_op_ext!(
    TypeOpIntSext,
    CPUI_INT_SEXT,
    "INT_SEXT",
    typeop_flags::INHERITS_SIGN,
    "sext",
    Int,
    Int,
    {
        /// `SEXT<insize><outsize>` — the operator name carries both sizes
        /// (typeop.cc:1148-1155).
        // Ghidra: typeop.cc:1148 TypeOpIntSext::getOperatorName
        fn get_operator_name(&self, op: &PcodeOp) -> String {
            let in_size = op.get_in(0).map(|v| v.read().unwrap().get_size());
            let out_size = op.get_out().map(|v| v.read().unwrap().get_size());
            format!("SEXT{}{}", in_size.unwrap_or(0), out_size.unwrap_or(0))
        }

        /// The extension input cast (typeop.cc:1157-1165): the
        /// `inputTypeLocal(slot)` base (TYPE_INT) forced under
        /// `checkIntPromotionForExtension` (a signed promotion into SEXT is
        /// implied), else `castStandard(reqtype,curtype,TRUE,FALSE)`.
        // Ghidra: typeop.cc:1157 TypeOpIntSext::getInputCast
        fn get_input_cast(
            &self,
            op: &crate::op::PcodeOpRef,
            slot: usize,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            let strategy = factory_cast_strategy(&self.type_factory);
            extension_input_cast(self, op, slot, &strategy, fd)
        }
    }
);
// (The former `TypeOpTrunc` macro instantiation — the pre-12.0.4 Rust name
// for SUBPIECE — was removed by WORKPKG-UNMAP-TYPEOP-0001: the oracle class
// is `TypeOpSubpiece` (typeop.cc:2116) and the TypeOpManager table's dead
// first SUBPIECE registration (overwritten in place by TypeOpSubpiece) went
// with it. The 12.0.4 registerInstructions table (typeop.cc:44) registers
// exactly one SUBPIECE entry.)

// Floating Point Operations
// Ghidra: typeop.cc:1783 TypeOpFloatAdd::TypeOpFloatAdd — TypeOpBinary("+",TYPE_FLOAT,TYPE_FLOAT)
binary_op!(
    TypeOpFloatAdd,
    CPUI_FLOAT_ADD,
    "FLOAT_ADD",
    typeop_flags::FLOATINGPOINT_OP,
    "f+",
    Float,
    Float
);
// Ghidra: typeop.cc:1807 TypeOpFloatSub::TypeOpFloatSub — TypeOpBinary("-",TYPE_FLOAT,TYPE_FLOAT)
binary_op!(
    TypeOpFloatSub,
    CPUI_FLOAT_SUB,
    "FLOAT_SUB",
    typeop_flags::FLOATINGPOINT_OP,
    "f-",
    Float,
    Float
);
// Ghidra: typeop.cc:1799 TypeOpFloatMult::TypeOpFloatMult — TypeOpBinary("*",TYPE_FLOAT,TYPE_FLOAT)
binary_op!(
    TypeOpFloatMult,
    CPUI_FLOAT_MULT,
    "FLOAT_MULT",
    typeop_flags::FLOATINGPOINT_OP,
    "f*",
    Float,
    Float
);
// Ghidra: typeop.cc:1791 TypeOpFloatDiv::TypeOpFloatDiv — TypeOpBinary("/",TYPE_FLOAT,TYPE_FLOAT)
binary_op!(
    TypeOpFloatDiv,
    CPUI_FLOAT_DIV,
    "FLOAT_DIV",
    typeop_flags::FLOATINGPOINT_OP,
    "f/",
    Float,
    Float
);
// Ghidra: typeop.cc:1815 TypeOpFloatNeg::TypeOpFloatNeg — TypeOpUnary("-",TYPE_FLOAT,TYPE_FLOAT)
unary_op!(
    TypeOpFloatNeg,
    CPUI_FLOAT_NEG,
    "FLOAT_NEG",
    typeop_flags::FLOATINGPOINT_OP,
    "f-",
    Float,
    Float
);
// Ghidra: typeop.cc:1823 TypeOpFloatAbs::TypeOpFloatAbs — TypeOpFunc("ABS",TYPE_FLOAT,TYPE_FLOAT)
functional_unary_op!(
    TypeOpFloatAbs,
    CPUI_FLOAT_ABS,
    "FLOAT_ABS",
    typeop_flags::FLOATINGPOINT_OP,
    "fabs",
    Float,
    Float
);
// Ghidra: typeop.cc:1831 TypeOpFloatSqrt::TypeOpFloatSqrt — TypeOpFunc("SQRT",TYPE_FLOAT,TYPE_FLOAT)
functional_unary_op!(
    TypeOpFloatSqrt,
    CPUI_FLOAT_SQRT,
    "FLOAT_SQRT",
    typeop_flags::FLOATINGPOINT_OP,
    "fsqrt",
    Float,
    Float
);
// Ghidra: typeop.cc:1743 TypeOpFloatEqual::TypeOpFloatEqual — TypeOpBinary("==",TYPE_BOOL,TYPE_FLOAT)
binary_op!(
    TypeOpFloatEqual,
    CPUI_FLOAT_EQUAL,
    "FLOAT_EQUAL",
    typeop_flags::FLOATINGPOINT_OP,
    "f==",
    Bool,
    Float
);
// Ghidra: typeop.cc:1751 TypeOpFloatNotEqual::TypeOpFloatNotEqual — TypeOpBinary("!=",TYPE_BOOL,TYPE_FLOAT)
binary_op!(
    TypeOpFloatNotEqual,
    CPUI_FLOAT_NOTEQUAL,
    "FLOAT_NOTEQUAL",
    typeop_flags::FLOATINGPOINT_OP,
    "f!=",
    Bool,
    Float
);
// Ghidra: typeop.cc:1759 TypeOpFloatLess::TypeOpFloatLess — TypeOpBinary("<",TYPE_BOOL,TYPE_FLOAT)
binary_op!(
    TypeOpFloatLess,
    CPUI_FLOAT_LESS,
    "FLOAT_LESS",
    typeop_flags::FLOATINGPOINT_OP,
    "f<",
    Bool,
    Float
);
// Ghidra: typeop.cc:1767 TypeOpFloatLessEqual::TypeOpFloatLessEqual — TypeOpBinary("<=",TYPE_BOOL,TYPE_FLOAT)
binary_op!(
    TypeOpFloatLessEqual,
    CPUI_FLOAT_LESSEQUAL,
    "FLOAT_LESSEQUAL",
    typeop_flags::FLOATINGPOINT_OP,
    "f<=",
    Bool,
    Float
);
// Ghidra: typeop.cc:1775 TypeOpFloatNan::TypeOpFloatNan — TypeOpFunc("NAN",TYPE_BOOL,TYPE_FLOAT)
functional_unary_op!(
    TypeOpFloatNan,
    CPUI_FLOAT_NAN,
    "FLOAT_NAN",
    typeop_flags::FLOATINGPOINT_OP,
    "isnan",
    Bool,
    Float
);
// Ghidra: typeop.cc:1904 TypeOpFloatFloat2Float::TypeOpFloatFloat2Float — TypeOpFunc("FLOAT2FLOAT",TYPE_FLOAT,TYPE_FLOAT)
functional_unary_op!(
    TypeOpFloatFloat2Float,
    CPUI_FLOAT_FLOAT2FLOAT,
    "FLOAT2FLOAT",
    typeop_flags::FLOATINGPOINT_OP,
    "f2f",
    Float,
    Float
);
// Ghidra: typeop.cc:1839 TypeOpFloatInt2Float::TypeOpFloatInt2Float — TypeOpFunc("INT2FLOAT",TYPE_FLOAT,TYPE_INT)
functional_unary_op_ext!(
    TypeOpFloatInt2Float,
    CPUI_FLOAT_INT2FLOAT,
    "INT2FLOAT",
    typeop_flags::FLOATINGPOINT_OP,
    "i2f",
    Float,
    Int,
    {
        /// The INT2FLOAT input cast (typeop.cc:1847-1862): no cast when the
        /// conversion absorbs an INT_ZEXT (`absorbZext`, cc:1850-1851); else
        /// the `inputTypeLocal(slot)` base (TYPE_INT) under
        /// `castStandard(reqtype,curtype,care_uint_int,true)` where
        /// `care_uint_int` drops to FALSE when the input's NZMask high bit
        /// is clear (cc:1855-1860: "If the high-bit is not set, we don't
        /// care if input is signed or unsigned").
        // Ghidra: typeop.cc:1847 TypeOpFloatInt2Float::getInputCast
        fn get_input_cast(
            &self,
            op: &crate::op::PcodeOpRef,
            slot: usize,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            let strategy = factory_cast_strategy(&self.type_factory);
            float_int2float_input_cast(self, op, slot, &strategy, fd)
        }
    }
);

impl TypeOpFloatInt2Float {
    /// Return the preferred zero-extension size for an unsigned integer input.
    // Ghidra: typeop.cc:1891 TypeOpFloatInt2Float::preferredZextSize
    pub fn preferred_zext_size(in_size: i32) -> i32 {
        if in_size < 4 {
            4
        } else if in_size < 8 {
            8
        } else {
            in_size + 1
        }
    }
}

// Ghidra: typeop.cc:1912 TypeOpFloatTrunc::TypeOpFloatTrunc — TypeOpFunc("TRUNC",TYPE_INT,TYPE_FLOAT)
functional_unary_op!(
    TypeOpFloatTrunc,
    CPUI_FLOAT_TRUNC,
    "TRUNC",
    typeop_flags::FLOATINGPOINT_OP,
    "ftrunc",
    Int,
    Float
);
// Ghidra: typeop.cc:1920 TypeOpFloatCeil::TypeOpFloatCeil — TypeOpFunc("CEIL",TYPE_FLOAT,TYPE_FLOAT)
functional_unary_op!(
    TypeOpFloatCeil,
    CPUI_FLOAT_CEIL,
    "CEIL",
    typeop_flags::FLOATINGPOINT_OP,
    "fceil",
    Float,
    Float
);
// Ghidra: typeop.cc:1928 TypeOpFloatFloor::TypeOpFloatFloor — TypeOpFunc("FLOOR",TYPE_FLOAT,TYPE_FLOAT)
functional_unary_op!(
    TypeOpFloatFloor,
    CPUI_FLOAT_FLOOR,
    "FLOOR",
    typeop_flags::FLOATINGPOINT_OP,
    "ffloor",
    Float,
    Float
);
// Ghidra: typeop.cc:1936 TypeOpFloatRound::TypeOpFloatRound — TypeOpFunc("ROUND",TYPE_FLOAT,TYPE_FLOAT)
functional_unary_op!(
    TypeOpFloatRound,
    CPUI_FLOAT_ROUND,
    "ROUND",
    typeop_flags::FLOATINGPOINT_OP,
    "fround",
    Float,
    Float
);

// Boolean Operations
// Ghidra: typeop.cc:1727 TypeOpBoolAnd::TypeOpBoolAnd — TypeOpBinary("&&",TYPE_BOOL,TYPE_BOOL)
binary_op!(
    TypeOpBoolAnd, CPUI_BOOL_AND, "BOOL_AND", 0, "&&", Bool, Bool
);
// Ghidra: typeop.cc:1735 TypeOpBoolOr::TypeOpBoolOr — TypeOpBinary("||",TYPE_BOOL,TYPE_BOOL)
binary_op!(TypeOpBoolOr, CPUI_BOOL_OR, "BOOL_OR", 0, "||", Bool, Bool);
// Ghidra: typeop.cc:1719 TypeOpBoolXor::TypeOpBoolXor — TypeOpBinary("^^",TYPE_BOOL,TYPE_BOOL)
binary_op!(
    TypeOpBoolXor, CPUI_BOOL_XOR, "BOOL_XOR", 0, "^^", Bool, Bool
);
// Ghidra: typeop.cc:1711 TypeOpBoolNegate::TypeOpBoolNegate — TypeOpUnary("!",TYPE_BOOL,TYPE_BOOL)
unary_op!(
    TypeOpBoolNot,
    CPUI_BOOL_NEGATE,
    "BOOL_NEGATE",
    0,
    "!",
    Bool,
    Bool
);

// Special Operations
// Ghidra: typeop.cc:2037 TypeOpPiece::TypeOpPiece — TypeOpFunc("CONCAT",TYPE_UNKNOWN,TYPE_UNKNOWN)
functional_binary_op_ext!(
    TypeOpPiece,
    CPUI_PIECE,
    "PIECE",
    0,
    "concat",
    Unknown,
    Unknown,
    {
        /// `CONCAT<insize><insize>` — the operator name carries both input
        /// sizes (typeop.cc:2048-2055).
        // Ghidra: typeop.cc:2048 TypeOpPiece::getOperatorName
        fn get_operator_name(&self, op: &PcodeOp) -> String {
            let in0 = op
                .get_in(0)
                .map(|v| v.read().unwrap().get_size())
                .unwrap_or(0);
            let in1 = op
                .get_in(1)
                .map(|v| v.read().unwrap().get_size())
                .unwrap_or(0);
            format!("CONCAT{}{}", in0, in1)
        }

        /// "Never need a cast into a PIECE" (typeop.cc:2057-2061).
        // Ghidra: typeop.cc:2057 TypeOpPiece::getInputCast
        fn get_input_cast(
            &self,
            _op: &crate::op::PcodeOpRef,
            _slot: usize,
            _fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            None
        }

        /// The PIECE output token (typeop.cc:2063-2072): the output's
        /// DEF-facing high type when INT/UINT ("PIECE casts to uint or int,
        /// based on output"), else the factory UINT base ("If output is
        /// unknown or pointer, treat as cast to uint"). The fd-aware
        /// def-facing consult is keyed on slot -1
        /// (UNIONRESOLVE-PKG-B-0001).
        // Ghidra: typeop.cc:2063 TypeOpPiece::getOutputToken
        fn get_output_token_in_fd(
            &self,
            op: &crate::op::PcodeOpRef,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            piece_output_token_in_fd(op, fd, &self.type_factory)
        }
    }
);
// Ghidra: typeop.cc:2116 TypeOpSubpiece::TypeOpSubpiece — TypeOpFunc("SUB",TYPE_UNKNOWN,TYPE_UNKNOWN)
functional_binary_op_ext!(
    TypeOpSubpiece,
    CPUI_SUBPIECE,
    "SUBPIECE",
    0,
    "subpiece",
    Unknown,
    Unknown,
    {
        /// `SUB<insize><outsize>` — the operator name carries the input-0
        /// and output sizes (typeop.cc:2127-2134).
        // Ghidra: typeop.cc:2127 TypeOpSubpiece::getOperatorName
        fn get_operator_name(&self, op: &PcodeOp) -> String {
            let in0 = op
                .get_in(0)
                .map(|v| v.read().unwrap().get_size())
                .unwrap_or(0);
            let out = op
                .get_out()
                .map(|v| v.read().unwrap().get_size())
                .unwrap_or(0);
            format!("SUB{}{}", in0, out)
        }

        /// "Never need a cast into a SUBPIECE" (typeop.cc:2136-2140).
        // Ghidra: typeop.cc:2136 TypeOpSubpiece::getInputCast
        fn get_input_cast(
            &self,
            _op: &crate::op::PcodeOpRef,
            _slot: usize,
            _fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            None
        }

        /// The SUBPIECE output token (typeop.cc:2142-2159): a size-matching
        /// `findTruncation` field of the input-0 HIGH read-facing type at
        /// the SUBPIECE's composite byte offset (artificial slot 1), else
        /// the output's DEF-facing high type when not UNKNOWN, else the
        /// factory INT base.
        // Ghidra: typeop.cc:2142 TypeOpSubpiece::getOutputToken
        fn get_output_token_in_fd(
            &self,
            op: &crate::op::PcodeOpRef,
            fd: &crate::funcdata::Funcdata,
        ) -> Option<Arc<Datatype>> {
            subpiece_output_token_in_fd(op, fd, &self.type_factory)
        }
    }
);

impl TypeOpPiece {
    /// Compute the byte offset into an assumed composite data-type for an
    /// input to the given `CPUI_PIECE`.
    ///
    /// Faithful to `TypeOpPiece::computeByteOffsetForComposite`
    /// (typeop.cc:2104-2114). If the output varnode is a composite data-type,
    /// an input to PIECE represents a range of bytes starting at a particular
    /// offset within the data-type. The offset depends on the endianness of
    /// the output and the particular input slot:
    ///   - big-endian:    slot 0 -> 0,           slot 1 -> inVn0.size
    ///   - little-endian: slot 0 -> in(1).size,   slot 1 -> 0
    // Ghidra: typeop.cc:2104 TypeOpPiece::computeByteOffsetForComposite
    pub fn compute_byte_offset_for_composite(op: &PcodeOp, slot: i32) -> i64 {
        let in_vn0 = match op.get_in(0) {
            Some(v) => v.clone(),
            None => return 0,
        };
        let vn0 = in_vn0.read().unwrap();
        let big_endian = vn0.get_space().is_big_endian();
        if big_endian {
            if slot == 0 {
                0
            } else {
                vn0.get_size() as i64
            }
        } else {
            let in1_size = op
                .get_in(1)
                .map(|v| v.read().unwrap().get_size())
                .unwrap_or(0) as i64;
            if slot == 0 {
                in1_size
            } else {
                0
            }
        }
    }
}

impl TypeOpSubpiece {
    /// Compute the byte offset into an assumed composite data-type produced by
    /// the given `CPUI_SUBPIECE`.
    ///
    /// Faithful to `TypeOpSubpiece::computeByteOffsetForComposite`
    /// (typeop.cc:2195-2207). If the input varnode is a composite data-type,
    /// the extracted result of the SUBPIECE represents a range of bytes
    /// starting at a particular offset within the data-type. The offset
    /// depends on the endianness of the input:
    ///   - big-endian:    byteOff = vn.size - outSize - lsb
    ///   - little-endian: byteOff = lsb
    /// where `lsb` is the truncation shift constant held in input slot 1.
    // Ghidra: typeop.cc:2195 TypeOpSubpiece::computeByteOffsetForComposite
    pub fn compute_byte_offset_for_composite(op: &PcodeOp) -> i64 {
        let out_size = op
            .get_out()
            .map(|v| v.read().unwrap().get_size())
            .unwrap_or(0) as i64;
        let lsb = op
            .get_in(1)
            .map(|v| v.read().unwrap().get_offset() as i64)
            .unwrap_or(0);
        let vn = match op.get_in(0) {
            Some(v) => v.clone(),
            None => return 0,
        };
        let v = vn.read().unwrap();
        let vn_size = v.get_size() as i64;
        if v.get_space().is_big_endian() {
            vn_size - out_size - lsb
        } else {
            lsb
        }
    }
}

// Ghidra: typeop.cc:2558 TypeOpPopcount::TypeOpPopcount — TypeOpFunc("POPCOUNT",TYPE_INT,TYPE_UNKNOWN)
functional_unary_op!(
    TypeOpPopcount, CPUI_POPCOUNT, "POPCOUNT", 0, "popcount", Int, Unknown
);
// Ghidra: typeop.cc:2565 TypeOpLzcount::TypeOpLzcount — TypeOpFunc("LZCOUNT",TYPE_INT,TYPE_UNKNOWN)
functional_unary_op!(
    TypeOpLzcount, CPUI_LZCOUNT, "LZCOUNT", 0, "lzcount", Int, Unknown
);

// Control Flow Operations
/// Ghidra's `TypeOpBranch` takes the Architecture TypeFactory in its
/// constructor (typeop.cc:583) and never overrides `getOutputLocal`/
/// `getInputLocal`, so both fall through to the TypeOp base defaults
/// (`getBase(size,TYPE_UNKNOWN)`, typeop.cc:261-275).
pub struct TypeOpBranch {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpBranch {
    // Ghidra: typeop.cc:583 TypeOpBranch::TypeOpBranch
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpBranch {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_BRANCH
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "BRANCH"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); BRANCH has
    //   no get*Local override in Ghidra (typeop.hh:253-263), so the trait
    //   defaults below resolve through this factory.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:590 TypeOpBranch::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("goto {}", in0)
    }
}

/// `CBRANCH` type operator. Ghidra's `TypeOpCbranch` takes the Architecture
/// TypeFactory in its constructor (typeop.cc:602); `getInputLocal`
/// (typeop.cc:609-619) reads slot 1 as the BOOL base and slot 0 as a
/// pointer to the code type worded by the input's address space.
pub struct TypeOpCbranch {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpCbranch {
    // Ghidra: typeop.cc:602 TypeOpCbranch::TypeOpCbranch
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpCbranch {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CBRANCH
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CBRANCH"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
    //   getInputLocal override below resolves through it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:621 TypeOpCbranch::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("if ({}) goto {}", in1, in0)
    }

    /// The branch local input types (typeop.cc:609-619): slot 1 is the BOOL
    /// base of the condition's size; slot 0 is a pointer to the code type,
    /// sized by the input and worded by the input's address space
    /// ("First parameter is code pointer").
    // Ghidra: typeop.cc:609 TypeOpCbranch::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        if slot == 1 {
            // cc:614-615: Second param is bool.
            let size = op.get_in(1)?.read().unwrap().get_size();
            return type_factory.read().unwrap().get_base(size, TypeMetatype::Bool);
        }
        // cc:616-618: td = tlst->getTypeCode(); pointer worded by the
        // input's space word size.
        let in0 = op.get_in(0)?;
        let (size, word_size) = {
            let vn = in0.read().unwrap();
            (vn.get_size(), vn.get_space().word_size())
        };
        let code = type_factory
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_type_code();
        Some(
            type_factory
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_type_pointer(size, code, word_size),
        )
    }
}

/// Ghidra's `TypeOpBranchind` takes the Architecture TypeFactory in its
/// constructor (typeop.cc:646) and never overrides `getOutputLocal`/
/// `getInputLocal` (base defaults, typeop.cc:261-275).
pub struct TypeOpBranchind {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpBranchind {
    // Ghidra: typeop.cc:646 TypeOpBranchind::TypeOpBranchind
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpBranchind {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_BRANCHIND
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "BRANCHIND"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242);
    //   BRANCHIND has no get*Local override in Ghidra.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:653 TypeOpBranchind::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("goto [{}]", in0)
    }
}

pub struct TypeOpCall {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpCall {
    // Ghidra: typeop.cc:660 TypeOpCall::TypeOpCall
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpCall {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALL
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CALL"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags (the `opflags` field assigned in
    // the TypeOpCall constructor, typeop.cc:663:
    // `opflags = (PcodeOp::special|PcodeOp::call|PcodeOp::has_callspec|
    //              PcodeOp::coderef|PcodeOp::nocollapse)`).
    // Bit values mirror op.hh:73-104 (special=0x20000, call=0x4,
    // has_callspec=0x20000000, coderef=0x800, nocollapse=0x10; total
    // 0x20020814), identical to crate::op::opcode_flags(CPUI_CALL).
    fn get_flags(&self) -> u32 {
        crate::op::pcodeop_flags::SPECIAL
            | crate::op::pcodeop_flags::CALL
            | crate::op::pcodeop_flags::HAS_CALLSPEC
            | crate::op::pcodeop_flags::CODEREF
            | crate::op::pcodeop_flags::NOCOLLAPSE
    }
    // Ghidra: typeop.cc:667 TypeOpCall::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("call {}", in0)
    }

    // Ghidra: typeop.hh:319 TypeOpCall::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_call(op);
    }

    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242). TypeOpCall
    //   holds the constructor-injected Architecture TypeFactory, so the
    //   trait-local defaults (get_output_local) and the fallback below share
    //   exactly the factory Ghidra's TypeOp base would have used.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }

    // Ghidra: typeop.cc:687 TypeOpCall::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        // Shared base lookup: `TypeOp::getInputLocal` (typeop.cc:271-275) is
        // `tlst->getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN)` — always the
        // same Architecture TypeFactory the constructor received.
        let input_size = op.get_in(slot)?.read().unwrap().get_size();
        let fallback = || base_local_type(&self.type_factory, input_size, TypeMetatype::Unknown);

        // Ghidra gate: `(slot==0)||(vn->getSpace()->getType()!=IPTR_FSPEC)`
        // (typeop.cc:695). Rudra has no dedicated fspace yet: the D0
        // representation of an IPTR_FSPEC annotation is an Iop-space
        // ANNOTATION varnode carrying the typed callspec Weak
        // (Funcdata::new_varnode_call_specs / Funcdata::get_call_specs_of_op,
        // TYPEOP-FSPEC-SPACE-0001).
        if slot == 0 {
            return fallback();
        }
        let callspec = {
            let input0 = op.get_in(0)?.read().unwrap();
            if input0.get_space() != AddressSpace::Iop || !input0.is_annotation() {
                None
            } else {
                // Ghidra: FuncCallSpecs::getFspecFromConst(vn->getAddr())
                // (fspec.hh:1733) — typed Weak upgrade in Rudra.
                input0.get_call_spec()
            }
        };
        let Some(callspec) = callspec else {
            return fallback();
        };

        // Get types of call input parameters.
        // It's false to assume that the parameter symbol corresponds to the
        // varnode in the same slot, but this is easiest until we get giant
        // sized parameters working properly (typeop.cc:700-702).
        let selected_type = {
            let callspec = callspec.read().unwrap();
            callspec
                .prototype
                .get_param(slot - 1)
                .and_then(|parameter| {
                    if parameter.is_type_locked() {
                        let ct = &parameter.data_type;
                        // parameter may not match varnode (typeop.cc:707)
                        if ct.get_metatype() != TypeMetatype::Void && ct.get_size() <= input_size
                        {
                            return Some(ct.clone());
                        }
                    } else if parameter.is_this_pointer() {
                        // Known "this" pointer is effectively typelocked even
                        // if the prototype as a whole isn't (typeop.cc:710-714)
                        let ct = &parameter.data_type;
                        if let Datatype::Pointer(pointer) = ct.as_ref() {
                            if pointer.ptr_to.get_metatype() == TypeMetatype::Struct {
                                return Some(ct.clone());
                            }
                        }
                    }
                    None
                })
        };
        selected_type.or_else(fallback)
    }
}

pub struct TypeOpCallind {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpCallind {
    // Ghidra: typeop.cc:738 TypeOpCallind::TypeOpCallind
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }

    /// Shared body of `TypeOpCallind::getInputLocal` (typeop.cc:745-774).
    /// `fc` is the resolved call specification (`op->getParent()->
    /// getFuncdata()->getCallSpecs(op)`, typeop.cc:757); `None` mirrors
    /// Ghidra's `fc == 0` fall-through to the base lookup.
    // Ghidra: typeop.cc:745 TypeOpCallind::getInputLocal
    fn callind_input_local(
        &self,
        op: &PcodeOp,
        slot: usize,
        fc: Option<Arc<RwLock<crate::fspec::FuncCallSpecs>>>,
    ) -> Option<Arc<Datatype>> {
        // Shared base lookup: `TypeOp::getInputLocal` (typeop.cc:271-275) is
        // `tlst->getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN)` — always
        // the Architecture TypeFactory the constructor received.
        let input_size = op.get_in(slot)?.read().unwrap().get_size();
        let fallback =
            || base_local_type(&self.type_factory, input_size, TypeMetatype::Unknown);

        if slot == 0 {
            // First parameter is code pointer (typeop.cc:752-756):
            // td = tlst->getTypeCode();
            // spc = op->getAddr().getSpace();
            // return tlst->getTypePointer(in0.size, td, spc->getWordSize());
            // getTypeCode/getTypePointer mutate the factory cache, so a write
            // guard replaces the read guard for this branch. A spaceless op
            // address (Rudra legacy Address) has no wordsize to read; the
            // locked oracles run code spaces with wordsize 1, so 1 is the
            // faithful default.
            let mut factory = self.type_factory.write().unwrap();
            let code_type = factory.get_type_code();
            let in0_size = op.get_in(0)?.read().unwrap().get_size();
            let wordsize = op
                .get_addr()
                .get_space()
                .map(|spc| spc.get_word_size() as usize)
                .unwrap_or(1);
            return Some(factory.get_type_pointer(in0_size, code_type, wordsize));
        }

        let selected_type = {
            let Some(fc) = fc else {
                // fc == 0 -> TypeOp::getInputLocal(op,slot) (typeop.cc:758-759)
                return fallback();
            };
            let callspec = fc.read().unwrap();
            callspec
                .prototype
                .get_param(slot - 1)
                .and_then(|parameter| {
                    if parameter.is_type_locked() {
                        let ct = &parameter.data_type;
                        // CALLIND asymmetry: only the VOID guard — there is
                        // no `ct->getSize() <= op->getIn(slot)->getSize()`
                        // check here, unlike TypeOpCall (typeop.cc:764 vs
                        // CALL's :707).
                        if ct.get_metatype() != TypeMetatype::Void {
                            return Some(ct.clone());
                        }
                    } else if parameter.is_this_pointer() {
                        // this-pointer branch identical to CALL
                        // (typeop.cc:767-771 vs :710-714)
                        let ct = &parameter.data_type;
                        if let Datatype::Pointer(pointer) = ct.as_ref() {
                            if pointer.ptr_to.get_metatype() == TypeMetatype::Struct {
                                return Some(ct.clone());
                            }
                        }
                    }
                    None
                })
        };
        selected_type.or_else(fallback)
    }
}

impl TypeOp for TypeOpCallind {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALLIND
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CALLIND"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags (the `opflags` field assigned in
    // the TypeOpCallind constructor, typeop.cc:741:
    // `opflags = PcodeOp::special|PcodeOp::call|PcodeOp::has_callspec|
    //              PcodeOp::nocollapse`), mirroring
    // crate::op::opcode_flags(CPUI_CALLIND).
    fn get_flags(&self) -> u32 {
        crate::op::pcodeop_flags::SPECIAL
            | crate::op::pcodeop_flags::CALL
            | crate::op::pcodeop_flags::HAS_CALLSPEC
            | crate::op::pcodeop_flags::NOCOLLAPSE
    }
    // Ghidra: typeop.cc:791 TypeOpCallind::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("call [{}]", in0)
    }

    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242).
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }

    // Ghidra: typeop.cc:745 TypeOpCallind::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        // Slot 0 (code pointer) needs no Funcdata. For slot >= 1 Ghidra
        // resolves the callspec through op->getParent()->getFuncdata()->
        // getCallSpecs(op); a bare &PcodeOp carries no such chain in Rudra,
        // so the fd-less form observes the fc==0 default path. Use
        // get_input_local_in_fd for the full callspec resolution.
        self.callind_input_local(op, slot, None)
    }

    // Ghidra: typeop.cc:745 TypeOpCallind::getInputLocal (callspec branch at :757)
    fn get_input_local_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        // fc = op->getParent()->getFuncdata()->getCallSpecs(op)
        // (typeop.cc:757). Resolved before taking the op read guard below:
        // get_call_specs_of_op snapshots input(0) through its own op lock,
        // and recursive std::sync::RwLock reads are not guaranteed when a
        // writer is waiting.
        let fc = fd.get_call_specs_of_op(op);
        let op = op.0.read().unwrap();
        self.callind_input_local(&op, slot, fc)
    }

    // Ghidra: typeop.hh:329 TypeOpCallind::push -> lng->opCallind(op)
    //
    // Was previously mis-routed: CALLIND fell through the default `push`
    // (and the PcodeOp::push wrapper sent it to `op_call`). Ghidra's
    // `TypeOpCallind::push` (typeop.hh:329) calls `PrintLanguage::opCallind`,
    // overridden by `PrintC::op_callind` (printc.cc). We recover `PrintC` via
    // `as_printc_mut` and call the inherent `op_callind`; for any non-PrintC
    // language we keep the prior `op_call` behaviour as a safe fallback.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_callind(op),
            None => lng.op_call(op),
        }
    }
}

pub struct TypeOpReturn;
impl TypeOp for TypeOpReturn {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_RETURN
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "RETURN"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:882 TypeOpReturn::printRaw
    fn print_raw(&self, _op: &PcodeOp) -> String {
        "return".to_string()
    }

    // Ghidra: typeop.hh:350 TypeOpReturn::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_return(op);
    }

    // Ghidra: typeop.cc:901 TypeOpReturn::getInputLocal
    /// A RETURN input (slot >= 1) reads its local type from the enclosing
    /// function's return-value parameter: `fp->getOutputType()`
    /// (typeop.cc:918), kept only when it is not void and its size equals
    /// the input's; every other case (slot 0, missing Funcdata) observes
    /// the base default `getBase(size, TYPE_UNKNOWN)` (typeop.cc:271-275).
    /// This is the seed that lets a DWARF-locked enum return type
    /// (`CURLcode`, `main_init`'s `return CURLE_OK;`) reach the returned
    /// constant through ActionInferTypes' buildLocaltypes/writeBack.
    fn get_input_local_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        let input_size = op.0.read().unwrap().get_in(slot)?.read().unwrap().get_size();
        if slot == 0 {
            // typeop.cc:907-908: slot 0 is the indeterminate marker input —
            // base default getBase(size, TYPE_UNKNOWN) (typeop.cc:271-275).
            return base_local_type(
                &TypeFactory::shared_default(),
                input_size,
                TypeMetatype::Unknown,
            );
        }
        // typeop.cc:918: ct = fp->getOutputType(); — the current output
        // parameter's type (void when cleared/never set).
        let ct = fd.funcp.return_type.clone();
        if matches!(ct.as_ref(), Datatype::Void(_)) || ct.get_size() != input_size {
            // typeop.cc:919-920: void or size mismatch -> base default.
            return base_local_type(
                &TypeFactory::shared_default(),
                input_size,
                TypeMetatype::Unknown,
            );
        }
        Some(ct)
    }
}

pub struct TypeOpPtradd {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpPtradd {
    // Ghidra: typeop.cc:2224 TypeOpPtradd::TypeOpPtradd
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpPtradd {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_PTRADD
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
    //   getInputLocal/getOutputLocal INT bases and the base getInputCast
    //   fallback (cc:2265) resolve through it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "PTRADD"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2283 TypeOpPtradd::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in2 = op
            .get_in(2)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = ptradd({}, {}, {})", out, in0, in1, in2)
    }

    // Ghidra: typeop.cc:2232 TypeOpPtradd::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let size = op.get_in(slot)?.read().unwrap().get_size();
        base_local_type(&self.type_factory, size, TypeMetatype::Int)
    }

    // Ghidra: typeop.cc:2238 TypeOpPtradd::getOutputLocal
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(&self.type_factory, size, TypeMetatype::Int)
    }

    // Ghidra: typeop.cc:2244 TypeOpPtradd::getOutputToken
    /// The PTRADD output token is the input-0 HIGH read-facing type ("cast
    /// to the input data-type"). The fd-carrying dispatch form is the single
    /// implementation: cc:2247's `getHighTypeReadFacing(op)` consults the
    /// Funcdata union map keyed on slot 0 (varnode.cc:665-672), so a
    /// resolving (union) high type resolves to its field before becoming
    /// the token (UNIONRESOLVE-PKG-B-0001).
    fn get_output_token_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        let in0 = op.0.read().unwrap().get_in(0)?.clone();
        crate::unionresolve::vn_high_type_read_facing(fd, &in0, op, 0)
    }

    /// The PTRADD slot-0 input cast (typeop.cc:2250-2266): the operation
    /// expects the VARNODE's own read-facing type — not the (possibly
    /// different) HIGH read-facing type; a non-pointer on either side
    /// returns the varnode type, and equal `alignSize` on the one-level-down
    /// pointer bases cancels the cast. Other slots take the base arm
    /// (cc:2265). The cc:2255/2256 read-facing consults are fd-aware
    /// (UNIONRESOLVE-PKG-B-0001); the production SetCasts dispatch reaches
    /// this same shape through `ActionSetCasts::ptr_input_reqtype`
    /// (coreaction.rs).
    // Ghidra: typeop.cc:2250 TypeOpPtradd::getInputCast
    fn get_input_cast(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        if slot == 0 {
            return ptradd_input_cast(op, slot, fd);
        }
        // cc:2265: TypeOp::getInputCast — the base arm.
        base_input_cast_arm(self, op, slot, fd)
    }

    // Ghidra: typeop.cc:2268 TypeOpPtradd::propagateType
    fn propagate_type(
        &self, alt_type: &Arc<Datatype>, op: &PcodeOp, inslot: i32, outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot == 2 || outslot == 2 || (inslot != -1 && outslot != -1) || alt_type.get_metatype() != TypeMetatype::Pointer { return None; }
        if inslot == -1 { None } else { TypeOpIntAdd::propagate_add_in2out(alt_type, &self.type_factory, op, inslot) }
    }
}

pub struct TypeOpPtrsub {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpPtrsub {
    // Ghidra: typeop.cc:2296 TypeOpPtrsub::TypeOpPtrsub
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpPtrsub {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_PTRSUB
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
    //   getInputLocal/getOutputLocal INT bases resolve through it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "PTRSUB"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2380 TypeOpPtrsub::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} + {}", out, in0, in1)
    }

    // Ghidra: typeop.hh:837 TypeOpPtrsub::push -> lng->opPtrsub(op)
    //
    // Was previously mis-routed: PTRSUB inherited the default `push`, which
    // dispatched to `op_binary`. Ghidra's `TypeOpPtrsub::push` (typeop.hh:837)
    // calls `PrintLanguage::opPtrsub`, overridden by `PrintC::op_ptrsub`
    // (printc.cc). We recover `PrintC` via `as_printc_mut` and call the
    // inherent `op_ptrsub`; non-PrintC languages keep the generic binary
    // fallback so existing behaviour is unchanged.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_ptrsub(op),
            None => lng.op_binary(op),
        }
    }

    // Ghidra: typeop.cc:2308-2312 TypeOpPtrsub::getOutputLocal
    // This requests getBase(output-size, TYPE_INT), never the input struct
    // pointer. The covered 8-byte case is canonical int8; oversized getBase
    // conversion remains TYPEFACTORY-LOCALTYPE-CACHE-0001. Field/gap pointer
    // semantics belong exclusively to get_output_token below
    // (typeop.cc:2349-2364).
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(&self.type_factory, size, TypeMetatype::Int)
    }

    // Ghidra: typeop.cc:2314 TypeOpPtrsub::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let size = op.get_in(slot)?.read().unwrap().get_size();
        base_local_type(&self.type_factory, size, TypeMetatype::Int)
    }

    // TypeOpPtrsub::getInputCast (typeop.cc:2320-2347) has no trait-side
    // duplicate anymore: the production SetCasts dispatch computes it via
    // `ActionSetCasts::ptr_input_reqtype` (coreaction.rs), whose cc:2325/2326
    // read-facing consults are fd-aware (UNIONRESOLVE-PKG-B-0001 merged the
    // former degenerate trait copy into that single implementation).

    // Ghidra: typeop.cc:2349 TypeOpPtrsub::getOutputToken
    /// The fd-carrying dispatch form is the single implementation: the
    /// cc:2352 `op->getIn(0)->getHighTypeReadFacing(op)` base consult goes
    /// through the fd-aware twin (Funcdata union map, slot-0 key,
    /// varnode.cc:665-672), so a union-ptr base resolves to its field
    /// pointer before `downChain` runs (UNIONRESOLVE-PKG-B-0001).
    fn get_output_token_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        let in0 = op.0.read().unwrap().get_in(0)?.clone();
        let high = match crate::unionresolve::vn_high_type_read_facing(fd, &in0, op, 0) {
            Some(high) => high,
            // cc:2363 delegates non-pointer inputs to TypeOp::getOutputToken,
            // whose cc:282-286 implementation returns outputTypeLocal().
            None => {
                let op_rg = op.0.read().unwrap();
                return self.get_output_local(&op_rg);
            }
        };
        let pointer = match high.as_ref() {
            Datatype::Pointer(p) => p,
            _ => {
                let op_rg = op.0.read().unwrap();
                return self.get_output_local(&op_rg);
            }
        };
        // cc:2354 assigns the unsigned addressToByte result to the signed
        // in/out offset consumed by downChain.  The residual value written
        // back by that one virtual call is the value tested at cc:2358.
        let raw = op.0.read().unwrap().get_in(1)?.read().unwrap().get_offset();
        let mut type_offset =
            crate::space::AddrSpace::address_to_byte(raw, pointer.wordsize as u32) as i64;
        let mut parent = None;
        let mut parent_off = 0;
        let mut factory = self.type_factory.write().unwrap();
        let rettype = factory.down_chain_virtual(
            &high,
            &mut type_offset,
            &mut parent,
            &mut parent_off,
            false,
        );
        if type_offset == 0 {
            if let Some(rettype) = rettype { return Some(rettype); }
        }
        let pointee = factory.get_base(1, TypeMetatype::Unknown)?;
        Some(factory.get_type_pointer(
            op.0.read().unwrap().get_out()?.read().unwrap().get_size(), pointee, pointer.wordsize,
        ))
    }

    // Ghidra: typeop.cc:2366 TypeOpPtrsub::propagateType
    fn propagate_type(
        &self, alt_type: &Arc<Datatype>, op: &PcodeOp, inslot: i32, outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot != -1 && outslot != -1 || alt_type.get_metatype() != TypeMetatype::Pointer { return None; }
        if inslot == -1 { None } else { TypeOpIntAdd::propagate_add_in2out(alt_type, &self.type_factory, op, inslot) }
    }
}

pub struct TypeOpMulti;
impl TypeOp for TypeOpMulti {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_MULTIEQUAL
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "MULTIEQUAL"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:1967 TypeOpMulti::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = phi({})", out, inputs.join(", "))
    }

    // Ghidra: typeop.hh:758 TypeOpMulti::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_multiequal(op);
    }

    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal (base; Multi does not override)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        // Phi node output matches inputs. Pick first non-none.
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            if let Some(dt) = &v.read().unwrap().v_type {
                return Some(dt.clone());
            }
            i += 1;
        }
        None
    }

    // Ghidra: typeop.hh:152 TypeOp::getInputLocal (base; Multi does not override)
    fn get_input_local(&self, op: &PcodeOp, _slot: usize) -> Option<Arc<Datatype>> {
        // Inputs should match the output type
        op.get_out().and_then(|v| v.read().unwrap().v_type.clone())
    }

    /// MULTIEQUAL is a transparent phi node: a type propagates across it in
    /// either direction (input<->output). One slot must be the output (-1).
    /// Spacebase inputs are rewrapped as a pointer to an unknown base type.
    /// Faithful to `TypeOpMulti::propagateType` (typeop.cc:1951-1965).
    // Ghidra: typeop.cc:1951 TypeOpMulti::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot != -1 && outslot != -1 {
            return None; // Must propagate input <-> output
        }
        // coreaction.cc:5080: invn = (inslot==-1) ? op->getOut() : op->getIn(inslot)
        // — the SPACEBASE test is on the edge's SOURCE varnode, which is the
        // op output when propagating output->input.
        let src_vn = if inslot == -1 {
            op.get_out().cloned()
        } else {
            op.get_in(inslot as usize).cloned()
        };
        if let Some(vn) = src_vn {
            if vn.read().unwrap().is_spacebase() {
                // typeop.cc:1957-1960: getTypePointer(alttype->getSize(),
                    // getBase(1,TYPE_UNKNOWN), defaultDataSpace->getWordSize())
                    // — the POINTER SIZE is the alttype's size, the pointee is
                    // unknown1 (SB-ORD186-PTRARITH-0001: propagate_to_pointer
                    // sized the pointer from the unknown1 base (=1), not from
                    // alttype). Ram wordsize is 1.
                    return Some(std::sync::Arc::new(Datatype::Pointer(
                        crate::type_system::datatype::TypePointer::new(
                            alt_type.get_size(),
                            std::sync::Arc::new(Datatype::Base(
                                crate::type_system::TypeBase::new(
                                    "unknown".to_string(),
                                    1,
                                    TypeMetatype::Unknown,
                                ),
                            )),
                            1,
                        ),
                    )));
            }
        }
        Some(alt_type.clone())
    }
}

/// `INDIRECT` type operator. Ghidra's `TypeOpIndirect` takes the
/// Architecture TypeFactory in its constructor (typeop.cc:1985);
/// `getInputLocal` (typeop.cc:1992-2003) reads slot 0 through the base
/// default and slot 1 as a pointer to the code type worded by the space of
/// the op referenced through the iop constant.
pub struct TypeOpIndirect {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpIndirect {
    // Ghidra: typeop.cc:1985 TypeOpIndirect::TypeOpIndirect
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpIndirect {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INDIRECT
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "INDIRECT"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
    //   getInputLocal override below resolves through it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:2022 TypeOpIndirect::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {}({})", out, in0, in1)
    }

    // Ghidra: typeop.hh:769 TypeOpIndirect::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_indirect(op);
    }

    // Ghidra: typeop.hh:149 TypeOp::getOutputLocal (base; Indirect does not
    // override) — `tlst->getBase(out->getSize(),TYPE_UNKNOWN)`
    // (typeop.cc:261-268).
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Unknown)
    }

    /// The INDIRECT local input types (typeop.cc:1992-2003): slot 0 through
    /// the `TypeOp::getInputLocal` base default; slot 1 is a pointer to the
    /// code type, sized by input-0 and worded by the address space of the op
    /// referenced through the iop constant (cc:2000-2002 "Second parameter
    /// is code pointer"). The fd-less form words the pointer by this op's
    /// own code space — the referenced op lives in the same function body,
    /// so both address spaces are the same one; the fd-carrying form below
    /// decodes the referenced op exactly.
    // Ghidra: typeop.cc:1992 TypeOpIndirect::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        if slot == 0 {
            // cc:1997-1998: TypeOp::getInputLocal base default.
            let size = op.get_in(0)?.read().unwrap().get_size();
            return type_factory.read().unwrap().get_base(size, TypeMetatype::Unknown);
        }
        // cc:1999-2002: code pointer sized by in(0), worded by the
        // referenced op's space word size (this op's code space).
        let in0 = op.get_in(0)?;
        let size = in0.read().unwrap().get_size();
        let word_size = op
            .get_addr()
            .get_space()
            .map(|space| space.get_word_size() as usize)
            .unwrap_or(1);
        let code = type_factory
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_type_code();
        Some(
            type_factory
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_type_pointer(size, code, word_size),
        )
    }

    /// fd-carrying form of the slot-1 arm: decodes the referenced op via
    /// `Funcdata::get_op_from_const` (the `PcodeOp::getOpFromConst` twin)
    /// and words the code pointer by that op's own address space, exactly
    /// as cc:2000-2002 does; every other path delegates to the fd-less
    /// form above.
    // Ghidra: typeop.cc:1992 TypeOpIndirect::getInputLocal (iop const arm)
    fn get_input_local_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        if slot != 1 {
            let op = op.0.read().unwrap();
            return self.get_input_local(&op, slot);
        }
        let (in0, iop_vn) = {
            let op = op.0.read().unwrap();
            (op.get_in(0)?.clone(), op.get_in(1)?.clone())
        };
        let type_factory = self.local_type_factory()?;
        let size = in0.read().unwrap().get_size();
        let word_size = fd
            .get_op_from_const(&iop_vn)
            .and_then(|iop| {
                iop.0
                    .read()
                    .unwrap()
                    .get_addr()
                    .get_space()
                    .map(|space| space.get_word_size() as usize)
            })
            .unwrap_or(1);
        let code = type_factory
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_type_code();
        Some(
            type_factory
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_type_pointer(size, code, word_size),
        )
    }

    /// INDIRECT is transparent (like COPY/MULTIEQUAL) but never propagates
    /// along slot 1 (the code-pointer input) and does not propagate for an
    /// indirect creation. Otherwise a type flows input<->output, with a
    /// spacebase rewrapped as a pointer to an unknown base type.
    /// Faithful to `TypeOpIndirect::propagateType` (typeop.cc:2005-2020).
    // Ghidra: typeop.cc:2005 TypeOpIndirect::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        if inslot == 1 || outslot == 1 {
            return None; // Never propagate along the code-pointer edge
        }
        if inslot != -1 && outslot != -1 {
            return None; // Must propagate input <-> output
        }
        let src_slot = if inslot == -1 { outslot } else { inslot };
        if src_slot >= 0 {
            if let Some(vn) = op.get_in(src_slot as usize) {
                if vn.read().unwrap().is_spacebase() {
                    return Some(propagate_to_pointer(&Arc::new(Datatype::Base(
                        crate::type_system::TypeBase::new(
                            "unknown".to_string(),
                            1,
                            TypeMetatype::Unknown,
                        ),
                    ))));
                }
            }
        }
        Some(alt_type.clone())
    }
}

/// Ghidra's `TypeOpSegment` takes the Architecture TypeFactory in its
/// constructor (typeop.cc:2390). Its `getInputLocal`/`getOutputLocal`
/// overrides are commented out in Ghidra (typeop.hh:852-853), so both use
/// the TypeOp base defaults (`getBase(size,TYPE_UNKNOWN)`,
/// typeop.cc:261-275).
pub struct TypeOpSegment {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpSegment {
    // Ghidra: typeop.cc:2390 TypeOpSegment::TypeOpSegment
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpSegment {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_SEGMENTOP
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "SEGMENTOP"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242);
    //   SEGMENTOP has no live get*Local override in Ghidra
    //   (typeop.hh:852-853 commented out).
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:2397 TypeOpSegment::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = segment({})", out, inputs.join(", "))
    }

    // Ghidra: typeop.hh:858 TypeOpSegment::push -> lng->opSegmentOp(op)
    //
    // Was previously unrouted: SEGMENTOP inherited the default `push`, which
    // dispatched to `op_binary` (a no-op-ish fallback). Ghidra's
    // `TypeOpSegment::push` (typeop.hh:858) calls `PrintLanguage::opSegmentOp`,
    // overridden by `PrintC::op_segment` (printc.cc). We recover `PrintC` via
    // `as_printc_mut` and call the inherent `op_segment`; non-PrintC languages
    // fall back to `op_binary` to preserve prior behaviour.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_segment(op),
            None => lng.op_binary(op),
        }
    }

    /// The SEGMENTOP output token (typeop.cc:2414-2418): input-2's HIGH
    /// read-facing type ("Assume type of ptr portion"). The fd-aware
    /// consult is keyed on slot 2.
    // Ghidra: typeop.cc:2414 TypeOpSegment::getOutputToken
    fn get_output_token_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        let in2 = {
            let op = op.0.read().unwrap();
            op.get_in(2)?.clone()
        };
        crate::unionresolve::vn_high_type_read_facing(fd, &in2, op, 2)
            .or_else(|| in2.read().unwrap().v_type.clone())
    }

    /// "Never need a cast for inputs" (typeop.cc:2420-2424).
    // Ghidra: typeop.cc:2420 TypeOpSegment::getInputCast
    fn get_input_cast(
        &self,
        _op: &crate::op::PcodeOpRef,
        _slot: usize,
        _fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        None
    }
}

pub struct TypeOpCpoolref;
impl TypeOp for TypeOpCpoolref {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CPOOLREF
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CPOOLREF"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2471 TypeOpCpoolref::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = cpool({})", out, inputs.join(", "))
    }

    // Ghidra: typeop.hh:870 TypeOpCpoolref::push -> lng->opCpoolRefOp(op)
    //
    // Was previously unrouted: CPOOLREF inherited the default `push`, which
    // dispatched to `op_binary`. Ghidra's `TypeOpCpoolref::push`
    // (typeop.hh:870) calls `PrintLanguage::opCpoolRefOp`, overridden by
    // `PrintC::op_cpoolref` (printc.cc). We recover `PrintC` via
    // `as_printc_mut` and call the inherent `op_cpoolref`; non-PrintC
    // languages fall back to `op_binary` to preserve prior behaviour.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_cpoolref(op),
            None => lng.op_binary(op),
        }
    }
}

pub struct TypeOpNew;
impl TypeOp for TypeOpNew {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_NEW
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "NEW"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:2511 TypeOpNew::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let mut inputs = Vec::new();
        let mut i = 0;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        format!("{} = new({})", out, inputs.join(", "))
    }

    // Ghidra: typeop.hh:881 TypeOpNew::push -> lng->opNewOp(op)
    //
    // Was previously unrouted: NEW inherited the default `push`, which
    // dispatched to `op_binary`. Ghidra's `TypeOpNew::push` (typeop.hh:881)
    // calls `PrintLanguage::opNewOp`, overridden by `PrintC::op_new`
    // (printc.cc). We recover `PrintC` via `as_printc_mut` and call the
    // inherent `op_new`; non-PrintC languages fall back to `op_binary` to
    // preserve prior behaviour.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_new(op),
            None => lng.op_binary(op),
        }
    }
}

/// `CALLOTHER` type operator. Ghidra's `TypeOpCallother` takes the
/// Architecture TypeFactory in its constructor (typeop.cc:811);
/// `getInputLocal` (typeop.cc:855-863) consults the user-op descriptor
/// registered for the CALLOTHER index held in input slot 0 and falls back
/// to the `TypeOp::getInputLocal` base default.
pub struct TypeOpCallother {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpCallother {
    // Ghidra: typeop.cc:811 TypeOpCallother::TypeOpCallother
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpCallother {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CALLOTHER
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "CALLOTHER"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
    //   getInputLocal fallback below resolves through it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:818 TypeOpCallother::printRaw
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        // Ghidra emits the operator name (looked up via getOperatorName, see
        // typeop.cc:837), then the inputs after slot 0 (which holds the
        // CALLOTHER index). We mirror that here, calling get_operator_name.
        let name = self.get_operator_name(op);
        let mut inputs = Vec::new();
        // Skip slot 0 (the CALLOTHER index constant); print remaining inputs.
        let mut i = 1;
        while let Some(v) = op.get_in(i) {
            inputs.push(format!("{}", v.read().unwrap()));
            i += 1;
        }
        if inputs.is_empty() {
            format!("{} = {}", out, name)
        } else {
            format!("{} = {}({})", out, name, inputs.join(", "))
        }
    }

    // Ghidra: typeop.hh:339 TypeOpCallother::push -> lng->opCallother(op)
    //
    // Was previously unrouted: CALLOTHER inherited the default `push`, which
    // dispatched to `op_binary`. Ghidra's `TypeOpCallother::push`
    // (typeop.hh:339) calls `PrintLanguage::opCallother`, overridden by
    // `PrintC::op_callother` (printc.cc). We recover `PrintC` via
    // `as_printc_mut` and call the inherent `op_callother`; non-PrintC
    // languages fall back to `op_binary` to preserve prior behaviour.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_callother(op),
            None => lng.op_binary(op),
        }
    }

    /// The CALLOTHER operator name (typeop.cc:837-853) via the inherent
    /// twin below.
    // Ghidra: typeop.cc:837 TypeOpCallother::getOperatorName
    fn get_operator_name(&self, op: &PcodeOp) -> String {
        TypeOpCallother::userop_operator_name(op)
    }

    /// fd-less form: no parent Funcdata chain, so the descriptor table is
    /// unreachable — this observes the base default exactly as Ghidra's
    /// `userOp == null` arm (cc:860-862). The fd-carrying form below
    /// performs the real lookup.
    // Ghidra: typeop.cc:855 TypeOpCallother::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        // cc:862: TypeOp::getInputLocal(op,slot) base default.
        let type_factory = self.local_type_factory()?;
        let size = op.get_in(slot)?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Unknown)
    }

    /// fd-carrying form (typeop.cc:855-863): the user-op descriptor
    /// registered for the CALLOTHER index in input slot 0
    /// (`tlst->getArch()->userops.getOp(...)`, cc:858) supplies the fixed
    /// input type when present; the null result falls to the `TypeOp`
    /// base default (cc:862).
    // Ghidra: typeop.cc:855 TypeOpCallother::getInputLocal (userop arm)
    fn get_input_local_in_fd(
        &self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        fd: &crate::funcdata::Funcdata,
    ) -> Option<Arc<Datatype>> {
        let (index, in_size) = {
            let op = op.0.read().unwrap();
            let index = op.get_in(0)?.read().unwrap().get_offset() as i32;
            let in_size = op.get_in(slot)?.read().unwrap().get_size();
            (index, in_size)
        };
        // cc:858-861: userOp->getInputLocal(op,slot) wins when non-null.
        if let Some(manager) = fd
            .arch
            .as_ref()
            .and_then(|arch| arch.userops.clone())
        {
            if let Some(res) = manager.read().unwrap().get_input_local(index, slot as i32) {
                return Some(res.clone());
            }
        }
        // cc:862: TypeOp::getInputLocal(op,slot).
        let type_factory = self.local_type_factory()?;
        base_local_type(type_factory, in_size, TypeMetatype::Unknown)
    }
}

impl TypeOpCallother {
    /// Look up the actual operator name for a CALLOTHER op.
    ///
    /// Faithful to `TypeOpCallother::getOperatorName` (typeop.cc:837-853):
    /// query the architecture's userop table by the CALLOTHER index held in
    /// input slot 0; if a registered `UserPcodeOp` exists, return its name;
    /// otherwise fall back to `CALLOTHER[<slot0>]`.
    ///
    /// Rudra's `TypeOp` does not (yet) carry a back-pointer to the owning
    /// `Architecture`/`UserOpManage`, so the table lookup must be supplied by
    /// the caller. The default path mirrors Ghidra's fallback branch
    /// (`TypeOp::getOperatorName(op) + '[' + slot0 + ']'`).
    // Ghidra: typeop.cc:837 TypeOpCallother::getOperatorName
    pub fn userop_operator_name(op: &PcodeOp) -> String {
        if let Some(index_vn) = op.get_in(0) {
            let vn = index_vn.read().unwrap();
            let index = vn.get_offset() as i32;
            if let Some(name) = callother_userop_name(op, index) {
                return name;
            }
            // Fallback: "CALLOTHER[<index varnode>]" (typeop.cc:848-852).
            return format!("CALLOTHER[{}]", vn);
        }
        "CALLOTHER".to_string()
    }
}

/// Hook consulted by `TypeOpCallother::get_operator_name` to resolve the
/// `UserOpManage` entry for a CALLOTHER index.
///
/// Ghidra reaches the manager via `op->getParent()->getFuncdata()->getArch()
/// ->userops.getOp(index)` (typeop.cc:840-846). Rudra's `PcodeOp` has no such
/// link today, so this returns `None` until the architecture wiring lands; the
/// caller then falls back to the `CALLOTHER[...]` form, exactly as Ghidra does
/// when the index is unregistered.
// RUDRA-GLUE: indirection for the (not-yet-wired) PcodeOp -> UserOpManage edge
//   used by typeop.cc:837 TypeOpCallother::getOperatorName.
fn callother_userop_name(_op: &PcodeOp, _index: i32) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// TypeOpCast — CPUI_CAST
//
// Ghidra's `TypeOpCast` (typeop.cc:2209 / typeop.hh:803) is a `TypeOp`
// subclass (not TypeOpUnary/Binary/Func) that exists only to print explicit
// type conversions and dispatch to `PrintLanguage::opCast`. It sets no input/
// output type requirements ("We don't care what types are cast") and carries
// a dummy `OpBehavior`. This is a hand-written Rust struct mirroring that.
// ---------------------------------------------------------------------------

/// `CPUI_CAST` type operator.
///
/// Faithful to `TypeOpCast` (typeop.cc:2209-2222 / typeop.hh:803-811).
/// Constructor in Ghidra:
///   `TypeOpCast(t)` sets `name = "(cast)"`,
///   `opflags = unary | special | nocollapse`,
///   `behave = new OpBehavior(CPUI_CAST, false, true)` (dummy).
/// `push` forwards to `PrintLanguage::opCast`; `printRaw` prints
/// `out = (cast) in0`. No type requirements ("We don't care what types are
/// cast", typeop.hh:807-808), so `getOutputLocal`/`getInputLocal` use the
/// `TypeOp` base defaults `getBase(size,TYPE_UNKNOWN)` (typeop.cc:261-275).
pub struct TypeOpCast {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpCast {
    // Ghidra: typeop.cc:2209 TypeOpCast::TypeOpCast
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpCast {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_CAST
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "(cast)"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    // opflags = unary | special | nocollapse (PcodeOp flags, not addlflags);
    // TypeOpCast sets no addlflags, so this is 0 — matches TypeOpCopy/Return.
    fn get_flags(&self) -> u32 {
        0
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); CAST has no
    //   get*Local override in Ghidra (typeop.hh:804-811).
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }

    // Ghidra: typeop.hh:809 TypeOpCast::push  -> lng->opCast(op)
    //
    // Was previously mis-routed: `TypeOpCast::push` called the trait's generic
    // `op_binary` fallback because Rudra's `PrintLanguage` trait did not (and
    // still does not) declare an `op_cast`. Ghidra's `TypeOpCast::push`
    // (typeop.hh:809) calls `PrintLanguage::opCast`, overridden by
    // `PrintC::op_type_cast` (printc.cc). We recover `PrintC` via
    // `as_printc_mut` and call the inherent `op_type_cast`; non-PrintC
    // languages keep the prior `op_binary` fallback so behaviour is unchanged.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_type_cast(op),
            None => lng.op_binary(op),
        }
    }

    // Ghidra: typeop.cc:2216 TypeOpCast::printRaw
    //
    // Ghidra emits: `<out> = (cast) <in0>` — the literal name "(cast)" between
    // the output and the single input.
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = (cast) {}", out, in0)
    }
}

// ---------------------------------------------------------------------------
// TypeOpInsert / TypeOpExtract — CPUI_INSERT / CPUI_EXTRACT
//
// Hand-written instead of `functional_binary_op!` because Ghidra's
// `TypeOpInsert::push` (typeop.hh:890) and `TypeOpExtract::push`
// (typeop.hh:898) call PrintLanguage emitters that are overridden only by
// `PrintC` (`PrintC::op_insert` / `PrintC::op_extract`, printc.cc), i.e. the
// macro's generic `op_binary` push is wrong here. Every other field mirrors
// what `functional_binary_op!` would emit so behaviour is unchanged apart
// from the corrected push routing.
// ---------------------------------------------------------------------------

/// CPUI_INSERT type operator.
///
/// Faithful to `TypeOpInsert` (typeop.hh:886-891 / typeop.cc:2528-2541).
/// Ghidra constructor: `TypeOpFunc(t, CPUI_INSERT, "INSERT", TYPE_UNKNOWN, TYPE_INT)`
/// with `opflags = ternary`. `push` forwards to `PrintLanguage::opInsertOp`,
/// overridden by `PrintC::op_insert`. `getInputLocal` overrides the TypeOpFunc
/// default: slot 0 is the value being inserted into, whose local type stays
/// `getBase(size, TYPE_UNKNOWN)`.
pub struct TypeOpInsert {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpInsert {
    // Ghidra: typeop.cc:2528 TypeOpInsert::TypeOpInsert — TypeOpFunc("INSERT",TYPE_UNKNOWN,TYPE_INT)
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpInsert {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INSERT
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "INSERT"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:377 TypeOpFunc::printRaw (INSERT has no printRaw override)
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = insert({}, {})", out, in0, in1)
    }
    // Ghidra: typeop.hh:890 TypeOpInsert::push -> lng->opInsertOp(op)
    //
    // Was previously mis-routed: the `functional_binary_op!` macro generated a
    // `push` that dispatched to `op_binary`. Ghidra's `TypeOpInsert::push`
    // (typeop.hh:890) calls `PrintLanguage::opInsertOp`, overridden by
    // `PrintC::op_insert` (printc.cc). We recover `PrintC` via `as_printc_mut`
    // and call the inherent `op_insert`; non-PrintC languages fall back to
    // `op_binary` to preserve prior behaviour.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_insert(op),
            None => lng.op_binary(op),
        }
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
    //   constructor-registered metaout/metain below resolve through it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:365 TypeOpFunc::getOutputLocal (INSERT inherits,
    //   metaout=TYPE_UNKNOWN)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Unknown)
    }
    // Ghidra: typeop.cc:2535 TypeOpInsert::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_in(slot)?.read().unwrap().get_size();
        if slot == 0 {
            return base_local_type(type_factory, size, TypeMetatype::Unknown);
        }
        base_local_type(type_factory, size, TypeMetatype::Int)
    }
}

/// CPUI_EXTRACT type operator.
///
/// Faithful to `TypeOpExtract` (typeop.hh:894-899 / typeop.cc:2543-2556).
/// Ghidra constructor: `TypeOpFunc(t, CPUI_EXTRACT, "EXTRACT", TYPE_INT, TYPE_INT)`
/// with `opflags = ternary`. `push` forwards to `PrintLanguage::opExtractOp`,
/// overridden by `PrintC::op_extract`. `getInputLocal` overrides the TypeOpFunc
/// default: slot 0's local type stays `getBase(size, TYPE_UNKNOWN)`.
pub struct TypeOpExtract {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpExtract {
    // Ghidra: typeop.cc:2543 TypeOpExtract::TypeOpExtract — TypeOpFunc("EXTRACT",TYPE_INT,TYPE_INT)
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpExtract {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_EXTRACT
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "EXTRACT"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        0
    }
    // Ghidra: typeop.cc:377 TypeOpFunc::printRaw (EXTRACT has no printRaw override)
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = extract({}, {})", out, in0, in1)
    }
    // Ghidra: typeop.hh:898 TypeOpExtract::push -> lng->opExtractOp(op)
    //
    // Was previously mis-routed: the `functional_binary_op!` macro generated a
    // `push` that dispatched to `op_binary`. Ghidra's `TypeOpExtract::push`
    // (typeop.hh:898) calls `PrintLanguage::opExtractOp`, overridden by
    // `PrintC::op_extract` (printc.cc). We recover `PrintC` via `as_printc_mut`
    // and call the inherent `op_extract`; non-PrintC languages fall back to
    // `op_binary` to preserve prior behaviour.
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        match as_printc_mut(lng) {
            Some(printc) => printc.op_extract(op),
            None => lng.op_binary(op),
        }
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
    //   constructor-registered metaout/metain below resolve through it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:365 TypeOpFunc::getOutputLocal (EXTRACT inherits,
    //   metaout=TYPE_INT)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Int)
    }
    // Ghidra: typeop.cc:2550 TypeOpExtract::getInputLocal
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_in(slot)?.read().unwrap().get_size();
        if slot == 0 {
            return base_local_type(type_factory, size, TypeMetatype::Unknown);
        }
        base_local_type(type_factory, size, TypeMetatype::Int)
    }
}

// ---------------------------------------------------------------------------
// Hand-written impls for the comparison ops and INT_ADD.
//
// These were pulled out of the `binary_op!` macro because Ghidra's
// `TypeOpBinary` gives them a non-default metaout (TYPE_BOOL for comparisons,
// TYPE_INT for INT_ADD) and they override getInputCast/propagateType.
// ---------------------------------------------------------------------------

/// Shared body emitted by `compare_op_impl!` / `signed_compare_op_impl!`:
/// matches the fields the `binary_op!` macro sets (opcode/name/flags/print/push)
/// plus the TypeOpBinary local-type defaults with the constructor-registered
/// metatype pair (every comparison ctor is `TypeOpBinary(sym,TYPE_BOOL,metain)`).
macro_rules! compare_op_common {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr,
     $metain:ident) => {
        // Ghidra: typeop.hh:71 TypeOp::getOpcode
        fn get_opcode(&self) -> OpCode {
            OpCode::$opcode
        }
        // Ghidra: typeop.hh:70 TypeOp::getName
        fn get_name(&self) -> &str {
            $name
        }
        // Ghidra: typeop.hh:72 TypeOp::getFlags
        fn get_flags(&self) -> u32 {
            $flags
        }
        // Ghidra: typeop.cc:335 TypeOpBinary::printRaw (comparison ops inherit)
        fn print_raw(&self, op: &PcodeOp) -> String {
            let out = op
                .get_out()
                .map(|v| format!("{}", v.read().unwrap()))
                .unwrap_or_else(|| "_".to_string());
            let in0 = op
                .get_in(0)
                .map(|v| format!("{}", v.read().unwrap()))
                .unwrap_or_else(|| "_".to_string());
            let in1 = op
                .get_in(1)
                .map(|v| format!("{}", v.read().unwrap()))
                .unwrap_or_else(|| "_".to_string());
            format!("{} = {} {} {}", out, in0, $symbol, in1)
        }
        // RUDRA-GLUE: macro-generated generic binary push for comparison ops.
        fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
            lng.op_binary(op);
        }
        // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
        //   constructor-registered metaout/metain below resolve through it.
        fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
            Some(&self.type_factory)
        }
        // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal (metaout=TYPE_BOOL)
        fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
            let type_factory = self.local_type_factory()?;
            let size = op.get_out()?.read().unwrap().get_size();
            base_local_type(type_factory, size, TypeMetatype::Bool)
        }
        // Ghidra: typeop.cc:329 TypeOpBinary::getInputLocal
        fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
            let type_factory = self.local_type_factory()?;
            let size = op.get_in(slot)?.read().unwrap().get_size();
            base_local_type(type_factory, size, TypeMetatype::$metain)
        }
    };
}

/// Comparison ops whose output is a bool and whose propagateType flows the
/// incoming type across the two inputs (input<->input only), matching Ghidra's
/// `TypeOpEqual::propagateAcrossCompare` (typeop.cc:963-986). The result
/// metatype is Bool.
macro_rules! compare_op_impl {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr,
     $metain:ident) => {
        pub struct $struct_name {
            type_factory: Arc<RwLock<TypeFactory>>,
        }

        impl $struct_name {
            // RUDRA-GLUE: stores the base-class `tlst` field every Ghidra
            //   TypeOp subclass constructor receives (typeop.cc:233-242); the
            //   per-subclass constructor line is cited at the registration
            //   site below.
            pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
                Self { type_factory }
            }
        }

        impl TypeOp for $struct_name {
            compare_op_common!($struct_name, $opcode, $name, $flags, $symbol, $metain);

            /// A comparison's output is boolean.
            // RUDRA-GLUE: exposes the per-subclass `metaout` field
            //   (typeop.hh:205 TYPE_BOOL set by TypeOpBinary ctor).
            fn get_output_metatype(&self) -> Option<TypeMetatype> {
                Some(TypeMetatype::Bool)
            }

            /// The Equal/NotEqual arms use the exact `TypeOpEqual/
            /// TypeOpNotEqual::getInputCast` selection — High read-facing
            /// types, `typeOrder`, and the comparison integer-promotion
            /// check — routed through the fd-aware canonical
            /// `comparison_input_cast` (union_map consult at each High
            /// read-facing read, UNIONRESOLVE-PKG-B-0001). The LESS/
            /// LESSEQUAL arms use the ordering-comparison form
            /// (cc:1075-1083/1099-1107): `inputTypeLocal(slot)` base
            /// (TYPE_UINT), promotion check, else castStandard(TRUE,FALSE).
            // Ghidra: typeop.cc:932 TypeOpEqual::getInputCast /
            //   typeop.cc:1075 TypeOpIntLess::getInputCast
            fn get_input_cast(
                &self,
                op: &crate::op::PcodeOpRef,
                slot: usize,
                fd: &crate::funcdata::Funcdata,
            ) -> Option<Arc<Datatype>> {
                let strategy = factory_cast_strategy(&self.type_factory);
                let opcode = op.0.read().unwrap().opcode;
                match opcode {
                    OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                        comparison_input_cast(fd, op, slot, &strategy)
                    }
                    OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL => {
                        // cc:1082/1106: care_ptr_uint = FALSE (unsigned).
                        ordering_compare_input_cast(self, op, slot, &strategy, fd, false)
                    }
                    _ => None,
                }
            }

            /// Comparisons propagate a type across their two input operands
            /// (never to/from the output) via the shared
            /// `TypeOpEqual::propagateAcrossCompare` body: a spacebase input
            /// is rewrapped as a pointer to the unknown base; a mid-struct
            /// PointerRel degrades to a plain pointer.
            /// Faithful to `TypeOpEqual::propagateAcrossCompare`
            /// (typeop.cc:963-986).
            // Ghidra: typeop.cc:945 TypeOpEqual::propagateType
            fn propagate_type(
                &self,
                alt_type: &Arc<Datatype>,
                op: &PcodeOp,
                inslot: i32,
                outslot: i32,
            ) -> Option<Arc<Datatype>> {
                propagate_across_compare(alt_type, op, inslot, outslot, Some(&self.type_factory))
            }
        }
    };
}

/// Signed comparisons (INT_SLESS / INT_SLESSEQUAL) only propagate TYPE_INT
/// across their inputs, matching Ghidra's `TypeOpIntSless::propagateType`
/// (typeop.cc:1033-1039).
macro_rules! signed_compare_op_impl {
    ($struct_name:ident, $opcode:ident, $name:expr, $flags:expr, $symbol:expr,
     $metain:ident) => {
        pub struct $struct_name {
            type_factory: Arc<RwLock<TypeFactory>>,
        }

        impl $struct_name {
            // RUDRA-GLUE: stores the base-class `tlst` field every Ghidra
            //   TypeOp subclass constructor receives (typeop.cc:233-242); the
            //   per-subclass constructor line is cited at the registration
            //   site below.
            pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
                Self { type_factory }
            }
        }

        impl TypeOp for $struct_name {
            compare_op_common!($struct_name, $opcode, $name, $flags, $symbol, $metain);

            /// A signed comparison's output is boolean.
            // RUDRA-GLUE: exposes the per-subclass `metaout` field
            //   (typeop.hh:205 TYPE_BOOL set by TypeOpBinary ctor).
            fn get_output_metatype(&self) -> Option<TypeMetatype> {
                Some(TypeMetatype::Bool)
            }

            /// The ordering-comparison input cast for the signed compares
            /// (typeop.cc:1023-1031 SLESS / cc:1049-1057 SLESSEQUAL):
            /// `inputTypeLocal(slot)` base (TYPE_INT), promotion check,
            /// else `castStandard(reqtype,curtype,TRUE,TRUE)`.
            // Ghidra: typeop.cc:1023 TypeOpIntSless::getInputCast
            fn get_input_cast(
                &self,
                op: &crate::op::PcodeOpRef,
                slot: usize,
                fd: &crate::funcdata::Funcdata,
            ) -> Option<Arc<Datatype>> {
                let strategy = factory_cast_strategy(&self.type_factory);
                // cc:1030/1056: care_ptr_uint = TRUE (signed compares).
                ordering_compare_input_cast(self, op, slot, &strategy, fd, true)
            }

            /// Signed comparisons only propagate signed (TYPE_INT) types
            /// across their inputs; nothing flows to/from the bool output.
            /// Faithful to `TypeOpIntSless::propagateType`
            /// (typeop.cc:1033-1039).
            // Ghidra: typeop.cc:1033 TypeOpIntSless::propagateType
            fn propagate_type(
                &self,
                alt_type: &Arc<Datatype>,
                _op: &PcodeOp,
                inslot: i32,
                outslot: i32,
            ) -> Option<Arc<Datatype>> {
                if inslot == -1 || outslot == -1 {
                    return None; // Must propagate input <-> input
                }
                if alt_type.get_metatype() != TypeMetatype::Int {
                    return None; // Only propagate signed things
                }
                Some(alt_type.clone())
            }
        }
    };
}

// Ghidra: typeop.cc:924 TypeOpEqual::TypeOpEqual — TypeOpBinary("==",TYPE_BOOL,TYPE_INT)
compare_op_impl!(TypeOpIntEqual, CPUI_INT_EQUAL, "INT_EQUAL", 0, "==", Int);
// Ghidra: typeop.cc:988 TypeOpNotEqual::TypeOpNotEqual — TypeOpBinary("!=",TYPE_BOOL,TYPE_INT)
compare_op_impl!(
    TypeOpIntNotEqual,
    CPUI_INT_NOTEQUAL,
    "INT_NOTEQUAL",
    0,
    "!=",
    Int
);
// Ghidra: typeop.cc:1067 TypeOpIntLess::TypeOpIntLess — TypeOpBinary("<",TYPE_BOOL,TYPE_UINT)
compare_op_impl!(TypeOpIntLess, CPUI_INT_LESS, "INT_LESS", 0, "<", Uint);
// Ghidra: typeop.cc:1091 TypeOpIntLessEqual::TypeOpIntLessEqual — TypeOpBinary("<=",TYPE_BOOL,TYPE_UINT)
compare_op_impl!(
    TypeOpIntLessEqual,
    CPUI_INT_LESSEQUAL,
    "INT_LESSEQUAL",
    0,
    "<=",
    Uint
);
// Ghidra: typeop.cc:1015 TypeOpIntSless::TypeOpIntSless — TypeOpBinary("<",TYPE_BOOL,TYPE_INT)
signed_compare_op_impl!(
    TypeOpIntSless,
    CPUI_INT_SLESS,
    "INT_SLESS",
    typeop_flags::INHERITS_SIGN,
    "s<",
    Int
);
// Ghidra: typeop.cc:1041 TypeOpIntSlessEqual::TypeOpIntSlessEqual — TypeOpBinary("<=",TYPE_BOOL,TYPE_INT)
signed_compare_op_impl!(
    TypeOpIntSlessEqual,
    CPUI_INT_SLESSEQUAL,
    "INT_SLESSEQUAL",
    typeop_flags::INHERITS_SIGN,
    "s<=",
    Int
);

/// CPUI_INT_ADD with custom get_output_token and propagate_type.
///
/// `get_output_token` uses the arithmetic typing rule (the output's own high
/// type). `propagate_type` lets a pointer flow input->output (and back) when
/// the other addend is a constant, and otherwise flows int/uint types when
/// adding a constant; it never flows pointer types output->input.
/// Faithful to `TypeOpIntAdd` (typeop.cc:1167-1201). The local-type defaults
/// inherit TypeOpBinary with the constructor pair (TYPE_INT,TYPE_INT)
/// (typeop.cc:1167).
pub struct TypeOpIntAdd {
    type_factory: Arc<RwLock<TypeFactory>>,
}

impl TypeOpIntAdd {
    // Ghidra: typeop.cc:1167 TypeOpIntAdd::TypeOpIntAdd — TypeOpBinary("+",TYPE_INT,TYPE_INT)
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        Self { type_factory }
    }
}

impl TypeOp for TypeOpIntAdd {
    // Ghidra: typeop.hh:71 TypeOp::getOpcode
    fn get_opcode(&self) -> OpCode {
        OpCode::CPUI_INT_ADD
    }
    // Ghidra: typeop.hh:70 TypeOp::getName
    fn get_name(&self) -> &str {
        "INT_ADD"
    }
    // Ghidra: typeop.hh:72 TypeOp::getFlags
    fn get_flags(&self) -> u32 {
        typeop_flags::ARITHMETIC_OP
    }
    // Ghidra: typeop.cc:335 TypeOpBinary::printRaw (IntAdd inherits)
    fn print_raw(&self, op: &PcodeOp) -> String {
        let out = op
            .get_out()
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in0 = op
            .get_in(0)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        let in1 = op
            .get_in(1)
            .map(|v| format!("{}", v.read().unwrap()))
            .unwrap_or_else(|| "_".to_string());
        format!("{} = {} + {}", out, in0, in1)
    }
    // Ghidra: typeop.hh:439 TypeOpIntAdd::push
    fn push(&self, lng: &mut dyn PrintLanguage, op: &PcodeOp) {
        lng.op_binary(op);
    }
    // RUDRA-GLUE: base-class `tlst` provider (typeop.cc:233-242); the
    //   constructor-registered metaout/metain below resolve through it.
    fn local_type_factory(&self) -> Option<&Arc<RwLock<TypeFactory>>> {
        Some(&self.type_factory)
    }
    // Ghidra: typeop.cc:323 TypeOpBinary::getOutputLocal (inherited, TYPE_INT)
    fn get_output_local(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_out()?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Int)
    }
    // Ghidra: typeop.cc:329 TypeOpBinary::getInputLocal (inherited, TYPE_INT)
    fn get_input_local(&self, op: &PcodeOp, slot: usize) -> Option<Arc<Datatype>> {
        let type_factory = self.local_type_factory()?;
        let size = op.get_in(slot)?.read().unwrap().get_size();
        base_local_type(type_factory, size, TypeMetatype::Int)
    }

    /// The output token of an ADD follows the arithmetic typing rule: the
    /// earliest-ordering input HIGH type (bool demoted to base int).
    /// Faithful to `TypeOpIntAdd::getOutputToken` (typeop.cc:1175-1179),
    /// which returns `castStrategy->arithmeticOutputStandard(op)`.
    // Ghidra: typeop.cc:1175 TypeOpIntAdd::getOutputToken
    fn get_output_token(&self, op: &PcodeOp) -> Option<Arc<Datatype>> {
        crate::type_system::cast::arithmetic_output_standard(op, &self.type_factory)
    }

    /// Pointer arithmetic rule. A pointer propagates input->output when the
    /// other input makes sense as a pointer add, transformed through
    /// `propagateAddIn2Out`'s downChain; ints/uints propagate only into the
    /// slot-1 constant. Pointers never propagate output->input. Anything
    /// else is blocked.
    /// Faithful to `TypeOpIntAdd::propagateType` (typeop.cc:1181-1201).
    // Ghidra: typeop.cc:1181 TypeOpIntAdd::propagateType
    fn propagate_type(
        &self,
        alt_type: &Arc<Datatype>,
        op: &PcodeOp,
        inslot: i32,
        outslot: i32,
    ) -> Option<Arc<Datatype>> {
        let meta = alt_type.get_metatype();
        if meta != TypeMetatype::Pointer {
            // Only int/uint may flow, and only into the slot-1 constant
            // (typeop.cc:1186-1189). A missing in(1) is ill-formed for a
            // binary op (the oracle would dereference null); safe Rust
            // blocks the edge instead of panicking.
            if meta != TypeMetatype::Int && meta != TypeMetatype::Uint {
                return None;
            }
            if outslot != 1
                || !op
                    .get_in(1)
                    .is_some_and(|in1| in1.read().unwrap().is_constant())
            {
                return None;
            }
        } else if inslot != -1 && outslot != -1 {
            return None; // Must propagate input <-> output for pointers
        }
        // typeop.cc:1194: outvn is the edge's target varnode — the op output
        // when outslot < 0, else the op input at outslot (the
        // ActionInferTypes::propagateTypeEdge caller convention,
        // coreaction.cc:5095-5098).
        let out_is_constant = if outslot < 0 {
            op.get_out()
                .is_some_and(|out| out.read().unwrap().is_constant())
        } else {
            op.get_in(outslot as usize)
                .is_some_and(|out| out.read().unwrap().is_constant())
        };
        if out_is_constant && meta != TypeMetatype::Pointer {
            return Some(alt_type.clone());
        }
        if inslot == -1 {
            // Propagating output to input: don't propagate pointer types
            // this direction (typeop.cc:1196-1197).
            return None;
        }
        // typeop.cc:1199: propagateAddIn2Out(alttype, tlst, op, inslot) —
        // `tlst` is this TypeOp's factory member.
        Self::propagate_add_in2out(alt_type, &self.type_factory, op, inslot)
    }
}

/// Command returned by `propagate_add_pointer`, mirroring Ghidra's integer
/// return codes (typeop.cc:1255-1267):
///   - `AddZero`:   "add a constant" adding a zero  (PTRSUB or PTRADD)
///   - `AddConst`:  "add a constant"; the constant is passed back in `offset`
///   - `NoPropagate`: the pointer does not propagate through
///   - `Passthrough`: the input data-type propagates through untransformed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagateAddCommand {
    AddZero,
    AddConst,
    NoPropagate,
    Passthrough,
}

impl TypeOpIntAdd {
    /// Determine whether a data-type edge looks like a pointer propagating
    /// through an "add a constant" operation.
    ///
    /// Faithful to `TypeOpIntAdd::propagateAddPointer` (typeop.cc:1268-1316).
    /// Given the PcodeOp propagating the data-type, the input edge `slot`, and
    /// the size `sz` of the data-type being pointed to, returns a command
    /// indicating how the op should be treated. When the command is `AddConst`
    /// or `AddZero`, the constant offset is written into `offset`.
    ///
    /// The down-chain reconstruction that consumes this classifier is
    /// [`Self::propagate_add_in2out`] below.
    // Ghidra: typeop.cc:1268 TypeOpIntAdd::propagateAddPointer
    pub fn propagate_add_pointer(
        op: &PcodeOp,
        slot: i32,
        sz: i32) -> (PropagateAddCommand, u64) {
        match op.get_opcode() {
            OpCode::CPUI_PTRADD => {
                // typeop.cc:1271-1282
                if slot != 0 {
                    return (PropagateAddCommand::NoPropagate, 0);
                }
                let constvn = match op.get_in(1) {
                    Some(v) => v.clone(),
                    None => return (PropagateAddCommand::NoPropagate, 0),
                };
                let cv = constvn.read().unwrap();
                let mult = op
                    .get_in(2)
                    .map(|v| v.read().unwrap().get_offset())
                    .unwrap_or(0);
                if cv.is_constant() {
                    let off =
                        (cv.get_offset().wrapping_mul(mult)) & calc_mask(cv.get_size());
                    return (
                        if off == 0 {
                            PropagateAddCommand::AddZero
                        } else {
                            PropagateAddCommand::AddConst
                        },
                        off,
                    );
                }
                if sz != 0 && (mult % sz as u64) != 0 {
                    return (PropagateAddCommand::NoPropagate, 0);
                }
                return (PropagateAddCommand::Passthrough, 0);
            }
            OpCode::CPUI_PTRSUB => {
                // typeop.cc:1283-1287
                if slot != 0 {
                    return (PropagateAddCommand::NoPropagate, 0);
                }
                let off = op
                    .get_in(1)
                    .map(|v| v.read().unwrap().get_offset())
                    .unwrap_or(0);
                return (
                    if off == 0 {
                        PropagateAddCommand::AddZero
                    } else {
                        PropagateAddCommand::AddConst
                    },
                    off,
                );
            }
            OpCode::CPUI_INT_ADD => {
                // typeop.cc:1288-1314
                let other_slot = (1 - slot) as usize;
                let othervn = match op.get_in(other_slot) {
                    Some(v) => v.clone(),
                    None => return (PropagateAddCommand::NoPropagate, 0),
                };
                let ov = othervn.read().unwrap();
                // Check if othervn is an offset.
                if !ov.is_constant() {
                    if ov.is_written() {
                        if let Some(def) = ov.get_def() {
                            let multop = def.read().unwrap();
                            if multop.get_opcode() == OpCode::CPUI_INT_MULT {
                                let constvn = multop.get_in(1);
                                if let Some(cv_arc) = constvn {
                                    let cv = cv_arc.read().unwrap();
                                    if cv.is_constant() {
                                        let mult = cv.get_offset();
                                        // If multiplying by -1, assume pointer difference.
                                        if mult == calc_mask(cv.get_size()) {
                                            return (PropagateAddCommand::NoPropagate, 0);
                                        }
                                        if sz != 0 && (mult % sz as u64) != 0 {
                                            return (PropagateAddCommand::NoPropagate, 0);
                                        }
                                    }
                                }
                                return (PropagateAddCommand::Passthrough, 0);
                            }
                        }
                    }
                    if sz == 1 {
                        return (PropagateAddCommand::Passthrough, 0);
                    }
                    return (PropagateAddCommand::NoPropagate, 0);
                }
                // othervn is constant: check if it is marked as a pointer.
                if ov
                    .v_type
                    .as_ref()
                    .map(|t| t.get_metatype() == TypeMetatype::Pointer)
                    .unwrap_or(false)
                {
                    return (PropagateAddCommand::NoPropagate, 0);
                }
                let off = ov.get_offset();
                return (
                    if off == 0 {
                        PropagateAddCommand::AddZero
                    } else {
                        PropagateAddCommand::AddConst
                    },
                    off,
                );
            }
            _ => (PropagateAddCommand::NoPropagate, 0),
        }
    }

    /// Assuming a pointer data-type from an ADD PcodeOp propagates from an
    /// input to its output, calculate the transformed data-type of the output
    /// Varnode, which will depend on details of the operation. If the edge
    /// doesn't make sense as "an ADD to a pointer", prevent the propagation by
    /// returning the output Varnode's current data-type.
    ///
    /// Faithful to `TypeOpIntAdd::propagateAddIn2Out` (typeop.cc:1215-1253).
    /// `alttype` is the resolved input pointer data-type (callers guarantee
    /// TYPE_PTR); `typegrp` is the owning TypeFactory, threaded explicitly
    /// because the C++ original reaches it through the TypeOp's `tlst` member —
    /// the factory is genuinely mutated (downChain/getBase/getTypePointer/
    /// getTypePointerRel all intern). The production caller is the
    /// PTRSUB/PTRADD/INT_ADD pointer arm of the ActionInferTypes dispatch
    /// (`TypeOpPtrsub::propagateType` typeop.cc:2375,
    /// `TypeOpPtradd::propagateType` typeop.cc:2279,
    /// `TypeOpIntAdd::propagateType` typeop.cc:1200).
    // Ghidra: typeop.cc:1215 TypeOpIntAdd::propagateAddIn2Out
    pub fn propagate_add_in2out(
        alttype: &Arc<Datatype>,
        typegrp: &Arc<RwLock<TypeFactory>>,
        op: &PcodeOp,
        inslot: i32,
    ) -> Option<Arc<Datatype>> {
        // typeop.cc:1216: `TypePointer *pointer = (TypePointer *)alttype;` —
        // the C++ downcast is unchecked; every caller guards metatype ==
        // TYPE_PTR first. A non-pointer input stops the propagation.
        let ptr0 = match alttype.as_ref() {
            Datatype::Pointer(p) => p.clone(),
            _ => return None,
        };
        // typeop.cc:1220: sz = pointer->getPtrTo()->getAlignSize()
        let (command, offset) =
            Self::propagate_add_pointer(op, inslot, ptr0.ptr_to.get_align_size() as i32);
        if command == PropagateAddCommand::NoPropagate {
            return None; // Doesn't look like a good pointer add
        }
        let mut factory = typegrp.write().unwrap();
        // typeop.cc:1222-1223: `parent`/`parentOff` are shared accumulator
        // slots across the whole do-while loop — cleared once before it,
        // written only by downChain when the current pointee is a struct or
        // array, never reset between iterations. The `getTypePointerRel` call
        // below (typeop.cc:1241) uses the END-of-loop snapshot.
        let mut parent: Option<Arc<Datatype>> = None;
        let mut parent_off: i64 = 0;
        let mut pointer: Option<Arc<Datatype>> = Some(alttype.clone());
        if command != PropagateAddCommand::Passthrough {
            // typeop.cc:1224-1232: do { pointer = downChain(...) } while —
            // body runs at least once; break on a NULL chain; continue only
            // while the re-normalized offset stays non-zero. There is no
            // explicit depth cap (termination relies on offset consumption /
            // NULL). allowWrap = (op->code() != CPUI_PTRSUB): PTRSUB never
            // wraps. typeOffset is int8 in Ghidra (uintb -> int8 implicit
            // conversion; negative encodings reach the wrap branch).
            let wordsize = ptr0.wordsize as u32;
            let mut type_offset =
                crate::space::AddrSpace::address_to_byte_int(offset as i64, wordsize);
            let allow_wrap = op.get_opcode() != OpCode::CPUI_PTRSUB;
            loop {
                // Loop-entry invariant: pointer is Some (do-while shape).
                let current = pointer.clone().expect("do-while entry invariant");
                let next = factory.down_chain_virtual(
                    &current,
                    &mut type_offset,
                    &mut parent,
                    &mut parent_off,
                    allow_wrap,
                );
                match next {
                    None => {
                        pointer = None;
                        break;
                    }
                    Some(found) => {
                        pointer = Some(found);
                        if type_offset == 0 {
                            break;
                        }
                    }
                }
            }
        }
        if let Some(parent_pointer) = parent.clone() {
            // typeop.cc:1233-1242: if the innermost containing object is a
            // TYPE_STRUCT or TYPE_ARRAY, preserve info about this container.
            let pt = match &pointer {
                None => factory
                    .get_base(1, TypeMetatype::Unknown)
                    .expect("canonical unknown1 base type"), // Offset does not point at a proper sub-type
                Some(found) => match found.as_ref() {
                    Datatype::Pointer(ptype) => ptype.ptr_to.clone(), // The sub-type being directly pointed at
                    _ => return None, // ill-typed in the oracle (unchecked C++ cast)
                },
            };
            // typeop.cc:1241: the ephemeral UNNAMED getTypePointerRel overload
            // (type.cc:4016), not the named type.cc:4029 form.
            pointer = Some(factory.get_type_pointer_rel_ephemeral(parent_pointer, pt, parent_off));
        }
        // typeop.cc:1243-1247: a dead chain with command AddZero (added 0)
        // falls back to the input type; anything else is NULL. The parent
        // block above already ran, so this only fires when both the chain
        // and the container accumulator are empty.
        let pointer = match pointer {
            Some(found) => found,
            // command == 0 (AddZero): return alttype (typeop.cc:1244-1245).
            None if command == PropagateAddCommand::AddZero => {
                return Some(alttype.clone());
            }
            None => return None,
        };
        // typeop.cc:1248-1251: spacebase input whose transformed pointee is
        // TYPE_SPACEBASE rewrites to an unknown base-type pointer, sized from
        // the RESULT pointer (not the input alttype).
        if op
            .get_in(inslot as usize)
            .is_some_and(|input| input.read().unwrap().is_spacebase())
        {
            if let Datatype::Pointer(ptype) = pointer.as_ref() {
                if ptype.ptr_to.get_metatype() == TypeMetatype::Spacebase {
                    let unknown = factory
                        .get_base(1, TypeMetatype::Unknown)
                        .expect("canonical unknown1 base type");
                    return Some(
                        factory.get_type_pointer(
                        ptype.base.size, unknown, ptype.wordsize,
                    ));
                }
            }
        }
        Some(pointer)
    }
}

/// Manager for TypeOps
///
/// This handles the mapping between OpCodes and their TypeOp implementations.
pub struct TypeOpManager {
    ops: Vec<Option<Box<dyn TypeOp>>>,
}

impl TypeOpManager {
    // RUDRA-GLUE: Rust manager ctor; mirrors Ghidra's
    //   `TypeOp::registerInstructions(inst, tlst, trans)` (typeop.cc:24),
    //   which allocates and registers one TypeOp subclass per op-code into the
    //   `inst` vector. Rudra stores them in `Self::ops` keyed by OpCode.
    pub fn new(type_factory: Arc<RwLock<TypeFactory>>) -> Self {
        let mut ops: Vec<Option<Box<dyn TypeOp>>> = Vec::new();
        ops.resize_with(256, || None); // Large enough for all opcodes

        // Register initial ops
        ops[OpCode::CPUI_COPY as usize] = Some(Box::new(TypeOpCopy::new(type_factory.clone())));
        ops[OpCode::CPUI_LOAD as usize] = Some(Box::new(TypeOpLoad));
        ops[OpCode::CPUI_STORE as usize] = Some(Box::new(TypeOpStore));

        // Arithmetic
        ops[OpCode::CPUI_INT_ADD as usize] = Some(Box::new(TypeOpIntAdd::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SUB as usize] = Some(Box::new(TypeOpIntSub::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_MULT as usize] = Some(Box::new(TypeOpIntMult::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_DIV as usize] = Some(Box::new(TypeOpIntDiv::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SDIV as usize] = Some(Box::new(TypeOpIntSdiv::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_REM as usize] = Some(Box::new(TypeOpIntRem::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SREM as usize] = Some(Box::new(TypeOpIntSrem::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_2COMP as usize] = Some(Box::new(TypeOpIntNeg::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_CARRY as usize] = Some(Box::new(TypeOpIntCarry::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SCARRY as usize] = Some(Box::new(TypeOpIntScarry::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SBORROW as usize] = Some(Box::new(TypeOpIntSborrow::new(type_factory.clone())));

        // Bitwise
        ops[OpCode::CPUI_INT_AND as usize] = Some(Box::new(TypeOpIntAnd::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_OR as usize] = Some(Box::new(TypeOpIntOr::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_XOR as usize] = Some(Box::new(TypeOpIntXor::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_NEGATE as usize] = Some(Box::new(TypeOpIntNot::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_LEFT as usize] = Some(Box::new(TypeOpIntLeft::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_RIGHT as usize] = Some(Box::new(TypeOpIntRight::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SRIGHT as usize] = Some(Box::new(TypeOpIntSright::new(type_factory.clone())));

        // Comparison
        ops[OpCode::CPUI_INT_EQUAL as usize] = Some(Box::new(TypeOpIntEqual::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_NOTEQUAL as usize] = Some(Box::new(TypeOpIntNotEqual::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_LESS as usize] = Some(Box::new(TypeOpIntLess::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SLESS as usize] = Some(Box::new(TypeOpIntSless::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_LESSEQUAL as usize] = Some(Box::new(TypeOpIntLessEqual::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SLESSEQUAL as usize] = Some(Box::new(TypeOpIntSlessEqual::new(type_factory.clone())));

        // Extension
        ops[OpCode::CPUI_INT_ZEXT as usize] = Some(Box::new(TypeOpIntZext::new(type_factory.clone())));
        ops[OpCode::CPUI_INT_SEXT as usize] = Some(Box::new(TypeOpIntSext::new(type_factory.clone())));

        // Floating Point
        ops[OpCode::CPUI_FLOAT_ADD as usize] = Some(Box::new(TypeOpFloatAdd::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_SUB as usize] = Some(Box::new(TypeOpFloatSub::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_MULT as usize] = Some(Box::new(TypeOpFloatMult::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_DIV as usize] = Some(Box::new(TypeOpFloatDiv::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_NEG as usize] = Some(Box::new(TypeOpFloatNeg::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_ABS as usize] = Some(Box::new(TypeOpFloatAbs::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_SQRT as usize] = Some(Box::new(TypeOpFloatSqrt::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_EQUAL as usize] = Some(Box::new(TypeOpFloatEqual::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_NOTEQUAL as usize] = Some(Box::new(TypeOpFloatNotEqual::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_LESS as usize] = Some(Box::new(TypeOpFloatLess::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_LESSEQUAL as usize] = Some(Box::new(TypeOpFloatLessEqual::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_NAN as usize] = Some(Box::new(TypeOpFloatNan::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_FLOAT2FLOAT as usize] =
            Some(Box::new(TypeOpFloatFloat2Float::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_INT2FLOAT as usize] =
            Some(Box::new(TypeOpFloatInt2Float::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_TRUNC as usize] = Some(Box::new(TypeOpFloatTrunc::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_CEIL as usize] = Some(Box::new(TypeOpFloatCeil::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_FLOOR as usize] = Some(Box::new(TypeOpFloatFloor::new(type_factory.clone())));
        ops[OpCode::CPUI_FLOAT_ROUND as usize] = Some(Box::new(TypeOpFloatRound::new(type_factory.clone())));

        // Boolean
        ops[OpCode::CPUI_BOOL_AND as usize] = Some(Box::new(TypeOpBoolAnd::new(type_factory.clone())));
        ops[OpCode::CPUI_BOOL_OR as usize] = Some(Box::new(TypeOpBoolOr::new(type_factory.clone())));
        ops[OpCode::CPUI_BOOL_XOR as usize] = Some(Box::new(TypeOpBoolXor::new(type_factory.clone())));
        ops[OpCode::CPUI_BOOL_NEGATE as usize] = Some(Box::new(TypeOpBoolNot::new(type_factory.clone())));

        // Special
        ops[OpCode::CPUI_PIECE as usize] = Some(Box::new(TypeOpPiece::new(type_factory.clone())));
        ops[OpCode::CPUI_SUBPIECE as usize] = Some(Box::new(TypeOpSubpiece::new(type_factory.clone())));
        ops[OpCode::CPUI_POPCOUNT as usize] = Some(Box::new(TypeOpPopcount::new(type_factory.clone())));
        ops[OpCode::CPUI_LZCOUNT as usize] = Some(Box::new(TypeOpLzcount::new(type_factory.clone())));

        // Control Flow
        ops[OpCode::CPUI_BRANCH as usize] = Some(Box::new(TypeOpBranch::new(type_factory.clone())));
        ops[OpCode::CPUI_CBRANCH as usize] =
            Some(Box::new(TypeOpCbranch::new(type_factory.clone())));
        ops[OpCode::CPUI_BRANCHIND as usize] =
            Some(Box::new(TypeOpBranchind::new(type_factory.clone())));
        ops[OpCode::CPUI_CALL as usize] = Some(Box::new(TypeOpCall::new(type_factory.clone())));
        ops[OpCode::CPUI_CALLIND as usize] =
            Some(Box::new(TypeOpCallind::new(type_factory.clone())));
        ops[OpCode::CPUI_RETURN as usize] = Some(Box::new(TypeOpReturn));

        // Pointer/SSA/Other
        ops[OpCode::CPUI_PTRADD as usize] =
            Some(Box::new(TypeOpPtradd::new(type_factory.clone())));
        ops[OpCode::CPUI_PTRSUB as usize] =
            Some(Box::new(TypeOpPtrsub::new(type_factory.clone())));
        ops[OpCode::CPUI_MULTIEQUAL as usize] = Some(Box::new(TypeOpMulti));
        ops[OpCode::CPUI_INDIRECT as usize] =
            Some(Box::new(TypeOpIndirect::new(type_factory.clone())));
        ops[OpCode::CPUI_SEGMENTOP as usize] =
            Some(Box::new(TypeOpSegment::new(type_factory.clone())));
        ops[OpCode::CPUI_CPOOLREF as usize] = Some(Box::new(TypeOpCpoolref));
        ops[OpCode::CPUI_NEW as usize] = Some(Box::new(TypeOpNew));
        ops[OpCode::CPUI_CALLOTHER as usize] =
            Some(Box::new(TypeOpCallother::new(type_factory.clone())));
        ops[OpCode::CPUI_CAST as usize] = Some(Box::new(TypeOpCast::new(type_factory.clone())));
        ops[OpCode::CPUI_INSERT as usize] = Some(Box::new(TypeOpInsert::new(type_factory.clone())));
        ops[OpCode::CPUI_EXTRACT as usize] = Some(Box::new(TypeOpExtract::new(type_factory.clone())));

        Self { ops }
    }

    // RUDRA-GLUE: Rust accessor for the opcode→TypeOp table; in Ghidra the
    //   table is `vector<TypeOp*> inst` indexed by OpCode and held by
    //   TypeFactory (typeop.hh:186 registerInstructions). Lookups go through
    //   PcodeOp::getOpcode (op.hh:232) → TypeOp*.
    pub fn get_op(&self, opcode: OpCode) -> Option<&dyn TypeOp> {
        self.ops[opcode as usize].as_ref().map(|o| o.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Per-op push carrying (MIGW1-TYPEOP-0002): typeop.hh TypeOpX::push virtuals.
//
// Oracle layer (typeop.hh, one inline push per concrete subclass):
//   `virtual void push(PrintLanguage *lng,const PcodeOp *op,const PcodeOp *readOp) const
//      { lng->opXxx(op[,readOp]); }`
// Each route below is one TypeOp subclass push, anchored at its typeop.hh
// declaration line, dispatching to the PrintC virtual of the same name
// (printc.rs per-op emitters, printc.hh:283-344 anchors). The Arc transport
// (`op_arc`, `read_op`) is the Rust signature form of the C++ pointer pair
// (see printc::OpArcRef). The `None` fallback mirrors the legacy generic
// emitters for any PrintLanguage implementation other than PrintC (the C++
// virtuals are pure — every language supplies its own; op_binary/op_unary
// are Rudra's generic stand-ins, matching the PcodeOp::push wrapper above).
//
// Production entry: PrintC::dispatch_op_rpn delegates the 53 opcodes in
// push_opcode_rpn here (typeop.hh:170 TypeOp::push virtual dispatch twin)
// — the same `op->getOpcode()->push(this,op,readOp)` hop the oracle's
// emitExpression (printc.cc:2493) and recurse (printlanguage.cc:532) make.
// ---------------------------------------------------------------------------

// Ghidra: typeop.hh:359 TypeOpEqual::push
// (`{ lng->opIntEqual(op); }` → printc.hh:283 opBinary(&equal,op))
/// INT_EQUAL push route: PrintC::opIntEqual — equal token "==" (id 12).
pub fn push_int_equal(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_equal(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:371 TypeOpNotEqual::push
// (`{ lng->opIntNotEqual(op); }` → printc.hh:284 opBinary(&not_equal,op))
/// INT_NOTEQUAL push route: PrintC::opIntNotEqual — not_equal token "!=" (id 13).
pub fn push_int_not_equal(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_not_equal(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:384 TypeOpIntSless::push
// (`{ lng->opIntSless(op); }` → printc.hh:285 opBinary(&less_than,op))
/// INT_SLESS push route: PrintC::opIntSless — less_than token "<" (id 8).
pub fn push_int_sless(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_sless(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:394 TypeOpIntSlessEqual::push
// (`{ lng->opIntSlessEqual(op); }` → printc.hh:286 opBinary(&less_equal,op))
/// INT_SLESSEQUAL push route: PrintC::opIntSlessEqual — less_equal "<=" (id 9).
pub fn push_int_sless_equal(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_sless_equal(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:401 TypeOpIntLess::push
// (`{ lng->opIntLess(op); }` → printc.hh:287 opBinary(&less_than,op))
/// INT_LESS push route: PrintC::opIntLess — the same less_than static
/// instance INT_SLESS dispatches to (printc.cc:44).
pub fn push_int_less(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_less(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:411 TypeOpIntLessEqual::push
// (`{ lng->opIntLessEqual(op); }` → printc.hh:288 opBinary(&less_equal,op))
/// INT_LESSEQUAL push route: PrintC::opIntLessEqual — less_equal "<=" (id 9).
pub fn push_int_less_equal(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_less_equal(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:421 TypeOpIntZext::push
// (`{ lng->opIntZext(op,readOp); }` → printc.cc:786 body)
/// INT_ZEXT push route: PrintC::opIntZext — cast/hide/func decision; the
/// only route that consumes `read_op` (isExtensionCastImplied, cast.cc:249).
pub fn push_int_zext(
    lng: &mut dyn PrintLanguage,
    op_arc: &OpArcRef,
    op: &PcodeOp,
    read_op: Option<&OpArcRef>,
) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_zext_rpn(op_arc, op, read_op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:430 TypeOpIntSext::push
// (`{ lng->opIntSext(op,readOp); }` → printc.cc:799 body)
/// INT_SEXT push route: PrintC::opIntSext — cast/hide/func decision.
pub fn push_int_sext(
    lng: &mut dyn PrintLanguage,
    op_arc: &OpArcRef,
    op: &PcodeOp,
    read_op: Option<&OpArcRef>,
) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_sext_rpn(op_arc, op, read_op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:439 TypeOpIntAdd::push
// (`{ lng->opIntAdd(op); }` → printc.hh:291 opBinary(&binary_plus,op))
/// INT_ADD push route: PrintC::opIntAdd — binary_plus "+" (id 3); Rudra
/// keeps the struct-field recovery pre-check (documented at the emitter).
pub fn push_int_add(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_add(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:451 TypeOpIntSub::push
// (`{ lng->opIntSub(op); }` → printc.hh:292 opBinary(&binary_minus,op))
/// INT_SUB push route: PrintC::opIntSub — binary_minus "-" (id 4).
pub fn push_int_sub(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_sub(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:459 TypeOpIntCarry::push
// (`{ lng->opIntCarry(op); }` → printc.hh:293 opFunc(op))
/// INT_CARRY push route: PrintC::opIntCarry — opFunc `CARRY<insize>`.
pub fn push_int_carry(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_carry(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:467 TypeOpIntScarry::push
// (`{ lng->opIntScarry(op); }` → printc.hh:294 opFunc(op))
/// INT_SCARRY push route: PrintC::opIntScarry — opFunc `SCARRY<insize>`.
pub fn push_int_scarry(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_scarry(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:475 TypeOpIntSborrow::push
// (`{ lng->opIntSborrow(op); }` → printc.hh:295 opFunc(op))
/// INT_SBORROW push route: PrintC::opIntSborrow — opFunc `SBORROW<insize>`.
pub fn push_int_sborrow(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_sborrow(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:483 TypeOpInt2Comp::push
// (`{ lng->opInt2Comp(op); }` → printc.hh:296 opUnary(&unary_minus,op))
/// INT_2COMP push route: PrintC::opInt2Comp — unary_minus token.
pub fn push_int_2comp(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_2comp(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:491 TypeOpIntNegate::push
// (`{ lng->opIntNegate(op); }` → printc.hh:297 opUnary(&bitwise_not,op))
/// INT_NEGATE push route: PrintC::opIntNegate — bitwise_not token.
pub fn push_int_negate(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_negate(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:502 TypeOpIntXor::push
// (`{ lng->opIntXor(op); }` → printc.hh:298 opBinary(&bitwise_xor,op))
/// INT_XOR push route: PrintC::opIntXor — bitwise_xor "^" (id 15).
pub fn push_int_xor(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_xor(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:512 TypeOpIntAnd::push
// (`{ lng->opIntAnd(op); }` → printc.hh:299 opBinary(&bitwise_and,op))
/// INT_AND push route: PrintC::opIntAnd — bitwise_and "&" (id 14).
pub fn push_int_and(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_and(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:522 TypeOpIntOr::push
// (`{ lng->opIntOr(op); }` → printc.hh:300 opBinary(&bitwise_or,op))
/// INT_OR push route: PrintC::opIntOr — bitwise_or "|" (id 16).
pub fn push_int_or(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_or(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:529 TypeOpIntLeft::push
// (`{ lng->opIntLeft(op); }` → printc.hh:301 opBinary(&shift_left,op))
/// INT_LEFT push route: PrintC::opIntLeft — shift_left "<<" (id 5).
pub fn push_int_left(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_left(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:538 TypeOpIntRight::push
// (`{ lng->opIntRight(op); }` → printc.hh:302 opBinary(&shift_right,op))
/// INT_RIGHT push route: PrintC::opIntRight — shift_right ">>" (id 6).
pub fn push_int_right(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_right(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:548 TypeOpIntSright::push
// (`{ lng->opIntSright(op); }` → printc.hh:303 opBinary(&shift_sright,op))
/// INT_SRIGHT push route: PrintC::opIntSright — shift_sright (id 7, the
/// distinct signed static instance; prints the same ">>").
pub fn push_int_sright(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_sright(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:559 TypeOpIntMult::push
// (`{ lng->opIntMult(op); }` → printc.hh:304 opBinary(&multiply,op))
/// INT_MULT push route: PrintC::opIntMult — multiply "*" (id 0).
pub fn push_int_mult(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_mult(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:567 TypeOpIntDiv::push
// (`{ lng->opIntDiv(op); }` → printc.hh:305 opBinary(&divide,op))
/// INT_DIV push route: PrintC::opIntDiv — divide "/" (id 1).
pub fn push_int_div(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_div(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:575 TypeOpIntSdiv::push
// (`{ lng->opIntSdiv(op); }` → printc.hh:306 opBinary(&divide,op))
/// INT_SDIV push route: PrintC::opIntSdiv — the same divide static instance.
pub fn push_int_sdiv(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_sdiv(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:583 TypeOpIntRem::push
// (`{ lng->opIntRem(op); }` → printc.hh:307 opBinary(&modulo,op))
/// INT_REM push route: PrintC::opIntRem — modulo "%" (id 2).
pub fn push_int_rem(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_rem(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:591 TypeOpIntSrem::push
// (`{ lng->opIntSrem(op); }` → printc.hh:308 opBinary(&modulo,op))
/// INT_SREM push route: PrintC::opIntSrem — the same modulo static instance.
pub fn push_int_srem(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_int_srem(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:599 TypeOpBoolNegate::push
// (`{ lng->opBoolNegate(op); }` → printc.cc:814 body)
/// BOOL_NEGATE push route: PrintC::opBoolNegate — the full three-branch
/// negation chain (negatetoken consume / flip / boolean_not token).
pub fn push_bool_negate(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_bool_negate_rpn(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:606 TypeOpBoolXor::push
// (`{ lng->opBoolXor(op); }` → printc.hh:310 opBinary(&boolean_xor,op))
/// BOOL_XOR push route: PrintC::opBoolXor — boolean_xor "^^" (id 18).
pub fn push_bool_xor(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_bool_xor(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:613 TypeOpBoolAnd::push
// (`{ lng->opBoolAnd(op); }` → printc.hh:311 opBinary(&boolean_and,op))
/// BOOL_AND push route: PrintC::opBoolAnd — boolean_and "&&" (id 17).
pub fn push_bool_and(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_bool_and(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:620 TypeOpBoolOr::push
// (`{ lng->opBoolOr(op); }` → printc.hh:312 opBinary(&boolean_or,op))
/// BOOL_OR push route: PrintC::opBoolOr — boolean_or "||" (id 19).
pub fn push_bool_or(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_bool_or(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:627 TypeOpFloatEqual::push
// (`{ lng->opFloatEqual(op); }` → printc.hh:313 opBinary(&equal,op))
/// FLOAT_EQUAL push route: PrintC::opFloatEqual — equal token (id 12).
pub fn push_float_equal(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_equal(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:634 TypeOpFloatNotEqual::push
// (`{ lng->opFloatNotEqual(op); }` → printc.hh:314 opBinary(&not_equal,op))
/// FLOAT_NOTEQUAL push route: PrintC::opFloatNotEqual — not_equal (id 13).
pub fn push_float_not_equal(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_not_equal(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:641 TypeOpFloatLess::push
// (`{ lng->opFloatLess(op); }` → printc.hh:315 opBinary(&less_than,op))
/// FLOAT_LESS push route: PrintC::opFloatLess — less_than (id 8).
pub fn push_float_less(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_less(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:648 TypeOpFloatLessEqual::push
// (`{ lng->opFloatLessEqual(op); }` → printc.hh:316 opBinary(&less_equal,op))
/// FLOAT_LESSEQUAL push route: PrintC::opFloatLessEqual — less_equal (id 9).
pub fn push_float_less_equal(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_less_equal(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:655 TypeOpFloatNan::push
// (`{ lng->opFloatNan(op); }` → printc.hh:317 opFunc(op))
/// FLOAT_NAN push route: PrintC::opFloatNan — opFunc "NAN".
pub fn push_float_nan(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_nan(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:662 TypeOpFloatAdd::push
// (`{ lng->opFloatAdd(op); }` → printc.hh:318 opBinary(&binary_plus,op))
/// FLOAT_ADD push route: PrintC::opFloatAdd — binary_plus (id 3).
pub fn push_float_add(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_add(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:669 TypeOpFloatDiv::push
// (`{ lng->opFloatDiv(op); }` → printc.hh:319 opBinary(&divide,op))
/// FLOAT_DIV push route: PrintC::opFloatDiv — divide (id 1).
pub fn push_float_div(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_div(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:676 TypeOpFloatMult::push
// (`{ lng->opFloatMult(op); }` → printc.hh:320 opBinary(&multiply,op))
/// FLOAT_MULT push route: PrintC::opFloatMult — multiply (id 0).
pub fn push_float_mult(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_mult(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:683 TypeOpFloatSub::push
// (`{ lng->opFloatSub(op); }` → printc.hh:321 opBinary(&binary_minus,op))
/// FLOAT_SUB push route: PrintC::opFloatSub — binary_minus (id 4).
pub fn push_float_sub(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_sub(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:690 TypeOpFloatNeg::push
// (`{ lng->opFloatNeg(op); }` → printc.hh:322 opUnary(&unary_minus,op))
/// FLOAT_NEG push route: PrintC::opFloatNeg — unary_minus token.
pub fn push_float_neg(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_neg(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:697 TypeOpFloatAbs::push
// (`{ lng->opFloatAbs(op); }` → printc.hh:323 opFunc(op))
/// FLOAT_ABS push route: PrintC::opFloatAbs — opFunc "ABS"
/// (typeop.cc:1823 ctor name).
pub fn push_float_abs(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_abs(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:704 TypeOpFloatSqrt::push
// (`{ lng->opFloatSqrt(op); }` → printc.hh:324 opFunc(op))
/// FLOAT_SQRT push route: PrintC::opFloatSqrt — opFunc "SQRT"
/// (typeop.cc:1831 ctor name).
pub fn push_float_sqrt(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_sqrt(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:712 TypeOpFloatInt2Float::push
// (`{ lng->opFloatInt2Float(op); }` → printc.cc:830 body)
/// FLOAT_INT2FLOAT push route: PrintC::opFloatInt2Float — absorbZext +
/// `(float)x` typecast form.
pub fn push_float_int2float(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_int2float_rpn(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:721 TypeOpFloatFloat2Float::push
// (`{ lng->opFloatFloat2Float(op); }` → printc.hh:326 opTypeCast(op))
/// FLOAT_FLOAT2FLOAT push route: PrintC::opFloatFloat2Float — plain
/// `(type)input` cast.
pub fn push_float_float2float(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_float2float_rpn(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:728 TypeOpFloatTrunc::push
// (`{ lng->opFloatTrunc(op); }` → printc.hh:327 opTypeCast(op))
/// FLOAT_TRUNC push route: PrintC::opFloatTrunc — plain `(type)input` cast.
pub fn push_float_trunc(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_trunc_rpn(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:735 TypeOpFloatCeil::push
// (`{ lng->opFloatCeil(op); }` → printc.hh:328 opFunc(op))
/// FLOAT_CEIL push route: PrintC::opFloatCeil — opFunc "CEIL"
/// (typeop.cc:1920 ctor name).
pub fn push_float_ceil(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_ceil(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:742 TypeOpFloatFloor::push
// (`{ lng->opFloatFloor(op); }` → printc.hh:329 opFunc(op))
/// FLOAT_FLOOR push route: PrintC::opFloatFloor — opFunc "FLOOR"
/// (typeop.cc:1928 ctor name).
pub fn push_float_floor(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_floor(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:749 TypeOpFloatRound::push
// (`{ lng->opFloatRound(op); }` → printc.hh:330 opFunc(op))
/// FLOAT_ROUND push route: PrintC::opFloatRound — opFunc "ROUND"
/// (typeop.cc:1936 ctor name).
pub fn push_float_round(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_float_round(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:784 TypeOpPiece::push
// (`{ lng->opPiece(op); }` → printc.hh:333 opFunc(op))
/// PIECE push route: PrintC::opPiece — opFunc `CONCAT<sz0><sz1>`
/// (typeop.cc:2048-2056 getOperatorName).
pub fn push_piece(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_piece(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:799 TypeOpSubpiece::push
// (`{ lng->opSubpiece(op); }` → printc.cc:843 body)
/// SUBPIECE push route: PrintC::opSubpiece — field-extraction / cast / func
/// ladder.
pub fn push_subpiece(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_subpiece_virtual_rpn(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:823 TypeOpPtradd::push
// (`{ lng->opPtradd(op); }` → printc.cc:880 body)
/// PTRADD push route: PrintC::opPtradd — subscript/binary_plus decision.
/// This closes the table gap the legacy `PcodeOp::push` wrapper registered
/// ("Rudra's typeop.rs push dispatch table lacks the PTRADD arm", printc.rs
/// emit_expression comment): the RPN transport now routes through here.
pub fn push_ptradd(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_ptradd_rpn(op_arc, op),
        None => lng.op_binary(op),
    }
}

// Ghidra: typeop.hh:905 TypeOpPopcount::push
// (`{ lng->opPopcountOp(op); }` → printc.hh:343 opFunc(op))
/// POPCOUNT push route: PrintC::opPopcountOp — opFunc "POPCOUNT"
/// (typeop.cc:2558 ctor name).
pub fn push_popcount(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_popcount(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:912 TypeOpLzcount::push
// (`{ lng->opLzcountOp(op); }` → printc.hh:344 opFunc(op))
/// LZCOUNT push route: PrintC::opLzcountOp — opFunc "LZCOUNT"
/// (typeop.cc:2565 ctor name).
pub fn push_lzcount(lng: &mut dyn PrintLanguage, op_arc: &OpArcRef, op: &PcodeOp) {
    match as_printc_mut(lng) {
        Some(printc) => printc.op_lzcount(op_arc, op),
        None => lng.op_unary(op),
    }
}

// Ghidra: typeop.hh:170 TypeOp::push (virtual dispatch through the
// registerInstructions inst table, typeop.cc:24-119)
/// Opcode → per-op push routing: the Rust twin of Ghidra's
/// `op->getOpcode()->push(lng, op, readOp)` virtual dispatch. Returns
/// `true` when the opcode was routed (one of the 53 carried TypeOp push
/// entries), `false` when the caller must keep its own local arm (the
/// ops whose PrintC emitters are NOT TypeOpX::push one-liners: COPY, LOAD,
/// STORE, CALL, CALLIND, CALLOTHER, RETURN, CBRANCH, CAST, PTRSUB — plus
/// the empty push bodies MULTIEQUAL/INDIRECT which printc.hh:331-332
/// defines as `{}`, carried by dispatch_op_rpn's no-op fallthrough).
// RUDRA-GLUE: Ghidra dispatches through the TypeOp* inst table held by the
//   TypeFactory; PrintC has no Architecture/TypeFactory plumbing to reach
//   constructed instances, and no push body reads instance state, so the
//   table is a static per-opcode match to the free per-op routes above.
pub fn push_opcode_rpn(
    lng: &mut dyn PrintLanguage,
    op_arc: &OpArcRef,
    op: &PcodeOp,
    read_op: Option<&OpArcRef>,
) -> bool {
    match op.opcode {
        // Ghidra: typeop.hh:359 TypeOpEqual::push
        OpCode::CPUI_INT_EQUAL => push_int_equal(lng, op_arc, op),
        // Ghidra: typeop.hh:371 TypeOpNotEqual::push
        OpCode::CPUI_INT_NOTEQUAL => push_int_not_equal(lng, op_arc, op),
        // Ghidra: typeop.hh:384 TypeOpIntSless::push
        OpCode::CPUI_INT_SLESS => push_int_sless(lng, op_arc, op),
        // Ghidra: typeop.hh:394 TypeOpIntSlessEqual::push
        OpCode::CPUI_INT_SLESSEQUAL => push_int_sless_equal(lng, op_arc, op),
        // Ghidra: typeop.hh:401 TypeOpIntLess::push
        OpCode::CPUI_INT_LESS => push_int_less(lng, op_arc, op),
        // Ghidra: typeop.hh:411 TypeOpIntLessEqual::push
        OpCode::CPUI_INT_LESSEQUAL => push_int_less_equal(lng, op_arc, op),
        // Ghidra: typeop.hh:421 TypeOpIntZext::push
        OpCode::CPUI_INT_ZEXT => push_int_zext(lng, op_arc, op, read_op),
        // Ghidra: typeop.hh:430 TypeOpIntSext::push
        OpCode::CPUI_INT_SEXT => push_int_sext(lng, op_arc, op, read_op),
        // Ghidra: typeop.hh:439 TypeOpIntAdd::push
        OpCode::CPUI_INT_ADD => push_int_add(lng, op_arc, op),
        // Ghidra: typeop.hh:451 TypeOpIntSub::push
        OpCode::CPUI_INT_SUB => push_int_sub(lng, op_arc, op),
        // Ghidra: typeop.hh:459 TypeOpIntCarry::push
        OpCode::CPUI_INT_CARRY => push_int_carry(lng, op_arc, op),
        // Ghidra: typeop.hh:467 TypeOpIntScarry::push
        OpCode::CPUI_INT_SCARRY => push_int_scarry(lng, op_arc, op),
        // Ghidra: typeop.hh:475 TypeOpIntSborrow::push
        OpCode::CPUI_INT_SBORROW => push_int_sborrow(lng, op_arc, op),
        // Ghidra: typeop.hh:483 TypeOpInt2Comp::push
        OpCode::CPUI_INT_2COMP => push_int_2comp(lng, op_arc, op),
        // Ghidra: typeop.hh:491 TypeOpIntNegate::push
        OpCode::CPUI_INT_NEGATE => push_int_negate(lng, op_arc, op),
        // Ghidra: typeop.hh:502 TypeOpIntXor::push
        OpCode::CPUI_INT_XOR => push_int_xor(lng, op_arc, op),
        // Ghidra: typeop.hh:512 TypeOpIntAnd::push
        OpCode::CPUI_INT_AND => push_int_and(lng, op_arc, op),
        // Ghidra: typeop.hh:522 TypeOpIntOr::push
        OpCode::CPUI_INT_OR => push_int_or(lng, op_arc, op),
        // Ghidra: typeop.hh:529 TypeOpIntLeft::push
        OpCode::CPUI_INT_LEFT => push_int_left(lng, op_arc, op),
        // Ghidra: typeop.hh:538 TypeOpIntRight::push
        OpCode::CPUI_INT_RIGHT => push_int_right(lng, op_arc, op),
        // Ghidra: typeop.hh:548 TypeOpIntSright::push
        OpCode::CPUI_INT_SRIGHT => push_int_sright(lng, op_arc, op),
        // Ghidra: typeop.hh:559 TypeOpIntMult::push
        OpCode::CPUI_INT_MULT => push_int_mult(lng, op_arc, op),
        // Ghidra: typeop.hh:567 TypeOpIntDiv::push
        OpCode::CPUI_INT_DIV => push_int_div(lng, op_arc, op),
        // Ghidra: typeop.hh:575 TypeOpIntSdiv::push
        OpCode::CPUI_INT_SDIV => push_int_sdiv(lng, op_arc, op),
        // Ghidra: typeop.hh:583 TypeOpIntRem::push
        OpCode::CPUI_INT_REM => push_int_rem(lng, op_arc, op),
        // Ghidra: typeop.hh:591 TypeOpIntSrem::push
        OpCode::CPUI_INT_SREM => push_int_srem(lng, op_arc, op),
        // Ghidra: typeop.hh:599 TypeOpBoolNegate::push
        OpCode::CPUI_BOOL_NEGATE => push_bool_negate(lng, op_arc, op),
        // Ghidra: typeop.hh:606 TypeOpBoolXor::push
        OpCode::CPUI_BOOL_XOR => push_bool_xor(lng, op_arc, op),
        // Ghidra: typeop.hh:613 TypeOpBoolAnd::push
        OpCode::CPUI_BOOL_AND => push_bool_and(lng, op_arc, op),
        // Ghidra: typeop.hh:620 TypeOpBoolOr::push
        OpCode::CPUI_BOOL_OR => push_bool_or(lng, op_arc, op),
        // Ghidra: typeop.hh:627 TypeOpFloatEqual::push
        OpCode::CPUI_FLOAT_EQUAL => push_float_equal(lng, op_arc, op),
        // Ghidra: typeop.hh:634 TypeOpFloatNotEqual::push
        OpCode::CPUI_FLOAT_NOTEQUAL => push_float_not_equal(lng, op_arc, op),
        // Ghidra: typeop.hh:641 TypeOpFloatLess::push
        OpCode::CPUI_FLOAT_LESS => push_float_less(lng, op_arc, op),
        // Ghidra: typeop.hh:648 TypeOpFloatLessEqual::push
        OpCode::CPUI_FLOAT_LESSEQUAL => push_float_less_equal(lng, op_arc, op),
        // Ghidra: typeop.hh:655 TypeOpFloatNan::push
        OpCode::CPUI_FLOAT_NAN => push_float_nan(lng, op_arc, op),
        // Ghidra: typeop.hh:662 TypeOpFloatAdd::push
        OpCode::CPUI_FLOAT_ADD => push_float_add(lng, op_arc, op),
        // Ghidra: typeop.hh:669 TypeOpFloatDiv::push
        OpCode::CPUI_FLOAT_DIV => push_float_div(lng, op_arc, op),
        // Ghidra: typeop.hh:676 TypeOpFloatMult::push
        OpCode::CPUI_FLOAT_MULT => push_float_mult(lng, op_arc, op),
        // Ghidra: typeop.hh:683 TypeOpFloatSub::push
        OpCode::CPUI_FLOAT_SUB => push_float_sub(lng, op_arc, op),
        // Ghidra: typeop.hh:690 TypeOpFloatNeg::push
        OpCode::CPUI_FLOAT_NEG => push_float_neg(lng, op_arc, op),
        // Ghidra: typeop.hh:697 TypeOpFloatAbs::push
        OpCode::CPUI_FLOAT_ABS => push_float_abs(lng, op_arc, op),
        // Ghidra: typeop.hh:704 TypeOpFloatSqrt::push
        OpCode::CPUI_FLOAT_SQRT => push_float_sqrt(lng, op_arc, op),
        // Ghidra: typeop.hh:712 TypeOpFloatInt2Float::push
        OpCode::CPUI_FLOAT_INT2FLOAT => push_float_int2float(lng, op_arc, op),
        // Ghidra: typeop.hh:721 TypeOpFloatFloat2Float::push
        OpCode::CPUI_FLOAT_FLOAT2FLOAT => push_float_float2float(lng, op_arc, op),
        // Ghidra: typeop.hh:728 TypeOpFloatTrunc::push
        OpCode::CPUI_FLOAT_TRUNC => push_float_trunc(lng, op_arc, op),
        // Ghidra: typeop.hh:735 TypeOpFloatCeil::push
        OpCode::CPUI_FLOAT_CEIL => push_float_ceil(lng, op_arc, op),
        // Ghidra: typeop.hh:742 TypeOpFloatFloor::push
        OpCode::CPUI_FLOAT_FLOOR => push_float_floor(lng, op_arc, op),
        // Ghidra: typeop.hh:749 TypeOpFloatRound::push
        OpCode::CPUI_FLOAT_ROUND => push_float_round(lng, op_arc, op),
        // Ghidra: typeop.hh:784 TypeOpPiece::push
        OpCode::CPUI_PIECE => push_piece(lng, op_arc, op),
        // Ghidra: typeop.hh:799 TypeOpSubpiece::push
        OpCode::CPUI_SUBPIECE => push_subpiece(lng, op_arc, op),
        // Ghidra: typeop.hh:823 TypeOpPtradd::push
        OpCode::CPUI_PTRADD => push_ptradd(lng, op_arc, op),
        // Ghidra: typeop.hh:905 TypeOpPopcount::push
        OpCode::CPUI_POPCOUNT => push_popcount(lng, op_arc, op),
        // Ghidra: typeop.hh:912 TypeOpLzcount::push
        OpCode::CPUI_LZCOUNT => push_lzcount(lng, op_arc, op),
        _ => return false,
    }
    true
}

impl crate::op::PcodeOp {
    /// Push this operation to a language printer
    // RUDRA-GLUE: convenience wrapper that dispatches by opcode; in Ghidra the
    //   per-op push lives on the TypeOp subclass (typeop.hh:170 push), and
    //   PcodeOp has no push method of its own (it forwards via opcode->push).
    pub fn push(&self, lng: &mut dyn PrintLanguage) {
        // RUDRA-GLUE: this wrapper mirrors the per-opcode `TypeOp*::push`
        //   routing defined above (and in Ghidra typeop.hh:261..). The opcodes
        //   whose PrintC emitter is an inherent method on `PrintC`
        //   (`op_callind`, `op_ptrsub`, `op_callother`, `op_new`, `op_insert`,
        //   `op_extract`, `op_cpoolref`, `op_segment`, `op_type_cast`) are
        //   reached via the `as_printc_mut` down-cast; everything else uses the
        //   `PrintLanguage` trait emitters (`op_copy`, `op_load`, ...).
        //   CALL is correctly handled by the trait `op_call`; only CALLIND
        //   needs the PrintC-specific path. See the per-opcode `push` overrides
        //   on `TypeOpCallind`/`TypeOpPtrsub`/... for the authoritative
        //   Ghidra-cited routing.
        match self.opcode {
            OpCode::CPUI_COPY => lng.op_copy(self),
            OpCode::CPUI_LOAD => lng.op_load(self),
            OpCode::CPUI_STORE => lng.op_store(self),
            OpCode::CPUI_MULTIEQUAL => lng.op_multiequal(self),
            OpCode::CPUI_INDIRECT => lng.op_indirect(self),
            // Ghidra: TypeOpCall::push -> opCall; TypeOpCallind::push -> opCallind.
            // CALL stays on the trait emitter; CALLIND needs the PrintC path.
            OpCode::CPUI_CALL => lng.op_call(self),
            OpCode::CPUI_CALLIND => match as_printc_mut(lng) {
                Some(printc) => printc.op_callind(self),
                None => lng.op_call(self),
            },
            OpCode::CPUI_RETURN => lng.op_return(self),
            OpCode::CPUI_CBRANCH => lng.op_cbranch(self),
            OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND => lng.op_branch(self),
            // Unary ops (Ghidra TypeOpUnary/TypeOpFunc subclasses)
            OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_INT_NEGATE
            | OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT
            | OpCode::CPUI_INT_ZEXT
            | OpCode::CPUI_INT_SEXT => lng.op_unary(self),
            // PrintC-specific emitters (no PrintLanguage trait method).
            // Routed via down-cast with an `op_binary` fallback for non-PrintC
            // languages, matching the per-opcode `TypeOp*::push` overrides.
            OpCode::CPUI_PTRSUB => match as_printc_mut(lng) {
                Some(printc) => printc.op_ptrsub(self),
                None => lng.op_binary(self),
            },
            OpCode::CPUI_CALLOTHER => match as_printc_mut(lng) {
                Some(printc) => printc.op_callother(self),
                None => lng.op_binary(self),
            },
            OpCode::CPUI_NEW => match as_printc_mut(lng) {
                Some(printc) => printc.op_new(self),
                None => lng.op_binary(self),
            },
            OpCode::CPUI_INSERT => match as_printc_mut(lng) {
                Some(printc) => printc.op_insert(self),
                None => lng.op_binary(self),
            },
            OpCode::CPUI_EXTRACT => match as_printc_mut(lng) {
                Some(printc) => printc.op_extract(self),
                None => lng.op_binary(self),
            },
            OpCode::CPUI_CPOOLREF => match as_printc_mut(lng) {
                Some(printc) => printc.op_cpoolref(self),
                None => lng.op_binary(self),
            },
            OpCode::CPUI_SEGMENTOP => match as_printc_mut(lng) {
                Some(printc) => printc.op_segment(self),
                None => lng.op_binary(self),
            },
            OpCode::CPUI_CAST => match as_printc_mut(lng) {
                Some(printc) => printc.op_type_cast(self),
                None => lng.op_binary(self),
            },
            // Default to binary for all other ops
            _ => lng.op_binary(self),
        }
    }
}

// ---------------------------------------------------------------------------
// TypeOp::evaluateUnary / TypeOp::evaluateBinary bridge (typeop.hh:81-92).
//
// In Ghidra, `PcodeOp::collapse` (op.cc:450-472) calls
// `opcode->evaluateUnary/evaluateBinary` — where `opcode` is the op's TypeOp*
// — and those inline methods (typeop.hh:81-92) delegate directly to the
// OpBehavior object (`behave->evaluateUnary/evaluateBinary`). Rudra has no
// per-op TypeOp instance, so this module-level bridge plays that role:
// integer/bool/piece arms delegate to the `opbehavior` free functions
// (opbehavior.cc:171-792), and the FLOAT_* arms perform the
// `OpBehaviorFloat*::evaluate*` dispatch (opbehavior.cc:569-750), including
// the `translate->getFloatFormat(size)` lookup whose null case is the C++
// base-class LowlevelError ("Unary/Binary emulation unimplemented").
// `None` here encodes "Ghidra throws LowlevelError/EvaluationError", which
// `RuleCollapseConstants::applyOp` maps to `opMarkNoCollapse`
// (ruleaction.cc:3867-3870).
// ---------------------------------------------------------------------------

// Ghidra: typeop.hh:81 TypeOp::evaluateUnary
/// TypeOp evaluate bridge for unary constant folding. Faithful to
/// `TypeOp::evaluateUnary(int4 sizeout,int4 sizein,uintb in1)`
/// (typeop.hh:81-82): delegates to the OpBehavior layer. FLOAT_* arms
/// reproduce `OpBehaviorFloat*::evaluateUnary` (opbehavior.cc:609-750):
/// the FloatFormat is looked up by input size (output size for
/// INT2FLOAT/FLOAT2FLOAT); a missing format yields `None` (the C++
/// LowlevelError path). The final `calc_mask(size_out)` keeps the
/// free-function sizing contract and implements `FloatFormat::opTrunc`'s
// own `res &= calc_mask(sizeout)` (float.cc:638).
pub fn evaluate_unary(opc: OpCode, size_out: usize, size_in: usize, in1: u64) -> Option<u64> {
    use crate::opbehavior::float_format;
    let result = match opc {
        // Ghidra: opbehavior.cc:609 OpBehaviorFloatNan::evaluateUnary
        OpCode::CPUI_FLOAT_NAN => float_format(size_in)?.op_nan(in1),
        // Ghidra: opbehavior.cc:659 OpBehaviorFloatNeg::evaluateUnary
        OpCode::CPUI_FLOAT_NEG => float_format(size_in)?.op_neg(in1),
        // Ghidra: opbehavior.cc:669 OpBehaviorFloatAbs::evaluateUnary
        OpCode::CPUI_FLOAT_ABS => float_format(size_in)?.op_abs(in1),
        // Ghidra: opbehavior.cc:679 OpBehaviorFloatSqrt::evaluateUnary
        OpCode::CPUI_FLOAT_SQRT => float_format(size_in)?.op_sqrt(in1),
        // Ghidra: opbehavior.cc:722 OpBehaviorFloatCeil::evaluateUnary
        OpCode::CPUI_FLOAT_CEIL => float_format(size_in)?.op_ceil(in1),
        // Ghidra: opbehavior.cc:732 OpBehaviorFloatFloor::evaluateUnary
        OpCode::CPUI_FLOAT_FLOOR => float_format(size_in)?.op_floor(in1),
        // Ghidra: opbehavior.cc:742 OpBehaviorFloatRound::evaluateUnary
        OpCode::CPUI_FLOAT_ROUND => float_format(size_in)?.op_round(in1),
        // Ghidra: opbehavior.cc:689 OpBehaviorFloatInt2Float::evaluateUnary
        // (format lookup is by *output* size — the output is the float)
        OpCode::CPUI_FLOAT_INT2FLOAT => float_format(size_out)?.op_int2float(in1, size_in),
        // Ghidra: opbehavior.cc:699 OpBehaviorFloatFloat2Float::evaluateUnary
        // (formatout then formatin; either missing is the error path)
        OpCode::CPUI_FLOAT_FLOAT2FLOAT => {
            let formatout = float_format(size_out)?;
            let formatin = float_format(size_in)?;
            formatin.op_float2_float(in1, formatout)
        }
        // Ghidra: opbehavior.cc:712 OpBehaviorFloatTrunc::evaluateUnary
        OpCode::CPUI_FLOAT_TRUNC => float_format(size_in)?.op_trunc(in1, size_out),
        // All non-float unary opcodes (COPY/ZEXT/SEXT/2COMP/NEGATE/
        // BOOL_NEGATE/POPCOUNT/LZCOUNT) delegate to the OpBehavior table.
        _ => return crate::opbehavior::evaluate_unary(opc, size_out, size_in, in1),
    };
    Some(result & calc_mask(size_out))
}

// Ghidra: typeop.hh:91 TypeOp::evaluateBinary
/// TypeOp evaluate bridge for binary constant folding. Faithful to
/// `TypeOp::evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2)`
/// (typeop.hh:91-92): delegates to the OpBehavior layer. FLOAT_* arms
/// reproduce `OpBehaviorFloat*::evaluateBinary` (opbehavior.cc:569-657):
/// the FloatFormat is looked up by input size; a missing format yields
/// `None` (the C++ LowlevelError path).
pub fn evaluate_binary(
    opc: OpCode,
    size_out: usize,
    size_in: usize,
    in1: u64,
    in2: u64,
) -> Option<u64> {
    use crate::opbehavior::float_format;
    let result = match opc {
        // Ghidra: opbehavior.cc:569 OpBehaviorFloatEqual::evaluateBinary
        OpCode::CPUI_FLOAT_EQUAL => float_format(size_in)?.op_equal(in1, in2),
        // Ghidra: opbehavior.cc:579 OpBehaviorFloatNotEqual::evaluateBinary
        OpCode::CPUI_FLOAT_NOTEQUAL => float_format(size_in)?.op_not_equal(in1, in2),
        // Ghidra: opbehavior.cc:589 OpBehaviorFloatLess::evaluateBinary
        OpCode::CPUI_FLOAT_LESS => float_format(size_in)?.op_less(in1, in2),
        // Ghidra: opbehavior.cc:599 OpBehaviorFloatLessEqual::evaluateBinary
        OpCode::CPUI_FLOAT_LESSEQUAL => float_format(size_in)?.op_less_equal(in1, in2),
        // Ghidra: opbehavior.cc:619 OpBehaviorFloatAdd::evaluateBinary
        OpCode::CPUI_FLOAT_ADD => float_format(size_in)?.op_add(in1, in2),
        // Ghidra: opbehavior.cc:629 OpBehaviorFloatDiv::evaluateBinary
        OpCode::CPUI_FLOAT_DIV => float_format(size_in)?.op_div(in1, in2),
        // Ghidra: opbehavior.cc:639 OpBehaviorFloatMult::evaluateBinary
        OpCode::CPUI_FLOAT_MULT => float_format(size_in)?.op_mult(in1, in2),
        // Ghidra: opbehavior.cc:649 OpBehaviorFloatSub::evaluateBinary
        OpCode::CPUI_FLOAT_SUB => float_format(size_in)?.op_sub(in1, in2),
        // All non-float binary opcodes (INT_*/BOOL_*/PIECE/SUBPIECE)
        // delegate to the OpBehavior table.
        _ => return crate::opbehavior::evaluate_binary(opc, size_out, size_in, in1, in2),
    };
    Some(result & calc_mask(size_out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, SeqNum};
    use crate::type_system::datatype::{TypeField, TypePointer, TypeStruct};
    use crate::type_system::TypeBase;
    use crate::varnode::{varnode_flags, Varnode};
    use std::sync::{Arc, RwLock};

    /// Build a typed varnode with the given data-type.
    fn typed_vn(size: usize, offset: u64, dt: Option<Arc<Datatype>>) -> Arc<RwLock<Varnode>> {
        let mut vn = Varnode::new(size, Address::new(offset));
        vn.v_type = dt;
        Arc::new(RwLock::new(vn))
    }

    fn pcodeop(opcode: OpCode) -> PcodeOp {
        PcodeOp::new(SeqNum::new(Address::new(0), 0), opcode)
    }

    /// Wrap a plain unit-fixture op into a `PcodeOpRef` for the fd-carrying
    /// trait dispatch forms.
    fn op_ref(op: PcodeOp) -> crate::op::PcodeOpRef {
        crate::op::PcodeOpRef(Arc::new(RwLock::new(op)))
    }

    /// Detached Funcdata (empty union map) for fd-carrying calls from unit
    /// fixtures — the union consult then observes exactly the map-miss arm,
    /// matching the detached-fixture semantics documented on the degenerate
    /// Varnode methods (varnode.rs).
    fn detached_fd() -> crate::funcdata::Funcdata {
        crate::funcdata::Funcdata::new("t", Address::new(0x1000), 0)
    }

    #[test]
    fn float_int2float_input_cast_absorbs_zext_and_tracks_high_bit() {
        use crate::varnode::varnode_flags;
        // typeop.cc:1847-1862.
        let f2i = TypeOpFloatInt2Float::new(raw_factory());
        // absorbZext (cc:1850-1851): an implied INT_ZEXT output feeding the
        // conversion never takes a cast.
        let mut zext = pcodeop(OpCode::CPUI_INT_ZEXT);
        let zext_out = typed_vn(8, 0x30, None);
        zext.output = Some(zext_out.clone());
        let zext_ref = op_ref(zext);
        // cc:1876: vn0->isWritten() && vn0->isImplied() — the Rust
        // is_written reads the WRITTEN flag (opSetOutput sets flag+def
        // together); the def link mirrors the defining-op edge the oracle
        // reads through vn0->getDef().
        zext_out
            .write()
            .unwrap()
            .set_flags(varnode_flags::WRITTEN | varnode_flags::IMPLIED);
        zext_out
            .write()
            .unwrap()
            .def
            .replace(std::sync::Arc::downgrade(&zext_ref.0));
        let mut op = pcodeop(OpCode::CPUI_FLOAT_INT2FLOAT);
        op.inrefs.push(zext_out);
        op.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(0, 1))));
        let op_r = op_ref(op);
        assert!(f2i.get_input_cast(&op_r, 0, &detached_fd()).is_none());
        // The absorb predicate itself (cc:1872-1883).
        assert!(float_int2float_absorb_zext(&op_r));

        // care_uint_int (cc:1855-1860): a 4-byte input whose NZMask cannot
        // carry the high bit drops the signed/unsigned distinction — an
        // uint-typed current type under the int base is cast-free. A
        // high-bit-capable input (constant with bit 31 set) keeps it: the
        // uint current type takes the int base cast.
        let uint4 = Arc::new(Datatype::Base(TypeBase::new(
            "uint".into(), 4, TypeMetatype::Uint,
        )));
        let mut plain = pcodeop(OpCode::CPUI_FLOAT_INT2FLOAT);
        plain.inrefs.push(typed_vn(4, 0x10, Some(uint4.clone())));
        plain.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(0, 1))));
        // Non-constant input with no NZMask constraint (high bit possible):
        // care stays TRUE -> uint under int base takes the cast.
        let cast = f2i
            .get_input_cast(&op_ref(plain), 0, &detached_fd())
            .expect("high-bit-capable uint takes the int base cast");
        assert_eq!(cast.get_metatype(), TypeMetatype::Int);

        // A constant whose NZMask high bit is clear drops care_uint_int —
        // the uint current type becomes cast-free under the int base
        // (cc:1858-1859 shift reads the constant's NZMask).
        let mut const_op = pcodeop(OpCode::CPUI_FLOAT_INT2FLOAT);
        const_op.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(0x7f, 4))));
        const_op.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(0, 1))));
        assert!(f2i
            .get_input_cast(&op_ref(const_op), 0, &detached_fd())
            .is_none());
    }

    #[test]
    fn extension_input_cast_forces_under_mismatched_promotion() {
        // typeop.cc:1131-1139/1157-1165: the extension's input takes its
        // inputTypeLocal base (ZEXT=UINT, SEXT=INT) when the promotion
        // direction mismatches, else castStandard(TRUE,FALSE).
        let zext = TypeOpIntZext::new(raw_factory());
        let sext = TypeOpIntSext::new(raw_factory());
        // A 1-byte int-typed input under ZEXT (req uint1, cur int1,
        // care_uint_int=TRUE) takes the uint base (cast.cc:352-361).
        let int1 = Arc::new(Datatype::Base(TypeBase::new(
            "int1".into(), 1, TypeMetatype::Int,
        )));
        let mut op = pcodeop(OpCode::CPUI_INT_ZEXT);
        op.inrefs.push(typed_vn(1, 0x10, Some(int1)));
        op.output = Some(typed_vn(4, 0x20, None));
        let cast = zext
            .get_input_cast(&op_ref(op), 0, &detached_fd())
            .expect("int1 under uint1 base takes the cast");
        assert_eq!(cast.get_metatype(), TypeMetatype::Uint);
        assert_eq!(cast.get_size(), 1);
        // The mirrored SEXT case: uint1 current under the int1 base.
        let mut op = pcodeop(OpCode::CPUI_INT_SEXT);
        let uint1 = Arc::new(Datatype::Base(TypeBase::new(
            "uint1".into(), 1, TypeMetatype::Uint,
        )));
        op.inrefs.push(typed_vn(1, 0x10, Some(uint1)));
        op.output = Some(typed_vn(4, 0x20, None));
        let cast = sext
            .get_input_cast(&op_ref(op), 0, &detached_fd())
            .expect("uint1 under int1 base takes the cast");
        assert_eq!(cast.get_metatype(), TypeMetatype::Int);
    }

    #[test]
    fn shift_and_divrem_input_casts_use_own_extensionGate() {
        // typeop.cc:1543-1556 INT_RIGHT slot0: promotion gate requires the
        // UNSIGNED extension; the base metain is UINT.
        let right = TypeOpIntRight::new(raw_factory());
        let mut op = pcodeop(OpCode::CPUI_INT_RIGHT);
        let uint2 = Arc::new(Datatype::Base(TypeBase::new(
            "uint2".into(), 2, TypeMetatype::Uint,
        )));
        op.inrefs.push(typed_vn(2, 0x10, Some(uint2)));
        op.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(3, 1))));
        op.output = Some(typed_vn(2, 0x20, None));
        let op_r = op_ref(op);
        // uint current under uint base is cast-free regardless of gate.
        assert!(right.get_input_cast(&op_r, 0, &detached_fd()).is_none());
        // Slot 1 (the shift amount) takes the base arm (cc:1555).
        assert!(right.get_input_cast(&op_r, 1, &detached_fd()).is_none());

        // INT_SDIV (cc:1659-1669): metain=INT; a uint-typed current takes
        // the int base with care_uint_int=TRUE.
        let sdiv = TypeOpIntSdiv::new(raw_factory());
        let mut div_op = pcodeop(OpCode::CPUI_INT_SDIV);
        let uint4 = Arc::new(Datatype::Base(TypeBase::new(
            "uint".into(), 4, TypeMetatype::Uint,
        )));
        div_op.inrefs.push(typed_vn(4, 0x10, Some(uint4)));
        div_op.inrefs.push(typed_vn(4, 0x20, Some(int_t())));
        let cast = sdiv
            .get_input_cast(&op_ref(div_op), 0, &detached_fd())
            .expect("uint under sdiv int base takes the cast");
        assert_eq!(cast.get_metatype(), TypeMetatype::Int);
        // INT_DIV (cc:1639-1649): metain=UINT; uint current is cast-free.
        let div = TypeOpIntDiv::new(raw_factory());
        let mut udiv_op = pcodeop(OpCode::CPUI_INT_DIV);
        let uint4b = Arc::new(Datatype::Base(TypeBase::new(
            "uint".into(), 4, TypeMetatype::Uint,
        )));
        udiv_op.inrefs.push(typed_vn(4, 0x10, Some(uint4b)));
        udiv_op.inrefs.push(typed_vn(4, 0x20, Some(int_t())));
        assert!(div
            .get_input_cast(&op_ref(udiv_op), 0, &detached_fd())
            .is_none());
    }

    #[test]
    fn piece_subpiece_segment_never_take_input_casts() {
        // typeop.cc:2057-2061/2136-2140/2420-2424: "Never need a cast".
        let piece = TypeOpPiece::new(raw_factory());
        let subpiece = TypeOpSubpiece::new(raw_factory());
        let segment = TypeOpSegment::new(raw_factory());
        for (op_impl, opc) in [
            (&piece as &dyn TypeOp, OpCode::CPUI_PIECE),
            (&subpiece, OpCode::CPUI_SUBPIECE),
            (&segment, OpCode::CPUI_SEGMENTOP),
        ] {
            let mut op = pcodeop(opc);
            op.inrefs.push(typed_vn(4, 0x10, Some(int_t())));
            op.inrefs.push(typed_vn(4, 0x20, Some(int_t())));
            op.output = Some(typed_vn(4, 0x30, None));
            assert!(
                op_impl.get_input_cast(&op_ref(op), 0, &detached_fd()).is_none(),
                "{:?} never casts inputs",
                opc
            );
        }
    }

    #[test]
    fn operator_names_carry_sizes() {
        // typeop.cc:1122/1148/1340/1356/1372/2048/2127 + typeop.hh:183
        // default.
        let factory = raw_factory();
        let mut zext = pcodeop(OpCode::CPUI_INT_ZEXT);
        zext.inrefs.push(typed_vn(1, 0x10, None));
        zext.output = Some(typed_vn(4, 0x20, None));
        assert_eq!(
            TypeOpIntZext::new(factory.clone()).get_operator_name(&zext),
            "ZEXT14"
        );
        assert_eq!(
            TypeOpIntSext::new(factory.clone()).get_operator_name(&zext),
            "SEXT14"
        );
        let mut carry = pcodeop(OpCode::CPUI_INT_CARRY);
        carry.inrefs.push(typed_vn(4, 0x10, None));
        carry.inrefs.push(typed_vn(4, 0x20, None));
        assert_eq!(
            TypeOpIntCarry::new(factory.clone()).get_operator_name(&carry),
            "CARRY4"
        );
        assert_eq!(
            TypeOpIntScarry::new(factory.clone()).get_operator_name(&carry),
            "SCARRY4"
        );
        assert_eq!(
            TypeOpIntSborrow::new(factory.clone()).get_operator_name(&carry),
            "SBORROW4"
        );
        let mut piece = pcodeop(OpCode::CPUI_PIECE);
        piece.inrefs.push(typed_vn(4, 0x10, None));
        piece.inrefs.push(typed_vn(4, 0x20, None));
        piece.output = Some(typed_vn(8, 0x30, None));
        assert_eq!(
            TypeOpPiece::new(factory.clone()).get_operator_name(&piece),
            "CONCAT44"
        );
        let mut sub = pcodeop(OpCode::CPUI_SUBPIECE);
        sub.inrefs.push(typed_vn(8, 0x10, None));
        sub.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(0, 1))));
        sub.output = Some(typed_vn(4, 0x30, None));
        assert_eq!(
            TypeOpSubpiece::new(factory.clone()).get_operator_name(&sub),
            "SUB84"
        );
        // Default (typeop.hh:183): the bare display name.
        assert_eq!(
            TypeOpIntAdd::new(factory.clone()).get_operator_name(&carry),
            "INT_ADD"
        );
    }

    #[test]
    fn cbranch_indirect_local_input_types() {
        // typeop.cc:609-619 Cbranch: slot 1 is the bool base; slot 0 a code
        // pointer worded by the input's space.
        let cbranch = TypeOpCbranch::new(aligned_factory());
        let mut op = pcodeop(OpCode::CPUI_CBRANCH);
        op.inrefs.push(typed_vn(8, 0x500010, None));
        op.inrefs.push(typed_vn(1, 0x1, None));
        let bool_t = cbranch
            .get_input_local(&op, 1)
            .expect("slot 1 bool base");
        assert_eq!(bool_t.get_metatype(), TypeMetatype::Bool);
        assert_eq!(bool_t.get_size(), 1);
        let code_ptr = cbranch
            .get_input_local(&op, 0)
            .expect("slot 0 code pointer");
        assert_eq!(code_ptr.get_metatype(), TypeMetatype::Pointer);
        assert_eq!(code_ptr.get_size(), 8);
        // The pointee is the code type (metatype CODE).
        match code_ptr.as_ref() {
            Datatype::Pointer(p) => assert_eq!(p.ptr_to.get_metatype(), TypeMetatype::Code),
            _ => panic!("slot 0 must be a pointer"),
        }

        // typeop.cc:1992-2003 Indirect: slot 0 base default; slot 1 code
        // pointer sized by in(0).
        let indirect = TypeOpIndirect::new(aligned_factory());
        let mut iop = pcodeop(OpCode::CPUI_INDIRECT);
        iop.inrefs.push(typed_vn(4, 0x10, None));
        iop.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(0x99, 8))));
        let base = indirect
            .get_input_local(&iop, 0)
            .expect("slot 0 base default");
        assert_eq!(base.get_metatype(), TypeMetatype::Unknown);
        let code_ptr = indirect
            .get_input_local(&iop, 1)
            .expect("slot 1 code pointer");
        assert_eq!(code_ptr.get_size(), 4);
        match code_ptr.as_ref() {
            Datatype::Pointer(p) => assert_eq!(p.ptr_to.get_metatype(), TypeMetatype::Code),
            _ => panic!("slot 1 must be a pointer"),
        }

        // typeop.cc:855-863 Callother: no descriptor table reachable from a
        // detached fixture -> the base UNKNOWN default for every slot.
        let callother = TypeOpCallother::new(aligned_factory());
        let mut cop = pcodeop(OpCode::CPUI_CALLOTHER);
        cop.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(3, 1))));
        cop.inrefs.push(typed_vn(4, 0x10, None));
        let local = callother
            .get_input_local(&cop, 1)
            .expect("callother base default");
        assert_eq!(local.get_metatype(), TypeMetatype::Unknown);
    }

    #[test]
    fn ptradd_input_cast_align_size_arm() {
        // typeop.cc:2250-2266: equal alignSize on the one-level-down bases
        // cancels the cast; different align sizes return the varnode type.
        let ptradd = TypeOpPtradd::new(raw_factory());
        let char_t = Arc::new(Datatype::Base(TypeBase::new(
            "char".into(), 1, TypeMetatype::Int,
        )));
        let int_t = int_t();
        let char_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("char *".into(), 8, TypeMetatype::Pointer),
            ptr_to: char_t.clone(),
            wordsize: 1,
        }));
        let int_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int_t.clone(),
            wordsize: 1,
        }));
        // vn type char* (alignSize 1) vs high type int* (alignSize 4):
        // different base align sizes -> the varnode type is the cast.
        let mut op = pcodeop(OpCode::CPUI_PTRADD);
        let vn = typed_vn(8, 0x10, Some(char_ptr.clone()));
        vn.write().unwrap().high = Some(high_of(int_ptr.clone()));
        op.inrefs.push(vn);
        op.inrefs.push(typed_vn(8, 0x20, None));
        op.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(1, 1))));
        let cast = ptradd
            .get_input_cast(&op_ref(op), 0, &detached_fd())
            .expect("differing align sizes force the varnode-type cast");
        assert!(Arc::ptr_eq(&cast, &char_ptr));
        // Equal bases cancel the cast.
        let vn2 = typed_vn(8, 0x30, Some(char_ptr.clone()));
        vn2.write().unwrap().high = Some(high_of(char_ptr.clone()));
        let mut op2 = pcodeop(OpCode::CPUI_PTRADD);
        op2.inrefs.push(vn2);
        op2.inrefs.push(typed_vn(8, 0x40, None));
        op2.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(1, 1))));
        let op2_r = op_ref(op2);
        assert!(ptradd.get_input_cast(&op2_r, 0, &detached_fd()).is_none());
        // Non-slot-0 takes the base arm: a typed int input under the INT
        // metain is cast-free.
        assert!(ptradd.get_input_cast(&op2_r, 1, &detached_fd()).is_none());
    }

    #[test]
    fn shift_output_tokens_demote_bool_to_int() {
        // typeop.cc:1518-1525/1558-1565/1608-1615: the token is in(0)'s
        // read-facing type with BOOL demoted to the factory INT base.
        let factory = aligned_factory();
        let left = TypeOpIntLeft::new(factory.clone());
        let mut op = pcodeop(OpCode::CPUI_INT_LEFT);
        let bool_t = Arc::new(Datatype::Base(TypeBase::new(
            "bool".into(), 1, TypeMetatype::Bool,
        )));
        op.inrefs.push(typed_vn(1, 0x10, Some(bool_t)));
        op.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(3, 1))));
        let token = left
            .get_output_token_in_fd(&op_ref(op), &detached_fd())
            .expect("bool in0 demotes to int");
        assert_eq!(token.get_metatype(), TypeMetatype::Int);
        assert_eq!(token.get_size(), 1);
        // A non-bool in0 passes through unchanged.
        let int4 = int_t();
        let mut op2 = pcodeop(OpCode::CPUI_INT_LEFT);
        op2.inrefs.push(typed_vn(4, 0x10, Some(int4.clone())));
        op2.inrefs.push(Arc::new(RwLock::new(Varnode::new_constant(3, 1))));
        let token = left
            .get_output_token_in_fd(&op_ref(op2), &detached_fd())
            .expect("int in0 passes through");
        assert!(Arc::ptr_eq(&token, &int4));
    }

    #[test]
    fn piece_output_token_int_uint_or_uint_base() {
        // typeop.cc:2063-2072: INT/UINT def-facing output passes through;
        // anything else falls to the factory UINT base.
        let piece = TypeOpPiece::new(raw_factory());
        let int4 = int_t();
        let mut op = pcodeop(OpCode::CPUI_PIECE);
        op.inrefs.push(typed_vn(4, 0x10, None));
        op.inrefs.push(typed_vn(4, 0x20, None));
        op.output = Some(typed_vn(8, 0x30, Some(int4.clone())));
        let token = piece
            .get_output_token_in_fd(&op_ref(op), &detached_fd())
            .expect("int output passes through");
        assert!(Arc::ptr_eq(&token, &int4));
        // An unknown output falls to the uint base (cc:2071).
        let mut op2 = pcodeop(OpCode::CPUI_PIECE);
        op2.inrefs.push(typed_vn(4, 0x10, None));
        op2.inrefs.push(typed_vn(4, 0x20, None));
        op2.output = Some(typed_vn(8, 0x30, None));
        let token = piece
            .get_output_token_in_fd(&op_ref(op2), &detached_fd())
            .expect("unknown output falls to the uint base");
        assert_eq!(token.get_metatype(), TypeMetatype::Uint);
        assert_eq!(token.get_size(), 8);
    }

    fn int_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new(
            "int".into(), 4, TypeMetatype::Int,
        )))
    }

    /// A HighVariable seeded with the given type (the fixture equivalent of
    /// Ghidra's `new HighVariable(vn)` + `updateType` settling).
    fn high_of(dt: Arc<Datatype>) -> Arc<RwLock<crate::variable::HighVariable>> {
        Arc::new(RwLock::new(crate::variable::HighVariable::new(dt)))
    }

    fn progress_data_t() -> Arc<Datatype> {
        let long_t = Arc::new(Datatype::Base(TypeBase::new(
            "long".into(),
            8,
            TypeMetatype::Int,
        )));
        Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("ProgressData".into(), 32, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "total".into(), offset: 0, type_ptr: long_t.clone() ,
                },
                TypeField { name: "prev".into(), offset: 8, type_ptr: long_t.clone() ,
                },
                TypeField { name: "point".into(), offset: 16, type_ptr: long_t ,
                },
                TypeField { name: "width".into(), offset: 24, type_ptr: int_t() ,
                },
            ],
        }))
    }

    /// Compare two `Option<Arc<Datatype>>` by Arc identity (same allocation).
    fn same_arc(got: Option<Arc<Datatype>>, want: &Arc<Datatype>) -> bool {
        match got {
            Some(g) => Arc::ptr_eq(&g, want),
            None => false,
        }
    }

    /// Bare TypeFactory shared by tests that exercise factory-backed
    /// local-type defaults.
    fn raw_factory() -> Arc<RwLock<TypeFactory>> {
        Arc::new(RwLock::new(TypeFactory::raw()))
    }

    /// A factory with the default size→alignment map installed (the raw
    /// constructor state lacks it and `getTypePointer` construction — used
    /// by the propagateAcrossCompare spacebase/pointerRel arms — throws the
    /// "alignment map not initialized" LowlevelError exactly as the oracle
    /// does for an uninitialized TypeFactory).
    fn aligned_factory() -> Arc<RwLock<TypeFactory>> {
        let factory = raw_factory();
        factory
            .write()
            .unwrap()
            .set_default_alignment_map();
        factory
    }

    #[test]
    fn copy_propagate_type_is_transparent() {
        // COPY propagates input<->output (one slot is -1).
        let op = pcodeop(OpCode::CPUI_COPY);
        let t = int_t();
        let copy = TypeOpCopy::new(raw_factory());
        // input slot 0 -> output returns the same Arc.
        assert!(same_arc(copy.propagate_type(&t, &op, 0, -1), &t));
        // input<->input is blocked (both slots >= 0).
        assert!(copy.propagate_type(&t, &op, 0, 1).is_none());
    }

    #[test]
    fn copy_get_output_token_uses_input() {
        let mut op = pcodeop(OpCode::CPUI_COPY);
        let t = int_t();
        op.inrefs.push(typed_vn(4, 0x10, Some(t.clone())));
        let copy = TypeOpCopy::new(raw_factory());
        // The token is the input varnode's high type (Arc identity); the
        // detached fd consult takes the map-miss arm, and the v_type
        // fallback serves the no-AssignHigh fixture.
        assert!(same_arc(
            copy.get_output_token_in_fd(&op_ref(op), &detached_fd()),
            &t
        ));
    }

    #[test]
    fn compare_propagate_only_across_inputs() {
        // INT_EQUAL propagates a type across its two inputs, never to output.
        let op = pcodeop(OpCode::CPUI_INT_EQUAL);
        let t = int_t();
        let equal = TypeOpIntEqual::new(raw_factory());
        assert!(same_arc(equal.propagate_type(&t, &op, 0, 1), &t));
        // To/from the output is blocked.
        assert!(equal.propagate_type(&t, &op, -1, 0).is_none());

        // typeop.cc:968-971: a spacebase input rewraps as a pointer to the
        // unknown base, sized by the alttype.
        let mut sb_op = pcodeop(OpCode::CPUI_INT_EQUAL);
        let sb = typed_vn(8, 0x10, None);
        sb.write().unwrap().set_flags(varnode_flags::SPACEBASE);
        sb_op.inrefs.push(sb);
        sb_op.inrefs.push(typed_vn(8, 0x20, None));
        let equal = TypeOpIntEqual::new(aligned_factory());
        let wrapped = equal
            .propagate_type(&t, &sb_op, 0, 1)
            .expect("spacebase wraps");
        assert_eq!(wrapped.get_metatype(), TypeMetatype::Pointer);
        assert_eq!(wrapped.get_size(), t.get_size());

        // typeop.cc:972-979: a mid-struct PointerRel degrades to a plain
        // pointer of the same size across comparisons.
        let parent = Arc::new(Datatype::Struct(crate::type_system::datatype::TypeStruct {
            base: TypeBase::new("relparent".into(), 16, TypeMetatype::Struct),
            fields: Vec::new(),
        }));
        let mut rel_ptr_base =
            TypeBase::new("int * rel".into(), 8, TypeMetatype::Pointer);
        rel_ptr_base.pointer_rel = Some(crate::type_system::datatype::PointerRelState {
            parent: parent.clone(),
            offset: 4,
            stripped: None,
        });
        let rel_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: rel_ptr_base,
            ptr_to: int_t(),
            wordsize: 1,
        }));
        // typeop.cc:972-979: a mid-struct PointerRel degrades to a plain
        // pointer of the same size across comparisons. (The invn must not
        // be a spacebase here — cc:968's wrap runs first.)
        let mut rel_op = pcodeop(OpCode::CPUI_INT_EQUAL);
        rel_op.inrefs.push(typed_vn(8, 0x10, None));
        rel_op.inrefs.push(typed_vn(8, 0x20, None));
        let degraded = equal
            .propagate_type(&rel_ptr, &rel_op, 0, 1)
            .expect("pointer-rel degrades");
        assert_eq!(degraded.get_metatype(), TypeMetatype::Pointer);
        assert_eq!(degraded.get_size(), 8);
        // The degraded pointer has no relative state left.
        match degraded.as_ref() {
            Datatype::Pointer(p) => assert!(p.base.pointer_rel.is_none()),
            _ => panic!("degraded must stay a pointer"),
        }
        // Negative-offset relative pointers pass through unchanged
        // (cc:980-981 else arm).
        let mut neg_rel_base =
            TypeBase::new("int * rel-neg".into(), 8, TypeMetatype::Pointer);
        neg_rel_base.pointer_rel = Some(crate::type_system::datatype::PointerRelState {
            parent,
            offset: -1,
            stripped: None,
        });
        let neg_rel = Arc::new(Datatype::Pointer(TypePointer {
            base: neg_rel_base,
            ptr_to: int_t(),
            wordsize: 1,
        }));
        assert!(same_arc(equal.propagate_type(&neg_rel, &rel_op, 0, 1), &neg_rel));
    }

    #[test]
    fn signed_compare_only_propagates_int() {
        let op = pcodeop(OpCode::CPUI_INT_SLESS);
        let sless = TypeOpIntSless::new(raw_factory());
        // uint does NOT propagate through a signed compare.
        let uint_t = Arc::new(Datatype::Base(TypeBase::new(
            "uint".into(),
            4,
            TypeMetatype::Uint,
        )));
        assert!(sless.propagate_type(&uint_t, &op, 0, 1).is_none());
        // int does.
        let t = int_t();
        assert!(same_arc(sless.propagate_type(&t, &op, 0, 1), &t));
    }

    #[test]
    fn compare_output_metatype_is_bool_and_cast_uses_own_base() {
        // typeop.cc:1075-1083 TypeOpIntLess::getInputCast: the required type
        // is the op's own inputTypeLocal base (TYPE_UINT for INT_LESS), NOT
        // the other operand's type.
        let mut op = pcodeop(OpCode::CPUI_INT_LESS);
        let t = int_t();
        op.inrefs.push(typed_vn(4, 0x10, Some(t.clone())));
        op.inrefs.push(typed_vn(4, 0x20, Some(t.clone())));
        let less = TypeOpIntLess::new(raw_factory());
        assert_eq!(less.get_output_metatype(), Some(TypeMetatype::Bool));
        // care_uint_int=TRUE (cc:1082 third arg): an int4 current type
        // under the uint4 base DOES take the cast (cast.cc:352-361 — INT is
        // not in the care=true whitelist).
        let cast = less
            .get_input_cast(&op_ref(op), 1, &detached_fd())
            .expect("int cur under uint base takes the cast");
        assert_eq!(cast.get_metatype(), TypeMetatype::Uint);
        assert_eq!(cast.get_size(), 4);

        // A pointer-typed current type takes the uint base cast as well
        // (size mismatch forces the cast; the result preserves the reqtype).
        let ptr_t = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: t.clone(),
            wordsize: 1,
        }));
        let mut ptr_op = pcodeop(OpCode::CPUI_INT_LESS);
        ptr_op.inrefs.push(typed_vn(4, 0x10, Some(t.clone())));
        ptr_op.inrefs.push(typed_vn(4, 0x20, Some(ptr_t)));
        let cast = less
            .get_input_cast(&op_ref(ptr_op), 1, &detached_fd())
            .expect("pointer current type forces the base cast");
        assert_eq!(cast.get_metatype(), TypeMetatype::Uint);
        assert_eq!(cast.get_size(), 4);

        // A uint current type is cast-free (cast.cc:354-355 whitelist).
        let uint_t = Arc::new(Datatype::Base(TypeBase::new(
            "uint".into(),
            4,
            TypeMetatype::Uint,
        )));
        let mut uint_op = pcodeop(OpCode::CPUI_INT_LESS);
        uint_op.inrefs.push(typed_vn(4, 0x10, Some(t.clone())));
        uint_op.inrefs.push(typed_vn(4, 0x20, Some(uint_t)));
        assert!(less
            .get_input_cast(&op_ref(uint_op), 1, &detached_fd())
            .is_none());

        // typeop.cc:1023-1031 TypeOpIntSless::getInputCast: the same shape
        // with care_uint_int=TRUE — an int current type under the INT base
        // is cast-free, an uint current type takes the int base cast.
        let sless = TypeOpIntSless::new(raw_factory());
        let mut sless_op = pcodeop(OpCode::CPUI_INT_SLESS);
        sless_op.inrefs.push(typed_vn(4, 0x10, Some(t.clone())));
        sless_op.inrefs.push(typed_vn(4, 0x20, Some(t.clone())));
        assert!(sless
            .get_input_cast(&op_ref(sless_op), 1, &detached_fd())
            .is_none());
        let uint_t = Arc::new(Datatype::Base(TypeBase::new(
            "uint".into(),
            4,
            TypeMetatype::Uint,
        )));
        let mut uint_op = pcodeop(OpCode::CPUI_INT_SLESS);
        uint_op.inrefs.push(typed_vn(4, 0x10, Some(t.clone())));
        uint_op.inrefs.push(typed_vn(4, 0x20, Some(uint_t)));
        let cast = sless
            .get_input_cast(&op_ref(uint_op), 1, &detached_fd())
            .expect("uint under signed compare forces the int base");
        assert_eq!(cast.get_metatype(), TypeMetatype::Int);
    }

    #[test]
    fn load_propagate_wraps_and_unwraps_pointer() {
        // LOAD: output(value) -> input(pointer) wraps the value as a pointer.
        let mut op = pcodeop(OpCode::CPUI_LOAD);
        op.output = Some(typed_vn(4, 0x20, None));
        let t = int_t();
        let wrapped = TypeOpLoad.propagate_type(&t, &op, -1, 1).expect("wraps");
        assert_eq!(wrapped.get_metatype(), TypeMetatype::Pointer);
        // input(pointer) -> output(value) unwraps to the pointee.
        let ptr_t = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: t.clone(),
            wordsize: 1,
        }));
        assert!(same_arc(TypeOpLoad.propagate_type(&ptr_t, &op, 1, -1), &t));
        // The space-constant edge (slot 0) never propagates.
        assert!(TypeOpLoad.propagate_type(&t, &op, 0, -1).is_none());
    }

    #[test]
    fn load_value_to_pointer_checks_output_source_spacebase() {
        let mut op = pcodeop(OpCode::CPUI_LOAD);
        let output = typed_vn(4, 0x20, None);
        output.write().unwrap().set_flags(varnode_flags::SPACEBASE);
        op.output = Some(output);
        op.inrefs.push(typed_vn(8, 0, None));
        op.inrefs.push(typed_vn(8, 0x30, None));

        assert!(TypeOpLoad
            .propagate_type(&int_t(), &op, -1, 1)
            .is_none());
    }

    #[test]
    fn pointer_dereference_propagation_is_width_gated() {
        let progress = progress_data_t();
        let progress_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("ProgressData *".into(), 8, TypeMetatype::Pointer),
            ptr_to: progress.clone(),
            wordsize: 1,
        }));

        assert!(propagate_from_pointer(&progress_ptr, 16).is_none());
        assert!(propagate_from_pointer(&progress_ptr, 4).is_none());
        assert!(same_arc(
            propagate_from_pointer(&progress_ptr, 32), &progress
        ));

        let int = int_t();
        let int_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int.clone(),
            wordsize: 1,
        }));
        assert!(same_arc(propagate_from_pointer(&int_ptr, 4), &int));
    }

    #[test]
    fn store_pointer_to_value_uses_value_varnode_width() {
        let progress = progress_data_t();
        let progress_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("ProgressData *".into(), 8, TypeMetatype::Pointer),
            ptr_to: progress.clone(),
            wordsize: 1,
        }));
        for width in [16, 4] {
            let mut op = pcodeop(OpCode::CPUI_STORE);
            op.inrefs.push(typed_vn(8, 0, None));
            op.inrefs.push(typed_vn(8, 0x100, None));
            op.inrefs.push(typed_vn(width, 0x200, None));
            assert!(TypeOpStore
                .propagate_type(&progress_ptr, &op, 1, 2)
                .is_none());
        }

        let mut exact = pcodeop(OpCode::CPUI_STORE);
        exact.inrefs.push(typed_vn(8, 0, None));
        exact.inrefs.push(typed_vn(8, 0x100, None));
        exact.inrefs.push(typed_vn(32, 0x200, None));
        assert!(same_arc(
            TypeOpStore.propagate_type(&progress_ptr, &exact, 1, 2),
            &progress
        ));
    }

    #[test]
    fn ptrsub_gap_output_token_is_unknown_pointer() {
        // FIELDCAST-TRACE-2026-08-27: ProgressData has fields at 0/8/16/24,
        // while offset 28 is a legal in-struct synthetic gap. Ghidra's
        // TypeOpPtrsub::getOutputToken (typeop.cc:2349-2364) falls back to
        // pointer-to-unknown for this nonzero unresolved offset.
        let factory = raw_factory();
        factory
            .write()
            .unwrap()
            .setup_sizes(&crate::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let progress = progress_data_t();
        let progress_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("ProgressData *".into(), 8, TypeMetatype::Pointer),
            ptr_to: progress,
            wordsize: 1,
        }));
        let mut gap = pcodeop(OpCode::CPUI_PTRSUB);
        let base = typed_vn(8, 0x10, Some(progress_ptr.clone()));
        let high = Arc::new(RwLock::new(crate::variable::HighVariable::new(
            progress_ptr,
        )));
        high.write().unwrap().add_instance(base.clone());
        base.write().unwrap().high = Some(high);
        gap.inrefs.push(base);
        gap.inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(28, 8))));
        gap.output = Some(typed_vn(8, 0x20, None));
        let ptrsub = TypeOpPtrsub::new(factory);
        // Compute the fd-less local assertion before `gap` is moved into
        // the PcodeOpRef for the fd-carrying token call.
        let local_meta = ptrsub.get_output_local(&gap).unwrap().get_metatype();
        let gap_ref = op_ref(gap);
        let token = ptrsub
            .get_output_token_in_fd(&gap_ref, &detached_fd())
            .expect("gap fallback token");
        let pointee = match token.as_ref() {
            Datatype::Pointer(pointer) => &pointer.ptr_to,
            other => panic!("expected pointer token, got {other:?}"),
        };
        assert_eq!(token.get_size(), 8);
        assert_eq!(pointee.get_metatype(), TypeMetatype::Unknown);
        assert_eq!(pointee.get_size(), 1);
        assert_eq!(local_meta, TypeMetatype::Int);
    }

    #[test]
    fn ptrsub_exact_nonzero_field_output_token_is_field_pointer() {
        // typeop.cc:2354-2359: offset 8 is passed by reference through one
        // downChain call.  ProgressData::prev consumes the complete offset,
        // so the residual is zero and the token is a pointer to the field.
        let factory = raw_factory();
        factory
            .write()
            .unwrap()
            .setup_sizes(&crate::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let progress = progress_data_t();
        let expected = match progress.as_ref() {
            Datatype::Struct(structure) => structure.fields[1].type_ptr.clone(),
            _ => unreachable!(),
        };
        let progress_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("ProgressData *".into(), 8, TypeMetatype::Pointer),
            ptr_to: progress,
            wordsize: 1,
        }));
        let mut field = pcodeop(OpCode::CPUI_PTRSUB);
        let base = typed_vn(8, 0x10, Some(progress_ptr.clone()));
        let high = Arc::new(RwLock::new(crate::variable::HighVariable::new(
            progress_ptr,
        )));
        high.write().unwrap().add_instance(base.clone());
        base.write().unwrap().high = Some(high);
        field.inrefs.push(base);
        field
            .inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(8, 8))));
        field.output = Some(typed_vn(8, 0x20, None));

        let ptrsub = TypeOpPtrsub::new(factory);
        let token = ptrsub
            .get_output_token_in_fd(&op_ref(field), &detached_fd())
            .expect("exact field token");
        let pointee = match token.as_ref() {
            Datatype::Pointer(pointer) => &pointer.ptr_to,
            other => panic!("expected pointer token, got {other:?}"),
        };
        assert!(Arc::ptr_eq(pointee, &expected));
        assert_eq!(pointee.get_metatype(), TypeMetatype::Int);
        assert_eq!(pointee.get_size(), 8);
        let canonical = ptrsub
            .type_factory
            .write()
            .unwrap()
            .get_type_pointer(8, expected, 1);
        assert!(Arc::ptr_eq(&token, &canonical));
    }

    #[test]
    fn int_add_propagates_pointer_with_constant() {
        // INT_ADD lets a pointer flow input->output; here in[1] is a constant.
        let mut op = pcodeop(OpCode::CPUI_INT_ADD);
        op.inrefs.push(typed_vn(8, 0x10, None));
        op.inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(4, 8))));
        let ptr_t = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int_t(),
            wordsize: 1,
        }));
        let add = TypeOpIntAdd::new(raw_factory());
        // pointer input 0 -> output propagates (the 8-byte constant's value
        // 4 wraps to zero on the 4-byte int pointee, downChain returns the
        // pointer itself, typeop.cc:1098).
        assert!(same_arc(add.propagate_type(&ptr_t, &op, 0, -1), &ptr_t));
        // pointer output -> input is blocked.
        assert!(add.propagate_type(&ptr_t, &op, -1, 0).is_none());
    }

    /// TYPEOP-INTADD-PROPTEST-0001: the int arm only flows into the slot-1
    /// CONSTANT (typeop.cc:1188 `outslot != 1 || !op->getIn(1)->isConstant()`),
    /// and the constant target returns alttype directly through the
    /// cc:1194-1195 outvn->isConstant() branch. Pre-fix the const test was
    /// inverted (constant slot blocked, non-constant slot allowed).
    #[test]
    fn int_add_int_arm_flows_into_constant_slot() {
        let mut op = pcodeop(OpCode::CPUI_INT_ADD);
        op.inrefs.push(typed_vn(8, 0x10, None));
        op.inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(0x10, 4))));
        let add = TypeOpIntAdd::new(raw_factory());
        let t = int_t();
        // int input 0 -> constant slot 1 propagates (cc:1188 + cc:1194).
        assert!(same_arc(add.propagate_type(&t, &op, 0, 1), &t));
        // int output -> constant slot 1 also propagates: the cc:1194
        // outvn->isConstant() branch fires before the cc:1196 inslot==-1
        // block.
        assert!(same_arc(add.propagate_type(&t, &op, -1, 1), &t));
    }

    /// TYPEOP-INTADD-PROPTEST-0001: a non-constant slot-1 target blocks the
    /// int arm (cc:1188 `!isConstant`), and so does any target that is not
    /// slot 1. Pre-fix the non-constant slot was (invertedly) allowed.
    #[test]
    fn int_add_int_arm_blocks_nonconstant_and_non_slot1_targets() {
        let mut op = pcodeop(OpCode::CPUI_INT_ADD);
        op.inrefs.push(typed_vn(8, 0x10, None));
        op.inrefs.push(typed_vn(4, 0x20, None)); // slot 1 NOT constant
        let add = TypeOpIntAdd::new(raw_factory());
        assert!(add.propagate_type(&int_t(), &op, 0, 1).is_none());
        // outslot != 1 blocks regardless of the constant (cc:1188 first
        // conjunct): to the output...
        let mut const_op = pcodeop(OpCode::CPUI_INT_ADD);
        const_op.inrefs.push(typed_vn(8, 0x10, None));
        const_op
            .inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(0x10, 4))));
        assert!(add.propagate_type(&int_t(), &const_op, 0, -1).is_none());
        // ...and to input slot 0.
        assert!(add.propagate_type(&int_t(), &const_op, 1, 0).is_none());
    }

    /// TYPEOP-INTADD-PROPTEST-0001: uint shares the int-arm rule
    /// (typeop.cc:1186 allows TYPE_UINT as well).
    #[test]
    fn int_add_uint_arm_flows_into_constant_slot() {
        let uint_t = Arc::new(Datatype::Base(TypeBase::new(
            "uint".into(),
            4,
            TypeMetatype::Uint,
        )));
        let mut op = pcodeop(OpCode::CPUI_INT_ADD);
        op.inrefs.push(typed_vn(8, 0x10, None));
        op.inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(0x10, 4))));
        let add = TypeOpIntAdd::new(raw_factory());
        assert!(same_arc(add.propagate_type(&uint_t, &op, 0, 1), &uint_t));
    }

    /// TYPEOP-INTADD-PROPTEST-0001: the pointer arm delegates to
    /// propagateAddIn2Out (typeop.cc:1199) instead of passing alttype
    /// through: a non-constant other input is NoPropagate (typeop.cc:1290/
    /// 1302), a bad constant offset kills the downChain (typeop.cc:1221 via
    /// getSubType failure), and a zero constant falls back to alttype through
    /// the cc:1243-1245 AddZero branch. Pre-fix every one of these returned
    /// Some(alttype) directly.
    #[test]
    fn int_add_pointer_arm_delegates_to_propagate_add_in2out() {
        let ptr_t = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int_t(),
            wordsize: 1,
        }));
        let add = TypeOpIntAdd::new(raw_factory());

        // Non-constant offset: NoPropagate (sz=4 != 1, no INT_MULT def).
        let mut nonconst_op = pcodeop(OpCode::CPUI_INT_ADD);
        nonconst_op.inrefs.push(typed_vn(8, 0x10, None));
        nonconst_op.inrefs.push(typed_vn(8, 0x50, None));
        assert!(add.propagate_type(&ptr_t, &nonconst_op, 0, -1).is_none());

        // Constant 5 on a 4-byte pointee: wraps to offset 1, getSubType on
        // the base pointee fails, command is AddConst -> NULL (cc:1246).
        let mut bad_op = pcodeop(OpCode::CPUI_INT_ADD);
        bad_op.inrefs.push(typed_vn(8, 0x10, None));
        bad_op
            .inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(5, 4))));
        assert!(add.propagate_type(&ptr_t, &bad_op, 0, -1).is_none());

        // Constant 0: AddZero with a dead chain falls back to alttype
        // (cc:1243-1245).
        let mut zero_op = pcodeop(OpCode::CPUI_INT_ADD);
        zero_op.inrefs.push(typed_vn(8, 0x10, None));
        zero_op
            .inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(0, 4))));
        assert!(same_arc(add.propagate_type(&ptr_t, &zero_op, 0, -1), &ptr_t));

        // Cross-input propagation is blocked (cc:1191-1192), even with a
        // constant target edge.
        assert!(add.propagate_type(&ptr_t, &zero_op, 0, 1).is_none());
        // Output -> input stays blocked when the target edge is constant:
        // cc:1194 requires meta != TYPE_PTR, then cc:1196 blocks inslot==-1.
        assert!(add.propagate_type(&ptr_t, &zero_op, -1, 1).is_none());
    }

    #[test]
    fn default_trait_methods_are_none() {
        // Ops without overrides use the trait defaults.
        let branch = TypeOpBranch::new(Arc::new(RwLock::new(TypeFactory::raw())));
        let op = pcodeop(OpCode::CPUI_BRANCH);
        assert!(branch.get_output_token(&op).is_none());
        assert!(branch.get_output_metatype().is_none());
        let t = int_t();
        assert!(branch.propagate_type(&t, &op, -1, 0).is_none());
        let branch_op_ref = op_ref(op);
        assert!(branch
            .get_input_cast(&branch_op_ref, 0, &detached_fd())
            .is_none());
    }

    #[test]
    fn float_int2float_preferred_zext_size_matches_ghidra_boundaries() {
        let cases = [(1, 4), (2, 4), (3, 4), (4, 8), (7, 8), (8, 9), (16, 17)];

        for (input, expected) in cases {
            assert_eq!(
                TypeOpFloatInt2Float::preferred_zext_size(input),
                expected,
                "input size {input}"
            );
        }
    }

    /// Regression guard for PRINTC-CAST-OPNAME-0001 M1: every macro-family
    /// opcode derives its local types from the constructor-registered
    /// metatype pair via `getBase(size, meta)` (typeop.cc:323/329/345/351/
    /// 365/371), never from the opposite varnode's v_type.
    #[test]
    fn local_defaults_follow_constructor_metatypes() {
        let factory = raw_factory();
        let mut zext = pcodeop(OpCode::CPUI_INT_ZEXT);
        zext.inrefs.push(typed_vn(1, 0x10, None));
        zext.output = Some(typed_vn(4, 0x20, None));
        let zext_op = TypeOpIntZext::new(factory.clone());
        // ZEXT ctor: TypeOpFunc("ZEXT",TYPE_UINT,TYPE_UINT) — typeop.cc:1116.
        assert_eq!(
            zext_op.get_output_local(&zext).unwrap().get_metatype(), TypeMetatype::Uint
        );
        assert_eq!(zext_op.get_output_local(&zext).unwrap().get_size(), 4);
        assert_eq!(
            zext_op.get_input_local(&zext, 0).unwrap().get_metatype(), TypeMetatype::Uint
        );
        assert_eq!(zext_op.get_input_local(&zext, 0).unwrap().get_size(), 1);

        let mut sext = pcodeop(OpCode::CPUI_INT_SEXT);
        sext.inrefs.push(typed_vn(1, 0x10, None));
        sext.output = Some(typed_vn(4, 0x20, None));
        let sext_op = TypeOpIntSext::new(factory.clone());
        // SEXT ctor: TypeOpFunc("SEXT",TYPE_INT,TYPE_INT) — typeop.cc:1141.
        assert_eq!(
            sext_op.get_output_local(&sext).unwrap().get_metatype(), TypeMetatype::Int
        );
        assert_eq!(
            sext_op.get_input_local(&sext, 0).unwrap().get_metatype(), TypeMetatype::Int
        );

        let mut sub = pcodeop(OpCode::CPUI_SUBPIECE);
        sub.inrefs.push(typed_vn(8, 0x10, None));
        sub.inrefs
            .push(Arc::new(RwLock::new(Varnode::new_constant(1, 0))));
        sub.output = Some(typed_vn(4, 0x20, None));
        let sub_op = TypeOpSubpiece::new(factory.clone());
        // SUBPIECE ctor: TypeOpFunc("SUB",TYPE_UNKNOWN,TYPE_UNKNOWN) —
        // typeop.cc:2116. Both sides stay UNKNOWN (cast decision is the
        // printer's isSubpieceCast predicate, not a metatype).
        assert_eq!(
            sub_op.get_output_local(&sub).unwrap().get_metatype(), TypeMetatype::Unknown
        );
        assert_eq!(
            sub_op.get_input_local(&sub, 0).unwrap().get_metatype(), TypeMetatype::Unknown
        );

        // Repeat lookups must return the factory-canonical Arc (identity).
        let a = zext_op.get_output_local(&zext).unwrap();
        let b = zext_op.get_output_local(&zext).unwrap();
        assert!(Arc::ptr_eq(&a, &b));

        let mut shift = pcodeop(OpCode::CPUI_INT_LEFT);
        shift.inrefs.push(typed_vn(4, 0x10, None));
        shift.inrefs.push(typed_vn(4, 0x20, None));
        shift.output = Some(typed_vn(4, 0x30, None));
        let left_op = TypeOpIntLeft::new(factory.clone());
        // INT_LEFT ctor: TypeOpBinary("<<",TYPE_INT,TYPE_INT) — typeop.cc:1502;
        // getInputLocal override: slot 1 (shift amount) is getBaseNoChar(size,
        // TYPE_INT) — typeop.cc:1509.
        assert_eq!(
            left_op.get_output_local(&shift).unwrap().get_metatype(), TypeMetatype::Int
        );
        assert_eq!(
            left_op.get_input_local(&shift, 0).unwrap().get_metatype(), TypeMetatype::Int
        );
        assert_eq!(
            left_op.get_input_local(&shift, 1).unwrap().get_metatype(), TypeMetatype::Int
        );

        let mut cmp = pcodeop(OpCode::CPUI_INT_LESS);
        cmp.inrefs.push(typed_vn(4, 0x10, None));
        cmp.inrefs.push(typed_vn(4, 0x20, None));
        cmp.output = Some(typed_vn(1, 0x30, None));
        let less_op = TypeOpIntLess::new(factory.clone());
        // INT_LESS ctor: TypeOpBinary("<",TYPE_BOOL,TYPE_UINT) — typeop.cc:1067.
        assert_eq!(
            less_op.get_output_local(&cmp).unwrap().get_metatype(), TypeMetatype::Bool
        );
        assert_eq!(
            less_op.get_input_local(&cmp, 0).unwrap().get_metatype(), TypeMetatype::Uint
        );

        let mut insert = pcodeop(OpCode::CPUI_INSERT);
        insert.inrefs.push(typed_vn(4, 0x10, None));
        insert.inrefs.push(typed_vn(4, 0x20, None));
        insert.inrefs.push(typed_vn(1, 0x30, None));
        insert.output = Some(typed_vn(4, 0x40, None));
        let insert_op = TypeOpInsert::new(factory.clone());
        // INSERT ctor: TypeOpFunc("INSERT",TYPE_UNKNOWN,TYPE_INT) —
        // typeop.cc:2528; getInputLocal keeps slot 0 UNKNOWN (typeop.cc:2535).
        assert_eq!(
            insert_op.get_output_local(&insert).unwrap().get_metatype(), TypeMetatype::Unknown
        );
        assert_eq!(
            insert_op
                .get_input_local(&insert, 0)
                .unwrap()
                .get_metatype(), TypeMetatype::Unknown
        );
        assert_eq!(
            insert_op
                .get_input_local(&insert, 1)
                .unwrap()
                .get_metatype(), TypeMetatype::Int
        );
    }
}
