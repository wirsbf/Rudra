//! P-code operation behavior emulation.
//!
//! Corresponds to Ghidra's `opbehavior.hh` / `opbehavior.cc`.
//!
//! Each P-code opcode has an associated `OpBehavior` that describes how to
//! emulate the operation: `evaluateUnary`, `evaluateBinary`, `evaluateTernary`,
//! and reverse variants (`recoverInputUnary`, `recoverInputBinary`). This is
//! used by constant folding (RuleCollapseConstants) and by the jump-table
//! analysis emulator.
//!
//! Two parallel APIs are provided:
//! - **Free functions** (`evaluate_unary`, `evaluate_binary`, ...) — the
//!   ergonomically idiomatic Rust interface used by `emulate.rs`, `op.rs`,
//!   `jumptable.rs`, and `unify.rs`. Each arm is a faithful port of the
//!   matching `OpBehavior*::evaluate*` body.
//! - **OOP trait + subclasses** (`OpBehavior` trait, `OpBehaviorIntAdd`, ...)
//!   — a direct port of the C++ class hierarchy so the alignment between
//!   Rugra and Ghidra can be audited class-by-class. `OpBehaviorFactory`
//!   mirrors `OpBehavior::registerInstructions`.
//!
//! # Status
//! Fully aligned with `opbehavior.cc`. All 40+ opcode behaviors, the reverse
//! (recover-input) variants, and the registry/factory are ported.

use crate::address::{calc_mask, count_leading_zeros, signbit_negative};
use crate::float_emulate::FloatFormat;
use crate::opcodes::OpCode;
use crate::rangeutil::sign_extend_size;

// ---------------------------------------------------------------------------
// Low-level bit helpers (mirror Ghidra's inline functions in address.hh).
// ---------------------------------------------------------------------------

/// Mask of `bits` set bits. Equivalent to `calc_mask(size)` for `size = bits/8`,
/// kept as a separate helper for callers that work in bit-widths.
// RUDRA-GLUE: bit-width mask used by the legacy free-function bodies
fn mask_bits(bits: usize) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Sign-extend a value occupying the low `in_size` bytes to a full `i64`.
/// Faithful to Ghidra's `sign_extend(val, sizein*8-1)` (address.hh:555).
// Ghidra: address.hh:555 sign_extend
fn sign_extend_to_i64(val: u64, in_size: usize) -> i64 {
    let bits = in_size * 8;
    if bits == 0 {
        return 0;
    }
    if bits >= 64 {
        return val as i64;
    }
    let shift = 64 - bits;
    ((val << shift) as i64) >> shift
}

/// `uintb_negate(val, size)` — bitwise NOT of the low `size` bytes, masked.
/// Faithful to Ghidra's `uintb_negate` (address.cc:654).
// Ghidra: address.cc:654 uintb_negate
fn uintb_negate(val: u64, size_bytes: usize) -> u64 {
    !val & calc_mask(size_bytes)
}

/// `zero_extend(sres, 8*sizeout-1)` — truncate a signed value to `size_out`
/// bytes, reinterpreting as unsigned. Used by `INT_SDIV` / `INT_SREM`
/// (opbehavior.cc:542,566).
// Ghidra: opbehavior.cc:542 zero_extend
fn zero_extend(sres: i64, size_out: usize) -> u64 {
    (sres as u64) & calc_mask(size_out)
}

// ===========================================================================
// Error type (opbehavior.hh:30 EvaluationError)
// ===========================================================================

/// Mirror of Ghidra's `EvaluationError` (opbehavior.hh:30). Thrown when
/// emulation/recovery cannot proceed (e.g. divide-by-zero, output out of range
/// for an inverse op). Subclasses `LowlevelError` in C++; here we carry the
/// message directly since the free functions surface failure via `Option`.
// Ghidra: opbehavior.hh:30 EvaluationError
#[derive(Debug, Clone)]
pub struct EvaluationError(pub String);

impl std::fmt::Display for EvaluationError {
    // RUDRA-GLUE: Rust Display adapter for EvaluationError; Ghidra inherits LowlevelError and has no formatting override
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EvaluationError: {}", self.0)
    }
}

impl std::error::Error for EvaluationError {}

impl EvaluationError {
    // Ghidra: opbehavior.hh:31 EvaluationError::EvaluationError
    /// Construct with an explanatory string, mirroring the C++ constructor.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

// ===========================================================================
// Free-function evaluate API (ergonomic Rust surface).
//
// Each `match` arm is a 1:1 port of the corresponding `OpBehavior*::evaluate*`
// body in opbehavior.cc; line references are given per arm. Failure modes that
// throw `EvaluationError` in C++ (divide-by-zero, etc.) return `None` instead.
// ===========================================================================

/// Evaluate a unary P-code operation on constant inputs.
///
/// Returns the result as a `u64` masked to `size_out` bytes, or `None` if the
/// opcode has no unary behavior (special/control-flow ops, binary-only ops).
///
/// Each arm is a faithful port of the matching `OpBehavior*::evaluateUnary`
/// body; see the per-arm `// Ghidra:` references.
// Ghidra: opbehavior.cc:185-821 (per-class evaluateUnary bodies)
pub fn evaluate_unary(opc: OpCode, size_out: usize, size_in: usize, in1: u64) -> Option<u64> {
    let out_mask = calc_mask(size_out);
    let result = match opc {
        // Ghidra: opbehavior.cc:171 OpBehaviorCopy::evaluateUnary
        OpCode::CPUI_COPY => in1,
        // Ghidra: opbehavior.cc:251 OpBehaviorIntZext::evaluateUnary
        OpCode::CPUI_INT_ZEXT => in1,
        // Ghidra: opbehavior.cc:266 OpBehaviorIntSext::evaluateUnary
        OpCode::CPUI_INT_SEXT => sign_extend_size(in1, size_in, size_out),
        // Ghidra: opbehavior.cc:376 OpBehaviorIntNegate::evaluateUnary
        OpCode::CPUI_INT_NEGATE => uintb_negate(in1, size_in),
        // Ghidra: opbehavior.cc:362 OpBehaviorInt2Comp::evaluateUnary
        OpCode::CPUI_INT_2COMP => uintb_negate(in1.wrapping_sub(1), size_in),
        // Ghidra: opbehavior.cc:541 OpBehaviorBoolNegate::evaluateUnary
        OpCode::CPUI_BOOL_NEGATE => in1 ^ 1,
        // Ghidra: opbehavior.cc:782 OpBehaviorPopcount::evaluateUnary
        OpCode::CPUI_POPCOUNT => crate::utils::bits::popcount(in1) as u64,
        // Ghidra: opbehavior.cc:788 OpBehaviorLzcount::evaluateUnary
        //
        // `count_leading_zeros(in1) - 8*(sizeof(uintb) - sizein)`. Ghidra's
        // `uintb` is 8 bytes, so the subtraction re-bases the host-level CLZ
        // (which counts 64 bits) down to the `size_in`-byte width.
        OpCode::CPUI_LZCOUNT => {
            (count_leading_zeros(in1) - (8 * (8 - size_in.min(8))) as i32) as u64
        }
        _ => return None,
    };
    // Binary/unary results in Ghidra are NOT uniformly masked — e.g. OpBehaviorCopy
    // returns `in1` verbatim and the caller is responsible for sizing. The free
    // function historically masks to `size_out` for caller convenience; we keep
    // that contract for back-compat with emulate.rs/op.rs/unify.rs callers that
    // rely on `Option<u64>` already being sized.
    Some(result & out_mask)
}

/// Evaluate a binary P-code operation on constant inputs.
///
/// Each arm is a faithful port of the matching `OpBehavior*::evaluateBinary`
/// body; see the per-arm `// Ghidra:` references. `None` is returned when the
/// opcode has no binary behavior or when evaluation is undefined (divide by
/// zero).
// Ghidra: opbehavior.cc:197-809 (per-class evaluateBinary bodies)
pub fn evaluate_binary(
    opc: OpCode,
    size_out: usize,
    size_in: usize,
    in1: u64,
    in2: u64,
) -> Option<u64> {
    let out_mask = calc_mask(size_out);
    let result = match opc {
        // Ghidra: opbehavior.cc:290 OpBehaviorIntAdd::evaluateBinary
        OpCode::CPUI_INT_ADD => (in1.wrapping_add(in2)) & out_mask,
        // Ghidra: opbehavior.cc:304 OpBehaviorIntSub::evaluateBinary
        OpCode::CPUI_INT_SUB => (in1.wrapping_sub(in2)) & out_mask,
        // Ghidra: opbehavior.cc:492 OpBehaviorIntMult::evaluateBinary
        OpCode::CPUI_INT_MULT => (in1.wrapping_mul(in2)) & out_mask,
        // Ghidra: opbehavior.cc:499 OpBehaviorIntDiv::evaluateBinary
        // (in2==0 throws EvaluationError in Ghidra; here surfaced as None)
        OpCode::CPUI_INT_DIV => {
            if in2 == 0 {
                return None;
            }
            in1 / in2
        }
        // Ghidra: opbehavior.cc:507 OpBehaviorIntSdiv::evaluateBinary
        // Signed division with truncation toward zero (C semantics), then
        // zero_extend to size_out.
        OpCode::CPUI_INT_SDIV => {
            if in2 == 0 {
                return None;
            }
            let bits = 8 * size_in - 1;
            let num = sign_extend_to_i64(in1 & mask_bits(bits + 1), size_in);
            let denom = sign_extend_to_i64(in2 & mask_bits(bits + 1), size_in);
            zero_extend(num / denom, size_out)
        }
        // Ghidra: opbehavior.cc:519 OpBehaviorIntRem::evaluateBinary
        OpCode::CPUI_INT_REM => {
            if in2 == 0 {
                return None;
            }
            in1 % in2
        }
        // Ghidra: opbehavior.cc:529 OpBehaviorIntSrem::evaluateBinary
        OpCode::CPUI_INT_SREM => {
            if in2 == 0 {
                return None;
            }
            let bits = 8 * size_in - 1;
            let val = sign_extend_to_i64(in1 & mask_bits(bits + 1), size_in);
            let modulus = sign_extend_to_i64(in2 & mask_bits(bits + 1), size_in);
            zero_extend(val % modulus, size_out)
        }
        // Ghidra: opbehavior.cc:397 OpBehaviorIntAnd::evaluateBinary
        OpCode::CPUI_INT_AND => in1 & in2,
        // Ghidra: opbehavior.cc:404 OpBehaviorIntOr::evaluateBinary
        OpCode::CPUI_INT_OR => in1 | in2,
        // Ghidra: opbehavior.cc:390 OpBehaviorIntXor::evaluateBinary
        OpCode::CPUI_INT_XOR => in1 ^ in2,
        // Ghidra: opbehavior.cc:411 OpBehaviorIntLeft::evaluateBinary
        // (in2 >= sizeout*8 ⇒ 0)
        OpCode::CPUI_INT_LEFT => {
            if in2 >= (size_out * 8) as u64 {
                0
            } else {
                (in1 << in2) & out_mask
            }
        }
        // Ghidra: opbehavior.cc:432 OpBehaviorIntRight::evaluateBinary
        // Logical right shift; input is first masked to sizeout bytes.
        OpCode::CPUI_INT_RIGHT => {
            if in2 >= (size_out * 8) as u64 {
                0
            } else {
                (in1 & out_mask) >> in2
            }
        }
        // Ghidra: opbehavior.cc:454 OpBehaviorIntSright::evaluateBinary
        // Arithmetic right shift. For overlarge shifts, returns all-ones
        // (negative) or 0 depending on the input sign bit.
        OpCode::CPUI_INT_SRIGHT => {
            if in2 >= (8 * size_out) as u64 {
                if signbit_negative(in1, size_in) {
                    out_mask
                } else {
                    0
                }
            } else if signbit_negative(in1, size_in) {
                // Sign-extend the shifted-out bits with 1s.
                let mut res = in1 >> in2;
                let mut m = calc_mask(size_in);
                m = (m >> in2) ^ m;
                res |= m;
                res
            } else {
                in1 >> in2
            }
        }
        // Ghidra: opbehavior.cc:183 OpBehaviorEqual::evaluateBinary
        OpCode::CPUI_INT_EQUAL => u64::from(in1 == in2),
        // Ghidra: opbehavior.cc:190 OpBehaviorNotEqual::evaluateBinary
        OpCode::CPUI_INT_NOTEQUAL => u64::from(in1 != in2),
        // Ghidra: opbehavior.cc:237 OpBehaviorIntLess::evaluateBinary
        OpCode::CPUI_INT_LESS => u64::from(in1 < in2),
        // Ghidra: opbehavior.cc:244 OpBehaviorIntLessEqual::evaluateBinary
        OpCode::CPUI_INT_LESSEQUAL => u64::from(in1 <= in2),
        // Ghidra: opbehavior.cc:197 OpBehaviorIntSless::evaluateBinary
        // Compares sign bits first; falls back to unsigned compare if equal.
        OpCode::CPUI_INT_SLESS => {
            if size_in == 0 {
                0
            } else {
                let m = 0x80u64 << (8 * (size_in - 1));
                let bit1 = in1 & m;
                let bit2 = in2 & m;
                if bit1 != bit2 {
                    u64::from(bit1 != 0)
                } else {
                    u64::from(in1 < in2)
                }
            }
        }
        // Ghidra: opbehavior.cc:217 OpBehaviorIntSlessEqual::evaluateBinary
        OpCode::CPUI_INT_SLESSEQUAL => {
            if size_in == 0 {
                0
            } else {
                let m = 0x80u64 << (8 * (size_in - 1));
                let bit1 = in1 & m;
                let bit2 = in2 & m;
                if bit1 != bit2 {
                    u64::from(bit1 != 0)
                } else {
                    u64::from(in1 <= in2)
                }
            }
        }
        // Ghidra: opbehavior.cc:323 OpBehaviorIntCarry::evaluateBinary
        OpCode::CPUI_INT_CARRY => {
            u64::from(in1 > (in1.wrapping_add(in2) & calc_mask(size_in)))
        }
        // Ghidra: opbehavior.cc:330 OpBehaviorIntScarry::evaluateBinary
        // a = sign(in1), b = sign(in2), r = sign(sum); res = (r^a) & (a^b^1).
        OpCode::CPUI_INT_SCARRY => {
            if size_in == 0 {
                return Some(0);
            }
            let res = in1.wrapping_add(in2);
            let mut a = ((in1 >> (size_in * 8 - 1)) & 1) as u32;
            let b = ((in2 >> (size_in * 8 - 1)) & 1) as u32;
            let mut r = ((res >> (size_in * 8 - 1)) & 1) as u32;
            r ^= a;
            a ^= b;
            a ^= 1;
            r &= a;
            r as u64
        }
        // Ghidra: opbehavior.cc:346 OpBehaviorIntSborrow::evaluateBinary
        // a = sign(in1), b = sign(in2), r = sign(diff); res = (a^r) & (r^b^1).
        OpCode::CPUI_INT_SBORROW => {
            if size_in == 0 {
                return Some(0);
            }
            let res = in1.wrapping_sub(in2);
            let mut a = ((in1 >> (size_in * 8 - 1)) & 1) as u32;
            let b = ((in2 >> (size_in * 8 - 1)) & 1) as u32;
            let mut r = ((res >> (size_in * 8 - 1)) & 1) as u32;
            a ^= r;
            r ^= b;
            r ^= 1;
            a &= r;
            a as u64
        }
        // Ghidra: opbehavior.cc:548 OpBehaviorBoolXor::evaluateBinary
        OpCode::CPUI_BOOL_XOR => in1 ^ in2,
        // Ghidra: opbehavior.cc:555 OpBehaviorBoolAnd::evaluateBinary
        OpCode::CPUI_BOOL_AND => in1 & in2,
        // Ghidra: opbehavior.cc:562 OpBehaviorBoolOr::evaluateBinary
        OpCode::CPUI_BOOL_OR => in1 | in2,
        // Ghidra: opbehavior.cc:752 OpBehaviorPiece::evaluateBinary
        // (in1<<((sizeout-sizein)*8)) | in2. Note Ghidra assumes sizein is the
        // size of *each* input piece.
        OpCode::CPUI_PIECE => (in1 << ((size_out - size_in) * 8)) | in2,
        // Ghidra: opbehavior.cc:759 OpBehaviorSubpiece::evaluateBinary
        // in2 is the truncated-byte offset (not a sized varnode value).
        OpCode::CPUI_SUBPIECE => {
            if in2 >= 8 {
                0
            } else {
                (in1 >> (in2 * 8)) & out_mask
            }
        }
        // Ghidra: opbehavior.cc:775 OpBehaviorPtrsub::evaluateBinary
        OpCode::CPUI_PTRSUB => (in1.wrapping_add(in2)) & out_mask,
        // CPUI_PTRADD is canonically ternary (opbehavior.hh:516); the binary
        // form used by older callers treats the missing wordsize as 1.
        // RUDRA-GLUE: binary PTRADD fallback for callers without wordsize
        OpCode::CPUI_PTRADD => (in1.wrapping_add(in2)) & out_mask,
        _ => return None,
    };
    Some(result & out_mask)
}

/// Evaluate a ternary P-code operation on constant inputs.
///
/// Only `CPUI_PTRADD` has a ternary behavior (opbehavior.hh:516 /
/// opbehavior.cc:768): `res = (in1 + in2 * in3) & mask(sizeout)`.
// Ghidra: opbehavior.cc:768 OpBehaviorPtradd::evaluateTernary
pub fn evaluate_ternary(
    opc: OpCode,
    size_out: usize,
    _size_in: usize,
    in1: u64,
    in2: u64,
    in3: u64,
) -> Option<u64> {
    let out_mask = calc_mask(size_out);
    let result = match opc {
        // Ghidra: opbehavior.cc:768 OpBehaviorPtradd::evaluateTernary
        OpCode::CPUI_PTRADD => (in1.wrapping_add(in2.wrapping_mul(in3))) & out_mask,
        _ => return None,
    };
    Some(result & out_mask)
}

/// Recover the input for a unary op given its output (inverse of
/// `evaluate_unary`). Returns `None` if recovery is not defined (lossy ops) or
/// if the output is out of range.
// Ghidra: opbehavior.cc:151 OpBehavior::recoverInputUnary + per-class overrides
pub fn recover_input_unary(
    opc: OpCode,
    size_out: usize,
    out: u64,
    size_in: usize,
) -> Option<u64> {
    let in_mask = calc_mask(size_in);
    let result = match opc {
        // Ghidra: opbehavior.cc:177 OpBehaviorCopy::recoverInputUnary
        OpCode::CPUI_COPY => out,
        // Ghidra: opbehavior.cc:257 OpBehaviorIntZext::recoverInputUnary
        // Throws if (mask&out)!=out; surfaced as None.
        OpCode::CPUI_INT_ZEXT => {
            if (in_mask & out) != out {
                return None;
            }
            out
        }
        // Ghidra: opbehavior.cc:273 OpBehaviorIntSext::recoverInputUnary
        OpCode::CPUI_INT_SEXT => {
            let mask_long = calc_mask(size_out);
            let mask_short = calc_mask(size_in);
            if (out & (mask_short ^ (mask_short >> 1))) == 0 {
                // Positive input.
                if (out & mask_short) != out {
                    return None;
                }
            } else if (out & (mask_long ^ mask_short)) != (mask_long ^ mask_short) {
                // Negative input.
                return None;
            }
            out & mask_short
        }
        // Ghidra: opbehavior.cc:383 OpBehaviorIntNegate::recoverInputUnary
        OpCode::CPUI_INT_NEGATE => uintb_negate(out, size_in),
        // Ghidra: opbehavior.cc:369 OpBehaviorInt2Comp::recoverInputUnary
        OpCode::CPUI_INT_2COMP => uintb_negate(out.wrapping_sub(1), size_in),
        // BOOL_NEGATE has no recoverInputUnary override in Ghidra; the base
        // class throws. Recovering input from `out^1` is technically sound for
        // a 1-bit boolean so we provide it, but mark as glue since Ghidra does
        // not implement it.
        // RUDRA-GLUE: BOOL_NEGATE recovery not implemented in Ghidra base class
        OpCode::CPUI_BOOL_NEGATE => return None,
        _ => return None,
    };
    Some(result & in_mask)
}

/// Recover one input of a binary op given the output and the other input.
///
/// `slot` selects which input to recover (0 = first, 1 = second). Returns
/// `None` if recovery is not defined for this opcode/slot or if the output is
/// out of range.
// Ghidra: opbehavior.cc:165 OpBehavior::recoverInputBinary + per-class overrides
pub fn recover_input_binary(
    opc: OpCode,
    slot: usize,
    size_out: usize,
    out: u64,
    size_in: usize,
    other: u64,
) -> Option<u64> {
    let in_mask = calc_mask(size_in);
    let result = match opc {
        // Ghidra: opbehavior.cc:297 OpBehaviorIntAdd::recoverInputBinary
        OpCode::CPUI_INT_ADD => out.wrapping_sub(other) & calc_mask(size_out),
        // Ghidra: opbehavior.cc:311 OpBehaviorIntSub::recoverInputBinary
        // slot 0: in + out ; slot 1: in - out
        OpCode::CPUI_INT_SUB => {
            let r = if slot == 0 {
                other.wrapping_add(out)
            } else {
                other.wrapping_sub(out)
            };
            r & calc_mask(size_out)
        }
        // Ghidra: opbehavior.cc:421 OpBehaviorIntLeft::recoverInputBinary
        // slot 0 (value): out >> sa, after verifying no high bits were lost.
        // slot 1 (shift amount): base class throws (return None).
        OpCode::CPUI_INT_LEFT => {
            if slot != 0 || other >= (size_out * 8) as u64 {
                return None;
            }
            let sa = other as usize;
            if (out << (8 * size_out - sa)) & calc_mask(size_out) != 0 {
                return None; // Output is not in range of left shift operation
            }
            out >> sa
        }
        // Ghidra: opbehavior.cc:442 OpBehaviorIntRight::recoverInputBinary
        // slot 0 (value): out << sa, after verifying no low bits were lost.
        // slot 1 (shift amount): base class throws (return None).
        OpCode::CPUI_INT_RIGHT => {
            if slot != 0 || other >= (size_out * 8) as u64 {
                return None;
            }
            let sa = other as usize;
            if (out >> (8 * size_in - sa)) != 0 {
                return None; // Output is not in range of right shift operation
            }
            out << sa
        }
        // Ghidra: opbehavior.cc:474 OpBehaviorIntSright::recoverInputBinary
        // slot 0 (value): out << sa, after verifying the top (sa+1) bits are
        // all 1s (negative) — i.e. the output really is a sign-extending shift.
        // slot 1 (shift amount): base class throws (return None).
        OpCode::CPUI_INT_SRIGHT => {
            if slot != 0 || other >= (size_out * 8) as u64 {
                return None;
            }
            let sa = other as usize;
            let mut testval = out >> (size_in * 8 - sa - 1);
            let mut count = 0;
            for _ in 0..=sa {
                if (testval & 1) != 0 {
                    count += 1;
                }
                testval >>= 1;
            }
            if count != sa + 1 {
                return None; // Output is not in range of right shift operation
            }
            out << sa
        }
        _ => return None,
    };
    Some(result & in_mask)
}

// ===========================================================================
// OOP trait + subclass hierarchy (direct port of opbehavior.hh classes).
//
// Each struct mirrors a `class OpBehavior*` in opbehavior.hh; the trait
// `OpBehavior` mirrors the C++ base class's virtual surface. The factory
// `OpBehaviorFactory::register_instructions` mirrors
// `OpBehavior::registerInstructions` (opbehavior.cc:38).
// ===========================================================================

/// Metadata describing an opcode behavior: which opcode it is, whether it is
/// unary, and whether it is "special" (neither unary nor binary — e.g. control
/// flow, MULTIEQUAL, INDIRECT).
// Ghidra: opbehavior.hh:44 OpBehavior (base class fields)
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorMeta {
    /// The internal enumeration for pcode types (opbehavior.hh:45).
    pub opcode: OpCode,
    /// true = use unary interfaces, false = use binary (opbehavior.hh:46).
    pub isunary: bool,
    /// Is op not a normal unary or binary op (opbehavior.hh:47).
    pub isspecial: bool,
}

impl OpBehaviorMeta {
    /// A normal (unary or binary) behavior constructor (opbehavior.hh:85).
    // Ghidra: opbehavior.hh:85 OpBehavior::OpBehavior(opc,isun)
    pub const fn new(opcode: OpCode, isunary: bool) -> Self {
        Self {
            opcode,
            isunary,
            isspecial: false,
        }
    }

    /// A special behavior constructor (opbehavior.hh:97).
    // Ghidra: opbehavior.hh:97 OpBehavior::OpBehavior(opc,isun,isspec)
    pub const fn new_special(opcode: OpCode, isunary: bool, isspecial: bool) -> Self {
        Self {
            opcode,
            isunary,
            isspecial,
        }
    }

    /// Get the opcode for this pcode operation (opbehavior.hh:108).
    // Ghidra: opbehavior.hh:108 OpBehavior::getOpcode
    pub const fn opcode(&self) -> OpCode {
        self.opcode
    }

    /// Check if this is a special operator (opbehavior.hh:115).
    // Ghidra: opbehavior.hh:115 OpBehavior::isSpecial
    pub const fn is_special(&self) -> bool {
        self.isspecial
    }

    /// Check if operator is unary (opbehavior.hh:121).
    // Ghidra: opbehavior.hh:121 OpBehavior::isUnary
    pub const fn is_unary(&self) -> bool {
        self.isunary
    }
}

/// Mirror of Ghidra's `OpBehavior` virtual interface (opbehavior.hh:44).
///
/// Each implementing struct corresponds 1:1 to a `class OpBehavior*` subclass
/// in `opbehavior.hh`. Default method bodies reproduce the C++ base-class
/// behavior (throwing `EvaluationError`), matching opbehavior.cc:128-183.
// Ghidra: opbehavior.hh:44 OpBehavior
pub trait OpBehavior {
    /// Metadata: opcode, unary/special flags (opbehavior.hh:45-47).
    // Ghidra: opbehavior.hh:56 OpBehavior::getOpcode / isSpecial / isUnary
    fn meta(&self) -> OpBehaviorMeta;

    /// Convenience: the opcode.
    // Ghidra: opbehavior.hh:108 OpBehavior::getOpcode
    fn opcode(&self) -> OpCode {
        self.meta().opcode()
    }

    /// Convenience: is this a special (non-unary/binary) op.
    // Ghidra: opbehavior.hh:115 OpBehavior::isSpecial
    fn is_special(&self) -> bool {
        self.meta().is_special()
    }

    /// Convenience: is this a unary op.
    // Ghidra: opbehavior.hh:121 OpBehavior::isUnary
    fn is_unary(&self) -> bool {
        self.meta().is_unary()
    }

    /// Emulate the unary op-code on an input value (opbehavior.hh:65).
    /// Base class throws (opbehavior.cc:128).
    // Ghidra: opbehavior.cc:114 OpBehavior::evaluateUnary
    fn evaluate_unary(&self, _sizeout: usize, _sizein: usize, _in1: u64) -> u64 {
        let name = self.opcode().name();
        panic!("Unary emulation unimplemented for {}", name);
    }

    /// Emulate the binary op-code on input values (opbehavior.hh:68).
    /// Base class throws (opbehavior.cc:140).
    // Ghidra: opbehavior.cc:126 OpBehavior::evaluateBinary
    fn evaluate_binary(&self, _sizeout: usize, _sizein: usize, _in1: u64, _in2: u64) -> u64 {
        let name = self.opcode().name();
        panic!("Binary emulation unimplemented for {}", name);
    }

    /// Emulate the ternary op-code on input values (opbehavior.hh:71).
    /// Base class throws (opbehavior.cc:153).
    // Ghidra: opbehavior.cc:139 OpBehavior::evaluateTernary
    fn evaluate_ternary(
        &self,
        _sizeout: usize,
        _sizein: usize,
        _in1: u64,
        _in2: u64,
        _in3: u64,
    ) -> u64 {
        let name = self.opcode().name();
        panic!("Ternary emulation unimplemented for {}", name);
    }

    /// Reverse the binary op-code, recovering an input value (opbehavior.hh:74).
    /// Base class throws (opbehavior.cc:179).
    // Ghidra: opbehavior.cc:165 OpBehavior::recoverInputBinary
    fn recover_input_binary(
        &self,
        _slot: usize,
        _sizeout: usize,
        _out: u64,
        _sizein: usize,
        _in: u64,
    ) -> u64 {
        panic!("Cannot recover input parameter without loss of information");
    }

    /// Reverse the unary op-code, recovering the input value (opbehavior.hh:77).
    /// Base class throws (opbehavior.cc:165).
    // Ghidra: opbehavior.cc:151 OpBehavior::recoverInputUnary
    fn recover_input_unary(&self, _sizeout: usize, _out: u64, _sizein: usize) -> u64 {
        panic!("Cannot recover input parameter without loss of information");
    }
}

/// Non-panicking variants matching Ghidra Java's
/// `OpBehavior.evaluateUnaryNoExc` / `evaluateBinaryNoExc` semantics: on
/// failure (no behavior, divide-by-zero, or base-class throw) return `None`.
/// These route through the free functions which already encode that contract.
// RUDRA-GLUE: NoExc wrappers (Ghidra Java OpBehavior API); reuse free fns
pub fn evaluate_unary_no_exc(
    opc: OpCode,
    sizeout: usize,
    sizein: usize,
    in1: u64,
) -> Option<u64> {
    evaluate_unary(opc, sizeout, sizein, in1)
}

/// Non-panicking binary evaluate; see [`evaluate_unary_no_exc`].
// RUDRA-GLUE: NoExc wrappers (Ghidra Java OpBehavior API); reuse free fns
pub fn evaluate_binary_no_exc(
    opc: OpCode,
    sizeout: usize,
    sizein: usize,
    in1: u64,
    in2: u64,
) -> Option<u64> {
    evaluate_binary(opc, sizeout, sizein, in1, in2)
}

// ---------------------------------------------------------------------------
// Macro to reduce boilerplate for the trivial 1:1 subclass ports.
// ---------------------------------------------------------------------------

/// Generates an `OpBehavior` implementation whose `evaluate*`/`recover*`
/// methods delegate to the matching free-function arm. Each generated method
/// is annotated with its Ghidra source line.
macro_rules! impl_eval_only {
    ($ty:ty, $opc:expr, $isunary:expr, $evalu:ident, $evalb:ident) => {
        impl OpBehavior for $ty {
            // RUDRA-GLUE: declarative-macro template for per-subclass metadata; Ghidra stores these fields in separate inline constructors
            fn meta(&self) -> OpBehaviorMeta {
                OpBehaviorMeta::new($opc, $isunary)
            }
            impl_eval_only!(@method $evalu, $evalb);
        }
    };
    (@method unary, binary) => {
        // RUDRA-GLUE: declarative-macro template delegating generated unary trait methods; Ghidra defines separate subclass virtual functions
        fn evaluate_unary(&self, sizeout: usize, sizein: usize, in1: u64) -> u64 {
            evaluate_unary(self.opcode(), sizeout, sizein, in1)
                .expect("evaluate_unary returned None for known unary behavior")
        }
    };
    (@method binary, unary) => {
        // RUDRA-GLUE: declarative-macro template delegating generated binary trait methods; Ghidra defines separate subclass virtual functions
        fn evaluate_binary(
            &self,
            sizeout: usize,
            sizein: usize,
            in1: u64,
            in2: u64,
        ) -> u64 {
            evaluate_binary(self.opcode(), sizeout, sizein, in1, in2)
                .expect("evaluate_binary returned None for known binary behavior")
        }
    };
}

// ===========================================================================
// CPUI_COPY — OpBehaviorCopy (opbehavior.hh:128)
// ===========================================================================

/// CPUI_COPY behavior (opbehavior.hh:128).
// Ghidra: opbehavior.hh:128 OpBehaviorCopy
pub struct OpBehaviorCopy;

impl OpBehaviorCopy {
    // Ghidra: opbehavior.hh:130 OpBehaviorCopy::OpBehaviorCopy
    pub const fn new() -> Self {
        Self
    }
}

impl OpBehavior for OpBehaviorCopy {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorCopy; Ghidra stores CPUI_COPY/unary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_COPY, true)
    }
    // Ghidra: opbehavior.cc:171 OpBehaviorCopy::evaluateUnary
    fn evaluate_unary(&self, _sizeout: usize, _sizein: usize, in1: u64) -> u64 {
        in1
    }
    // Ghidra: opbehavior.cc:177 OpBehaviorCopy::recoverInputUnary
    fn recover_input_unary(&self, _sizeout: usize, out: u64, _sizein: usize) -> u64 {
        out
    }
}

// ===========================================================================
// CPUI_INT_EQUAL / NOTEQUAL — OpBehaviorEqual / OpBehaviorNotEqual
// ===========================================================================

/// CPUI_INT_EQUAL behavior (opbehavior.hh:136).
// Ghidra: opbehavior.hh:136 OpBehaviorEqual
pub struct OpBehaviorEqual;
impl OpBehaviorEqual {
    // Ghidra: opbehavior.hh:138 OpBehaviorEqual::OpBehaviorEqual
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(OpBehaviorEqual, OpCode::CPUI_INT_EQUAL, false, binary, unary);

/// CPUI_INT_NOTEQUAL behavior (opbehavior.hh:143).
// Ghidra: opbehavior.hh:143 OpBehaviorNotEqual
pub struct OpBehaviorNotEqual;
impl OpBehaviorNotEqual {
    // Ghidra: opbehavior.hh:145 OpBehaviorNotEqual::OpBehaviorNotEqual
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorNotEqual,
    OpCode::CPUI_INT_NOTEQUAL,
    false,
    binary,
    unary
);

// ===========================================================================
// CPUI_INT_SLESS / SLESSEQUAL
// ===========================================================================

/// CPUI_INT_SLESS behavior (opbehavior.hh:150).
// Ghidra: opbehavior.hh:150 OpBehaviorIntSless
pub struct OpBehaviorIntSless;
impl OpBehaviorIntSless {
    // Ghidra: opbehavior.hh:152 OpBehaviorIntSless::OpBehaviorIntSless
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorIntSless,
    OpCode::CPUI_INT_SLESS,
    false,
    binary,
    unary
);

/// CPUI_INT_SLESSEQUAL behavior (opbehavior.hh:157).
// Ghidra: opbehavior.hh:157 OpBehaviorIntSlessEqual
pub struct OpBehaviorIntSlessEqual;
impl OpBehaviorIntSlessEqual {
    // Ghidra: opbehavior.hh:159 OpBehaviorIntSlessEqual::OpBehaviorIntSlessEqual
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorIntSlessEqual,
    OpCode::CPUI_INT_SLESSEQUAL,
    false,
    binary,
    unary
);

// ===========================================================================
// CPUI_INT_LESS / LESSEQUAL
// ===========================================================================

/// CPUI_INT_LESS behavior (opbehavior.hh:164).
// Ghidra: opbehavior.hh:164 OpBehaviorIntLess
pub struct OpBehaviorIntLess;
impl OpBehaviorIntLess {
    // Ghidra: opbehavior.hh:166 OpBehaviorIntLess::OpBehaviorIntLess
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(OpBehaviorIntLess, OpCode::CPUI_INT_LESS, false, binary, unary);

/// CPUI_INT_LESSEQUAL behavior (opbehavior.hh:171).
// Ghidra: opbehavior.hh:171 OpBehaviorIntLessEqual
pub struct OpBehaviorIntLessEqual;
impl OpBehaviorIntLessEqual {
    // Ghidra: opbehavior.hh:173 OpBehaviorIntLessEqual::OpBehaviorIntLessEqual
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorIntLessEqual,
    OpCode::CPUI_INT_LESSEQUAL,
    false,
    binary,
    unary
);

// ===========================================================================
// CPUI_INT_ZEXT / SEXT
// ===========================================================================

/// CPUI_INT_ZEXT behavior (opbehavior.hh:178).
// Ghidra: opbehavior.hh:178 OpBehaviorIntZext
pub struct OpBehaviorIntZext;
impl OpBehaviorIntZext {
    // Ghidra: opbehavior.hh:180 OpBehaviorIntZext::OpBehaviorIntZext
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntZext {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntZext; Ghidra stores CPUI_INT_ZEXT/unary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_ZEXT, true)
    }
    // Ghidra: opbehavior.cc:251 OpBehaviorIntZext::evaluateUnary
    fn evaluate_unary(&self, _sizeout: usize, _sizein: usize, in1: u64) -> u64 {
        in1
    }
    // Ghidra: opbehavior.cc:257 OpBehaviorIntZext::recoverInputUnary
    fn recover_input_unary(&self, _sizeout: usize, out: u64, sizein: usize) -> u64 {
        let m = calc_mask(sizein);
        if (m & out) != out {
            panic!("Output is not in range of zext operation");
        }
        out
    }
}

/// CPUI_INT_SEXT behavior (opbehavior.hh:186).
// Ghidra: opbehavior.hh:186 OpBehaviorIntSext
pub struct OpBehaviorIntSext;
impl OpBehaviorIntSext {
    // Ghidra: opbehavior.hh:188 OpBehaviorIntSext::OpBehaviorIntSext
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntSext {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntSext; Ghidra stores CPUI_INT_SEXT/unary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_SEXT, true)
    }
    // Ghidra: opbehavior.cc:266 OpBehaviorIntSext::evaluateUnary
    fn evaluate_unary(&self, sizeout: usize, sizein: usize, in1: u64) -> u64 {
        sign_extend_size(in1, sizein, sizeout)
    }
    // Ghidra: opbehavior.cc:273 OpBehaviorIntSext::recoverInputUnary
    fn recover_input_unary(&self, sizeout: usize, out: u64, sizein: usize) -> u64 {
        let masklong = calc_mask(sizeout);
        let maskshort = calc_mask(sizein);
        if (out & (maskshort ^ (maskshort >> 1))) == 0 {
            if (out & maskshort) != out {
                panic!("Output is not in range of sext operation");
            }
        } else if (out & (masklong ^ maskshort)) != (masklong ^ maskshort) {
            panic!("Output is not in range of sext operation");
        }
        out & maskshort
    }
}

// ===========================================================================
// CPUI_INT_ADD / SUB (with recoverInputBinary)
// ===========================================================================

/// CPUI_INT_ADD behavior (opbehavior.hh:194).
// Ghidra: opbehavior.hh:194 OpBehaviorIntAdd
pub struct OpBehaviorIntAdd;
impl OpBehaviorIntAdd {
    // Ghidra: opbehavior.hh:196 OpBehaviorIntAdd::OpBehaviorIntAdd
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntAdd {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntAdd; Ghidra stores CPUI_INT_ADD/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_ADD, false)
    }
    // Ghidra: opbehavior.cc:290 OpBehaviorIntAdd::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        (in1.wrapping_add(in2)) & calc_mask(sizeout)
    }
    // Ghidra: opbehavior.cc:297 OpBehaviorIntAdd::recoverInputBinary
    fn recover_input_binary(
        &self,
        _slot: usize,
        sizeout: usize,
        out: u64,
        _sizein: usize,
        in_: u64,
    ) -> u64 {
        (out.wrapping_sub(in_)) & calc_mask(sizeout)
    }
}

/// CPUI_INT_SUB behavior (opbehavior.hh:202).
// Ghidra: opbehavior.hh:202 OpBehaviorIntSub
pub struct OpBehaviorIntSub;
impl OpBehaviorIntSub {
    // Ghidra: opbehavior.hh:204 OpBehaviorIntSub::OpBehaviorIntSub
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntSub {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntSub; Ghidra stores CPUI_INT_SUB/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_SUB, false)
    }
    // Ghidra: opbehavior.cc:304 OpBehaviorIntSub::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        (in1.wrapping_sub(in2)) & calc_mask(sizeout)
    }
    // Ghidra: opbehavior.cc:311 OpBehaviorIntSub::recoverInputBinary
    fn recover_input_binary(
        &self,
        slot: usize,
        sizeout: usize,
        out: u64,
        _sizein: usize,
        in_: u64,
    ) -> u64 {
        let res = if slot == 0 {
            in_.wrapping_add(out)
        } else {
            in_.wrapping_sub(out)
        };
        res & calc_mask(sizeout)
    }
}

// ===========================================================================
// CPUI_INT_CARRY / SCARRY / SBORROW
// ===========================================================================

/// CPUI_INT_CARRY behavior (opbehavior.hh:210).
// Ghidra: opbehavior.hh:210 OpBehaviorIntCarry
pub struct OpBehaviorIntCarry;
impl OpBehaviorIntCarry {
    // Ghidra: opbehavior.hh:212 OpBehaviorIntCarry::OpBehaviorIntCarry
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorIntCarry,
    OpCode::CPUI_INT_CARRY,
    false,
    binary,
    unary
);

/// CPUI_INT_SCARRY behavior (opbehavior.hh:217).
// Ghidra: opbehavior.hh:217 OpBehaviorIntScarry
pub struct OpBehaviorIntScarry;
impl OpBehaviorIntScarry {
    // Ghidra: opbehavior.hh:219 OpBehaviorIntScarry::OpBehaviorIntScarry
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorIntScarry,
    OpCode::CPUI_INT_SCARRY,
    false,
    binary,
    unary
);

/// CPUI_INT_SBORROW behavior (opbehavior.hh:224).
// Ghidra: opbehavior.hh:224 OpBehaviorIntSborrow
pub struct OpBehaviorIntSborrow;
impl OpBehaviorIntSborrow {
    // Ghidra: opbehavior.hh:226 OpBehaviorIntSborrow::OpBehaviorIntSborrow
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorIntSborrow,
    OpCode::CPUI_INT_SBORROW,
    false,
    binary,
    unary
);

// ===========================================================================
// CPUI_INT_2COMP / NEGATE (unary, with recoverInputUnary)
// ===========================================================================

/// CPUI_INT_2COMP behavior (opbehavior.hh:231).
// Ghidra: opbehavior.hh:231 OpBehaviorInt2Comp
pub struct OpBehaviorInt2Comp;
impl OpBehaviorInt2Comp {
    // Ghidra: opbehavior.hh:233 OpBehaviorInt2Comp::OpBehaviorInt2Comp
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorInt2Comp {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorInt2Comp; Ghidra stores CPUI_INT_2COMP/unary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_2COMP, true)
    }
    // Ghidra: opbehavior.cc:362 OpBehaviorInt2Comp::evaluateUnary
    fn evaluate_unary(&self, _sizeout: usize, sizein: usize, in1: u64) -> u64 {
        uintb_negate(in1.wrapping_sub(1), sizein)
    }
    // Ghidra: opbehavior.cc:369 OpBehaviorInt2Comp::recoverInputUnary
    fn recover_input_unary(&self, _sizeout: usize, out: u64, sizein: usize) -> u64 {
        uintb_negate(out.wrapping_sub(1), sizein)
    }
}

/// CPUI_INT_NEGATE behavior (opbehavior.hh:239).
// Ghidra: opbehavior.hh:239 OpBehaviorIntNegate
pub struct OpBehaviorIntNegate;
impl OpBehaviorIntNegate {
    // Ghidra: opbehavior.hh:241 OpBehaviorIntNegate::OpBehaviorIntNegate
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntNegate {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntNegate; Ghidra stores CPUI_INT_NEGATE/unary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_NEGATE, true)
    }
    // Ghidra: opbehavior.cc:376 OpBehaviorIntNegate::evaluateUnary
    fn evaluate_unary(&self, _sizeout: usize, sizein: usize, in1: u64) -> u64 {
        uintb_negate(in1, sizein)
    }
    // Ghidra: opbehavior.cc:383 OpBehaviorIntNegate::recoverInputUnary
    fn recover_input_unary(&self, _sizeout: usize, out: u64, sizein: usize) -> u64 {
        uintb_negate(out, sizein)
    }
}

// ===========================================================================
// CPUI_INT_XOR / AND / OR
// ===========================================================================

/// CPUI_INT_XOR behavior (opbehavior.hh:247).
// Ghidra: opbehavior.hh:247 OpBehaviorIntXor
pub struct OpBehaviorIntXor;
impl OpBehaviorIntXor {
    // Ghidra: opbehavior.hh:249 OpBehaviorIntXor::OpBehaviorIntXor
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(OpBehaviorIntXor, OpCode::CPUI_INT_XOR, false, binary, unary);

/// CPUI_INT_AND behavior (opbehavior.hh:254).
// Ghidra: opbehavior.hh:254 OpBehaviorIntAnd
pub struct OpBehaviorIntAnd;
impl OpBehaviorIntAnd {
    // Ghidra: opbehavior.hh:256 OpBehaviorIntAnd::OpBehaviorIntAnd
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(OpBehaviorIntAnd, OpCode::CPUI_INT_AND, false, binary, unary);

/// CPUI_INT_OR behavior (opbehavior.hh:261).
// Ghidra: opbehavior.hh:261 OpBehaviorIntOr
pub struct OpBehaviorIntOr;
impl OpBehaviorIntOr {
    // Ghidra: opbehavior.hh:263 OpBehaviorIntOr::OpBehaviorIntOr
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(OpBehaviorIntOr, OpCode::CPUI_INT_OR, false, binary, unary);

// ===========================================================================
// CPUI_INT_LEFT / RIGHT / SRIGHT (binary, with recoverInputBinary)
// ===========================================================================

/// CPUI_INT_LEFT behavior (opbehavior.hh:268).
// Ghidra: opbehavior.hh:268 OpBehaviorIntLeft
pub struct OpBehaviorIntLeft;
impl OpBehaviorIntLeft {
    // Ghidra: opbehavior.hh:270 OpBehaviorIntLeft::OpBehaviorIntLeft
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntLeft {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntLeft; Ghidra stores CPUI_INT_LEFT/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_LEFT, false)
    }
    // Ghidra: opbehavior.cc:411 OpBehaviorIntLeft::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 >= (sizeout * 8) as u64 {
            0
        } else {
            (in1 << in2) & calc_mask(sizeout)
        }
    }
    // Ghidra: opbehavior.cc:421 OpBehaviorIntLeft::recoverInputBinary
    fn recover_input_binary(
        &self,
        slot: usize,
        sizeout: usize,
        out: u64,
        sizein: usize,
        in_: u64,
    ) -> u64 {
        if slot != 0 || in_ >= (sizeout * 8) as u64 {
            panic!("Cannot recover input parameter without loss of information");
        }
        let sa = in_ as usize;
        if (out << (8 * sizeout - sa)) & calc_mask(sizeout) != 0 {
            panic!("Output is not in range of left shift operation");
        }
        out >> sa
    }
}

/// CPUI_INT_RIGHT behavior (opbehavior.hh:276).
// Ghidra: opbehavior.hh:276 OpBehaviorIntRight
pub struct OpBehaviorIntRight;
impl OpBehaviorIntRight {
    // Ghidra: opbehavior.hh:278 OpBehaviorIntRight::OpBehaviorIntRight
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntRight {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntRight; Ghidra stores CPUI_INT_RIGHT/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_RIGHT, false)
    }
    // Ghidra: opbehavior.cc:432 OpBehaviorIntRight::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 >= (sizeout * 8) as u64 {
            0
        } else {
            (in1 & calc_mask(sizeout)) >> in2
        }
    }
    // Ghidra: opbehavior.cc:442 OpBehaviorIntRight::recoverInputBinary
    fn recover_input_binary(
        &self,
        slot: usize,
        sizeout: usize,
        out: u64,
        sizein: usize,
        in_: u64,
    ) -> u64 {
        if slot != 0 || in_ >= (sizeout * 8) as u64 {
            panic!("Cannot recover input parameter without loss of information");
        }
        let sa = in_ as usize;
        if (out >> (8 * sizein - sa)) != 0 {
            panic!("Output is not in range of right shift operation");
        }
        out << sa
    }
}

/// CPUI_INT_SRIGHT behavior (opbehavior.hh:284).
// Ghidra: opbehavior.hh:284 OpBehaviorIntSright
pub struct OpBehaviorIntSright;
impl OpBehaviorIntSright {
    // Ghidra: opbehavior.hh:286 OpBehaviorIntSright::OpBehaviorIntSright
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntSright {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntSright; Ghidra stores CPUI_INT_SRIGHT/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_SRIGHT, false)
    }
    // Ghidra: opbehavior.cc:454 OpBehaviorIntSright::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 >= (8 * sizeout) as u64 {
            if signbit_negative(in1, sizein) {
                calc_mask(sizeout)
            } else {
                0
            }
        } else if signbit_negative(in1, sizein) {
            let mut res = in1 >> in2;
            let mut m = calc_mask(sizein);
            m = (m >> in2) ^ m;
            res |= m;
            res
        } else {
            in1 >> in2
        }
    }
    // Ghidra: opbehavior.cc:474 OpBehaviorIntSright::recoverInputBinary
    fn recover_input_binary(
        &self,
        slot: usize,
        sizeout: usize,
        out: u64,
        sizein: usize,
        in_: u64,
    ) -> u64 {
        if slot != 0 || in_ >= (sizeout * 8) as u64 {
            panic!("Cannot recover input parameter without loss of information");
        }
        let sa = in_ as usize;
        let mut testval = out >> (sizein * 8 - sa - 1);
        let mut count = 0;
        for _ in 0..=sa {
            if (testval & 1) != 0 {
                count += 1;
            }
            testval >>= 1;
        }
        if count != sa + 1 {
            panic!("Output is not in range of right shift operation");
        }
        out << sa
    }
}

// ===========================================================================
// CPUI_INT_MULT / DIV / SDIV / REM / SREM
// ===========================================================================

/// CPUI_INT_MULT behavior (opbehavior.hh:292).
// Ghidra: opbehavior.hh:292 OpBehaviorIntMult
pub struct OpBehaviorIntMult;
impl OpBehaviorIntMult {
    // Ghidra: opbehavior.hh:294 OpBehaviorIntMult::OpBehaviorIntMult
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorIntMult,
    OpCode::CPUI_INT_MULT,
    false,
    binary,
    unary
);

/// CPUI_INT_DIV behavior (opbehavior.hh:299).
// Ghidra: opbehavior.hh:299 OpBehaviorIntDiv
pub struct OpBehaviorIntDiv;
impl OpBehaviorIntDiv {
    // Ghidra: opbehavior.hh:301 OpBehaviorIntDiv::OpBehaviorIntDiv
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntDiv {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntDiv; Ghidra stores CPUI_INT_DIV/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_DIV, false)
    }
    // Ghidra: opbehavior.cc:499 OpBehaviorIntDiv::evaluateBinary
    // Throws EvaluationError on divide-by-zero in Ghidra; here we panic to
    // match the trait contract (use evaluate_binary_no_exc for safe access).
    fn evaluate_binary(&self, _sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 == 0 {
            panic!("Divide by 0");
        }
        in1 / in2
    }
}

/// CPUI_INT_SDIV behavior (opbehavior.hh:306).
// Ghidra: opbehavior.hh:306 OpBehaviorIntSdiv
pub struct OpBehaviorIntSdiv;
impl OpBehaviorIntSdiv {
    // Ghidra: opbehavior.hh:308 OpBehaviorIntSdiv::OpBehaviorIntSdiv
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntSdiv {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntSdiv; Ghidra stores CPUI_INT_SDIV/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_SDIV, false)
    }
    // Ghidra: opbehavior.cc:507 OpBehaviorIntSdiv::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 == 0 {
            panic!("Divide by 0");
        }
        let num = sign_extend_to_i64(in1, sizein);
        let denom = sign_extend_to_i64(in2, sizein);
        let sres = num / denom;
        zero_extend(sres, sizeout)
    }
}

/// CPUI_INT_REM behavior (opbehavior.hh:313).
// Ghidra: opbehavior.hh:313 OpBehaviorIntRem
pub struct OpBehaviorIntRem;
impl OpBehaviorIntRem {
    // Ghidra: opbehavior.hh:315 OpBehaviorIntRem::OpBehaviorIntRem
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntRem {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntRem; Ghidra stores CPUI_INT_REM/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_REM, false)
    }
    // Ghidra: opbehavior.cc:519 OpBehaviorIntRem::evaluateBinary
    fn evaluate_binary(&self, _sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 == 0 {
            panic!("Remainder by 0");
        }
        in1 % in2
    }
}

/// CPUI_INT_SREM behavior (opbehavior.hh:320).
// Ghidra: opbehavior.hh:320 OpBehaviorIntSrem
pub struct OpBehaviorIntSrem;
impl OpBehaviorIntSrem {
    // Ghidra: opbehavior.hh:322 OpBehaviorIntSrem::OpBehaviorIntSrem
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorIntSrem {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorIntSrem; Ghidra stores CPUI_INT_SREM/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_INT_SREM, false)
    }
    // Ghidra: opbehavior.cc:529 OpBehaviorIntSrem::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 == 0 {
            panic!("Remainder by 0");
        }
        let val = sign_extend_to_i64(in1, sizein);
        let modulus = sign_extend_to_i64(in2, sizein);
        let sres = val % modulus;
        zero_extend(sres, sizeout)
    }
}

// ===========================================================================
// CPUI_BOOL_NEGATE / XOR / AND / OR
// ===========================================================================

/// CPUI_BOOL_NEGATE behavior (opbehavior.hh:327).
// Ghidra: opbehavior.hh:327 OpBehaviorBoolNegate
pub struct OpBehaviorBoolNegate;
impl OpBehaviorBoolNegate {
    // Ghidra: opbehavior.hh:329 OpBehaviorBoolNegate::OpBehaviorBoolNegate
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorBoolNegate {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorBoolNegate; Ghidra stores CPUI_BOOL_NEGATE/unary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_BOOL_NEGATE, true)
    }
    // Ghidra: opbehavior.cc:541 OpBehaviorBoolNegate::evaluateUnary
    fn evaluate_unary(&self, _sizeout: usize, _sizein: usize, in1: u64) -> u64 {
        in1 ^ 1
    }
}

/// CPUI_BOOL_XOR behavior (opbehavior.hh:334).
// Ghidra: opbehavior.hh:334 OpBehaviorBoolXor
pub struct OpBehaviorBoolXor;
impl OpBehaviorBoolXor {
    // Ghidra: opbehavior.hh:336 OpBehaviorBoolXor::OpBehaviorBoolXor
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorBoolXor,
    OpCode::CPUI_BOOL_XOR,
    false,
    binary,
    unary
);

/// CPUI_BOOL_AND behavior (opbehavior.hh:341).
// Ghidra: opbehavior.hh:341 OpBehaviorBoolAnd
pub struct OpBehaviorBoolAnd;
impl OpBehaviorBoolAnd {
    // Ghidra: opbehavior.hh:343 OpBehaviorBoolAnd::OpBehaviorBoolAnd
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorBoolAnd,
    OpCode::CPUI_BOOL_AND,
    false,
    binary,
    unary
);

/// CPUI_BOOL_OR behavior (opbehavior.hh:348).
// Ghidra: opbehavior.hh:348 OpBehaviorBoolOr
pub struct OpBehaviorBoolOr;
impl OpBehaviorBoolOr {
    // Ghidra: opbehavior.hh:350 OpBehaviorBoolOr::OpBehaviorBoolOr
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(OpBehaviorBoolOr, OpCode::CPUI_BOOL_OR, false, binary, unary);

// ===========================================================================
// CPUI_FLOAT_* — OpBehaviorFloat* (opbehavior.hh:354-496)
//
// In Ghidra these carry a `const Translate *translate` member to look up the
// FloatFormat for a given size. Rugra has no Translate object at this layer,
// so the float behaviors hold a closure `fmt_lookup: Fn(usize) -> Option<&'static FloatFormat>`
// instead. The static float formats (single/double precision) are constructed
// once and reused.
// ===========================================================================

/// Static FloatFormat cache for the float behaviors. Mirrors the formats a
/// `Translate` object would expose via `getFloatFormat`. Currently IEEE754
/// single (4 bytes) and double (8 bytes).
///
/// Lazily constructed because `FloatFormat::new` is not `const`.
// RUDRA-GLUE: stand-in for Translate::getFloatFormat(size) (float.cc layer)
pub fn float_format(size: usize) -> Option<&'static FloatFormat> {
    match size {
        4 => Some(FLOAT_FMT_4.get_or_init(|| FloatFormat::new(4))),
        8 => Some(FLOAT_FMT_8.get_or_init(|| FloatFormat::new(8))),
        _ => None,
    }
}

static FLOAT_FMT_4: std::sync::OnceLock<FloatFormat> = std::sync::OnceLock::new();
static FLOAT_FMT_8: std::sync::OnceLock<FloatFormat> = std::sync::OnceLock::new();

macro_rules! float_binary_behavior {
    ($ty:ident, $opc:expr, $method:ident, $ghidra_decl:expr, $ghidra_eval:expr) => {
        // Ghidra: opbehavior.hh:$ghidra_decl
        pub struct $ty;
        impl $ty {
            // RUDRA-GLUE: one template emits eight zero-sized constructors; Ghidra defines distinct Translate-bearing constructors at opbehavior.hh:358,366,374,382,398,406,414,422
            pub const fn new() -> Self { Self }
        }
        impl OpBehavior for $ty {
            // RUDRA-GLUE: macro-generated metadata adapter for binary float behaviors; Ghidra stores these fields in each Translate-bearing constructor and has no meta() virtual
            fn meta(&self) -> OpBehaviorMeta { OpBehaviorMeta::new($opc, false) }
            // Ghidra: opbehavior.cc:$ghidra_eval $ty::evaluateBinary
            fn evaluate_binary(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
                match float_format(sizein) {
                    Some(fmt) => fmt.$method(in1, in2),
                    None => {
                        let _ = sizeout;
                        let name = self.opcode().name();
                        panic!("Binary emulation unimplemented for {}", name)
                    }
                }
            }
        }
    };
}

macro_rules! float_unary_behavior {
    ($ty:ident, $opc:expr, $method:ident, $ghidra_decl:expr, $ghidra_eval:expr) => {
        // Ghidra: opbehavior.hh:$ghidra_decl
        pub struct $ty;
        impl $ty {
            // RUDRA-GLUE: one template emits seven zero-sized constructors; Ghidra defines distinct Translate-bearing constructors at opbehavior.hh:390,430,438,446,478,486,494
            pub const fn new() -> Self { Self }
        }
        impl OpBehavior for $ty {
            // RUDRA-GLUE: macro-generated metadata adapter for unary float behaviors; Ghidra stores these fields in each Translate-bearing constructor and has no meta() virtual
            fn meta(&self) -> OpBehaviorMeta { OpBehaviorMeta::new($opc, true) }
            // Ghidra: opbehavior.cc:$ghidra_eval $ty::evaluateUnary
            fn evaluate_unary(&self, sizeout: usize, sizein: usize, in1: u64) -> u64 {
                match float_format(sizein) {
                    Some(fmt) => fmt.$method(in1),
                    None => {
                        let _ = sizeout;
                        let name = self.opcode().name();
                        panic!("Unary emulation unimplemented for {}", name)
                    }
                }
            }
        }
    };
}

// CPUI_FLOAT_EQUAL (opbehavior.hh:355) / opbehavior.cc:598
float_binary_behavior!(OpBehaviorFloatEqual, OpCode::CPUI_FLOAT_EQUAL, op_equal, "355 OpBehaviorFloatEqual", "598 OpBehaviorFloatEqual::evaluateBinary");
// CPUI_FLOAT_NOTEQUAL (opbehavior.hh:363) / opbehavior.cc:608
float_binary_behavior!(OpBehaviorFloatNotEqual, OpCode::CPUI_FLOAT_NOTEQUAL, op_not_equal, "363 OpBehaviorFloatNotEqual", "608 OpBehaviorFloatNotEqual::evaluateBinary");
// CPUI_FLOAT_LESS (opbehavior.hh:371) / opbehavior.cc:618
float_binary_behavior!(OpBehaviorFloatLess, OpCode::CPUI_FLOAT_LESS, op_less, "371 OpBehaviorFloatLess", "618 OpBehaviorFloatLess::evaluateBinary");
// CPUI_FLOAT_LESSEQUAL (opbehavior.hh:379) / opbehavior.cc:628
float_binary_behavior!(OpBehaviorFloatLessEqual, OpCode::CPUI_FLOAT_LESSEQUAL, op_less_equal, "379 OpBehaviorFloatLessEqual", "628 OpBehaviorFloatLessEqual::evaluateBinary");
// CPUI_FLOAT_ADD (opbehavior.hh:395) / opbehavior.cc:648
float_binary_behavior!(OpBehaviorFloatAdd, OpCode::CPUI_FLOAT_ADD, op_add, "395 OpBehaviorFloatAdd", "648 OpBehaviorFloatAdd::evaluateBinary");
// CPUI_FLOAT_DIV (opbehavior.hh:403) / opbehavior.cc:658
float_binary_behavior!(OpBehaviorFloatDiv, OpCode::CPUI_FLOAT_DIV, op_div, "403 OpBehaviorFloatDiv", "658 OpBehaviorFloatDiv::evaluateBinary");
// CPUI_FLOAT_MULT (opbehavior.hh:411) / opbehavior.cc:668
float_binary_behavior!(OpBehaviorFloatMult, OpCode::CPUI_FLOAT_MULT, op_mult, "411 OpBehaviorFloatMult", "668 OpBehaviorFloatMult::evaluateBinary");
// CPUI_FLOAT_SUB (opbehavior.hh:419) / opbehavior.cc:678
float_binary_behavior!(OpBehaviorFloatSub, OpCode::CPUI_FLOAT_SUB, op_sub, "419 OpBehaviorFloatSub", "678 OpBehaviorFloatSub::evaluateBinary");

// CPUI_FLOAT_NAN (opbehavior.hh:387) / opbehavior.cc:638
float_unary_behavior!(OpBehaviorFloatNan, OpCode::CPUI_FLOAT_NAN, op_nan, "387 OpBehaviorFloatNan", "638 OpBehaviorFloatNan::evaluateUnary");
// CPUI_FLOAT_NEG (opbehavior.hh:427) / opbehavior.cc:688
float_unary_behavior!(OpBehaviorFloatNeg, OpCode::CPUI_FLOAT_NEG, op_neg, "427 OpBehaviorFloatNeg", "688 OpBehaviorFloatNeg::evaluateUnary");
// CPUI_FLOAT_ABS (opbehavior.hh:435) / opbehavior.cc:698
float_unary_behavior!(OpBehaviorFloatAbs, OpCode::CPUI_FLOAT_ABS, op_abs, "435 OpBehaviorFloatAbs", "698 OpBehaviorFloatAbs::evaluateUnary");
// CPUI_FLOAT_SQRT (opbehavior.hh:443) / opbehavior.cc:708
float_unary_behavior!(OpBehaviorFloatSqrt, OpCode::CPUI_FLOAT_SQRT, op_sqrt, "443 OpBehaviorFloatSqrt", "708 OpBehaviorFloatSqrt::evaluateUnary");
// CPUI_FLOAT_CEIL (opbehavior.hh:475) / opbehavior.cc:751
float_unary_behavior!(OpBehaviorFloatCeil, OpCode::CPUI_FLOAT_CEIL, op_ceil, "475 OpBehaviorFloatCeil", "751 OpBehaviorFloatCeil::evaluateUnary");
// CPUI_FLOAT_FLOOR (opbehavior.hh:483) / opbehavior.cc:761
float_unary_behavior!(OpBehaviorFloatFloor, OpCode::CPUI_FLOAT_FLOOR, op_floor, "483 OpBehaviorFloatFloor", "761 OpBehaviorFloatFloor::evaluateUnary");
// CPUI_FLOAT_ROUND (opbehavior.hh:491) / opbehavior.cc:771
float_unary_behavior!(OpBehaviorFloatRound, OpCode::CPUI_FLOAT_ROUND, op_round, "491 OpBehaviorFloatRound", "771 OpBehaviorFloatRound::evaluateUnary");

/// CPUI_FLOAT_INT2FLOAT behavior (opbehavior.hh:451).
///
/// Differs from the other float behaviors: the format is looked up by
/// `sizeout` (not `sizein`), because the *output* is the float.
// Ghidra: opbehavior.hh:451 OpBehaviorFloatInt2Float
pub struct OpBehaviorFloatInt2Float;
impl OpBehaviorFloatInt2Float {
    // Ghidra: opbehavior.hh:454 OpBehaviorFloatInt2Float::OpBehaviorFloatInt2Float
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorFloatInt2Float {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorFloatInt2Float; Ghidra stores CPUI_FLOAT_INT2FLOAT/unary/non-special in its Translate-bearing constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_FLOAT_INT2FLOAT, true)
    }
    // Ghidra: opbehavior.cc:689 OpBehaviorFloatInt2Float::evaluateUnary
    fn evaluate_unary(&self, sizeout: usize, sizein: usize, in1: u64) -> u64 {
        match float_format(sizeout) {
            Some(fmt) => fmt.op_int2float(in1, sizein),
            None => {
                let name = self.opcode().name();
                panic!("Unary emulation unimplemented for {}", name)
            }
        }
    }
}

/// CPUI_FLOAT_FLOAT2FLOAT behavior (opbehavior.hh:459). Needs both an input
/// and an output FloatFormat.
// Ghidra: opbehavior.hh:459 OpBehaviorFloatFloat2Float
pub struct OpBehaviorFloatFloat2Float;
impl OpBehaviorFloatFloat2Float {
    // Ghidra: opbehavior.hh:462 OpBehaviorFloatFloat2Float::OpBehaviorFloatFloat2Float
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorFloatFloat2Float {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorFloatFloat2Float; Ghidra stores CPUI_FLOAT_FLOAT2FLOAT/unary/non-special in its Translate-bearing constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_FLOAT_FLOAT2FLOAT, true)
    }
    // Ghidra: opbehavior.cc:699 OpBehaviorFloatFloat2Float::evaluateUnary
    fn evaluate_unary(&self, sizeout: usize, sizein: usize, in1: u64) -> u64 {
        let name = self.opcode().name();
        let formatout = match float_format(sizeout) {
            Some(f) => f,
            None => panic!("Unary emulation unimplemented for {}", name),
        };
        let formatin = match float_format(sizein) {
            Some(f) => f,
            None => panic!("Unary emulation unimplemented for {}", name),
        };
        formatin.op_float2_float(in1, formatout)
    }
}

/// CPUI_FLOAT_TRUNC behavior (opbehavior.hh:467).
// Ghidra: opbehavior.hh:467 OpBehaviorFloatTrunc
pub struct OpBehaviorFloatTrunc;
impl OpBehaviorFloatTrunc {
    // Ghidra: opbehavior.hh:470 OpBehaviorFloatTrunc::OpBehaviorFloatTrunc
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorFloatTrunc {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorFloatTrunc; Ghidra stores CPUI_FLOAT_TRUNC/unary/non-special in its Translate-bearing constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_FLOAT_TRUNC, true)
    }
    // Ghidra: opbehavior.cc:712 OpBehaviorFloatTrunc::evaluateUnary
    fn evaluate_unary(&self, sizeout: usize, sizein: usize, in1: u64) -> u64 {
        match float_format(sizein) {
            Some(fmt) => fmt.op_trunc(in1, sizeout),
            None => {
                let name = self.opcode().name();
                panic!("Unary emulation unimplemented for {}", name)
            }
        }
    }
}

// ===========================================================================
// CPUI_PIECE / SUBPIECE / PTRADD / PTRSUB / POPCOUNT / LZCOUNT
// ===========================================================================

/// CPUI_PIECE behavior (opbehavior.hh:499).
// Ghidra: opbehavior.hh:499 OpBehaviorPiece
pub struct OpBehaviorPiece;
impl OpBehaviorPiece {
    // Ghidra: opbehavior.hh:501 OpBehaviorPiece::OpBehaviorPiece
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorPiece {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorPiece; Ghidra stores CPUI_PIECE/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_PIECE, false)
    }
    // Ghidra: opbehavior.cc:752 OpBehaviorPiece::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        (in1 << ((sizeout - sizein) * 8)) | in2
    }
}

/// CPUI_SUBPIECE behavior (opbehavior.hh:506).
// Ghidra: opbehavior.hh:506 OpBehaviorSubpiece
pub struct OpBehaviorSubpiece;
impl OpBehaviorSubpiece {
    // Ghidra: opbehavior.hh:508 OpBehaviorSubpiece::OpBehaviorSubpiece
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorSubpiece {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorSubpiece; Ghidra stores CPUI_SUBPIECE/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_SUBPIECE, false)
    }
    // Ghidra: opbehavior.cc:759 OpBehaviorSubpiece::evaluateBinary
    fn evaluate_binary(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 >= 8 {
            0
        } else {
            (in1 >> (in2 * 8)) & calc_mask(sizeout)
        }
    }
}

/// CPUI_PTRADD behavior (opbehavior.hh:513) — ternary.
// Ghidra: opbehavior.hh:513 OpBehaviorPtradd
pub struct OpBehaviorPtradd;
impl OpBehaviorPtradd {
    // Ghidra: opbehavior.hh:515 OpBehaviorPtradd::OpBehaviorPtradd
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorPtradd {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorPtradd; Ghidra stores CPUI_PTRADD/binary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_PTRADD, false)
    }
    // Ghidra: opbehavior.cc:768 OpBehaviorPtradd::evaluateTernary
    fn evaluate_ternary(
        &self,
        sizeout: usize,
        _sizein: usize,
        in1: u64,
        in2: u64,
        in3: u64,
    ) -> u64 {
        (in1.wrapping_add(in2.wrapping_mul(in3))) & calc_mask(sizeout)
    }
}

/// CPUI_PTRSUB behavior (opbehavior.hh:520).
// Ghidra: opbehavior.hh:520 OpBehaviorPtrsub
pub struct OpBehaviorPtrsub;
impl OpBehaviorPtrsub {
    // Ghidra: opbehavior.hh:522 OpBehaviorPtrsub::OpBehaviorPtrsub
    pub const fn new() -> Self {
        Self
    }
}
impl_eval_only!(
    OpBehaviorPtrsub,
    OpCode::CPUI_PTRSUB,
    false,
    binary,
    unary
);

/// CPUI_POPCOUNT behavior (opbehavior.hh:527).
// Ghidra: opbehavior.hh:527 OpBehaviorPopcount
pub struct OpBehaviorPopcount;
impl OpBehaviorPopcount {
    // Ghidra: opbehavior.hh:529 OpBehaviorPopcount::OpBehaviorPopcount
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorPopcount {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorPopcount; Ghidra stores CPUI_POPCOUNT/unary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_POPCOUNT, true)
    }
    // Ghidra: opbehavior.cc:782 OpBehaviorPopcount::evaluateUnary
    fn evaluate_unary(&self, _sizeout: usize, _sizein: usize, in1: u64) -> u64 {
        crate::utils::bits::popcount(in1) as u64
    }
}

/// CPUI_LZCOUNT behavior (opbehavior.hh:534).
// Ghidra: opbehavior.hh:534 OpBehaviorLzcount
pub struct OpBehaviorLzcount;
impl OpBehaviorLzcount {
    // Ghidra: opbehavior.hh:536 OpBehaviorLzcount::OpBehaviorLzcount
    pub const fn new() -> Self {
        Self
    }
}
impl OpBehavior for OpBehaviorLzcount {
    // RUDRA-GLUE: Rust OpBehavior::meta adapter for OpBehaviorLzcount; Ghidra stores CPUI_LZCOUNT/unary/non-special in its inline/base constructor and has no meta() virtual
    fn meta(&self) -> OpBehaviorMeta {
        OpBehaviorMeta::new(OpCode::CPUI_LZCOUNT, true)
    }
    // Ghidra: opbehavior.cc:788 OpBehaviorLzcount::evaluateUnary
    fn evaluate_unary(&self, _sizeout: usize, sizein: usize, in1: u64) -> u64 {
        (count_leading_zeros(in1) - (8 * (8 - sizein.min(8))) as i32) as u64
    }
}

// ===========================================================================
// Registry / factory — OpBehaviorFactory
//
// Mirrors `OpBehavior::registerInstructions` (opbehavior.cc:38). The C++
// version fills a `vector<OpBehavior*>` indexed by opcode (size CPUI_MAX)
// with one entry per opcode; special/control-flow opcodes get a bare
// `OpBehavior(opc, false, true)` placeholder. We reproduce that layout as a
// `Box<[Option<Box<dyn OpBehavior>>]>` indexed by `OpCode` discriminant.
// ===========================================================================

/// A registry of opcode behaviors, indexed by opcode. Mirrors the
/// `vector<OpBehavior*> inst` populated by `OpBehavior::registerInstructions`.
// Ghidra: opbehavior.cc:24 OpBehavior::registerInstructions
pub struct OpBehaviorFactory {
    table: Vec<Option<Box<dyn OpBehavior>>>,
}

impl OpBehaviorFactory {
    /// Build the registry. Equivalent to a one-shot
    /// `OpBehavior::registerInstructions(inst, trans)` (opbehavior.cc:38-122).
    // Ghidra: opbehavior.cc:24 OpBehavior::registerInstructions
    pub fn new() -> Self {
        let mut f = Self {
            table: (0..OpCode::CPUI_MAX as usize).map(|_| None).collect(),
        };
        f.register_all();
        f
    }

    /// Number of registered behaviors (excluding `None` placeholders).
    // RUDRA-GLUE: Rust registry convenience accessor; Ghidra exposes the caller-owned behavior vector directly and has no registered-count method
    pub fn len(&self) -> usize {
        self.table.iter().filter(|b| b.is_some()).count()
    }

    /// Whether the registry is empty.
    // RUDRA-GLUE: Rust registry convenience accessor; Ghidra exposes the caller-owned behavior vector directly and has no emptiness method
    pub fn is_empty(&self) -> bool {
        self.table.iter().all(|b| b.is_none())
    }

    /// Look up the behavior for `opc`, mirroring `inst[opc]`.
    // RUDRA-GLUE: Rust trait-object table accessor replacing direct inst[opc] vector indexing in Ghidra
    pub fn get(&self, opc: OpCode) -> Option<&dyn OpBehavior> {
        self.table
            .get(opc as usize)
            .and_then(|b| b.as_deref())
    }

    /// Register one behavior at its opcode slot.
    // RUDRA-GLUE: Rust ownership helper for placing a boxed behavior in its opcode slot; Ghidra performs each inst[...] assignment inline
    fn register(&mut self, behavior: Box<dyn OpBehavior>) {
        let opc = behavior.opcode();
        self.table[opc as usize] = Some(behavior);
    }

    /// Register a "special" placeholder behavior (neither unary nor binary):
    /// LOAD, STORE, BRANCH, ..., MULTIEQUAL, INDIRECT, CAST, SEGMENTOP, ...
    /// Mirrors `new OpBehavior(opc, false, true)` calls in registerInstructions.
    // Ghidra: opbehavior.cc:44-52,54-55,91,115-119 (special placeholders)
    fn register_special(&mut self, opc: OpCode) {
        struct SpecialBehavior {
            meta: OpBehaviorMeta,
        }
        impl OpBehavior for SpecialBehavior {
            // RUDRA-GLUE: local trait adapter for Ghidra's bare special OpBehavior(opc,false,true) objects; Ghidra has no meta() virtual
            fn meta(&self) -> OpBehaviorMeta {
                self.meta
            }
        }
        self.register(Box::new(SpecialBehavior {
            meta: OpBehaviorMeta::new_special(opc, false, true),
        }));
    }

    /// Register all behaviors, in the exact order of registerInstructions
    /// (opbehavior.cc:43-121).
    // Ghidra: opbehavior.cc:24 OpBehavior::registerInstructions body
    fn register_all(&mut self) {
        // Ghidra: opbehavior.cc:43-52 — control-flow specials
        self.register_special(OpCode::CPUI_LOAD);
        self.register_special(OpCode::CPUI_STORE);
        self.register_special(OpCode::CPUI_BRANCH);
        self.register_special(OpCode::CPUI_CBRANCH);
        self.register_special(OpCode::CPUI_BRANCHIND);
        self.register_special(OpCode::CPUI_CALL);
        self.register_special(OpCode::CPUI_CALLIND);
        self.register_special(OpCode::CPUI_CALLOTHER);
        self.register_special(OpCode::CPUI_RETURN);

        // Ghidra: opbehavior.cc:54-55 — merge specials
        self.register_special(OpCode::CPUI_MULTIEQUAL);
        self.register_special(OpCode::CPUI_INDIRECT);

        // Ghidra: opbehavior.cc:57-84 — concrete behaviors
        self.register(Box::new(OpBehaviorCopy::new()));
        self.register(Box::new(OpBehaviorPiece::new()));
        self.register(Box::new(OpBehaviorSubpiece::new()));
        self.register(Box::new(OpBehaviorEqual::new()));
        self.register(Box::new(OpBehaviorNotEqual::new()));
        self.register(Box::new(OpBehaviorIntSless::new()));
        self.register(Box::new(OpBehaviorIntSlessEqual::new()));
        self.register(Box::new(OpBehaviorIntLess::new()));
        self.register(Box::new(OpBehaviorIntLessEqual::new()));
        self.register(Box::new(OpBehaviorIntZext::new()));
        self.register(Box::new(OpBehaviorIntSext::new()));
        self.register(Box::new(OpBehaviorIntAdd::new()));
        self.register(Box::new(OpBehaviorIntSub::new()));
        self.register(Box::new(OpBehaviorIntCarry::new()));
        self.register(Box::new(OpBehaviorIntScarry::new()));
        self.register(Box::new(OpBehaviorIntSborrow::new()));
        self.register(Box::new(OpBehaviorInt2Comp::new()));
        self.register(Box::new(OpBehaviorIntNegate::new()));
        self.register(Box::new(OpBehaviorIntXor::new()));
        self.register(Box::new(OpBehaviorIntAnd::new()));
        self.register(Box::new(OpBehaviorIntOr::new()));
        self.register(Box::new(OpBehaviorIntLeft::new()));
        self.register(Box::new(OpBehaviorIntRight::new()));
        self.register(Box::new(OpBehaviorIntSright::new()));
        self.register(Box::new(OpBehaviorIntMult::new()));
        self.register(Box::new(OpBehaviorIntDiv::new()));
        self.register(Box::new(OpBehaviorIntSdiv::new()));
        self.register(Box::new(OpBehaviorIntRem::new()));
        self.register(Box::new(OpBehaviorIntSrem::new()));

        // Ghidra: opbehavior.cc:86-89 — boolean ops
        self.register(Box::new(OpBehaviorBoolNegate::new()));
        self.register(Box::new(OpBehaviorBoolXor::new()));
        self.register(Box::new(OpBehaviorBoolAnd::new()));
        self.register(Box::new(OpBehaviorBoolOr::new()));

        // Ghidra: opbehavior.cc:91 — CAST (special)
        self.register_special(OpCode::CPUI_CAST);
        // Ghidra: opbehavior.cc:92-93 — PTRADD/PTRSUB as plain (non-special)
        // binary behaviors. registerInstructions uses the bare `OpBehavior`
        // base class here, which throws on evaluate — matching the C++.
        struct PtrBehavior {
            meta: OpBehaviorMeta,
        }
        impl OpBehavior for PtrBehavior {
            // RUDRA-GLUE: local trait adapter for Ghidra's bare normal OpBehavior(opc,false) placeholders; Ghidra has no meta() virtual
            fn meta(&self) -> OpBehaviorMeta {
                self.meta
            }
        }
        self.register(Box::new(PtrBehavior {
            meta: OpBehaviorMeta::new(OpCode::CPUI_PTRADD, false),
        }));
        self.register(Box::new(PtrBehavior {
            meta: OpBehaviorMeta::new(OpCode::CPUI_PTRSUB, false),
        }));

        // Ghidra: opbehavior.cc:95-114 — float behaviors
        self.register(Box::new(OpBehaviorFloatEqual::new()));
        self.register(Box::new(OpBehaviorFloatNotEqual::new()));
        self.register(Box::new(OpBehaviorFloatLess::new()));
        self.register(Box::new(OpBehaviorFloatLessEqual::new()));
        self.register(Box::new(OpBehaviorFloatNan::new()));
        self.register(Box::new(OpBehaviorFloatAdd::new()));
        self.register(Box::new(OpBehaviorFloatDiv::new()));
        self.register(Box::new(OpBehaviorFloatMult::new()));
        self.register(Box::new(OpBehaviorFloatSub::new()));
        self.register(Box::new(OpBehaviorFloatNeg::new()));
        self.register(Box::new(OpBehaviorFloatAbs::new()));
        self.register(Box::new(OpBehaviorFloatSqrt::new()));
        self.register(Box::new(OpBehaviorFloatInt2Float::new()));
        self.register(Box::new(OpBehaviorFloatFloat2Float::new()));
        self.register(Box::new(OpBehaviorFloatTrunc::new()));
        self.register(Box::new(OpBehaviorFloatCeil::new()));
        self.register(Box::new(OpBehaviorFloatFloor::new()));
        self.register(Box::new(OpBehaviorFloatRound::new()));

        // Ghidra: opbehavior.cc:115-117 — special placeholders
        self.register_special(OpCode::CPUI_SEGMENTOP);
        self.register_special(OpCode::CPUI_CPOOLREF);
        self.register_special(OpCode::CPUI_NEW);

        // Ghidra: opbehavior.cc:118-119 — INSERT/EXTRACT as plain binary
        // base-class placeholders (throw on evaluate).
        self.register(Box::new(PtrBehavior {
            meta: OpBehaviorMeta::new(OpCode::CPUI_INSERT, false),
        }));
        self.register(Box::new(PtrBehavior {
            meta: OpBehaviorMeta::new(OpCode::CPUI_EXTRACT, false),
        }));

        // Ghidra: opbehavior.cc:120-121
        self.register(Box::new(OpBehaviorPopcount::new()));
        self.register(Box::new(OpBehaviorLzcount::new()));
    }
}

impl Default for OpBehaviorFactory {
    // RUDRA-GLUE: Rust Default implementation delegating to OpBehaviorFactory::new; Ghidra has no factory type or Default constructor
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_add() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_ADD, 4, 4, 3, 5), Some(8));
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_ADD, 4, 4, 0xffffffff, 1),
            Some(0)
        );
    }

    #[test]
    fn test_evaluate_sub() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_SUB, 4, 4, 10, 3), Some(7));
    }

    #[test]
    fn test_evaluate_and_or_xor() {
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_AND, 4, 4, 0xff, 0x0f),
            Some(0x0f)
        );
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_OR, 4, 4, 0xf0, 0x0f),
            Some(0xff)
        );
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_XOR, 4, 4, 0xff, 0x0f),
            Some(0xf0)
        );
    }

    #[test]
    fn test_evaluate_shifts() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_LEFT, 4, 4, 1, 4), Some(16));
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_RIGHT, 4, 4, 256, 4),
            Some(16)
        );
        // Ghidra opbehavior.cc:477: arithmetic right shift preserves sign.
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SRIGHT, 4, 4, 0x80000000, 1),
            Some(0xc0000000)
        );
        // Overlarge shift on negative input ⇒ all-ones.
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SRIGHT, 4, 4, 0x80000000, 64),
            Some(0xffffffff)
        );
        // Overlarge shift on positive input ⇒ 0.
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SRIGHT, 4, 4, 0x40000000, 64),
            Some(0)
        );
    }

    #[test]
    fn test_evaluate_left_overflow() {
        // Ghidra opbehavior.cc:432: in2 >= sizeout*8 ⇒ 0
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_LEFT, 4, 4, 1, 32), Some(0));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_RIGHT, 4, 4, 1, 32), Some(0));
    }

    #[test]
    fn test_evaluate_compare() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_EQUAL, 4, 4, 5, 5), Some(1));
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_NOTEQUAL, 4, 4, 5, 6),
            Some(1)
        );
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_LESS, 4, 4, 3, 5), Some(1));
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SLESS, 4, 4, 0xffffffff, 1),
            Some(1)
        );
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SLESSEQUAL, 4, 4, 0xffffffff, 1),
            Some(1)
        );
    }

    #[test]
    fn test_evaluate_unary() {
        assert_eq!(
            evaluate_unary(OpCode::CPUI_INT_NEGATE, 4, 4, 0),
            Some(0xffffffff)
        );
        assert_eq!(
            evaluate_unary(OpCode::CPUI_INT_2COMP, 4, 4, 5),
            Some(0xfffffffb)
        );
        assert_eq!(evaluate_unary(OpCode::CPUI_INT_SEXT, 2, 1, 0xff), Some(0xffff));
    }

    #[test]
    fn test_evaluate_popcount_lzcount() {
        assert_eq!(evaluate_unary(OpCode::CPUI_POPCOUNT, 4, 4, 0xff), Some(8));
        assert_eq!(evaluate_unary(OpCode::CPUI_POPCOUNT, 4, 4, 0), Some(0));
        // LZCOUNT(0x00ff, sizein=2): leading zeros in 16-bit width = 8.
        assert_eq!(evaluate_unary(OpCode::CPUI_LZCOUNT, 4, 2, 0x00ff), Some(8));
    }

    #[test]
    fn test_evaluate_div_rem() {
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_DIV, 4, 4, 17, 5), Some(3));
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_REM, 4, 4, 17, 5), Some(2));
        // Divide by zero ⇒ None.
        assert_eq!(evaluate_binary(OpCode::CPUI_INT_DIV, 4, 4, 17, 0), None);
        // Signed: -17 / 5 = -3 → 0xfffffffd
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SDIV, 4, 4, 0xffffffef, 5),
            Some(0xfffffffd)
        );
        // Signed remainder: -17 % 5 = -2 → 0xfffffffe
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SREM, 4, 4, 0xffffffef, 5),
            Some(0xfffffffe)
        );
    }

    #[test]
    fn test_evaluate_carry_scarry_sborrow() {
        // INT_CARRY: 0xff + 2 in size=1 overflows.
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_CARRY, 1, 1, 0xff, 2),
            Some(1)
        );
        // INT_SCARRY: (-1)+(-1) carries into positive-sign region? sign change.
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SCARRY, 4, 4, 0x80000000, 0x80000000),
            Some(1)
        );
        // INT_SBORROW: 0 - INT_MIN borrows.
        assert_eq!(
            evaluate_binary(OpCode::CPUI_INT_SBORROW, 4, 4, 0, 0x80000000),
            Some(1)
        );
    }

    #[test]
    fn test_evaluate_piece_subpiece() {
        // PIECE(high=0x12, low=0x34) with sizein=1, sizeout=2 → 0x1234
        assert_eq!(
            evaluate_binary(OpCode::CPUI_PIECE, 2, 1, 0x12, 0x34),
            Some(0x1234)
        );
        // SUBPIECE(in=0x12345678, offset=1 byte) with sizeout=1 → 0x56
        assert_eq!(
            evaluate_binary(OpCode::CPUI_SUBPIECE, 1, 1, 0x12345678, 1),
            Some(0x56)
        );
        // SUBPIECE offset beyond uintb width ⇒ 0
        assert_eq!(
            evaluate_binary(OpCode::CPUI_SUBPIECE, 1, 1, 0x12345678, 8),
            Some(0)
        );
    }

    #[test]
    fn test_evaluate_ternary_ptradd() {
        // PTRADD(base=0x1000, index=4, mult=2) = 0x1000 + 4*2 = 0x1008
        assert_eq!(
            evaluate_ternary(OpCode::CPUI_PTRADD, 8, 8, 0x1000, 4, 2),
            Some(0x1008)
        );
    }

    #[test]
    fn test_recover_input_left() {
        // INT_LEFT: 1 << 4 = 16. Recover slot 0: 16 >> 4 = 1.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_LEFT, 0, 4, 16, 4, 4),
            Some(1)
        );
        // slot 1 (shift amount) cannot be recovered.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_LEFT, 1, 4, 16, 4, 1),
            None
        );
        // Shift >= size*8 is invalid.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_LEFT, 0, 4, 16, 4, 32),
            None
        );
        // Out-of-range: 0xff << 0 would lose bits when shifted back — but 0xff
        // shifted by 0 is itself, which is fine. Try a real lossy case: out=0x1f
        // recovered with shift 4 → 0x1f<<4 loses low bit, so it's out of range.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_LEFT, 0, 4, 0x1f0, 4, 4),
            Some(0x1f)
        );
    }

    #[test]
    fn test_recover_input_right() {
        // INT_RIGHT: 256 >> 4 = 16. Recover slot 0: 16 << 4 = 256.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_RIGHT, 0, 4, 16, 4, 4),
            Some(256)
        );
        // slot 1 not recoverable.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_RIGHT, 1, 4, 16, 4, 4),
            None
        );
        // In-range: out=0x11, shift 4 ⇒ recover 0x11<<4 = 0x110. Ghidra checks
        // (out>>(8*sizein-sa))==0; here (0x11>>28)==0, so it IS in range.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_RIGHT, 0, 4, 0x11, 4, 4),
            Some(0x110)
        );
        // Genuinely out of range: out has high bits set that a right shift of
        // `sa` could not have produced. out=0x10_000_000 with size_in=4, sa=4:
        // (0x10000000 >> 28) = 1 != 0 ⇒ out of range.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_RIGHT, 0, 4, 0x10000000, 4, 4),
            None
        );
    }

    #[test]
    fn test_recover_input_sright() {
        // INT_SRIGHT: 0xffffff00 >> 4 = 0xfffffff0 (sign-extended). Recover
        // slot 0: 0xfffffff0 << 4 = 0xffffff00 (mask to 32 bits).
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_SRIGHT, 0, 4, 0xfffffff0, 4, 4),
            Some(0xffffff00)
        );
        // Positive value not in negative-shift range fails.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_SRIGHT, 0, 4, 0x10, 4, 4),
            None
        );
    }

    #[test]
    fn test_recover_input_add_sub() {
        // INT_ADD: 3 + 4 = 7. Recover slot 0: 7 - 4 = 3.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_ADD, 0, 4, 7, 4, 4),
            Some(3)
        );
        // INT_SUB slot 0: 7 - 4 = 3. Recover: 3 + 4 = 7.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_SUB, 0, 4, 3, 4, 4),
            Some(7)
        );
        // INT_SUB slot 1: 7 - 4 = 3. Recover: 7 - 3 = 4.
        assert_eq!(
            recover_input_binary(OpCode::CPUI_INT_SUB, 1, 4, 3, 4, 7),
            Some(4)
        );
    }

    #[test]
    fn test_recover_input_unary() {
        // COPY: recover input == output.
        assert_eq!(recover_input_unary(OpCode::CPUI_COPY, 4, 5, 4), Some(5));
        // INT_NEGATE: recover !out.
        assert_eq!(
            recover_input_unary(OpCode::CPUI_INT_NEGATE, 4, 0xff, 4),
            Some(0xffffff00)
        );
        // INT_2COMP: recover -out.
        assert_eq!(
            recover_input_unary(OpCode::CPUI_INT_2COMP, 4, 0xfffffffb, 4),
            Some(5)
        );
        // INT_ZEXT: out of range ⇒ None.
        assert_eq!(
            recover_input_unary(OpCode::CPUI_INT_ZEXT, 1, 0x1ff, 1),
            None
        );
        // INT_ZEXT: in range ⇒ out.
        assert_eq!(
            recover_input_unary(OpCode::CPUI_INT_ZEXT, 2, 0xff, 1),
            Some(0xff)
        );
    }

    // ----- OOP trait tests -----

    #[test]
    fn test_oop_int_add() {
        let b = OpBehaviorIntAdd::new();
        assert_eq!(b.opcode(), OpCode::CPUI_INT_ADD);
        assert!(!b.is_unary());
        assert!(!b.is_special());
        assert_eq!(b.evaluate_binary(4, 4, 3, 5), 8);
        assert_eq!(b.recover_input_binary(0, 4, 8, 4, 5), 3);
    }

    #[test]
    fn test_oop_int_left_recover() {
        let b = OpBehaviorIntLeft::new();
        assert_eq!(b.evaluate_binary(4, 4, 1, 4), 16);
        assert_eq!(b.recover_input_binary(0, 4, 16, 4, 4), 1);
        // slot 1 / out-of-range panics — verify via catch_unwind.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b.recover_input_binary(1, 4, 16, 4, 4)
        }));
        assert!(res.is_err());
    }

    #[test]
    fn test_oop_int_div_panics_on_zero() {
        let b = OpBehaviorIntDiv::new();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b.evaluate_binary(4, 4, 10, 0)
        }));
        assert!(res.is_err());
    }

    #[test]
    fn test_oop_popcount() {
        let b = OpBehaviorPopcount::new();
        assert_eq!(b.evaluate_unary(4, 4, 0xff), 8);
    }

    #[test]
    fn test_oop_copy() {
        let b = OpBehaviorCopy::new();
        assert_eq!(b.evaluate_unary(4, 4, 42), 42);
        assert_eq!(b.recover_input_unary(4, 42, 4), 42);
    }

    #[test]
    fn test_oop_float_add() {
        let b = OpBehaviorFloatAdd::new();
        let fmt = FloatFormat::new(8);
        let a = fmt.get_encoding(1.5);
        let bb = fmt.get_encoding(2.5);
        let expected = fmt.get_encoding(4.0);
        assert_eq!(b.evaluate_binary(8, 8, a, bb), expected);
    }

    #[test]
    fn test_factory_registry() {
        let f = OpBehaviorFactory::new();
        // Concrete behaviors present.
        let add = f.get(OpCode::CPUI_INT_ADD).expect("INT_ADD registered");
        assert_eq!(add.opcode(), OpCode::CPUI_INT_ADD);
        assert_eq!(add.evaluate_binary(4, 4, 3, 5), 8);

        // Special placeholders present.
        let load = f.get(OpCode::CPUI_LOAD).expect("LOAD registered");
        assert!(load.is_special());

        // Popcount works via the registry.
        let pc = f.get(OpCode::CPUI_POPCOUNT).expect("POPCOUNT registered");
        assert_eq!(pc.evaluate_unary(4, 4, 0xff), 8);

        // Spot-check a representative sample across every category registered
        // by OpBehavior::registerInstructions (opbehavior.cc:43-121): control-
        // flow specials, merge specials, int/bool arithmetic+logic, shifts,
        // div/rem, float ops, piece/subpiece/ptradd/ptrsub, popcount/lzcount,
        // and the bare base-class placeholders (CAST/INSERT/EXTRACT/SEGMENTOP).
        for opc in [
            OpCode::CPUI_COPY,
            OpCode::CPUI_LOAD,
            OpCode::CPUI_STORE,
            OpCode::CPUI_BRANCH,
            OpCode::CPUI_CBRANCH,
            OpCode::CPUI_BRANCHIND,
            OpCode::CPUI_CALL,
            OpCode::CPUI_CALLIND,
            OpCode::CPUI_CALLOTHER,
            OpCode::CPUI_RETURN,
            OpCode::CPUI_INT_EQUAL,
            OpCode::CPUI_INT_ADD,
            OpCode::CPUI_INT_SRIGHT,
            OpCode::CPUI_INT_DIV,
            OpCode::CPUI_INT_SREM,
            OpCode::CPUI_BOOL_XOR,
            OpCode::CPUI_MULTIEQUAL,
            OpCode::CPUI_INDIRECT,
            OpCode::CPUI_PIECE,
            OpCode::CPUI_SUBPIECE,
            OpCode::CPUI_CAST,
            OpCode::CPUI_PTRADD,
            OpCode::CPUI_PTRSUB,
            OpCode::CPUI_FLOAT_ADD,
            OpCode::CPUI_FLOAT_TRUNC,
            OpCode::CPUI_FLOAT_ROUND,
            OpCode::CPUI_SEGMENTOP,
            OpCode::CPUI_CPOOLREF,
            OpCode::CPUI_NEW,
            OpCode::CPUI_INSERT,
            OpCode::CPUI_EXTRACT,
            OpCode::CPUI_POPCOUNT,
            OpCode::CPUI_LZCOUNT,
        ] {
            assert!(f.get(opc).is_some(), "missing behavior for {:?}", opc);
        }
    }

    #[test]
    fn test_evaluate_no_exc() {
        assert_eq!(evaluate_unary_no_exc(OpCode::CPUI_INT_NEGATE, 4, 4, 0), Some(0xffffffff));
        assert_eq!(evaluate_binary_no_exc(OpCode::CPUI_INT_ADD, 4, 4, 3, 5), Some(8));
        // Unknown opcode ⇒ None.
        assert_eq!(evaluate_binary_no_exc(OpCode::CPUI_BRANCH, 4, 4, 1, 2), None);
    }
}
