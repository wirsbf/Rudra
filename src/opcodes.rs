//! P-code operation codes
//!
//! Corresponds to Ghidra's `opcodes.hh`

use serde::{Deserialize, Serialize};
use std::fmt;

/// P-code operation type (OpCode in Ghidra)
///
/// This enum represents all possible P-code operations. Each operation
/// has specific semantics for how it operates on its input and output varnodes.
/// Prefixes match Ghidra's `CPUI_` naming convention.
///
/// Numeric values are 1:1 with Ghidra `opcodes.hh:37-130` (authoritative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum OpCode {
    CPUI_COPY = 1,
    CPUI_LOAD = 2,
    CPUI_STORE = 3,
    CPUI_BRANCH = 4,
    CPUI_CBRANCH = 5,
    CPUI_BRANCHIND = 6,
    CPUI_CALL = 7,
    CPUI_CALLIND = 8,
    CPUI_CALLOTHER = 9,
    CPUI_RETURN = 10,
    CPUI_INT_EQUAL = 11,
    CPUI_INT_NOTEQUAL = 12,
    CPUI_INT_SLESS = 13,
    CPUI_INT_SLESSEQUAL = 14,
    CPUI_INT_LESS = 15,
    CPUI_INT_LESSEQUAL = 16,
    CPUI_INT_ZEXT = 17,
    CPUI_INT_SEXT = 18,
    CPUI_INT_ADD = 19,
    CPUI_INT_SUB = 20,
    CPUI_INT_CARRY = 21,
    CPUI_INT_SCARRY = 22,
    CPUI_INT_SBORROW = 23,
    CPUI_INT_2COMP = 24,
    CPUI_INT_NEGATE = 25,
    CPUI_INT_XOR = 26,
    CPUI_INT_AND = 27,
    CPUI_INT_OR = 28,
    CPUI_INT_LEFT = 29,
    CPUI_INT_RIGHT = 30,
    CPUI_INT_SRIGHT = 31,
    CPUI_INT_MULT = 32,
    CPUI_INT_DIV = 33,
    CPUI_INT_SDIV = 34,
    CPUI_INT_REM = 35,
    CPUI_INT_SREM = 36,
    CPUI_BOOL_NEGATE = 37,
    CPUI_BOOL_XOR = 38,
    CPUI_BOOL_AND = 39,
    CPUI_BOOL_OR = 40,
    CPUI_FLOAT_EQUAL = 41,
    CPUI_FLOAT_NOTEQUAL = 42,
    CPUI_FLOAT_LESS = 43,
    CPUI_FLOAT_LESSEQUAL = 44,
    CPUI_FLOAT_NAN = 46,
    CPUI_FLOAT_ADD = 47,
    CPUI_FLOAT_DIV = 48,
    CPUI_FLOAT_MULT = 49,
    CPUI_FLOAT_SUB = 50,
    CPUI_FLOAT_NEG = 51,
    CPUI_FLOAT_ABS = 52,
    CPUI_FLOAT_SQRT = 53,
    CPUI_FLOAT_INT2FLOAT = 54,
    CPUI_FLOAT_FLOAT2FLOAT = 55,
    CPUI_FLOAT_TRUNC = 56,
    CPUI_FLOAT_CEIL = 57,
    CPUI_FLOAT_FLOOR = 58,
    CPUI_FLOAT_ROUND = 59,
    CPUI_MULTIEQUAL = 60,
    CPUI_INDIRECT = 61,
    CPUI_PIECE = 62,
    CPUI_SUBPIECE = 63,
    CPUI_CAST = 64,
    CPUI_PTRADD = 65,
    CPUI_PTRSUB = 66,
    CPUI_SEGMENTOP = 67,
    CPUI_CPOOLREF = 68,
    CPUI_NEW = 69,
    CPUI_INSERT = 70,
    CPUI_EXTRACT = 71,
    CPUI_POPCOUNT = 72,
    CPUI_LZCOUNT = 73,
    CPUI_MAX = 74,
}

impl OpCode {
    /// Ghidra: opcodes.cc:60 get_opname — `opcode_name[opc]` direct enum-value
    /// index into the locked table at opcodes.cc:29-48. 1:1 spelling port
    /// (PCODE-OPNAME-TABLE-0001): the table's placeholder-alias slots for the
    /// SLEIGH compiler/interpreter (header comment opcodes.cc:23-28) print
    /// MULTIEQUAL→"BUILD", INDIRECT→"DELAY_SLOT", PTRADD→"LABEL",
    /// PTRSUB→"CROSSBUILD", and the float family drops the FLOAT_ prefix
    /// (INT2FLOAT/FLOAT2FLOAT/TRUNC/CEIL/FLOOR/ROUND). `opcode_indices` serves
    /// only get_opcode's name→enum binary search (opcodes.cc:75-84), not this
    /// lookup.
    pub fn name(&self) -> &'static str {
        match self {
            OpCode::CPUI_COPY => "COPY",
            OpCode::CPUI_LOAD => "LOAD",
            OpCode::CPUI_STORE => "STORE",
            OpCode::CPUI_INT_ADD => "INT_ADD",
            OpCode::CPUI_INT_SUB => "INT_SUB",
            OpCode::CPUI_INT_MULT => "INT_MULT",
            OpCode::CPUI_INT_DIV => "INT_DIV",
            OpCode::CPUI_INT_SDIV => "INT_SDIV",
            OpCode::CPUI_INT_REM => "INT_REM",
            OpCode::CPUI_INT_SREM => "INT_SREM",
            OpCode::CPUI_INT_2COMP => "INT_2COMP",
            OpCode::CPUI_INT_CARRY => "INT_CARRY",
            OpCode::CPUI_INT_SCARRY => "INT_SCARRY",
            OpCode::CPUI_INT_SBORROW => "INT_SBORROW",
            OpCode::CPUI_INT_AND => "INT_AND",
            OpCode::CPUI_INT_OR => "INT_OR",
            OpCode::CPUI_INT_XOR => "INT_XOR",
            OpCode::CPUI_INT_NEGATE => "INT_NEGATE",
            OpCode::CPUI_INT_LEFT => "INT_LEFT",
            OpCode::CPUI_INT_RIGHT => "INT_RIGHT",
            OpCode::CPUI_INT_SRIGHT => "INT_SRIGHT",
            OpCode::CPUI_INT_EQUAL => "INT_EQUAL",
            OpCode::CPUI_INT_NOTEQUAL => "INT_NOTEQUAL",
            OpCode::CPUI_INT_LESS => "INT_LESS",
            OpCode::CPUI_INT_SLESS => "INT_SLESS",
            OpCode::CPUI_INT_LESSEQUAL => "INT_LESSEQUAL",
            OpCode::CPUI_INT_SLESSEQUAL => "INT_SLESSEQUAL",
            OpCode::CPUI_INT_ZEXT => "INT_ZEXT",
            OpCode::CPUI_INT_SEXT => "INT_SEXT",
            // CPUI_TRUNC removed: was Rugra-only, not in Ghidra. Integer
            // truncation uses CPUI_SUBPIECE; float uses CPUI_FLOAT_TRUNC.
            OpCode::CPUI_FLOAT_ADD => "FLOAT_ADD",
            OpCode::CPUI_FLOAT_SUB => "FLOAT_SUB",
            OpCode::CPUI_FLOAT_MULT => "FLOAT_MULT",
            OpCode::CPUI_FLOAT_DIV => "FLOAT_DIV",
            OpCode::CPUI_FLOAT_NEG => "FLOAT_NEG",
            OpCode::CPUI_FLOAT_ABS => "FLOAT_ABS",
            OpCode::CPUI_FLOAT_SQRT => "FLOAT_SQRT",
            OpCode::CPUI_FLOAT_EQUAL => "FLOAT_EQUAL",
            OpCode::CPUI_FLOAT_NOTEQUAL => "FLOAT_NOTEQUAL",
            OpCode::CPUI_FLOAT_LESS => "FLOAT_LESS",
            OpCode::CPUI_FLOAT_LESSEQUAL => "FLOAT_LESSEQUAL",
            OpCode::CPUI_FLOAT_NAN => "FLOAT_NAN",
            OpCode::CPUI_FLOAT_FLOAT2FLOAT => "FLOAT2FLOAT",
            OpCode::CPUI_FLOAT_INT2FLOAT => "INT2FLOAT",
            OpCode::CPUI_FLOAT_TRUNC => "TRUNC",
            OpCode::CPUI_FLOAT_CEIL => "CEIL",
            OpCode::CPUI_FLOAT_FLOOR => "FLOOR",
            OpCode::CPUI_FLOAT_ROUND => "ROUND",
            OpCode::CPUI_BRANCH => "BRANCH",
            OpCode::CPUI_CBRANCH => "CBRANCH",
            OpCode::CPUI_BRANCHIND => "BRANCHIND",
            OpCode::CPUI_CALL => "CALL",
            OpCode::CPUI_CALLIND => "CALLIND",
            OpCode::CPUI_RETURN => "RETURN",
            OpCode::CPUI_PIECE => "PIECE",
            OpCode::CPUI_SUBPIECE => "SUBPIECE",
            OpCode::CPUI_BOOL_AND => "BOOL_AND",
            OpCode::CPUI_BOOL_OR => "BOOL_OR",
            OpCode::CPUI_BOOL_XOR => "BOOL_XOR",
            OpCode::CPUI_BOOL_NEGATE => "BOOL_NEGATE",
            OpCode::CPUI_POPCOUNT => "POPCOUNT",
            OpCode::CPUI_LZCOUNT => "LZCOUNT",
            OpCode::CPUI_CALLOTHER => "CALLOTHER",
            OpCode::CPUI_MULTIEQUAL => "BUILD",
            OpCode::CPUI_INDIRECT => "DELAY_SLOT",
            OpCode::CPUI_CPOOLREF => "CPOOLREF",
            OpCode::CPUI_NEW => "NEW",
            OpCode::CPUI_SEGMENTOP => "SEGMENTOP",
            OpCode::CPUI_PTRADD => "LABEL",
            OpCode::CPUI_PTRSUB => "CROSSBUILD",
            OpCode::CPUI_EXTRACT => "EXTRACT",
            OpCode::CPUI_INSERT => "INSERT",
            OpCode::CPUI_CAST => "CAST",
            OpCode::CPUI_MAX => "MAX",
        }
    }

    // RUDRA-GLUE: from_i32 (no Ghidra counterpart found)
    /// Convert from raw integer opcode to OpCode enum
    ///
    /// Used by the P-code injection bridge to convert `PcodeOpRaw.opcode`
    /// integer values into typed `OpCode` variants.
    pub fn from_i32(raw: i32) -> Option<OpCode> {
        match raw {
            1 => Some(OpCode::CPUI_COPY),
            2 => Some(OpCode::CPUI_LOAD),
            3 => Some(OpCode::CPUI_STORE),
            4 => Some(OpCode::CPUI_BRANCH),
            5 => Some(OpCode::CPUI_CBRANCH),
            6 => Some(OpCode::CPUI_BRANCHIND),
            7 => Some(OpCode::CPUI_CALL),
            8 => Some(OpCode::CPUI_CALLIND),
            9 => Some(OpCode::CPUI_CALLOTHER),
            10 => Some(OpCode::CPUI_RETURN),
            11 => Some(OpCode::CPUI_INT_EQUAL),
            12 => Some(OpCode::CPUI_INT_NOTEQUAL),
            13 => Some(OpCode::CPUI_INT_SLESS),
            14 => Some(OpCode::CPUI_INT_SLESSEQUAL),
            15 => Some(OpCode::CPUI_INT_LESS),
            16 => Some(OpCode::CPUI_INT_LESSEQUAL),
            17 => Some(OpCode::CPUI_INT_ZEXT),
            18 => Some(OpCode::CPUI_INT_SEXT),
            19 => Some(OpCode::CPUI_INT_ADD),
            20 => Some(OpCode::CPUI_INT_SUB),
            21 => Some(OpCode::CPUI_INT_CARRY),
            22 => Some(OpCode::CPUI_INT_SCARRY),
            23 => Some(OpCode::CPUI_INT_SBORROW),
            24 => Some(OpCode::CPUI_INT_2COMP),
            25 => Some(OpCode::CPUI_INT_NEGATE),
            26 => Some(OpCode::CPUI_INT_XOR),
            27 => Some(OpCode::CPUI_INT_AND),
            28 => Some(OpCode::CPUI_INT_OR),
            29 => Some(OpCode::CPUI_INT_LEFT),
            30 => Some(OpCode::CPUI_INT_RIGHT),
            31 => Some(OpCode::CPUI_INT_SRIGHT),
            32 => Some(OpCode::CPUI_INT_MULT),
            33 => Some(OpCode::CPUI_INT_DIV),
            34 => Some(OpCode::CPUI_INT_SDIV),
            35 => Some(OpCode::CPUI_INT_REM),
            36 => Some(OpCode::CPUI_INT_SREM),
            37 => Some(OpCode::CPUI_BOOL_NEGATE),
            38 => Some(OpCode::CPUI_BOOL_XOR),
            39 => Some(OpCode::CPUI_BOOL_AND),
            40 => Some(OpCode::CPUI_BOOL_OR),
            41 => Some(OpCode::CPUI_FLOAT_EQUAL),
            42 => Some(OpCode::CPUI_FLOAT_NOTEQUAL),
            43 => Some(OpCode::CPUI_FLOAT_LESS),
            44 => Some(OpCode::CPUI_FLOAT_LESSEQUAL),
            46 => Some(OpCode::CPUI_FLOAT_NAN),
            47 => Some(OpCode::CPUI_FLOAT_ADD),
            48 => Some(OpCode::CPUI_FLOAT_DIV),
            49 => Some(OpCode::CPUI_FLOAT_MULT),
            50 => Some(OpCode::CPUI_FLOAT_SUB),
            51 => Some(OpCode::CPUI_FLOAT_NEG),
            52 => Some(OpCode::CPUI_FLOAT_ABS),
            53 => Some(OpCode::CPUI_FLOAT_SQRT),
            54 => Some(OpCode::CPUI_FLOAT_INT2FLOAT),
            55 => Some(OpCode::CPUI_FLOAT_FLOAT2FLOAT),
            56 => Some(OpCode::CPUI_FLOAT_TRUNC),
            57 => Some(OpCode::CPUI_FLOAT_CEIL),
            58 => Some(OpCode::CPUI_FLOAT_FLOOR),
            59 => Some(OpCode::CPUI_FLOAT_ROUND),
            60 => Some(OpCode::CPUI_MULTIEQUAL),
            61 => Some(OpCode::CPUI_INDIRECT),
            62 => Some(OpCode::CPUI_PIECE),
            63 => Some(OpCode::CPUI_SUBPIECE),
            64 => Some(OpCode::CPUI_CAST),
            65 => Some(OpCode::CPUI_PTRADD),
            66 => Some(OpCode::CPUI_PTRSUB),
            67 => Some(OpCode::CPUI_SEGMENTOP),
            68 => Some(OpCode::CPUI_CPOOLREF),
            69 => Some(OpCode::CPUI_NEW),
            70 => Some(OpCode::CPUI_INSERT),
            71 => Some(OpCode::CPUI_EXTRACT),
            72 => Some(OpCode::CPUI_POPCOUNT),
            73 => Some(OpCode::CPUI_LZCOUNT),
            _ => None,
        }
    }

    // RUDRA-GLUE: is_block_terminator (no Ghidra counterpart found)
    /// Check if this opcode is a control flow terminator (ends a basic block)
    pub fn is_block_terminator(&self) -> bool {
        matches!(
            self,
            OpCode::CPUI_BRANCH
                | OpCode::CPUI_CBRANCH
                | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_RETURN
        )
    }

    // Ghidra: typeop.cc ctor bodies where `opflags = ... | PcodeOp::commutative`
    /// Check if this opcode is commutative (operand order doesn't matter).
    /// Mirrors the commutative flag set per-opcode in typeop.cc constructors
    /// (the same set captured in op.rs::opcode_flags). Note INT_LEFT/INT_DIV
    /// are NOT commutative in Ghidra despite being sometimes assumed so.
    pub fn is_commutative(&self) -> bool {
        matches!(
            self,
            OpCode::CPUI_INT_ADD
                | OpCode::CPUI_INT_MULT
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_CARRY
                | OpCode::CPUI_INT_SCARRY
                | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR
                | OpCode::CPUI_BOOL_XOR
                | OpCode::CPUI_FLOAT_ADD
                | OpCode::CPUI_FLOAT_MULT
                | OpCode::CPUI_FLOAT_EQUAL
                | OpCode::CPUI_FLOAT_NOTEQUAL
        )
    }

    // RUDRA-GLUE: is_commutative_or_pure (no Ghidra counterpart found)
    /// Check if this opcode is a deterministic, side-effect-free operation
    /// suitable for CSE (Common Subexpression Elimination).
    ///
    /// Excludes LOAD/STORE (memory side-effects), branches, calls, and
    /// SSA-internal ops (MULTIEQUAL, INDIRECT).
    pub fn is_commutative_or_pure(&self) -> bool {
        matches!(
            self,
            // Arithmetic
            OpCode::CPUI_INT_ADD
                | OpCode::CPUI_INT_SUB
                | OpCode::CPUI_INT_MULT
                | OpCode::CPUI_INT_DIV
                | OpCode::CPUI_INT_SDIV
                | OpCode::CPUI_INT_REM
                | OpCode::CPUI_INT_SREM
                | OpCode::CPUI_INT_2COMP
                | OpCode::CPUI_INT_CARRY
                | OpCode::CPUI_INT_SCARRY
                | OpCode::CPUI_INT_SBORROW
                // Bitwise
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_INT_NEGATE
                | OpCode::CPUI_INT_LEFT
                | OpCode::CPUI_INT_RIGHT
                | OpCode::CPUI_INT_SRIGHT
                // Comparison
                | OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS
                | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL
                // Extension/Truncation
                | OpCode::CPUI_INT_ZEXT
                | OpCode::CPUI_INT_SEXT
                | OpCode::CPUI_SUBPIECE
                // Float arithmetic
                | OpCode::CPUI_FLOAT_ADD
                | OpCode::CPUI_FLOAT_SUB
                | OpCode::CPUI_FLOAT_MULT
                | OpCode::CPUI_FLOAT_DIV
                | OpCode::CPUI_FLOAT_NEG
                | OpCode::CPUI_FLOAT_ABS
                | OpCode::CPUI_FLOAT_SQRT
                | OpCode::CPUI_FLOAT_EQUAL
                | OpCode::CPUI_FLOAT_NOTEQUAL
                | OpCode::CPUI_FLOAT_LESS
                | OpCode::CPUI_FLOAT_LESSEQUAL
                | OpCode::CPUI_FLOAT_NAN
                // Boolean
                | OpCode::CPUI_BOOL_AND
                | OpCode::CPUI_BOOL_OR
                | OpCode::CPUI_BOOL_XOR
                | OpCode::CPUI_BOOL_NEGATE
                // Misc pure
                | OpCode::CPUI_POPCOUNT
                | OpCode::CPUI_LZCOUNT
                | OpCode::CPUI_PIECE
                | OpCode::CPUI_SUBPIECE
        )
    }
}

impl fmt::Display for OpCode {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// RUDRA-GLUE: get_booleanflip (no Ghidra counterpart found)
/// Get the complementary OpCode for boolean-flip transformations.
/// Faithful to Ghidra's `get_booleanflip` (opcodes.cc:94-135). For a comparison
/// opcode, returns the negated opcode; `reorder` is set true when the operands
/// must be swapped to preserve semantics (e.g. `!(V < W) => W <= V`).
/// Returns `CPUI_MAX` if `opc` is not a flippable comparison.
///
/// Note: Rugra `CPUI_BOOL_NEGATE` == Ghidra `CPUI_BOOL_NEGATE`.
pub fn get_booleanflip(opc: OpCode, reorder: &mut bool) -> OpCode {
    match opc {
        OpCode::CPUI_INT_EQUAL => {
            *reorder = false;
            OpCode::CPUI_INT_NOTEQUAL
        }
        OpCode::CPUI_INT_NOTEQUAL => {
            *reorder = false;
            OpCode::CPUI_INT_EQUAL
        }
        OpCode::CPUI_INT_SLESS => {
            *reorder = true;
            OpCode::CPUI_INT_SLESSEQUAL
        }
        OpCode::CPUI_INT_SLESSEQUAL => {
            *reorder = true;
            OpCode::CPUI_INT_SLESS
        }
        OpCode::CPUI_INT_LESS => {
            *reorder = true;
            OpCode::CPUI_INT_LESSEQUAL
        }
        OpCode::CPUI_INT_LESSEQUAL => {
            *reorder = true;
            OpCode::CPUI_INT_LESS
        }
        // Ghidra BOOL_NEGATE == Rugra BOOL_NOT.
        OpCode::CPUI_BOOL_NEGATE => {
            *reorder = false;
            OpCode::CPUI_COPY
        }
        OpCode::CPUI_FLOAT_EQUAL => {
            *reorder = false;
            OpCode::CPUI_FLOAT_NOTEQUAL
        }
        OpCode::CPUI_FLOAT_NOTEQUAL => {
            *reorder = false;
            OpCode::CPUI_FLOAT_EQUAL
        }
        OpCode::CPUI_FLOAT_LESS => {
            *reorder = true;
            OpCode::CPUI_FLOAT_LESSEQUAL
        }
        OpCode::CPUI_FLOAT_LESSEQUAL => {
            *reorder = true;
            OpCode::CPUI_FLOAT_LESS
        }
        _ => OpCode::CPUI_MAX,
    }
}
