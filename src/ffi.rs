//! FFI interface for Rudra
//!
//! This module provides C-compatible interfaces to Rudra's core logic,
//! allowing it to be integrated into Ghidra's C++ decompiler or used for
//! comparison testing ("对拍").

use crate::varnode::Varnode;
use crate::{Address, AddressSpace, Funcdata, OpCode, SeqNum};
use lazy_static::lazy_static;
use std::os::raw::c_char;
use std::sync::Mutex;

lazy_static! {
    /// Global state to hold the Rudra program currently being compared
    ///
    /// TESTLIB-STATE-CONTAMINATION-0001: every accessor below recovers a
    /// poisoned guard with `into_inner` instead of panicking. The mutex
    /// still enforces mutual exclusion, but a panic inside one critical
    /// section no longer poisons the singleton for the rest of the process
    /// (which used to cascade `PoisonError` into every later test that
    /// called `set_current_program`). Callers always overwrite the slot
    /// before reading it, so no comparison state can leak across a
    /// recovered boundary.
    static ref CURRENT_PROGRAM: Mutex<Option<Funcdata>> = Mutex::new(None);
}

/// C-compatible representation of a Varnode for FFI comparison
#[repr(C)]
pub struct VarnodeFFI {
    pub space_id: i32,
    pub offset: u64,
    pub size: u32,
}

#[repr(C)]
pub struct PcodeCompareResultFFI {
    pub status: i32,
}

pub const PCODE_COMPARE_MATCH: i32 = 0;
pub const PCODE_COMPARE_OPCODE_MISMATCH: i32 = 1;
pub const PCODE_COMPARE_OUTPUT_MISMATCH: i32 = 2;
pub const PCODE_COMPARE_INPUT_COUNT_MISMATCH: i32 = 3;
pub const PCODE_COMPARE_INPUT_MISMATCH: i32 = 4;
pub const PCODE_COMPARE_MISSING_RUDRA_OP: i32 = 5;

// RUDRA-GLUE: map_ghidra_opcode (no Ghidra counterpart found)
/// Map Ghidra OpCode integers to Rudra PcodeOp enum
/// Values are based on Ghidra's opcodes.hh
pub fn map_ghidra_opcode(opcode: i32) -> Option<OpCode> {
    // 严格按照 Ghidra opcodes.hh 枚举值映射，1:1 对拍红线
    match opcode {
        // === Data Movement ===
        1 => Some(OpCode::CPUI_COPY),
        2 => Some(OpCode::CPUI_LOAD),
        3 => Some(OpCode::CPUI_STORE),

        // === Control Flow ===
        4 => Some(OpCode::CPUI_BRANCH),
        5 => Some(OpCode::CPUI_CBRANCH),
        6 => Some(OpCode::CPUI_BRANCHIND),
        7 => Some(OpCode::CPUI_CALL),
        8 => Some(OpCode::CPUI_CALLIND),
        9 => Some(OpCode::CPUI_CALLOTHER),
        10 => Some(OpCode::CPUI_RETURN),

        // === Integer Comparison ===
        11 => Some(OpCode::CPUI_INT_EQUAL),
        12 => Some(OpCode::CPUI_INT_NOTEQUAL),
        13 => Some(OpCode::CPUI_INT_SLESS),
        14 => Some(OpCode::CPUI_INT_SLESSEQUAL),
        15 => Some(OpCode::CPUI_INT_LESS),
        16 => Some(OpCode::CPUI_INT_LESSEQUAL),

        // === Extension ===
        17 => Some(OpCode::CPUI_INT_ZEXT),
        18 => Some(OpCode::CPUI_INT_SEXT),

        // === Integer Arithmetic ===
        19 => Some(OpCode::CPUI_INT_ADD),
        20 => Some(OpCode::CPUI_INT_SUB),
        21 => Some(OpCode::CPUI_INT_CARRY), // Ghidra: INT_CARRY, NOT INT_MULT!
        22 => Some(OpCode::CPUI_INT_SCARRY), // Ghidra: INT_SCARRY, NOT INT_DIV!
        23 => Some(OpCode::CPUI_INT_SBORROW), // Ghidra: INT_SBORROW, NOT INT_SDIV!
        24 => Some(OpCode::CPUI_INT_2COMP),   // Ghidra: INT_2COMP (twos complement)
        25 => Some(OpCode::CPUI_INT_NEGATE),   // Ghidra: INT_NEGATE (bitwise ~)

        // === Bitwise ===
        26 => Some(OpCode::CPUI_INT_XOR),
        27 => Some(OpCode::CPUI_INT_AND),
        28 => Some(OpCode::CPUI_INT_OR),
        29 => Some(OpCode::CPUI_INT_LEFT),
        30 => Some(OpCode::CPUI_INT_RIGHT),
        31 => Some(OpCode::CPUI_INT_SRIGHT),

        // === Integer Multiply/Divide ===
        32 => Some(OpCode::CPUI_INT_MULT),
        33 => Some(OpCode::CPUI_INT_DIV),
        34 => Some(OpCode::CPUI_INT_SDIV),
        35 => Some(OpCode::CPUI_INT_REM),
        36 => Some(OpCode::CPUI_INT_SREM),

        // === Boolean ===
        37 => Some(OpCode::CPUI_BOOL_NEGATE), // Ghidra: BOOL_NEGATE
        38 => Some(OpCode::CPUI_BOOL_XOR),
        39 => Some(OpCode::CPUI_BOOL_AND),
        40 => Some(OpCode::CPUI_BOOL_OR),

        // === Floating Point ===
        41 => Some(OpCode::CPUI_FLOAT_EQUAL),
        42 => Some(OpCode::CPUI_FLOAT_NOTEQUAL),
        43 => Some(OpCode::CPUI_FLOAT_LESS),
        44 => Some(OpCode::CPUI_FLOAT_LESSEQUAL),
        // 45 is unused in Ghidra
        46 => Some(OpCode::CPUI_FLOAT_NAN),
        47 => Some(OpCode::CPUI_FLOAT_ADD),
        48 => Some(OpCode::CPUI_FLOAT_DIV),
        49 => Some(OpCode::CPUI_FLOAT_MULT),
        50 => Some(OpCode::CPUI_FLOAT_SUB),
        51 => Some(OpCode::CPUI_FLOAT_NEG),
        52 => Some(OpCode::CPUI_FLOAT_ABS),
        53 => Some(OpCode::CPUI_FLOAT_SQRT),

        // === Float Conversion ===
        54 => Some(OpCode::CPUI_FLOAT_INT2FLOAT),
        55 => Some(OpCode::CPUI_FLOAT_FLOAT2FLOAT),
        56 => Some(OpCode::CPUI_FLOAT_TRUNC),
        57 => Some(OpCode::CPUI_FLOAT_CEIL),
        58 => Some(OpCode::CPUI_FLOAT_FLOOR),
        59 => Some(OpCode::CPUI_FLOAT_ROUND),

        // === Internal / SSA ===
        60 => Some(OpCode::CPUI_MULTIEQUAL),
        61 => Some(OpCode::CPUI_INDIRECT),
        62 => Some(OpCode::CPUI_PIECE),
        63 => Some(OpCode::CPUI_SUBPIECE),

        // === Type / Pointer ===
        64 => Some(OpCode::CPUI_CAST), // R37 (2026-07-02): uncommented — CPUI_CAST
                                        // variant exists (opcodes.rs) and to_ghidra_opcode
                                        // already maps it → Some(64). The round-trip
                                        // was asymmetric: Ghidra→Rudra dropped it.
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

// RUDRA-GLUE: to_ghidra_opcode (no Ghidra counterpart found)
/// Convert a Rudra OpCode enum to the corresponding Ghidra integer opcode value.
///
/// This is the inverse of `map_ghidra_opcode`. It is needed by the verification
/// framework so that when Rudra-side ops are passed to FFI comparison functions,
/// the opcode integer matches Ghidra's numbering scheme (from `opcodes.hh`).
pub fn to_ghidra_opcode(op: OpCode) -> Option<i32> {
    match op {
        OpCode::CPUI_COPY => Some(1),
        OpCode::CPUI_LOAD => Some(2),
        OpCode::CPUI_STORE => Some(3),
        OpCode::CPUI_BRANCH => Some(4),
        OpCode::CPUI_CBRANCH => Some(5),
        OpCode::CPUI_BRANCHIND => Some(6),
        OpCode::CPUI_CALL => Some(7),
        OpCode::CPUI_CALLIND => Some(8),
        OpCode::CPUI_CALLOTHER => Some(9),
        OpCode::CPUI_RETURN => Some(10),
        OpCode::CPUI_INT_EQUAL => Some(11),
        OpCode::CPUI_INT_NOTEQUAL => Some(12),
        OpCode::CPUI_INT_SLESS => Some(13),
        OpCode::CPUI_INT_SLESSEQUAL => Some(14),
        OpCode::CPUI_INT_LESS => Some(15),
        OpCode::CPUI_INT_LESSEQUAL => Some(16),
        OpCode::CPUI_INT_ZEXT => Some(17),
        OpCode::CPUI_INT_SEXT => Some(18),
        OpCode::CPUI_INT_ADD => Some(19),
        OpCode::CPUI_INT_SUB => Some(20),
        OpCode::CPUI_INT_CARRY => Some(21),
        OpCode::CPUI_INT_SCARRY => Some(22),
        OpCode::CPUI_INT_SBORROW => Some(23),
        OpCode::CPUI_INT_2COMP => Some(24),
        OpCode::CPUI_INT_NEGATE => Some(25),
        OpCode::CPUI_INT_XOR => Some(26),
        OpCode::CPUI_INT_AND => Some(27),
        OpCode::CPUI_INT_OR => Some(28),
        OpCode::CPUI_INT_LEFT => Some(29),
        OpCode::CPUI_INT_RIGHT => Some(30),
        OpCode::CPUI_INT_SRIGHT => Some(31),
        OpCode::CPUI_INT_MULT => Some(32),
        OpCode::CPUI_INT_DIV => Some(33),
        OpCode::CPUI_INT_SDIV => Some(34),
        OpCode::CPUI_INT_REM => Some(35),
        OpCode::CPUI_INT_SREM => Some(36),
        OpCode::CPUI_BOOL_NEGATE => Some(37),
        OpCode::CPUI_BOOL_XOR => Some(38),
        OpCode::CPUI_BOOL_AND => Some(39),
        OpCode::CPUI_BOOL_OR => Some(40),
        OpCode::CPUI_FLOAT_EQUAL => Some(41),
        OpCode::CPUI_FLOAT_NOTEQUAL => Some(42),
        OpCode::CPUI_FLOAT_LESS => Some(43),
        OpCode::CPUI_FLOAT_LESSEQUAL => Some(44),
        OpCode::CPUI_FLOAT_NAN => Some(46),
        OpCode::CPUI_FLOAT_ADD => Some(47),
        OpCode::CPUI_FLOAT_DIV => Some(48),
        OpCode::CPUI_FLOAT_MULT => Some(49),
        OpCode::CPUI_FLOAT_SUB => Some(50),
        OpCode::CPUI_FLOAT_NEG => Some(51),
        OpCode::CPUI_FLOAT_ABS => Some(52),
        OpCode::CPUI_FLOAT_SQRT => Some(53),
        OpCode::CPUI_FLOAT_INT2FLOAT => Some(54),
        OpCode::CPUI_FLOAT_FLOAT2FLOAT => Some(55),
        OpCode::CPUI_FLOAT_TRUNC => Some(56),
        OpCode::CPUI_FLOAT_CEIL => Some(57),
        OpCode::CPUI_FLOAT_FLOOR => Some(58),
        OpCode::CPUI_FLOAT_ROUND => Some(59),
        OpCode::CPUI_MULTIEQUAL => Some(60),
        OpCode::CPUI_INDIRECT => Some(61),
        OpCode::CPUI_PIECE => Some(62),
        OpCode::CPUI_SUBPIECE => Some(63),
        OpCode::CPUI_CAST => Some(64),
        OpCode::CPUI_PTRADD => Some(65),
        OpCode::CPUI_PTRSUB => Some(66),
        OpCode::CPUI_SEGMENTOP => Some(67),
        OpCode::CPUI_CPOOLREF => Some(68),
        OpCode::CPUI_NEW => Some(69),
        OpCode::CPUI_INSERT => Some(70),
        OpCode::CPUI_EXTRACT => Some(71),
        OpCode::CPUI_POPCOUNT => Some(72),
        OpCode::CPUI_LZCOUNT => Some(73),
        OpCode::CPUI_SUBPIECE => Some(56), // Same as FLOAT_TRUNC in Ghidra
        OpCode::CPUI_MAX => None,
    }
}

// RUDRA-GLUE: C ABI scalar dispatcher aggregates many Ghidra OpBehavior evaluators; Ghidra has no single equivalent entry point.
/// FFI interface for constant folding evaluation
///
/// This adapter covers a subset of Ghidra's distributed
/// OpBehavior::evaluateBinary/Unary implementations; it is not a one-to-one mapping.
///
/// # Arguments
/// * `opcode` - The Ghidra OpCode integer
/// * `size_out` - Expected output size in bytes
/// * `val1` - First input constant value
/// * `size1` - First input size in bytes
/// * `val2` - Second input constant value
/// * `size2` - Second input size in bytes
/// * `has_val2` - Boolean indicating if the second input is used (binary op)
///
/// # Returns
/// The resulting constant value, or 0 if evaluation failed or opcode is unsupported.
#[no_mangle]
pub extern "C" fn rudra_evaluate_constant(
    opcode: i32,
    size_out: usize,
    val1: u64,
    size1: usize,
    val2: u64,
    _size2: usize,
    _has_val2: bool,
) -> u64 {
    let op = match map_ghidra_opcode(opcode) {
        Some(o) => o,
        None => return 0,
    };

    let res = match op {
        OpCode::CPUI_INT_ADD => val1.wrapping_add(val2),
        OpCode::CPUI_INT_SUB => val1.wrapping_sub(val2),
        OpCode::CPUI_INT_MULT => val1.wrapping_mul(val2),
        OpCode::CPUI_INT_DIV => {
            if val2 != 0 {
                val1 / val2
            } else {
                0
            }
        }
        OpCode::CPUI_INT_SDIV => {
            if val2 != 0 {
                (val1 as i64 / val2 as i64) as u64
            } else {
                0
            }
        }
        OpCode::CPUI_INT_REM => {
            if val2 != 0 {
                val1 % val2
            } else {
                0
            }
        }
        OpCode::CPUI_INT_SREM => {
            if val2 != 0 {
                (val1 as i64 % val2 as i64) as u64
            } else {
                0
            }
        }
        OpCode::CPUI_INT_2COMP => val1.wrapping_neg(),
        OpCode::CPUI_INT_NEGATE => !val1,
        OpCode::CPUI_INT_LEFT => val1.wrapping_shl((val2 as u32) & 0x3f),
        OpCode::CPUI_INT_RIGHT => val1.wrapping_shr((val2 as u32) & 0x3f),
        OpCode::CPUI_INT_SRIGHT => {
            let bit_size = (size1 * 8).min(64);
            if bit_size == 0 {
                return 0;
            }
            let shift = 64 - bit_size;
            let sval = ((val1 << shift) as i64 >> shift) as i64;
            let shift_count = (val2 as u32) & 0x3f;
            (sval >> shift_count) as u64
        }
        OpCode::CPUI_INT_EQUAL => {
            if val1 == val2 {
                1
            } else {
                0
            }
        }
        OpCode::CPUI_INT_NOTEQUAL => {
            if val1 != val2 {
                1
            } else {
                0
            }
        }
        OpCode::CPUI_INT_LESS => {
            if val1 < val2 {
                1
            } else {
                0
            }
        }
        OpCode::CPUI_INT_SLESS => {
            let bit_size = (size1 * 8).min(64);
            let shift = 64 - bit_size;
            let s1 = (val1 << shift) as i64 >> shift;
            let s2 = (val2 << shift) as i64 >> shift;
            if s1 < s2 {
                1
            } else {
                0
            }
        }
        OpCode::CPUI_INT_LESSEQUAL => {
            if val1 <= val2 {
                1
            } else {
                0
            }
        }
        OpCode::CPUI_INT_SLESSEQUAL => {
            let bit_size = (size1 * 8).min(64);
            let shift = 64 - bit_size;
            let s1 = (val1 << shift) as i64 >> shift;
            let s2 = (val2 << shift) as i64 >> shift;
            if s1 <= s2 {
                1
            } else {
                0
            }
        }
        OpCode::CPUI_INT_AND => val1 & val2,
        OpCode::CPUI_INT_OR => val1 | val2,
        OpCode::CPUI_INT_XOR => val1 ^ val2,
        OpCode::CPUI_INT_ZEXT => val1,
        OpCode::CPUI_INT_SEXT => {
            let bit_size = (size1 * 8).min(64);
            if bit_size == 0 {
                return 0;
            }
            let shift = 64 - bit_size;
            ((val1 << shift) as i64 >> shift) as u64
        }
        _ => return 0,
    };

    // Mask result to the requested output size to match Ghidra behavior
    if size_out > 0 && size_out < 8 {
        let mask = (1u64 << (size_out * 8)).wrapping_sub(1);
        res & mask
    } else {
        res
    }
}

// RUDRA-GLUE: exports Cargo package metadata through Rudra's C ABI; Ghidra has no Rudra-version endpoint.
/// Get the version of Rudra as a C string
#[no_mangle]
pub extern "C" fn rudra_version() -> *const c_char {
    static VERSION_C: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION_C.as_ptr() as *const c_char
}

// RUDRA-GLUE: set_current_program (no Ghidra counterpart found)
/// Set the current program for comparison
/// This is called by Rudra before starting the comparison with Ghidra
pub fn set_current_program(program: Funcdata) {
    let mut lock = CURRENT_PROGRAM
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *lock = Some(program);
}

// RUDRA-GLUE: initializes Rudra's process-global comparison fixture; Ghidra has no corresponding C test hook.
/// Initialize a blank program for FFI testing
#[no_mangle]
pub extern "C" fn rudra_init_test_program() {
    let mut lock = CURRENT_PROGRAM
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *lock = Some(Funcdata::new("test_func", Address::new(0), 0));
}

// RUDRA-GLUE: builds Rudra test IR from flattened C arguments; Ghidra has no equivalent C fixture builder.
/// Add an operation to the current test program
/// This allows Python/C++ to simulate Rudra's analysis state for comparison tests
#[no_mangle]
pub extern "C" fn rudra_add_test_op(
    addr: u64,
    opcode_val: i32,
    out_space: i32,
    out_offset: u64,
    out_size: u32,
) {
    let mut lock = CURRENT_PROGRAM
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(ref mut program) = *lock {
        let op_addr = Address::new(addr);
        let seqnum = SeqNum::new(op_addr, program.obank.get_uniqid());

        let op_type = match map_ghidra_opcode(opcode_val) {
            Some(o) => o,
            None => OpCode::CPUI_COPY, // Fallback
        };

        let op_ref = program.obank.create(op_type, 0, op_addr);
        let mut op_guard = op_ref.0.write().unwrap();
        op_guard.start = seqnum;

        if out_size > 0 {
            let space = if out_space == 1 {
                AddressSpace::Register
            } else {
                AddressSpace::Ram
            };
            let mut vn = Varnode::new(out_size as usize, Address::new(out_offset));
            vn.address_space = space;
            vn.set_flags(crate::varnode::varnode_flags::EXPLICIT);
            op_guard.output = Some(std::sync::Arc::new(std::sync::RwLock::new(vn)));
        }
    }
}

// RUDRA-GLUE: ignores a foreign buffer pointer and only logs its length; Ghidra has no matching callback.
/// Report binary-buffer metadata received from an FFI caller.
/// The pointer is currently ignored; only the supplied length is logged.
#[no_mangle]
pub extern "C" fn rudra_set_binary_data(_ptr: *const u8, len: usize) {
    // This would typically initialize a global analysis context
    println!("[RUDRA] Analysis context initialized with {} bytes", len);
}

// RUDRA-GLUE: logs an externally supplied jump-table observation; it does not implement Ghidra JumpTable::recoverAddresses.
/// Observe and validate a jumptable recovery in Ghidra
///
/// This is used for comparison testing to ensure Rudra's jumptable
/// recovery matches Ghidra's and is logically sound.
#[no_mangle]
pub extern "C" fn rudra_observe_jumptable(op_addr: u64, table_addr: u64, size: usize) {
    println!(
        "[RUDRA OBSERVE] JumpTable at 0x{:x}, Table: 0x{:x}, Entries: {}",
        op_addr, table_addr, size
    );

    // Validation 1: Size check
    if size == 0 || size > 4096 {
        println!(
            "[RUDRA WARN] Suspect JumpTable size: {} at 0x{:x}",
            size, op_addr
        );
    }

    // Validation 2: Table alignment (typically jump tables are pointer-aligned)
    if table_addr % 4 != 0 {
        println!(
            "[RUDRA WARN] Unaligned JumpTable address: 0x{:x}",
            table_addr
        );
    }

    // Validation 3: Null check
    if table_addr == 0 && size > 0 {
        println!(
            "[RUDRA ERR] JumpTable at 0x{:x} has non-zero size but null address!",
            op_addr
        );
    }

    // TODO: Cross-reference with Rudra's own recovery engine to ensure
    // 100% parity in decompilation output for the 'curl' sample.
}

// RUDRA-GLUE: space_to_ffi_id (no Ghidra counterpart found)
/// Convert Rudra AddressSpace to the FFI convention space_id.
///
/// The FFI convention (used by VarnodeFFI) uses:
///   Register=1, Ram=2, Unique=3, Const=4
///
/// This differs from the internal space.rs convention:
///   Ram=0, Register=1, Unique=2, Const=3
fn space_to_ffi_id(space: crate::AddressSpace) -> i32 {
    match space {
        crate::AddressSpace::Register => 1,
        crate::AddressSpace::Ram => 2,
        crate::AddressSpace::Unique => 3,
        crate::AddressSpace::Const => 4,
        _ => 0,
    }
}

// RUDRA-GLUE: compares flattened foreign P-code with Rudra state; Ghidra has no cross-engine C comparator.
/// Compare a P-code operation from Ghidra with Rudra's internal state
///
/// This is the "ultimate comparison" function that verifies if Rudra's
/// entire analysis pipeline produces the same P-code structure as Ghidra.
#[no_mangle]
pub unsafe extern "C" fn rudra_compare_pcode(
    op_addr: u64,
    op_order: u32,
    opcode: i32,
    out_vn: *const VarnodeFFI,
    inputs: *const VarnodeFFI,
    input_count: i32,
) -> PcodeCompareResultFFI {
    let lock = CURRENT_PROGRAM
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let program = match lock.as_ref() {
        Some(p) => p,
        None => {
            return PcodeCompareResultFFI {
                status: PCODE_COMPARE_MISSING_RUDRA_OP,
            }
        }
    };

    // Find Rudra op at this address and sequence order
    let op_addr_obj = Address::new(op_addr);
    let rudra_op = program
        .obank
        .optree
        .iter()
        .find(|o| {
            let op = o.0.read().unwrap();
            op.get_addr() == op_addr_obj && op.get_seq_num().order == op_order
        })
        .cloned();
    let mapped_op = map_ghidra_opcode(opcode);

    // Check if Ghidra op exists in Rudra
    let Some(r_op_ref) = rudra_op else {
        println!(
            "[RUDRA DIFF] 0x{:x}:{} Ghidra has op {}, but Rudra has NONE",
            op_addr, op_order, opcode
        );
        return PcodeCompareResultFFI {
            status: PCODE_COMPARE_MISSING_RUDRA_OP,
        };
    };

    let r_op = r_op_ref.0.read().unwrap();

    let opcode_matches = match (r_op.get_opcode(), mapped_op) {
        (a, Some(b)) => a == b,
        _ => false,
    };

    if !opcode_matches {
        println!(
            "[RUDRA DIFF] 0x{:x}:{} Opcode mismatch. Ghidra Op: {}, Rudra Op: {:?}",
            op_addr,
            op_order,
            opcode,
            r_op.get_opcode()
        );
        return PcodeCompareResultFFI {
            status: PCODE_COMPARE_OPCODE_MISMATCH,
        };
    }

    // Compare Output
    match (r_op.get_out(), out_vn.as_ref()) {
        (Some(r_out_lock), Some(g_out)) => {
            let r_out = r_out_lock.read().unwrap();
            let r_ffi_space = space_to_ffi_id(r_out.space());
            // Skip offset comparison for unique-space varnodes since
            // Rudra and Ghidra use different unique allocation strategies.
            let is_unique = r_out.space().is_unique() || g_out.space_id == 3;
            let space_match = r_ffi_space == g_out.space_id;
            let offset_match = is_unique || r_out.offset() == g_out.offset;
            let size_match = r_out.size() == g_out.size as usize;
            if !space_match || !offset_match || !size_match {
                println!("[RUDRA DIFF] 0x{:x}:{} Output mismatch. Rudra: {} (ffi_space={}), Ghidra space: {}, offset: 0x{:x}, size: {}",
                    op_addr, op_order, *r_out, r_ffi_space, g_out.space_id, g_out.offset, g_out.size);
                return PcodeCompareResultFFI {
                    status: PCODE_COMPARE_OUTPUT_MISMATCH,
                };
            }
        }
        (None, Some(_)) => {
            println!(
                "[RUDRA DIFF] 0x{:x}:{} Ghidra has output, Rudra has NONE",
                op_addr, op_order
            );
            return PcodeCompareResultFFI {
                status: PCODE_COMPARE_OUTPUT_MISMATCH,
            };
        }
        (Some(_), None) => {
            println!(
                "[RUDRA DIFF] 0x{:x}:{} Rudra has output, Ghidra has NONE",
                op_addr, op_order
            );
            return PcodeCompareResultFFI {
                status: PCODE_COMPARE_OUTPUT_MISMATCH,
            };
        }
        (None, None) => (),
    }

    // Compare Input Count
    let r_input_count = r_op.num_input();
    if r_input_count != input_count as usize {
        println!(
            "[RUDRA DIFF] 0x{:x}:{} Input count mismatch. Rudra: {}, Ghidra: {}",
            op_addr, op_order, r_input_count, input_count
        );
        return PcodeCompareResultFFI {
            status: PCODE_COMPARE_INPUT_COUNT_MISMATCH,
        };
    }

    // Compare Inputs
    let ghidra_inputs = if input_count > 0 && !inputs.is_null() {
        std::slice::from_raw_parts(inputs, input_count as usize)
    } else {
        &[]
    };

    for (idx, g_in) in ghidra_inputs.iter().enumerate() {
        let Some(r_in_lock) = r_op.get_in(idx) else {
            println!(
                "[RUDRA DIFF] 0x{:x}:{} Missing Rudra input at index {}",
                op_addr, op_order, idx
            );
            return PcodeCompareResultFFI {
                status: PCODE_COMPARE_INPUT_MISMATCH,
            };
        };

        let r_in = r_in_lock.read().unwrap();
        let r_ffi_space = space_to_ffi_id(r_in.space());
        // Skip offset comparison for unique-space varnodes
        let is_unique = r_in.space().is_unique() || g_in.space_id == 3;
        let space_match = r_ffi_space == g_in.space_id;
        let offset_match = is_unique || r_in.offset() == g_in.offset;
        let size_match = r_in.size() == g_in.size as usize;
        if !space_match || !offset_match || !size_match
        {
            println!(
                "[RUDRA DIFF] 0x{:x}:{} Input mismatch at index {}. Rudra: {} (ffi_space={}), Ghidra space: {}, offset: 0x{:x}, size: {}",
                op_addr, op_order, idx, *r_in, r_ffi_space, g_in.space_id, g_in.offset, g_in.size
            );
            return PcodeCompareResultFFI {
                status: PCODE_COMPARE_INPUT_MISMATCH,
            };
        }
    }

    PcodeCompareResultFFI {
        status: PCODE_COMPARE_MATCH,
    }
}

// RUDRA-GLUE: logs an external numeric SSA label; Ghidra Varnode has no version field, and this is not Heritage::rename.
/// Intercept and compare SSA versioning (Heritage)
#[no_mangle]
pub unsafe extern "C" fn rudra_check_varnode_version(vn: *const VarnodeFFI, version: i32) {
    if vn.is_null() {
        return;
    }
    let g_vn = &*vn;

    // In a full implementation, we would look up the varnode in the current Funcdata
    // and verify that the version matches. For now, we log the observation for the
    // python FFI testing framework to consume.
    println!(
        "[RUDRA OBSERVE] SSA check for space: {}, offset: 0x{:x}, size: {} -> v{}",
        g_vn.space_id, g_vn.offset, g_vn.size, version
    );
}

// RUDRA-GLUE: logs a flattened external CFG observation; it does not implement Ghidra FlowBlock algorithms.
/// Intercept and compare Control Flow Graph structure
#[no_mangle]
pub unsafe extern "C" fn rudra_check_block_structure(
    block_id: i32,
    block_type: i32,
    successors: *const i32,
    succ_count: i32,
) {
    println!(
        "[RUDRA OBSERVE] CFG check for block {}, type {}, succ_count {}",
        block_id, block_type, succ_count
    );

    if successors.is_null() && succ_count > 0 {
        println!(
            "[RUDRA DIFF] CFG: Null successor array but count is {}",
            succ_count
        );
    }
}

// RUDRA-GLUE: logs an external action event; it does not implement Ghidra Action::perform.
/// Intercept and compare Transformation Actions
#[no_mangle]
pub unsafe extern "C" fn rudra_check_action_apply(
    action_name: *const std::ffi::c_char,
    func_addr: u64,
    modified: bool,
) {
    if !action_name.is_null() {
        let c_str = std::ffi::CStr::from_ptr(action_name);
        if let Ok(name_str) = c_str.to_str() {
            println!(
                "[RUDRA OBSERVE] Action {} at 0x{:x}, modified: {}",
                name_str, func_addr, modified
            );
        }
    }
}
