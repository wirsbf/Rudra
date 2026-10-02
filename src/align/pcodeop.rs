//! PcodeOp and PcodeOperation alignment verification logic.
//!
//! This module ensures that Rudra's P-code operations match Ghidra's
//! internal PcodeOp representation as defined in `op.hh`.

use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::varnode::Varnode;
use crate::ffi::VarnodeFFI;
use crate::align::address::verify_seqnum;
use crate::align::varnode::verify_varnode;

// RUDRA-GLUE: verify_opcode (no Ghidra counterpart found)
/// Verify that a Rudra OpCode matches a Ghidra opcode
///
/// Note: `ghidra_opcode` uses Ghidra's numbering scheme (from opcodes.hh),
/// which is DIFFERENT from Rudra's enum values. We must use
/// `map_ghidra_opcode` (not `OpCode::from_i32`) to convert.
pub fn verify_opcode(rudra_op: OpCode, ghidra_opcode: i32) -> bool {
    match crate::ffi::map_ghidra_opcode(ghidra_opcode) {
        Some(mapped_op) => {
            let matches = rudra_op == mapped_op;
            if !matches {
                eprintln!(
                    "[ALIGN DIFF] Opcode mismatch: Rudra {:?} != Ghidra opcode {} (mapped: {:?})",
                    rudra_op, ghidra_opcode, mapped_op
                );
            }
            matches
        }
        None => {
            eprintln!(
                "[ALIGN DIFF] Unknown Ghidra opcode: {}",
                ghidra_opcode
            );
            false
        }
    }
}

// RUDRA-GLUE: verify_operation (no Ghidra counterpart found)
/// Verify that a complete PcodeOperation aligns with Ghidra's representation
///
/// This checks:
/// - Opcode match
/// - SeqNum match
/// - Input count and values
/// - Output presence and value
pub fn verify_operation(
    rudra_op: &PcodeOp,
    ghidra_opcode: i32,
    ghidra_addr: u64,
    ghidra_seq: u32,
    ghidra_inputs: &[VarnodeFFI],
    ghidra_output: Option<&VarnodeFFI>,
) -> bool {
    // 1. Verify opcode
    let opcode_match = verify_opcode(rudra_op.get_opcode(), ghidra_opcode);

    // 2. Verify sequence number
    let seqnum_match = verify_seqnum(rudra_op.get_seq_num(), ghidra_addr, ghidra_seq);

    // 3. Verify input count
    let input_count_match = rudra_op.num_input() == ghidra_inputs.len();
    if !input_count_match {
        eprintln!(
            "[ALIGN DIFF] Input count mismatch at {}: Rudra {} != Ghidra {}",
            rudra_op.get_seq_num(),
            rudra_op.num_input(),
            ghidra_inputs.len()
        );
    }

    // 4. Verify inputs
    let inputs_match = if input_count_match {
        let mut all_match = true;
        for i in 0..rudra_op.num_input() {
            if let Some(r_in_lock) = rudra_op.get_in(i) {
                let r_in = r_in_lock.read().unwrap();
                if !verify_varnode(&r_in, &ghidra_inputs[i]) {
                    all_match = false;
                }
            }
        }
        all_match
    } else {
        false
    };

    // 5. Verify output
    let output_match = match (rudra_op.get_out(), ghidra_output) {
        (Some(r_out_lock), Some(g_out)) => {
            let r_out = r_out_lock.read().unwrap();
            verify_varnode(&r_out, g_out)
        },
        (None, None) => true,
        _ => {
            eprintln!(
                "[ALIGN DIFF] Output presence mismatch at {}",
                rudra_op.get_seq_num()
            );
            false
        }
    };

    opcode_match && seqnum_match && input_count_match && inputs_match && output_match
}

// RUDRA-GLUE: verify_inputs (no Ghidra counterpart found)
/// Verify input list alignment
pub fn verify_inputs(rudra_inputs: &[Varnode], ghidra_inputs: &[VarnodeFFI]) -> bool {
    if rudra_inputs.len() != ghidra_inputs.len() {
        eprintln!(
            "[ALIGN DIFF] Input count mismatch: Rudra {} != Ghidra {}",
            rudra_inputs.len(),
            ghidra_inputs.len()
        );
        return false;
    }

    rudra_inputs.iter()
        .zip(ghidra_inputs.iter())
        .all(|(r, g)| verify_varnode(r, g))
}

// RUDRA-GLUE: verify_output (no Ghidra counterpart found)
/// Verify output alignment
pub fn verify_output(rudra_output: Option<&Varnode>, ghidra_output: Option<&VarnodeFFI>) -> bool {
    match (rudra_output, ghidra_output) {
        (Some(r), Some(g)) => verify_varnode(r, g),
        (None, None) => true,
        (Some(_), None) => {
            eprintln!("[ALIGN DIFF] Rudra has output but Ghidra doesn't");
            false
        }
        (None, Some(_)) => {
            eprintln!("[ALIGN DIFF] Ghidra has output but Rudra doesn't");
            false
        }
    }
}

// Note: Re-enable tests later when test logic incorporates Arc<RwLock<PcodeOp>>
/*
#[cfg(test)]
mod tests {
...
}
*/
