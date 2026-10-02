//! Varnode alignment verification logic.
//!
//! This module ensures that Rudra's Varnode representation matches Ghidra's
//! internal Varnode class as defined in `varnode.hh`.

use crate::varnode::Varnode;
use crate::AddressSpace;
use crate::ffi::VarnodeFFI;

// RUDRA-GLUE: verify_varnode (no Ghidra counterpart found)
/// Verify that a Rudra Varnode aligns with Ghidra's FFI representation.
///
/// This checks space, offset, and size parity.
pub fn verify_varnode(rudra_vn: &Varnode, ghidra_vn: &VarnodeFFI) -> bool {
    // Map Rudra AddressSpace to FFI convention space_id for comparison
    // FFI convention: Register=1, Ram=2, Unique=3, Const=4
    let rudra_space_id = match rudra_vn.space() {
        AddressSpace::Register => 1,
        AddressSpace::Ram => 2,
        AddressSpace::Unique => 3,
        AddressSpace::Const => 4,
        _ => 0,
    };

    let space_match = if rudra_vn.is_unique() {
        true // Skip strict space ID check for Unique as it varies by Architecture
    } else {
        rudra_space_id == ghidra_vn.space_id
    };

    // Skip offset comparison for unique-space varnodes since Rudra and Ghidra
    // use different unique allocation strategies. Only compare space + size.
    let offset_match = if rudra_vn.is_unique() || ghidra_vn.space_id == 3 {
        true // Unique offsets are implementation-specific, not comparable
    } else {
        rudra_vn.offset() == ghidra_vn.offset
    };
    let size_match = rudra_vn.size() == ghidra_vn.size as usize;

    if !space_match || !offset_match || !size_match {
        eprintln!(
            "[ALIGN DIFF] Varnode mismatch!\n  Rudra:  {}\n  Ghidra: Space={}, Offset=0x{:x}, Size={}",
            rudra_vn, ghidra_vn.space_id, ghidra_vn.offset, ghidra_vn.size
        );
    }

    space_match && offset_match && size_match
}

// RUDRA-GLUE: verify_varnode_list (no Ghidra counterpart found)
/// Verify a list of Varnodes (typically P-code operation inputs)
pub fn verify_varnode_list(rudra_list: &[Varnode], ghidra_list: &[VarnodeFFI]) -> bool {
    if rudra_list.len() != ghidra_list.len() {
        eprintln!(
            "[ALIGN DIFF] Varnode list length mismatch: Rudra={}, Ghidra={}",
            rudra_list.len(),
            ghidra_list.len()
        );
        return false;
    }

    rudra_list.iter()
        .zip(ghidra_list.iter())
        .all(|(r, g)| verify_varnode(r, g))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_alignment_success() {
        let vn = Varnode::new_register(0x10, 4);
        let ffi = VarnodeFFI {
            space_id: 1,
            offset: 0x10,
            size: 4,
        };
        assert!(verify_varnode(&vn, &ffi));
    }

    #[test]
    fn test_varnode_alignment_failure() {
        let vn = Varnode::new_register(0x10, 4);
        let ffi = VarnodeFFI {
            space_id: 1,
            offset: 0x11, // Wrong offset
            size: 4,
        };
        assert!(!verify_varnode(&vn, &ffi));
    }
}
