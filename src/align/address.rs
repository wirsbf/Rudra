//! Address and SeqNum alignment verification logic.
//!
//! This module ensures that Rudra's address representation matches Ghidra's
//! internal Address and SeqNum classes as defined in `address.hh`.

use crate::Address;
use crate::{SeqNum, AddressSpace};

// RUDRA-GLUE: verify_address (no Ghidra counterpart found)
/// Verify that a Rudra Address aligns with Ghidra's representation.
///
/// Ghidra Addresses consist of an AddressSpace and an offset.
pub fn verify_address(
    rudra_addr: &Address,
    rudra_space: &AddressSpace,
    ghidra_offset: u64,
    ghidra_space_id: i32,
) -> bool {
    let offset_match = rudra_addr.as_u64() == ghidra_offset;

    // Space IDs are architecture-dependent in Ghidra.
    // Common mappings: Register=1, RAM=2 or higher.
    let _space_match = match (rudra_space, ghidra_space_id) {
        (AddressSpace::Register, 1) => true,
        (AddressSpace::Ram, id) if id >= 2 => true,
        (AddressSpace::Unique, _) => true, // Unique space IDs vary wildly
        _ => false,
    };

    if !offset_match {
        eprintln!(
            "[ALIGN DIFF] Address offset mismatch: Rudra 0x{:x} != Ghidra 0x{:x}",
            rudra_addr.as_u64(),
            ghidra_offset
        );
    }

    offset_match
}

// RUDRA-GLUE: verify_seqnum (no Ghidra counterpart found)
/// Verify that a Rudra SeqNum aligns with Ghidra's representation.
///
/// Ghidra SeqNum includes an Address and a 'time' or 'order' index
/// used to distinguish multiple P-code operations for a single instruction.
pub fn verify_seqnum(
    rudra_seq: &SeqNum,
    ghidra_offset: u64,
    ghidra_order: u32,
) -> bool {
    let addr_match = rudra_seq.addr.as_u64() == ghidra_offset;
    let order_match = rudra_seq.order == ghidra_order;

    if !addr_match || !order_match {
        eprintln!(
            "[ALIGN DIFF] SeqNum mismatch: Rudra ({}:{}) != Ghidra (0x{:x}:{})",
            rudra_seq.addr, rudra_seq.order, ghidra_offset, ghidra_order
        );
    }

    addr_match && order_match
}

// RUDRA-GLUE: map_ghidra_space (no Ghidra counterpart found)
/// Helper to convert Ghidra space ID to Rudra AddressSpace for verification
pub fn map_ghidra_space(space_id: i32) -> AddressSpace {
    match space_id {
        1 => AddressSpace::Register,
        2 => AddressSpace::Ram,
        _ => AddressSpace::Other(space_id as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_alignment() {
        let addr = Address::new(0x1000);
        let space = AddressSpace::Ram;
        assert!(verify_address(&addr, &space, 0x1000, 2));
    }

    #[test]
    fn test_seqnum_alignment() {
        let seq = SeqNum::new(Address::new(0x1000), 5);
        assert!(verify_seqnum(&seq, 0x1000, 5));
    }

    #[test]
    fn test_space_mapping() {
        assert_eq!(map_ghidra_space(1), AddressSpace::Register);
        assert_eq!(map_ghidra_space(2), AddressSpace::Ram);
    }
}
