//! Range and RangeList alignment verification logic.
//!
//! This module ensures that Rudra's address range representation matches Ghidra's
//! internal Range and RangeList classes as defined in `address.hh`.

use crate::Address;

/// Represents an address range (start, end)
///
/// Corresponds to Ghidra's Range class
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// First address in the range (inclusive)
    pub first: Address,
    /// Last address in the range (inclusive)
    pub last: Address,
}

impl Range {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Create a new range
    pub fn new(first: Address, last: Address) -> Option<Self> {
        if first.as_u64() <= last.as_u64() {
            Some(Range { first, last })
        } else {
            None
        }
    }

    // RUDRA-GLUE: contains (no Ghidra counterpart found)
    /// Check if an address is contained in this range
    pub fn contains(&self, addr: Address) -> bool {
        addr.as_u64() >= self.first.as_u64() && addr.as_u64() <= self.last.as_u64()
    }

    // RUDRA-GLUE: get_first (no Ghidra counterpart found)
    /// Get the first address
    pub fn get_first(&self) -> Address {
        self.first
    }

    // RUDRA-GLUE: get_last (no Ghidra counterpart found)
    /// Get the last address
    pub fn get_last(&self) -> Address {
        self.last
    }

    // RUDRA-GLUE: size (no Ghidra counterpart found)
    /// Get the size of the range in bytes
    pub fn size(&self) -> u64 {
        self.last.as_u64().saturating_sub(self.first.as_u64()).saturating_add(1)
    }

    // RUDRA-GLUE: overlaps (no Ghidra counterpart found)
    /// Check if this range overlaps with another
    pub fn overlaps(&self, other: &Range) -> bool {
        self.first.as_u64() <= other.last.as_u64()
            && other.first.as_u64() <= self.last.as_u64()
    }

    // RUDRA-GLUE: is_adjacent (no Ghidra counterpart found)
    /// Check if this range is adjacent to another
    pub fn is_adjacent(&self, other: &Range) -> bool {
        self.last.as_u64().saturating_add(1) == other.first.as_u64()
            || other.last.as_u64().saturating_add(1) == self.first.as_u64()
    }
}

/// Represents a collection of non-overlapping address ranges
///
/// Corresponds to Ghidra's RangeList class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeList {
    /// Sorted list of non-overlapping ranges
    ranges: Vec<Range>,
}

impl RangeList {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Create a new empty range list
    pub fn new() -> Self {
        RangeList { ranges: Vec::new() }
    }

    // RUDRA-GLUE: insert_range (no Ghidra counterpart found)
    /// Insert a range into the list, merging overlapping ranges
    pub fn insert_range(&mut self, new_range: Range) {
        if self.ranges.is_empty() {
            self.ranges.push(new_range);
            return;
        }

        let mut merged = new_range;
        let mut to_remove = Vec::new();

        for (i, existing) in self.ranges.iter().enumerate() {
            if merged.overlaps(existing) || merged.is_adjacent(existing) {
                // Merge the ranges
                let first = std::cmp::min(merged.first.as_u64(), existing.first.as_u64());
                let last = std::cmp::max(merged.last.as_u64(), existing.last.as_u64());
                merged = Range {
                    first: Address::new(first),
                    last: Address::new(last),
                };
                to_remove.push(i);
            }
        }

        // Remove merged ranges (in reverse order to maintain indices)
        for &i in to_remove.iter().rev() {
            self.ranges.remove(i);
        }

        // Insert merged range in sorted position
        let insert_pos = self.ranges
            .binary_search_by_key(&merged.first.as_u64(), |r| r.first.as_u64())
            .unwrap_or_else(|pos| pos);
        self.ranges.insert(insert_pos, merged);
    }

    // RUDRA-GLUE: remove_range (no Ghidra counterpart found)
    /// Remove a range from the list
    pub fn remove_range(&mut self, to_remove: Range) {
        let mut new_ranges = Vec::new();

        for existing in &self.ranges {
            if !existing.overlaps(&to_remove) {
                // No overlap, keep the range
                new_ranges.push(*existing);
            } else {
                // Handle partial overlap
                if existing.first.as_u64() < to_remove.first.as_u64() {
                    // Keep the part before the removed range
                    if let Some(range) = Range::new(
                        existing.first,
                        Address::new(to_remove.first.as_u64().saturating_sub(1))
                    ) {
                        new_ranges.push(range);
                    }
                }
                if existing.last.as_u64() > to_remove.last.as_u64() {
                    // Keep the part after the removed range
                    if let Some(range) = Range::new(
                        Address::new(to_remove.last.as_u64().saturating_add(1)),
                        existing.last
                    ) {
                        new_ranges.push(range);
                    }
                }
            }
        }

        self.ranges = new_ranges;
    }

    // RUDRA-GLUE: in_range (no Ghidra counterpart found)
    /// Check if an address is in any range in the list
    pub fn in_range(&self, addr: Address) -> bool {
        self.ranges.iter().any(|r| r.contains(addr))
    }

    // RUDRA-GLUE: num_ranges (no Ghidra counterpart found)
    /// Get the number of ranges in the list
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    // RUDRA-GLUE: ranges (no Ghidra counterpart found)
    /// Get all ranges
    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }

    // RUDRA-GLUE: merge (no Ghidra counterpart found)
    /// Merge another RangeList into this one
    pub fn merge(&mut self, other: &RangeList) {
        for range in &other.ranges {
            self.insert_range(*range);
        }
    }

    // RUDRA-GLUE: is_empty (no Ghidra counterpart found)
    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    // RUDRA-GLUE: clear (no Ghidra counterpart found)
    /// Clear all ranges
    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

impl Default for RangeList {
    // RUDRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

// RUDRA-GLUE: verify_range (no Ghidra counterpart found)
/// Verify that a Rudra Range aligns with Ghidra's representation
pub fn verify_range(
    rudra_range: &Range,
    ghidra_first: u64,
    ghidra_last: u64,
) -> bool {
    let first_match = rudra_range.first.as_u64() == ghidra_first;
    let last_match = rudra_range.last.as_u64() == ghidra_last;

    if !first_match || !last_match {
        eprintln!(
            "[ALIGN DIFF] Range mismatch: Rudra [0x{:x}, 0x{:x}] != Ghidra [0x{:x}, 0x{:x}]",
            rudra_range.first.as_u64(),
            rudra_range.last.as_u64(),
            ghidra_first,
            ghidra_last
        );
    }

    first_match && last_match
}

// RUDRA-GLUE: verify_range_list (no Ghidra counterpart found)
/// Verify that a Rudra RangeList aligns with Ghidra's representation
pub fn verify_range_list(
    rudra_list: &RangeList,
    ghidra_ranges: &[(u64, u64)], // (first, last) pairs
) -> bool {
    if rudra_list.num_ranges() != ghidra_ranges.len() {
        eprintln!(
            "[ALIGN DIFF] RangeList count mismatch: Rudra {} != Ghidra {}",
            rudra_list.num_ranges(),
            ghidra_ranges.len()
        );
        return false;
    }

    for (rudra_range, (ghidra_first, ghidra_last)) in rudra_list.ranges().iter().zip(ghidra_ranges.iter()) {
        if !verify_range(rudra_range, *ghidra_first, *ghidra_last) {
            return false;
        }
    }

    true
}

// RUDRA-GLUE: verify_contains (no Ghidra counterpart found)
/// Verify that contains() function aligns
pub fn verify_contains(
    rudra_range: &Range,
    test_addr: u64,
    ghidra_result: bool,
) -> bool {
    let rudra_result = rudra_range.contains(Address::new(test_addr));

    if rudra_result != ghidra_result {
        eprintln!(
            "[ALIGN DIFF] Range::contains(0x{:x}) mismatch: Rudra {} != Ghidra {}",
            test_addr,
            rudra_result,
            ghidra_result
        );
    }

    rudra_result == ghidra_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_creation() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();
        assert_eq!(range.first.as_u64(), 0x1000);
        assert_eq!(range.last.as_u64(), 0x2000);

        // Invalid range (first > last)
        assert!(Range::new(Address::new(0x2000), Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_range_contains() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();

        assert!(range.contains(Address::new(0x1000))); // First
        assert!(range.contains(Address::new(0x1500))); // Middle
        assert!(range.contains(Address::new(0x2000))); // Last
        assert!(!range.contains(Address::new(0x0FFF))); // Before
        assert!(!range.contains(Address::new(0x2001))); // After
    }

    #[test]
    fn test_range_size() {
        let range = Range::new(Address::new(0x1000), Address::new(0x1FFF)).unwrap();
        assert_eq!(range.size(), 0x1000); // 4096 bytes
    }

    #[test]
    fn test_range_overlap() {
        let r1 = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();
        let r2 = Range::new(Address::new(0x1500), Address::new(0x2500)).unwrap();
        let r3 = Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap();

        assert!(r1.overlaps(&r2));
        assert!(r2.overlaps(&r1));
        assert!(!r1.overlaps(&r3));
    }

    #[test]
    fn test_range_list_insert() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        assert_eq!(list.num_ranges(), 1);

        // Non-overlapping range
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());
        assert_eq!(list.num_ranges(), 2);
    }

    #[test]
    fn test_range_list_merge() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x1500), Address::new(0x2500)).unwrap());

        // Should merge into one range
        assert_eq!(list.num_ranges(), 1);
        assert_eq!(list.ranges()[0].first.as_u64(), 0x1000);
        assert_eq!(list.ranges()[0].last.as_u64(), 0x2500);
    }

    #[test]
    fn test_range_list_in_range() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());

        assert!(list.in_range(Address::new(0x1500)));
        assert!(list.in_range(Address::new(0x3500)));
        assert!(!list.in_range(Address::new(0x2500)));
    }

    #[test]
    fn test_range_list_remove() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x3000)).unwrap());

        // Remove middle part
        list.remove_range(Range::new(Address::new(0x1500), Address::new(0x2500)).unwrap());

        assert_eq!(list.num_ranges(), 2);
        assert!(list.in_range(Address::new(0x1000)));
        assert!(!list.in_range(Address::new(0x2000)));
        assert!(list.in_range(Address::new(0x2F00)));
    }

    #[test]
    fn test_verify_range() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();
        assert!(verify_range(&range, 0x1000, 0x2000));
        assert!(!verify_range(&range, 0x1000, 0x1FFF));
    }

    #[test]
    fn test_verify_range_list() {
        let mut list = RangeList::new();
        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());

        let ghidra_ranges = vec![(0x1000, 0x2000), (0x3000, 0x4000)];
        assert!(verify_range_list(&list, &ghidra_ranges));
    }

    #[test]
    fn test_verify_contains() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();

        assert!(verify_contains(&range, 0x1500, true));
        assert!(verify_contains(&range, 0x3000, false));
    }
}
