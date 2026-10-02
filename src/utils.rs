//! Utility functions and helpers for Rugra
//!
//! This module contains various utility functions used throughout the decompiler,
//! including bit manipulation, collection helpers, and common operations.



/// Bit manipulation utilities
pub mod bits {
    // RUDRA-GLUE: extract (no Ghidra counterpart found)
    /// Extract a bit range from a value
    ///
    /// # Arguments
    ///
    /// * `value` - The value to extract from
    /// * `start` - Starting bit position (0-indexed)
    /// * `length` - Number of bits to extract
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let value = 0b11010110u8;
    /// let bits = extract(value as u64, 2, 4);
    /// assert_eq!(bits, 0b0101);
    /// ```
    pub fn extract(value: u64, start: usize, length: usize) -> u64 {
        let mask = (1u64 << length) - 1;
        (value >> start) & mask
    }

    // RUDRA-GLUE: insert (no Ghidra counterpart found)
    /// Set a bit range in a value
    ///
    /// # Arguments
    ///
    /// * `value` - The original value
    /// * `start` - Starting bit position
    /// * `length` - Number of bits to set
    /// * `bits` - The bits to insert
    pub fn insert(value: u64, start: usize, length: usize, bits: u64) -> u64 {
        let mask = ((1u64 << length) - 1) << start;
        (value & !mask) | ((bits << start) & mask)
    }

    // RUDRA-GLUE: sign_extend (no Ghidra counterpart found)
    /// Sign-extend a value
    ///
    /// # Arguments
    ///
    /// * `value` - The value to sign-extend
    /// * `bits` - Number of significant bits in the value
    pub fn sign_extend(value: u64, bits: usize) -> i64 {
        let shift = 64 - bits;
        ((value << shift) as i64) >> shift
    }

    // RUDRA-GLUE: popcount (no Ghidra counterpart found)
    /// Count the number of set bits (population count)
    pub fn popcount(value: u64) -> u32 {
        value.count_ones()
    }

    // RUDRA-GLUE: leading_zeros (no Ghidra counterpart found)
    /// Count leading zeros
    pub fn leading_zeros(value: u64) -> u32 {
        value.leading_zeros()
    }

    // RUDRA-GLUE: trailing_zeros (no Ghidra counterpart found)
    /// Count trailing zeros
    pub fn trailing_zeros(value: u64) -> u32 {
        value.trailing_zeros()
    }

    // RUDRA-GLUE: is_power_of_two (no Ghidra counterpart found)
    /// Check if a value is a power of 2
    pub fn is_power_of_two(value: u64) -> bool {
        value != 0 && (value & (value - 1)) == 0
    }

    // RUDRA-GLUE: next_power_of_two (no Ghidra counterpart found)
    /// Get the next power of 2 greater than or equal to the value
    pub fn next_power_of_two(value: u64) -> u64 {
        if value == 0 {
            1
        } else {
            1u64 << (64 - (value - 1).leading_zeros())
        }
    }
}

/// String formatting utilities
pub mod format {
    use crate::Address;

    // RUDRA-GLUE: hex_bytes (no Ghidra counterpart found)
    /// Format a byte slice as a hexadecimal string
    pub fn hex_bytes(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    // RUDRA-GLUE: format_address (no Ghidra counterpart found)
    /// Format an address with padding
    pub fn format_address(addr: Address, width: usize) -> String {
        format!("{:0width$x}", addr.as_u64(), width = width)
    }

    // RUDRA-GLUE: escape_c_string (no Ghidra counterpart found)
    /// Escape a string for C output
    pub fn escape_c_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                '\\' => result.push_str("\\\\"),
                '"' => result.push_str("\\\""),
                '\0' => result.push_str("\\0"),
                c if c.is_ascii_control() => {
                    result.push_str(&format!("\\x{:02x}", c as u8));
                }
                c => result.push(c),
            }
        }
        result
    }

    // RUDRA-GLUE: make_c_identifier (no Ghidra counterpart found)
    /// Generate a valid C identifier from a string
    pub fn make_c_identifier(s: &str) -> String {
        let mut result = String::new();
        for (i, ch) in s.chars().enumerate() {
            if i == 0 && ch.is_ascii_digit() {
                result.push('_');
            }
            if ch.is_alphanumeric() || ch == '_' {
                result.push(ch);
            } else {
                result.push('_');
            }
        }
        if result.is_empty() {
            result.push_str("var");
        }
        result
    }
}

/// Graph and data structure utilities
pub mod graph {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::hash::Hash;

    // RUDRA-GLUE: compute_dominators (no Ghidra counterpart found)
    /// Compute dominators using the iterative algorithm
    ///
    /// Returns a map from each node to its immediate dominator
    pub fn compute_dominators<T>(
        entry: T,
        successors: &HashMap<T, Vec<T>>,
    ) -> HashMap<T, T>
    where
        T: Clone + Eq + Hash,
    {
        let mut dom: HashMap<T, HashSet<T>> = HashMap::new();
        let mut all_nodes = HashSet::new();

        // Collect all nodes
        for (node, succs) in successors {
            all_nodes.insert(node.clone());
            all_nodes.extend(succs.iter().cloned());
        }

        // Initialize: entry dominates only itself, others dominate by all nodes
        for node in &all_nodes {
            if node == &entry {
                let mut s = HashSet::new();
                s.insert(entry.clone());
                dom.insert(node.clone(), s);
            } else {
                dom.insert(node.clone(), all_nodes.clone());
            }
        }

        // Iterate until fixpoint
        let mut changed = true;
        while changed {
            changed = false;
            for node in &all_nodes {
                if node == &entry {
                    continue;
                }

                // Find predecessors
                let preds: Vec<T> = successors
                    .iter()
                    .filter_map(|(pred, succs)| {
                        if succs.contains(node) {
                            Some(pred.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                if preds.is_empty() {
                    continue;
                }

                // new_dom = {node} ∪ (∩ dom[p] for p in preds)
                let mut new_dom: HashSet<T> = dom[&preds[0]].clone();
                for pred in &preds[1..] {
                    new_dom = new_dom
                        .intersection(&dom[pred])
                        .cloned()
                        .collect();
                }
                new_dom.insert(node.clone());

                if new_dom != dom[node] {
                    dom.insert(node.clone(), new_dom);
                    changed = true;
                }
            }
        }

        // Convert to immediate dominators
        let mut idom = HashMap::new();
        for (node, dominators) in &dom {
            if node == &entry {
                continue;
            }
            // The immediate dominator is the unique dominator that doesn't dominate any other dominator
            let candidates: Vec<_> = dominators
                .iter()
                .filter(|d| *d != node)
                .cloned()
                .collect();

            if let Some(immediate) = candidates.iter().find(|candidate| {
                !candidates
                    .iter()
                    .any(|other| other != *candidate && dom[other].contains(*candidate))
            }) {
                idom.insert(node.clone(), immediate.clone());
            }
        }

        idom
    }

    // RUDRA-GLUE: topological_sort (no Ghidra counterpart found)
    /// Perform topological sort on a directed acyclic graph
    pub fn topological_sort<T>(nodes: &[T], edges: &HashMap<T, Vec<T>>) -> Option<Vec<T>>
    where
        T: Clone + Eq + Hash,
    {
        let mut in_degree: HashMap<T, usize> = HashMap::new();
        let mut result = Vec::new();
        let mut queue = VecDeque::new();

        // Calculate in-degrees
        for node in nodes {
            in_degree.entry(node.clone()).or_insert(0);
        }
        for succs in edges.values() {
            for succ in succs {
                *in_degree.entry(succ.clone()).or_insert(0) += 1;
            }
        }

        // Find all nodes with in-degree 0
        for (node, &degree) in &in_degree {
            if degree == 0 {
                queue.push_back(node.clone());
            }
        }

        // Process nodes
        while let Some(node) = queue.pop_front() {
            result.push(node.clone());

            if let Some(succs) = edges.get(&node) {
                for succ in succs {
                    if let Some(degree) = in_degree.get_mut(succ) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(succ.clone());
                        }
                    }
                }
            }
        }

        // Check if all nodes were processed (no cycles)
        if result.len() == nodes.len() {
            Some(result)
        } else {
            None // Graph has cycles
        }
    }
}

/// Memory and byte utilities
pub mod memory {
    use crate::{Error, Result};

    // RUDRA-GLUE: read_u64 (no Ghidra counterpart found)
    /// Read a value from bytes with the given endianness
    pub fn read_u64(bytes: &[u8], offset: usize, size: usize, little_endian: bool) -> Result<u64> {
        if offset + size > bytes.len() {
            return Err(Error::Generic(format!(
                "Read out of bounds: offset={}, size={}, len={}",
                offset,
                size,
                bytes.len()
            )));
        }

        let slice = &bytes[offset..offset + size];
        let mut result = 0u64;

        if little_endian {
            for (i, &byte) in slice.iter().enumerate() {
                result |= (byte as u64) << (i * 8);
            }
        } else {
            for (i, &byte) in slice.iter().enumerate() {
                result |= (byte as u64) << ((size - 1 - i) * 8);
            }
        }

        Ok(result)
    }

    // RUDRA-GLUE: align_up (no Ghidra counterpart found)
    /// Align a value up to the given alignment
    pub fn align_up(value: u64, alignment: u64) -> u64 {
        (value + alignment - 1) & !(alignment - 1)
    }

    // RUDRA-GLUE: align_down (no Ghidra counterpart found)
    /// Align a value down to the given alignment
    pub fn align_down(value: u64, alignment: u64) -> u64 {
        value & !(alignment - 1)
    }

    // RUDRA-GLUE: is_aligned (no Ghidra counterpart found)
    /// Check if a value is aligned
    pub fn is_aligned(value: u64, alignment: u64) -> bool {
        value & (alignment - 1) == 0
    }
}

/// Collection utilities
pub mod collections {
    use std::collections::HashMap;
    use std::hash::Hash;

    // RUDRA-GLUE: hash_map_with_capacity (no Ghidra counterpart found)
    /// Create a HashMap with initial capacity
    pub fn hash_map_with_capacity<K, V>(capacity: usize) -> HashMap<K, V>
    where
        K: Eq + Hash,
    {
        HashMap::with_capacity(capacity)
    }

    // RUDRA-GLUE: group_by (no Ghidra counterpart found)
    /// Group items by a key function
    pub fn group_by<T, K, F>(items: Vec<T>, key_fn: F) -> HashMap<K, Vec<T>>
    where
        K: Eq + Hash,
        F: Fn(&T) -> K,
    {
        let mut groups: HashMap<K, Vec<T>> = HashMap::new();
        for item in items {
            let key = key_fn(&item);
            groups.entry(key).or_default().push(item);
        }
        groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bits() {
        let value = 0b11010110u64;
        assert_eq!(bits::extract(value, 0, 2), 0b10);
        assert_eq!(bits::extract(value, 2, 4), 0b0101);
        assert_eq!(bits::extract(value, 4, 4), 0b1101);
    }

    #[test]
    fn test_insert_bits() {
        let value = 0b11111111u64;
        let result = bits::insert(value, 2, 4, 0b0000);
        assert_eq!(result, 0b11000011);
    }

    #[test]
    fn test_sign_extend() {
        // 8-bit: 0xFF = -1
        assert_eq!(bits::sign_extend(0xFF, 8), -1);
        // 8-bit: 0x7F = 127
        assert_eq!(bits::sign_extend(0x7F, 8), 127);
        // 16-bit: 0x8000 = -32768
        assert_eq!(bits::sign_extend(0x8000, 16), -32768);
    }

    #[test]
    fn test_popcount() {
        assert_eq!(bits::popcount(0b11010110), 5);
        assert_eq!(bits::popcount(0), 0);
        assert_eq!(bits::popcount(0xFFFFFFFFFFFFFFFF), 64);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(bits::is_power_of_two(1));
        assert!(bits::is_power_of_two(2));
        assert!(bits::is_power_of_two(4));
        assert!(bits::is_power_of_two(8));
        assert!(!bits::is_power_of_two(0));
        assert!(!bits::is_power_of_two(3));
        assert!(!bits::is_power_of_two(6));
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(bits::next_power_of_two(0), 1);
        assert_eq!(bits::next_power_of_two(1), 1);
        assert_eq!(bits::next_power_of_two(2), 2);
        assert_eq!(bits::next_power_of_two(3), 4);
        assert_eq!(bits::next_power_of_two(5), 8);
        assert_eq!(bits::next_power_of_two(100), 128);
    }

    #[test]
    fn test_hex_bytes() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(format::hex_bytes(&bytes), "de ad be ef");
    }

    #[test]
    fn test_escape_c_string() {
        assert_eq!(format::escape_c_string("hello"), "hello");
        assert_eq!(format::escape_c_string("hello\nworld"), "hello\\nworld");
        assert_eq!(format::escape_c_string("\"quote\""), "\\\"quote\\\"");
        assert_eq!(format::escape_c_string("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn test_make_c_identifier() {
        assert_eq!(format::make_c_identifier("hello"), "hello");
        assert_eq!(format::make_c_identifier("hello-world"), "hello_world");
        assert_eq!(format::make_c_identifier("123abc"), "_123abc");
        assert_eq!(format::make_c_identifier(""), "var");
    }

    #[test]
    fn test_read_u64_little_endian() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let result = memory::read_u64(&bytes, 0, 4, true).unwrap();
        assert_eq!(result, 0x04030201);
    }

    #[test]
    fn test_read_u64_big_endian() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let result = memory::read_u64(&bytes, 0, 4, false).unwrap();
        assert_eq!(result, 0x01020304);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(memory::align_up(0, 4), 0);
        assert_eq!(memory::align_up(1, 4), 4);
        assert_eq!(memory::align_up(4, 4), 4);
        assert_eq!(memory::align_up(5, 4), 8);
        assert_eq!(memory::align_up(100, 16), 112);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(memory::align_down(0, 4), 0);
        assert_eq!(memory::align_down(1, 4), 0);
        assert_eq!(memory::align_down(4, 4), 4);
        assert_eq!(memory::align_down(5, 4), 4);
        assert_eq!(memory::align_down(100, 16), 96);
    }

    #[test]
    fn test_is_aligned() {
        assert!(memory::is_aligned(0, 4));
        assert!(!memory::is_aligned(1, 4));
        assert!(memory::is_aligned(4, 4));
        assert!(!memory::is_aligned(5, 4));
        assert!(memory::is_aligned(16, 16));
    }

    #[test]
    fn test_group_by() {
        let items = vec![1, 2, 3, 4, 5, 6];
        let groups = collections::group_by(items, |x| x % 2);

        assert_eq!(groups[&0], vec![2, 4, 6]);
        assert_eq!(groups[&1], vec![1, 3, 5]);
    }
}
