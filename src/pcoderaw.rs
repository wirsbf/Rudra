//! Raw P-code operations
//!
//! This module corresponds to Ghidra's `pcoderaw.hh` and provides raw
//! P-code operation structures used during initial translation before
//! full P-code generation.
//!
//! # Overview
//!
//! PcodeOpRaw represents a P-code operation in its initial, unprocessed form.
//! It's used by the SLEIGH translator before operations are fully constructed
//! and added to the function's P-code representation.

use crate::address::{Address, SeqNum};
use crate::space::AddressSpace;
use crate::varnode::VarnodeData;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Raw varnode data (before full Varnode construction)
///
/// Simplified representation used during P-code translation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VarnodeRaw {
    /// Address space
    pub space: AddressSpace,
    /// Offset within the space
    pub offset: u64,
    /// Size in bytes
    pub size: usize,
}

impl VarnodeRaw {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Create a new raw varnode
    pub fn new(space: AddressSpace, offset: u64, size: usize) -> Self {
        VarnodeRaw {
            space,
            offset,
            size,
        }
    }

    // RUDRA-GLUE: to_varnode_data (no Ghidra counterpart found)
    /// Convert to VarnodeData
    pub fn to_varnode_data(&self) -> VarnodeData {
        VarnodeData::new(self.space, self.offset, self.size)
    }
}

impl fmt::Display for VarnodeRaw {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:0x{:x}:{}", self.space, self.offset, self.size)
    }
}

/// Raw P-code operation
///
/// Corresponds to Ghidra's `PcodeOpRaw` class in pcoderaw.hh
///
/// This represents a P-code operation during the translation phase,
/// before it's fully constructed and added to the function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeOpRaw {
    /// Operation code (as integer, matching Ghidra opcodes)
    opcode: i32,
    /// Output varnode (if any)
    output: Option<VarnodeRaw>,
    /// Input varnodes
    inputs: Vec<VarnodeRaw>,
    /// Sequence number
    seqnum: Option<SeqNum>,
    /// Behavior flags
    behavior: u32,
}

impl PcodeOpRaw {
    // Ghidra: pcoderaw.hh:110 PcodeOpRaw::new
    /// Create a new raw P-code operation
    pub fn new(opcode: i32) -> Self {
        PcodeOpRaw {
            opcode,
            output: None,
            inputs: Vec::new(),
            seqnum: None,
            behavior: 0,
        }
    }

    // Ghidra: pcoderaw.hh:210 PcodeOpRaw::addInput
    /// Add an input varnode
    ///
    /// Corresponds to `addInput` in Ghidra
    pub fn add_input(&mut self, varnode: VarnodeRaw) {
        self.inputs.push(varnode);
    }

    // Ghidra: pcoderaw.hh:218 PcodeOpRaw::clearInputs
    /// Clear all inputs
    ///
    /// Corresponds to `clearInputs` in Ghidra
    pub fn clear_inputs(&mut self) {
        self.inputs.clear();
    }

    // Ghidra: pcoderaw.hh:154 PcodeOpRaw::getOpcode
    /// Get the opcode
    ///
    /// Corresponds to `getOpcode` in Ghidra
    pub fn get_opcode(&self) -> i32 {
        self.opcode
    }

    // RUDRA-GLUE: set_opcode — mutator for the raw-layer FlowOverride
    // transport of `Funcdata::overrideFlow` (funcdata_op.cc:991-1020
    // opSetOpcode table). Ghidra mutates the dead PcodeOp in place before
    // block formation; Rugra's injection path rewrites the raw op before
    // `inject_raw_ops` phase-1 creates the PcodeOp, which needs this
    // setter (the builder API only covers whole-op construction).
    pub fn set_opcode(&mut self, opcode: i32) {
        self.opcode = opcode;
    }

    // Ghidra: pcoderaw.hh:225 PcodeOpRaw::numInput
    /// Get the number of inputs
    ///
    /// Corresponds to `numInput` in Ghidra
    pub fn num_input(&self) -> usize {
        self.inputs.len()
    }

    // Ghidra: pcoderaw.hh:110 PcodeOpRaw::inputs
    /// Get the inputs
    pub fn inputs(&self) -> &[VarnodeRaw] {
        &self.inputs
    }

    // Ghidra: pcoderaw.hh:193 PcodeOpRaw::setOutput
    /// Set the output varnode
    ///
    /// Corresponds to `setOutput` in Ghidra
    pub fn set_output(&mut self, varnode: VarnodeRaw) {
        self.output = Some(varnode);
    }

    // Ghidra: pcoderaw.hh:110 PcodeOpRaw::output
    /// Get the output varnode
    pub fn output(&self) -> Option<&VarnodeRaw> {
        self.output.as_ref()
    }

    // Ghidra: pcoderaw.hh:166 PcodeOpRaw::setSeqNum
    /// Set the sequence number
    ///
    /// Corresponds to `setSeqNum` in Ghidra
    pub fn set_seq_num(&mut self, seqnum: SeqNum) {
        self.seqnum = Some(seqnum);
    }

    // Ghidra: pcoderaw.hh:110 PcodeOpRaw::seqNum
    /// Get the sequence number
    pub fn seq_num(&self) -> Option<SeqNum> {
        self.seqnum
    }

    // Ghidra: pcoderaw.hh:136 PcodeOpRaw::setBehavior
    /// Set the behavior flags
    ///
    /// Corresponds to `setBehavior` in Ghidra
    pub fn set_behavior(&mut self, behavior: u32) {
        self.behavior = behavior;
    }

    // Ghidra: pcoderaw.hh:110 PcodeOpRaw::behavior
    /// Get the behavior flags
    pub fn behavior(&self) -> u32 {
        self.behavior
    }

    // Ghidra: pcoderaw.cc:96 PcodeOpRaw::decode
    /// Decode from string format
    ///
    /// Corresponds to `decode` in Ghidra
    ///
    /// Format: "opcode output input1 input2 ..."
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        let opcode = parts[0].parse().ok()?;
        let mut op = PcodeOpRaw::new(opcode);

        // Parse output if present (indicated by "->")
        let mut idx = 1;
        if idx < parts.len() && parts[idx] == "->" {
            idx += 1;
            if idx < parts.len() {
                if let Some(vn) = Self::parse_varnode(parts[idx]) {
                    op.set_output(vn);
                }
                idx += 1;
            }
        }

        // Parse inputs
        while idx < parts.len() {
            if let Some(vn) = Self::parse_varnode(parts[idx]) {
                op.add_input(vn);
            }
            idx += 1;
        }

        Some(op)
    }

    // Ghidra: pcoderaw.hh:110 PcodeOpRaw::parseVarnode
    /// Helper to parse a varnode from string "space:offset:size"
    fn parse_varnode(s: &str) -> Option<VarnodeRaw> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return None;
        }

        let space = match parts[0] {
            "ram" => AddressSpace::Ram,
            "register" => AddressSpace::Register,
            "unique" => AddressSpace::Unique,
            "const" => AddressSpace::Const,
            "stack" => AddressSpace::Stack,
            _ => {
                if let Ok(id) = parts[0].parse() {
                    AddressSpace::Other(id)
                } else {
                    return None;
                }
            }
        };

        let offset = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).ok()?;
        let size = parts[2].parse().ok()?;

        Some(VarnodeRaw::new(space, offset, size))
    }

    // Ghidra: pcoderaw.hh:110 PcodeOpRaw::encode
    /// Encode to string format
    pub fn encode(&self) -> String {
        let mut result = format!("{}", self.opcode);

        if let Some(out) = &self.output {
            result.push_str(&format!(" -> {}", out));
        }

        for input in &self.inputs {
            result.push_str(&format!(" {}", input));
        }

        result
    }
}

impl fmt::Display for PcodeOpRaw {
    // Ghidra: pcoderaw.hh:110 PcodeOpRaw::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PcodeOpRaw[opcode={}]", self.opcode)?;
        if let Some(out) = &self.output {
            write!(f, " -> {}", out)?;
        }
        write!(f, " (")?;
        for (i, input) in self.inputs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", input)?;
        }
        write!(f, ")")
    }
}

/// Builder for PcodeOpRaw
pub struct PcodeOpRawBuilder {
    op: PcodeOpRaw,
}

impl PcodeOpRawBuilder {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Create a new builder
    pub fn new(opcode: i32) -> Self {
        PcodeOpRawBuilder {
            op: PcodeOpRaw::new(opcode),
        }
    }

    // RUDRA-GLUE: output (no Ghidra counterpart found)
    /// Set output
    pub fn output(mut self, space: AddressSpace, offset: u64, size: usize) -> Self {
        self.op.set_output(VarnodeRaw::new(space, offset, size));
        self
    }

    // RUDRA-GLUE: input (no Ghidra counterpart found)
    /// Add input
    pub fn input(mut self, space: AddressSpace, offset: u64, size: usize) -> Self {
        self.op.add_input(VarnodeRaw::new(space, offset, size));
        self
    }

    // RUDRA-GLUE: seq_num (no Ghidra counterpart found)
    /// Set sequence number
    pub fn seq_num(mut self, addr: Address, order: u32) -> Self {
        self.op.set_seq_num(SeqNum::new(addr, order));
        self
    }

    // RUDRA-GLUE: behavior (no Ghidra counterpart found)
    /// Set behavior
    pub fn behavior(mut self, behavior: u32) -> Self {
        self.op.set_behavior(behavior);
        self
    }

    // RUDRA-GLUE: build (no Ghidra counterpart found)
    /// Build the PcodeOpRaw
    pub fn build(self) -> PcodeOpRaw {
        self.op
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_raw_creation() {
        let vn = VarnodeRaw::new(AddressSpace::Register, 0x10, 4);
        assert_eq!(vn.space, AddressSpace::Register);
        assert_eq!(vn.offset, 0x10);
        assert_eq!(vn.size, 4);
    }

    #[test]
    fn test_pcodeop_raw_creation() {
        let op = PcodeOpRaw::new(19); // INT_ADD
        assert_eq!(op.get_opcode(), 19);
        assert_eq!(op.num_input(), 0);
        assert!(op.output.as_ref().is_none());
    }

    #[test]
    fn test_pcodeop_raw_add_input() {
        let mut op = PcodeOpRaw::new(19);
        op.add_input(VarnodeRaw::new(AddressSpace::Register, 0, 4));
        op.add_input(VarnodeRaw::new(AddressSpace::Register, 4, 4));

        assert_eq!(op.num_input(), 2);
        assert_eq!(op.inputs.as_slice()[0].offset, 0);
        assert_eq!(op.inputs.as_slice()[1].offset, 4);
    }

    #[test]
    fn test_pcodeop_raw_clear_inputs() {
        let mut op = PcodeOpRaw::new(19);
        op.add_input(VarnodeRaw::new(AddressSpace::Register, 0, 4));
        op.add_input(VarnodeRaw::new(AddressSpace::Register, 4, 4));
        assert_eq!(op.num_input(), 2);

        op.clear_inputs();
        assert_eq!(op.num_input(), 0);
    }

    #[test]
    fn test_pcodeop_raw_set_output() {
        let mut op = PcodeOpRaw::new(19);
        op.set_output(VarnodeRaw::new(AddressSpace::Register, 8, 4));

        assert!(op.output.as_ref().is_some());
        assert_eq!(op.output.as_ref().unwrap().offset, 8);
    }

    #[test]
    fn test_pcodeop_raw_set_seq_num() {
        let mut op = PcodeOpRaw::new(19);
        op.set_seq_num(SeqNum::new(Address::new(0x1000), 0));

        assert!(op.seq_num().is_some());
        assert_eq!(op.seq_num().unwrap().get_addr().as_u64(), 0x1000);
    }

    #[test]
    fn test_pcodeop_raw_set_behavior() {
        let mut op = PcodeOpRaw::new(19);
        op.set_behavior(0x42);

        assert_eq!(op.behavior(), 0x42);
    }

    #[test]
    fn test_pcodeop_raw_builder() {
        let op = PcodeOpRawBuilder::new(19)
            .output(AddressSpace::Register, 0, 4)
            .input(AddressSpace::Register, 4, 4)
            .input(AddressSpace::Register, 8, 4)
            .seq_num(Address::new(0x1000), 0)
            .behavior(0)
            .build();

        assert_eq!(op.get_opcode(), 19);
        assert_eq!(op.num_input(), 2);
        assert!(op.output.as_ref().is_some());
        assert!(op.seq_num().is_some());
    }

    #[test]
    fn test_pcodeop_raw_decode_encode() {
        let op_str = "19 -> register:0:4 register:4:4 register:8:4";
        let op = PcodeOpRaw::decode(op_str).unwrap();

        assert_eq!(op.get_opcode(), 19);
        assert_eq!(op.num_input(), 2);
        assert!(op.output.as_ref().is_some());

        let encoded = op.encode();
        let decoded = PcodeOpRaw::decode(&encoded).unwrap();
        assert_eq!(decoded.get_opcode(), op.get_opcode());
        assert_eq!(decoded.num_input(), op.num_input());
    }

    #[test]
    fn test_varnode_raw_display() {
        let vn = VarnodeRaw::new(AddressSpace::Register, 0x10, 4);
        let display = format!("{}", vn);
        assert!(display.contains("register"));
        assert!(display.contains("10"));
        assert!(display.contains("4"));
    }

    #[test]
    fn test_pcodeop_raw_display() {
        let mut op = PcodeOpRaw::new(19);
        op.set_output(VarnodeRaw::new(AddressSpace::Register, 0, 4));
        op.add_input(VarnodeRaw::new(AddressSpace::Register, 4, 4));
        op.add_input(VarnodeRaw::new(AddressSpace::Register, 8, 4));

        let display = format!("{}", op);
        assert!(display.contains("PcodeOpRaw"));
        assert!(display.contains("19"));
    }
}
