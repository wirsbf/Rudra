//! Alignment verification module for Rugra and Ghidra.
//!
//! This module contains the logic to verify that Rugra's internal data structures
//! and analysis results match Ghidra's C++ decompiler implementation.
//!
//! # Runtime Verification
//!
//! The `runtime_verify` module provides actual runtime comparison testing between
//! Rugra and Ghidra outputs, going beyond static type checking to ensure behavioral
//! equivalence. This is critical for guaranteeing output consistency.
//!
//! Note: Runtime verification requires `once_cell` dependency in Cargo.toml

pub mod address;
pub mod datatype;
pub mod function_snapshot;
pub mod pcodeop;
pub mod range;
pub mod runtime_verify;
pub mod varnode;

/// Helper trait for objects that can be cross-verified with Ghidra
pub trait AlignmentCheck {
    // RUDRA-GLUE: check_alignment (no Ghidra counterpart found)
    /// Verify that this object is aligned with its Ghidra counterpart
    fn check_alignment(&self) -> bool;
}
pub mod action;
pub mod block;
pub mod heritage;
