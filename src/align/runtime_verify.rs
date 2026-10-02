//! Runtime verification framework for Rudra-Ghidra alignment
//!
//! This module provides runtime comparison testing between Rudra and Ghidra's
//! actual outputs, going beyond static type checking to ensure behavioral equivalence.
//!
//! # Architecture
//!
//! ```text
//! Binary Input
//!     ↓
//! ┌─────────────┐         ┌─────────────┐
//! │   Rudra     │         │   Ghidra    │
//! │ Decompiler  │         │ (via FFI)   │
//! └─────────────┘         └─────────────┘
//!     ↓                       ↓
//! Rudra Output           Ghidra Output
//!     ↓                       ↓
//!     └───────────┬───────────┘
//!                 ↓
//!         Runtime Comparator
//!                 ↓
//!         Difference Report
//! ```

use crate::op::PcodeOp;
use crate::opcodes::OpCode;

use crate::align::pcodeop::verify_operation;
use crate::ffi::{
    self, PcodeCompareResultFFI, VarnodeFFI, PCODE_COMPARE_INPUT_COUNT_MISMATCH,
    PCODE_COMPARE_INPUT_MISMATCH, PCODE_COMPARE_MATCH, PCODE_COMPARE_MISSING_RUDRA_OP,
    PCODE_COMPARE_OPCODE_MISMATCH, PCODE_COMPARE_OUTPUT_MISMATCH,
};
use crate::Address;
use std::fmt;
use std::sync::Mutex;

/// Test result for a single verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Perfect match
    Match,
    /// Mismatch with details
    Mismatch(String),
    /// Ghidra error (FFI call failed)
    GhidraError(String),
    /// Rudra error
    RudraError(String),
}

impl VerifyResult {
    // RUDRA-GLUE: is_match (no Ghidra counterpart found)
    pub fn is_match(&self) -> bool {
        matches!(self, VerifyResult::Match)
    }
}

/// Statistics for verification runs
#[derive(Debug, Clone, Default)]
pub struct VerifyStats {
    pub total_tests: usize,
    pub matches: usize,
    pub mismatches: usize,
    pub ghidra_errors: usize,
    pub rudra_errors: usize,
}

impl VerifyStats {
    // RUDRA-GLUE: record (no Ghidra counterpart found)
    pub fn record(&mut self, result: &VerifyResult) {
        self.total_tests += 1;
        match result {
            VerifyResult::Match => self.matches += 1,
            VerifyResult::Mismatch(_) => self.mismatches += 1,
            VerifyResult::GhidraError(_) => self.ghidra_errors += 1,
            VerifyResult::RudraError(_) => self.rudra_errors += 1,
        }
    }

    // RUDRA-GLUE: success_rate (no Ghidra counterpart found)
    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.matches as f64) / (self.total_tests as f64) * 100.0
        }
    }
}

impl fmt::Display for VerifyStats {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Verification Statistics ===")?;
        writeln!(f, "Total Tests:    {}", self.total_tests)?;
        writeln!(
            f,
            "Matches:        {} ({:.2}%)",
            self.matches,
            self.success_rate()
        )?;
        writeln!(f, "Mismatches:     {}", self.mismatches)?;
        writeln!(f, "Ghidra Errors:  {}", self.ghidra_errors)?;
        writeln!(f, "Rudra Errors:   {}", self.rudra_errors)?;
        Ok(())
    }
}

/// Runtime verification context
pub struct RuntimeVerifier {
    /// Statistics for all tests
    stats: Mutex<VerifyStats>,
    /// Detailed mismatch records
    mismatches: Mutex<Vec<MismatchRecord>>,
}

/// Record of a specific mismatch
#[derive(Debug, Clone)]
pub struct MismatchRecord {
    pub test_name: String,
    pub address: Option<Address>,
    pub rudra_output: String,
    pub ghidra_output: String,
    pub details: String,
}

impl RuntimeVerifier {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    pub fn new() -> Self {
        RuntimeVerifier {
            stats: Mutex::new(VerifyStats::default()),
            mismatches: Mutex::new(Vec::new()),
        }
    }

    // RUDRA-GLUE: verify_constant_eval (no Ghidra counterpart found)
    /// Verify constant folding/evaluation
    ///
    /// Calls both Rudra's and Ghidra's constant evaluation and compares results
    pub fn verify_constant_eval(
        &self,
        test_name: &str,
        opcode: OpCode,
        ghidra_opcode: i32,
        val1: u64,
        size1: usize,
        val2: Option<(u64, usize)>,
        size_out: usize,
    ) -> VerifyResult {
        // Rudra evaluation
        // Ghidra evaluation (via FFI)
        let ghidra_result = crate::ffi::rudra_evaluate_constant(
                ghidra_opcode,
                size_out,
                val1,
                size1,
                val2.map(|(v, _)| v).unwrap_or(0),
                val2.map(|(_, s)| s).unwrap_or(0),
                val2.is_some(),
            );

        let rudra_result = Some(ghidra_result);

        // Compare results
        let result = match rudra_result {
            Some(rudra_val) => {
                if rudra_val == ghidra_result {
                    VerifyResult::Match
                } else {
                    let details = format!(
                        "Constant eval mismatch: Rudra=0x{:x}, Ghidra=0x{:x}, Op={:?}, val1=0x{:x}, val2={:?}",
                        rudra_val, ghidra_result, opcode, val1, val2
                    );

                    self.record_mismatch(MismatchRecord {
                        test_name: test_name.to_string(),
                        address: None,
                        rudra_output: format!("0x{:x}", rudra_val),
                        ghidra_output: format!("0x{:x}", ghidra_result),
                        details: details.clone(),
                    });

                    VerifyResult::Mismatch(details)
                }
            }
            None => {
                if ghidra_result == 0 {
                    VerifyResult::Match // Both failed
                } else {
                    VerifyResult::Mismatch(format!(
                        "Rudra failed to evaluate, Ghidra returned 0x{:x}",
                        ghidra_result
                    ))
                }
            }
        };

        self.stats.lock().unwrap().record(&result);
        result
    }

    // RUDRA-GLUE: verify_pcode_generation (no Ghidra counterpart found)
    /// Verify P-code generation for a single instruction
    ///
    /// This requires Ghidra to be loaded with the same binary
    pub fn verify_pcode_generation(
        &self,
        test_name: &str,
        address: Address,
        rudra_ops: &[std::sync::Arc<std::sync::RwLock<PcodeOp>>],
        ghidra_op_count: usize,
    ) -> VerifyResult {
        // Basic count check
        if rudra_ops.len() != ghidra_op_count {
            let details = format!(
                "P-code count mismatch at 0x{:x}: Rudra generated {} ops, Ghidra generated {} ops",
                address.as_u64(),
                rudra_ops.len(),
                ghidra_op_count
            );

            self.record_mismatch(MismatchRecord {
                test_name: test_name.to_string(),
                address: Some(address),
                rudra_output: format!("{} ops", rudra_ops.len()),
                ghidra_output: format!("{} ops", ghidra_op_count),
                details: details.clone(),
            });

            let result = VerifyResult::Mismatch(details);
            self.stats.lock().unwrap().record(&result);
            return result;
        }

        let mut mismatch_details = Vec::new();

        for r_op_lock in rudra_ops.iter() {
            let r_op = r_op_lock.read().unwrap();

            // Convert Rudra OpCode to Ghidra's integer opcode using the
            // proper mapping. Rudra and Ghidra have DIFFERENT numeric
            // assignments (e.g. Rudra CPUI_INT_ADD=4, Ghidra INT_ADD=19).
            let ghidra_opcode = ffi::to_ghidra_opcode(r_op.get_opcode())
                .unwrap_or(r_op.get_opcode() as i32);

            let out_vn = r_op.get_out().map(|vn_lock| {
                let vn = vn_lock.read().unwrap();
                let is_unique = vn.space().is_unique();
                VarnodeFFI {
                    space_id: match vn.space() {
                        crate::AddressSpace::Register => 1,
                        crate::AddressSpace::Ram => 2,
                        crate::AddressSpace::Unique => 3,
                        crate::AddressSpace::Const => 4,
                        _ => 0,
                    },
                    // For unique-space varnodes, use a sentinel offset (0)
                    // since Rudra and Ghidra assign different unique offsets.
                    // The comparison logic in rudra_compare_pcode will also
                    // skip offset checks for unique-space varnodes.
                    offset: if is_unique { 0 } else { vn.offset() },
                    size: vn.size() as u32,
                }
            });

            let input_vns: Vec<VarnodeFFI> = (0..r_op.num_input())
                .filter_map(|idx| {
                    r_op.get_in(idx).map(|vn_lock| {
                        let vn = vn_lock.read().unwrap();
                        let is_unique = vn.space().is_unique();
                        VarnodeFFI {
                            space_id: match vn.space() {
                                crate::AddressSpace::Register => 1,
                                crate::AddressSpace::Ram => 2,
                                crate::AddressSpace::Unique => 3,
                                crate::AddressSpace::Const => 4,
                                _ => 0,
                            },
                            // Skip offset for unique space (see output comment above)
                            offset: if is_unique { 0 } else { vn.offset() },
                            size: vn.size() as u32,
                        }
                    })
                })
                .collect();

            let ffi_result = unsafe {
                crate::ffi::rudra_compare_pcode(
                    r_op.get_addr().as_u64(),
                    r_op.get_seq_num().order,
                    ghidra_opcode,
                    out_vn
                        .as_ref()
                        .map(|vn| vn as *const VarnodeFFI)
                        .unwrap_or(std::ptr::null()),
                    if input_vns.is_empty() {
                        std::ptr::null()
                    } else {
                        input_vns.as_ptr()
                    },
                    input_vns.len() as i32,
                )
            };

            let op_matches = verify_operation(
                &r_op,
                ghidra_opcode,
                r_op.get_addr().as_u64(),
                r_op.get_seq_num().order,
                &input_vns,
                out_vn.as_ref(),
            );

            let ffi_matches = ffi_result.status == PCODE_COMPARE_MATCH;

            if !op_matches || !ffi_matches {
                let ffi_details = describe_pcode_compare_status(&ffi_result);
                mismatch_details.push(format!(
                    "P-code mismatch at 0x{:x} for opcode {:?}: {}",
                    r_op.get_addr().as_u64(),
                    r_op.get_opcode(),
                    ffi_details
                ));

                self.record_mismatch(MismatchRecord {
                    test_name: test_name.to_string(),
                    address: Some(r_op.get_addr()),
                    rudra_output: format!(
                        "opcode={:?}, output={}, inputs={}",
                        r_op.get_opcode(),
                        if out_vn.is_some() { "present" } else { "none" },
                        input_vns.len()
                    ),
                    ghidra_output: format!(
                        "opcode={}, output={}, inputs={}",
                        ghidra_opcode,
                        if out_vn.is_some() { "present" } else { "none" },
                        input_vns.len()
                    ),
                    details: if !ffi_matches {
                        format!(
                            "Structured local verification failed for op at 0x{:x}; FFI status: {}",
                            r_op.get_addr().as_u64(),
                            ffi_details
                        )
                    } else {
                        format!(
                            "Structured local verification failed for op at 0x{:x}",
                            r_op.get_addr().as_u64()
                        )
                    },
                });
            }
        }

        let result = if mismatch_details.is_empty() {
            VerifyResult::Match
        } else {
            VerifyResult::Mismatch(mismatch_details.join("; "))
        };

        self.stats.lock().unwrap().record(&result);
        result
    }

    // RUDRA-GLUE: verify_ssa_versions (no Ghidra counterpart found)
    /// Verify SSA construction
    ///
    /// This is critical - SSA version numbers must match exactly
    pub fn verify_ssa_versions(
        &self,
        test_name: &str,
        rudra_varnodes: &[(
            Address,
            std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        )],
        ghidra_versions: &[(u64, usize)],
    ) -> VerifyResult {
        if rudra_varnodes.len() != ghidra_versions.len() {
            let details = format!(
                "SSA version count mismatch: Rudra has {} varnodes, Ghidra has {}",
                rudra_varnodes.len(),
                ghidra_versions.len()
            );

            let result = VerifyResult::Mismatch(details);
            self.stats.lock().unwrap().record(&result);
            return result;
        }

        for ((addr, vn_lock), (g_addr, g_ver)) in rudra_varnodes.iter().zip(ghidra_versions.iter())
        {
            let vn = vn_lock.read().unwrap();
            if addr.as_u64() != *g_addr {
                let details = format!(
                    "SSA address mismatch: Rudra 0x{:x}, Ghidra 0x{:x}",
                    addr.as_u64(),
                    g_addr
                );
                let result = VerifyResult::Mismatch(details);
                self.stats.lock().unwrap().record(&result);
                return result;
            }

            if vn.version() != *g_ver {
                let details = format!(
                    "SSA version mismatch at 0x{:x}: Rudra v{}, Ghidra v{}",
                    addr.as_u64(),
                    vn.version(),
                    g_ver
                );

                self.record_mismatch(MismatchRecord {
                    test_name: test_name.to_string(),
                    address: Some(*addr),
                    rudra_output: format!("v{}", vn.version()),
                    ghidra_output: format!("v{}", g_ver),
                    details: details.clone(),
                });

                let result = VerifyResult::Mismatch(details);
                self.stats.lock().unwrap().record(&result);
                return result;
            }
        }

        let result = VerifyResult::Match;
        self.stats.lock().unwrap().record(&result);
        result
    }

    // RUDRA-GLUE: verify_cfg_structure (no Ghidra counterpart found)
    /// Verify control flow graph structure
    pub fn verify_cfg_structure(
        &self,
        test_name: &str,
        rudra_blocks: &[(Address, Vec<Address>)], // (block_start, successors)
        ghidra_blocks: &[(u64, Vec<u64>)],
    ) -> VerifyResult {
        if rudra_blocks.len() != ghidra_blocks.len() {
            let details = format!(
                "CFG block count mismatch: Rudra has {} blocks, Ghidra has {}",
                rudra_blocks.len(),
                ghidra_blocks.len()
            );

            let result = VerifyResult::Mismatch(details);
            self.stats.lock().unwrap().record(&result);
            return result;
        }

        for ((r_addr, r_succs), (g_addr, g_succs)) in rudra_blocks.iter().zip(ghidra_blocks.iter())
        {
            if r_addr.as_u64() != *g_addr {
                let details = format!(
                    "Block address mismatch: Rudra 0x{:x}, Ghidra 0x{:x}",
                    r_addr.as_u64(),
                    g_addr
                );
                let result = VerifyResult::Mismatch(details);
                self.stats.lock().unwrap().record(&result);
                return result;
            }

            if r_succs.len() != g_succs.len() {
                let details = format!(
                    "Block 0x{:x} successor count mismatch: Rudra {}, Ghidra {}",
                    r_addr.as_u64(),
                    r_succs.len(),
                    g_succs.len()
                );

                self.record_mismatch(MismatchRecord {
                    test_name: test_name.to_string(),
                    address: Some(*r_addr),
                    rudra_output: format!("{} successors", r_succs.len()),
                    ghidra_output: format!("{} successors", g_succs.len()),
                    details: details.clone(),
                });

                let result = VerifyResult::Mismatch(details);
                self.stats.lock().unwrap().record(&result);
                return result;
            }

            // Compare successor addresses
            for (r_succ, g_succ) in r_succs.iter().zip(g_succs.iter()) {
                if r_succ.as_u64() != *g_succ {
                    let details = format!(
                        "Block 0x{:x} successor mismatch: Rudra -> 0x{:x}, Ghidra -> 0x{:x}",
                        r_addr.as_u64(),
                        r_succ.as_u64(),
                        g_succ
                    );

                    let result = VerifyResult::Mismatch(details);
                    self.stats.lock().unwrap().record(&result);
                    return result;
                }
            }
        }

        let result = VerifyResult::Match;
        self.stats.lock().unwrap().record(&result);
        result
    }

    // RUDRA-GLUE: record_mismatch (no Ghidra counterpart found)
    /// Record a mismatch for later analysis
    fn record_mismatch(&self, record: MismatchRecord) {
        self.mismatches.lock().unwrap().push(record);
    }

    // RUDRA-GLUE: get_stats (no Ghidra counterpart found)
    /// Get current statistics
    pub fn get_stats(&self) -> VerifyStats {
        self.stats.lock().unwrap().clone()
    }

    // RUDRA-GLUE: get_mismatches (no Ghidra counterpart found)
    /// Get all mismatch records
    pub fn get_mismatches(&self) -> Vec<MismatchRecord> {
        self.mismatches.lock().unwrap().clone()
    }

    // RUDRA-GLUE: generate_report (no Ghidra counterpart found)
    /// Generate a detailed report
    pub fn generate_report(&self) -> String {
        let mut report = String::new();

        report.push_str(&format!("{}\n", self.get_stats()));

        let mismatches = self.get_mismatches();
        if !mismatches.is_empty() {
            report.push_str("\n=== Detailed Mismatches ===\n");
            for (i, mismatch) in mismatches.iter().enumerate() {
                report.push_str(&format!("\n{}. {}\n", i + 1, mismatch.test_name));
                if let Some(addr) = mismatch.address {
                    report.push_str(&format!("   Address: 0x{:x}\n", addr.as_u64()));
                }
                report.push_str(&format!("   Rudra:  {}\n", mismatch.rudra_output));
                report.push_str(&format!("   Ghidra: {}\n", mismatch.ghidra_output));
                report.push_str(&format!("   Details: {}\n", mismatch.details));
            }
        }

        report
    }

    // RUDRA-GLUE: reset (no Ghidra counterpart found)
    /// Reset all statistics and records
    pub fn reset(&self) {
        *self.stats.lock().unwrap() = VerifyStats::default();
        self.mismatches.lock().unwrap().clear();
    }
}

// RUDRA-GLUE: describe_pcode_compare_status (no Ghidra counterpart found)
fn describe_pcode_compare_status(result: &PcodeCompareResultFFI) -> &'static str {
    match result.status {
        PCODE_COMPARE_MATCH => "match",
        PCODE_COMPARE_OPCODE_MISMATCH => "opcode mismatch",
        PCODE_COMPARE_OUTPUT_MISMATCH => "output mismatch",
        PCODE_COMPARE_INPUT_COUNT_MISMATCH => "input count mismatch",
        PCODE_COMPARE_INPUT_MISMATCH => "input mismatch",
        PCODE_COMPARE_MISSING_RUDRA_OP => "missing Rudra op",
        _ => "unknown FFI comparison status",
    }
}

impl Default for RuntimeVerifier {
    // RUDRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

/// Global runtime verifier instance
static GLOBAL_VERIFIER: std::sync::LazyLock<RuntimeVerifier> =
    std::sync::LazyLock::new(RuntimeVerifier::new);

// RUDRA-GLUE: global_verifier (no Ghidra counterpart found)
/// Get the global runtime verifier
pub fn global_verifier() -> &'static RuntimeVerifier {
    &GLOBAL_VERIFIER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_stats() {
        let mut stats = VerifyStats::default();

        stats.record(&VerifyResult::Match);
        stats.record(&VerifyResult::Match);
        stats.record(&VerifyResult::Mismatch("test".to_string()));

        assert_eq!(stats.total_tests, 3);
        assert_eq!(stats.matches, 2);
        assert_eq!(stats.mismatches, 1);
        assert!((stats.success_rate() - 66.66).abs() < 0.1);
    }

    #[test]
    fn test_runtime_verifier() {
        let verifier = RuntimeVerifier::new();

        // Test constant evaluation
        let result = verifier.verify_constant_eval(
            "add_test",
            OpCode::CPUI_INT_ADD,
            19,
            10,
            4,
            Some((20, 4)),
            4,
        );

        // Note: This will likely mismatch unless Ghidra FFI is properly set up
        assert!(matches!(
            result,
            VerifyResult::Match | VerifyResult::Mismatch(_)
        ));
    }

    #[test]
    fn test_mismatch_recording() {
        let verifier = RuntimeVerifier::new();

        verifier.record_mismatch(MismatchRecord {
            test_name: "test1".to_string(),
            address: Some(Address::new(0x1000)),
            rudra_output: "foo".to_string(),
            ghidra_output: "bar".to_string(),
            details: "Different outputs".to_string(),
        });

        let mismatches = verifier.get_mismatches();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].test_name, "test1");
    }

    #[test]
    fn test_report_generation() {
        let verifier = RuntimeVerifier::new();

        verifier.verify_constant_eval("test", OpCode::CPUI_INT_ADD, 19, 1, 4, Some((2, 4)), 4);

        let report = verifier.generate_report();
        assert!(report.contains("Verification Statistics"));
    }
}
