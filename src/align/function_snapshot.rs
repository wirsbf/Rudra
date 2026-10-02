#![allow(clippy::module_name_repetitions)]

//! Function-level semantic snapshot scaffolding for Rugra-Ghidra alignment.
//!
//! This module provides a **function-oriented, serializable snapshot format**
//! that can be used to compare Rugra and Ghidra at a granularity that is more
//! meaningful than single-instruction checks.
//!
//! The goal of this module is **not** to prove current parity by itself.
//! Instead, it defines the data structures and helper routines needed for a
//! future batch-alignment workflow:
//!
//! 1. Build a [`crate::Funcdata`] for a function
//! 2. Export a [`FunctionSemanticSnapshot`]
//! 3. Export a comparable snapshot from Ghidra
//! 4. Compare the two snapshots in bulk
//! 5. Classify mismatches by semantic layer
//!
//! The snapshot format is intentionally layered:
//!
//! - function identity / metadata
//! - P-code summary
//! - CFG summary
//! - SSA / varnode summary
//! - free-form notes and evidence tags
//!
//! This allows future batch runners to say things like:
//!
//! - “P-code shape matches, CFG differs”
//! - “CFG matches, SSA versions differ”
//! - “Instruction count matches, but opcode sequence diverges”
//!
//! ## Important boundary
//!
//! This module is **scaffolding** for batch alignment. It should be understood
//! as a structured export layer, not as an assertion that Rugra and Ghidra are
//! already aligned at the function level.

use crate::address::{Address, SeqNum};
use crate::block::{BlockEdge, FlowBlock};
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::varnode::{VarnodeDefRef, VarnodeLocRef};
use crate::Funcdata;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Function-level semantic snapshot.
///
/// This is the top-level export object for a single function. It is designed to
/// be serializable so that snapshots can be written to disk, exchanged between
/// tools, or consumed by future batch comparison runners.
///
/// A snapshot is intentionally descriptive rather than prescriptive:
///
/// - it records what Rugra currently observes
/// - it does not claim that those observations are already aligned with Ghidra
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSemanticSnapshot {
    /// Snapshot format version.
    ///
    /// This should be bumped if the schema changes in a way that breaks old
    /// comparison logic or invalidates previously stored JSON artifacts.
    pub schema_version: u32,

    /// Identity and basic function metadata.
    pub function: FunctionIdentitySnapshot,

    /// High-level summary counters for quick batch dashboards.
    pub summary: FunctionSummarySnapshot,

    /// Linearized P-code snapshot.
    pub pcode: PcodeSnapshot,

    /// Control-flow graph snapshot.
    pub cfg: CfgSnapshot,

    /// SSA / varnode summary snapshot.
    pub ssa: SsaSnapshot,

    /// Free-form tags that can be attached by a caller, batch runner, or
    /// future importer.
    pub tags: Vec<String>,

    /// Additional notes for diagnostics, provenance, or temporary bookkeeping.
    pub notes: Vec<String>,
}

impl FunctionSemanticSnapshot {
    /// Current schema version for function semantic snapshots.
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;

    // RUDRA-GLUE: from_funcdata (no Ghidra counterpart found)
    /// Build a snapshot directly from a [`crate::Funcdata`].
    ///
    /// This is the main construction entrypoint for Rugra-side batch alignment
    /// scaffolding. It extracts currently observable function-level state and
    /// packages it into a stable, serializable structure.
    pub fn from_funcdata(func: &Funcdata) -> Self {
        let function = FunctionIdentitySnapshot {
            name: func.name.clone(),
            entry: func.baseaddr,
            size: func.size,
        };

        let pcode_ops = collect_pcode_ops(func);
        let blocks = collect_cfg_blocks(func);
        let ssa_varnodes = collect_ssa_varnodes(func);

        let summary = FunctionSummarySnapshot {
            pcode_op_count: pcode_ops.len(),
            basic_block_count: blocks.len(),
            varnode_count: ssa_varnodes.len(),
            has_symbols: !func.symbol_table.is_empty(),
            has_strings: !func.string_table.is_empty(),
        };

        Self {
            schema_version: Self::CURRENT_SCHEMA_VERSION,
            function,
            summary,
            pcode: PcodeSnapshot { ops: pcode_ops },
            cfg: CfgSnapshot { blocks },
            ssa: SsaSnapshot {
                varnodes: ssa_varnodes,
            },
            tags: Vec::new(),
            notes: Vec::new(),
        }
    }

    // RUDRA-GLUE: with_tag (no Ghidra counterpart found)
    /// Attach a single tag and return the updated snapshot.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    // RUDRA-GLUE: with_note (no Ghidra counterpart found)
    /// Attach a single note and return the updated snapshot.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    // RUDRA-GLUE: to_pretty_json (no Ghidra counterpart found)
    /// Serialize this snapshot to pretty-printed JSON.
    pub fn to_pretty_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    // RUDRA-GLUE: from_json_str (no Ghidra counterpart found)
    /// Parse a snapshot from JSON text.
    pub fn from_json_str(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    // RUDRA-GLUE: write_json_file (no Ghidra counterpart found)
    /// Write this snapshot to a JSON file.
    pub fn write_json_file(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let json = self
            .to_pretty_json()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        fs::write(path, json)
    }

    // RUDRA-GLUE: read_json_file (no Ghidra counterpart found)
    /// Read a snapshot from a JSON file.
    pub fn read_json_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let json = fs::read_to_string(path)?;
        Self::from_json_str(&json)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }
}

/// Identity and coarse metadata for a function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionIdentitySnapshot {
    /// Human-readable function name as currently known to Rugra.
    pub name: String,

    /// Function entry address.
    pub entry: Address,

    /// Function size in bytes, when available in current `Funcdata`.
    pub size: i32,
}

/// High-level counters used for batch dashboards and coarse mismatch triage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSummarySnapshot {
    /// Number of linearized P-code operations currently present.
    pub pcode_op_count: usize,

    /// Number of basic blocks currently visible in the CFG snapshot.
    pub basic_block_count: usize,

    /// Number of varnodes summarized in the SSA layer.
    pub varnode_count: usize,

    /// Whether the function context currently carries symbol metadata.
    pub has_symbols: bool,

    /// Whether the function context currently carries string metadata.
    pub has_strings: bool,
}

/// Full P-code layer snapshot for a function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PcodeSnapshot {
    /// Linearized P-code operations ordered by sequence number.
    pub ops: Vec<PcodeOpSnapshot>,
}

/// Serializable P-code operation snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcodeOpSnapshot {
    /// Sequence number for the P-code operation.
    pub seq: SeqNum,

    /// P-code opcode.
    pub opcode: OpCode,

    /// Output varnode summary, if present.
    pub output: Option<VarnodeSnapshot>,

    /// Input varnode summaries in slot order.
    pub inputs: Vec<VarnodeSnapshot>,
}

/// CFG layer snapshot for a function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CfgSnapshot {
    /// Basic blocks ordered by start address and index.
    pub blocks: Vec<BasicBlockSnapshot>,
}

/// Serializable basic block snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BasicBlockSnapshot {
    /// Block index as currently assigned by Rugra.
    pub index: i32,

    /// Block start address.
    pub start: Address,

    /// Sequence numbers of the operations in this block.
    pub ops: Vec<SeqNum>,

    /// Successor block start addresses.
    pub successors: Vec<Address>,

    /// Predecessor block start addresses.
    pub predecessors: Vec<Address>,
}

/// SSA / varnode layer snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SsaSnapshot {
    /// Summarized varnodes currently known to the function.
    pub varnodes: Vec<SsaVarnodeSnapshot>,
}

/// Serializable SSA-oriented varnode summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsaVarnodeSnapshot {
    /// Storage identity summary.
    pub varnode: VarnodeSnapshot,

    /// SSA version, if currently meaningful in the Rugra-side representation.
    pub version: usize,

    /// Whether this varnode currently looks like a formal input.
    pub is_input: bool,

    /// Whether this varnode currently looks like a written / defined value.
    pub is_written: bool,

    /// Defining operation sequence number, if available.
    pub defining_op: Option<SeqNum>,

    /// Sequence numbers of descendant / use operations.
    pub uses: Vec<SeqNum>,
}

/// Serializable, comparison-friendly varnode snapshot.
///
/// This is intentionally small and stable. It captures the pieces that are most
/// useful for alignment and batch reporting:
///
/// - address space
/// - offset
/// - size
///
/// It does not attempt to serialize every bitflag or every internal helper
/// state on the live `Varnode` object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VarnodeSnapshot {
    /// Address space.
    pub space: AddressSpace,

    /// Offset within the address space.
    pub offset: u64,

    /// Size in bytes.
    pub size: usize,
}

/// High-level semantic layer classification for batch mismatch triage.
///
/// Future comparison code can use this enum to classify which layer of a
/// function disagrees with a Ghidra-side snapshot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SnapshotSemanticLayer {
    /// Function identity / metadata layer.
    Function,

    /// P-code operation layer.
    Pcode,

    /// CFG / block structure layer.
    Cfg,

    /// SSA / varnode layer.
    Ssa,
}

/// A single semantic mismatch record between two function snapshots.
///
/// This struct is intentionally generic so it can be reused by future Rugra-
/// side batch runners and by eventual Rugra-vs-Ghidra comparison tooling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSemanticMismatch {
    /// Function entry address used as the mismatch anchor.
    pub function_entry: Address,

    /// Function name at the time the mismatch was recorded.
    pub function_name: String,

    /// Semantic layer where the mismatch was classified.
    pub layer: SnapshotSemanticLayer,

    /// Short machine-readable mismatch code.
    pub code: String,

    /// Human-readable mismatch details.
    pub details: String,
}

/// Per-function comparison result summary.
///
/// This is a lightweight result shape that future batch runners can emit after
/// comparing a Rugra snapshot with a Ghidra snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionSemanticCompareResult {
    /// Function entry point used as comparison key.
    pub function_entry: Address,

    /// Function name.
    pub function_name: String,

    /// Whether the compared snapshots matched at the currently selected level.
    pub matched: bool,

    /// Collected mismatches.
    pub mismatches: Vec<FunctionSemanticMismatch>,
}

impl FunctionSemanticCompareResult {
    // RUDRA-GLUE: match_result (no Ghidra counterpart found)
    /// Create a successful comparison result.
    pub fn match_result(snapshot: &FunctionSemanticSnapshot) -> Self {
        Self {
            function_entry: snapshot.function.entry,
            function_name: snapshot.function.name.clone(),
            matched: true,
            mismatches: Vec::new(),
        }
    }

    // RUDRA-GLUE: mismatch_result (no Ghidra counterpart found)
    /// Create a mismatch result from collected mismatch records.
    pub fn mismatch_result(
        snapshot: &FunctionSemanticSnapshot,
        mismatches: Vec<FunctionSemanticMismatch>,
    ) -> Self {
        Self {
            function_entry: snapshot.function.entry,
            function_name: snapshot.function.name.clone(),
            matched: false,
            mismatches,
        }
    }

    // RUDRA-GLUE: compare (no Ghidra counterpart found)
    /// Compare two function snapshots and return a per-function comparison result.
    pub fn compare(rugra: &FunctionSemanticSnapshot, reference: &FunctionSemanticSnapshot) -> Self {
        let mismatches = collect_snapshot_mismatches(rugra, reference);

        if mismatches.is_empty() {
            Self::match_result(rugra)
        } else {
            Self::mismatch_result(rugra, mismatches)
        }
    }
}

/// Batch-level result structure for many function comparisons.
///
/// This is scaffolding for future “batch align a corpus of functions against
/// Ghidra” workflows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BatchSemanticCompareReport {
    /// Number of functions compared.
    pub total_functions: usize,

    /// Number of functions that matched at the chosen comparison level.
    pub matched_functions: usize,

    /// Number of functions that produced at least one mismatch.
    pub mismatched_functions: usize,

    /// Per-function comparison results.
    pub results: Vec<FunctionSemanticCompareResult>,
}

impl BatchSemanticCompareReport {
    // RUDRA-GLUE: from_results (no Ghidra counterpart found)
    /// Construct a batch report from per-function results.
    pub fn from_results(results: Vec<FunctionSemanticCompareResult>) -> Self {
        let total_functions = results.len();
        let matched_functions = results.iter().filter(|r| r.matched).count();
        let mismatched_functions = total_functions.saturating_sub(matched_functions);

        Self {
            total_functions,
            matched_functions,
            mismatched_functions,
            results,
        }
    }

    // RUDRA-GLUE: from_rugra_snapshots (no Ghidra counterpart found)
    /// Build a batch report from Rugra-side function snapshots without requiring
    /// a Ghidra-side reference yet.
    ///
    /// Each snapshot is treated as an individual “matched” entry so the report can
    /// already be used as a batch export / inventory artifact before true
    /// cross-tool comparison is wired in.
    pub fn from_rugra_snapshots(snapshots: &[FunctionSemanticSnapshot]) -> Self {
        let results = snapshots
            .iter()
            .map(FunctionSemanticCompareResult::match_result)
            .collect();

        Self::from_results(results)
    }

    // RUDRA-GLUE: to_pretty_json (no Ghidra counterpart found)
    /// Serialize this batch report to pretty-printed JSON.
    pub fn to_pretty_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    // RUDRA-GLUE: from_json_str (no Ghidra counterpart found)
    /// Parse a batch report from JSON text.
    pub fn from_json_str(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }

    // RUDRA-GLUE: write_json_file (no Ghidra counterpart found)
    /// Write this batch report to a JSON file.
    pub fn write_json_file(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let json = self
            .to_pretty_json()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        fs::write(path, json)
    }

    // RUDRA-GLUE: read_json_file (no Ghidra counterpart found)
    /// Read a batch report from a JSON file.
    pub fn read_json_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let json = fs::read_to_string(path)?;
        Self::from_json_str(&json)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    // RUDRA-GLUE: match_rate (no Ghidra counterpart found)
    /// Return the match rate as a percentage in the range `[0.0, 100.0]`.
    pub fn match_rate(&self) -> f64 {
        if self.total_functions == 0 {
            0.0
        } else {
            (self.matched_functions as f64 / self.total_functions as f64) * 100.0
        }
    }

    // RUDRA-GLUE: mismatch_count_by_layer (no Ghidra counterpart found)
    /// Count mismatches by semantic layer.
    pub fn mismatch_count_by_layer(&self) -> BTreeMap<SnapshotSemanticLayer, usize> {
        let mut counts = BTreeMap::new();

        for result in &self.results {
            for mismatch in &result.mismatches {
                *counts.entry(mismatch.layer).or_insert(0) += 1;
            }
        }

        counts
    }
}

impl Ord for SnapshotSemanticLayer {
    // RUDRA-GLUE: cmp (no Ghidra counterpart found)
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl PartialOrd for SnapshotSemanticLayer {
    // RUDRA-GLUE: partial_cmp (no Ghidra counterpart found)
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// RUDRA-GLUE: build_function_snapshots (no Ghidra counterpart found)
/// Build Rugra-side semantic snapshots for a batch of functions.
///
/// This helper is intentionally simple: it just maps each provided
/// [`crate::Funcdata`] to a [`FunctionSemanticSnapshot`]. The resulting vector can
/// later be written to disk, compared against Ghidra-side exports, or wrapped in
/// a [`BatchSemanticCompareReport`].
pub fn build_function_snapshots(funcs: &[Funcdata]) -> Vec<FunctionSemanticSnapshot> {
    funcs
        .iter()
        .map(FunctionSemanticSnapshot::from_funcdata)
        .collect()
}

// RUDRA-GLUE: compare_function_snapshots (no Ghidra counterpart found)
/// Compare a single Rugra-side snapshot against a reference snapshot.
pub fn compare_function_snapshots(
    rugra: &FunctionSemanticSnapshot,
    reference: &FunctionSemanticSnapshot,
) -> FunctionSemanticCompareResult {
    FunctionSemanticCompareResult::compare(rugra, reference)
}

// RUDRA-GLUE: compare_snapshot_batches (no Ghidra counterpart found)
/// Compare Rugra-side snapshots against reference snapshots in batch.
///
/// Snapshots are paired by function entry address. Any Rugra snapshot without a
/// matching reference is reported as a function-layer mismatch. Any reference
/// snapshot without a matching Rugra snapshot is also surfaced as a mismatch
/// entry so the batch report can be used as a real inventory diff, not just a
/// pairwise compare helper.
pub fn compare_snapshot_batches(
    rugra_snapshots: &[FunctionSemanticSnapshot],
    reference_snapshots: &[FunctionSemanticSnapshot],
) -> BatchSemanticCompareReport {
    let rugra_by_entry = rugra_snapshots
        .iter()
        .map(|snapshot| (snapshot.function.entry, snapshot))
        .collect::<BTreeMap<_, _>>();
    let reference_by_entry = reference_snapshots
        .iter()
        .map(|snapshot| (snapshot.function.entry, snapshot))
        .collect::<BTreeMap<_, _>>();

    let all_entries = rugra_by_entry
        .keys()
        .chain(reference_by_entry.keys())
        .copied()
        .collect::<BTreeSet<_>>();

    let mut results = Vec::new();

    for entry in all_entries {
        match (rugra_by_entry.get(&entry), reference_by_entry.get(&entry)) {
            (Some(rugra), Some(reference)) => {
                results.push(compare_function_snapshots(rugra, reference));
            }
            (Some(rugra), None) => {
                results.push(FunctionSemanticCompareResult::mismatch_result(
                    rugra,
                    vec![FunctionSemanticMismatch {
                        function_entry: rugra.function.entry,
                        function_name: rugra.function.name.clone(),
                        layer: SnapshotSemanticLayer::Function,
                        code: "missing_reference_function".to_string(),
                        details: format!(
                            "No reference snapshot was found for function {} at {}",
                            rugra.function.name, rugra.function.entry
                        ),
                    }],
                ));
            }
            (None, Some(reference)) => {
                results.push(FunctionSemanticCompareResult {
                    function_entry: reference.function.entry,
                    function_name: reference.function.name.clone(),
                    matched: false,
                    mismatches: vec![FunctionSemanticMismatch {
                        function_entry: reference.function.entry,
                        function_name: reference.function.name.clone(),
                        layer: SnapshotSemanticLayer::Function,
                        code: "missing_rugra_function".to_string(),
                        details: format!(
                            "No Rugra snapshot was found for function {} at {}",
                            reference.function.name, reference.function.entry
                        ),
                    }],
                });
            }
            (None, None) => {}
        }
    }

    BatchSemanticCompareReport::from_results(results)
}

// RUDRA-GLUE: snapshots_to_pretty_json (no Ghidra counterpart found)
/// Serialize a batch of function snapshots to pretty-printed JSON.
pub fn snapshots_to_pretty_json(
    snapshots: &[FunctionSemanticSnapshot],
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(snapshots)
}

// RUDRA-GLUE: snapshots_from_json_str (no Ghidra counterpart found)
/// Parse a batch of function snapshots from JSON text.
pub fn snapshots_from_json_str(json: &str) -> serde_json::Result<Vec<FunctionSemanticSnapshot>> {
    serde_json::from_str(json)
}

// RUDRA-GLUE: write_snapshots_json_file (no Ghidra counterpart found)
/// Write a batch of function snapshots to a JSON file.
pub fn write_snapshots_json_file(
    snapshots: &[FunctionSemanticSnapshot],
    path: impl AsRef<Path>,
) -> std::io::Result<()> {
    let json = snapshots_to_pretty_json(snapshots)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    fs::write(path, json)
}

// RUDRA-GLUE: read_snapshots_json_file (no Ghidra counterpart found)
/// Read a batch of function snapshots from a JSON file.
pub fn read_snapshots_json_file(
    path: impl AsRef<Path>,
) -> std::io::Result<Vec<FunctionSemanticSnapshot>> {
    let json = fs::read_to_string(path)?;
    snapshots_from_json_str(&json)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

// RUDRA-GLUE: collect_snapshot_mismatches (no Ghidra counterpart found)
fn collect_snapshot_mismatches(
    rugra: &FunctionSemanticSnapshot,
    reference: &FunctionSemanticSnapshot,
) -> Vec<FunctionSemanticMismatch> {
    let mut mismatches = Vec::new();
    let entry = rugra.function.entry;
    let name = &rugra.function.name;

    // --- Function-level checks ---

    if rugra.schema_version != reference.schema_version {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: name.clone(),
            layer: SnapshotSemanticLayer::Function,
            code: "schema_version_mismatch".to_string(),
            details: format!(
                "Schema version differs: Rugra {} vs reference {}",
                rugra.schema_version, reference.schema_version
            ),
        });
    }

    if rugra.function.name != reference.function.name {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: name.clone(),
            layer: SnapshotSemanticLayer::Function,
            code: "function_name_mismatch".to_string(),
            details: format!(
                "Function name differs: Rugra '{}' vs reference '{}'",
                rugra.function.name, reference.function.name
            ),
        });
    }

    if rugra.function.entry != reference.function.entry {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: name.clone(),
            layer: SnapshotSemanticLayer::Function,
            code: "function_entry_mismatch".to_string(),
            details: format!(
                "Function entry differs: Rugra {} vs reference {}",
                rugra.function.entry, reference.function.entry
            ),
        });
    }

    if rugra.function.size != reference.function.size {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: name.clone(),
            layer: SnapshotSemanticLayer::Function,
            code: "function_size_mismatch".to_string(),
            details: format!(
                "Function size differs: Rugra {} vs reference {}",
                rugra.function.size, reference.function.size
            ),
        });
    }

    if rugra.summary != reference.summary {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: name.clone(),
            layer: SnapshotSemanticLayer::Function,
            code: "function_summary_mismatch".to_string(),
            details: format!(
                "Function summary differs: Rugra {:?} vs reference {:?}",
                rugra.summary, reference.summary
            ),
        });
    }

    // --- Fine-grained P-code diff ---
    mismatches.extend(diff_pcode_ops(entry, name, &rugra.pcode, &reference.pcode));

    // --- Fine-grained CFG diff ---
    mismatches.extend(diff_cfg_blocks(entry, name, &rugra.cfg, &reference.cfg));

    // --- Fine-grained SSA diff ---
    mismatches.extend(diff_ssa_varnodes(entry, name, &rugra.ssa, &reference.ssa));

    mismatches
}

// RUDRA-GLUE: diff_pcode_ops (no Ghidra counterpart found)
/// Fine-grained P-code operation diff.
///
/// Compares two P-code snapshots op-by-op. Reports:
/// - Op count mismatch
/// - Per-op opcode mismatch
/// - Per-op output varnode mismatch
/// - Per-op input varnode count or content mismatch
fn diff_pcode_ops(
    entry: Address,
    func_name: &str,
    rugra: &PcodeSnapshot,
    reference: &PcodeSnapshot,
) -> Vec<FunctionSemanticMismatch> {
    let mut mismatches = Vec::new();

    if rugra.ops.len() != reference.ops.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Pcode,
            code: "pcode_op_count_mismatch".to_string(),
            details: format!(
                "P-code op count differs: Rugra {} vs reference {}",
                rugra.ops.len(),
                reference.ops.len()
            ),
        });
    }

    let paired_len = rugra.ops.len().min(reference.ops.len());
    for i in 0..paired_len {
        let r_op = &rugra.ops[i];
        let g_op = &reference.ops[i];

        if r_op.opcode != g_op.opcode {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Pcode,
                code: "pcode_opcode_mismatch".to_string(),
                details: format!(
                    "Op[{}] opcode differs: Rugra {:?} vs reference {:?} (seq: {:?})",
                    i, r_op.opcode, g_op.opcode, r_op.seq
                ),
            });
        }

        if r_op.output != g_op.output {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Pcode,
                code: "pcode_output_mismatch".to_string(),
                details: format!(
                    "Op[{}] output differs: Rugra {:?} vs reference {:?}",
                    i, r_op.output, g_op.output
                ),
            });
        }

        if r_op.inputs.len() != g_op.inputs.len() {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Pcode,
                code: "pcode_input_count_mismatch".to_string(),
                details: format!(
                    "Op[{}] input count differs: Rugra {} vs reference {}",
                    i,
                    r_op.inputs.len(),
                    g_op.inputs.len()
                ),
            });
        } else {
            for (slot, (r_in, g_in)) in r_op.inputs.iter().zip(g_op.inputs.iter()).enumerate() {
                if r_in != g_in {
                    mismatches.push(FunctionSemanticMismatch {
                        function_entry: entry,
                        function_name: func_name.to_string(),
                        layer: SnapshotSemanticLayer::Pcode,
                        code: "pcode_input_varnode_mismatch".to_string(),
                        details: format!(
                            "Op[{}] input[{}] differs: Rugra {:?} vs reference {:?}",
                            i, slot, r_in, g_in
                        ),
                    });
                }
            }
        }
    }

    // Report extra ops as trailing mismatches
    for i in paired_len..rugra.ops.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Pcode,
            code: "pcode_extra_rugra_op".to_string(),
            details: format!(
                "Op[{}] exists only in Rugra: {:?} (seq: {:?})",
                i, rugra.ops[i].opcode, rugra.ops[i].seq
            ),
        });
    }
    for i in paired_len..reference.ops.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Pcode,
            code: "pcode_extra_reference_op".to_string(),
            details: format!(
                "Op[{}] exists only in reference: {:?} (seq: {:?})",
                i, reference.ops[i].opcode, reference.ops[i].seq
            ),
        });
    }

    mismatches
}

// RUDRA-GLUE: diff_cfg_blocks (no Ghidra counterpart found)
/// Fine-grained CFG block diff.
///
/// Compares two CFG snapshots block-by-block. Reports:
/// - Block count mismatch
/// - Per-block start address mismatch
/// - Per-block successor list mismatch
/// - Per-block predecessor list mismatch
/// - Per-block operation sequence mismatch
fn diff_cfg_blocks(
    entry: Address,
    func_name: &str,
    rugra: &CfgSnapshot,
    reference: &CfgSnapshot,
) -> Vec<FunctionSemanticMismatch> {
    let mut mismatches = Vec::new();

    if rugra.blocks.len() != reference.blocks.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Cfg,
            code: "cfg_block_count_mismatch".to_string(),
            details: format!(
                "Block count differs: Rugra {} vs reference {}",
                rugra.blocks.len(),
                reference.blocks.len()
            ),
        });
    }

    let paired_len = rugra.blocks.len().min(reference.blocks.len());
    for i in 0..paired_len {
        let r_blk = &rugra.blocks[i];
        let g_blk = &reference.blocks[i];

        if r_blk.start != g_blk.start {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Cfg,
                code: "cfg_block_start_mismatch".to_string(),
                details: format!(
                    "Block[{}] start address differs: Rugra {} vs reference {}",
                    i, r_blk.start, g_blk.start
                ),
            });
        }

        if r_blk.successors != g_blk.successors {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Cfg,
                code: "cfg_block_successors_mismatch".to_string(),
                details: format!(
                    "Block[{}] successors differ: Rugra {:?} vs reference {:?}",
                    i, r_blk.successors, g_blk.successors
                ),
            });
        }

        if r_blk.predecessors != g_blk.predecessors {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Cfg,
                code: "cfg_block_predecessors_mismatch".to_string(),
                details: format!(
                    "Block[{}] predecessors differ: Rugra {:?} vs reference {:?}",
                    i, r_blk.predecessors, g_blk.predecessors
                ),
            });
        }

        if r_blk.ops.len() != g_blk.ops.len() {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Cfg,
                code: "cfg_block_ops_count_mismatch".to_string(),
                details: format!(
                    "Block[{}] op count differs: Rugra {} vs reference {}",
                    i,
                    r_blk.ops.len(),
                    g_blk.ops.len()
                ),
            });
        }
    }

    for i in paired_len..rugra.blocks.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Cfg,
            code: "cfg_extra_rugra_block".to_string(),
            details: format!(
                "Block[{}] exists only in Rugra: start={}",
                i, rugra.blocks[i].start
            ),
        });
    }
    for i in paired_len..reference.blocks.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Cfg,
            code: "cfg_extra_reference_block".to_string(),
            details: format!(
                "Block[{}] exists only in reference: start={}",
                i, reference.blocks[i].start
            ),
        });
    }

    mismatches
}

// RUDRA-GLUE: diff_ssa_varnodes (no Ghidra counterpart found)
/// Fine-grained SSA varnode diff.
///
/// Compares two SSA snapshots varnode-by-varnode. Reports:
/// - Varnode count mismatch
/// - Per-varnode space/offset/size mismatch
/// - Per-varnode version mismatch
/// - Per-varnode def/use chain mismatch
fn diff_ssa_varnodes(
    entry: Address,
    func_name: &str,
    rugra: &SsaSnapshot,
    reference: &SsaSnapshot,
) -> Vec<FunctionSemanticMismatch> {
    let mut mismatches = Vec::new();

    if rugra.varnodes.len() != reference.varnodes.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Ssa,
            code: "ssa_varnode_count_mismatch".to_string(),
            details: format!(
                "Varnode count differs: Rugra {} vs reference {}",
                rugra.varnodes.len(),
                reference.varnodes.len()
            ),
        });
    }

    let paired_len = rugra.varnodes.len().min(reference.varnodes.len());
    for i in 0..paired_len {
        let r_vn = &rugra.varnodes[i];
        let g_vn = &reference.varnodes[i];

        if r_vn.varnode != g_vn.varnode {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Ssa,
                code: "ssa_varnode_identity_mismatch".to_string(),
                details: format!(
                    "Varnode[{}] identity differs: Rugra {:?} vs reference {:?}",
                    i, r_vn.varnode, g_vn.varnode
                ),
            });
        }

        if r_vn.version != g_vn.version {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Ssa,
                code: "ssa_version_mismatch".to_string(),
                details: format!(
                    "Varnode[{}] ({:?}) version differs: Rugra {} vs reference {}",
                    i, r_vn.varnode, r_vn.version, g_vn.version
                ),
            });
        }

        if r_vn.is_input != g_vn.is_input {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Ssa,
                code: "ssa_input_flag_mismatch".to_string(),
                details: format!(
                    "Varnode[{}] is_input differs: Rugra {} vs reference {}",
                    i, r_vn.is_input, g_vn.is_input
                ),
            });
        }

        if r_vn.is_written != g_vn.is_written {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Ssa,
                code: "ssa_written_flag_mismatch".to_string(),
                details: format!(
                    "Varnode[{}] is_written differs: Rugra {} vs reference {}",
                    i, r_vn.is_written, g_vn.is_written
                ),
            });
        }

        if r_vn.defining_op != g_vn.defining_op {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Ssa,
                code: "ssa_defining_op_mismatch".to_string(),
                details: format!(
                    "Varnode[{}] defining_op differs: Rugra {:?} vs reference {:?}",
                    i, r_vn.defining_op, g_vn.defining_op
                ),
            });
        }

        if r_vn.uses != g_vn.uses {
            mismatches.push(FunctionSemanticMismatch {
                function_entry: entry,
                function_name: func_name.to_string(),
                layer: SnapshotSemanticLayer::Ssa,
                code: "ssa_uses_mismatch".to_string(),
                details: format!(
                    "Varnode[{}] uses differ: Rugra {:?} vs reference {:?}",
                    i, r_vn.uses, g_vn.uses
                ),
            });
        }
    }

    for i in paired_len..rugra.varnodes.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Ssa,
            code: "ssa_extra_rugra_varnode".to_string(),
            details: format!(
                "Varnode[{}] exists only in Rugra: {:?}",
                i, rugra.varnodes[i].varnode
            ),
        });
    }
    for i in paired_len..reference.varnodes.len() {
        mismatches.push(FunctionSemanticMismatch {
            function_entry: entry,
            function_name: func_name.to_string(),
            layer: SnapshotSemanticLayer::Ssa,
            code: "ssa_extra_reference_varnode".to_string(),
            details: format!(
                "Varnode[{}] exists only in reference: {:?}",
                i, reference.varnodes[i].varnode
            ),
        });
    }

    mismatches
}

// RUDRA-GLUE: collect_pcode_ops (no Ghidra counterpart found)
fn collect_pcode_ops(func: &Funcdata) -> Vec<PcodeOpSnapshot> {
    let mut ops: Vec<PcodeOpSnapshot> = func
        .obank
        .optree
        .iter()
        .map(|op_ref| {
            let op = op_ref.0.read().unwrap();

            let output = op.get_out().map(|vn_ref| {
                let vn = vn_ref.read().unwrap();
                VarnodeSnapshot {
                    space: vn.space(),
                    offset: vn.offset(),
                    size: vn.size(),
                }
            });

            let inputs = (0..op.num_input())
                .filter_map(|idx| {
                    op.get_in(idx).map(|vn_ref| {
                        let vn = vn_ref.read().unwrap();
                        VarnodeSnapshot {
                            space: vn.space(),
                            offset: vn.offset(),
                            size: vn.size(),
                        }
                    })
                })
                .collect();

            PcodeOpSnapshot {
                seq: *op.get_seq_num(),
                opcode: op.get_opcode(),
                output,
                inputs,
            }
        })
        .collect();

    ops.sort_by_key(|op| op.seq);
    ops
}

// RUDRA-GLUE: collect_cfg_blocks (no Ghidra counterpart found)
fn collect_cfg_blocks(func: &Funcdata) -> Vec<BasicBlockSnapshot> {
    let mut blocks = Vec::new();

    for block_ref in &func.bblocks.blocks {
        let block = block_ref.read().unwrap();

        let ops = block
            .get_ops()
            .iter()
            .map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                *op.get_seq_num()
            })
            .collect::<Vec<_>>();

        let successors = collect_block_edge_starts(&*block, false);
        let predecessors = collect_block_edge_starts(&*block, true);

        blocks.push(BasicBlockSnapshot {
            index: block.get_index(),
            start: block.get_start_addr(),
            ops,
            successors,
            predecessors,
        });
    }

    blocks.sort_by_key(|b| (b.start, b.index));
    blocks
}

// RUDRA-GLUE: collect_block_edge_starts (no Ghidra counterpart found)
fn collect_block_edge_starts(block: &dyn FlowBlock, incoming: bool) -> Vec<Address> {
    let size = if incoming {
        block.size_in()
    } else {
        block.size_out()
    };

    let mut addrs = Vec::new();
    for idx in 0..size {
        let edge = if incoming {
            block.get_in(idx)
        } else {
            block.get_out(idx)
        };

        if let Some(BlockEdge { point, .. }) = edge {
            let bank = block
                .owner_bank()
                .expect("collect_block_edge_starts on unregistered block");
            addrs.push(bank.expect_arc(point).read().unwrap().get_start_addr());
        }
    }

    addrs.sort();
    addrs.dedup();
    addrs
}

// RUDRA-GLUE: collect_ssa_varnodes (no Ghidra counterpart found)
fn collect_ssa_varnodes(func: &Funcdata) -> Vec<SsaVarnodeSnapshot> {
    let mut seen_keys = BTreeSet::new();
    let mut snapshots = Vec::new();

    for vn_ref in iter_unique_varnodes(func) {
        let vn = vn_ref.read().unwrap();
        let key = (vn.space().space_id(), vn.offset(), vn.size(), vn.version());

        if !seen_keys.insert(key) {
            continue;
        }

        let defining_op = vn.def.as_ref().and_then(|def| def.upgrade()).map(|op_ref| {
            let op = op_ref.read().unwrap();
            *op.get_seq_num()
        });

        let mut uses = vn
            .descend
            .iter()
            .filter_map(|use_ref| use_ref.upgrade())
            .map(|op_ref| {
                let op = op_ref.read().unwrap();
                *op.get_seq_num()
            })
            .collect::<Vec<_>>();

        uses.sort();
        uses.dedup();

        snapshots.push(SsaVarnodeSnapshot {
            varnode: VarnodeSnapshot {
                space: vn.space(),
                offset: vn.offset(),
                size: vn.size(),
            },
            version: vn.version(),
            is_input: vn.is_input(),
            is_written: vn.is_written(),
            defining_op,
            uses,
        });
    }

    snapshots.sort_by_key(|v| {
        (
            v.varnode.space.space_id(),
            v.varnode.offset,
            v.varnode.size,
            v.version,
        )
    });

    snapshots
}

// RUDRA-GLUE: iter_unique_varnodes (no Ghidra counterpart found)
fn iter_unique_varnodes(func: &Funcdata) -> Vec<Arc<RwLock<crate::varnode::Varnode>>> {
    let mut seen_ptrs = BTreeSet::new();
    let mut result = Vec::new();

    for VarnodeLocRef(vn_ref) in func.vbank.begin_loc() {
        let ptr = Arc::as_ptr(vn_ref) as *const () as usize;
        if seen_ptrs.insert(ptr) {
            result.push(vn_ref.clone());
        }
    }

    for VarnodeDefRef(vn_ref) in func.vbank.begin_def() {
        let ptr = Arc::as_ptr(vn_ref) as *const () as usize;
        if seen_ptrs.insert(ptr) {
            result.push(vn_ref.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};

    #[test]
    fn test_snapshot_from_funcdata_basic() {
        let mut fd = Funcdata::new("snap_test", Address::new(0x1000), 4);

        let mut raw = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        raw.set_seq_num(SeqNum::new(Address::new(0x1000), 0));
        raw.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        raw.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8));

        fd.inject_raw_ops(&[raw]);

        let snap = FunctionSemanticSnapshot::from_funcdata(&fd);

        assert_eq!(
            snap.schema_version,
            FunctionSemanticSnapshot::CURRENT_SCHEMA_VERSION
        );
        assert_eq!(snap.function.name, "snap_test");
        assert_eq!(snap.function.entry, Address::new(0x1000));
        assert_eq!(snap.summary.pcode_op_count, 1);
        assert_eq!(snap.summary.basic_block_count, 1);
        assert_eq!(snap.pcode.ops.len(), 1);
        assert_eq!(snap.pcode.ops[0].opcode, OpCode::CPUI_COPY);
        assert_eq!(snap.ssa.varnodes.len(), 2);
    }

    #[test]
    fn test_batch_report_counts() {
        let snapshot = FunctionSemanticSnapshot {
            schema_version: 1,
            function: FunctionIdentitySnapshot {
                name: "f".to_string(),
                entry: Address::new(0x1000),
                size: 1,
            },
            summary: FunctionSummarySnapshot {
                pcode_op_count: 0,
                basic_block_count: 0,
                varnode_count: 0,
                has_symbols: false,
                has_strings: false,
            },
            pcode: PcodeSnapshot::default(),
            cfg: CfgSnapshot::default(),
            ssa: SsaSnapshot::default(),
            tags: Vec::new(),
            notes: Vec::new(),
        };

        let ok = FunctionSemanticCompareResult::match_result(&snapshot);
        let bad = FunctionSemanticCompareResult::mismatch_result(
            &snapshot,
            vec![FunctionSemanticMismatch {
                function_entry: Address::new(0x1000),
                function_name: "f".to_string(),
                layer: SnapshotSemanticLayer::Pcode,
                code: "opcode_mismatch".to_string(),
                details: "example".to_string(),
            }],
        );

        let report = BatchSemanticCompareReport::from_results(vec![ok, bad]);

        assert_eq!(report.total_functions, 2);
        assert_eq!(report.matched_functions, 1);
        assert_eq!(report.mismatched_functions, 1);
        assert!((report.match_rate() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compare_function_snapshots_match() {
        let snapshot = FunctionSemanticSnapshot {
            schema_version: 1,
            function: FunctionIdentitySnapshot {
                name: "cmp_ok".to_string(),
                entry: Address::new(0x3000),
                size: 4,
            },
            summary: FunctionSummarySnapshot {
                pcode_op_count: 1,
                basic_block_count: 1,
                varnode_count: 2,
                has_symbols: false,
                has_strings: false,
            },
            pcode: PcodeSnapshot {
                ops: vec![PcodeOpSnapshot {
                    seq: SeqNum::new(Address::new(0x3000), 0),
                    opcode: OpCode::CPUI_COPY,
                    output: Some(VarnodeSnapshot {
                        space: AddressSpace::Register,
                        offset: 0x00,
                        size: 8,
                    }),
                    inputs: vec![VarnodeSnapshot {
                        space: AddressSpace::Register,
                        offset: 0x18,
                        size: 8,
                    }],
                }],
            },
            cfg: CfgSnapshot {
                blocks: vec![BasicBlockSnapshot {
                    index: 0,
                    start: Address::new(0x3000),
                    ops: vec![SeqNum::new(Address::new(0x3000), 0)],
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                }],
            },
            ssa: SsaSnapshot {
                varnodes: vec![
                    SsaVarnodeSnapshot {
                        varnode: VarnodeSnapshot {
                            space: AddressSpace::Register,
                            offset: 0x00,
                            size: 8,
                        },
                        version: 0,
                        is_input: false,
                        is_written: true,
                        defining_op: Some(SeqNum::new(Address::new(0x3000), 0)),
                        uses: Vec::new(),
                    },
                    SsaVarnodeSnapshot {
                        varnode: VarnodeSnapshot {
                            space: AddressSpace::Register,
                            offset: 0x18,
                            size: 8,
                        },
                        version: 0,
                        is_input: true,
                        is_written: false,
                        defining_op: None,
                        uses: vec![SeqNum::new(Address::new(0x3000), 0)],
                    },
                ],
            },
            tags: vec!["rugra".to_string()],
            notes: vec!["match".to_string()],
        };

        let result = compare_function_snapshots(&snapshot, &snapshot);

        assert!(result.matched);
        assert!(result.mismatches.is_empty());
    }

    #[test]
    fn test_compare_function_snapshots_detects_layered_mismatches() {
        let rugra = FunctionSemanticSnapshot {
            schema_version: 1,
            function: FunctionIdentitySnapshot {
                name: "cmp_bad".to_string(),
                entry: Address::new(0x4000),
                size: 4,
            },
            summary: FunctionSummarySnapshot {
                pcode_op_count: 1,
                basic_block_count: 1,
                varnode_count: 1,
                has_symbols: false,
                has_strings: false,
            },
            pcode: PcodeSnapshot {
                ops: vec![PcodeOpSnapshot {
                    seq: SeqNum::new(Address::new(0x4000), 0),
                    opcode: OpCode::CPUI_COPY,
                    output: None,
                    inputs: Vec::new(),
                }],
            },
            cfg: CfgSnapshot {
                blocks: vec![BasicBlockSnapshot {
                    index: 0,
                    start: Address::new(0x4000),
                    ops: vec![SeqNum::new(Address::new(0x4000), 0)],
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                }],
            },
            ssa: SsaSnapshot {
                varnodes: vec![SsaVarnodeSnapshot {
                    varnode: VarnodeSnapshot {
                        space: AddressSpace::Register,
                        offset: 0x00,
                        size: 8,
                    },
                    version: 0,
                    is_input: true,
                    is_written: false,
                    defining_op: None,
                    uses: Vec::new(),
                }],
            },
            tags: Vec::new(),
            notes: Vec::new(),
        };

        let reference = FunctionSemanticSnapshot {
            schema_version: 2,
            function: FunctionIdentitySnapshot {
                name: "cmp_bad_ref".to_string(),
                entry: Address::new(0x4000),
                size: 8,
            },
            summary: FunctionSummarySnapshot {
                pcode_op_count: 2,
                basic_block_count: 2,
                varnode_count: 2,
                has_symbols: true,
                has_strings: false,
            },
            pcode: PcodeSnapshot {
                ops: vec![PcodeOpSnapshot {
                    seq: SeqNum::new(Address::new(0x4000), 0),
                    opcode: OpCode::CPUI_INT_ADD,
                    output: None,
                    inputs: Vec::new(),
                }],
            },
            cfg: CfgSnapshot {
                blocks: vec![
                    BasicBlockSnapshot {
                        index: 0,
                        start: Address::new(0x4000),
                        ops: vec![SeqNum::new(Address::new(0x4000), 0)],
                        successors: vec![Address::new(0x4010)],
                        predecessors: Vec::new(),
                    },
                    BasicBlockSnapshot {
                        index: 1,
                        start: Address::new(0x4010),
                        ops: Vec::new(),
                        successors: Vec::new(),
                        predecessors: vec![Address::new(0x4000)],
                    },
                ],
            },
            ssa: SsaSnapshot {
                varnodes: vec![
                    SsaVarnodeSnapshot {
                        varnode: VarnodeSnapshot {
                            space: AddressSpace::Register,
                            offset: 0x00,
                            size: 8,
                        },
                        version: 1,
                        is_input: false,
                        is_written: true,
                        defining_op: Some(SeqNum::new(Address::new(0x4000), 0)),
                        uses: Vec::new(),
                    },
                    SsaVarnodeSnapshot {
                        varnode: VarnodeSnapshot {
                            space: AddressSpace::Const,
                            offset: 1,
                            size: 1,
                        },
                        version: 0,
                        is_input: true,
                        is_written: false,
                        defining_op: None,
                        uses: vec![SeqNum::new(Address::new(0x4000), 0)],
                    },
                ],
            },
            tags: Vec::new(),
            notes: Vec::new(),
        };

        let result = compare_function_snapshots(&rugra, &reference);

        assert!(!result.matched);
        assert!(result
            .mismatches
            .iter()
            .any(|m| m.layer == SnapshotSemanticLayer::Function));
        assert!(result
            .mismatches
            .iter()
            .any(|m| m.layer == SnapshotSemanticLayer::Pcode));
        assert!(result
            .mismatches
            .iter()
            .any(|m| m.layer == SnapshotSemanticLayer::Cfg));
        assert!(result
            .mismatches
            .iter()
            .any(|m| m.layer == SnapshotSemanticLayer::Ssa));
    }

    #[test]
    fn test_compare_snapshot_batches_reports_missing_entries() {
        let rugra = FunctionSemanticSnapshot {
            schema_version: 1,
            function: FunctionIdentitySnapshot {
                name: "only_rugra".to_string(),
                entry: Address::new(0x5000),
                size: 4,
            },
            summary: FunctionSummarySnapshot {
                pcode_op_count: 0,
                basic_block_count: 0,
                varnode_count: 0,
                has_symbols: false,
                has_strings: false,
            },
            pcode: PcodeSnapshot::default(),
            cfg: CfgSnapshot::default(),
            ssa: SsaSnapshot::default(),
            tags: Vec::new(),
            notes: Vec::new(),
        };

        let reference = FunctionSemanticSnapshot {
            schema_version: 1,
            function: FunctionIdentitySnapshot {
                name: "only_ref".to_string(),
                entry: Address::new(0x6000),
                size: 4,
            },
            summary: FunctionSummarySnapshot {
                pcode_op_count: 0,
                basic_block_count: 0,
                varnode_count: 0,
                has_symbols: false,
                has_strings: false,
            },
            pcode: PcodeSnapshot::default(),
            cfg: CfgSnapshot::default(),
            ssa: SsaSnapshot::default(),
            tags: Vec::new(),
            notes: Vec::new(),
        };

        let report = compare_snapshot_batches(&[rugra], &[reference]);

        assert_eq!(report.total_functions, 2);
        assert_eq!(report.matched_functions, 0);
        assert_eq!(report.mismatched_functions, 2);
        assert!(report
            .results
            .iter()
            .flat_map(|result| result.mismatches.iter())
            .any(|mismatch| mismatch.code == "missing_reference_function"));
        assert!(report
            .results
            .iter()
            .flat_map(|result| result.mismatches.iter())
            .any(|mismatch| mismatch.code == "missing_rugra_function"));
    }

    #[test]
    fn test_snapshot_json_roundtrip() {
        let snapshot = FunctionSemanticSnapshot {
            schema_version: 1,
            function: FunctionIdentitySnapshot {
                name: "roundtrip".to_string(),
                entry: Address::new(0x2000),
                size: 8,
            },
            summary: FunctionSummarySnapshot {
                pcode_op_count: 1,
                basic_block_count: 1,
                varnode_count: 2,
                has_symbols: false,
                has_strings: false,
            },
            pcode: PcodeSnapshot::default(),
            cfg: CfgSnapshot::default(),
            ssa: SsaSnapshot::default(),
            tags: vec!["rugra".to_string()],
            notes: vec!["example".to_string()],
        };

        let json = snapshot.to_pretty_json().unwrap();
        let decoded = FunctionSemanticSnapshot::from_json_str(&json).unwrap();

        assert_eq!(snapshot, decoded);
    }

    #[test]
    fn test_build_function_snapshots_batch() {
        let fd1 = Funcdata::new("f1", Address::new(0x1000), 4);
        let fd2 = Funcdata::new("f2", Address::new(0x2000), 8);

        let snapshots = build_function_snapshots(&[fd1, fd2]);

        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].function.name, "f1");
        assert_eq!(snapshots[1].function.name, "f2");
    }

    #[test]
    fn test_batch_report_from_rugra_snapshots() {
        let snapshots = vec![
            FunctionSemanticSnapshot {
                schema_version: 1,
                function: FunctionIdentitySnapshot {
                    name: "f1".to_string(),
                    entry: Address::new(0x1000),
                    size: 1,
                },
                summary: FunctionSummarySnapshot {
                    pcode_op_count: 0,
                    basic_block_count: 0,
                    varnode_count: 0,
                    has_symbols: false,
                    has_strings: false,
                },
                pcode: PcodeSnapshot::default(),
                cfg: CfgSnapshot::default(),
                ssa: SsaSnapshot::default(),
                tags: Vec::new(),
                notes: Vec::new(),
            },
            FunctionSemanticSnapshot {
                schema_version: 1,
                function: FunctionIdentitySnapshot {
                    name: "f2".to_string(),
                    entry: Address::new(0x2000),
                    size: 1,
                },
                summary: FunctionSummarySnapshot {
                    pcode_op_count: 0,
                    basic_block_count: 0,
                    varnode_count: 0,
                    has_symbols: false,
                    has_strings: false,
                },
                pcode: PcodeSnapshot::default(),
                cfg: CfgSnapshot::default(),
                ssa: SsaSnapshot::default(),
                tags: Vec::new(),
                notes: Vec::new(),
            },
        ];

        let report = BatchSemanticCompareReport::from_rugra_snapshots(&snapshots);

        assert_eq!(report.total_functions, 2);
        assert_eq!(report.matched_functions, 2);
        assert_eq!(report.mismatched_functions, 0);
    }
}
