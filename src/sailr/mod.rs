//! # sailr — the SAILR enhancement layer (compiler-aware structuring)
//!
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: USENIX 2024 SAILR paper (mahaloz) — angr/analyses/decompiler/structuring + region_identifier.py / kuna p7_regions+p8_structure)
//!
//! **ENHANCEMENT domain — no Ghidra counterpart.**  This module ports the
//! SAILR family of structuring algorithms (RegionIdentifier region
//! splitting + pattern-based loop recovery by compiler rotation +
//! short-circuit `&&`/`||` diamond recovery + switch pattern recognition)
//! as a standalone enhancement layer.  It is **not** wired into the default
//! structuring path: the default face stays the faithful
//! [`crate::blockaction`] port and its alignment discipline is untouched.
//! Phase 2 will expose this as a configurable "enhanced face" behind the
//! integration seam documented in
//! `docs/alignment_docs/SAILR_INTEGRATION_DESIGN_2026-09-26.md`.
//!
//! # Layout
//!
//! * [`graph`] — the mutable deterministic digraph substrate (arena nodes,
//!   `(addr, ident)` global order, DFS utilities, quasi-topological sort,
//!   (incremental) dominators, `subgraph_between_nodes`).
//! * [`region_id`] — the RegionIdentifier port: collapses a private CFG
//!   copy into a nested `GraphRegion` tree, with the refined loop-body /
//!   exit projection (`cyclic_loops`) the structurer consumes.
//! * [`structurer`] — the pattern structurer: schema cascade over a
//!   self-contained working graph, producing the [`structurer::StructuredNode`]
//!   output IR designed to map one-to-one onto the `block.rs` block kinds.
//!
//! # Input seam (Phase 2 adapter points)
//!
//! * `RegionIdentifier::build_from_cfg(blocks, edges, entry)` — drive from
//!   `Funcdata::bblocks` (one node per basic block, `branchy` precomputed
//!   from the tail op).
//! * `Structurer::new(&SailrInput)` — drive from the same CFG plus the
//!   precomputed per-block facts (`complex`/`switch`/`simple_return`),
//!   mirroring the precomputations `ActionBlockStructure` does for
//!   `CollapseStructure`.
//!
//! # Gates
//!
//! * default-face neutrality: the module is dead code to the pipeline
//!   (one `mod` declaration); canon output is byte-identical.
//! * algorithm correctness: unit tests over synthetic compiler-degraded
//!   CFG shapes (loops by rotation, short-circuit diamonds, switches).

pub mod graph;
pub mod region_id;
pub mod structurer;

pub use graph::{
    dfs_back_edges, dfs_postorder_deterministic, immediate_dominators,
    quasi_topological_sort, subgraph_between_nodes, IncrementalDominators, NodeKey, NodeKind,
    NodePool, NodeSet, RegionGraph, RegionId, RegionNodeId,
};
pub use region_id::{CyclicLoop, GraphRegion, RegionIdentifier, RegionVisitor};
pub use structurer::{
    CfgBlock, CfgEdge, CondExpr, CondLeaf, GotoKind, LoopKind, SailrInput, StructuredNode,
    Structurer, SwitchCase,
};
