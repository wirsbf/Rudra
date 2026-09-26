//! SAILR enhancement layer — the pattern-based structurer.
//!
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr/analyses/decompiler/structuring/{phoenix,sailr,recursive_structurer}.py / kuna p8_structure region_structurer.rs)
//!
//! Port of the SAILR/Phoenix schema family onto a self-contained working
//! graph: the compiler-degradation pattern matchers that recover source-level
//! structure a generic structurer (Ghidra `CollapseStructure`) emits gotos
//! for.  This module is **not** part of upstream Ghidra and is **not** wired
//! into the default structuring path (Phase 1: algorithm + tests only).
//!
//! # Schema cascade (per round, until one component remains)
//!
//! 1. short-circuit conditions (pre-pass fixpoint) — `&&`/`||` diamonds
//! 2. switch-case recovery (jump-table switch head + case fan-out)
//! 3. sequence chains (single-in/single-out runs)
//! 4. if / if-else (ITE)
//! 5. cyclic schemas: inf-loop / do-while / while-do folds + loop refinement
//!    (secondary exits -> break, secondary latches -> continue, mid-entries
//!    -> goto), innermost-first
//! 6. wrap already-virtualized goto edges
//! 7. last resort: virtualize one edge (SAILR H1/H2/H3 dominance-tiered
//!    ordering)
//!
//! # Working-graph model
//!
//! Mirrors the Ghidra `BlockGraph` shape the default face uses (blocks with
//! in/out edge vectors carrying `goto`/`back`/`default` flags, out edge 0 =
//! false/fall-through and out edge 1 = true for binary blocks, a live
//! component list), but over this module's own arena — Phase 2 maps the
//! output [`StructuredNode`] tree onto `block.rs` block kinds one-to-one
//! (`Seq`↔List, `Condition`↔Condition, `If`/`IfElse`↔If, `Switch`↔Switch,
//! `WhileDo`/`DoWhile`/`InfLoop`↔WhileDo/DoWhile/InfLoop, `Goto`↔Goto).
//!
//! # Condition model
//!
//! Conditions are abstract: a leaf refers to the branching block's terminal
//! condition by address (`invert` accumulates the negation parity — the
//! deferred data-flow half Ghidra tracks as `boolean_flip`), and folds
//! compose `And`/`Or` exactly as `BlockGraph::newBlockCondition` chooses
//! them (`Or` iff the second block sits on the first block's false out).
//! Concrete condition recovery (P-code/`condexe`) is the Phase 2 seam.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};

use crate::sailr::graph::{
    dfs_postorder_deterministic, immediate_dominators, NodeKind, NodePool, RegionGraph,
    RegionNodeId,
};

/// Loop-kind classification for the recovered loop nodes.  A source `for` is
/// structurally a `While` whose body ends in the induction update; the
/// `init`/`iterate` hooks on [`StructuredNode::WhileDo`] are the Phase 2
/// dataflow seam that upgrades the classification.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr StructuredLoopNode sort + Ghidra BlockWhileDo initialize/iterate ops)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    While,
    DoWhile,
    Inf,
}

/// Kind of a recovered unstructured jump.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr BreakNode/ContinueNode/Goto / Ghidra f_break_goto,f_continue_goto,f_goto_goto)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotoKind {
    Plain,
    Break,
    Continue,
}

/// An abstract condition expression.  `Leaf` refers to a branching block's
/// terminal condition (by address + external payload); `invert` is the
/// accumulated negation parity.  `And`/`Or` compose per
/// `BlockGraph::newBlockCondition`.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:1780 newBlockCondition opcode choice / angr condition-processor edge conditions)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondExpr {
    /// A single block's terminal condition (`invert` = printed `!`).
    Leaf(CondLeaf),
    And(Box<CondExpr>, Box<CondExpr>),
    Or(Box<CondExpr>, Box<CondExpr>),
}

/// Leaf of a [`CondExpr`].
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra PcodeOp boolean_flip deferred flip / kuna pending_flips)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondLeaf {
    /// Address of the block whose terminal branch provides the condition.
    pub addr: u64,
    /// External payload of that block (Phase 2: the bblocks BlockId).
    pub external: Option<usize>,
    /// Negation parity (each negateCondition flips it once).
    pub invert: bool,
}

impl CondExpr {
    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:3023 BlockCondition::negateCondition (De Morgan distribution + opcode flip))
    /// Negate in place: flip the operator (And <-> Or) and distribute the
    /// NOT to both sides (each leaf flips its parity).
    pub fn negate(&mut self) {
        Self::swap_op(self);
        match self {
            CondExpr::Leaf(l) => l.invert = !l.invert,
            CondExpr::And(a, b) | CondExpr::Or(a, b) => {
                a.negate_leafwise();
                b.negate_leafwise();
            }
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: helper mirroring the recursive distribution without re-flipping inner operators)
    /// Flip every leaf parity below this node (no operator flips).
    fn negate_leafwise(&mut self) {
        match self {
            CondExpr::Leaf(l) => l.invert = !l.invert,
            CondExpr::And(a, b) | CondExpr::Or(a, b) => {
                a.negate_leafwise();
                b.negate_leafwise();
            }
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:3029 opc = (opc==BOOL_AND) ? BOOL_OR : BOOL_AND)
    /// Flip the top-level operator (And <-> Or) without touching operands.
    fn swap_op(cond: &mut CondExpr) {
        let old = std::mem::replace(
            cond,
            CondExpr::Leaf(CondLeaf { addr: 0, external: None, invert: false }),
        );
        *cond = match old {
            CondExpr::And(a, b) => CondExpr::Or(a, b),
            CondExpr::Or(a, b) => CondExpr::And(a, b),
            leaf => leaf,
        };
    }
}

/// One switch case: target address, default flag, and the folded case body.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra CaseOrder / angr SwitchCase)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchCase {
    pub target_addr: u64,
    pub is_default: bool,
    pub body: StructuredNode,
}

/// The structured output IR — the Phase 2 adapter maps each variant onto the
/// corresponding `block.rs` block kind.  Condition-bearing nodes reference
/// the branching block by address/external payload in their [`CondExpr`]
/// leaves (statement recovery by reference is the print-side seam).
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr StructuredNode hierarchy / Ghidra block.hh BlockType family)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuredNode {
    /// A leaf basic block (`addr` + external payload; `invert` = negation
    /// parity when this block is consumed as a condition).
    Block {
        addr: u64,
        external: Option<usize>,
        invert: bool,
    },
    /// A sequence (BlockList).
    Seq {
        body: Vec<StructuredNode>,
    },
    /// A folded condition node (BlockCondition).
    Condition {
        cond: CondExpr,
    },
    /// if (cond) { then } — no else clause (BlockIf).
    If {
        cond: CondExpr,
        then: Box<StructuredNode>,
    },
    /// if (cond) { then } else { els } (BlockIfElse).
    IfElse {
        cond: CondExpr,
        then: Box<StructuredNode>,
        els: Box<StructuredNode>,
    },
    /// switch (head) { cases } (BlockSwitch).
    Switch {
        head: Box<StructuredNode>,
        cases: Vec<SwitchCase>,
        /// Is there a fall-through exit block after the switch?
        has_exit: bool,
    },
    /// while (cond) { body } (BlockWhileDo).  `init`/`iterate` are the
    /// for-loop recovery hooks (Phase 2 dataflow seam; always `None` here).
    WhileDo {
        kind: LoopKind,
        cond: CondExpr,
        body: Box<StructuredNode>,
        init: Option<u64>,
        iterate: Option<u64>,
        /// Loop head address (continue classification).
        head_addr: u64,
        /// Addresses of the loop's structural exits (break classification).
        exit_addrs: BTreeSet<u64>,
    },
    /// do { body } while (cond) (BlockDoWhile).  The body carries the loop's
    /// statements; the trailing test is the cond leaf.
    DoWhile {
        kind: LoopKind,
        cond: CondExpr,
        body: Box<StructuredNode>,
        head_addr: u64,
        exit_addrs: BTreeSet<u64>,
    },
    /// while (true) { body } (BlockInfLoop).
    InfLoop {
        kind: LoopKind,
        body: Box<StructuredNode>,
        /// Loop head address (continue classification).
        head_addr: u64,
        exit_addrs: BTreeSet<u64>,
    },
    /// goto / break / continue (BlockGoto family).
    Goto {
        target_addr: u64,
        kind: GotoKind,
    },
}

impl StructuredNode {
    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra BlockList::negateCondition recursing to last block)
    /// Negate the condition this node computes, if it is a condition-bearing
    /// node (Block leaf flips parity; Seq recurses to its last member;
    /// Condition De-Morgans).  Returns whether anything changed.
    pub fn negate_in_place(&mut self) -> bool {
        match self {
            StructuredNode::Block { invert, .. } => {
                *invert = !*invert;
                true
            }
            StructuredNode::Seq { body } => match body.last_mut() {
                Some(last) => last.negate_in_place(),
                None => false,
            },
            StructuredNode::Condition { cond } => {
                cond.negate();
                true
            }
            _ => false,
        }
    }
}

//
// Input
//

/// Per-block facts the structurer needs (the Phase 2 adapter precomputes
/// these over `bblocks`, exactly the way `ActionBlockStructure` precomputes
/// `is_complex`/`is_switch_out` for `CollapseStructure`).
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna region_structurer.rs compute_switch_maps/compute_complex_blocks precomputation shape)
#[derive(Debug, Clone, Default)]
pub struct CfgBlock {
    /// Start address (deterministic ordering key).
    pub addr: u64,
    /// `BlockBasic::isComplex`: more than one non-trivial statement — gates
    /// the short-circuit fold (`false` = a bare CBRANCH may fold).
    pub complex: bool,
    /// `f_switch_out`: ends with a resolved indirect branch (jump table).
    pub switch: bool,
    /// A simple return/exit sink (the H3 virtualize heuristic).
    pub simple_return: bool,
    /// External payload (Phase 2: the bblocks `BlockId`).
    pub external: Option<usize>,
}

/// One input CFG edge.  Out-edge order within a block is the input list
/// order; for a binary branch, the first edge is the FALSE/fall-through edge
/// and the second is the TRUE edge (Ghidra's out[0]/out[1] convention).
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra BlockEdge out0=false/out1=true convention)
#[derive(Debug, Clone)]
pub struct CfgEdge {
    pub src: usize,
    pub dst: usize,
    /// For a switch head: is this the default case edge?
    pub default_edge: bool,
}

// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: CfgEdge with non-default edge default)
impl CfgEdge {
    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: constructor convenience for non-default edges)
    pub fn new(src: usize, dst: usize) -> CfgEdge {
        CfgEdge { src, dst, default_edge: false }
    }
}

/// The structurer input: a CFG projection with per-block facts.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna region_structurer.rs input precomputation over Funcdata)
#[derive(Debug, Clone, Default)]
pub struct SailrInput {
    pub blocks: Vec<CfgBlock>,
    pub edges: Vec<CfgEdge>,
    /// Index of the entry block.
    pub entry: usize,
}

//
// Working graph
//

/// Id of a working block in the structurer's arena.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock arena / kuna BlockId)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SId(pub u32);

/// One out-edge of a working block (the `BlockEdge` analog: destination and
/// edge flags; the in-edge lists are addressed by source id, so no reverse
/// index bookkeeping is needed).
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.hh BlockEdge {point,label})
#[derive(Debug, Clone)]
struct SOut {
    dst: SId,
    /// `f_goto_edge`: unstructured jump edge.
    goto: bool,
    /// `f_back_edge`: loop back edge.
    back: bool,
    /// `f_defaultswitch_edge`: the switch's default case edge.
    default_sw: bool,
}

/// One in-edge of a working block.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra BlockEdge reverse view)
#[derive(Debug, Clone)]
struct SIn {
    src: SId,
    goto: bool,
    back: bool,
}

/// A working block: a live structuring component carrying the folded payload.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock + BlockGraph list / kuna FlowBlock arena)
#[derive(Debug, Clone)]
struct SBlock {
    addr: u64,
    external: Option<usize>,
    complex: bool,
    switch: bool,
    simple_return: bool,
    /// Reverse-post-order index from the input CFG (deterministic key).
    index: i32,
    succs: Vec<SOut>,
    preds: Vec<SIn>,
    payload: StructuredNode,
}

/// Round cap on structuring rounds: `2*n^2 + 64` (hang-guard turning a
/// mis-port into a clean failure — every schema application removes at least
/// one component or edge).
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna region_structurer.rs round_cap)
fn round_cap(num_nodes: i32) -> i64 {
    let n = num_nodes as i64;
    2 * n * n + 64
}

/// SAILR H2 post-dominator caps (angr `SAILRStructurer` defaults).
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr sailr.py postdom_max_edges/postdom_max_graph_size)
const POSTDOM_MAX_EDGES: i32 = 10;
const POSTDOM_MAX_GRAPH_SIZE: i32 = 50;

/// A candidate edge for virtualization: `src --edge--> dst`.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna region_structurer.rs Edge)
#[derive(Debug, Clone)]
struct VEdge {
    src: SId,
    edge: usize,
    dst: SId,
}

/// Outcome of the loop refinement on one head.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna region_structurer.rs LoopRefineOutcome)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopRefineOutcome {
    /// At least one secondary edge was virtualized — progress.
    Progressed,
    /// Multi-entry at the head (irreducible): cannot refine.
    Irreducible,
    /// Nothing needed refining.
    NoChange,
}

/// The SAILR pattern structurer.
// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr phoenix.py PhoenixStructurer._analyze + sailr.py SAILRStructurer / kuna RegionStructurer)
pub struct Structurer {
    arena: Vec<SBlock>,
    /// Live top-level components, in list order (Ghidra's BlockGraph list).
    list: Vec<SId>,
    entry: SId,
    /// Region-identifier loop projection (optional; RI-grounded refinement).
    cyclic_loops: BTreeMap<u64, crate::sailr::region_id::CyclicLoop>,
    /// Input complexity by block address (BlockBasic::isComplex lookups).
    complex_by_addr: BTreeMap<u64, bool>,
    /// Full exit-address sets captured at refinement time (before the
    /// secondary exits virtualize away), keyed by loop head address — the
    /// break-classification ground truth for `loop_exit_addrs`.
    exit_cache: BTreeMap<u64, BTreeSet<u64>>,
}

impl Structurer {
    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna RegionStructurer::new + seeding)
    /// Seed the working graph from the input projection: one leaf block per
    /// input block (edges in input order, out[0]=false/out[1]=true), back
    /// edges marked by a deterministic DFS from the entry.
    pub fn new(input: &SailrInput) -> Result<Structurer> {
        if input.blocks.is_empty() {
            return Err(anyhow!("sailr structurer: empty input"));
        }
        if input.entry >= input.blocks.len() {
            return Err(anyhow!("sailr structurer: entry index out of range"));
        }
        let mut arena: Vec<SBlock> = Vec::with_capacity(input.blocks.len());
        let mut complex_by_addr: BTreeMap<u64, bool> = BTreeMap::new();
        for (i, b) in input.blocks.iter().enumerate() {
            arena.push(SBlock {
                addr: b.addr,
                external: b.external,
                complex: b.complex,
                switch: b.switch,
                simple_return: b.simple_return,
                index: i as i32,
                succs: Vec::new(),
                preds: Vec::new(),
                payload: StructuredNode::Block {
                    addr: b.addr,
                    external: b.external,
                    invert: false,
                },
            });
            complex_by_addr.insert(b.addr, b.complex);
        }
        for e in input.edges.iter() {
            if e.src >= arena.len() || e.dst >= arena.len() {
                return Err(anyhow!("sailr structurer: edge index out of range"));
            }
            let (s, d) = (SId(e.src as u32), SId(e.dst as u32));
            if arena[s.0 as usize].succs.iter().any(|o| o.dst == d) {
                continue; // dedup parallel duplicates
            }
            arena[s.0 as usize].succs.push(SOut {
                dst: d,
                goto: false,
                back: false,
                default_sw: e.default_edge,
            });
            arena[d.0 as usize].preds.push(SIn { src: s, goto: false, back: false });
        }
        let mut st = Structurer {
            arena,
            list: (0..input.blocks.len() as u32).map(SId).collect(),
            entry: SId(input.entry as u32),
            cyclic_loops: BTreeMap::new(),
            complex_by_addr,
            exit_cache: BTreeMap::new(),
        };
        st.mark_back_edges();
        Ok(st)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra structure_loops back-edge marking / angr loop_heads)
    /// Mark back edges with a deterministic DFS from the entry (children
    /// visited in destination-address order).
    fn mark_back_edges(&mut self) {
        let entry = self.entry;
        let mut visited: BTreeSet<SId> = BTreeSet::new();
        let mut finished: BTreeSet<SId> = BTreeSet::new();
        struct Frame {
            node: SId,
            children: Vec<SId>,
            cursor: usize,
        }
        let start_children = self.sorted_succ_ids(entry);
        let mut stack: Vec<Frame> =
            vec![Frame { node: entry, children: start_children, cursor: 0 }];
        while let Some(frame) = stack.last_mut() {
            let node = frame.node;
            visited.insert(node);
            if frame.cursor < frame.children.len() {
                let child = frame.children[frame.cursor];
                frame.cursor += 1;
                if visited.contains(&child) {
                    if !finished.contains(&child) {
                        self.mark_edge_back(node, child);
                    }
                } else if !finished.contains(&child) {
                    let children = self.sorted_succ_ids(child);
                    stack.push(Frame { node: child, children, cursor: 0 });
                }
            } else {
                finished.insert(node);
                stack.pop();
            }
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra f_back_edge flag on both BlockEdge ends)
    /// Flag every `src -> dst` edge (both ends) as a back edge.
    fn mark_edge_back(&mut self, src: SId, dst: SId) {
        for o in self.arena[src.0 as usize].succs.iter_mut() {
            if o.dst == dst {
                o.back = true;
            }
        }
        for i in self.arena[dst.0 as usize].preds.iter_mut() {
            if i.src == src {
                i.back = true;
            }
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: region-graph get_sorted_succs ordering)
    /// Successor ids of a block in destination-address order.
    fn sorted_succ_ids(&self, n: SId) -> Vec<SId> {
        let mut v: Vec<SId> = self.arena[n.0 as usize].succs.iter().map(|o| o.dst).collect();
        v.sort_by_key(|&s| self.arena[s.0 as usize].addr);
        v
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna with_loop_refine + RegionIdentifier::cyclic_loops)
    /// Attach the region identifier's cyclic-loop projection (RI-grounded
    /// loop-body/exit refinement input; optional).
    pub fn with_cyclic_loops(
        mut self,
        loops: Vec<crate::sailr::region_id::CyclicLoop>,
    ) -> Structurer {
        self.cyclic_loops = loops.into_iter().map(|l| (l.head_addr, l)).collect();
        self
    }

    //
    // Accessors
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra BlockGraph::getSize)
    /// Number of live top-level components.
    fn size(&self) -> i32 {
        self.list.len() as i32
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra BlockGraph::getBlock)
    /// The i-th live component.
    fn component(&self, i: i32) -> SId {
        self.list[i as usize]
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::sizeOut)
    fn size_out(&self, b: SId) -> usize {
        self.arena[b.0 as usize].succs.len()
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::sizeIn)
    fn size_in(&self, b: SId) -> usize {
        self.arena[b.0 as usize].preds.len()
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::getOut)
    fn get_out(&self, b: SId, i: usize) -> SId {
        self.arena[b.0 as usize].succs[i].dst
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::getIn)
    fn get_in(&self, b: SId, i: usize) -> SId {
        self.arena[b.0 as usize].preds[i].src
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::isGotoOut)
    fn is_goto_out(&self, b: SId, i: usize) -> bool {
        self.arena[b.0 as usize].succs[i].goto
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::isGotoIn)
    fn is_goto_in(&self, b: SId, i: usize) -> bool {
        self.arena[b.0 as usize].preds[i].goto
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::isBackEdgeOut)
    fn is_back_edge_out(&self, b: SId, i: usize) -> bool {
        self.arena[b.0 as usize].succs[i].back
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::isBackEdgeIn)
    fn is_back_edge_in(&self, b: SId, i: usize) -> bool {
        self.arena[b.0 as usize].preds[i].back
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::isDefaultBranch)
    fn is_default_branch(&self, b: SId, i: usize) -> bool {
        self.arena[b.0 as usize].succs[i].default_sw
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::isSwitchOut)
    fn is_switch_out(&self, b: SId) -> bool {
        self.arena[b.0 as usize].switch
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::isInteriorGotoTarget)
    fn is_interior_goto_target(&self, b: SId) -> bool {
        self.arena[b.0 as usize].preds.iter().any(|p| p.goto)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::index)
    fn get_index(&self, b: SId) -> i32 {
        self.arena[b.0 as usize].index
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock front address)
    fn addr_of(&self, b: SId) -> u64 {
        self.arena[b.0 as usize].addr
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna is_complex (block.hh:254/549/649 override set))
    /// `FlowBlock::isComplex`: everything is complex except a BlockCopy of
    /// a non-complex BlockBasic and a BlockCondition (which delegates to
    /// its first sub-block).
    fn is_complex(&self, b: SId) -> bool {
        match &self.arena[b.0 as usize].payload {
            StructuredNode::Block { addr, .. } => {
                self.complex_by_addr.get(addr).copied().unwrap_or(true)
            }
            StructuredNode::Condition { cond } => match cond {
                CondExpr::Leaf(l) => self.complex_by_addr.get(&l.addr).copied().unwrap_or(true),
                CondExpr::And(a, _) | CondExpr::Or(a, _) => match &**a {
                    CondExpr::Leaf(l) => {
                        self.complex_by_addr.get(&l.addr).copied().unwrap_or(true)
                    }
                    _ => true,
                },
            },
            _ => true,
        }
    }

    //
    // Graph surgery
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:218 FlowBlock::swapEdges)
    /// Swap the two out-edges of a binary block (negateCondition topology
    /// half).  In-edge lists are source-addressed, so no reverse-index
    /// repair is needed.
    fn swap_edges(&mut self, b: SId) {
        self.arena[b.0 as usize].succs.swap(0, 1);
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:294 negateCondition family (Basic/List/Condition overrides))
    /// The negateCondition port: payload half (leaf flip / De Morgan /
    /// list-last recursion) + topology swap when `top`.
    fn negate_condition(&mut self, b: SId, top: bool) -> bool {
        let changed = self.arena[b.0 as usize].payload.negate_in_place();
        if top && self.size_out(b) == 2 {
            self.swap_edges(b);
        }
        changed
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:307 FlowBlock::setGotoBranch)
    /// Mark an out-edge as an unstructured goto (flags both ends).
    fn set_goto_branch(&mut self, b: SId, i: usize) {
        let dst = self.arena[b.0 as usize].succs[i].dst;
        self.arena[b.0 as usize].succs[i].goto = true;
        for p in self.arena[dst.0 as usize].preds.iter_mut() {
            if p.src == b {
                p.goto = true;
            }
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::addEdge)
    /// Add (or flag-merge) the edge `src -> dst`.
    fn link(&mut self, src: SId, dst: SId, goto: bool, back: bool, dflt: bool) {
        if let Some(oi) = self.arena[src.0 as usize].succs.iter().position(|o| o.dst == dst) {
            let o = &mut self.arena[src.0 as usize].succs[oi];
            o.goto |= goto;
            o.back |= back;
            o.default_sw |= dflt;
            let merged_goto = o.goto;
            let merged_back = o.back;
            for p in self.arena[dst.0 as usize].preds.iter_mut() {
                if p.src == src {
                    p.goto = merged_goto;
                    p.back = merged_back;
                }
            }
            return;
        }
        self.arena[src.0 as usize].succs.push(SOut { dst, goto, back, default_sw: dflt });
        self.arena[dst.0 as usize].preds.push(SIn { src, goto, back });
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra FlowBlock::removeEdge)
    /// Remove the edge `src -> dst` if present.
    fn unlink(&mut self, src: SId, dst: SId) {
        if let Some(pos) = self.arena[src.0 as usize].succs.iter().position(|o| o.dst == dst) {
            self.arena[src.0 as usize].succs.remove(pos);
        }
        if let Some(pos) = self.arena[dst.0 as usize].preds.iter().position(|p| p.src == src) {
            self.arena[dst.0 as usize].preds.remove(pos);
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:895 BlockGraph::selfIdentify + dedup + :940 identifyInternal + :880 forceOutputNum + :1204 forceFalseEdge)
    ///
    /// Collapse `members` into a fresh composite block: the composite
    /// inherits in-edges from outside the set and out-edges to outside the
    /// set (parallel edges deduplicated, flags OR-merged, exactly
    /// `selfIdentify`+`dedup`), the members leave the live list, and the
    /// composite is appended (Ghidra `addBlock`).  Returns the composite id.
    fn identify_internal(&mut self, members: &[SId]) -> SId {
        let mset: BTreeSet<SId> = members.iter().copied().collect();
        // Aggregate out-edges (member -> outside), dedup by dst.
        let mut out_map: Vec<(SId, bool, bool, bool)> = Vec::new();
        for &m in members.iter() {
            for o in self.arena[m.0 as usize].succs.iter() {
                if mset.contains(&o.dst) {
                    continue;
                }
                match out_map.iter_mut().find(|e| e.0 == o.dst) {
                    Some(e) => {
                        e.1 |= o.goto;
                        e.2 |= o.back;
                        e.3 |= o.default_sw;
                    }
                    None => out_map.push((o.dst, o.goto, o.back, o.default_sw)),
                }
            }
        }
        // Aggregate in-edges (outside -> member), dedup by src.
        let mut in_map: Vec<(SId, bool, bool)> = Vec::new();
        for &m in members.iter() {
            for p in self.arena[m.0 as usize].preds.iter() {
                if mset.contains(&p.src) {
                    continue;
                }
                match in_map.iter_mut().find(|e| e.0 == p.src) {
                    Some(e) => {
                        e.1 |= p.goto;
                        e.2 |= p.back;
                    }
                    None => in_map.push((p.src, p.goto, p.back)),
                }
            }
        }
        let min_index = members.iter().map(|&m| self.arena[m.0 as usize].index).min().unwrap();
        let addr = members.iter().map(|&m| self.arena[m.0 as usize].addr).min().unwrap();
        let switch = members.iter().any(|&m| self.arena[m.0 as usize].switch);
        let simple_return = members.iter().all(|&m| self.arena[m.0 as usize].simple_return);
        let external = self.arena[members[0].0 as usize].external;
        let id = SId(self.arena.len() as u32);
        self.arena.push(SBlock {
            addr,
            external,
            complex: true, // composites are complex by default (base isComplex)
            switch,
            simple_return,
            index: min_index,
            succs: Vec::new(),
            preds: Vec::new(),
            payload: StructuredNode::Block { addr, external, invert: false },
        });
        // Detach the members: remove every edge touching them from the
        // outside, then clear their adjacency wholesale.
        for &m in members.iter() {
            let outs: Vec<SId> = self.arena[m.0 as usize].succs.iter().map(|o| o.dst).collect();
            for d in outs {
                self.unlink(m, d);
            }
            let ins: Vec<SId> = self.arena[m.0 as usize].preds.iter().map(|p| p.src).collect();
            for s in ins {
                self.unlink(s, m);
            }
        }
        // Track the entry component through the fold.
        if mset.contains(&self.entry) {
            self.entry = id;
        }
        self.list.retain(|&s| !mset.contains(&s));
        self.list.push(id);
        // Wire the composite.
        for (dst, goto, back, dflt) in out_map {
            self.link(id, dst, goto, back, dflt);
        }
        for (src, goto, back) in in_map {
            self.link(src, id, goto, back, false);
        }
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:880 forceOutputNum (self back-edges) + :1204 forceFalseEdge)
    /// Ensure the composite has two out-edges and that out[0] targets
    /// `false_dst`.
    fn force_binary(&mut self, b: SId, false_dst: SId) {
        while self.size_out(b) < 2 {
            self.link(b, b, false, true, false);
        }
        if self.get_out(b, 0) != false_dst && self.size_out(b) == 2 {
            self.swap_edges(b);
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna cond_expr (front-leaf condition resolution through BlockCopy/BlockCondition/BlockList))
    /// The condition expression of a condition-bearing working block (Leaf ->
    /// its leaf; Condition -> its cond; Seq -> recurse to the last member).
    fn cond_expr(&self, b: SId) -> Option<CondExpr> {
        match &self.arena[b.0 as usize].payload {
            StructuredNode::Block { addr, external, invert } => Some(CondExpr::Leaf(CondLeaf {
                addr: *addr,
                external: *external,
                invert: *invert,
            })),
            StructuredNode::Condition { cond } => Some(cond.clone()),
            StructuredNode::Seq { body } => match body.last() {
                Some(StructuredNode::Condition { cond }) => Some(cond.clone()),
                Some(StructuredNode::Block { addr, external, invert }) => {
                    Some(CondExpr::Leaf(CondLeaf {
                        addr: *addr,
                        external: *external,
                        invert: *invert,
                    }))
                }
                _ => None,
            },
            _ => None,
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:1780 newBlockCondition)
    /// Fold `bl` + `orblock` into a composite condition node: `Or` iff
    /// `orblock` sits on `bl`'s false out, else `And`; the composite's false
    /// out is `orblock`'s current out[0].
    fn new_block_condition(&mut self, bl: SId, orblock: SId) -> SId {
        let out0 = self.get_out(orblock, 0);
        let op_is_or = self.get_out(bl, 0) == orblock;
        let c1 = self.leaf_cond_of(bl);
        let c2 = self.leaf_cond_of(orblock);
        let cond = if op_is_or {
            CondExpr::Or(Box::new(c1), Box::new(c2))
        } else {
            CondExpr::And(Box::new(c1), Box::new(c2))
        };
        let id = self.identify_internal(&[bl, orblock]);
        self.arena[id.0 as usize].payload = StructuredNode::Condition { cond };
        self.force_binary(id, out0);
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: cond_expr with structural fallback to the block's own leaf)
    /// A block's condition (its extracted cond, or its own leaf).
    fn leaf_cond_of(&self, b: SId) -> CondExpr {
        self.cond_expr(b).unwrap_or(CondExpr::Leaf(CondLeaf {
            addr: self.addr_of(b),
            external: self.arena[b.0 as usize].external,
            invert: false,
        }))
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:1825 newBlockIf)
    /// Fold `cond + tc` into an if node (single out-edge: the after path).
    fn new_block_if(&mut self, cond: SId, tc: SId) -> SId {
        let c = self.leaf_cond_of(cond);
        // The reconvergence target must be read BEFORE the fold detaches the
        // member edges.
        let keep = self.next_after_if(cond, tc);
        let tc_payload = self.take_payload(tc);
        let id = self.identify_internal(&[cond, tc]);
        self.arena[id.0 as usize].payload = StructuredNode::If {
            cond: c,
            then: Box::new(tc_payload),
        };
        self.reduce_to_single_out(id, keep);
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:1843 newBlockIfElse)
    /// Fold `cond + tc + fc` into an if-else node (single out-edge).
    fn new_block_if_else(&mut self, cond: SId, tc: SId, fc: SId) -> SId {
        let c = self.leaf_cond_of(cond);
        // The reconvergence target must be read BEFORE the fold detaches the
        // member edges.
        let keep = self.next_after_if(cond, tc);
        let tc_payload = self.take_payload(tc);
        let fc_payload = self.take_payload(fc);
        let id = self.identify_internal(&[cond, tc, fc]);
        self.arena[id.0 as usize].payload = StructuredNode::IfElse {
            cond: c,
            then: Box::new(tc_payload),
            els: Box::new(fc_payload),
        };
        self.reduce_to_single_out(id, keep);
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra ruleBlockIf/ruleBlockIfElse `gotoEndBlock` (the reconvergence target))
    /// The reconvergence target of an if/if-else fold: the clause exit.
    fn next_after_if(&self, cond: SId, tc: SId) -> Option<SId> {
        if self.size_out(tc) == 1 && self.get_out(tc, 0) != cond {
            Some(self.get_out(tc, 0))
        } else {
            None
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra newBlockGoto forceOutputNum(0) + newBlockIf forceOutputNum(1) semantics)
    /// Reduce the composite to the retained out-edge — a plain goto block is
    /// TERMINAL (no out edges survive the wrap: the goto lives in the
    /// payload, and a residual flagged edge would re-trigger the wrap
    /// forever).
    fn reduce_to_single_out(&mut self, id: SId, keep: Option<SId>) {
        match keep {
            None => {
                // Terminal: remove every out-edge.
                loop {
                    let n = self.size_out(id);
                    if n == 0 {
                        break;
                    }
                    let d = self.get_out(id, n - 1);
                    self.unlink(id, d);
                }
            }
            Some(k) => loop {
                let n = self.size_out(id);
                if n <= 1 {
                    break;
                }
                let mut removed = false;
                for i in 0..n {
                    let d = self.get_out(id, i);
                    if d != k {
                        self.unlink(id, d);
                        removed = true;
                        break;
                    }
                }
                if !removed {
                    break;
                }
            },
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:1861 newBlockWhileDo)
    /// Fold `cond + cl` into a while-do loop node (single out-edge: the loop
    /// exit).
    fn new_block_while_do(&mut self, cond: SId, cl: SId, exit_addrs: BTreeSet<u64>) -> SId {
        let c = self.leaf_cond_of(cond);
        let head_addr = self.addr_of(cond);
        let cl_payload = self.take_payload(cl);
        let id = self.identify_internal(&[cond, cl]);
        self.arena[id.0 as usize].payload = StructuredNode::WhileDo {
            kind: LoopKind::While,
            cond: c,
            body: Box::new(cl_payload),
            init: None,
            iterate: None,
            head_addr,
            exit_addrs,
        };
        // The loop's only structural out-edge is the exit (the back-edge into
        // the folded set is internal now).
        self.reduce_to_single_out(id, self.loop_exit_target(id));
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra newBlockWhileDo forceOutputNum(1) (loop exit is the single out))
    /// The loop composite's exit target: the out-edge that is not a self or
    /// back edge into the folded loop.
    fn loop_exit_target(&self, id: SId) -> Option<SId> {
        (0..self.size_out(id))
            .map(|i| self.get_out(id, i))
            .find(|&d| d != id)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.cc:1877 newBlockDoWhile (cond block carries body + trailing test))
    /// Fold the self-testing `cond` block into a do-while loop node; the
    /// block's payload becomes the loop body (its trailing test is the cond).
    fn new_block_do_while(&mut self, cond: SId, exit_addrs: BTreeSet<u64>) -> SId {
        let c = self.leaf_cond_of(cond);
        let head_addr = self.addr_of(cond);
        let body_payload = self.take_payload(cond);
        let id = self.identify_internal(&[cond]);
        self.arena[id.0 as usize].payload = StructuredNode::DoWhile {
            kind: LoopKind::DoWhile,
            cond: c,
            body: Box::new(body_payload),
            head_addr,
            exit_addrs,
        };
        self.reduce_to_single_out(id, self.loop_exit_target(id));
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra newBlockInfLoop)
    /// Fold the self-looping `body` block into an inf-loop node.
    fn new_block_inf_loop(&mut self, body: SId, head_addr: u64, exit_addrs: BTreeSet<u64>) -> SId {
        let body_payload = self.take_payload(body);
        let id = self.identify_internal(&[body]);
        self.arena[id.0 as usize].payload = StructuredNode::InfLoop {
            kind: LoopKind::Inf,
            body: Box::new(body_payload),
            head_addr,
            exit_addrs,
        };
        self.reduce_to_single_out(id, self.loop_exit_target(id));
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra newBlockList / ruleBlockCat)
    /// Fold a chain of blocks into a sequence node.
    fn new_block_list(&mut self, nodes: &[SId]) -> SId {
        let payloads: Vec<StructuredNode> = nodes.iter().map(|&n| self.take_payload(n)).collect();
        let id = self.identify_internal(nodes);
        self.arena[id.0 as usize].payload = StructuredNode::Seq { body: payloads };
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra newBlockSwitch / ruleBlockSwitch + CaseOrder)
    /// Fold a switch head + its case bodies into a switch node.  The
    /// composite keeps any non-case out-edges (the exit / continue back
    /// edges).
    fn new_block_switch(
        &mut self,
        head: SId,
        case_bodies: &[(SId, bool)],
        has_exit: bool,
    ) -> SId {
        let head_payload = self.take_payload(head);
        let mut members: Vec<SId> = vec![head];
        let mut case_nodes: Vec<SwitchCase> = Vec::new();
        for &(body, is_default) in case_bodies.iter() {
            members.push(body);
            let payload = self.take_payload(body);
            case_nodes.push(SwitchCase {
                target_addr: self.addr_of(body),
                is_default,
                body: payload,
            });
        }
        let id = self.identify_internal(&members);
        self.arena[id.0 as usize].payload = StructuredNode::Switch {
            head: Box::new(head_payload),
            cases: case_nodes,
            has_exit,
        };
        // `clearFlag(f_switch_out)`: the composite's BRANCHIND is structured
        // now — do not consider it a switch-out anymore (prevents the
        // switch schema from re-matching its own output).
        self.arena[id.0 as usize].switch = false;
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra newBlockGoto / newBlockIfGoto / newBlockMultiGoto)
    /// Wrap `bl`'s goto out-edge into a goto node: a plain trailing goto for
    /// single-out blocks, an if-goto for binary blocks (true edge is the
    /// goto, false edge is kept as the structural exit).
    fn new_block_goto(&mut self, bl: SId, e: usize) -> SId {
        let target = self.get_out(bl, e);
        let target_addr = self.addr_of(target);
        let keep = if self.size_out(bl) == 2 { Some(self.get_out(bl, 0)) } else { None };
        let payload = self.take_payload(bl);
        let goto_node = StructuredNode::Goto { target_addr, kind: GotoKind::Plain };
        let id = self.identify_internal(&[bl]);
        if self.size_out(bl) == 2 && e == 1 {
            // if-goto: cond + goto-then.
            let c = match &payload {
                StructuredNode::Condition { cond } => cond.clone(),
                StructuredNode::Block { addr, external, invert } => CondExpr::Leaf(CondLeaf {
                    addr: *addr,
                    external: *external,
                    invert: *invert,
                }),
                StructuredNode::Seq { .. } => self.seq_last_cond(&payload),
                _ => CondExpr::Leaf(CondLeaf {
                    addr: self.addr_of(bl),
                    external: None,
                    invert: false,
                }),
            };
            self.arena[id.0 as usize].payload = StructuredNode::If {
                cond: c,
                then: Box::new(goto_node),
            };
        } else {
            self.arena[id.0 as usize].payload =
                StructuredNode::Seq { body: vec![payload, goto_node] };
        }
        // Drop every out-edge except the structural exit.
        if let Some(k) = keep {
            self.reduce_to_single_out(id, Some(k));
        } else {
            self.reduce_to_single_out(id, None);
        }
        id
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: cond_expr Seq-last resolution mirrored on a detached payload)
    /// The cond of the last condition-bearing member of a detached Seq
    /// payload.
    fn seq_last_cond(&self, payload: &StructuredNode) -> CondExpr {
        if let StructuredNode::Seq { body } = payload {
            if let Some(last) = body.last() {
                match last {
                    StructuredNode::Condition { cond } => return cond.clone(),
                    StructuredNode::Block { addr, external, invert } => {
                        return CondExpr::Leaf(CondLeaf {
                            addr: *addr,
                            external: *external,
                            invert: *invert,
                        })
                    }
                    _ => {}
                }
            }
        }
        CondExpr::Leaf(CondLeaf { addr: 0, external: None, invert: false })
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: mem::replace helper for payload handoff into composites)
    /// Take a block's payload (replacing it with a placeholder) so a fold can
    /// move it into the composite.
    fn take_payload(&mut self, b: SId) -> StructuredNode {
        std::mem::replace(
            &mut self.arena[b.0 as usize].payload,
            StructuredNode::Block { addr: 0, external: None, invert: false },
        )
    }

    //
    // Driver
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr phoenix.py _analyze / kuna RegionStructurer::structure)
    ///
    /// Drive the schema cascade to a single root.  Returns `Some(root)` on
    /// success, `None` if the graph could not be collapsed (the caller falls
    /// back — honest-partial, never a panic).
    pub fn structure(&mut self) -> Result<Option<StructuredNode>> {
        let cap = round_cap(self.size());

        // (a1 pre-pass) short-circuit / condition folding to a fixpoint —
        // cascading conditions fold into one compound condition before the
        // if/sequence/loop cascade.
        let mut precond_rounds: i64 = 0;
        loop {
            precond_rounds += 1;
            if precond_rounds > cap {
                break;
            }
            if !self.match_short_circuit_conditions()? {
                break;
            }
        }

        let mut rounds: i64 = 0;
        while self.size() > 1 && !self.only_entry_and_goto_islands() {
            rounds += 1;
            if rounds > cap {
                return Ok(None); // hang-guard: report non-convergence
            }
            // (a0) switch-case recovery (nested switches resolve first).
            if self.match_switch_cases()? {
                continue;
            }
            // (a) sequence chains.
            if self.match_sequence()? {
                continue;
            }
            // (a2) if / if-else.
            if self.match_ite()? {
                continue;
            }
            // (a3) cyclic schemas (loop folds + refinement).
            if self.match_cyclic_schemas()? {
                continue;
            }
            // (b) wrap already-marked goto edges.
            if self.rule_block_goto()? {
                continue;
            }
            // (c) last resort: virtualize one edge.
            if self.virtualize_one_edge()? {
                continue;
            }
            // Nothing matched and >1 component remains: stuck knot.
            return Ok(None);
        }
        if self.list.contains(&self.entry) {
            let root = self.entry;
            let mut tree = self.arena[root.0 as usize].payload.clone();
            self.classify_gotos(&mut tree, &mut Vec::new());
            return Ok(Some(tree));
        }
        Ok(None)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra multi-top-level goto graph form / angr goto-target termination)
    ///
    /// Is every live component other than the entry a goto-target island
    /// (no structural in-edge from the live set)?  Such residuals are exactly
    /// what the wrapped `Goto` nodes point at; the entry-rooted structure is
    /// complete.
    fn only_entry_and_goto_islands(&self) -> bool {
        for &c in self.list.iter() {
            if c == self.entry {
                continue;
            }
            let structural_in = (0..self.size_in(c)).any(|j| !self.is_goto_in(c, j));
            if structural_in {
                return false;
            }
        }
        true
    }

    //
    // (a1) short-circuit conditions — the &&/|| diamond fold
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr phoenix.py:2770 _match_acyclic_short_circuit_conditions / Ghidra blockaction.cc:1321 ruleBlockOr / kuna match_acyclic_short_circuit_conditions)
    /// Fold cascading short-circuit conditions into a single composite
    /// condition node (`&&`/`||` diamonds the compiler lowers to branch
    /// pairs).
    fn match_short_circuit_conditions(&mut self) -> Result<bool> {
        let n = self.size();
        for i in 0..n {
            let bl = self.component(i);
            if self.try_block_or(bl)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra blockaction.cc:1321-1372 ruleBlockOr (verbatim structural guards))
    ///
    /// The fold: `bl` and its successor `orblock` are both binary
    /// conditions; `orblock` is single-in, non-complex (a bare branch), and
    /// one of `orblock`'s out-edges (the shared clause) is also a direct
    /// out-edge of `bl`.  Orientation negations make `orblock` the false out
    /// of `bl` and the clause the true out of `orblock`, then the pair folds
    /// into a composite condition.
    fn try_block_or(&mut self, bl: SId) -> Result<bool> {
        if self.size_out(bl) != 2 {
            return Ok(false);
        }
        if self.is_goto_out(bl, 0) || self.is_goto_out(bl, 1) {
            return Ok(false);
        }
        if self.is_switch_out(bl) {
            return Ok(false);
        }
        for i in 0..2usize {
            let orblock = self.get_out(bl, i); // False out is other part of OR
            if orblock == bl {
                continue; // orblock cannot be same block
            }
            if self.size_in(orblock) != 1 {
                continue; // nothing else can hit orblock
            }
            if self.size_out(orblock) != 2 {
                continue; // orblock must also be a binary condition
            }
            if self.is_interior_goto_target(orblock) {
                continue; // no unstructured jumps into or
            }
            if self.is_switch_out(orblock) {
                continue;
            }
            if self.is_back_edge_out(bl, i) {
                continue; // don't use a loop branch to get to orblock
            }
            if self.is_complex(orblock) {
                continue; // control flow too complicated for condition
            }
            let clauseblock = self.get_out(bl, 1 - i);
            if clauseblock == bl {
                continue; // no looping
            }
            if clauseblock == orblock {
                continue;
            }
            let mut j = 0usize;
            while j < 2 {
                if clauseblock == self.get_out(orblock, j) {
                    break;
                }
                j += 1;
            }
            if j == 2 {
                continue; // clauses don't match
            }
            if self.get_out(orblock, 1 - j) == bl {
                continue; // no looping
            }

            if i == 1 {
                // orblock needs to be the false out of bl.
                self.negate_condition(bl, true);
            }
            if j == 0 {
                // clauseblock needs to be the true out of orblock.
                self.negate_condition(orblock, true);
            }
            self.new_block_condition(bl, orblock);
            return Ok(true);
        }
        Ok(false)
    }

    //
    // (a0) switch-case recovery
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr phoenix.py:1433 _match_acyclic_switch_cases + :2014 _address_computed / Ghidra blockaction.cc:1649 ruleBlockSwitch / kuna match_acyclic_switch_cases)
    /// Find a structured switch region and fold it into a switch node.
    fn match_switch_cases(&mut self) -> Result<bool> {
        let any_switch = self.list.iter().any(|&s| self.is_switch_out(s));
        if !any_switch {
            return Ok(false);
        }
        let n = self.size();
        for i in 0..n {
            let bl = self.component(i);
            if self.try_switch_cases(bl)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra blockaction.cc:1649 ruleBlockSwitch (case/exit topology) + :1607 checkSwitchSkips + kuna is_continue_case)
    ///
    /// The fold: a switch head whose cases each have a single in-edge from
    /// the head and at most one out-edge to a common exit block.  A case
    /// whose only out-edge is a back-edge to a loop head is a *terminal
    /// continue case* (a `continue`) — it neither becomes nor constrains the
    /// exit.  Skip-to-exit edges virtualize to gotos first (progress).
    fn try_switch_cases(&mut self, bl: SId) -> Result<bool> {
        if !self.is_switch_out(bl) {
            return Ok(false);
        }
        let sizeout = self.size_out(bl);
        let mut exitblock: Option<SId> = None;

        let is_continue_case = |s: &Self, c: SId| -> bool {
            s.size_out(c) == 1 && s.is_back_edge_out(c, 0)
        };

        // Find the "obvious" exit block.
        for i in 0..sizeout {
            let curbl = self.get_out(bl, i);
            if is_continue_case(self, curbl) {
                continue; // terminal continue case — never the exit
            }
            if curbl == bl {
                exitblock = Some(curbl); // exit back to top of switch (loop)
                break;
            }
            if self.size_out(curbl) > 1 {
                exitblock = Some(curbl);
                break;
            }
            if self.size_in(curbl) > 1 {
                exitblock = Some(curbl);
                break;
            }
        }

        if exitblock.is_none() {
            // Every immediate block has sizeIn==1 and sizeOut<=1.
            for i in 0..sizeout {
                let curbl = self.get_out(bl, i);
                if is_continue_case(self, curbl) {
                    continue;
                }
                if self.size_in(curbl) > 0 && self.is_goto_in(curbl, 0) {
                    return Ok(false); // in cannot be a goto
                }
                if self.is_switch_out(curbl) {
                    return Ok(false); // resolve nested switch first
                }
                if self.size_out(curbl) == 1 {
                    if self.is_goto_out(curbl, 0) {
                        return Ok(false); // out cannot be a goto
                    }
                    let curout = self.get_out(curbl, 0);
                    match exitblock {
                        Some(e) if e != curout => return Ok(false),
                        Some(_) => {}
                        None => exitblock = Some(curout),
                    }
                }
            }
        } else if let Some(e) = exitblock {
            // A determined exit block: no in/out gotos on it, and every case
            // must fall through only to it.
            for i in 0..self.size_in(e) {
                if self.is_goto_in(e, i) {
                    return Ok(false);
                }
            }
            for i in 0..self.size_out(e) {
                if self.is_goto_out(e, i) {
                    return Ok(false);
                }
            }
            for i in 0..sizeout {
                let curbl = self.get_out(bl, i);
                if curbl == e {
                    continue; // switch can go straight to the exit
                }
                if is_continue_case(self, curbl) {
                    continue;
                }
                if self.size_in(curbl) > 1 {
                    return Ok(false); // only the switch may fall into a case
                }
                if self.size_in(curbl) > 0 && self.is_goto_in(curbl, 0) {
                    return Ok(false);
                }
                if self.size_out(curbl) > 1 {
                    return Ok(false); // at most one exit from a case
                }
                if self.size_out(curbl) == 1 {
                    if self.is_goto_out(curbl, 0) {
                        return Ok(false);
                    }
                    if self.get_out(curbl, 0) != e {
                        return Ok(false); // which must be the exit block
                    }
                }
                if self.is_switch_out(curbl) {
                    return Ok(false); // nested switch first
                }
            }
        }

        // Skip-to-exit handling: virtualize non-default skip edges.
        if !self.check_switch_skips(bl, exitblock)? {
            return Ok(true); // progress was made; re-match next round
        }

        // Collect the case components.
        let mut case_bodies: Vec<(SId, bool)> = Vec::new();
        for i in 0..sizeout {
            let curbl = self.get_out(bl, i);
            if Some(curbl) == exitblock {
                continue; // the exit is not a case
            }
            let is_default = self.is_default_branch(bl, i);
            case_bodies.push((curbl, is_default));
        }
        self.new_block_switch(bl, &case_bodies, exitblock.is_some());
        Ok(true)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra blockaction.cc:1607 checkSwitchSkips)
    /// Convert any non-default switch edge that skips straight to the exit
    /// into a goto.  Returns `false` (and marks the gotos) when such skip
    /// edges exist alongside a default that does not go to the exit — the
    /// switch re-matches next round; otherwise `true`.
    fn check_switch_skips(&mut self, switchbl: SId, exitblock: Option<SId>) -> Result<bool> {
        let exitblock = match exitblock {
            Some(e) => e,
            None => return Ok(true),
        };
        let sizeout = self.size_out(switchbl);
        let mut defaultnottoexit = false;
        let mut anyskiptoexit = false;
        for edgenum in 0..sizeout {
            if self.get_out(switchbl, edgenum) == exitblock {
                if !self.is_default_branch(switchbl, edgenum) {
                    anyskiptoexit = true;
                }
            } else if self.is_default_branch(switchbl, edgenum) {
                defaultnottoexit = true;
            }
        }
        if !anyskiptoexit {
            return Ok(true);
        }
        if !defaultnottoexit {
            return Ok(true);
        }
        for edgenum in 0..sizeout {
            if self.get_out(switchbl, edgenum) == exitblock
                && !self.is_default_branch(switchbl, edgenum)
            {
                self.set_goto_branch(switchbl, edgenum);
            }
        }
        Ok(false)
    }

    //
    // (a) sequence chains
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr phoenix.py:2562 _match_acyclic_sequence / Ghidra ruleBlockCat / kuna match_acyclic_sequence)
    /// Find a chain of single-pred/single-succ components and collapse it
    /// into a sequence.
    fn match_sequence(&mut self) -> Result<bool> {
        let n = self.size();
        for i in 0..n {
            let bl = self.component(i);
            if let Some(nodes) = self.sequence_chain_from(bl) {
                self.new_block_list(&nodes);
                return Ok(true);
            }
        }
        Ok(false)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra block.hh:336 isDecisionOut (f_irreducible|f_back_edge|f_goto_edge))
    /// `isDecisionOut`: a structured, non-back, non-goto edge.
    fn is_decision_out(&self, b: SId, i: usize) -> bool {
        !self.is_goto_out(b, i) && !self.is_back_edge_out(b, i)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra blockaction.cc ruleBlockCat (start + extension guards, isDecisionOut))
    /// If `bl` starts a foldable single-in/single-out sequence chain, return
    /// the chain (>= 2 blocks); else `None`.
    fn sequence_chain_from(&self, bl: SId) -> Option<Vec<SId>> {
        if self.size_out(bl) != 1 || self.is_switch_out(bl) {
            return None;
        }
        // Must be the START of the chain (only merge at the head of a run).
        if self.size_in(bl) == 1 && self.size_out(self.get_in(bl, 0)) == 1 {
            return None;
        }
        let out0 = self.get_out(bl, 0);
        if out0 == bl {
            return None; // self-loop / back edge
        }
        if self.size_in(out0) != 1 {
            return None; // `end` must have a single predecessor
        }
        if !self.is_decision_out(bl, 0) {
            return None; // not a goto or a loopbottom
        }
        if self.is_switch_out(out0) {
            return None; // switch resolves first
        }

        let mut nodes = vec![bl, out0];
        let mut outblock = out0;
        // Extend the chain greedily.
        loop {
            if self.size_out(outblock) != 1 {
                break;
            }
            let nxt = self.get_out(outblock, 0);
            if nxt == nodes[0] {
                break; // no looping back to the chain head
            }
            if self.size_in(nxt) != 1 {
                break;
            }
            if !self.is_decision_out(outblock, 0) {
                break; // don't use a loop bottom
            }
            if self.is_switch_out(nxt) {
                break;
            }
            outblock = nxt;
            nodes.push(outblock);
        }
        Some(nodes)
    }

    //
    // (a2) if / if-else
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr phoenix.py:2599 _match_acyclic_ite / Ghidra ruleBlockIfElse+ruleBlockIf / kuna match_acyclic_ite)
    /// Fold a 2-out condition whose true/false clauses reconverge into an
    /// if-else, or whose true clause exits to the false successor into an
    /// if-then.
    fn match_ite(&mut self) -> Result<bool> {
        let n = self.size();
        for i in 0..n {
            let bl = self.component(i);
            if self.try_if_else(bl)? {
                return Ok(true);
            }
            if self.try_if_then_true_clause(bl)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra blockaction.cc ruleBlockIfElse (structural guards, verbatim))
    /// If/else: a 2-out condition whose true and false clauses each have a
    /// single in-edge and a single out-edge, both exiting to the same block.
    fn try_if_else(&mut self, bl: SId) -> Result<bool> {
        if self.size_out(bl) != 2 || self.is_switch_out(bl) {
            return Ok(false);
        }
        if self.is_goto_out(bl, 0) || self.is_goto_out(bl, 1) {
            return Ok(false);
        }
        let tc = self.get_out(bl, 1); // true out
        let fc = self.get_out(bl, 0); // false out
        if tc == bl || fc == bl {
            return Ok(false); // no loops
        }
        if self.size_in(tc) != 1 || self.size_in(fc) != 1 {
            return Ok(false); // nothing else may hit a clause
        }
        if self.size_out(tc) != 1 || self.size_out(fc) != 1 {
            return Ok(false); // single exit from each clause
        }
        if self.is_switch_out(tc) || self.is_switch_out(fc) {
            return Ok(false);
        }
        if self.is_goto_out(tc, 0) || self.is_goto_out(fc, 0) {
            return Ok(false); // clauses must exit structurally
        }
        let out_t = self.get_out(tc, 0);
        let out_f = self.get_out(fc, 0);
        if out_t == bl || out_t != out_f {
            return Ok(false); // clauses must reconverge
        }
        self.new_block_if_else(bl, tc, fc);
        Ok(true)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra ruleBlockIf i==1 arm / kuna try_if_then_true_clause)
    /// If-then (true-clause only): the true clause is single-in/single-out
    /// and exits to the false successor (the after-if path).  The
    /// false-clause arm needs a condition flip and is left to the virtualize
    /// fallback (honest-partial).
    fn try_if_then_true_clause(&mut self, bl: SId) -> Result<bool> {
        if self.size_out(bl) != 2 || self.is_switch_out(bl) {
            return Ok(false);
        }
        if self.get_out(bl, 0) == bl || self.get_out(bl, 1) == bl {
            return Ok(false); // no loops
        }
        if self.is_goto_out(bl, 0) || self.is_goto_out(bl, 1) {
            return Ok(false);
        }
        // Only the true-edge clause.
        let clause = self.get_out(bl, 1);
        let after = self.get_out(bl, 0);
        if self.size_in(clause) != 1 || self.size_out(clause) != 1 {
            return Ok(false);
        }
        if self.is_switch_out(clause) || self.is_goto_out(clause, 0) {
            return Ok(false);
        }
        if self.get_out(clause, 0) != after {
            return Ok(false); // path after the clause must be the other branch
        }
        self.new_block_if(bl, clause);
        Ok(true)
    }

    //
    // (a3) cyclic schemas — loop recovery by rotation pattern
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr phoenix.py:310 _analyze_cyclic + :329 _match_cyclic_schemas / kuna match_cyclic_schemas)
    ///
    /// Find a natural loop and either fold it (inf-loop / do-while /
    /// while-do, innermost-first) or refine it (mark secondary exits/latches
    /// as gotos) so a later round can fold it.
    fn match_cyclic_schemas(&mut self) -> Result<bool> {
        let heads = self.collect_loop_heads();
        if heads.is_empty() {
            return Ok(false);
        }
        // Try to fold loops already in a foldable structural shape.
        for &head in heads.iter() {
            if !self.list.contains(&head) {
                continue;
            }
            if self.try_fold_loop(head)? {
                return Ok(true);
            }
        }
        // Refine the loops the base schemas could not fold (innermost first).
        let ordered = self.order_loop_heads_innermost_first(&heads);
        for &head in ordered.iter() {
            if !self.list.contains(&head) {
                continue;
            }
            match self.refine_loop_edges(head)? {
                LoopRefineOutcome::Progressed => return Ok(true),
                LoopRefineOutcome::Irreducible | LoopRefineOutcome::NoChange => {}
            }
        }
        Ok(false)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna collect_loop_heads (live components with an f_back_edge in))
    /// Every live component reached by a back-edge (a loop head), in
    /// component order.
    fn collect_loop_heads(&self) -> Vec<SId> {
        let mut heads = Vec::new();
        for &bl in self.list.iter() {
            let sizein = self.size_in(bl);
            for j in 0..sizein {
                if self.is_back_edge_in(bl, j) {
                    heads.push(bl);
                    break;
                }
            }
        }
        heads
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna order_loop_heads_innermost_first (depth-ordered loopbody analog))
    /// Order loop heads innermost-first: a head whose natural-loop body
    /// contains no other live loop head sorts first (stable by descending
    /// index within a class).
    fn order_loop_heads_innermost_first(&self, heads: &[SId]) -> Vec<SId> {
        let head_set: BTreeSet<SId> = heads.iter().copied().collect();
        let mut keyed: Vec<(i32, i32, SId)> = Vec::with_capacity(heads.len());
        for &head in heads.iter() {
            let body = self.natural_loop_body(head);
            let inner = body
                .iter()
                .filter(|&&b| b != head && head_set.contains(&b))
                .count() as i32;
            keyed.push((inner, -self.get_index(head), head));
        }
        keyed.sort();
        keyed.into_iter().map(|(_, _, h)| h).collect()
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: classic natural-loop walk (latches + dominated predecessors) / kuna natural_loop_body)
    /// The natural-loop body of `head`: seed with the latches (back-edge
    /// sources into `head`), then walk predecessors dominated by `head`.
    fn natural_loop_body(&self, head: SId) -> Vec<SId> {
        let idom = self.component_dominators();
        let mut body: Vec<SId> = vec![head];
        let mut in_body: BTreeSet<SId> = BTreeSet::new();
        in_body.insert(head);
        let mut stack: Vec<SId> = Vec::new();
        for j in 0..self.size_in(head) {
            if self.is_back_edge_in(head, j) {
                let latch = self.get_in(head, j);
                if in_body.insert(latch) {
                    body.push(latch);
                    stack.push(latch);
                }
            }
        }
        while let Some(cur) = stack.pop() {
            for j in 0..self.size_in(cur) {
                let p = self.get_in(cur, j);
                if in_body.contains(&p) {
                    continue;
                }
                // Only nodes dominated by head belong to the natural loop.
                if Self::idom_dominates(&idom, head, p) {
                    in_body.insert(p);
                    body.push(p);
                    stack.push(p);
                }
            }
        }
        body
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna build_component_graph (component snapshot for dominators))
    /// Immediate dominators over the live-component snapshot graph, rooted at
    /// a synthetic head reaching every entry component.
    fn component_dominators(&self) -> BTreeMap<SId, SId> {
        let (pool, graph, head, id_of) = self.build_component_graph();
        let mut ridom: BTreeMap<RegionNodeId, RegionNodeId> = BTreeMap::new();
        let _ = immediate_dominators(&pool, &graph, head, &mut ridom);
        let mut block_of: BTreeMap<RegionNodeId, SId> = BTreeMap::new();
        for (&s, &n) in id_of.iter() {
            block_of.insert(n, s);
        }
        let mut idom: BTreeMap<SId, SId> = BTreeMap::new();
        for (n, d) in ridom.iter() {
            if let (Some(&s), Some(&sd)) = (block_of.get(n), block_of.get(d)) {
                idom.insert(s, sd);
            }
        }
        idom
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils.graph.dominates)
    /// Does `dominator` dominate `node` under the component idom map?
    fn idom_dominates(idom: &BTreeMap<SId, SId>, dominator: SId, node: SId) -> bool {
        let mut n: Option<SId> = Some(node);
        while let Some(cur) = n {
            if cur == dominator {
                return true;
            }
            n = match idom.get(&cur) {
                Some(&d) if d != cur => Some(d),
                _ => None,
            };
        }
        false
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra ruleBlockWhileDo/ruleBlockDoWhile/ruleBlockInfLoop / angr phoenix _match_cyclic_{while,dowhile,natural_loop} / kuna try_fold_loop)
    ///
    /// Fold a loop already in a clean structural shape (inside-out):
    ///   * **inf-loop** — a 1-out block whose single edge self-loops
    ///     (`while (true) { ... }`, the degraded while);
    ///   * **do-while** — a 2-out condition with one out-edge self-looping
    ///     (the compiler-rotated bottom test; negated when the self-loop is
    ///     the false edge so the loop executes on TRUE);
    ///   * **while-do** — a 2-out condition with a single-in/single-out
    ///     clause looping back (the top test; negated when the clause is the
    ///     false edge, and rejected when the head is complex — the overflow
    ///     guard — or an interior goto target — the malformed-while-head
    ///     guard — so refinement can produce the inf-loop form instead).
    fn try_fold_loop(&mut self, head: SId) -> Result<bool> {
        let sizeout = self.size_out(head);

        // inf-loop: single out-edge looping back onto head.
        if sizeout == 1 {
            if self.is_goto_out(head, 0) || self.is_switch_out(head) {
                return Ok(false);
            }
            if self.get_out(head, 0) != head {
                return Ok(false);
            }
            let exits = self.loop_exit_addrs(head);
            let head_addr = self.addr_of(head);
            self.new_block_inf_loop(head, head_addr, exits);
            return Ok(true);
        }
        if sizeout != 2 || self.is_switch_out(head) {
            return Ok(false);
        }
        if self.is_goto_out(head, 0) || self.is_goto_out(head, 1) {
            return Ok(false);
        }

        // do-while: one of head's out-edges self-loops to head.  The loop
        // must execute on the TRUE condition; if the self-loop is the false
        // edge (i == 0) we flip the condition.
        for i in 0..2usize {
            if self.get_out(head, i) == head {
                if i == 0 {
                    self.negate_condition(head, true);
                }
                let exits = self.loop_exit_addrs(head);
                self.new_block_do_while(head, exits);
                return Ok(true);
            }
        }

        // while-do: one out-edge is a clause (single-in/single-out) that
        // loops back to head; the other leaves the loop.
        if self.is_interior_goto_target(head) {
            return Ok(false); // malformed while head (continue goto aimed at it)
        }
        // Overflow guard: a complex head cannot render inline as
        // `while (<expr>)` — leave it for refinement (inf-loop form).
        if self.is_complex(head) {
            return Ok(false);
        }
        for i in 0..2usize {
            let clause = self.get_out(head, i);
            if clause == head {
                continue;
            }
            if self.size_in(clause) != 1 || self.size_out(clause) != 1 {
                continue;
            }
            if self.is_switch_out(clause) || self.is_goto_out(clause, 0) {
                continue;
            }
            if self.get_out(clause, 0) != head {
                continue; // clause must loop back to head
            }
            // The clause must be the TRUE out: flip when it sits on the
            // false edge.
            if i == 0 {
                self.negate_condition(head, true);
            }
            let exits = self.loop_exit_addrs(head);
            self.new_block_while_do(head, clause, exits);
            return Ok(true);
        }
        Ok(false)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna loop_exit_addrs via RI successor frontier / structural fallback)
    /// The addresses of the loop's structural exits: with an RI projection
    /// for this head, its successor frontier; else every out-edge target of
    /// body components leaving the natural-loop body (the kept structural
    /// exit AND the virtualized break targets — both classify as exits).
    fn loop_exit_addrs(&self, head: SId) -> BTreeSet<u64> {
        let head_addr = self.addr_of(head);
        if let Some(cached) = self.exit_cache.get(&head_addr) {
            return cached.clone();
        }
        if let Some(l) = self.cyclic_loops.get(&head_addr) {
            // Only a non-degenerate frontier grounds the exits: when the RI
            // absorbed every exit into the body (a whole-function loop), the
            // structural walk is the better ground truth (the same note the
            // reference port makes for the getopt loop).
            if !l.exits.is_empty() {
                return l.exits.clone();
            }
        }
        let body: BTreeSet<SId> = self.natural_loop_body(head).into_iter().collect();
        let mut exits = BTreeSet::new();
        for &b in body.iter() {
            for e in 0..self.size_out(b) {
                let dst = self.get_out(b, e);
                if dst == b || body.contains(&dst) {
                    continue;
                }
                exits.insert(self.addr_of(dst));
            }
        }
        exits
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier _refine_loop_successors_to_guarded_successors + _refine_cyclic_core / kuna refine_loop_edges)
    ///
    /// Refine a not-yet-foldable loop by virtualizing its *secondary*
    /// control edges to gotos: keep ONE structural exit (the normal exit —
    /// the RI frontier's lowest address when grounded, else the most-targeted
    /// destination) and ONE primary latch; virtualize mid-body entry edges
    /// (making the loop single-entry at the head), secondary latches
    /// (`continue`), and every other exit edge (`break`).  Abnormal head
    /// entries are virtualized when the RI identifies the loop; otherwise the
    /// loop is declared irreducible and left to the fallback.
    fn refine_loop_edges(&mut self, head: SId) -> Result<LoopRefineOutcome> {
        let head_addr = self.addr_of(head);
        // The RI projection only grounds the refinement when its frontier is
        // non-degenerate: an RI loop that absorbed every exit (a
        // whole-function body) would misidentify the entire function as the
        // loop — fall back to the structural natural-loop walk.
        let ri_loop = self
            .cyclic_loops
            .get(&head_addr)
            .filter(|l| !l.exits.is_empty())
            .cloned();

        // Live body set + exit-address set: from the RI projection when
        // present, else the structural natural-loop walk.
        let (in_body, exit_addrs): (BTreeSet<SId>, Option<BTreeSet<u64>>) = match &ri_loop {
            Some(l) => {
                let mut s = BTreeSet::new();
                for &comp in self.list.iter() {
                    if l.body.contains(&self.addr_of(comp)) {
                        s.insert(comp);
                    }
                }
                s.insert(head);
                (s, Some(l.exits.clone()))
            }
            None => {
                let body = self.natural_loop_body(head);
                (body.into_iter().collect(), None)
            }
        };

        // (1) Latch edges: back-edges into `head` from a body component.
        let mut latch_edges: Vec<(SId, usize)> = Vec::new();
        {
            for j in 0..self.size_in(head) {
                if self.is_back_edge_in(head, j) {
                    let latch = self.get_in(head, j);
                    for e in 0..self.size_out(latch) {
                        if self.get_out(latch, e) == head
                            && self.is_back_edge_out(latch, e)
                            && !self.is_goto_out(latch, e)
                        {
                            latch_edges.push((latch, e));
                        }
                    }
                }
            }
        }

        // (2) Exit edges (body -> non-body) and mid-body entry edges.
        let mut exit_edges: Vec<(SId, usize, SId)> = Vec::new();
        let mut mid_entry_edges: Vec<(SId, usize)> = Vec::new();
        let body_vec: Vec<SId> = in_body.iter().copied().collect();
        for &bl in body_vec.iter() {
            for e in 0..self.size_out(bl) {
                let dst = self.get_out(bl, e);
                if dst == bl {
                    continue;
                }
                if !in_body.contains(&dst)
                    && !self.is_goto_out(bl, e)
                    && !self.is_back_edge_out(bl, e)
                {
                    exit_edges.push((bl, e, dst));
                }
            }
            if bl != head {
                for j in 0..self.size_in(bl) {
                    let p = self.get_in(bl, j);
                    if !in_body.contains(&p) {
                        for e in 0..self.size_out(p) {
                            if self.get_out(p, e) == bl
                                && !self.is_goto_out(p, e)
                                && !self.is_back_edge_out(p, e)
                            {
                                mid_entry_edges.push((p, e));
                            }
                        }
                    }
                }
            }
        }

        // Cache the FULL exit set now — the secondary exits virtualize away
        // below, and the loop fold later needs every exit address for the
        // break classification.
        if !exit_edges.is_empty() {
            let full: BTreeSet<u64> =
                exit_edges.iter().map(|&(_, _, dst)| self.addr_of(dst)).collect();
            self.exit_cache
                .entry(head_addr)
                .and_modify(|e| e.extend(full.clone()))
                .or_insert(full);
        }

        // (3) Normal exit: RI-grounded (lowest frontier address with a live
        // edge) else most-targeted destination (ties by index).
        let normal_exit = self.choose_normal_exit_grounded(&exit_edges, &exit_addrs);

        // Irreducible at the head (multi-entry that is not a back-edge):
        // virtualize the extra head entries when the RI identifies the loop;
        // otherwise leave the merge to the acyclic schemas.
        if self.head_extra_entries(head, &in_body) > 0 {
            if ri_loop.is_none() {
                return Ok(LoopRefineOutcome::Irreducible);
            }
            let extra = self.head_extra_entry_edges(head, &in_body);
            let mut any = false;
            for (src, e) in extra {
                self.set_goto_branch(src, e);
                any = true;
            }
            return Ok(if any {
                LoopRefineOutcome::Progressed
            } else {
                LoopRefineOutcome::Irreducible
            });
        }

        let mut progressed = false;

        // (3a) Mid-body entries -> goto (single-entry at head).
        for &(src, e) in mid_entry_edges.iter() {
            self.set_goto_branch(src, e);
            progressed = true;
        }
        if progressed {
            return Ok(LoopRefineOutcome::Progressed);
        }

        // (3b) Secondary latches -> goto (continue).  Keep ONE primary latch
        // — a folded switch composite's consolidated back-edge is protected
        // (virtualizing it shatters the switch's continue cases); else the
        // deepest, highest-index source.
        if latch_edges.len() > 1 {
            let primary = latch_edges
                .iter()
                .copied()
                .find(|&(latch, _)| {
                    matches!(
                        self.arena[latch.0 as usize].payload,
                        StructuredNode::Switch { .. }
                    )
                })
                .or_else(|| {
                    latch_edges
                        .iter()
                        .copied()
                        .max_by_key(|&(latch, _)| self.get_index(latch))
                })
                .unwrap();
            for &(latch, e) in latch_edges.iter() {
                if (latch, e) == primary {
                    continue;
                }
                self.set_goto_branch(latch, e);
                progressed = true;
            }
            if progressed {
                return Ok(LoopRefineOutcome::Progressed);
            }
        }

        // (3c) Secondary exits -> goto (break).  Keep ONE structural exit.
        if exit_edges.len() > 1 {
            let keep = self.choose_structural_exit(head, &exit_edges, normal_exit);
            for &(src, e, _dst) in exit_edges.iter() {
                if Some((src, e)) == keep {
                    continue;
                }
                self.set_goto_branch(src, e);
                progressed = true;
            }
        }

        Ok(if progressed {
            LoopRefineOutcome::Progressed
        } else {
            LoopRefineOutcome::NoChange
        })
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna choose_normal_exit_grounded + choose_normal_exit)
    /// Choose the loop's normal exit target: RI-grounded lowest frontier
    /// address with a live edge; else the most-targeted destination, ties by
    /// earliest index.
    fn choose_normal_exit_grounded(
        &self,
        exit_edges: &[(SId, usize, SId)],
        exit_addrs: &Option<BTreeSet<u64>>,
    ) -> Option<SId> {
        if let Some(addrs) = exit_addrs {
            if !addrs.is_empty() {
                let mut best: Option<(u64, SId)> = None;
                for &(_, _, dst) in exit_edges.iter() {
                    let a = self.addr_of(dst);
                    if addrs.contains(&a) {
                        match best {
                            None => best = Some((a, dst)),
                            Some((ba, _)) if a < ba => best = Some((a, dst)),
                            _ => {}
                        }
                    }
                }
                if let Some((_, dst)) = best {
                    return Some(dst);
                }
            }
        }
        self.choose_normal_exit(exit_edges)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr _refine_cyclic_core successor pick / kuna choose_normal_exit)
    /// Most-targeted exit destination, ties by earliest component index.
    fn choose_normal_exit(&self, exit_edges: &[(SId, usize, SId)]) -> Option<SId> {
        if exit_edges.is_empty() {
            return None;
        }
        let mut counts: BTreeMap<SId, i32> = BTreeMap::new();
        for &(_, _, dst) in exit_edges.iter() {
            *counts.entry(dst).or_insert(0) += 1;
        }
        let max = counts.values().copied().max().unwrap_or(0);
        let mut best: Option<SId> = None;
        let mut best_idx = i32::MAX;
        for (&dst, &c) in counts.iter() {
            if c == max {
                let idx = self.get_index(dst);
                if idx < best_idx {
                    best_idx = idx;
                    best = Some(dst);
                }
            }
        }
        best
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna choose_structural_exit)
    /// Pick the single exit edge to keep structural: prefer an exit straight
    /// off the head to the normal exit; else the earliest by
    /// `(src index, dst index)`.
    fn choose_structural_exit(
        &self,
        head: SId,
        exit_edges: &[(SId, usize, SId)],
        normal_exit: Option<SId>,
    ) -> Option<(SId, usize)> {
        if let Some(ne) = normal_exit {
            for &(src, e, dst) in exit_edges.iter() {
                if src == head && dst == ne {
                    return Some((src, e));
                }
            }
        }
        let mut best: Option<(SId, usize, SId)> = None;
        for &(src, e, dst) in exit_edges.iter() {
            match best {
                None => best = Some((src, e, dst)),
                Some((bs, _, bd)) => {
                    let (si, di) = (self.get_index(src), self.get_index(dst));
                    let (bsi, bdi) = (self.get_index(bs), self.get_index(bd));
                    if (si, di) < (bsi, bdi) {
                        best = Some((src, e, dst));
                    }
                }
            }
        }
        best.map(|(s, e, _)| (s, e))
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna head_extra_entries)
    /// Count the head's *extra* entries: non-back-edge in-edges from outside
    /// the body that are not gotos (one preheader entry is normal).
    fn head_extra_entries(&self, head: SId, in_body: &BTreeSet<SId>) -> i32 {
        let mut entries = 0;
        for j in 0..self.size_in(head) {
            if self.is_back_edge_in(head, j) {
                continue;
            }
            let p = self.get_in(head, j);
            if !in_body.contains(&p) && !self.is_goto_in(head, j) {
                entries += 1;
            }
        }
        if entries > 1 {
            entries - 1
        } else {
            0
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna head_extra_entry_edges)
    /// The head's extra (abnormal) entry edges, keeping the lowest-index
    /// predecessor as the structural preheader.
    fn head_extra_entry_edges(&self, head: SId, in_body: &BTreeSet<SId>) -> Vec<(SId, usize)> {
        let mut preds: Vec<SId> = Vec::new();
        for j in 0..self.size_in(head) {
            if self.is_back_edge_in(head, j) || self.is_goto_in(head, j) {
                continue;
            }
            let p = self.get_in(head, j);
            if !in_body.contains(&p) {
                preds.push(p);
            }
        }
        if preds.len() <= 1 {
            return Vec::new();
        }
        let keep = preds.iter().copied().min_by_key(|&p| self.get_index(p));
        let mut res: Vec<(SId, usize)> = Vec::new();
        for &p in preds.iter() {
            if Some(p) == keep {
                continue;
            }
            for e in 0..self.size_out(p) {
                if self.get_out(p, e) == head && !self.is_goto_out(p, e) {
                    res.push((p, e));
                }
            }
        }
        res
    }

    //
    // (b) wrap already-marked goto edges
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Ghidra ruleBlockGoto / kuna rule_block_goto)
    /// If any component has an out-edge already flagged goto (by a prior
    /// virtualization round), wrap it into a goto node (plain trailing goto,
    /// if-goto when the true edge is the goto, or an inline case-goto on a
    /// switch head).
    fn rule_block_goto(&mut self) -> Result<bool> {
        let n = self.size();
        for i in 0..n {
            let bl = self.component(i);
            let sizeout = self.size_out(bl);
            for e in 0..sizeout {
                if !self.is_goto_out(bl, e) {
                    continue;
                }
                if self.is_switch_out(bl) {
                    // Multi-goto on a switch head: inline the case goto.
                    let target = self.get_out(bl, e);
                    let target_addr = self.addr_of(target);
                    let payload = self.take_payload(bl);
                    self.arena[bl.0 as usize].payload = StructuredNode::Seq {
                        body: vec![
                            payload,
                            StructuredNode::Goto { target_addr, kind: GotoKind::Plain },
                        ],
                    };
                    self.unlink(bl, target);
                    return Ok(true);
                }
                if sizeout == 2 {
                    // Only when the TRUE edge is the goto (matching
                    // ruleBlockGoto's precondition).
                    if self.is_goto_out(bl, 1) {
                        self.new_block_goto(bl, 1);
                        return Ok(true);
                    }
                    continue;
                }
                if sizeout == 1 {
                    self.new_block_goto(bl, e);
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    //
    // (c) last resort — edge virtualization with SAILR ordering
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr phoenix.py _last_resort_refinement + sailr.py _order_virtualizable_edges / kuna virtualize_one_edge)
    ///
    /// Pick the "best" remaining structured edge and mark it a goto.
    /// Candidates: structured (non-goto) out-edges of live components,
    /// excluding self-loops.  Ordering: the dominance-tiered buckets
    /// (crossing — neither endpoint dominates the other — first, then
    /// secondary — dst dominates src), and within the bucket H1 sibling
    /// count, H2 post-dominator count (capped), H3 return-edge, base
    /// post-order tiebreak.
    fn virtualize_one_edge(&mut self) -> Result<bool> {
        let mut candidates: Vec<VEdge> = Vec::new();
        for &src in self.list.iter() {
            for e in 0..self.size_out(src) {
                if self.is_goto_out(src, e) {
                    continue; // already virtualized
                }
                let dst = self.get_out(src, e);
                if dst == src {
                    continue; // self-loop
                }
                candidates.push(VEdge { src, edge: e, dst });
            }
        }
        if candidates.is_empty() {
            return Ok(false);
        }
        let best = self.order_virtualizable_edges_sailr(&candidates);
        self.set_goto_branch(best.src, best.edge);
        Ok(true)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr sailr.py _order_virtualizable_edges + phoenix.py _last_resort_refinement bucketing / kuna order_virtualizable_edges_sailr)
    /// The SAILR ordering: dominance-tier the candidates over the component
    /// snapshot (crossing / secondary; `other` edges are never chosen), then
    /// order within the bucket by H1/H2/H3 + base.
    fn order_virtualizable_edges_sailr<'e>(&self, candidates: &'e [VEdge]) -> &'e VEdge {
        let (pool, graph, head, id_of) = self.build_component_graph();
        let mut fdom_map: BTreeMap<RegionNodeId, RegionNodeId> = BTreeMap::new();
        let _ = immediate_dominators(&pool, &graph, head, &mut fdom_map);

        let mut crossing: Vec<&VEdge> = Vec::new();
        let mut secondary: Vec<&VEdge> = Vec::new();
        for e in candidates {
            let sn = id_of[&e.src];
            let dn = id_of[&e.dst];
            let s_dom_d = dominates_lookup(&fdom_map, sn, dn);
            let d_dom_s = dominates_lookup(&fdom_map, dn, sn);
            if !s_dom_d && !d_dom_s {
                crossing.push(e); // all_edges_wo_dominance
            } else if !s_dom_d {
                secondary.push(e); // dst dominates src
            }
            // else: `other` — never virtualized here
        }

        let bucket: Vec<&VEdge> = if !crossing.is_empty() {
            crossing
        } else if !secondary.is_empty() {
            secondary
        } else {
            // No crossing/secondary edge: fall back to the flat ordering so
            // the structurer still makes progress.
            return self.order_virtualizable_edges_flat(candidates);
        };
        self.sailr_order_within_bucket(&pool, &graph, &id_of, &bucket)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr sailr.py H1->H2->H3->_chick_order_edges / kuna sailr_order_within_bucket)
    /// H1 (sibling count) -> H2 (post-dom count, capped) -> H3 (return edge)
    /// -> base (post-order node_seq, in/out degrees, addresses).
    fn sailr_order_within_bucket<'e>(
        &self,
        pool: &NodePool,
        graph: &RegionGraph,
        id_of: &BTreeMap<SId, RegionNodeId>,
        edges: &[&'e VEdge],
    ) -> &'e VEdge {
        if edges.len() == 1 {
            return edges[0];
        }
        // Stable base order by (src addr, dst addr).
        let mut best: Vec<&VEdge> = edges.to_vec();
        best.sort_by_key(|e| (self.addr_of(e.src), self.addr_of(e.dst)));

        // H1: minimum sibling count = in_degree(dst) - 1 over the snapshot.
        let sib = |e: &VEdge| -> i32 { graph.size_in(id_of[&e.dst]).unwrap_or(0) - 1 };
        let with_sib: Vec<&VEdge> = best.iter().copied().filter(|e| sib(e) > 0).collect();
        if !with_sib.is_empty() {
            let min_sib = with_sib.iter().map(|e| sib(e)).min().unwrap();
            let h1: Vec<&VEdge> =
                with_sib.iter().copied().filter(|e| sib(e) == min_sib).collect();
            if h1.len() == 1 {
                return h1[0];
            }
            best = h1;
        }

        // H2: post-dominator count (capped).
        if best.len() as i32 <= POSTDOM_MAX_EDGES && graph.num_nodes() <= POSTDOM_MAX_GRAPH_SIZE {
            if let Some(h2) = self.sailr_h2_postdom(pool, graph, id_of, &best) {
                if h2.len() == 1 {
                    return h2[0];
                }
                if !h2.is_empty() {
                    best = h2;
                }
            }
        }

        // H3: prefer an edge whose destination is a simple return.
        let h3: Vec<&VEdge> = best
            .iter()
            .copied()
            .filter(|e| self.arena[e.dst.0 as usize].simple_return)
            .collect();
        if h3.len() == 1 {
            return h3[0];
        }
        if !h3.is_empty() {
            best = h3;
        }

        // Base tiebreak: post-order node_seq (closer to head first), then
        // dst in-degree, src out-degree, addresses.
        let node_seq = self.compute_node_seq(pool, graph, id_of);
        let mut sorted: Vec<&VEdge> = best.clone();
        sorted.sort_by(|a, b| {
            let ka = (
                std::cmp::Reverse(node_seq.get(&a.dst).copied().unwrap_or(0)),
                graph.size_in(id_of[&a.dst]).unwrap_or(0),
                graph.size_out(id_of[&a.src]).unwrap_or(0),
                self.addr_of(a.dst),
                self.addr_of(a.src),
            );
            let kb = (
                std::cmp::Reverse(node_seq.get(&b.dst).copied().unwrap_or(0)),
                graph.size_in(id_of[&b.dst]).unwrap_or(0),
                graph.size_out(id_of[&b.src]).unwrap_or(0),
                self.addr_of(b.dst),
                self.addr_of(b.src),
            );
            ka.cmp(&kb)
        });
        sorted[0]
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr sailr.py H2 postdom count / kuna sailr_h2_postdom)
    /// H2: for each candidate edge, remove it, recompute post-dominators over
    /// the snapshot, and count strict post-dominator relationships; keep the
    /// edges whose removal yields the MOST post-dominators.
    fn sailr_h2_postdom<'e>(
        &self,
        pool: &NodePool,
        graph: &RegionGraph,
        id_of: &BTreeMap<SId, RegionNodeId>,
        edges: &[&'e VEdge],
    ) -> Option<Vec<&'e VEdge>> {
        let real_nodes: Vec<RegionNodeId> = id_of.values().copied().collect();
        let mut counts: Vec<(usize, &VEdge)> = Vec::with_capacity(edges.len());
        let mut max_count: usize = 0;
        for &e in edges {
            // Build the reversed graph of (snapshot minus edge src->dst) with
            // a synthetic tail every original sink connects to.
            let mut lpool = pool.clone();
            let tail = lpool.make(NodeKind::Dummy, u64::MAX, u32::MAX);
            let mut rev = RegionGraph::new();
            for &nid in &real_nodes {
                rev.add_node(&lpool, nid);
            }
            rev.add_node(&lpool, tail);
            let removed = (id_of[&e.src], id_of[&e.dst]);
            for &src in &real_nodes {
                let succs: Vec<RegionNodeId> = graph.get_succs(src).ok()?.to_vec();
                let mut has_succ = false;
                for dst in succs {
                    if (src, dst) == removed {
                        continue;
                    }
                    has_succ = true;
                    rev.add_edge(&lpool, dst, src); // reversed
                }
                if !has_succ {
                    rev.add_edge(&lpool, tail, src);
                }
            }
            let mut idom: BTreeMap<RegionNodeId, RegionNodeId> = BTreeMap::new();
            if immediate_dominators(&lpool, &rev, tail, &mut idom).is_err() {
                return None;
            }
            let mut cnt = 0usize;
            for &nid in &real_nodes {
                if let Some(&d) = idom.get(&nid) {
                    if d != nid && d != tail {
                        cnt += 1;
                    }
                }
            }
            if cnt > max_count {
                max_count = cnt;
            }
            counts.push((cnt, e));
        }
        let winners: Vec<&VEdge> = counts
            .into_iter()
            .filter(|(c, _)| *c == max_count)
            .map(|(_, e)| e)
            .collect();
        if winners.is_empty() {
            None
        } else {
            Some(winners)
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr _chick_order_edges node_seq / kuna order_virtualizable_edges (flat fallback))
    /// The flat fallback ordering (H1 + H3 + address keys), used when no
    /// crossing/secondary bucket exists.
    fn order_virtualizable_edges_flat<'e>(&self, edges: &'e [VEdge]) -> &'e VEdge {
        let sibling_count = |e: &VEdge| -> i32 { self.size_in(e.dst) as i32 - 1 };
        let min_siblings = edges.iter().map(sibling_count).min().unwrap_or(0);
        let mut best: Vec<&VEdge> = edges
            .iter()
            .filter(|e| sibling_count(e) == min_siblings)
            .collect();
        if best.len() == 1 {
            return best[0];
        }
        let returns: Vec<&VEdge> = best
            .iter()
            .copied()
            .filter(|e| self.arena[e.dst.0 as usize].simple_return)
            .collect();
        if returns.len() == 1 {
            return returns[0];
        }
        if !returns.is_empty() {
            best = returns;
        }
        best.sort_by(|a, b| {
            let ka = (
                self.size_in(a.dst),
                self.size_out(a.src),
                self.addr_of(a.dst),
                self.addr_of(a.src),
            );
            let kb = (
                self.size_in(b.dst),
                self.size_out(b.src),
                self.addr_of(b.dst),
                self.addr_of(b.src),
            );
            ka.cmp(&kb)
        });
        best[0]
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna build_component_graph)
    /// The live-component snapshot as a region graph (nodes = components,
    /// edges = every component out-edge, synthetic head reaching all
    /// entries).
    #[allow(clippy::type_complexity)]
    fn build_component_graph(
        &self,
    ) -> (NodePool, RegionGraph, RegionNodeId, BTreeMap<SId, RegionNodeId>) {
        let mut pool = NodePool::new();
        let mut graph = RegionGraph::new();
        let mut id_of: BTreeMap<SId, RegionNodeId> = BTreeMap::new();
        let n = self.size();
        for i in 0..n {
            let c = self.component(i);
            let nid = pool.make(NodeKind::Block, self.addr_of(c), i as u32);
            graph.add_node(&pool, nid);
            id_of.insert(c, nid);
        }
        for i in 0..n {
            let c = self.component(i);
            for e in 0..self.size_out(c) {
                let dst = self.get_out(c, e);
                if let (Some(&sn), Some(&dn)) = (id_of.get(&c), id_of.get(&dst)) {
                    graph.add_edge(&pool, sn, dn);
                }
            }
        }
        let head = pool.make(NodeKind::Dummy, 0, u32::MAX);
        graph.add_node(&pool, head);
        for i in 0..n {
            let c = self.component(i);
            if let Some(&nid) = id_of.get(&c) {
                if graph.size_in(nid).unwrap_or(0) == 0 {
                    graph.add_edge(&pool, head, nid);
                }
            }
        }
        (pool, graph, head, id_of)
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna compute_node_seq)
    /// Post-order node_seq over the snapshot graph (the base tiebreak):
    /// larger for nodes earlier in post-order (closer to the head).
    fn compute_node_seq(
        &self,
        pool: &NodePool,
        graph: &RegionGraph,
        id_of: &BTreeMap<SId, RegionNodeId>,
    ) -> BTreeMap<SId, i32> {
        let mut head = None;
        let mut all: Vec<RegionNodeId> = Vec::new();
        graph.get_nodes(&mut all);
        for nid in all {
            if graph.size_in(nid).unwrap_or(0) == 0 {
                head = Some(nid);
                break;
            }
        }
        let mut seq: BTreeMap<SId, i32> = BTreeMap::new();
        let head = match head {
            Some(h) => h,
            None => return seq,
        };
        let mut postorder: Vec<RegionNodeId> = Vec::new();
        if dfs_postorder_deterministic(pool, graph, head, &mut postorder).is_err() {
            return seq;
        }
        let mut block_of: BTreeMap<RegionNodeId, SId> = BTreeMap::new();
        for (&bl, &nid) in id_of {
            block_of.insert(nid, bl);
        }
        for (pi, &nid) in postorder.iter().enumerate() {
            if let Some(&bl) = block_of.get(&nid) {
                seq.insert(bl, pi as i32 + 1);
            }
        }
        seq
    }

    //
    // Post-pass: break/continue classification
    //

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr _rewrite_conditional_jumps_to_breaks + _rewrite_jumps_to_continues / Ghidra scopeBreak)
    ///
    /// Classify the plain gotos inside the recovered tree against the open
    /// loop scopes: a goto targeting a loop's exit address (innermost first)
    /// becomes `Break`; one targeting the loop head becomes `Continue`;
    /// everything else stays `Plain`.
    fn classify_gotos(&self, node: &mut StructuredNode, loops: &mut Vec<(u64, BTreeSet<u64>)>) {
        match node {
            StructuredNode::Seq { body } => {
                for n in body.iter_mut() {
                    self.classify_gotos(n, loops);
                }
            }
            StructuredNode::If { then, .. } => self.classify_gotos(then, loops),
            StructuredNode::IfElse { then, els, .. } => {
                self.classify_gotos(then, loops);
                self.classify_gotos(els, loops);
            }
            StructuredNode::Switch { cases, .. } => {
                for c in cases.iter_mut() {
                    self.classify_gotos(&mut c.body, loops);
                }
            }
            StructuredNode::WhileDo { body, head_addr, exit_addrs, .. } => {
                loops.push((*head_addr, exit_addrs.clone()));
                self.classify_gotos(body, loops);
                loops.pop();
            }
            StructuredNode::DoWhile { body, head_addr, exit_addrs, .. } => {
                loops.push((*head_addr, exit_addrs.clone()));
                self.classify_gotos(body, loops);
                loops.pop();
            }
            StructuredNode::InfLoop { body, head_addr, exit_addrs, .. } => {
                loops.push((*head_addr, exit_addrs.clone()));
                self.classify_gotos(body, loops);
                loops.pop();
            }
            StructuredNode::Goto { target_addr, kind } => {
                // Innermost loop first.
                for (head, exits) in loops.iter().rev() {
                    if exits.contains(target_addr) {
                        *kind = GotoKind::Break;
                        return;
                    }
                    if *target_addr == *head {
                        *kind = GotoKind::Continue;
                        return;
                    }
                }
                *kind = GotoKind::Plain;
            }
            _ => {}
        }
    }
}

// RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils.graph.dominates on an idom map)
/// Does `dominator` dominate `node` under a raw idom map over RegionNodeIds?
fn dominates_lookup(
    idom: &BTreeMap<RegionNodeId, RegionNodeId>,
    dominator: RegionNodeId,
    node: RegionNodeId,
) -> bool {
    let mut n: Option<RegionNodeId> = Some(node);
    while let Some(cur) = n {
        if cur == dominator {
            return true;
        }
        n = match idom.get(&cur) {
            Some(&d) if d != cur => Some(d),
            _ => None,
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: build a `SailrInput` from `(addr, complex)` blocks and
    /// `(src, dst)` edge pairs, tracking the entry index.
    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna region_structurer test seeding)
    struct In {
        input: SailrInput,
    }

    impl In {
        fn new(blocks: &[(u64, bool)], edges: &[(usize, usize)], entry: usize) -> In {
            let mut input = SailrInput { entry, ..Default::default() };
            for (i, &(addr, complex)) in blocks.iter().enumerate() {
                input.blocks.push(CfgBlock {
                    addr,
                    complex,
                    switch: false,
                    simple_return: false,
                    external: Some(i),
                });
            }
            for &(s, d) in edges {
                input.edges.push(CfgEdge::new(s, d));
            }
            In { input }
        }

        fn run(&self) -> StructuredNode {
            let mut st = Structurer::new(&self.input).unwrap();
            st.structure().unwrap().expect("structuring must converge")
        }
    }

    // ------------------------------------------------------------------
    // sequence / if / if-else
    // ------------------------------------------------------------------

    #[test]
    fn sequence_chain_folds() {
        // A -> B -> C (single-in/single-out run).
        let inp = In::new(
            &[(0x10, false), (0x20, false), (0x30, false)],
            &[(0, 1), (1, 2)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => {
                assert_eq!(body.len(), 3);
                assert_eq!(block_addr(&body[0]), 0x10);
                assert_eq!(block_addr(&body[1]), 0x20);
                assert_eq!(block_addr(&body[2]), 0x30);
            }
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn if_else_diamond_folds() {
        // cond: true -> then; false -> else; both -> join.
        // out[0] = false edge = else, out[1] = true edge = then.
        let inp = In::new(
            &[(0x10, false), (0x20, false), (0x30, false), (0x40, false)],
            &[(0, 2), (0, 1), (1, 3), (2, 3)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => {
                assert_eq!(body.len(), 2);
                match &body[0] {
                    StructuredNode::IfElse { cond, then, els } => {
                        assert_eq!(leaf_addr(cond), 0x10);
                        assert_eq!(block_addr(then), 0x20); // true clause
                        assert_eq!(block_addr(els), 0x30); // false clause
                    }
                    other => panic!("expected IfElse, got {other:?}"),
                }
                assert_eq!(block_addr(&body[1]), 0x40);
            }
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn if_then_true_clause_folds() {
        // cond: true -> clause -> after; false -> after.
        let inp = In::new(
            &[(0x10, false), (0x20, false), (0x30, false)],
            &[(0, 2), (0, 1), (1, 2)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => {
                assert_eq!(body.len(), 2);
                match &body[0] {
                    StructuredNode::If { cond, then } => {
                        assert_eq!(leaf_addr(cond), 0x10);
                        assert_eq!(block_addr(then), 0x20);
                    }
                    other => panic!("expected If, got {other:?}"),
                }
            }
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // short-circuit diamonds (&& / ||)
    // ------------------------------------------------------------------

    #[test]
    fn short_circuit_or_diamond_folds() {
        // `if (A || B) X else Y`:
        //   A: false -> B, true -> X ; B: false -> Y, true -> X ; X,Y -> J.
        let inp = In::new(
            &[
                (0x10, false), // A
                (0x20, false), // B
                (0x30, false), // X
                (0x40, false), // Y
                (0x50, false), // J
            ],
            &[(0, 1), (0, 2), (1, 3), (1, 2), (2, 4), (3, 4)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => match &body[0] {
                StructuredNode::IfElse { cond, then, els } => {
                    // The composite condition is `A || B` (B sits on A's
                    // false out: no negation fires).
                    match cond {
                        CondExpr::Or(a, b) => {
                            assert_eq!(leaf_addr(a), 0x10);
                            assert!(!leaf_invert(a));
                            assert_eq!(leaf_addr(b), 0x20);
                            assert!(!leaf_invert(b));
                        }
                        other => panic!("expected Or composite, got {other:?}"),
                    }
                    assert_eq!(block_addr(then), 0x30); // X (true clause)
                    assert_eq!(block_addr(els), 0x40); // Y (false clause)
                }
                other => panic!("expected IfElse over the composite, got {other:?}"),
            },
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn short_circuit_and_diamond_folds() {
        // `if (A && B) X else Y` (De Morgan form):
        //   A: false -> Y, true -> B ; B: false -> Y, true -> X ; X,Y -> J.
        // Mechanical fold: both conditions negate, composite = `!A || !B`,
        // composite true-out = Y (the source else).
        let inp = In::new(
            &[
                (0x10, false), // A
                (0x20, false), // B
                (0x30, false), // X
                (0x40, false), // Y
                (0x50, false), // J
            ],
            &[(0, 3), (0, 1), (1, 3), (1, 2), (2, 4), (3, 4)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => match &body[0] {
                StructuredNode::IfElse { cond, .. } => match cond {
                    CondExpr::Or(a, b) => {
                        assert_eq!(leaf_addr(a), 0x10);
                        assert!(leaf_invert(a), "A negated by the i==1 orientation");
                        assert_eq!(leaf_addr(b), 0x20);
                        assert!(leaf_invert(b), "B negated by the j==0 orientation");
                    }
                    other => panic!("expected Or composite (De Morgan), got {other:?}"),
                },
                other => panic!("expected IfElse over the composite, got {other:?}"),
            },
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn short_circuit_skips_complex_orblock() {
        // Same diamond but B is complex (statements before the branch):
        // the fold must decline (ruleBlockOr's isComplex guard).
        let inp = In::new(
            &[
                (0x10, false),
                (0x20, true), // complex B
                (0x30, false),
                (0x40, false),
                (0x50, false),
            ],
            &[(0, 1), (0, 2), (1, 3), (1, 2), (2, 4), (3, 4)],
            0,
        );
        let tree = inp.run();
        // No Condition composite anywhere in the tree.
        assert!(!has_condition(&tree));
    }

    // ------------------------------------------------------------------
    // loop recovery by rotation pattern
    // ------------------------------------------------------------------

    #[test]
    fn while_do_top_tested_folds() {
        // head: false -> exit, true -> body; body -> head (back edge).
        let inp = In::new(
            &[(0x10, false), (0x20, false), (0x30, false)],
            &[(0, 2), (0, 1), (1, 0)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => {
                assert_eq!(body.len(), 2);
                match &body[0] {
                    StructuredNode::WhileDo { kind, cond, body, head_addr, exit_addrs, .. } => {
                        assert_eq!(*kind, LoopKind::While);
                        assert_eq!(leaf_addr(cond), 0x10);
                        assert!(!leaf_invert(cond)); // clause on the true out: no flip
                        assert_eq!(block_addr(body), 0x20);
                        assert_eq!(*head_addr, 0x10);
                        assert!(exit_addrs.contains(&0x30));
                    }
                    other => panic!("expected WhileDo, got {other:?}"),
                }
                assert_eq!(block_addr(&body[1]), 0x30);
            }
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn while_do_false_edge_clause_negates() {
        // head: TRUE -> exit, FALSE -> body (the flipped rotation): the fold
        // negates so the clause rides the true out.
        let inp = In::new(
            &[(0x10, false), (0x20, false), (0x30, false)],
            &[(0, 1), (0, 2), (1, 0)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => match &body[0] {
                StructuredNode::WhileDo { cond, .. } => {
                    assert_eq!(leaf_addr(cond), 0x10);
                    assert!(leaf_invert(cond), "flipped rotation negates the condition");
                }
                other => panic!("expected WhileDo, got {other:?}"),
            },
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn do_while_rotated_true_self_loop_folds() {
        // O2-rotated while: body: false -> exit, true -> body (self).
        // entry -> body.
        let inp = In::new(
            &[(0x10, false), (0x20, false), (0x30, false)],
            &[(0, 1), (1, 2), (1, 1)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => {
                assert_eq!(body.len(), 3);
                assert_eq!(block_addr(&body[0]), 0x10); // entry precedes the loop
                match &body[1] {
                    StructuredNode::DoWhile { kind, cond, body, head_addr, .. } => {
                        assert_eq!(*kind, LoopKind::DoWhile);
                        assert_eq!(leaf_addr(cond), 0x20);
                        assert!(!leaf_invert(cond)); // self-loop on the true edge
                        assert_eq!(block_addr(body), 0x20);
                        assert_eq!(*head_addr, 0x20);
                    }
                    other => panic!("expected DoWhile, got {other:?}"),
                }
                assert_eq!(block_addr(&body[2]), 0x30);
            }
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn do_while_rotated_false_self_loop_negates() {
        // body: TRUE -> exit, FALSE -> body (self): negated so the loop
        // executes on TRUE.
        let inp = In::new(
            &[(0x10, false), (0x20, false), (0x30, false)],
            &[(0, 1), (1, 1), (1, 2)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => match &body[1] {
                StructuredNode::DoWhile { cond, .. } => {
                    assert_eq!(leaf_addr(cond), 0x20);
                    assert!(leaf_invert(cond));
                }
                other => panic!("expected DoWhile, got {other:?}"),
            },
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn inf_loop_degraded_while_folds() {
        // while(true) { body }: body self-loops with no exit at all.
        let inp = In::new(&[(0x10, false), (0x20, false)], &[(0, 1), (1, 1)], 0);
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => match &body[1] {
                StructuredNode::InfLoop { kind, body, head_addr, .. } => {
                    assert_eq!(*kind, LoopKind::Inf);
                    assert_eq!(block_addr(body), 0x20);
                    assert_eq!(*head_addr, 0x20);
                }
                other => panic!("expected InfLoop, got {other:?}"),
            },
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn multi_exit_loop_refines_to_break() {
        // head: false -> exit1, true -> body; body: false -> head (back),
        // true -> exit2.  Two exits: refinement virtualizes body->exit2 as a
        // break goto, keeps head->exit1 structural, folds a while-do whose
        // body ends in `break`.
        let inp = In::new(
            &[
                (0x10, false), // head
                (0x20, false), // body
                (0x30, false), // exit1
                (0x40, false), // exit2
            ],
            &[(0, 2), (0, 1), (1, 0), (1, 3)],
            0,
        );
        let tree = inp.run();
        match tree {
            StructuredNode::Seq { body } => {
                assert_eq!(body.len(), 2);
                match &body[0] {
                    StructuredNode::WhileDo { cond, body, exit_addrs, .. } => {
                        assert_eq!(leaf_addr(cond), 0x10);
                        assert!(exit_addrs.contains(&0x30) && exit_addrs.contains(&0x40));
                        // The loop body carries a Break to the virtualized exit.
                        match &**body {
                            StructuredNode::Seq { body } => {
                                assert_eq!(block_addr(&body[0]), 0x20);
                                match &body[1] {
                                    StructuredNode::Goto { target_addr, kind } => {
                                        assert_eq!(*target_addr, 0x40);
                                        assert_eq!(*kind, GotoKind::Break);
                                    }
                                    other => panic!("expected Break goto, got {other:?}"),
                                }
                            }
                            other => panic!("expected body Seq, got {other:?}"),
                        }
                    }
                    other => panic!("expected WhileDo, got {other:?}"),
                }
            }
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn multi_latch_loop_refines_to_continue() {
        // head with two distinct latch blocks: head: true->b1, false->exit;
        // b1: false->latch-a, true->latch-b; both latches -> head.
        let inp = In::new(
            &[
                (0x10, false), // head
                (0x20, false), // b1
                (0x30, false), // latch-a (false arm of b1)
                (0x50, false), // latch-b (true arm of b1)
                (0x40, false), // exit
            ],
            &[(0, 4), (0, 1), (1, 2), (1, 3), (2, 0), (3, 0)],
            0,
        );
        let tree = inp.run();
        // The loop must fold (as a loop node, not gotos everywhere).
        assert!(has_loop(&tree), "loop recovered");
        // At most the one secondary latch continue remains.
        let mut continues = 0;
        count_gotos(&tree, GotoKind::Continue, &mut continues);
        assert!(continues <= 1, "at most one secondary-latch continue, got {continues}");
    }

    // ------------------------------------------------------------------
    // switch recovery
    // ------------------------------------------------------------------

    #[test]
    fn switch_cases_fold() {
        // head (switch-out): c1, c2, default -> cd; all cases -> exit.
        let mut input = SailrInput { entry: 0, ..Default::default() };
        let addrs = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        for (i, &a) in addrs.iter().enumerate() {
            input.blocks.push(CfgBlock {
                addr: a,
                complex: false,
                switch: i == 0,
                simple_return: false,
                external: Some(i),
            });
        }
        // head out-edges: c1, c2, cd (default).
        input.edges.push(CfgEdge::new(0, 1));
        input.edges.push(CfgEdge::new(0, 2));
        input.edges.push(CfgEdge { src: 0, dst: 3, default_edge: true });
        // cases fall through to the common exit.
        input.edges.push(CfgEdge::new(1, 4));
        input.edges.push(CfgEdge::new(2, 4));
        input.edges.push(CfgEdge::new(3, 4));
        // exit -> after.
        input.edges.push(CfgEdge::new(4, 5));

        let mut st = Structurer::new(&input).unwrap();
        let tree = st.structure().unwrap().expect("switch must fold");
        match tree {
            StructuredNode::Seq { body } => {
                // [Switch, exit-block, after-block]
                assert_eq!(body.len(), 3);
                match &body[0] {
                    StructuredNode::Switch { cases, has_exit, .. } => {
                        assert_eq!(cases.len(), 3);
                        assert!(*has_exit);
                        let targets: Vec<u64> = cases.iter().map(|c| c.target_addr).collect();
                        assert!(targets.contains(&0x20));
                        assert!(targets.contains(&0x30));
                        assert!(targets.contains(&0x40));
                        let defaults = cases.iter().filter(|c| c.is_default).count();
                        assert_eq!(defaults, 1);
                    }
                    other => panic!("expected Switch, got {other:?}"),
                }
                assert_eq!(block_addr(&body[1]), 0x50);
                assert_eq!(block_addr(&body[2]), 0x60);
            }
            other => panic!("expected Seq, got {other:?}"),
        }
    }

    #[test]
    fn switch_in_loop_continue_case_folds() {
        // The getopt pattern: loop head -> switch head; switch cases either
        // continue (back edge to the loop head) or fall to the switch exit;
        // the switch exit loops back; the loop head's false edge exits.
        let mut input = SailrInput { entry: 0, ..Default::default() };
        let addrs = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        for (i, &a) in addrs.iter().enumerate() {
            input.blocks.push(CfgBlock {
                addr: a,
                complex: false,
                switch: i == 1,
                simple_return: false,
                external: Some(i),
            });
        }
        // head(0x10): false -> exit(0x60), true -> switch(0x20).
        input.edges.push(CfgEdge::new(0, 5));
        input.edges.push(CfgEdge::new(0, 1));
        // switch(0x20): c1 (0x30) and default (0x40).
        input.edges.push(CfgEdge::new(1, 2));
        input.edges.push(CfgEdge { src: 1, dst: 3, default_edge: true });
        // c1: continue (terminal back edge to the loop head).
        input.edges.push(CfgEdge::new(2, 0));
        // default: falls through to the loop latch (back edge to the head).
        input.edges.push(CfgEdge::new(3, 0));

        let mut st = Structurer::new(&input).unwrap();
        let tree = st.structure().unwrap().expect("switch-in-loop must fold");
        // A loop node must exist wrapping the switch.
        assert!(has_loop(&tree), "loop recovered around the switch");
        assert!(has_switch(&tree), "switch recovered inside the loop");
    }

    // ------------------------------------------------------------------
    // goto fallback (the honest-partial escape)
    // ------------------------------------------------------------------

    #[test]
    fn unstructured_jump_falls_back_to_goto() {
        // A jump into the middle of a diamond: entry -> a / e; a -> b, c;
        // b -> d; c -> d; e jumps into b.
        let inp = In::new(
            &[
                (0x10, false), // entry
                (0x20, false), // a
                (0x30, false), // b
                (0x40, false), // c
                (0x50, false), // d
                (0x60, false), // e (jumps into b)
            ],
            &[(0, 1), (1, 2), (1, 3), (2, 4), (3, 4), (0, 5), (5, 2)],
            0,
        );
        let tree = inp.run();
        // The tree still forms (virtualize fallback), with at least one
        // goto for the unstructured entry edge.
        let mut plain = 0;
        count_gotos(&tree, GotoKind::Plain, &mut plain);
        let mut brk = 0;
        count_gotos(&tree, GotoKind::Break, &mut brk);
        assert!(plain + brk >= 1, "the jump into the diamond virtualizes to a goto");
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: test helper)
    fn block_addr(n: &StructuredNode) -> u64 {
        match n {
            StructuredNode::Block { addr, .. } => *addr,
            _ => panic!("expected a Block leaf, got {n:?}"),
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: test helper)
    fn leaf_addr(c: &CondExpr) -> u64 {
        match c {
            CondExpr::Leaf(l) => l.addr,
            _ => panic!("expected a Leaf condition, got {c:?}"),
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: test helper)
    fn leaf_invert(c: &CondExpr) -> bool {
        match c {
            CondExpr::Leaf(l) => l.invert,
            _ => panic!("expected a Leaf condition, got {c:?}"),
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: test helper)
    fn has_condition(n: &StructuredNode) -> bool {
        match n {
            StructuredNode::Condition { .. } => true,
            StructuredNode::Seq { body } => body.iter().any(has_condition),
            StructuredNode::If { then, .. } => has_condition(then),
            StructuredNode::IfElse { then, els, .. } => {
                has_condition(then) || has_condition(els)
            }
            StructuredNode::Switch { cases, .. } => {
                cases.iter().any(|c| has_condition(&c.body))
            }
            StructuredNode::WhileDo { body, .. } => has_condition(body),
            StructuredNode::DoWhile { body, .. } => has_condition(body),
            StructuredNode::InfLoop { body, .. } => has_condition(body),
            _ => false,
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: test helper)
    fn has_loop(n: &StructuredNode) -> bool {
        match n {
            StructuredNode::WhileDo { body, .. } => true || has_loop(body),
            StructuredNode::DoWhile { body, .. } => true || has_loop(body),
            StructuredNode::InfLoop { body, .. } => true || has_loop(body),
            StructuredNode::Seq { body } => body.iter().any(has_loop),
            StructuredNode::If { then, .. } => has_loop(then),
            StructuredNode::IfElse { then, els, .. } => has_loop(then) || has_loop(els),
            StructuredNode::Switch { cases, .. } => cases.iter().any(|c| has_loop(&c.body)),
            _ => false,
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: test helper)
    fn has_switch(n: &StructuredNode) -> bool {
        match n {
            StructuredNode::Switch { cases, .. } => true || cases.iter().any(|c| has_switch(&c.body)),
            StructuredNode::Seq { body } => body.iter().any(has_switch),
            StructuredNode::If { then, .. } => has_switch(then),
            StructuredNode::IfElse { then, els, .. } => has_switch(then) || has_switch(els),
            StructuredNode::WhileDo { body, .. } => has_switch(body),
            StructuredNode::DoWhile { body, .. } => has_switch(body),
            StructuredNode::InfLoop { body, .. } => has_switch(body),
            _ => false,
        }
    }

    // RUGRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: test helper)
    fn count_gotos(n: &StructuredNode, kind: GotoKind, count: &mut i32) {
        match n {
            StructuredNode::Goto { kind: k, .. } => {
                if *k == kind {
                    *count += 1;
                }
            }
            StructuredNode::Seq { body } => {
                for b in body {
                    count_gotos(b, kind, count);
                }
            }
            StructuredNode::If { then, .. } => count_gotos(then, kind, count),
            StructuredNode::IfElse { then, els, .. } => {
                count_gotos(then, kind, count);
                count_gotos(els, kind, count);
            }
            StructuredNode::Switch { cases, .. } => {
                for c in cases {
                    count_gotos(&c.body, kind, count);
                }
            }
            StructuredNode::WhileDo { body, .. } => count_gotos(body, kind, count),
            StructuredNode::DoWhile { body, .. } => count_gotos(body, kind, count),
            StructuredNode::InfLoop { body, .. } => count_gotos(body, kind, count),
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // RI-grounded refinement integration
    // ------------------------------------------------------------------

    #[test]
    fn region_identifier_grounds_loop_refinement() {
        // The same multi-exit loop as multi_exit_loop_refines_to_break, but
        // with the RegionIdentifier's projection attached: the refinement
        // keeps the RI frontier exit structural.
        let inp = In::new(
            &[(0x10, false), (0x20, false), (0x30, false), (0x40, false)],
            &[(0, 2), (0, 1), (1, 0), (1, 3)],
            0,
        );
        // Run the RegionIdentifier over the same shape.
        let mut ri = crate::sailr::region_id::RegionIdentifier::new();
        let blocks: Vec<(u64, usize, bool)> = inp
            .input
            .blocks
            .iter()
            .map(|b| (b.addr, b.external.unwrap_or(0), false))
            .collect();
        let edges: Vec<(usize, usize)> =
            inp.input.edges.iter().map(|e| (e.src, e.dst)).collect();
        ri.build_from_cfg(&blocks, &edges, 0x10).unwrap();
        let _ = ri.compute().unwrap();

        let mut st =
            Structurer::new(&inp.input).unwrap().with_cyclic_loops(ri.cyclic_loops());
        let tree = st.structure().unwrap().expect("must converge");
        match tree {
            StructuredNode::Seq { body } => match &body[0] {
                StructuredNode::WhileDo { exit_addrs, .. } => {
                    // RI-grounded exits: the successor frontier of the loop
                    // region contains the exit block.
                    assert!(!exit_addrs.is_empty());
                }
                other => panic!("expected WhileDo, got {other:?}"),
            },
            other => panic!("expected Seq, got {other:?}"),
        }
    }
}
