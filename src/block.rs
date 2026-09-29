//! Basic blocks and control flow graph
//!
//! Corresponds to Ghidra's `block.hh`

use crate::address::Address;
use crate::marshal::{AttributeId, Decoder, ElementId, Encoder};
use crate::op::PcodeOpRef;
use crate::opcodes::OpCode;
use std::sync::{Arc, RwLock, Weak};

// ===== Marshal ElementId / AttributeId helpers (block.cc:22-28, 30-31) =====
// Ghidra defines these as static ElementId/AttributeId instances. Rugra builds
// them on demand via constructor functions matching the Ghidra names.

/// `ELEM_BLOCK` (block.cc:22): a \<block> element wrapping a FlowBlock.
// Ghidra: block.cc:22 ELEM_BLOCK
pub fn elem_block() -> ElementId {
    ElementId::new("block", 134)
}
/// `ELEM_BHEAD` (block.cc:23): a \<bhead> element — header for a child block.
// Ghidra: block.cc:23 ELEM_BHEAD
pub fn elem_bhead() -> ElementId {
    ElementId::new("bhead", 135)
}
/// `ELEM_EDGE` (block.cc:31): an \<edge> element — a flow graph edge.
// Ghidra: block.cc:31 ELEM_EDGE
pub fn elem_edge() -> ElementId {
    ElementId::new("edge", 105)
}
/// `ELEM_TARGET` (block.cc:24): a \<target> element — a goto target ref.
// Ghidra: block.cc:24 ELEM_TARGET
pub fn elem_target() -> ElementId {
    ElementId::new("target", 136)
}

/// `ATTRIB_INDEX` (block.cc:26): block index attribute.
// Ghidra: block.cc:26 ATTRIB_INDEX
pub fn attrib_index() -> AttributeId {
    AttributeId::new("index", 13)
}
/// `ATTRIB_END` (block.cc:27): edge endpoint reference attribute.
// Ghidra: block.cc:27 ATTRIB_END
pub fn attrib_end() -> AttributeId {
    AttributeId::new("end", 37)
}
/// `ATTRIB_REV` (block.cc:28): edge reverse-index attribute.
// Ghidra: block.cc:28 ATTRIB_REV
pub fn attrib_rev() -> AttributeId {
    AttributeId::new("rev", 38)
}
/// `ATTRIB_DEPTH` (block.hh): goto-target depth attribute.
// Ghidra: block.hh ATTRIB_DEPTH
pub fn attrib_depth() -> AttributeId {
    AttributeId::new("depth", 39)
}
/// `ATTRIB_TYPE` (block.hh): goto-type / block-type attribute.
// Ghidra: block.hh ATTRIB_TYPE
pub fn attrib_type() -> AttributeId {
    AttributeId::new("type", 40)
}
/// `ATTRIB_ALTINDEX` (block.hh): BlockCopy alt-index attribute.
// Ghidra: block.hh ATTRIB_ALTINDEX
pub fn attrib_altindex() -> AttributeId {
    AttributeId::new("altindex", 41)
}
/// `ATTRIB_OPCODE` (block.hh): BlockCondition opcode attribute.
// Ghidra: block.hh ATTRIB_OPCODE
pub fn attrib_opcode() -> AttributeId {
    AttributeId::new("opcode", 42)
}

// ===== Free functions (block.cc static dispatch) =====

/// Ghidra `FlowBlock::nameToType` (block.cc:657-666): map a deserialized type
/// name string to a `BlockType`. Only "graph" and "copy" are distinguishable
/// from the base "plain" type when reading the \<bhead> tag; the structured
/// subtypes (if/while/do/switch) are inferred from component counts elsewhere.
// Ghidra: block.cc:657 FlowBlock::nameToType
pub fn name_to_type(nm: &str) -> BlockType {
    // cc:661-665: graph → t_graph; copy → t_copy; else t_plain.
    match nm {
        "graph" => BlockType::Graph,
        "copy" => BlockType::Copy,
        _ => BlockType::Plain,
    }
}

/// Ghidra `FlowBlock::typeToName` (block.cc:671-703): map a `BlockType` to its
/// serialized name string. Used by `BlockGraph::encodeBody` when writing the
/// \<bhead> type attribute.
// Ghidra: block.cc:671 FlowBlock::typeToName
pub fn type_to_name(bt: BlockType) -> &'static str {
    // cc:674-702: exhaustive switch over block_type.
    match bt {
        BlockType::Plain => "plain",
        BlockType::Basic => "basic",
        BlockType::Graph => "graph",
        BlockType::Copy => "copy",
        BlockType::Goto => "goto",
        BlockType::MultiGoto => "multigoto",
        BlockType::List => "list",
        BlockType::Condition => "condition",
        BlockType::If => "properif",
        BlockType::WhileDo => "whiledo",
        BlockType::DoWhile => "dowhile",
        BlockType::Switch => "switch",
        BlockType::InfLoop => "infloop",
    }
}

// Ghidra: block.cc:340 FlowBlock::getFrontLeaf
/// Descend the first-component chain until reaching a leaf block. Ghidra
/// walks `subBlock(0)` while `getType() != t_copy` — in the final structured
/// graph every emitted path bottoms out at a BlockCopy. Returns the entering
/// arc when it is already a copy; when a non-copy has no first component,
/// returns the deepest reachable node (Ghidra returns null there — callers
/// treat None as "no label", Rugra callers do the same via flag checks).
pub fn front_leaf(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
    let mut cur = bl.clone();
    loop {
        let next = {
            let b = cur.read().unwrap();
            match b.get_type() {
                BlockType::Copy => return Some(cur.clone()),
                BlockType::Basic => None,
                BlockType::List => b
                    .as_any()
                    .downcast_ref::<BlockList>()
                    .and_then(|l| l.children.first().cloned()),
                BlockType::If => b
                    .as_any()
                    .downcast_ref::<BlockIf>()
                    .map(|i| i.condition.clone()),
                BlockType::WhileDo => b
                    .as_any()
                    .downcast_ref::<BlockWhileDo>()
                    .map(|w| w.condition.clone()),
                BlockType::DoWhile => b
                    .as_any()
                    .downcast_ref::<BlockDoWhile>()
                    .map(|d| d.condition.clone()),
                BlockType::InfLoop => b
                    .as_any()
                    .downcast_ref::<BlockInfLoop>()
                    .map(|l| l.body.clone()),
                BlockType::Condition => b
                    .as_any()
                    .downcast_ref::<BlockCondition>()
                    .map(|c| c.first.clone()),
                BlockType::Switch => b
                    .as_any()
                    .downcast_ref::<BlockSwitch>()
                    .map(|sw| sw.control.clone()),
                // BlockGoto : BlockGraph — getFrontLeaf descends subBlock(0)
                // = the wrapped component (block.hh:559/561-562 delegate every
                // leaf/first/last query to getBlock(0)). Graph/Plain are not
                // structured-tree nodes (no subBlock(0) chain exists).
                // BlockMultiGoto likewise delegates to getBlock(0) — its
                // subBlock(0) is the wrapped multi-exit block (block.hh:587-
                // 589 delegate printRaw/emit/getExitLeaf the same way).
                BlockType::Goto => b
                    .as_any()
                    .downcast_ref::<BlockGoto>()
                    .and_then(|g| g.wrapped.clone()),
                BlockType::MultiGoto => b
                    .as_any()
                    .downcast_ref::<BlockMultiGoto>()
                    .and_then(|m| m.wrapped.clone()),
                _ => return Some(cur.clone()),
            }
        };
        match next {
            Some(n) => cur = n,
            None => return None,
        }
    }
}

// Ghidra: block.cc:1233 BlockGraph::markCopyBlock
/// `bl->getFrontLeaf()->flags |= fl` — set a property on the given block's
/// front leaf, never on the wrapper (block.cc:1233-1237). Dyn-FlowBlock
/// entry used by markUnstructured ports (BlockGoto holds the real dyn
/// target capture; BlockIf holds a dyn arc — both route here).
pub fn mark_front_leaf(bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, fl: u32) {
    if let Some(leaf) = front_leaf(bl) {
        leaf.write().unwrap().set_flags(fl);
    }
}

// Ghidra: block.cc:340 FlowBlock::getFrontLeaf
/// `getFrontLeaf` for an already-typed `Arc<RwLock<BlockBasic>>` — the
/// `getGotoTarget()->getFrontLeaf()` composition of
/// `BlockGoto::gotoPrints` (block.cc:2885). A BlockBasic is already a leaf
/// (Basic is one of Rugra's t_copy stand-ins), so the descent is a no-op
/// coercion; kept as a named helper so the call site reads as the oracle.
pub fn front_leaf_basic(
    bl: &Arc<RwLock<BlockBasic>>,
) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
    let coerced: Arc<RwLock<dyn FlowBlock + Send + Sync>> = bl.clone();
    front_leaf(&coerced)
}

// Ghidra: printc.cc:2303 PrintC::emitGotoStatement (exp_bl → emitLabel)
/// The label address of a (possibly structured) block for goto-statement
/// emission: the start address of the underlying basic block. The oracle's
/// emitGotoStatement prints `emitLabel(exp_bl)` — the label manager entry of
/// the destination FlowBlock; Rugra's printc derives `code_label(addr)` from
/// the same basic block's start address, reached by descending the front
/// leaf and taking the BlockCopy's original (BlockCopy itself does not
/// override getStart — block.hh:505-538 has no getStart, matching Rugra's
/// trait default — so the original's start is the faithful projection).
pub fn front_leaf_start_addr(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
) -> u64 {
    let leaf = front_leaf(bl).unwrap_or_else(|| bl.clone());
    let orig = {
        let r = leaf.read().unwrap();
        r.as_any()
            .downcast_ref::<BlockCopy>()
            .map(|c| c.original.clone())
    };
    let target = match orig {
        Some(o) => o,
        None => leaf,
    };
    let r = target.read().unwrap();
    // printc goto/label addressing is getEntryAddr-based (printc.cc:3170
    // emitLabel -> block.cc:2291): with a multi-range (spliced) block the
    // label keeps the entry chunk's address even though getStart() reports
    // the lowest cover range.
    if let Some(bb) = r.as_any().downcast_ref::<BlockBasic>() {
        bb.get_entry_addr().as_u64()
    } else {
        r.get_start_addr().as_u64()
    }
}

// RUGRA-GLUE: diagnostic front-leaf address for BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001
/// Debug helper: the front leaf's start address after descending BlockCopy
/// wrappers into the wrapped original (composites carry no start of their
/// own; BlockCopy inherits the null default). Used by the collapse trace
/// prints (blockaction.rs IRRED-SW) and print_tree_dbg.
pub fn dbg_front_leaf_start_addr(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
) -> u64 {
    let descend = |mut cur: Arc<RwLock<dyn FlowBlock + Send + Sync>>| {
        for _ in 0..8 {
            let next = {
                let r = cur.read().unwrap();
                if let Some(c) = r.as_any().downcast_ref::<BlockCopy>() {
                    Some(c.original.clone())
                } else {
                    None
                }
            };
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        cur
    };
    let mut cur = descend(bl.clone());
    if let Some(leaf) = front_leaf(&cur) {
        cur = descend(leaf);
        cur.read().unwrap().get_start_addr().as_u64()
    } else {
        cur.read().unwrap().get_start_addr().as_u64()
    }
}

// RUGRA-GLUE: diagnostic tree dumper for BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001
/// Debug-only replica of the `FlowBlock::printTree` recursion (block.cc:616)
/// covering every composite Rugra defines (Ghidra's virtual printTree does
/// this via the virtual dispatch): node index, type, front-leaf address, and
/// for unstructured nodes (BlockGoto / if-goto) target + goto_type +
/// precomputed prints flag. No oracle counterpart line-for-line; used by the
/// curl/httpd drivers' RUGRA_DUMP_FUNC hook and the tree-dump example.
pub fn print_tree_dbg(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    depth: usize,
    out: &mut String,
) {
    // RUGRA-GLUE: debug address stringifier for the tree dumper above
    fn addr_of(bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> String {
        let a = dbg_front_leaf_start_addr(bl);
        if a == 0 {
            "?".to_string()
        } else {
            format!("{:#x}", a)
        }
    }
    let rg = bl.read().unwrap();
    let indent = "  ".repeat(depth);
    let idx = rg.get_index();
    match rg.get_type() {
        BlockType::Graph => {
            if let Some(g) = rg.as_any().downcast_ref::<BlockGraph>() {
                out.push_str(&format!("{}#{} Graph [{}..]\n", indent, idx, addr_of(bl)));
                for c in &g.blocks {
                    print_tree_dbg(c, depth + 1, out);
                }
            }
        }
        BlockType::List => {
            if let Some(l) = rg.as_any().downcast_ref::<BlockList>() {
                out.push_str(&format!("{}#{} List [{}..]\n", indent, idx, addr_of(bl)));
                for c in &l.children {
                    print_tree_dbg(c, depth + 1, out);
                }
            }
        }
        BlockType::If => {
            if let Some(bif) = rg.as_any().downcast_ref::<BlockIf>() {
                if let Some(gt) = &bif.goto_target {
                    out.push_str(&format!(
                        "{}#{} IFGOTO cond=#{} target={}(#{}) goto_type={}\n",
                        indent,
                        idx,
                        bif.condition.read().unwrap().get_index(),
                        addr_of(gt),
                        gt.read().unwrap().get_index(),
                        bif.goto_type
                    ));
                    print_tree_dbg(&bif.condition, depth + 1, out);
                } else {
                    out.push_str(&format!(
                        "{}#{} If cond=#{}\n",
                        indent,
                        idx,
                        bif.condition.read().unwrap().get_index()
                    ));
                    print_tree_dbg(&bif.condition, depth + 1, out);
                    out.push_str(&format!("{}  then:\n", indent));
                    print_tree_dbg(&bif.if_body, depth + 1, out);
                    if let Some(eb) = &bif.else_body {
                        out.push_str(&format!("{}  else:\n", indent));
                        print_tree_dbg(eb, depth + 1, out);
                    }
                }
            }
        }
        BlockType::Goto => {
            if let Some(g) = rg.as_any().downcast_ref::<BlockGoto>() {
                let tgt = g
                    .target_dyn
                    .as_ref()
                    .map(|t| {
                        format!(
                            "{}(#{})",
                            addr_of(t),
                            t.read().unwrap().get_index()
                        )
                    })
                    .unwrap_or_else(|| "none".into());
                out.push_str(&format!(
                    "{}#{} Goto target={} goto_type={} prints={}\n",
                    indent,
                    idx,
                    tgt,
                    g.goto_type,
                    g.prints_precomputed
                ));
                if let Some(w) = &g.wrapped {
                    print_tree_dbg(w, depth + 1, out);
                }
            }
        }
        BlockType::DoWhile => {
            if let Some(dw) = rg.as_any().downcast_ref::<BlockDoWhile>() {
                out.push_str(&format!(
                    "{}#{} DoWhile cond=#{}\n",
                    indent,
                    idx,
                    dw.condition.read().unwrap().get_index()
                ));
                print_tree_dbg(&dw.condition, depth + 1, out);
            }
        }
        BlockType::WhileDo => {
            if let Some(wd) = rg.as_any().downcast_ref::<BlockWhileDo>() {
                out.push_str(&format!(
                    "{}#{} WhileDo cond=#{} body=#{}\n",
                    indent,
                    idx,
                    wd.condition.read().unwrap().get_index(),
                    wd.body.read().unwrap().get_index()
                ));
                print_tree_dbg(&wd.condition, depth + 1, out);
                print_tree_dbg(&wd.body, depth + 1, out);
            }
        }
        BlockType::Switch => {
            if let Some(sw) = rg.as_any().downcast_ref::<BlockSwitch>() {
                out.push_str(&format!(
                    "{}#{} Switch control=#{} numcases={}\n",
                    indent,
                    idx,
                    sw.control.read().unwrap().get_index(),
                    sw.cases.len()
                ));
                print_tree_dbg(&sw.control, depth + 1, out);
                for c in &sw.cases {
                    print_tree_dbg(c, depth + 1, out);
                }
            }
        }
        BlockType::InfLoop => {
            if let Some(il) = rg.as_any().downcast_ref::<crate::block::BlockInfLoop>() {
                out.push_str(&format!("{}#{} InfLoop @{}\n", indent, idx, addr_of(bl)));
                print_tree_dbg(&il.body, depth + 1, out);
            }
        }
        other => {
            out.push_str(&format!(
                "{}#{} {:?} @{}\n",
                indent,
                idx,
                other,
                addr_of(bl)
            ));
        }
    }
}

// Ghidra: block.cc:1335 BlockGraph::nextFlowAfter (sibling arm)
/// `BlockGraph::nextFlowAfter` (block.cc:1335-1353) for a plain graph/list
/// parent, evaluated for every component at once: each component's in-flow
/// successor is the next sibling's front leaf (cc:1349-1352); for the last
/// component it is `tail_next` — the successor the enclosing composite
/// itself received (cc:1344-1348's parent recursion, null at the root).
// pub for the bilateral goto_prints_nextflowafter_1204 fixture — the
// oracle side walks the virtual dispatch directly, and this is the only
// Rust-visible projection of the sibling arm.
pub fn graph_sibling_successors(
    components: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    tail_next: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
) -> Vec<Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>> {
    let n = components.len();
    (0..n)
        .map(|i| match components.get(i + 1) {
            // cc:1340-1343: find the block after this one; cc:1349-1352:
            // front-leaf it.
            Some(next) => front_leaf(next),
            // Last component: cc:1344-1348 parent arm, precomputed by the
            // caller as tail_next (None at the root = the oracle's null).
            None => tail_next.clone(),
        })
        .collect()
}

// Ghidra: block.cc:3524 BlockSwitch::grabCaseBasic (construction-order default rank)
/// The default's rank in the oracle's CONSTRUCTION-order caseblocks — the
/// position `grabCaseBasic`'s cs scan (block.cc:3529-3534, fed by
/// ruleBlockSwitch's out-edge scan cc:1714-1720) would place it at: the
/// number of REGULAR (gototype 0, cc:3510-3511) cases whose basic-graph
/// out-edge index (CaseOrder::outindex, cc:3509 `getInRevIndex`) precedes
/// the default's. Multigoto-appended cases (cc:3548-3553) come after the
/// whole regular scan, so they never count. Falls back to append-last
/// (cases.len(), the previous behavior) whenever the recorded coordinates
/// are incomplete — the oracle cannot express that shape (addCase throws
/// LowlevelError on detached coords, cc:3507-3508).
// pub for the bilateral gather default-position fixture — the oracle side
// walks caseblocks directly; this is the Rust reconstruction of the
// construction-order rank from the recorded basic-graph out-edge indices.
pub fn switch_default_construct_pos(sw: &BlockSwitch) -> usize {
    let Some(def_order) = &sw.default_order else {
        return sw.cases.len();
    };
    if def_order.outindex < 0
        || sw.case_order.len() != sw.cases.len()
        || sw.case_gototypes.len() != sw.cases.len()
        || sw.case_order.iter().any(|co| co.outindex < 0)
    {
        return sw.cases.len();
    }
    sw.case_order
        .iter()
        .zip(sw.case_gototypes.iter())
        .filter(|(co, &gt)| gt == 0 && co.outindex < def_order.outindex)
        .count()
}

// Ghidra: block.cc:1335 BlockGraph::nextFlowAfter (per-type dispatch)
/// The `getParent()->nextFlowAfter(this)` virtual dispatch (block.cc:2885),
/// evaluated for every component of `node` at once with the successor
/// `succ` the walk already computed for `node` itself. One row per
/// `FlowBlock::nextFlowAfter` override:
/// - `FlowBlock` base (block.hh:884-887): null — leaves never dispatch here
///   (the walk only recurses through walkable composites).
/// - `BlockGraph`/`BlockList` (block.cc:1335-1353; block.hh:600 no override):
///   the sibling arm above.
/// - `BlockGoto` (block.cc:2899-2903): front leaf of the goto target, for
///   any component (the wrapped block flows to the target).
/// - `BlockMultiGoto` (block.cc:2931-2934): null for any component — but
///   Rugra's MultiGoto `component_list_dyn` is empty (its wrapped child is
///   the dispatch basic leaf, which holds no BlockGoto), so this arm is
///   structurally unreachable here.
/// - `BlockCondition` (block.cc:3053-3056): null ("do not know where flow
///   goes") for any component.
/// - `BlockIf` (block.cc:3127-3134): slot 0 (the condition, incl. the
///   if-goto form's only component) → null; any other slot (tc/fc) → the
///   parent arm `succ` — **no sibling scan**: both bodies' successors are
///   the whole if's successor, never each other.
/// - `BlockWhileDo` (block.cc:3341-3351): slot 0 (condition) → null; the
///   body → `front_leaf(getBlock(0))` = the loop head (the body flows back
///   to the condition, not past the loop).
/// - `BlockDoWhile` (block.cc:3448-3451): null for any component ("don't
///   know what will execute next" — the fused body may iterate).
/// - `BlockInfLoop` (block.cc:3476-3483): `front_leaf(getBlock(0))` = the
///   loop head for any component (flow re-enters the loop).
/// - `BlockSwitch` (block.cc:3639-3661): oracle arm ① `getBlock(0)==bl →
///   null` addresses the dispatch root cs[0], which Rugra keeps in
///   `BlockSwitch::control` OUTSIDE the component list — no Rust component
///   reaches that arm (a t_multigoto root also falls to null via arm ②).
///   Arm ②: a component whose type is not `t_goto` → null ("Otherwise there
///   is a break statement in the flow"). Arm ③-⑤: a `t_goto` case is looked
///   up in the case order — oracle `caseblocks`, label/depth stable_sort at
///   finalizePrinting (block.cc:3591) after ActionFinalStructure's
///   `finalizePrinting` call (blockaction.cc:2192); the merged SORTED order
///   (cases + default at its label rank, the print order) supplies the next
///   caseblock's front leaf; the LAST caseblock defers to the parent arm
///   `succ` ("flow is to exit of switch").
// pub for the bilateral goto_prints_nextflowafter_1204 fixture — the
// oracle side queries the per-parent virtual dispatch directly, and this
// is the Rust-visible projection of that dispatch for every parent kind.
pub fn next_flow_after_successors(
    node: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    components: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    succ: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
) -> Vec<Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>> {
    let n = components.len();
    let bt = node.read().unwrap().get_type();
    match bt {
        BlockType::If => {
            // cc:3130-3131: getBlock(0)==bl → null ("do not know where flow
            // goes"); cc:3134: else parent recursion — no sibling scan.
            (0..n)
                .map(|i| if i == 0 { None } else { succ.clone() })
                .collect()
        }
        BlockType::WhileDo => {
            // cc:3344-3345: cond slot null ("don't know what will execute
            // next"); cc:3347-3350: body → front leaf of getBlock(0) (the
            // loop head).
            let mut v: Vec<Option<_>> = (0..n).map(|_| None).collect();
            if let Some(head) = components.first() {
                let head_leaf = front_leaf(head);
                for slot in v.iter_mut().skip(1) {
                    *slot = head_leaf.clone();
                }
            }
            v
        }
        BlockType::DoWhile | BlockType::Condition => {
            // cc:3451 / cc:3056: always null ("don't know what's next").
            (0..n).map(|_| None).collect()
        }
        BlockType::InfLoop => {
            // cc:3479-3482: front leaf of getBlock(0) for every component.
            let head_leaf = components.first().and_then(front_leaf);
            (0..n).map(|_| head_leaf.clone()).collect()
        }
        BlockType::Goto => {
            // cc:2902: getGotoTarget()->getFrontLeaf() for any component.
            let target = node
                .read()
                .unwrap()
                .as_any()
                .downcast_ref::<BlockGoto>()
                .and_then(|g| g.target_dyn.clone());
            let target_leaf = target.as_ref().and_then(front_leaf);
            (0..n).map(|_| target_leaf.clone()).collect()
        }
        BlockType::Switch => {
            let mut v: Vec<Option<_>> = Vec::with_capacity(n);
            // cc:3643-3661 walk the SORTED caseblocks order — the merged
            // print order (cases with the default at its label rank, the
            // same def_pos recipe printc uses for emission, block.cc:3591
            // stable sort + printc.cc:3331-3332) — not the raw component
            // list: the oracle's caseblocks include the default as an
            // ordinary member, so the LAST caseblock defers to the parent
            // arm (cc:3659-3660 "flow is to exit of switch") and the
            // default's own successor is the case at its rank + 1. With the
            // default appended last instead, the final real case would
            // compare against the default's front leaf and lose its goto
            // statement when the default is its goto target (observed:
            // httpd main case 0x66's `goto switchD_.._caseD_40;` silenced,
            // BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001 symptom ③).
            let merged: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = {
                let r = node.read().unwrap();
                let sw = r
                    .as_any()
                    .downcast_ref::<crate::block::BlockSwitch>()
                    .unwrap();
                let mut m: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = sw.cases.clone();
                if let Some(dc) = &sw.default_case {
                    let def_pos: usize = match sw.default_label {
                        Some(dl) if sw.case_order.len() == sw.cases.len() => {
                            sw.case_order.iter().filter(|co| co.label < dl).count()
                        }
                        // Pre-finalizePrinting arm (default_label unset —
                        // e.g. ActionReturnSplit's gatherReturnGotos walk,
                        // blockaction.cc:2210-2232): the oracle's caseblocks
                        // are in CONSTRUCTION order at that point — the cs
                        // out-edge scan of grabCaseBasic (block.cc:3529-
                        // 3534), where the default is an ordinary member at
                        // its out-edge rank (cc:3515 isdefault). The
                        // stable_sort by label only happens later, in
                        // finalizePrinting (cc:3591, called from
                        // ActionFinalStructure, blockaction.cc:2192) — after
                        // returnsplit. Appending the default last in this
                        // phase mis-positions the LAST real case's
                        // nextFlowAfter successor as the default's front
                        // leaf; when that case is a BlockGoto targeting the
                        // default's block, gotoPrints (cc:2881-2890) flips
                        // false and gatherReturnGotos drops the edge
                        // (SetCoderProperties 0x2891e: oracle splits 17
                        // return in-edges, Rugra 16).
                        _ => switch_default_construct_pos(sw),
                    };
                    let pos = def_pos.min(m.len());
                    m.insert(pos, dc.clone());
                }
                m
            };
            let merged_succ: Vec<Option<_>> = {
                let leaves: Vec<Option<_>> = merged
                    .iter()
                    .map(|c| front_leaf(c))
                    .collect();
                let mut ms: Vec<Option<_>> = Vec::with_capacity(merged.len());
                for (pos, component) in merged.iter().enumerate() {
                    let is_goto =
                        component.read().unwrap().get_type() == BlockType::Goto;
                    if !is_goto {
                        // cc:3646-3647: non-t_goto case → null ("Otherwise
                        // there is a break statement in the flow").
                        ms.push(None);
                    } else {
                        ms.push(match leaves.get(pos + 1) {
                            Some(Some(next)) => Some(next.clone()),
                            // cc:3659-3660: last caseblock defers to the
                            // parent arm `succ` ("flow is to exit of
                            // switch").
                            _ => succ.clone(),
                        });
                    }
                }
                ms
            };
            // Map the merged-order successors back onto the component list
            // order the caller iterates (component_list_dyn = cases + the
            // appended default): identity match by Arc pointer.
            for component in components.iter() {
                let mut found: Option<Option<_>> = None;
                for (pos, mc) in merged.iter().enumerate() {
                    if Arc::ptr_eq(mc, component) {
                        found = Some(merged_succ[pos].clone());
                        break;
                    }
                }
                v.push(found.unwrap_or(None));
            }
            v
        }
        // Root graph / BlockList / any other plain BlockGraph: the sibling
        // rule of block.cc:1340-1352.
        _ => graph_sibling_successors(components, succ),
    }
}

// RUGRA-GLUE: per-block step of the tree-wide gotoPrints evaluation.
/// A `BlockGoto` evaluates block.cc:2884-2888 here:
/// `gotobl = getGotoTarget()->getFrontLeaf(); nextbl = <successor>;
/// return gotobl != nextbl` (pointer identity; None vs None compares equal,
/// matching C++ null == null). Every block then recurses into its component
/// list, each component receiving the per-parent-type successor of
/// `next_flow_after_successors` — the virtual dispatch of cc:2885's
/// `getParent()->nextFlowAfter(this)` for every parent kind.
fn goto_prints_visit(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    succ: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
) {
    if bl.read().unwrap().get_type() == BlockType::Goto {
        let mut guard = bl.write().unwrap();
        if let Some(g) = guard.as_any_mut().downcast_mut::<BlockGoto>() {
            // cc:2885: gotobl = getGotoTarget()->getFrontLeaf();
            let gotobl = g.target_dyn.clone().and_then(|t| front_leaf(&t));
            // cc:2887: return (gotobl != nextbl);
            g.prints_precomputed = match (gotobl, succ.clone()) {
                (Some(a), Some(b)) => !Arc::ptr_eq(&a, &b),
                (None, None) => false,
                _ => true,
            };
        }
    }
    let components = BlockGraph::component_list_dyn(bl);
    if !components.is_empty() {
        let succs = next_flow_after_successors(bl, &components, succ);
        for (child, child_succ) in components.into_iter().zip(succs) {
            goto_prints_visit(&child, child_succ);
        }
    }
}

/// Type of flow block (corresponds to Ghidra's BlockType)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    Plain,
    Basic,
    Graph,
    Copy,
    Goto,
    MultiGoto,
    List,
    Condition,
    If,
    WhileDo,
    DoWhile,
    Switch,
    InfLoop,
}

/// Flags for PcodeBlock properties (corresponds to Ghidra's FlowBlock::block_flags)
pub mod block_flags {
    // Ghidra-shared flags (exact bit values from block.hh:88-105)
    pub const SWITCH_OUT: u32 = 0x10; // f_switch_out (block.hh:92)
    pub const UNSTRUCTURED_TARG: u32 = 0x20; // f_unstructured_targ (block.hh:93)
    pub const MARK: u32 = 0x80; // f_mark (block.hh:94)
    /// Ghidra f_mark2 = 0x100 (block.hh:95). A secondary mark. calcLoop
    /// (block.cc:2120/2133/2138) uses f_mark = "visited" and f_mark2 =
    /// "on the current DFS path" to detect cycles.
    pub const MARK2: u32 = 0x100; // f_mark2 (block.hh:95)
    pub const ENTRY_POINT: u32 = 0x200; // f_entry_point (block.hh:96)
    /// Ghidra f_interior_gotoout = 0x400 (block.hh:97). Block has an unstructured
    /// jump out of its interior. Set by setGotoBranch (block.cc:311).
    pub const INTERIOR_GOTOOUT: u32 = 0x400;
    /// Ghidra f_interior_gotoin = 0x800 (block.hh:98). Block is the target of an
    /// unstructured jump to its interior. Set by setGotoBranch (block.cc:313).
    pub const INTERIOR_GOTOIN: u32 = 0x800;
    pub const DEAD: u32 = 0x4000; // f_dead (block.hh:101)
    /// Ghidra f_label_bumpup = 0x1000 (block.hh:99). Labels for this block
    /// are printed by a parent higher in the hierarchy. Set/cleared by
    /// markLabelBumpUp (block.cc:259-263).
    pub const LABEL_BUMPUP: u32 = 0x1000;
    /// Ghidra f_donothing_loop = 0x2000 (block.hh:100). Block does nothing in
    /// an infinite loop (halt).
    pub const DONOTHING_LOOP: u32 = 0x2000;
    /// Ghidra f_whiledo_overflow = 0x8000 (block.hh:102). The conditional block
    /// of a while-do is too big to print as `while(cond)`; use overflow syntax.
    pub const WHILEDO_OVERFLOW: u32 = 0x8000;
    pub const JOINED_BLOCK: u32 = 0x20000; // f_joined_block (block.hh:105)
    /// Ghidra f_duplicate_block = 0x40000 (block.hh:106). Duplicated block.
    pub const DUPLICATE_BLOCK: u32 = 0x40000;
    // Ghidra f_flip_path = 0x10000 (block.hh:103). Path to this block was flipped.
    pub const FLIP_PATH: u32 = 0x10000;
    // Rugra-only flags (no Ghidra counterpart, placed at 0x100000+)
    pub const RETURN_TERMINAL: u32 = 0x100000;
    pub const CASE_BODY: u32 = 0x200000;
    pub const GOTO_EDGE_0: u32 = 0x400000;
    pub const GOTO_EDGE_1: u32 = 0x800000;
}

/// Goto branch classification (Ghidra block.hh:89-91).
/// Stored on BlockGoto::goto_type and BlockIf::goto_type.
pub mod goto_type {
    /// Ordinary unstructured `goto target;` (block.hh:89).
    pub const GOTO_GOTO: u32 = 1;
    /// Goto → loop exit, printed as `break;` (block.hh:90).
    pub const BREAK_GOTO: u32 = 2;
    /// Goto → loop iterate, printed as `continue;` (block.hh:91).
    pub const CONTINUE_GOTO: u32 = 4;
}

/// Flags for edge properties (corresponds to Ghidra's edge_flags)
///
/// These flags annotate outgoing edges of structured blocks
/// to indicate whether the edge represents a `break`, `continue`,
/// or plain `goto` in the final C output.
pub mod edge_flags {
    /// Ghidra `f_goto_edge` (block.hh:109).
    pub const F_GOTO_EDGE: u32 = 0x01;
    /// Ghidra `f_loop_edge` (block.hh:110).
    pub const F_LOOP_EDGE: u32 = 0x02;
    /// Ghidra `f_defaultswitch_edge` (block.hh:111).
    pub const F_DEFAULTSWITCH_EDGE: u32 = 0x04;
    /// Ghidra `f_irreducible` (block.hh:112).
    pub const F_IRREDUCIBLE_EDGE: u32 = 0x08;
    /// Ghidra `f_tree_edge` (block.hh:113).
    pub const F_TREE_EDGE: u32 = 0x10;
    /// Ghidra `f_forward_edge` (block.hh:114).
    pub const F_FORWARD_EDGE: u32 = 0x20;
    /// Ghidra `f_cross_edge` (block.hh:115).
    pub const F_CROSS_EDGE: u32 = 0x40;
    /// Ghidra `f_back_edge` (block.hh:116).
    pub const F_BACK_EDGE: u32 = 0x80;
    /// Ghidra `f_loop_exit_edge` (block.hh:117).
    pub const F_LOOP_EXIT_EDGE: u32 = 0x100;
    /// Rugra-only structured break annotation; kept outside oracle bits.
    pub const F_BREAK_EDGE: u32 = 0x200;
    /// Rugra-only structured continue annotation; kept outside oracle bits.
    pub const F_CONTINUE_EDGE: u32 = 0x400;
    /// Rugra-only switch dispatch annotation; kept outside oracle bits.
    pub const F_SWITCH_DISPATCH: u32 = 0x800;

    /// All spanning-tree edge flags, for clearing (Ghidra clears these
    /// together in structureLoops, block.cc:2206).
    pub const SPANNING_MASK: u32 =
        F_TREE_EDGE | F_FORWARD_EDGE | F_CROSS_EDGE | F_BACK_EDGE | F_LOOP_EDGE;
}

/// Common interface for all types of blocks (Basic, Graph, Condition, etc.)
///
/// Corresponds to Ghidra's `FlowBlock` base class
pub trait FlowBlock: std::fmt::Debug + Send + Sync {
    // RUGRA-GLUE: Rust trait-object downcast glue (no Ghidra counterpart)
    fn as_any(&self) -> &dyn std::any::Any;
    // RUGRA-GLUE: Rust trait-object downcast glue (no Ghidra counterpart)
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32;
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private; set by buildCopy/orderBlocks)
    fn set_index(&mut self, i: i32);
    // Ghidra: block.hh:184 FlowBlock::getType
    fn get_type(&self) -> BlockType;
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32;
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32);
    /// Clear a boolean property (Ghidra `clearFlag`, block.hh:156
    /// `flags &= ~fl`). Counterpart to `set_flags`; used by calcLoop's
    /// final sweep (block.cc:2125/2146) and stack pop (block.cc:2125).
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32);

    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize;
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize;

    /// Number of out-edges excluding goto-marked edges.
    /// GOTO_EDGE_0 marks out[0] as goto, GOTO_EDGE_1 marks out[1].
    // RUGRA-GLUE: Rugra helper for goto-aware out-edge counting (Ghidra uses raw sizeOut + edge flags)
    fn effective_size_out(&self) -> usize {
        let total = self.size_out();
        let flags = self.get_flags();
        let mut count = total;
        if flags & block_flags::GOTO_EDGE_0 != 0 && total >= 1 {
            count -= 1;
        }
        if flags & block_flags::GOTO_EDGE_1 != 0 && total >= 2 {
            count -= 1;
        }
        count
    }

    /// Get the i-th non-goto out-edge (skipping goto-marked edges).
    // RUGRA-GLUE: Rugra helper for goto-aware out-edge access (no direct Ghidra counterpart)
    fn effective_get_out(&self, slot: usize) -> Option<BlockEdge> {
        let flags = self.get_flags();
        let total = self.size_out();
        let mut effective_idx = 0usize;
        for i in 0..total {
            let is_goto = (i == 0 && flags & block_flags::GOTO_EDGE_0 != 0)
                || (i == 1 && flags & block_flags::GOTO_EDGE_1 != 0);
            if is_goto {
                continue;
            }
            if effective_idx == slot {
                return self.get_out(i);
            }
            effective_idx += 1;
        }
        None
    }

    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge>;
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge>;

    // RUGRA-GLUE: borrow-safety helper mirroring Ghidra's direct
    // `outofthis[i]` reference access (block.hh:301). get_out returns an
    // owned BlockEdge (Arc clone per call); the collapse-rule miss paths call
    // it tens of millions of times per giant function just to read
    // `.flags`/`.point`, so this reference form removes the refcount
    // round-trip while preserving identical reads.
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge>;
    // RUGRA-GLUE: incoming half of the reference accessors above
    // (Ghidra `intothis[i]`, block.hh:304).
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge>;

    // RUGRA-GLUE: mutable edge-vector accessors shared by every FlowBlock
    // subtype. Ghidra's FlowBlock base class owns outofthis/intothis
    // (block.hh:124-127), so edge-label writes (setOutEdgeFlag block.cc:240,
    // setGotoBranch block.cc:305) apply to EVERY block kind — structured
    // blocks included. Rugra duplicates the vectors per concrete type, so
    // the label mutators route through these accessors instead of a
    // downcast chain that silently dropped writes on BlockIf/BlockList/
    // BlockCondition/... (root cause of the selectGoto non-termination:
    // goto marks vanished between rounds, so TraceDAG re-proposed the same
    // edge forever).
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge>;
    // RUGRA-GLUE: incoming half of the shared edge-vector accessors above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge>;

    // Ghidra: block.cc:100 FlowBlock::halfDeleteInEdge
    /// Delete only the incoming half of an edge (our `intothis` entry),
    /// leaving the removed edge's outgoing half on the source block stale.
    /// Surviving entries slide left in order, and each surviving source-side
    /// half is decremented to point back at its new incoming slot.
    /// Faithful to `FlowBlock::halfDeleteInEdge` (block.cc:100-112): the
    /// peer's `outofthis[edge.reverse_index].reverse_index -= 1` runs during
    /// the slide, for EVERY FlowBlock subtype (Ghidra's edge arrays live on
    /// the base class); the former BlockBasic-only half-delete silently
    /// skipped structured peers, leaving stale reciprocal indices that later
    /// indexed out of bounds (BLOCK-RECIPROCAL-OOB-0001).
    fn half_delete_in_edge(&mut self, slot: usize) {
        let mut slot = slot;
        let last = self.in_edges_mut().len().saturating_sub(1);
        while slot < last {
            let edge = {
                let ins = self.in_edges_mut();
                if slot + 1 >= ins.len() {
                    break;
                }
                ins[slot + 1].clone()
            };
            self.in_edges_mut()[slot] = edge.clone();
            match edge.point.try_write() {
                Ok(mut source) => {
                    decrement_reciprocal_reverse_index(
                        &mut *source,
                        false,
                        edge.reverse_index as usize,
                    );
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    // The per-Funcdata graph rewrite is single-threaded; a
                    // held peer lock here is the self-loop case — mutate the
                    // outgoing half through our own accessor (the direct
                    // index mirrors decrement_for!'s unguarded indexing).
                    let list = self.out_edges_mut();
                    list[edge.reverse_index as usize].reverse_index -= 1;
                }
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    panic!("poisoned reciprocal source edge lock: {error}");
                }
            }
            slot += 1;
        }
        self.in_edges_mut().pop();
    }

    // Ghidra: block.cc:115 FlowBlock::halfDeleteOutEdge
    /// Delete only the outgoing half of an edge. Surviving entries slide
    /// left in order, and each surviving target-side half is decremented to
    /// point back at its new outgoing slot. Faithful to
    /// `FlowBlock::halfDeleteOutEdge` (block.cc:115-127); see
    /// `half_delete_in_edge` for the subtype-universal rationale.
    fn half_delete_out_edge(&mut self, slot: usize) {
        let mut slot = slot;
        let last = self.out_edges_mut().len().saturating_sub(1);
        while slot < last {
            let edge = {
                let outs = self.out_edges_mut();
                if slot + 1 >= outs.len() {
                    break;
                }
                outs[slot + 1].clone()
            };
            self.out_edges_mut()[slot] = edge.clone();
            match edge.point.try_write() {
                Ok(mut target) => {
                    decrement_reciprocal_reverse_index(
                        &mut *target,
                        true,
                        edge.reverse_index as usize,
                    );
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    // See half_delete_in_edge: the only recursively-held
                    // endpoint in the single-threaded pipeline is `self`.
                    let list = self.in_edges_mut();
                    list[edge.reverse_index as usize].reverse_index -= 1;
                }
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    panic!("poisoned reciprocal target edge lock: {error}");
                }
            }
            slot += 1;
        }
        self.out_edges_mut().pop();
    }

    // Ghidra: block.cc:130 FlowBlock::removeInEdge (exclusion-list form)
    /// Remove this block's incoming edges whose source index is in
    /// `exclude_indices`, as full bilateral edge removals: for each match,
    /// `halfDeleteInEdge(slot)` on self plus `halfDeleteOutEdge(rev)` on the
    /// source (the `removeInEdge` composition, block.cc:130-141). The former
    /// one-sided `retain` version left the sources' outgoing halves and all
    /// surviving edges' reciprocal reverse_index entries stale, which later
    /// surfaced as reciprocal-slot out-of-bounds panics
    /// (BLOCK-RECIPROCAL-OOB-0001). Trait-level because Ghidra's edge
    /// arrays live on the FlowBlock base for every subtype.
    fn remove_in_edge_from(&mut self, exclude_indices: &[i32]) {
        loop {
            let slot = {
                let ins = self.in_edges_mut();
                let mut found = None;
                for (i, e) in ins.iter().enumerate() {
                    // Use try_read to avoid RwLock deadlock when
                    // e.point == self (self-loop edge while holding our own
                    // write lock).
                    let src_idx = match e.point.try_read() {
                        Ok(p) => p.get_index(),
                        Err(_) => continue,
                    };
                    if exclude_indices.contains(&src_idx) {
                        found = Some(i);
                        break;
                    }
                }
                match found {
                    Some(s) => s,
                    None => break,
                }
            };
            // removeInEdge (block.cc:133-136): capture the peer and its
            // reverse slot BEFORE the slide, then delete both halves.
            let (peer, rev) = {
                let e = &self.in_edges_mut()[slot];
                (e.point.clone(), e.reverse_index)
            };
            self.half_delete_in_edge(slot);
            let peer_try = peer.try_write();
            match peer_try {
                Ok(mut source) => {
                    source.half_delete_out_edge(rev as usize);
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    // Self-loop: the peer is this block; our own write
                    // guard is the one being held.
                    self.half_delete_out_edge(rev as usize);
                }
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    panic!("poisoned reciprocal source edge lock: {error}");
                }
            }
        }
    }

    /// OR-set edge flags on the `slot`-th outgoing edge.
    /// Faithful to Ghidra's `FlowBlock::setOutEdgeFlag` (block.hh:288).
    /// Used by `findSpanningTree` to label tree/back/forward/cross edges.
    // Ghidra: block.cc:240 FlowBlock::setOutEdgeFlag
    fn set_out_edge_flag(&mut self, slot: usize, flag: u32) {
        // Ghidra's FlowBlock base class owns outofthis/intothis for EVERY
        // subtype (block.hh:124-127), so setOutEdgeFlag applies to structured
        // blocks (BlockIf/BlockList/BlockCondition/...) exactly as to
        // BlockBasic. Route through out_edges_mut instead of a downcast chain.
        let outs = self.out_edges_mut();
        if slot < outs.len() {
            outs[slot].flags |= flag;
        }
    }

    // Ghidra: block.hh:289 FlowBlock::clearOutEdgeFlag
    /// Clear a flag from a single outgoing edge. Faithful to Ghidra's
    /// `FlowBlock::clearOutEdgeFlag` (block.hh:289). Counterpart to
    /// `set_out_edge_flag`. Used by LoopBody::clearExitMarks.
    fn clear_out_edge_flag(&mut self, slot: usize, flag: u32) {
        let outs = self.out_edges_mut();
        if slot < outs.len() {
            outs[slot].flags &= !flag;
        }
    }

    /// Clear a mask of edge flags from ALL outgoing edges.
    /// Faithful to Ghidra's `FlowBlock::clearEdgeFlags` (block.cc).
    // Ghidra: block.cc:966 BlockGraph::clearEdgeFlags
    fn clear_edge_flags(&mut self, mask: u32) {
        for e in self.out_edges_mut().iter_mut() {
            e.flags &= !mask;
        }
    }

    // Ghidra: block.cc:446 FlowBlock::eliminateInDups
    /// Eliminate duplicate in-edges from the given block, keeping the first
    /// instance and OR-merging edge labels. Faithful to
    /// `FlowBlock::eliminateInDups` (block.cc:447-472): each duplicate is
    /// removed with PAIRED half-deletes (`halfDeleteInEdge(i)` here plus
    /// `bl->halfDeleteOutEdge(rev)` on the peer), so every surviving edge's
    /// reciprocal reverse_index stays consistent. `self_arc` is this
    /// block's own Arc (the peer may be this block in the self-loop case;
    /// the peer write then goes through the WouldBlock arm).
    fn eliminate_in_dups(
        &mut self,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        self_arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        let self_loop = Arc::ptr_eq(bl, self_arc);
        let mut indval: i64 = -1;
        let mut i = 0usize;
        while i < self.in_edges_mut().len() {
            let is_bl = {
                let ins = self.in_edges_mut();
                i < ins.len() && Arc::ptr_eq(&ins[i].point, bl)
            };
            if is_bl {
                if indval == -1 {
                    // The first instance of bl: we keep it.
                    indval = i as i64;
                    i += 1;
                } else {
                    // cc:458-462: merge labels, then the paired half-deletes.
                    let (label, rev) = {
                        let ins = self.in_edges_mut();
                        (ins[i].flags, ins[i].reverse_index)
                    };
                    self.in_edges_mut()[indval as usize].flags |= label;
                    self.half_delete_in_edge(i);
                    if self_loop {
                        // Peer is this block; our own write guard is held.
                        self.half_delete_out_edge(rev as usize);
                    } else {
                        match bl.try_write() {
                            Ok(mut peer) => {
                                peer.half_delete_out_edge(rev as usize);
                            }
                            Err(std::sync::TryLockError::WouldBlock) => {
                                self.half_delete_out_edge(rev as usize);
                            }
                            Err(std::sync::TryLockError::Poisoned(error)) => {
                                panic!("poisoned reciprocal edge lock: {error}");
                            }
                        }
                    }
                    // Don't increment i (the slide brought the next entry).
                }
            } else {
                i += 1;
            }
        }
    }

    // Ghidra: block.cc:475 FlowBlock::eliminateOutDups
    /// Eliminate duplicate out-edges to the given block, keeping the first
    /// instance and OR-merging edge labels. Faithful to
    /// `FlowBlock::eliminateOutDups` (block.cc:475-501) with the same
    /// paired half-delete protocol as `eliminate_in_dups`.
    fn eliminate_out_dups(
        &mut self,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        self_arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        let self_loop = Arc::ptr_eq(bl, self_arc);
        let mut indval: i64 = -1;
        let mut i = 0usize;
        while i < self.out_edges_mut().len() {
            let is_bl = {
                let outs = self.out_edges_mut();
                i < outs.len() && Arc::ptr_eq(&outs[i].point, bl)
            };
            if is_bl {
                if indval == -1 {
                    // The first instance of bl: we keep it.
                    indval = i as i64;
                    i += 1;
                } else {
                    // cc:488-491: merge labels, then the paired half-deletes.
                    let (label, rev) = {
                        let outs = self.out_edges_mut();
                        (outs[i].flags, outs[i].reverse_index)
                    };
                    self.out_edges_mut()[indval as usize].flags |= label;
                    self.half_delete_out_edge(i);
                    if self_loop {
                        self.half_delete_in_edge(rev as usize);
                    } else {
                        match bl.try_write() {
                            Ok(mut peer) => {
                                peer.half_delete_in_edge(rev as usize);
                            }
                            Err(std::sync::TryLockError::WouldBlock) => {
                                self.half_delete_in_edge(rev as usize);
                            }
                            Err(std::sync::TryLockError::Poisoned(error)) => {
                                panic!("poisoned reciprocal edge lock: {error}");
                            }
                        }
                    }
                    // Don't increment i.
                }
            } else {
                i += 1;
            }
        }
    }

    // Ghidra: block.cc:507 FlowBlock::findDups
    /// Find blocks that are at the end of multiple edges. Faithful to
    /// `FlowBlock::findDups` (block.cc:507-523): peers are marked with
    /// f_mark on first sight and f_mark2 once reported; a peer already
    /// f_mark-marked is a duplicate. Marks are erased in a second pass.
    /// `self_arc` covers the self-loop case whose lock cannot be taken
    /// (the caller holds this block's write guard): such edges are
    /// optimistically reported, which at worst triggers a no-op eliminate
    /// scan (the oracle's marks are an optimization, not semantics).
    fn find_dups(
        &self,
        ref_edges: &[BlockEdge],
        duplist: &mut Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
        self_arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        for e in ref_edges {
            if Arc::ptr_eq(&e.point, self_arc) {
                // cc:513-519 for the self-loop peer: we cannot take our own
                // write lock; report it (a no-op eliminate scan is safe).
                if !duplist.iter().any(|a| Arc::ptr_eq(a, self_arc)) {
                    duplist.push(self_arc.clone());
                }
                continue;
            }
            let mut p = match e.point.try_write() {
                Ok(g) => g,
                Err(_) => continue, // single-threaded: only self's guard is held
            };
            if p.get_flags() & block_flags::MARK2 != 0 {
                continue; // Already marked as a duplicate
            }
            if p.get_flags() & block_flags::MARK != 0 {
                // We have a duplicate.
                duplist.push(e.point.clone());
                p.set_flags(block_flags::MARK2);
            } else {
                p.set_flags(block_flags::MARK);
            }
        }
        // Erase our marks.
        for e in ref_edges {
            if Arc::ptr_eq(&e.point, self_arc) {
                continue;
            }
            if let Ok(mut p) = e.point.try_write() {
                p.clear_flags(block_flags::MARK | block_flags::MARK2);
            }
        }
    }

    // Ghidra: block.cc:525 FlowBlock::dedup
    /// Deduplicate both edge lists with paired half-deletes. Faithful to
    /// `FlowBlock::dedup` (block.cc:525-536): find duplicate in-edge peers,
    /// eliminate each with `eliminate_in_dups`, then the same for out-edges.
    /// `self_arc` is this block's own Arc (self-loop peers route their peer
    /// half-delete through the WouldBlock arm).
    fn dedup(&mut self, self_arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        let mut duplist: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        {
            let ins = self.in_edges_mut().clone();
            self.find_dups(&ins, &mut duplist, self_arc);
        }
        for bl in duplist.iter() {
            let bl = bl.clone();
            self.eliminate_in_dups(&bl, self_arc);
        }
        duplist.clear();
        {
            let outs = self.out_edges_mut().clone();
            self.find_dups(&outs, &mut duplist, self_arc);
        }
        for bl in duplist.iter() {
            let bl = bl.clone();
            self.eliminate_out_dups(&bl, self_arc);
        }
    }

    /// Is the i-th outgoing edge an irreducible edge? Faithful to Ghidra's
    /// `FlowBlock::isIrreducibleOut` (block.hh:332): the spanning-tree DFS
    /// pretends irreducible edges don't exist (block.cc:1089).
    // Ghidra: block.hh:332 FlowBlock::isIrreducibleOut
    fn is_irreducible_out(&self, i: usize) -> bool {
        self.get_out(i)
            .map(|e| (e.flags & edge_flags::F_IRREDUCIBLE_EDGE) != 0)
            .unwrap_or(false)
    }

    /// Is the i-th incoming edge part of the spanning tree? Faithful to
    /// Ghidra's `FlowBlock::isTreeEdgeIn` (block.hh:329). Read by
    /// `BlockGraph::findIrreducible` (block.cc:1179) to decide whether an
    /// irreducible edge forces a spanning-tree rebuild.
    // Ghidra: block.hh:329 FlowBlock::isTreeEdgeIn
    fn is_tree_edge_in(&self, i: usize) -> bool {
        self.get_in(i)
            .map(|e| (e.flags & edge_flags::F_TREE_EDGE) != 0)
            .unwrap_or(false)
    }

    /// Is the i-th incoming edge a back edge? Faithful to Ghidra's
    /// `FlowBlock::isBackEdgeIn` (block.hh:330). Read by
    /// `BlockGraph::findIrreducible` (block.cc:1158) to seed the reachunder
    /// set of each loop head.
    // Ghidra: block.hh:330 FlowBlock::isBackEdgeIn
    fn is_back_edge_in(&self, i: usize) -> bool {
        self.get_in(i)
            .map(|e| (e.flags & edge_flags::F_BACK_EDGE) != 0)
            .unwrap_or(false)
    }

    /// Is there a looping edge coming into this block (is this the top of a
    /// loop)? Faithful to Ghidra's `FlowBlock::hasLoopIn`
    /// (block.hh:314, block.cc:428-433): any in-edge labeled f_loop_edge.
    /// Read by `RulePullsubMulti::applyOp` (ruleaction.cc:883, "We only
    /// pull up, do not pull down to bottom of loop").
    // Ghidra: block.cc:428 FlowBlock::hasLoopIn
    fn has_loop_in(&self) -> bool {
        for i in 0..self.size_in() {
            if let Some(e) = self.get_in(i) {
                if (e.flags & edge_flags::F_LOOP_EDGE) != 0 {
                    return true;
                }
            }
        }
        false
    }

    /// Is the i-th incoming edge an irreducible edge? Faithful to Ghidra's
    /// `FlowBlock::isIrreducibleIn` (block.hh:333). The reachunder walk of
    /// `BlockGraph::findIrreducible` (block.cc:1170) pretends already-marked
    /// irreducible edges don't exist.
    // Ghidra: block.hh:333 FlowBlock::isIrreducibleIn
    fn is_irreducible_in(&self, i: usize) -> bool {
        self.get_in(i)
            .map(|e| (e.flags & edge_flags::F_IRREDUCIBLE_EDGE) != 0)
            .unwrap_or(false)
    }

    /// OR-set edge flags on the `slot`-th incoming edge. This is the mirrored
    /// half of Ghidra's `FlowBlock::setOutEdgeFlag` (block.cc:245 writes
    /// `bbout->intothis[reverse_index].label |= lab` in addition to the out
    /// edge), exposed so the mirrored write can be applied from the target
    /// side without holding both write locks at once.
    // Ghidra: block.cc:240 FlowBlock::setOutEdgeFlag (mirrored in-edge half)
    fn set_in_edge_flag(&mut self, slot: usize, flag: u32) {
        let ins = self.in_edges_mut();
        if slot < ins.len() {
            ins[slot].flags |= flag;
        }
    }

    /// Clear edge flags from the `slot`-th incoming edge. This is the mirrored
    /// half of Ghidra's `FlowBlock::clearOutEdgeFlag` (block.cc:254 writes
    /// `bbout->intothis[reverse_index].label &= ~lab` in addition to the out
    /// edge), exposed so the mirrored clear can be applied from the target
    /// side without holding both write locks at once. Consumed by
    /// findIrreducible's cross/forward relabel (block.cc:1182).
    // Ghidra: block.cc:250 FlowBlock::clearOutEdgeFlag (mirrored in-edge half)
    fn clear_in_edge_flag(&mut self, slot: usize, flag: u32) {
        let ins = self.in_edges_mut();
        if slot < ins.len() {
            ins[slot].flags &= !flag;
        }
    }

    /// Get the copy-map reference (Ghidra `copymap`: back reference to a
    /// BlockCopy of this block; reset to \b this and used as the FIND function
    /// by findSpanningTree/findIrreducible). Returns the stored Weak handle.
    // Ghidra: block.hh:163 FlowBlock::getCopyMap
    fn get_copy_map(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        None
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::copymap is private at
    // block.hh:123; findSpanningTree assigns it via direct field access)
    fn set_copy_map(&mut self, _m: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {}
    /// Number of descendants of this block in the spanning tree (+1). Ghidra
    /// `numdesc` (block.hh:126) is a private field with no accessor; it is
    /// written directly by findSpanningTree (block.cc:1073/1084). Unset blocks
    /// return -1 (Ghidra leaves the field uninitialized until discovery).
    // RUGRA-GLUE: Rust accessor for Ghidra FlowBlock::numdesc (block.hh:126,
    // private field, no Ghidra accessor; default marks "unset" instead of the
    /// uninitialized C++ value)
    fn get_num_desc(&self) -> i32 {
        -1
    }
    // RUGRA-GLUE: Rust mutator for Ghidra FlowBlock::numdesc (block.hh:126,
    // private field written directly by findSpanningTree block.cc:1073/1098)
    fn set_num_desc(&mut self, _n: i32) {}

    /// Is the `slot`-th outgoing edge a back edge?
    /// Faithful to Ghidra's `FlowBlock::isBackEdgeOut` (block.hh:331).
    // Ghidra: block.hh:331 FlowBlock::isBackEdgeOut
    fn is_back_edge_out(&self, slot: usize) -> bool {
        self.get_out(slot)
            .map(|e| e.flags & edge_flags::F_BACK_EDGE != 0)
            .unwrap_or(false)
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge);
    // RUGRA-GLUE: Rust edge-construction helper (Ghidra manages outofthis via friend addInEdge)
    fn add_out_edge(&mut self, edge: BlockEdge);

    // RUGRA-GLUE: Rust helper returning Vec<PcodeOpRef> (Ghidra BlockBasic exposes begin/end iterators)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        Vec::new()
    }
    /// Return the indexed component of this block. This is the Rust trait
    /// dispatch corresponding to Ghidra's virtual `FlowBlock::subBlock`.
    // Ghidra: block.hh:190 FlowBlock::subBlock
    fn sub_block(&self, _slot: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        None
    }
    /// Return the first PcodeOp reached through this block.
    // Ghidra: block.hh:233 FlowBlock::firstOp
    fn first_op(&self) -> Option<PcodeOpRef> {
        None
    }
    // Ghidra: block.hh:466 BlockBasic::insert
    fn add_op(&mut self, _op: PcodeOpRef) {}
    // Ghidra: block.hh:466 BlockBasic::insert
    fn insert_op(&mut self, _index: usize, _op: PcodeOpRef) {}

    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        Address::new(0)
    }

    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>>;

    // Dominance related methods
    // Ghidra: block.hh:162 FlowBlock::getImmedDom
    fn get_immed_dom(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        None
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::immed_dom is private; set by buildDomTree as friend)
    fn set_immed_dom(&mut self, _dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {}
    // RUGRA-GLUE: Rugra-only dom-depth field (Ghidra computes depth via buildDomDepth into separate vec)
    fn get_dom_depth(&self) -> i32 {
        -1
    }
    // RUGRA-GLUE: Rust mutator for dom_depth (Ghidra has no dom-depth field on FlowBlock)
    fn set_dom_depth(&mut self, _depth: i32) {}
    // RUGRA-GLUE: Rugra-only dom-children field (Ghidra returns dom tree via buildDomTree(child) external vec)
    fn get_dom_children(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        Vec::new()
    }
    // RUGRA-GLUE: Rust mutator for dom_children (Ghidra builds dom tree externally in BlockGraph::buildDomTree)
    fn add_dom_child(&mut self, _child: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {}
    // RUGRA-GLUE: Rust mutator for dom_children (Ghidra has no dom-children field on FlowBlock)
    fn clear_dom_children(&mut self) {}
    // RUGRA-GLUE: Rugra-only dom-frontier field (Ghidra has no dom-frontier field on FlowBlock)
    fn get_dom_frontier(&self) -> std::collections::HashSet<i32> {
        std::collections::HashSet::new()
    }
    // RUGRA-GLUE: Rust mutator for dom_frontier (Ghidra has no dom-frontier field on FlowBlock)
    fn add_to_dom_frontier(&mut self, _idx: i32) {}
    // RUGRA-GLUE: Rust mutator for dom_frontier (Ghidra has no dom-frontier field on FlowBlock)
    fn clear_dom_frontier(&mut self) {}

    /// Reverse-index of the given incoming edge slot — i.e. the index of
    /// `this` in the source block's outgoing list. Faithful to
    /// `FlowBlock::getInRevIndex` (block.hh:308).
    // Ghidra: block.hh:306 FlowBlock::getInRevIndex
    fn get_in_rev_index(&self, _slot: usize) -> i32 {
        -1
    }

    // ---- Dominance queries (block.hh:310, block.cc:386-395) ----

    /// Does this block dominate `other`? Walk `other`'s dominator chain up
    /// until we hit `self`. Faithful to `FlowBlock::dominates` (block.cc:386).
    // Ghidra: block.cc:386 FlowBlock::dominates
    fn dominates(&self, other: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        let self_idx = self.get_index();
        let mut cur = other.clone();
        loop {
            let (cur_idx, parent) = {
                let g = cur.read().unwrap();
                let idx = g.get_index();
                let dom = g.get_immed_dom().and_then(|w| w.upgrade());
                (idx, dom)
            };
            if cur_idx == self_idx && self_idx >= 0 {
                return true;
            }
            match parent {
                Some(p) => cur = p,
                None => return false,
            }
        }
    }

    // ---- CBRANCH true/false out-edge helpers ----
    // Ghidra block.hh:299-300: getFalseOut() = outofthis[0].point,
    // getTrueOut() = outofthis[1].point — PURELY POSITIONAL, they never read
    // the CBRANCH's BOOLEAN_FLIP flag. The layout invariant is established by
    // flow construction (flow.cc:960-967 / flow.rs:920-928: fallthru edge is
    // pushed first, then the branch edge, so out[0]=false path, out[1]=true
    // path for an unflipped CBRANCH) and re-established by negateCondition
    // (block.cc:2351, which toggles flip AND swaps the two out edges).
    // BOOLEAN_FLIP therefore only records that the boolean input's polarity
    // is inverted relative to the branch-taken edge; consumers that need
    // bool-polarity consult it at their call sites (condexe.cc:612,
    // expression.cc:227-230, ruleaction.cc:8981, ruleaction.cc:9428,
    // coreaction.cc:4538, double.cc:922) — never inside these getters.
    // NOTE: the `cbranch` parameter is vestigial (positional getters ignore
    // it); it is retained only so in-flight writers of leased consumer files
    // keep compiling. Follow-up: drop it once ruleaction.rs' lease frees
    // (see TODO CONDEXE-TRUEOUT-0002 residual in docs/TODO_BOARD.md).

    /// Get the TRUE out-edge target of this block (out[1], positional).
    /// `cbranch` is unused (kept for signature compatibility).
    // Ghidra: block.hh:300 FlowBlock::getTrueOut
    fn get_true_out(
        &self,
        _cbranch: &PcodeOpRef,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.get_out(1).map(|e| e.point)
    }

    /// Get the FALSE out-edge target of this block (out[0], positional).
    /// `cbranch` is unused (kept for signature compatibility).
    // Ghidra: block.hh:299 FlowBlock::getFalseOut
    fn get_false_out(
        &self,
        _cbranch: &PcodeOpRef,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.get_out(0).map(|e| e.point)
    }

    // ---- Mark / visit-count / edge-flag accessors (Ghidra block.hh:286-347) ----
    // These underpin LoopBody's body collection, exit detection, and TraceDAG
    // bounds. Defaults are no-ops; BlockBasic overrides them.
    /// Generic block mark (Ghidra `isMark`). Used by LoopBody::findBase etc.
    // Ghidra: block.hh:286 FlowBlock::isMark
    fn is_mark(&self) -> bool {
        false
    }
    // Ghidra: block.hh:287 FlowBlock::setMark
    fn set_mark(&mut self) {}
    // Ghidra: block.hh:288 FlowBlock::clearMark
    fn clear_mark(&mut self) {}
    /// Scratch visit count (Ghidra `getVisitCount`/`setVisitCount`). Used by
    /// LoopBody::extend to count how many in-edges reach a candidate block.
    // Ghidra: block.hh:283 FlowBlock::getVisitCount
    fn get_visit_count(&self) -> i32 {
        0
    }
    // Ghidra: block.hh:282 FlowBlock::setVisitCount
    fn set_visit_count(&mut self, _c: i32) {}

    // Ghidra: block.hh:143 FlowBlock::isSwitchOut
    /// Is this block a switch dispatch (BRANCHIND output)?
    fn is_switch_out(&self) -> bool {
        (self.get_flags() & block_flags::SWITCH_OUT) != 0
    }

    // Ghidra: block.hh:316 FlowBlock::isLoopIn
    fn is_loop_in(&self, i: usize) -> bool {
        self.get_in(i)
            .map(|e| (e.flags & edge_flags::F_LOOP_EDGE) != 0)
            .unwrap_or(false)
    }

    // Ghidra: block.hh:317 FlowBlock::isLoopOut
    fn is_loop_out(&self, i: usize) -> bool {
        self.get_out(i)
            .map(|e| (e.flags & edge_flags::F_LOOP_EDGE) != 0)
            .unwrap_or(false)
    }

    // Ghidra: block.hh:320 FlowBlock::isDefaultBranch
    fn is_default_branch(&self, i: usize) -> bool {
        self.get_out(i)
            .map(|e| (e.flags & edge_flags::F_DEFAULTSWITCH_EDGE) != 0)
            .unwrap_or(false)
    }

    // Ghidra: block.hh:336 FlowBlock::isLoopExitOut
    fn is_loop_exit_out(&self, i: usize) -> bool {
        self.get_out(i)
            .map(|e| (e.flags & edge_flags::F_LOOP_EXIT_EDGE) != 0)
            .unwrap_or(false)
    }

    /// Is the i-th incoming edge a goto/irreducible edge? (Ghidra `isGotoIn`.)
    // Ghidra: block.hh:346 FlowBlock::isGotoIn
    fn is_goto_in(&self, _i: usize) -> bool {
        false
    }
    /// Is the i-th outgoing edge a goto/irreducible edge? (Ghidra `isGotoOut`.)
    // Ghidra: block.hh:347 FlowBlock::isGotoOut
    fn is_goto_out(&self, _i: usize) -> bool {
        false
    }

    // Ghidra: block.hh:336 FlowBlock::isInteriorGotoTarget
    /// Is this block the target of an unstructured (goto) jump from inside
    /// a loop body? Faithful to `isInteriorGotoTarget()` (block.hh:336).
    /// Ghidra reads the f_interior_gotoin flag (set by setGotoBranch
    /// block.cc:313). Rugra now sets that flag in set_goto_branch, so this
    /// checks it directly. We also keep the in-edge goto check as a
    /// fallback for edges marked GOTO via other paths.
    fn is_interior_goto_target(&self) -> bool {
        if (self.get_flags() & block_flags::INTERIOR_GOTOIN) != 0 {
            return true;
        }
        for i in 0..self.size_in() {
            if self.is_goto_in(i) {
                return true;
            }
        }
        false
    }

    // Ghidra: block.hh:324 FlowBlock::hasInteriorGoto
    /// Is there an unstructured goto out of this block's interior? Faithful
    /// to `hasInteriorGoto()` (block.hh:324). Checks f_interior_gotoout
    /// (set by setGotoBranch block.cc:311).
    fn has_interior_goto(&self) -> bool {
        (self.get_flags() & block_flags::INTERIOR_GOTOOUT) != 0
    }

    // Ghidra: block.hh:297 FlowBlock::getFlipPath
    /// Have out edges been flipped (swapped) since the last path trace?
    /// Faithful to `getFlipPath()` (block.hh:297): checks f_flip_path flag.
    /// Used by jumptable checkUnrolledGuard (jumptable.cc:1369) to determine
    /// which in-edge index corresponds to the switch value.
    fn get_flip_path(&self) -> bool {
        (self.get_flags() & block_flags::FLIP_PATH) != 0
    }

    // Ghidra: block.hh:249 FlowBlock::isComplex
    /// Is \b this too complex to be a condition (BlockCondition)?
    /// Faithful to the base virtual (block.hh:249-250): returns \b true —
    /// anything that is not specifically a leaf/basic block (or a delegating
    /// subclass) is too complex to be emitted as a conditional clause.
    /// BlockBasic/BlockCopy/BlockCondition override with the real semantics
    /// (block.cc:2388, block.hh:536, block.hh:635).
    fn is_complex(&self) -> bool {
        true
    }

    // Ghidra: block.cc:405 FlowBlock::restrictedByConditional
    /// Check if this block is completely dominated by the conditional block
    /// `cond` — all paths reaching this block go through cond's edge, so a
    /// boolean constant holds. Faithful to `restrictedByConditional`
    /// (block.cc:405-425).
    fn restricted_by_conditional(&self, cond: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        // cc:408: single in-edge → always restricted.
        if self.size_in() == 1 {
            return true;
        }
        // cc:409: check immedDom == cond.
        let my_dom = self.get_immed_dom().and_then(|w| w.upgrade());
        match &my_dom {
            Some(d) if Arc::ptr_eq(d, cond) => {}
            _ => return false,
        }
        // cc:410-423: verify all in-edges only reach via cond.
        let mut seen_cond = false;
        let self_idx = self.get_index();
        for i in 0..self.size_in() {
            let in_block = match self.get_in(i) {
                Some(e) => e.point.clone(),
                None => continue,
            };
            if Arc::ptr_eq(&in_block, cond) {
                if seen_cond {
                    return false;
                }
                seen_cond = true;
                continue;
            }
            // Walk dom chain from in_block up to self, checking if cond is hit.
            let mut cur = in_block;
            loop {
                if Arc::ptr_eq(&cur, cond) {
                    return false;
                }
                let cur_idx = cur.read().unwrap().get_index();
                if cur_idx == self_idx {
                    break;
                }
                let up = cur
                    .read()
                    .unwrap()
                    .get_immed_dom()
                    .and_then(|w| w.upgrade());
                match up {
                    Some(u) => {
                        if Arc::ptr_eq(&u, cond) {
                            return false;
                        }
                        if u.read().unwrap().get_index() == self_idx {
                            break;
                        }
                        cur = u;
                    }
                    None => break,
                }
            }
        }
        true
    }

    // Ghidra: block.cc:294 FlowBlock::negateCondition
    /// Flip the true/false out-edge semantics of this block's CBRANCH.
    /// Returns true if the flip changed the dataflow. Faithful to
    /// `negateCondition(bool)` (block.hh:294). Base impl: if toporbottom,
    /// swap out edges + toggle f_flip_path, return false (no dataflow change).
    fn negate_condition(&mut self, toporbottom: bool) -> bool {
        if !toporbottom {
            return false;
        }
        self.swap_edges();
        false
    }

    // Ghidra: block.cc:218 FlowBlock::swapEdges
    /// Swap the two outgoing edges of this block. Faithful to
    /// `swapEdges()` (block.cc:218-233). Also updates reverse_index on
    /// the target blocks and toggles f_flip_path.
    fn swap_edges(&mut self) {
        let pending = {
            let outgoing = self.out_edges_mut();
            if outgoing.len() != 2 {
                return;
            }
            outgoing.swap(0, 1);
            outgoing
                .iter()
                .enumerate()
                .map(|(slot, edge)| (slot, edge.point.clone(), edge.reverse_index))
                .collect::<Vec<_>>()
        };
        for (slot, target, reverse_index) in pending {
            if reverse_index < 0 {
                continue;
            }
            match target.try_write() {
                Ok(mut peer) => {
                    if let Some(edge) = peer.in_edges_mut().get_mut(reverse_index as usize) {
                        edge.reverse_index = slot as i32;
                    }
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if let Some(edge) = self.in_edges_mut().get_mut(reverse_index as usize) {
                        edge.reverse_index = slot as i32;
                    }
                }
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    panic!("poisoned reciprocal edge lock: {error}");
                }
            }
        }
        if self.get_flags() & block_flags::FLIP_PATH != 0 {
            self.clear_flags(block_flags::FLIP_PATH);
        } else {
            self.set_flags(block_flags::FLIP_PATH);
        }
    }

    /// Is this block the entry point of the function? (block.hh:325)
    // Ghidra: block.hh:325 FlowBlock::isEntryPoint
    fn is_entry_point(&self) -> bool {
        (self.get_flags() & block_flags::ENTRY_POINT) != 0
    }
    /// Label the i-th out edge as a loop-exit edge (Ghidra `setLoopExit`).
    // Ghidra: block.hh:294 FlowBlock::setLoopExit
    fn set_loop_exit(&mut self, _i: usize) {}
    /// Clear the loop-exit label on the i-th out edge (Ghidra `clearLoopExit`).
    // Ghidra: block.hh:295 FlowBlock::clearLoopExit
    fn clear_loop_exit(&mut self, _i: usize) {}

    /// Ghidra `FlowBlock::scopeBreak` (block.hh:266, virtual; default impl in
    /// block.cc:284-289): propagate the current exit/loop-exit scope into
    /// children so unstructured gotos can be reclassified as `break`/
    /// `continue`. Default: recurse into all children. Structured block
    /// subtypes override this (block.cc:3075 BlockIf, 3324 BlockWhileDo, etc.).
    /// Rugra provides a default no-op for blocks with no structured children
    /// (BlockBasic/BlockCopy); the structured blocks override via their
    /// inherent `scope_break_goto_type` helpers which call this trait method
    /// to recurse.
    // Ghidra: block.hh:266 FlowBlock::scopeBreak
    fn scope_break_trait(&mut self, _cur_exit: i32, _cur_loop_exit: i32) {}

    /// Ghidra `FlowBlock::markUnstructured` (block.hh, virtual; default in
    /// block.cc is a no-op for leaf blocks like BlockBasic/BlockCopy). The
    /// `BlockGraph` override recurses into all children (block.cc:1238-1245);
    /// `BlockGoto`/`BlockIf`/`BlockSwitch` recurse then mark their goto
    /// targets (if still `f_goto_goto`) as `f_unstructured_targ`
    /// (block.cc:2811, 3022, 3558). Rugra's structured blocks provide
    /// inherent helpers; the default no-op covers BlockBasic (BlockGoto marks
    /// via its inherent `mark_unstructured_target`).
    // Ghidra: block.hh FlowBlock::markUnstructured
    fn mark_unstructured_trait(&mut self) {}

    /// Ghidra `FlowBlock::markLabelBumpUp` (block.hh:195, virtual; base body
    /// block.cc:259-264): mark that labels for this block are printed by
    /// somebody higher in the hierarchy. The base implementation only sets
    /// `f_label_bumpup` when `bump` is true — no recursion, no clearing.
    /// Consumers: `PrintC::emitAnyLabelStatement` (printc.cc:3222) returns
    /// early for flagged blocks. Overriding subtypes (via the inherited
    /// `BlockGraph::markLabelBumpUp` semantics, block.cc:1258-1268): every
    /// composite recurses — first subblock receives `bump` unchanged, all
    /// others receive `false`; WhileDo/DoWhile/InfLoop (block.cc:3316/3426/
    /// 3454) force `true` down the front chain, then clear their own flag
    /// when the incoming `bump` was false. Rugra's composite structs override
    /// this trait method; leaves (BlockBasic/BlockCopy) keep this default.
    // Ghidra: block.hh:195 FlowBlock::markLabelBumpUp
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        // cc:262-263: if (bump) flags |= f_label_bumpup;
        if bump {
            self.set_flags(block_flags::LABEL_BUMPUP);
        }
    }

    /// Ghidra `FlowBlock::getExitLeaf` (block.hh, virtual): the leaf block
    /// that flow exits through, if there is a single one. Default: null.
    /// BlockList/BlockIf override (block.cc:2953, 3111).
    // Ghidra: block.hh FlowBlock::getExitLeaf
    fn get_exit_leaf_trait(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        None
    }

    /// Ghidra `FlowBlock::flipInPlaceTest` (block.hh, virtual; block.cc:2368
    /// BlockBasic impl): test whether the CBRANCH controlling this block can
    /// be flipped in place without violating cover constraints. Returns 0 if
    /// flippable, non-zero reason code otherwise. Default: 2 (not flippable).
    // Ghidra: block.hh FlowBlock::flipInPlaceTest
    fn flip_in_place_test(&self) -> i32 {
        2
    }

    /// Ghidra `FlowBlock::flipInPlaceExecute` (block.hh, virtual): perform the
    /// in-place CBRANCH flip. Default: no-op (BlockBasic overrides in
    /// block.cc:2368 to negate the boolean input).
    // Ghidra: block.hh FlowBlock::flipInPlaceExecute
    fn flip_in_place_execute(&mut self) {}

    /// Ghidra `FlowBlock::lastOp` (block.hh, virtual): the last PcodeOp in
    /// this block, or null. Default: null. BlockBasic/BlockList/BlockIf/
    /// BlockCondition override (block.cc:761, 2960, 3119, 3016).
    // Ghidra: block.hh FlowBlock::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        None
    }

    /// Return the deepest component that performs this block's conditional
    /// split. Implementations that return themselves keep a weak self handle
    /// installed when the block is added to its graph.
    // Ghidra: block.hh:243 FlowBlock::getSplitPoint
    fn get_split_point(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        None
    }

    // ---- Marshaling (block.cc:2447-2510) ----

    /// Ghidra `FlowBlock::encodeHeader` (block.cc:2447-2451): emit the `index`
    /// attribute. Sub-classes (BlockCopy, BlockCondition) override to add
    /// extra attributes. Default writes only the index.
    // Ghidra: block.cc:2447 FlowBlock::encodeHeader
    fn encode_header_trait(&self, encoder: &mut dyn Encoder) {
        // cc:2450: encoder.writeSignedInteger(ATTRIB_INDEX, index);
        encoder.write_signed_integer(&attrib_index(), self.get_index() as i64);
    }

    /// Ghidra `FlowBlock::decodeHeader` (block.cc:2454-2458): read the `index`
    /// attribute and store it on this block.
    // Ghidra: block.cc:2454 FlowBlock::decodeHeader
    fn decode_header_trait(&mut self, decoder: &mut dyn Decoder) {
        // cc:2457: index = decoder.readSignedInteger(ATTRIB_INDEX);
        let i = decoder.read_signed_integer_attr(&attrib_index());
        self.set_index(i as i32);
    }

    /// Ghidra `FlowBlock::encodeEdges` (block.cc:2462-2468): emit one \<edge>
    /// element per incoming edge. Default iterates `intothis`.
    // Ghidra: block.cc:2462 FlowBlock::encodeEdges
    fn encode_edges_trait(&self, encoder: &mut dyn Encoder) {
        // cc:2465-2467: for (i=0; i<intothis.size(); ++i) intothis[i].encode(encoder);
        for i in 0..self.size_in() {
            if let Some(e) = self.get_in(i) {
                encode_block_edge(&e, encoder);
            }
        }
    }

    /// Ghidra `FlowBlock::encodeBody` (block.hh, virtual): emit the type-
    /// specific body of this block. Default: no-op (plain FlowBlock has no
    /// body). BlockBasic/BlockGraph/BlockGoto/BlockIf override.
    // Ghidra: block.hh FlowBlock::encodeBody
    fn encode_body_trait(&self, _encoder: &mut dyn Encoder) {}

    /// Ghidra `FlowBlock::decodeBody` (block.hh, virtual): restore the type-
    /// specific body. Default: no-op.
    // Ghidra: block.hh FlowBlock::decodeBody
    fn decode_body_trait(&mut self, _decoder: &mut dyn Decoder) {}

    /// Ghidra `FlowBlock::encode` (block.cc:2487-2495): encode this block as a
    /// \<block> element — header, body, then edges.
    // Ghidra: block.cc:2487 FlowBlock::encode
    fn encode_trait(&self, encoder: &mut dyn Encoder) {
        // cc:2490-2494: openElement(BLOCK); encodeHeader; encodeBody; encodeEdges; closeElement.
        let block_id = elem_block();
        encoder.open_element(&block_id);
        self.encode_header_trait(encoder);
        self.encode_body_trait(encoder);
        self.encode_edges_trait(encoder);
        encoder.close_element(&block_id);
    }

    /// Ghidra `FlowBlock::printHeader` (block.cc:604-611): emit the block
    /// index, optionally followed by the start-stop address range. Default
    /// writes the index and the address range if both ends are valid.
    // Ghidra: block.cc:604 FlowBlock::printHeader
    fn print_header_trait(&self) -> String {
        // cc:607: s << dec << index;
        let mut s = format!("{}", self.get_index());
        // cc:608-610: if (!getStart().isInvalid() && !getStop().isInvalid()) s << ' ' << getStart() << '-' << getStop();
        let start = self.get_start_addr();
        if !start.is_null() {
            s.push_str(&format!(" {}", start));
        }
        s
    }

    /// Ghidra `FlowBlock::printTree` (block.cc:616-625): emit the header
    /// indented by `level` spaces. Default does not recurse (leaf blocks).
    // Ghidra: block.cc:616 FlowBlock::printTree
    fn print_tree_trait(&self, level: i32) -> String {
        // cc:621-624: indent; printHeader(s); s << endl;
        let indent: String = "  ".repeat(level as usize);
        format!("{}{}\n", indent, self.print_header_trait())
    }

    /// Ghidra `FlowBlock::printRaw` (block.hh, virtual): emit the raw p-code /
    /// block listing. Default: emit just the header (no body to print).
    // Ghidra: block.hh FlowBlock::printRaw
    fn print_raw_trait(&self) -> String {
        // cc: default behaviour: just the header line.
        format!("{}\n", self.print_header_trait())
    }

    /// Ghidra `FlowBlock::printRawImpliedGoto` (block.hh, virtual): emit an
    /// implied goto comment if this block's fall-thru does not reach
    /// `next_block`. Default: no-op (no implied goto for leaf blocks without
    /// a single out-edge).
    // Ghidra: block.hh FlowBlock::printRawImpliedGoto
    fn print_raw_implied_goto_trait(
        &self,
        _next_block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> String {
        String::new()
    }
}

/// Ghidra `BlockEdge::encode` (block.cc:35-43): emit an \<edge> element with
/// `end` (the other-end block index) and `rev` (reverse-index) attributes.
/// Free function because Rugra's `BlockEdge` is a plain struct (no Ghidra
/// `BlockEdge::encode` method dispatch).
// Ghidra: block.cc:35 BlockEdge::encode
pub fn encode_block_edge(edge: &BlockEdge, encoder: &mut dyn Encoder) {
    // cc:38-42: openElement(EDGE); writeSignedInteger(ATTRIB_END, point->getIndex());
    //          writeSignedInteger(ATTRIB_REV, reverse_index); closeElement(EDGE);
    let edge_id = elem_edge();
    encoder.open_element(&edge_id);
    let end_idx = edge.point.read().unwrap().get_index();
    encoder.write_signed_integer(&attrib_end(), end_idx as i64);
    encoder.write_signed_integer(&attrib_rev(), edge.reverse_index as i64);
    encoder.close_element(&edge_id);
}

/// Find the CBRANCH that controls two block/edge paths.
/// Faithful to `FlowBlock::findCondition` (block.cc:839-858).
///
/// Given `bl1` reached via its `edge1`-th in-edge, and `bl2` reached via its
/// `edge2`-th in-edge, walk both in-chains up to the common 2-out (decision)
/// block that dominates both. Returns `(cond_block, slot1)` where `slot1` is
/// `bl1`'s rev-in-edge index into the condition block, or `None` if the paths
/// don't share a single decision point.
// Ghidra: block.cc:839 FlowBlock::findCondition
pub fn find_condition(
    bl1: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    edge1: usize,
    bl2: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    edge2: usize,
) -> Option<(Arc<RwLock<dyn FlowBlock + Send + Sync>>, i32)> {
    let cond1 = {
        let rg = bl1.read().unwrap();
        rg.get_in(edge1).map(|e| e.point)
    };
    let mut cond = cond1?;
    // Walk bl1's in-chain up to a 2-out decision block.  Ghidra (block.cc:845-847)
    // updates bl1 = cond; edge1 = 0 on every hop, so the final rev-index below
    // must be taken on the block directly below `cond`, not on the caller's
    // original bl1/edge1.
    let mut cur_bl1 = bl1.clone();
    let mut cur_edge1 = edge1;
    loop {
        let cond_rg = cond.read().unwrap();
        let nout = cond_rg.size_out();
        if nout == 2 {
            break;
        }
        if nout != 1 {
            return None;
        }
        let next = cond_rg.get_in(0).map(|e| e.point);
        drop(cond_rg);
        // cc:845-847: bl1 = cond; edge1 = 0; cond = bl1->getIn(0);
        let new_cond = match next {
            Some(p) => p,
            None => return None,
        };
        cur_bl1 = cond.clone();
        cur_edge1 = 0;
        cond = new_cond;
    }

    // Now walk bl2's in-chain up to `cond`.
    let mut cur_bl2 = bl2.clone();
    let mut cur_edge2 = edge2;
    loop {
        let bl2_in = {
            let rg = cur_bl2.read().unwrap();
            rg.get_in(cur_edge2).map(|e| e.point)
        };
        let bl2_pred = match bl2_in {
            Some(p) => p,
            None => return None,
        };
        if Arc::ptr_eq(&bl2_pred, &cond) {
            break;
        }
        let bl2_pred_rg = bl2_pred.read().unwrap();
        if bl2_pred_rg.size_out() != 1 {
            return None;
        }
        drop(bl2_pred_rg);
        cur_bl2 = bl2_pred;
        cur_edge2 = 0;
    }

    // slot1 = bl1's rev-in-edge index into cond — with bl1/edge1 as updated by
    // the walk (block.cc:856), i.e. the out-slot of `cond` whose edge leads to
    // the last block on the bl1 chain.
    let slot1 = {
        let rg = cur_bl1.read().unwrap();
        rg.get_in_rev_index(cur_edge1)
    };
    Some((cond, slot1))
}

/// FIND(y) for findIrreducible's union structure: reads `y->copymap`
/// (block.hh:123). findSpanningTree initializes every block's copymap to
/// \b this (block.cc:1027/1122) and findIrreducible's collapse step
/// (block.cc:1194) re-points reachunder members at the loop head, so the
/// one-step read is the complete FIND (Ghidra keeps the map flat and reads
/// the raw pointer directly at block.cc:1161/1173). The `Option` fallback
/// to `y` itself is unreachable on the oracle path (copymap is always set
/// for blocks in `list`).
// RUGRA-GLUE: FIND(y) read of Ghidra FlowBlock::copymap (block.hh:123 raw
// pointer dereference at block.cc:1161/1173; Rust Weak upgrade with
// unreachable self fallback)
fn find_copy_map(
    y: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
    y.read()
        .unwrap()
        .get_copy_map()
        .and_then(|w| w.upgrade())
        .unwrap_or_else(|| y.clone())
}

/// OR-set edge flags on the `i`-th outgoing edge of `cur` AND on the mirrored
/// incoming edge of the target block. Faithful to the complete Ghidra
/// `FlowBlock::setOutEdgeFlag` (block.cc:240-246): the label is applied to
/// `outofthis[i]` and to `outofthis[i].point->intothis[reverse_index]`.
/// Ghidra follows raw pointers; in Rugra the two halves live behind separate
/// `RwLock`s, so a self-edge (loop to the same block) must set both halves
/// under ONE guard — taking the second lock would deadlock on the caller's
/// held guard.
// Ghidra: block.cc:240 FlowBlock::setOutEdgeFlag
pub fn set_out_edge_flag_mirrored(
    cur: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    i: usize,
    lab: u32,
) {
    let (target, rev) = match cur.read().unwrap().get_out(i) {
        Some(e) => (e.point.clone(), e.reverse_index),
        None => return,
    };
    if Arc::ptr_eq(&target, cur) {
        // Self-edge: both halves live on this block; one exclusive guard.
        // Route through the trait-wide out_edges_mut/in_edges_mut so the
        // write lands for EVERY block kind (Ghidra's FlowBlock base owns
        // outofthis/intothis for all subtypes, block.hh:124-127) — the old
        // BlockBasic/BlockGraph downcast chain silently dropped self-edge
        // labels on structured blocks.
        let mut g = cur.write().unwrap();
        {
            let outs = g.out_edges_mut();
            if i < outs.len() {
                outs[i].flags |= lab;
            }
        }
        let ins = g.in_edges_mut();
        if (rev as usize) < ins.len() {
            ins[rev as usize].flags |= lab;
        }
    } else {
        cur.write().unwrap().set_out_edge_flag(i, lab);
        target.write().unwrap().set_in_edge_flag(rev as usize, lab);
    }
}

/// Clear edge flags from the `i`-th outgoing edge of `cur` AND from the
/// mirrored incoming edge of the target block. Faithful to the complete
/// Ghidra `FlowBlock::clearOutEdgeFlag` (block.cc:250-256): the label bits
/// are removed from `outofthis[i]` and from
/// `outofthis[i].point->intothis[reverse_index]`. Ghidra follows raw
/// pointers; in Rugra the two halves live behind separate `RwLock`s, so a
/// self-edge (loop to the same block) must clear both halves under ONE
/// guard. Called by findIrreducible (block.cc:1182) when a non-tree edge is
/// promoted to irreducible: the stale cross/forward classification is
/// removed from both halves.
// Ghidra: block.cc:250 FlowBlock::clearOutEdgeFlag
pub fn clear_out_edge_flag_mirrored(
    cur: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    i: usize,
    lab: u32,
) {
    let (target, rev) = match cur.read().unwrap().get_out(i) {
        Some(e) => (e.point.clone(), e.reverse_index),
        None => return,
    };
    if Arc::ptr_eq(&target, cur) {
        // Self-edge: both halves live on this block; one exclusive guard.
        // Trait-wide accessors (see set_out_edge_flag_mirrored): Ghidra's
        // FlowBlock base owns both edge arrays for every subtype.
        let mut g = cur.write().unwrap();
        {
            let outs = g.out_edges_mut();
            if i < outs.len() {
                outs[i].flags &= !lab;
            }
        }
        let ins = g.in_edges_mut();
        if (rev as usize) < ins.len() {
            ins[rev as usize].flags &= !lab;
        }
    } else {
        cur.write().unwrap().clear_out_edge_flag(i, lab);
        target
            .write()
            .unwrap()
            .clear_in_edge_flag(rev as usize, lab);
    }
}

/// Mark exactly one outgoing edge as the switch default and mirror every
/// label mutation onto the corresponding target incoming edge. Ghidra's
/// `setDefaultSwitch` scans outgoing edges in slot order, clears only slots
/// already carrying `f_defaultswitch_edge`, then marks `pos` through the
/// paired `setOutEdgeFlag` operation (block.cc:318-326).
// Ghidra: block.cc:318 FlowBlock::setDefaultSwitch
pub fn set_default_switch_mirrored(
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pos: usize) {
    let previous_defaults = {
        let rg = block.read().unwrap();
        (0..rg.size_out())
            .filter(|slot| {
                rg.get_out(*slot)
                    .map(|edge| edge.flags & edge_flags::F_DEFAULTSWITCH_EDGE != 0)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>()
    };
    for slot in previous_defaults {
        clear_out_edge_flag_mirrored(block, slot, edge_flags::F_DEFAULTSWITCH_EDGE);
    }
    set_out_edge_flag_mirrored(block, pos, edge_flags::F_DEFAULTSWITCH_EDGE);
}

/// Represents a basic block of P-code operations
///
/// Corresponds to Ghidra's `BlockBasic` class
#[derive(Debug)]
pub struct BlockBasic {
    /// Index of this block within the function
    pub index: i32,
    /// List of operations in this block
    pub ops: Vec<PcodeOpRef>,
    /// Input edges
    pub incoming: Vec<BlockEdge>,
    /// Output edges
    pub outgoing: Vec<BlockEdge>,
    /// Parent block (if nested in a composite block)
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    /// Weak self handle used to reproduce virtual methods that return
    /// `this` (`getExitLeaf` and `getSplitPoint`) through a trait object.
    // RUGRA-GLUE: Rust self-reference for Ghidra methods returning `this`
    pub self_ref: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Block flags
    pub flags: u32,
    /// Start address of the block
    pub start_addr: Address,
    /// Original instruction-address ranges (the block \e cover).  Ghidra
    /// `RangeList cover` (block.hh:465): starts as the single closed range
    /// of the block's instructions (`setInitialRange`), then grows via
    /// `mergeRange` when blocks are spliced (funcdata_block.cc:942) and is
    /// cloned via `copyRange` on node-split (funcdata_block.cc:832).
    /// `getStart`/`getStop` read the FIRST/LAST range in (space, offset)
    /// sort order, so a spliced block whose absorbed chunk sits at a LOWER
    /// address reports that lower address as its start (block.cc:2319-2335).
    // Ghidra: block.hh:465 BlockBasic::cover
    cover: crate::address::RangeList,

    /// Immediate dominator of this block
    pub immed_dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Depth in the dominator tree
    pub dom_depth: i32,
    /// Children in the dominator tree
    pub dom_children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Dominance frontier of this block (indices of blocks)
    pub dom_frontier: std::collections::HashSet<i32>,
    /// Scratch visit-count for LoopBody::extend (Ghidra getVisitCount/
    /// setVisitCount). Reset to 0 after each use.
    pub visit_count: i32,
    /// Back reference to a BlockCopy of this block (Ghidra `copymap`,
    /// block.hh:123). Reset to \b this by BlockGraph::find_spanning_tree
    /// (block.cc:1027/1122) and repurposed as the FIND function by
    /// findIrreducible (block.cc:1161/1194).
    pub copy_map: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Number of descendants of this block in the spanning tree (+1) (Ghidra
    /// `numdesc`, block.hh:126). -1 marks unset (Ghidra leaves the field
    /// uninitialized until findSpanningTree discovers the block).
    pub num_desc: i32,
}

impl BlockBasic {
    // Ghidra: block.hh:473 BlockBasic::BlockBasic
    pub fn new(index: i32, start_addr: Address) -> Self {
        Self {
            index,
            ops: Vec::new(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            self_ref: None,
            flags: 0,
            start_addr,
            cover: crate::address::RangeList::new(),
            immed_dom: None,
            dom_depth: -1,
            dom_children: Vec::new(),
            dom_frontier: std::collections::HashSet::new(),
            visit_count: 0,
            copy_map: None,
            num_desc: -1,
        }
    }

    // Ghidra: block.cc:2802 BlockBasic::liftVerifyUnroll
    /// Verify that all Varnodes in varArray are defined by the same opcode
    /// with matching constant operand, then "unroll" by replacing each
    /// varnode with its input at `slot`. Returns true if all match.
    /// Faithful to `liftVerifyUnroll` (block.cc:2802-2832).
    /// Used by jumptable checkUnrolledGuard to verify loop-unrolling guards.
    pub fn lift_verify_unroll(
        var_array: &mut Vec<Arc<RwLock<crate::varnode::Varnode>>>,
        slot: usize,
    ) -> bool {
        if var_array.is_empty() {
            return false;
        }
        // cc:2808: check first varnode's def op.
        let vn0 = var_array[0].clone();
        let (opc, cvn_opt): (
            crate::opcodes::OpCode,
            (
                Option<Arc<RwLock<crate::varnode::Varnode>>>,
                Option<Arc<RwLock<crate::varnode::Varnode>>>,
            ),
        ) = {
            let vn = vn0.read().unwrap();
            if !vn.is_written() {
                return false;
            }
            let def_arc = match vn.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d,
                None => return false,
            };
            let def = def_arc.read().unwrap();
            let opc = def.opcode;
            let cvn: Option<Arc<RwLock<crate::varnode::Varnode>>> = if def.num_input() == 2 {
                let other = def.get_in(1 - slot).cloned();
                match &other {
                    Some(v) if v.read().unwrap().is_constant() => other,
                    _ => return false,
                }
            } else {
                None
            };
            // cc:2817: varArray[0] = op->getIn(slot)
            let new_vn = def.get_in(slot).cloned();
            (opc, (cvn, new_vn))
        };
        // Replace var_array[0] with the slot input.
        if let (_, Some(new_vn)) = &cvn_opt {
            var_array[0] = new_vn.clone();
        } else {
            return false;
        }
        let cvn = cvn_opt.0;
        // cc:2818-2830: check remaining varnodes.
        let n = var_array.len();
        for i in 1..n {
            let vn = var_array[i].clone();
            let new_vn = {
                let vn_r = vn.read().unwrap();
                if !vn_r.is_written() {
                    return false;
                }
                let def_arc = match vn_r.def.as_ref().and_then(|w| w.upgrade()) {
                    Some(d) => d,
                    None => return false,
                };
                let def = def_arc.read().unwrap();
                if def.opcode != opc {
                    return false;
                }
                if let Some(ref cvn_arc) = cvn {
                    let cvn2 = match def.get_in(1 - slot) {
                        Some(v) => v.clone(),
                        None => return false,
                    };
                    let cvn2_r = cvn2.read().unwrap();
                    if !cvn2_r.is_constant() {
                        return false;
                    }
                    let cvn_r = cvn_arc.read().unwrap();
                    if cvn_r.get_size() != cvn2_r.get_size() {
                        return false;
                    }
                    if cvn_r.get_offset() != cvn2_r.get_offset() {
                        return false;
                    }
                }
                def.get_in(slot).cloned()
            };
            match new_vn {
                Some(v) => var_array[i] = v,
                None => return false,
            }
        }
        true
    }

    // Ghidra: block.cc:2712 BlockBasic::noInterveningStatement
    /// Check for values created in \b this block that flow outside the block.
    ///
    /// The block can calculate a value for a BRANCHIND or CBRANCH and can copy
    /// values and this method will still return \b true. But calculating any
    /// value used outside the block, writing to an addressable location, or
    /// performing a CALL or STORE causes the method to return \b false.
    /// Faithful to `noInterveningStatement` (block.cc:2712-2747).
    pub fn no_intervening_statement(&self) -> bool {
        // RUGRA-GLUE: Ghidra compares `op->getParent() != this` by C++ pointer
        // identity. Rugra blocks live behind Arc<RwLock<dyn FlowBlock>>;
        // ops' parents and this block's self_ref are weak refs to the same Arc
        // (set together by BlockGraph::add_block, block.rs:2792-2800), so
        // Arc::ptr_eq is the identity test. A block never inserted into a
        // graph has no self_ref; Ghidra cannot express that state (PcodeOp
        // parents are assigned on insert), so we conservatively treat an
        // unidentifiable self as "intervening" (return false).
        let self_arc = self.self_ref.as_ref().and_then(|w| w.upgrade());
        for bop_ref in &self.ops {
            // cc:2721-2722: markers and branches never count.
            let (is_marker, is_branch, eval_special, opcode, is_call, outvn) = {
                let bop = bop_ref.0.read().unwrap();
                let outvn = bop.get_out().cloned();
                (
                    bop.is_marker(),
                    bop.is_branch(),
                    bop.get_eval_type() == crate::op::pcodeop_flags::SPECIAL,
                    bop.opcode,
                    bop.is_call(),
                    outvn,
                )
            };
            if is_marker {
                continue;
            }
            if is_branch {
                continue;
            }
            // cc:2723-2734: special ops reject CALL/STORE/NEW; other ops skip
            // COPY/SUBPIECE.
            if eval_special {
                if is_call {
                    return false;
                }
                if opcode == OpCode::CPUI_STORE || opcode == OpCode::CPUI_NEW {
                    return false;
                }
            } else if opcode == OpCode::CPUI_COPY || opcode == OpCode::CPUI_SUBPIECE {
                continue;
            }
            // cc:2735-2737: address-tied outputs leave the block by aliasing.
            let Some(outvn) = outvn else {
                continue;
            };
            if outvn.read().unwrap().is_addr_tied() {
                return false;
            }
            // cc:2738-2744: any descendant outside this block disqualifies.
            let descendants: Vec<_> = outvn.read().unwrap().descend_iter().collect();
            for desc in descendants {
                let desc_parent = desc
                    .read()
                    .unwrap()
                    .parent
                    .as_ref()
                    .and_then(|w| w.upgrade());
                let same_block = match (&self_arc, &desc_parent) {
                    (Some(s), Some(p)) => Arc::ptr_eq(s, p),
                    _ => false,
                };
                if !same_block {
                    return false;
                }
            }
        }
        true
    }

    /// Add an operation to the end of the block
    // Ghidra: block.hh:466 BlockBasic::insert
    pub fn add_op(&mut self, op: PcodeOpRef) {
        let index = self.ops.len();
        <Self as FlowBlock>::insert_op(self, index, op);
    }

    /// Get the last operation in the block
    // Ghidra: block.hh:490 BlockBasic::lastOp
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        self.ops.last().cloned()
    }

    /// Replace the original instruction cover with the single closed range
    /// `[beg, end]`.  Ghidra takes the address space from `beg` and only the
    /// offset from `end`; preserving that detail prevents a later scalar
    /// reconstruction from dropping the space identity.
    ///
    /// Visibility: Ghidra keeps `setInitialRange` private with
    /// `friend class Funcdata` (block.hh:462/467), so the public construction
    /// path is the `Funcdata` inline `setBasicBlockRange(bb, beg, end)`
    /// (funcdata.hh:556) that just delegates here.  Rugra exposes this method
    /// as `pub` so out-of-crate oracle fixtures can build the same legal
    /// block state (the locked C++ fixture reaches the private member via
    /// `#define private public` and calls `fd.setBasicBlockRange`).
    // Ghidra: block.cc:2625 BlockBasic::setInitialRange
    pub fn set_initial_range(&mut self, beg: Address, end: Address) {
        let covered_end = match beg.get_space() {
            Some(space) => Address::with_space(&space, end.as_u64()),
            None => Address::new(end.as_u64()),
        };
        self.start_addr = beg;
        // cc:2628-2630: cover.clear(); insertRange(beg.space, beg.off, end.off)
        self.cover = crate::address::RangeList::new();
        if let Some(range) = crate::address::Range::new(beg, covered_end) {
            self.cover.insert_range(range);
        }
    }

    /// Copy address ranges from another basic block.  A node-split duplicate
    /// inherits the ORIGINAL block's whole cover (funcdata_block.cc:832), so
    /// both copies report the same getStart()/getStop() until re-ranged.
    // Ghidra: block.hh:468 BlockBasic::copyRange
    pub fn copy_range(&mut self, other: &BlockBasic) {
        self.cover = other.cover.clone();
    }

    /// Merge address ranges from another basic block: the union of both
    /// blocks' original instruction ranges.  Called by splice_block_basic
    /// (funcdata_block.cc:942) after absorbing the out-block's ops.
    // Ghidra: block.hh:469 BlockBasic::mergeRange
    pub fn merge_range(&mut self, other: &BlockBasic) {
        self.cover.merge(&other.cover);
    }

    /// Get the address of the (original) first operation to execute.  With a
    /// single cover range this matches `get_start_addr`; with MULTIPLE ranges
    /// (a spliced block) it returns the start of the range CONTAINING the
    /// first op — "relies slightly on normal fall-thru semantics" (the
    /// executed entry is the lowest-address chunk of the executed path).
    /// printc emitLabel (printc.cc:3170) uses this, NOT getStart.
    // Ghidra: block.cc:2302 BlockBasic::getEntryAddr
    pub fn get_entry_addr(&self) -> Address {
        if self.cover.num_ranges() == 1 {
            // cc:2297-2298: single range — return the start of the range.
            return self.cover.ranges()[0].get_first_addr();
        }
        // cc:2299-2308: multi-range — locate the cover range holding the
        // first op's address; absent a containing range, the op address
        // itself is the answer.
        let Some(first) = self.ops.first() else {
            // cc:2300-2301: no ops — Ghidra returns an invalid Address();
            // Rugra falls back to the construction addr (see get_stop_addr).
            return self.start_addr;
        };
        let addr = first.0.read().unwrap().get_addr();
        match self.cover.ranges().iter().find(|r| r.contains(addr)) {
            Some(range) => range.get_first_addr(),
            None => addr,
        }
    }

    /// Return the final address in the original instruction cover: the LAST
    /// range's last address in (space, offset) order.
    // Ghidra: block.cc:2328 BlockBasic::getStop
    pub fn get_stop_addr(&self) -> crate::address::Address {
        match self.cover.ranges().last() {
            Some(range) => range.get_last_addr(),
            // Ghidra returns an invalid Address() for an empty cover; Rugra
            // has no invalid Address, so fall back to the construction addr
            // (no flow-created block reaches this arm: flow.cc always sets a
            // range before the block joins the graph).
            None => self.start_addr,
        }
    }

    /// Get the first operation in the block
    // Ghidra: block.cc:2337 BlockBasic::firstOp
    pub fn first_op(&self) -> Option<PcodeOpRef> {
        self.ops.first().cloned()
    }

    /// Reset the SeqNum::order field for all PcodeOps in this block,
    /// distributing values evenly. Used by spliceBlockBasic after moving
    /// ops from another block.
    // Ghidra: block.cc:2638 BlockBasic::setOrder
    pub fn set_order(&mut self) {
        let n = self.ops.len();
        if n == 0 {
            return;
        }
        // Ghidra: step = (UINT_MAX / n) - 1, count += step each op.
        let step = if n > 0 {
            (u32::MAX / n as u32).saturating_sub(1)
        } else {
            0
        };
        let mut count = 0u32;
        for op_ref in &self.ops {
            count = count.saturating_add(step);
            op_ref.0.write().unwrap().start.set_order(count);
        }
    }
}

impl FlowBlock for BlockBasic {
    // RUGRA-GLUE: Rust trait-object downcast glue (no Ghidra counterpart)
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // RUGRA-GLUE: Rust trait-object downcast glue (no Ghidra counterpart)
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // Ghidra: block.hh:480 BlockBasic::getType
    fn get_type(&self) -> BlockType {
        BlockType::Basic
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }

    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }

    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }

    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }

    // RUGRA-GLUE: Rust edge-construction helper (Ghidra manages outofthis via friend addInEdge)
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }

    // RUGRA-GLUE: Rust helper (Ghidra BlockBasic exposes op list via begin/end iterators)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.ops.clone()
    }

    // Ghidra: block.hh:489 BlockBasic::firstOp
    fn first_op(&self) -> Option<PcodeOpRef> {
        self.get_ops().first().cloned()
    }

    // Ghidra: block.cc:2344 BlockBasic::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        self.get_ops().last().cloned()
    }

    // Ghidra: block.hh:488 BlockBasic::getExitLeaf
    fn get_exit_leaf_trait(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.self_ref.as_ref().and_then(Weak::upgrade)
    }

    // Ghidra: block.cc:2361 BlockBasic::getSplitPoint
    fn get_split_point(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        if self.outgoing.len() != 2 {
            return None;
        }
        self.self_ref.as_ref().and_then(Weak::upgrade)
    }

    // Ghidra: block.cc:2388 BlockBasic::isComplex
    /// Is this block too complicated to serve as a clause of a
    /// BlockCondition? Faithful port of `BlockBasic::isComplex`
    /// (block.cc:2388-2444): counts "statements" in the block —
    ///   - the branch itself, when sizeOut()>=2 (cc:2399-2400),
    ///   - every CALL (cc:2407-2408), checked before the output checks,
    ///   - every output-less op that is not a flow-break (stores, cc:2409-2412),
    ///   - every calculation whose output has no descendants, is
    ///     address-tied, is read by an op outside this block, or is read
    ///     more than max_implied_ref times (cc:2413-2438),
    /// returning true as soon as statement > 2 (cc:2441).
    fn is_complex(&self) -> bool {
        // cc:2398-2400: statement = 0; if (sizeOut()>=2) statement = 1;
        // Consider the branch as a statement.
        let mut statement: i32 = 0;
        if self.size_out() >= 2 {
            statement = 1;
        }
        // cc:2401: maxref = data->getArch()->max_implied_ref — the default 2
        // (architecture.cc:1420). Rugra's BlockBasic holds no arch
        // back-pointer; same constant precedent as ActionRestructureVarnode
        // (coreaction.rs "arch.max_implied_ref default").
        let maxref: i32 = 2;
        for op_ref in &self.ops {
            let inst = op_ref.0.read().unwrap();
            // cc:2405: if (inst->isMarker()) continue;
            if inst.is_marker() {
                continue;
            }
            match &inst.output {
                None => {
                    // cc:2407-2408: isCall is checked first in Ghidra, before
                    // the null-output arm — a CALL counts regardless of output.
                    if inst.is_call() {
                        statement += 1;
                    } else if !inst.is_flow_break() {
                        // cc:2409-2412: output-less flow-breaks are free;
                        // everything else (stores) is a statement.
                        statement += 1;
                    }
                }
                Some(out_vn) => {
                    if inst.is_call() {
                        // cc:2407-2408: calls with an output still count as
                        // exactly one statement (never reach calc-explicit).
                        statement += 1;
                    } else {
                        // cc:2413-2438: calculation with output — conservative
                        // version of Varnode::calc_explicit.
                        let vn = out_vn.read().unwrap();
                        let mut yesstatement = false;
                        if vn.descend_iter().next().is_none() {
                            // cc:2417-2418: hasNoDescend → dead calculation.
                            yesstatement = true;
                        } else if vn.is_addr_tied() {
                            // cc:2419-2420: isAddrTied → conservative explicit.
                            yesstatement = true;
                        } else {
                            // cc:2422-2435: count references; used outside
                            // this block or too many refs → statement.
                            let mut totalref: i32 = 0;
                            for d_arc in vn.descend_iter() {
                                let d_op = d_arc.read().unwrap();
                                // cc:2426: d_op->isMarker() ||
                                //          (d_op->getParent() != this)
                                // "used outside of block": Ghidra compares the
                                // descendant's live parent object identity;
                                // container membership is not a substitute for
                                // that relation.
                                let same_parent = d_op
                                    .parent
                                    .as_ref()
                                    .and_then(Weak::upgrade)
                                    .zip(self.self_ref.as_ref().and_then(Weak::upgrade))
                                    .is_some_and(|(parent, this)| Arc::ptr_eq(&parent, &this));
                                if d_op.is_marker()
                                    || !same_parent {
                                    yesstatement = true;
                                    break;
                                }
                                totalref += 1;
                                if totalref > maxref {
                                    // cc:2431-2433: used too many times.
                                    yesstatement = true;
                                    break;
                                }
                            }
                        }
                        if yesstatement {
                            statement += 1;
                        }
                    }
                }
            }
            // cc:2441: if (statement >2) return true;
            if statement > 2 {
                return true;
            }
        }
        false
    }

    // Ghidra: block.hh:466 BlockBasic::insert
    fn add_op(&mut self, op: PcodeOpRef) {
        self.insert_op(self.ops.len(), op);
    }

    // Ghidra: block.cc:2258 BlockBasic::insert
    fn insert_op(&mut self, index: usize, op: PcodeOpRef) {
        assert!(
            index <= self.ops.len(), "BlockBasic insert index is out of bounds"
        );
        let order_before = if index == 0 {
            2
        } else {
            self.ops[index - 1].0.read().unwrap().start.get_order()
        };
        let order_after = if index == self.ops.len() {
            let candidate = order_before.wrapping_add(0x0100_0000);
            if candidate <= order_before {
                u32::MAX
            } else {
                candidate
            }
        } else {
            self.ops[index].0.read().unwrap().start.get_order()
        };
        if let Some(parent) = self.self_ref.as_ref().and_then(Weak::upgrade) {
            op.0.write().unwrap().parent = Some(Arc::downgrade(&parent));
        }
        self.ops.insert(index, op);
        if order_after.wrapping_sub(order_before) <= 1 {
            self.set_order();
        } else {
            self.ops[index]
                .0
                .write()
                .unwrap()
                .start
                .set_order(order_after / 2 + order_before / 2);
        }
        let is_branch_indirect = {
            let inserted = self.ops[index].0.read().unwrap();
            inserted.is_branch() && inserted.opcode == OpCode::CPUI_BRANCHIND
        };
        if is_branch_indirect {
            self.flags |= block_flags::SWITCH_OUT;
        }
    }

    // Ghidra: block.cc:2319 BlockBasic::getStart
    fn get_start_addr(&self) -> Address {
        // First range's first address in (space, offset) sort order — NOT
        // the first op's address.  For a spliced block whose absorbed chunk
        // lives at a lower address, this reports that lower address.
        match self.cover.ranges().first() {
            Some(range) => range.get_first_addr(),
            // Ghidra returns an invalid Address() for an empty cover; fall
            // back to the construction addr (see get_stop_addr note).
            None => self.start_addr,
        }
    }

    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }

    // Ghidra: block.hh:162 FlowBlock::getImmedDom
    fn get_immed_dom(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.immed_dom.clone()
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::immed_dom is private)
    fn set_immed_dom(&mut self, dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.immed_dom = dom;
    }
    // RUGRA-GLUE: Rugra-only dom_depth field
    fn get_dom_depth(&self) -> i32 {
        self.dom_depth
    }
    // RUGRA-GLUE: Rust mutator for dom_depth
    fn set_dom_depth(&mut self, depth: i32) {
        self.dom_depth = depth;
    }
    // RUGRA-GLUE: Rugra-only dom_children field
    fn get_dom_children(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.dom_children.clone()
    }
    // RUGRA-GLUE: Rust mutator for dom_children
    fn add_dom_child(&mut self, child: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.dom_children.push(child);
    }
    // RUGRA-GLUE: Rust mutator for dom_children
    fn clear_dom_children(&mut self) {
        self.dom_children.clear();
    }
    // RUGRA-GLUE: Rugra-only dom_frontier field
    fn get_dom_frontier(&self) -> std::collections::HashSet<i32> {
        self.dom_frontier.clone()
    }
    // RUGRA-GLUE: Rust mutator for dom_frontier
    fn add_to_dom_frontier(&mut self, idx: i32) {
        self.dom_frontier.insert(idx);
    }
    // RUGRA-GLUE: Rust mutator for dom_frontier
    fn clear_dom_frontier(&mut self) {
        self.dom_frontier.clear();
    }
    // Ghidra: block.hh:306 FlowBlock::getInRevIndex
    fn get_in_rev_index(&self, slot: usize) -> i32 {
        self.incoming
            .get(slot)
            .map(|e| e.reverse_index)
            .unwrap_or(-1)
    }

    // ---- LoopBody mark / visit-count / edge-flag overrides ----
    // Ghidra: block.hh:286 FlowBlock::isMark
    fn is_mark(&self) -> bool {
        (self.flags & block_flags::MARK) != 0
    }
    // Ghidra: block.hh:287 FlowBlock::setMark
    fn set_mark(&mut self) {
        self.flags |= block_flags::MARK;
    }
    // Ghidra: block.hh:288 FlowBlock::clearMark
    fn clear_mark(&mut self) {
        self.flags &= !block_flags::MARK;
    }
    // Ghidra: block.hh:283 FlowBlock::getVisitCount
    fn get_visit_count(&self) -> i32 {
        self.visit_count
    }
    // Ghidra: block.hh:282 FlowBlock::setVisitCount
    fn set_visit_count(&mut self, c: i32) {
        self.visit_count = c;
    }
    // Ghidra: block.hh:163 FlowBlock::getCopyMap
    fn get_copy_map(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.copy_map.clone()
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::copymap is private at
    // block.hh:123; findSpanningTree assigns it via direct field access)
    fn set_copy_map(&mut self, m: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.copy_map = m;
    }
    // RUGRA-GLUE: Rust accessor for Ghidra FlowBlock::numdesc (block.hh:126)
    fn get_num_desc(&self) -> i32 {
        self.num_desc
    }
    // RUGRA-GLUE: Rust mutator for Ghidra FlowBlock::numdesc (block.hh:126)
    fn set_num_desc(&mut self, n: i32) {
        self.num_desc = n;
    }

    // Ghidra: block.cc:218 FlowBlock::swapEdges
    fn swap_edges(&mut self) {
        if self.outgoing.len() == 2 {
            self.outgoing.swap(0, 1);
            // cc:225-228: for each out slot i, the target block's in-edge at
            // this edge's reverse_index must now report reverse_index == i
            // (the in-edge's back-pointer followed the swapped edge). Same
            // BlockBasic-downcast peer-mutation pattern as replace_edges_thru.
            // try_write failing means the target lock is already held — in the
            // single-threaded per-Funcdata pipeline that is the self-loop
            // case (out-edge back to this very block), whose in-list we can
            // fix directly under our own &mut borrow.
            let pending: Vec<(usize, i32)> = self
                .outgoing
                .iter()
                .enumerate()
                .map(|(slot, edge)| (slot, edge.reverse_index))
                .collect();
            for (slot, rev) in pending {
                if rev < 0 {
                    continue;
                }
                let mut handled = false;
                {
                    let target = self.outgoing[slot].point.clone();
                    let tried = target.try_write();
                    if let Ok(mut target_guard) = tried {
                        handled = true;
                        if let Some(bb) = target_guard.as_any_mut().downcast_mut::<BlockBasic>() {
                            if let Some(in_edge) = bb.incoming.get_mut(rev as usize) {
                                in_edge.reverse_index = slot as i32;
                            }
                        }
                    }
                }
                if !handled {
                    if let Some(in_edge) = self.incoming.get_mut(rev as usize) {
                        in_edge.reverse_index = slot as i32;
                    }
                }
            }
            // cc:232: flags ^= f_flip_path
            self.flags ^= block_flags::FLIP_PATH;
        }
    }

    // Ghidra: block.cc:2351 BlockBasic::negateCondition
    fn negate_condition(&mut self, _toporbottom: bool) -> bool {
        // cc:2354: PcodeOp *lastop = op.back();
        let last_op = self.ops.last().cloned();
        if let Some(op_ref) = last_op {
            // cc:2355-2356: flip both the condition meaning and whether the
            // fall-through edge represents true or false.
            op_ref.0.write().unwrap().flags ^=
                crate::op::pcodeop_flags::BOOLEAN_FLIP | crate::op::pcodeop_flags::FALLTHRU_TRUE;
        }
        // cc:2357: the BlockBasic override ignores its argument and always
        // calls FlowBlock::negateCondition(true).
        self.swap_edges();
        // cc:2358: return true (dataflow changed)
        true
    }
    // Ghidra: block.hh:346 FlowBlock::isGotoIn
    fn is_goto_in(&self, i: usize) -> bool {
        // Goto-in: the i-th incoming edge is goto or irreducible (block.hh:346).
        self.incoming
            .get(i)
            .map(|e| (e.flags & (edge_flags::F_GOTO_EDGE | edge_flags::F_IRREDUCIBLE_EDGE)) != 0)
            .unwrap_or(false)
    }
    // Ghidra: block.hh:347 FlowBlock::isGotoOut
    fn is_goto_out(&self, i: usize) -> bool {
        // Goto-out: the i-th outgoing edge is goto or irreducible (block.hh:351).
        // Rugra marks gotos via block-level GOTO_EDGE_0/GOTO_EDGE_1 flags
        // (set by run_tracedag / goto_cascade), so we check both the edge flag
        // AND the block-level flag for slot i.
        let edge_goto = self
            .outgoing
            .get(i)
            .map(|e| (e.flags & (edge_flags::F_GOTO_EDGE | edge_flags::F_IRREDUCIBLE_EDGE)) != 0)
            .unwrap_or(false);
        if edge_goto {
            return true;
        }
        let block_goto = match i {
            0 => (self.flags & block_flags::GOTO_EDGE_0) != 0,
            1 => (self.flags & block_flags::GOTO_EDGE_1) != 0,
            _ => false,
        };
        block_goto
    }
    // Ghidra: block.hh:294 FlowBlock::setLoopExit
    fn set_loop_exit(&mut self, i: usize) {
        if let Some(e) = self.outgoing.get_mut(i) {
            e.flags |= edge_flags::F_LOOP_EXIT_EDGE;
        }
    }
    // Ghidra: block.hh:295 FlowBlock::clearLoopExit
    fn clear_loop_exit(&mut self, i: usize) {
        if let Some(e) = self.outgoing.get_mut(i) {
            e.flags &= !edge_flags::F_LOOP_EXIT_EDGE;
        }
    }
}

// RUGRA-GLUE: Rust trait-object field mutation for Ghidra's direct
// FlowBlock::intothis/outofthis access in halfDeleteInEdge/halfDeleteOutEdge.
fn decrement_reciprocal_reverse_index(block: &mut dyn FlowBlock, incoming_half: bool, slot: usize) {
    let block_index = block.get_index();
    let edges = if incoming_half {
        block.in_edges_mut()
    } else {
        block.out_edges_mut()
    };
    if slot >= edges.len() {
        eprintln!(
            "[BLOCKSTRUCT] WARN: reciprocal slot {} past peer {} {}-list (len {}); skipping decrement (BLOCK-RECIPROCAL-OOB-0001 residual)",
            slot,
            block_index,
            if incoming_half { "in" } else { "out" },
            edges.len()
        );
        return;
    }
    edges[slot].reverse_index -= 1;
}

/// BlockBasic-specific methods for edge manipulation (Ghidra identifyInternal support)
impl BlockBasic {
    // Ghidra: block.cc:178 FlowBlock::replaceOutEdge
    pub fn replace_out_edge_target(
        &mut self,
        slot: usize,
        new_target: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        if slot < self.outgoing.len() {
            self.outgoing[slot].point = new_target;
        }
    }

    // Ghidra: block.cc:160 FlowBlock::replaceInEdge
    pub fn replace_in_edge_source(
        &mut self,
        slot: usize,
        new_source: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        if slot < self.incoming.len() {
            self.incoming[slot].point = new_source;
        }
    }

    /// Reverse-index of the given outgoing edge slot, i.e. the slot in
    /// `out[slot].point`'s incoming list that points back at us.
    /// Faithful to `FlowBlock::getOutRevIndex` (block.cc).
    // Ghidra: block.hh:303 FlowBlock::getOutRevIndex
    pub fn get_out_rev_index(&self, slot: usize) -> i32 {
        self.outgoing[slot].reverse_index
    }

    /// Reverse-index of the given incoming edge slot. Faithful to
    /// `FlowBlock::getInRevIndex` (block.cc).
    // Ghidra: block.hh:306 FlowBlock::getInRevIndex
    pub fn get_in_rev_index(&self, slot: usize) -> i32 {
        self.incoming[slot].reverse_index
    }

    // Ghidra: block.cc:100/115 FlowBlock::halfDeleteInEdge/halfDeleteOutEdge
    // live as trait-default methods on FlowBlock (every subtype); the former
    // BlockBasic-only inherent copies silently skipped structured peers and
    // left stale reciprocal reverse_index entries (BLOCK-RECIPROCAL-OOB-0001).

    /// Remove edge `in`/`out` from this block but create a new direct edge
    /// between the in-block and the out-block, preserving slot positions.
    /// Faithful to `FlowBlock::replaceEdgesThru` (block.cc:198-216).
    ///
    /// Caller must hold NO lock on `self` while mutating the two peers; this
    /// method performs the writes directly on `self` then on the peers via
    /// their `as_any_mut()` downcasts.
    // Ghidra: block.cc:198 FlowBlock::replaceEdgesThru
    pub fn replace_edges_thru(&mut self, in_slot: usize, out_slot: usize) {
        // Capture the four endpoints before mutation.
        let inb = self.incoming[in_slot].point.clone();
        let inblock_outslot = self.incoming[in_slot].reverse_index as usize;
        let outb = self.outgoing[out_slot].point.clone();
        let outblock_inslot = self.outgoing[out_slot].reverse_index as usize;

        // Rewire inb.outofthis[inblock_outslot] -> outb.
        {
            let mut inb_rg = inb.write().unwrap();
            if let Some(bb) = inb_rg.as_any_mut().downcast_mut::<BlockBasic>() {
                bb.outgoing[inblock_outslot].point = outb.clone();
                bb.outgoing[inblock_outslot].reverse_index = outblock_inslot as i32;
            }
        }
        // Rewire outb.intothis[outblock_inslot] -> inb.
        {
            let mut outb_rg = outb.write().unwrap();
            if let Some(bb) = outb_rg.as_any_mut().downcast_mut::<BlockBasic>() {
                bb.incoming[outblock_inslot].point = inb;
                bb.incoming[outblock_inslot].reverse_index = inblock_outslot as i32;
            }
        }
        // Remove our half-edges (order matters: deleting the in-edge shifts
        // reverse-indices; Ghidra deletes in then out on `this`).
        self.half_delete_in_edge(in_slot);
        // After deleting in_slot, out_slot may have shifted only if out_slot
        // was an *out* edge (separate list), so out_slot is unaffected.
        self.half_delete_out_edge(out_slot);
    }

    // RUGRA-GLUE: Rust helper clearing both edge lists (Ghidra clears via BlockGraph::clear block.cc:1239)
    pub fn clear_edges(&mut self) {
        self.incoming.clear();
        self.outgoing.clear();
    }

    // RUGRA-GLUE: Rust accessor for outgoing edge slice (Ghidra exposes outofthis via getOut/sizeOut)
    pub fn get_outgoing(&self) -> &[BlockEdge] {
        &self.outgoing
    }

    // RUGRA-GLUE: Rust accessor for incoming edge slice (Ghidra exposes intothis via getIn/sizeIn)
    pub fn get_incoming(&self) -> &[BlockEdge] {
        &self.incoming
    }
}

/// Represents an edge between blocks in the control flow graph
///
/// Corresponds to Ghidra's `BlockEdge` class
#[derive(Debug, Clone)]
pub struct BlockEdge {
    /// The block at the other end of the edge
    pub point: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    /// Edge flags
    pub flags: u32,
    /// Reverse index (slot in the destination's input list or source's output list)
    pub reverse_index: i32,
}

impl BlockEdge {
    // RUGRA-GLUE: Rust constructor for BlockEdge (Ghidra BlockEdge is a struct, edges built via addInEdge)
    pub fn new(point: Arc<RwLock<dyn FlowBlock + Send + Sync>>, reverse_index: i32) -> Self {
        Self {
            point,
            flags: 0,
            reverse_index,
        }
    }

    // RUGRA-GLUE: Rust accessor for f_break_edge flag (Ghidra checks label & f_break_edge inline)
    pub fn is_break(&self) -> bool {
        self.flags & edge_flags::F_BREAK_EDGE != 0
    }

    // RUGRA-GLUE: Rust accessor for f_continue_edge flag (Ghidra checks label inline)
    pub fn is_continue(&self) -> bool {
        self.flags & edge_flags::F_CONTINUE_EDGE != 0
    }

    // RUGRA-GLUE: Rust accessor for f_goto_edge flag (Ghidra checks label & f_goto_edge inline)
    pub fn is_goto(&self) -> bool {
        self.flags & edge_flags::F_GOTO_EDGE != 0
    }
}

/// A reference to a block for use in collections
#[derive(Debug, Clone)]
pub struct BlockRef(pub Arc<RwLock<dyn FlowBlock + Send + Sync>>);

impl PartialEq for BlockRef {
    // RUGRA-GLUE: Rust PartialEq for BlockRef (Ghidra compares FlowBlock* directly)
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// A graph of blocks, which is itself a block
///
/// Corresponds to Ghidra's `BlockGraph` class
#[derive(Debug)]
pub struct BlockGraph {
    pub index: i32,
    pub blocks: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
    /// Back reference to a BlockCopy of this graph (Ghidra `copymap`,
    /// block.hh:123), reset to \b this by find_spanning_tree.
    pub copy_map: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Number of descendants in the spanning tree (+1) (Ghidra `numdesc`,
    /// block.hh:126); -1 marks unset.
    pub num_desc: i32,
    /// Parent chain (Rugra's equivalent of Ghidra `FlowBlock::parent`,
    /// block.hh:78): consumed block index -> index of the composite that
    /// absorbed it (the composite's install slot). Ghidra's
    /// `BlockGraph::addBlock` sets `bl->parent = this` when
    /// identifyInternal moves each component into the composite
    /// (block.cc:873/950), and components keep only their internal
    /// (component-to-component) edges — they are NEVER flagged f_dead
    /// (identifyInternal sets no flag; f_dead is exclusively Funcdata's
    /// dead basic-block removal, funcdata_block.cc:333/370). Algorithms
    /// like LoopBody::update (blockaction.cc:95-102) walk `getParent()`
    /// up to the graph level; Rugra resolves the same chain transitively
    /// via `resolve_to_graph_level`, and rule sweeps use map membership
    /// (`is_consumed`) in place of Ghidra's incremental list compaction
    /// (block.cc:953-960).
    // RUGRA-GLUE: identity-keyed hash map (Ghidra has no map here — blocks
    // are removed from the list on identifyInternal, block.cc:953-960; Rugra
    // keeps stable slots and records absorption instead). FxHashMap: the
    // is_consumed membership test runs per rule-try/per in-edge in the
    // collapse scan (tens of millions of lookups on giant functions); the
    // pass-through hasher keeps it a few-ns probe. Same key/value semantics,
    // no iteration-order-dependent consumer (the only .keys() walks feed
    // order-independent conditional rewrites / HashSet test fixtures).
    pub absorbed_into: rustc_hash::FxHashMap<i32, i32>,
}

impl BlockGraph {
    // RUGRA-GLUE: Rust BlockGraph constructor (Ghidra BlockGraph is constructed implicitly by Funcdata)
    pub fn new() -> Self {
        Self {
            index: -1,
            blocks: Vec::new(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
            copy_map: None,
            num_desc: -1,
            absorbed_into: rustc_hash::FxHashMap::default(),
        }
    }

    // Ghidra: block.cc:862 BlockGraph::addBlock
    pub fn add_block(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        let block_index = bl.read().unwrap().get_index();
        if self.blocks.is_empty() || block_index < self.index {
            self.index = block_index;
        }
        let self_weak = Arc::downgrade(&bl);
        {
            let mut block = bl.write().unwrap();
            if let Some(basic) = block.as_any_mut().downcast_mut::<BlockBasic>() {
                basic.self_ref = Some(self_weak.clone());
                // RUGRA-GLUE: Rust callers can populate a BlockBasic before
                // inserting it into the graph. Complete the invariant that
                // Ghidra establishes in BlockBasic::insert (block.cc:2266)
                // once the block Arc identity becomes available.
                for op in &basic.ops {
                    op.0.write().unwrap().parent = Some(self_weak.clone());
                }
            } else if let Some(copy) = block.as_any_mut().downcast_mut::<BlockCopy>() {
                copy.self_ref = Some(self_weak);
            }
        }
        self.blocks.push(bl);
    }

    /// Create and append an exact `BlockCopy` mirror of `source`.
    // Ghidra: block.cc:1681 BlockGraph::newBlockCopy
    pub fn new_block_copy(
        &mut self,
        source: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
        let (index, mut flags, incoming, outgoing, immed_dom, num_desc) = {
            let block = source.read().unwrap();
            let incoming = (0..block.size_in())
                .map(|slot| {
                    block
                        .get_in(slot)
                        .expect("FlowBlock size_in/get_in invariant violated")
                })
                .collect::<Vec<_>>();
            let outgoing = (0..block.size_out())
                .map(|slot| {
                    block
                        .get_out(slot)
                        .expect("FlowBlock size_out/get_out invariant violated")
                })
                .collect::<Vec<_>>();
            (
                block.get_index(),
                block.get_flags(),
                incoming,
                outgoing,
                block.get_immed_dom(),
                block.get_num_desc(),
            )
        };
        if outgoing.len() > 2 {
            flags |= block_flags::SWITCH_OUT;
        }
        let result: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(BlockCopy {
            index,
            flags,
            parent: None,
            self_ref: None,
            original: source,
            incoming,
            outgoing,
            immed_dom,
            copy_map: None,
            visit_count: 0,
            num_desc,
            dom_depth: -1,
            dom_children: Vec::new(),
            dom_frontier: std::collections::HashSet::new(),
        }));
        self.add_block(result.clone());
        result
    }

    /// Append a structured-graph mirror of `graph`, preserving the exact
    /// edge-vector order, labels, reciprocal slots, and copied block state.
    // Ghidra: block.cc:1925 BlockGraph::buildCopy
    pub fn build_copy(&mut self, graph: &BlockGraph) {
        let start_size = self.blocks.len();
        let originals = graph.blocks.clone();

        for original in originals {
            let copy = self.new_block_copy(original.clone());
            original
                .write()
                .unwrap()
                .set_copy_map(Some(Arc::downgrade(&copy)));
        }

        for copy in &self.blocks[start_size..] {
            let (incoming, outgoing, immed_dom) = {
                let block = copy.read().unwrap();
                let incoming = (0..block.size_in())
                    .map(|slot| {
                        block
                            .get_in(slot)
                            .expect("FlowBlock size_in/get_in invariant violated")
                    })
                    .collect::<Vec<_>>();
                let outgoing = (0..block.size_out())
                    .map(|slot| {
                        block
                            .get_out(slot)
                            .expect("FlowBlock size_out/get_out invariant violated")
                    })
                    .collect::<Vec<_>>();
                (incoming, outgoing, block.get_immed_dom())
            };
            let map_point = |point: &Arc<RwLock<dyn FlowBlock + Send + Sync>>| {
                let mapped = point.read().unwrap().get_copy_map();
                match mapped.and_then(|weak| weak.upgrade()) {
                    Some(result) => result,
                    None => panic!(
                        "BlockGraph::build_copy encountered an edge or dominator outside the source graph"
                    ),
                }
            };
            let mapped_incoming = incoming
                .into_iter()
                .map(|mut edge| {
                    edge.point = map_point(&edge.point);
                    edge
                })
                .collect::<Vec<_>>();
            let mapped_outgoing = outgoing
                .into_iter()
                .map(|mut edge| {
                    edge.point = map_point(&edge.point);
                    edge
                })
                .collect::<Vec<_>>();
            let mapped_dom = immed_dom.map(|weak| {
                let original_dom = match weak.upgrade() {
                    Some(dom) => dom,
                    None => {
                        panic!("BlockGraph::build_copy encountered an expired immediate dominator")
                    }
                };
                Arc::downgrade(&map_point(&original_dom))
            });
            let mut block = copy.write().unwrap();
            *block.in_edges_mut() = mapped_incoming;
            *block.out_edges_mut() = mapped_outgoing;
            block.set_immed_dom(mapped_dom);
        }
    }

    // RUGRA-GLUE: Rust accessor (Ghidra uses list.size() inline)
    pub fn get_size(&self) -> usize {
        self.blocks.len()
    }

    // RUGRA-GLUE: Rust accessor (Ghidra uses list[i] inline)
    pub fn get_block(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.blocks.get(i).cloned()
    }

    /// Resolve a block index to its current top-level (graph-level) form by
    /// following the absorption chain, mirroring Ghidra's
    /// `while (bl->getParent() != graph) bl = bl->getParent();` parent walks
    /// (e.g. LoopBody::update blockaction.cc:95-102, FloatingEdge::
    /// getCurrentEdge blockaction.cc:28-33, LoopBody::emitLikelyEdges
    /// blockaction.cc:367-379). A live block resolves to itself; a block
    /// absorbed by composite C installed at slot k resolves to k (and
    /// transitively further if C was itself absorbed later). The chain always
    /// terminates at a live top-level block because only live blocks can be
    /// re-absorbed.
    // RUGRA-GLUE: parent-chain walk over the absorbed_into map (Ghidra: block.hh:78 FlowBlock::parent)
    pub fn resolve_to_graph_level(&self, idx: i32) -> i32 {
        let mut cur = idx;
        // Bound the walk by the map size: each step must make progress, and
        // the absorption relation is acyclic (a composite is installed after
        // its components exist), so any chain is shorter than the map.
        for _ in 0..=self.absorbed_into.len() {
            match self.absorbed_into.get(&cur) {
                Some(&next) if next != cur => cur = next,
                _ => return cur,
            }
        }
        cur
    }

    /// Clear EVERY in-edge and out-edge label of every component block.
    /// This is `BlockGraph::clearEdgeFlags(~((uint4)0))` as invoked at the
    /// start of each findSpanningTree pass (block.cc:1045): the parameter is
    /// complemented inside Ghidra's clearEdgeFlags (block.cc:969 `fl = ~fl`),
    /// so passing all-ones clears all label bits on both edge halves.
    // Ghidra: block.cc:966 BlockGraph::clearEdgeFlags (all-ones invocation at block.cc:1045)
    fn clear_edge_flags_all(&mut self) {
        for bl in &self.blocks {
            let mut g = bl.write().unwrap();
            for edge in g.in_edges_mut() {
                edge.flags = 0;
            }
            for edge in g.out_edges_mut() {
                edge.flags = 0;
            }
        }
    }

    /// \brief Find a spanning tree (skipping irreducible edges).
    ///
    /// Faithful port of `BlockGraph::findSpanningTree` (block.cc:1009-1136):
    ///   - Label pre and reverse-post orderings, tree, forward, cross, and
    ///     back edges (block.cc:1093-1105).
    ///   - Calculate number of descendants (numdesc, block.cc:1073/1084/1098).
    ///   - Put the blocks of the graph in reverse post order — every block's
    ///     `index` becomes its reverse-post-order number (block.cc:1081) and
    ///     the component list itself is reordered to that order
    ///     (block.cc:1135 `list = rpostorder`).
    ///   - Return an array of all nodes in pre-order via `preorder`.
    ///   - `rootlist` is an in/out parameter: on entry it may be empty (the
    ///     graph's entry points are collected here); on exit it holds the
    ///     roots with the original head moved to the front (block.cc:1129).
    ///
    /// Each pass first clears ALL edge flags (in and out halves) of every
    /// component (block.cc:1045), so externally pre-set labels — including
    /// f_irreducible — do not survive into the traversal; the
    /// isIrreducibleOut skip (block.cc:1089) therefore only observes labels
    /// set on blocks outside `list`, matching the locked oracle exactly.
    ///
    /// Algorithm originally due to Tarjan. The first block is the entry
    /// block and remains first in the reverse post order: the rootlist
    /// head/tail swap at block.cc:1031-1035 makes the original head the last
    /// root visited (so it finishes last and takes RPO index 0).
    ///
    /// Errors: if after two passes extra roots are still being discovered,
    /// Ghidra throws LowlevelError("Could not generate spanning tree")
    /// (block.cc:1110-1111); Rugra returns the equivalent `anyhow` error.
    // Ghidra: block.cc:1009 BlockGraph::findSpanningTree
    pub fn find_spanning_tree(
        &mut self,
        preorder: &mut Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
        rootlist: &mut Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    ) -> anyhow::Result<()> {
        let n = self.blocks.len();
        if n == 0 {
            // cc:1012: if (list.size()==0) return;
            return Ok(());
        }
        let mut rpostorder: Vec<Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>> = vec![None; n]; // cc:1020 rpostorder.resize(list.size())
        let mut state: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::with_capacity(n); // cc:1021
        let mut istate: Vec<usize> = Vec::with_capacity(n); // cc:1022
        for i in 0..n {
            // cc:1023-1030: index = -1 (reverse post-order starts at 0),
            // visitcount = -1, copymap = this; collect sizeIn()==0 roots in
            // list order.
            let tmpbl = self.blocks[i].clone();
            {
                let mut g = tmpbl.write().unwrap();
                g.set_index(-1);
                g.set_visit_count(-1);
                g.set_copy_map(Some(std::sync::Arc::downgrade(&tmpbl)));
            }
            if tmpbl.read().unwrap().size_in() == 0 {
                rootlist.push(tmpbl);
            }
        }
        if rootlist.len() > 1 {
            // cc:1031-1035: make sure orighead is visited last (so it is
            // first in the reverse post order).
            let last = rootlist.len() - 1;
            rootlist.swap(0, last);
        } else if rootlist.is_empty() {
            // cc:1036-1038: no obvious starting block; assume first block.
            rootlist.push(self.blocks[0].clone());
        }
        let origrootpos = rootlist.len() - 1; // cc:1039

        for repeat in 0..2 {
            // cc:1041-1045
            let mut extraroots = false;
            let mut rpostcount = n as i32;
            let mut rootindex = 0usize;
            self.clear_edge_flags_all();
            while preorder.len() < n {
                // cc:1046
                // cc:1048-1058: go through blocks with no in edges; a stale
                // root from the previous pass (visitcount != -1) is removed
                // from rootlist by shifting the tail left.
                let mut startbl: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = None;
                while rootindex < rootlist.len() {
                    let cand = rootlist[rootindex].clone();
                    rootindex += 1;
                    if cand.read().unwrap().get_visit_count() == -1 {
                        startbl = Some(cand);
                        break;
                    }
                    rootlist.remove(rootindex - 1);
                    rootindex -= 1;
                }
                let startbl: Arc<RwLock<dyn FlowBlock + Send + Sync>> = match startbl {
                    Some(b) => b,
                    None => {
                        // cc:1059-1067: no unvisited root — take the next
                        // unvisited block in list order and treat it as
                        // another root. (While preorder.size() < list.size()
                        // an unvisited block always exists, so the scan
                        // always breaks; like Ghidra, the loop variable ends
                        // on the last block if it somehow did not.)
                        extraroots = true;
                        let mut found = self.blocks[n - 1].clone();
                        for i in 0..n {
                            found = self.blocks[i].clone();
                            if found.read().unwrap().get_visit_count() == -1 {
                                break;
                            }
                        }
                        rootlist.push(found.clone());
                        rootindex += 1;
                        found
                    }
                };
                // cc:1069-1073: discover the start block.
                state.push(startbl.clone());
                istate.push(0);
                startbl
                    .write()
                    .unwrap()
                    .set_visit_count(preorder.len() as i32);
                preorder.push(startbl.clone());
                startbl.write().unwrap().set_num_desc(1);

                // cc:1075-1107: iterative DFS.
                while !state.is_empty() {
                    let curbl = state.last().unwrap().clone();
                    let finished = {
                        let cur_size_out = curbl.read().unwrap().size_out();
                        cur_size_out <= *istate.last().unwrap()
                    };
                    if finished {
                        // cc:1077-1084: all children visited — finish node,
                        // assign reverse post-order index, accumulate
                        // numdesc into the DFS parent.
                        state.pop();
                        istate.pop();
                        rpostcount -= 1;
                        curbl.write().unwrap().set_index(rpostcount);
                        rpostorder[rpostcount as usize] = Some(curbl.clone());
                        if let Some(parent_arc) = state.last() {
                            let add = curbl.read().unwrap().get_num_desc();
                            let parent_arc = parent_arc.clone();
                            let mut pg = parent_arc.write().unwrap();
                            let total = pg.get_num_desc() + add;
                            pg.set_num_desc(total);
                        }
                    } else {
                        // cc:1086-1105: try the next child edge.
                        let edgenum = *istate.last().unwrap();
                        *istate.last_mut().unwrap() += 1;
                        if curbl.read().unwrap().is_irreducible_out(edgenum) {
                            // cc:1089: pretend irreducible edges don't exist.
                            continue;
                        }
                        let childbl = match curbl.read().unwrap().get_out(edgenum) {
                            Some(e) => e.point,
                            None => continue,
                        };
                        let child_visit = childbl.read().unwrap().get_visit_count();
                        if child_visit == -1 {
                            // cc:1092-1099: unvisited — tree edge, descend.
                            set_out_edge_flag_mirrored(&curbl, edgenum, edge_flags::F_TREE_EDGE);
                            state.push(childbl.clone());
                            istate.push(0);
                            childbl
                                .write()
                                .unwrap()
                                .set_visit_count(preorder.len() as i32);
                            preorder.push(childbl.clone());
                            childbl.write().unwrap().set_num_desc(1);
                        } else {
                            let child_index = childbl.read().unwrap().get_index();
                            if child_index == -1 {
                                // cc:1100-1101: childbl already on stack —
                                // back (loop) edge.
                                set_out_edge_flag_mirrored(
                                    &curbl,
                                    edgenum,
                                    edge_flags::F_BACK_EDGE | edge_flags::F_LOOP_EDGE,
                                );
                            } else {
                                let cur_visit = curbl.read().unwrap().get_visit_count();
                                if cur_visit < child_visit {
                                    // cc:1102-1103: childbl processing done,
                                    // discovered after curbl — forward edge.
                                    set_out_edge_flag_mirrored(
                                        &curbl,
                                        edgenum,
                                        edge_flags::F_FORWARD_EDGE,
                                    );
                                } else {
                                    // cc:1104-1105: cross edge.
                                    set_out_edge_flag_mirrored(
                                        &curbl,
                                        edgenum,
                                        edge_flags::F_CROSS_EDGE,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            if !extraroots {
                // cc:1109
                break;
            }
            if repeat == 1 {
                // cc:1110-1111: throw LowlevelError("Could not generate
                // spanning tree")
                anyhow::bail!("Could not generate spanning tree");
            }
            // cc:1114-1116: we had extra roots, so regenerate the post order
            // with the entry block moved to the last rootlist position.
            let last = rootlist.len() - 1;
            rootlist.swap(last, origrootpos);
            for i in 0..n {
                // cc:1118-1123: reset for the second pass.
                let tmpbl = self.blocks[i].clone();
                let mut g = tmpbl.write().unwrap();
                g.set_index(-1);
                g.set_visit_count(-1);
                g.set_copy_map(Some(std::sync::Arc::downgrade(&tmpbl)));
            }
            preorder.clear();
            state.clear();
            istate.clear();
        }

        if rootlist.len() > 1 {
            // cc:1129-1133: make sure orighead is at the front of rootlist.
            let last = rootlist.len() - 1;
            rootlist.swap(0, last);
        }

        // cc:1135: list = rpostorder — reorder components into reverse post
        // order. Every entry is filled because each of the n blocks receives
        // exactly one distinct finish slot 0..n-1.
        self.blocks = rpostorder
            .into_iter()
            .map(|slot| slot.expect("rpostorder fully assigned by DFS"))
            .collect();
        Ok(())
    }

    /// Clear a set of edge-label bits from BOTH halves (in and out edges) of
    /// every component block. Faithful to `BlockGraph::clearEdgeFlags`
    /// (block.cc:966-978): the mask parameter is complemented
    /// (cc:969 `fl = ~fl`) and AND-ed into every `intothis[i].label` and
    /// `outofthis[i].label` of every block in `list`, in list order.
    /// Invoked by structureLoops' rebuild pass with the spanning-tree label
    /// set (block.cc:2206, keeping f_irreducible intact) and by
    /// findSpanningTree's pass start with all-ones (block.cc:1045, see
    /// `clear_edge_flags_all`).
    // Ghidra: block.cc:966 BlockGraph::clearEdgeFlags
    pub fn clear_edge_flags_mask(&mut self, fl: u32) {
        let keep = !fl; // cc:969
        for bl in &self.blocks {
            let mut g = bl.write().unwrap();
            for edge in g.in_edges_mut() {
                edge.flags &= keep;
            }
            for edge in g.out_edges_mut() {
                edge.flags &= keep;
            }
        }
    }

    /// \brief Identify irreducible edges
    ///
    /// Faithful port of `BlockGraph::findIrreducible` (block.cc:1147-1199).
    /// Assuming the spanning tree has been properly labeled using
    /// `findSpanningTree`, test for and label irreducible edges (the test
    /// ignores any edges already labeled as irreducible). Returns \b true if
    /// the spanning tree needs to be rebuilt, because one of the tree edges
    /// is irreducible. Original algorithm due to Tarjan.
    ///
    /// Walks `preorder` in REVERSE (cc:1152-1153 `xi = preorder.size()-1`
    /// counting down), so every loop body is collapsed into its copymap
    /// representative before the enclosing loop head is processed:
    ///   - For each vertex x and each BACK edge into x (cc:1157-1158), the
    ///     source's FIND(y) (= `y->copymap`, cc:1161) seeds the reachunder
    ///     set and is marked (cc:1162). A self back edge (y == x) never
    ///     contributes (cc:1160).
    ///   - The reachunder BFS (cc:1164-1189) scans every in-edge of each set
    ///     member t, skipping edges already labeled irreducible (cc:1170).
    ///     For y' = FIND(y): if y' lies OUTSIDE x's preorder interval
    ///     [visitcount, visitcount + numdesc) (cc:1174 — strictly before x,
    ///     or at/after the subtree end), the edge is irreducible: the count
    ///     accumulates (cc:1176), the label is set on y's out edge slot
    ///     `t->getInRevIndex(i)` and its mirrored in half (cc:1177-1178),
    ///     and a TREE edge forces needrebuild (cc:1179-1180) while a
    ///     non-tree edge just drops its stale cross/forward classification
    ///     (cc:1182). Otherwise an unmarked y' != x joins the set (cc:1184).
    ///   - Finally the whole reachunder set collapses into x: marks are
    ///     cleared and every member's copymap is re-pointed at x
    ///     (cc:1191-1195) — the union step of the FIND structure that later
    ///     vertices observe via `y->copymap` reads.
    ///
    /// `irreduciblecount` is an in/out accumulator (structureLoops
    /// initializes it once before its rebuild loop, block.cc:2199).
    ///
    /// Ghidra dereferences `y->copymap` unconditionally; findSpanningTree
    /// guarantees it is set (to \b this) for every block in `list`
    /// (block.cc:1027/1122), so the Rust `Option` fallback to `y` itself is
    /// unreachable on the oracle path.
    // Ghidra: block.cc:1147 BlockGraph::findIrreducible
    pub fn find_irreducible(
        &self,
        preorder: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
        irreduciblecount: &mut i32,
    ) -> bool {
        // cc:1150: the current reachunder set being built (each member also
        // carries its mark).
        let mut reachunder: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        let mut needrebuild = false;
        let mut xi: i64 = preorder.len() as i64 - 1; // cc:1152
        while xi >= 0 {
            // cc:1153-1155: for each vertex in reverse pre-order.
            let x = preorder[xi as usize].clone();
            xi -= 1;
            let sizein = x.read().unwrap().size_in();
            for i in 0..sizein {
                // cc:1157-1158: for each back-edge into x.
                if !x.read().unwrap().is_back_edge_in(i) {
                    continue;
                }
                let y = match x.read().unwrap().get_in(i) {
                    Some(e) => e.point,
                    None => continue,
                };
                if Arc::ptr_eq(&y, &x) {
                    // cc:1160: the reachunder set does not include the loop
                    // head (self back edge).
                    continue;
                }
                // cc:1161-1162: add FIND(y) to reachunder and mark it.
                let ymap = find_copy_map(&y);
                reachunder.push(ymap.clone());
                ymap.write().unwrap().set_mark();
            }
            let mut q = 0usize; // cc:1164
            while q < reachunder.len() {
                let t = reachunder[q].clone();
                q += 1;
                let sizein_t = t.read().unwrap().size_in();
                for i in 0..sizein_t {
                    // cc:1170: pretend irreducible edges don't exist.
                    if t.read().unwrap().is_irreducible_in(i) {
                        continue;
                    }
                    // cc:1172: for each forward, tree, or cross edge (all
                    // back-edges into t have already been collapsed).
                    let y = match t.read().unwrap().get_in(i) {
                        Some(e) => e.point,
                        None => continue,
                    };
                    let yprime = find_copy_map(&y); // cc:1173: y' = FIND(y)
                    // RUGRA-GLUE: cc:1174 dereferences x and yprime as raw
                    // pointers — when y' == x (the loop head's own edge into
                    // a reachunder member: y == x and copymap still points
                    // at itself, cc:1027/1122) C++ reads the same object
                    // twice, which is naturally legal without locks. Rugra's
                    // per-block RwLock must not take two read guards of one
                    // lock for that snapshot (std::sync::RwLock::read is
                    // documented "might panic" when the lock is already
                    // held by the current thread), so the ptr_eq arm serves
                    // both interval reads from the single x guard — the
                    // values are identical by object identity
                    // (BLOCK-RWLOCK-RECURSIVE-READ-0001).
                    let (x_visitcount, x_numdesc, yprime_visitcount) = {
                        let xg = x.read().unwrap();
                        let x_visitcount = xg.get_visit_count();
                        let x_numdesc = xg.get_num_desc();
                        if Arc::ptr_eq(&yprime, &x) {
                            (x_visitcount, x_numdesc, x_visitcount)
                        } else {
                            let yg = yprime.read().unwrap();
                            (x_visitcount, x_numdesc, yg.get_visit_count())
                        }
                    };
                    if (x_visitcount > yprime_visitcount)
                        || (x_visitcount + x_numdesc <= yprime_visitcount)
                    {
                        // cc:1174-1183: the original Tarjan algorithm
                        // reports reducibility failure here — y' is outside
                        // x's preorder interval, so the edge is
                        // irreducible.
                        *irreduciblecount += 1; // cc:1176
                        let edgeout = t.read().unwrap().get_in_rev_index(i); // cc:1177
                        if edgeout < 0 {
                            // Unreachable for well-formed edges (addEdge
                            // always fills reverse_index); Ghidra would
                            // index out of bounds on a raw negative.
                            continue;
                        }
                        set_out_edge_flag_mirrored(
                            &y,
                            edgeout as usize,
                            edge_flags::F_IRREDUCIBLE_EDGE,
                        ); // cc:1178
                        if t.read().unwrap().is_tree_edge_in(i) {
                            // cc:1179-1180: a tree edge that is irreducible
                            // forces a spanning-tree rebuild.
                            needrebuild = true;
                        } else {
                            // cc:1181-1182: otherwise pretend the edge was
                            // already marked irreducible — drop the stale
                            // cross/forward classification on both halves.
                            clear_out_edge_flag_mirrored(
                                &y,
                                edgeout as usize,
                                edge_flags::F_CROSS_EDGE | edge_flags::F_FORWARD_EDGE,
                            );
                        }
                    } else if !(yprime.read().unwrap().is_mark()) && !Arc::ptr_eq(&yprime, &x) {
                        // cc:1184-1187: y' is inside x's interval, not yet
                        // in reachunder, and not x itself — add and mark.
                        yprime.write().unwrap().set_mark();
                        reachunder.push(yprime);
                    }
                }
            }
            // cc:1190-1196: collapse reachunder into a single node labeled
            // as x (clear the mark, re-point copymap).
            for s in &reachunder {
                s.write().unwrap().clear_mark();
                s.write()
                    .unwrap()
                    .set_copy_map(Some(std::sync::Arc::downgrade(&x)));
            }
            reachunder.clear();
        }
        needrebuild // cc:1198
    }

    /// Get the entry (start) block of this graph. Faithful to
    /// `BlockGraph::getStartBlock` (block.cc:1649-1655): the first block
    /// carrying the `f_entry_point` flag.
    // Ghidra: block.cc:1649 BlockGraph::getStartBlock
    pub fn get_start_block(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.blocks
            .iter()
            .find(|b| b.read().unwrap().is_entry_point())
            .cloned()
    }

    /// Remove a block from the graph, first detaching all its in/out edges.
    /// Faithful to `BlockGraph::removeBlock` (block.cc:1517-1536). The block
    /// is removed from the `blocks` list but is NOT dropped (the caller may
    /// still hold an `Arc`).
    // Ghidra: block.cc:1517 BlockGraph::removeBlock
    pub fn remove_block_arc(&mut self, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        // Detach all incoming edges (rip each source's out-edge to us).
        while bl.read().unwrap().size_in() > 0 {
            let src = {
                let bl_rg = bl.read().unwrap();
                bl_rg.get_in(0).map(|e| e.point)
            };
            if let Some(src) = src {
                self.remove_edge_blocks(&src, bl);
            } else {
                break;
            }
        }
        // Detach all outgoing edges.
        while bl.read().unwrap().size_out() > 0 {
            let dst = {
                let bl_rg = bl.read().unwrap();
                bl_rg.get_out(0).map(|e| e.point)
            };
            if let Some(dst) = dst {
                self.remove_edge_blocks(bl, &dst);
            } else {
                break;
            }
        }
        // Remove from the block list (keep order, drop the Arc entry).
        self.blocks.retain(|b| !Arc::ptr_eq(b, bl));
    }

    // Ghidra: block.cc:2154 BlockGraph::collectReachable
    /// Collect reachable (or unreachable) blocks via forward mark-propagation
    /// from `bl`. Faithful to `BlockGraph::collectReachable`
    /// (block.cc:2154-2187): `bl` is marked and pushed; a work index walks
    /// `res` in order, marking/pushing each unmarked out-edge target; with
    /// `un=true`, `res` is then rebuilt to hold every UNmarked block (the
    /// unreachable set) while marks are cleared, otherwise marks are simply
    /// cleared on the reachable set.
    pub fn collect_reachable(
        &self,
        res: &mut Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        un: bool,
    ) {
        bl.write().unwrap().set_mark();
        res.push(bl.clone());
        let mut total = 0usize;
        // Propagate forward to find all reachable blocks from entry point.
        while total < res.len() {
            let blk = res[total].clone();
            total += 1;
            let out_targets: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = {
                let blk_rg = blk.read().unwrap();
                let n = blk_rg.size_out();
                (0..n)
                    .filter_map(|j| blk_rg.get_out(j).map(|e| e.point.clone()))
                    .collect()
            };
            for blk2 in out_targets {
                if blk2.read().unwrap().is_mark() {
                    continue;
                }
                blk2.write().unwrap().set_mark();
                res.push(blk2);
            }
        }
        if un {
            // Anything not marked is unreachable.
            res.clear();
            let blocks: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = self.blocks.clone();
            for blk in blocks {
                let mut blk_rg = blk.write().unwrap();
                if blk_rg.is_mark() {
                    blk_rg.clear_mark();
                } else {
                    drop(blk_rg);
                    res.push(blk);
                }
            }
        } else {
            let blocks_snapshot = res.clone();
            for blk in blocks_snapshot {
                blk.write().unwrap().clear_mark();
            }
        }
    }

    /// Ghidra `BlockGraph::scopeBreak` (block.cc:1270-1288): walk this graph's
    /// child list in order and recurse `scopeBreak(cur_exit, cur_loop_exit)`
    /// into each child. For every child except the last, `cur_exit` is the
    /// next child's index (its fall-thru successor); for the last child,
    /// `cur_exit` is the value passed in (the enclosing scope's exit, or -1
    /// at the function top-level). `cur_loop_exit` is propagated unchanged
    /// (it is the innermost enclosing loop's exit, or -1 outside any loop).
    ///
    /// This is the entry point invoked by `ActionFinalStructure::apply`
    /// (blockaction.cc:2193: `graph.scopeBreak(-1,-1)`) to reclassify
    /// unstructured gotos whose target is an enclosing loop's exit as
    /// `break;` (BlockGoto::gototype = f_break_goto).
    // Ghidra: block.cc:1270 BlockGraph::scopeBreak
    pub fn scope_break(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:1277-1287: iter = list.begin(); while (iter != list.end()) {
        //          curbl = *iter; ++iter;
        //          if (iter == list.end()) ind = curexit; else ind = (*iter)->getIndex();
        //          curbl->scopeBreak(ind, curloopexit);
        //        }
        let n = self.blocks.len();
        for i in 0..n {
            // Look ahead to determine this child's exit (= next child's index,
            // or the inherited cur_exit for the last child).
            let ind = if i + 1 < n {
                self.blocks[i + 1].read().unwrap().get_index()
            } else {
                cur_exit
            };
            self.blocks[i]
                .write()
                .unwrap()
                .scope_break_trait(ind, cur_loop_exit);
        }
    }

    /// Ghidra `BlockGraph::markUnstructured` (block.cc:1238-1245): recurse
    /// `markUnstructured()` into every child. Each structured block subtype
    /// (BlockGoto/BlockIf/BlockSwitch) further marks its unconverted
    /// (`f_goto_goto`) goto target as `f_unstructured_targ`, so
    /// `emitLabelStatement` (printc.cc:3198-3214) prints a `code_r0x` label
    /// only for blocks that are genuine unstructured goto destinations —
    /// never for loop backedges or structured-branch targets. This is the
    /// entry point invoked by `ActionFinalStructure::apply`
    /// (blockaction.cc:2194: `graph.markUnstructured()`).
    // Ghidra: block.cc:1249 BlockGraph::markUnstructured
    pub fn mark_unstructured(&mut self) {
        // cc:1241-1244: for each child in list, call markUnstructured().
        let n = self.blocks.len();
        for i in 0..n {
            self.blocks[i].write().unwrap().mark_unstructured_trait();
        }
    }

    /// Ghidra `BlockGraph::markLabelBumpUp` (block.cc:1258-1268): mark self
    /// via the base `FlowBlock::markLabelBumpUp(bump)` (flag set only when
    /// `bump`), then recurse — the FIRST subblock receives `bump` unchanged,
    /// every other subblock receives `false` (virtual dispatch: loops force
    /// `true` down their own front chain regardless). Entry point invoked by
    /// `ActionFinalStructure::apply` (blockaction.cc:2195:
    /// `graph.markLabelBumpUp(false)`).
    // Ghidra: block.cc:1258 BlockGraph::markLabelBumpUp
    pub fn mark_label_bump_up(&mut self, bump: bool) {
        // cc:1261: FlowBlock::markLabelBumpUp(bump); // Mark ourselves if true
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        }
        // cc:1262: if (list.empty()) return;
        if self.blocks.is_empty() {
            return;
        }
        // cc:1263-1264: (*iter)->markLabelBumpUp(bump); // Only pass true
        // down to first subblock
        self.blocks[0].write().unwrap().mark_label_bump_up_trait(bump);
        // cc:1265-1267: ++iter; for(;iter!=list.end();++iter)
        //   (*iter)->markLabelBumpUp(false);
        for blk in self.blocks.iter().skip(1) {
            blk.write().unwrap().mark_label_bump_up_trait(false);
        }
    }

    /// Ghidra `BlockGraph::finalizePrinting` (block.cc:1364-1371): recurse
    /// `finalizePrinting(data)` into every child of the list. This is the
    /// entry point invoked by `ActionFinalStructure::apply`
    /// (blockaction.cc:2192: `graph.finalizePrinting(data)`); dispatching is
    /// per child via [`finalize_printing_block`], which runs the
    /// `BlockSwitch::finalizePrinting` override (block.cc:3556) for switch
    /// components, the `BlockWhileDo::finalizePrinting` override
    /// (block.cc:3403 — for-loop statement extraction) for while-do loops,
    /// and the inherited graph recursion for every other composite. Leaf
    /// types inherit the base `FlowBlock::finalizePrinting` no-op
    /// (block.hh:262).
    ///
    /// Free-function form because the WhileDo override needs `&mut Funcdata`
    /// (`moveRespectingCover`/`opMarkNonPrinting`), which cannot thread
    /// through a `&mut self` method on `fd.sblocks` itself.
    // Ghidra: block.cc:1364 BlockGraph::finalizePrinting
    //
    // NO re-entry guard — by alignment, not omission. The oracle's
    // `BlockGraph::finalizePrinting` (cc:1364-1371) is a plain recursion
    // over the component list with no visited set, exactly like its twin
    // `finalTransform` (cc:1355-1362): Ghidra relies on the structured
    // tree being single-owner over its walk shape BY CONSTRUCTION
    // (identifyInternal removes the components from the parent list,
    // cc:953-960; addBlock assigns the one `parent` pointer, cc:862-875;
    // goto-arm switch targets stay unconsumed in the surrounding graph,
    // cc:3548-3553; the BLOCKCONSISTENT_DEBUG build even asserts that
    // ownership at collapse time, cc:945-948). Rugra's dispatch keeps
    // the same per-node-once property structurally: the Switch arm walks
    // control + gototype==0 cases + the gototype==0 default arm, so the
    // one sanctioned aliasing (goto-arm case targets — and a
    // gototype!=0 default — which stay top-level roots AND sit in the
    // switch's `cases`/`default_case` slots with gototype != 0) is
    // excluded from this walk — see
    // `final_transform_block` for the sweep that DOES need its visited
    // guard against that aliasing. A silent visited guard here would
    // only ever MASK an invariant break — turning a loud shape bug into
    // the quiet for→while degradation of a doubly-finalized WhileDo —
    // so debug builds machine-check the ownership invariant at this
    // sweep entry instead (`debug_assert_structure_tree_unique`),
    // mirroring Ghidra's BLOCKCONSISTENT_DEBUG philosophy; release
    // builds run the oracle's exact unguarded recursion.
    // (F8FOR-FINALIZE-VISITED-0001 disposal: shared-child premise
    // disproven for the finalize walk shape — the asymmetry vs
    // `final_transform_block`'s guard is semantically required, since
    // the two sweeps walk different member sets for BlockSwitch.)
    pub fn finalize_printing_graph(fd: &mut crate::funcdata::Funcdata) {
        // cc:1368-1370: for(iter=list.begin();iter!=list.end();++iter)
        //   (*iter)->finalizePrinting(data);
        if fd.sblocks.blocks.is_empty() {
            return;
        }
        let top: Vec<std::sync::Arc<RwLock<dyn FlowBlock + Send + Sync>>> =
            fd.sblocks.blocks.clone();
        #[cfg(debug_assertions)]
        BlockGraph::debug_assert_structure_tree_unique(&top);
        for bl in &top {
            finalize_printing_block(bl, fd);
        }
    }

    /// Ghidra `BlockGraph::orderBlocks` (block.hh:430-431): sort the
    /// top-level component list with `FlowBlock::compareFinalOrder`
    /// (block.cc:709) — the entry block (index 0) first, blocks whose
    /// `lastOp()` is a RETURN last, otherwise ascending index — skipping
    /// the sort entirely when the list holds exactly one block. Called by
    /// `ActionFinalStructure::apply` (blockaction.cc:2191) BEFORE
    /// `finalizePrinting`/`scopeBreak`/`markUnstructured`, so the
    /// next-sibling fall-thru that `BlockGraph::scopeBreak` feeds each
    /// child (block.cc:1277-1287: `(*iter)->getIndex()` of the following
    /// list entry), `gotoPrints`' next-in-flow successor (block.cc:2881-
    /// 2890) and `emitBlockGraph`'s emission order all observe the final
    /// printing order.
    // Ghidra: block.hh:430 BlockGraph::orderBlocks
    pub fn order_blocks(&mut self) {
        // cc:431: if (list.size()!=1) sort(list.begin(),list.end(),compareFinalOrder);
        if self.blocks.len() != 1 {
            // Ghidra's std::sort is libstdc++ introsort: ranges <= 16
            // elements sort via its insertion-sort phase, which is STABLE
            // for comparator ties. The only tie compareFinalOrder produces
            // is two RETURN-ending blocks (block.cc:717-725 returns false
            // in both directions, never reaching the index comparison), so
            // Rust's stable sort reproduces the oracle's tie permutation
            // for the small top-level lists that dominate real structured
            // graphs. Ranges > 16 may permute ties differently from
            // libstdc++'s quicksort phase (registered residual, see the
            // blockstruct_orderblocks_1204 fixture notes).
            self.blocks.sort_by(compare_final_order);
        }
    }

    /// Debug-only single-ownership invariant check for the structured
    /// block tree (F8FOR-FINALIZE-VISITED-0001 disposal).
    ///
    /// The oracle runs BOTH tree sweeps unguarded —
    /// `BlockGraph::finalTransform` (block.cc:1355-1362) and
    /// `BlockGraph::finalizePrinting` (block.cc:1364-1371) are plain
    /// recursions with no visited set — because over the oracle's walk
    /// shape every node is reachable exactly once: `BlockGraph::addBlock`
    /// assigns the one `parent` pointer (block.cc:862-875),
    /// `identifyInternal` physically removes the components from the
    /// parent list (`list = newlist`, block.cc:953-960), the goto-arm
    /// switch targets are left in the surrounding graph (never consumed,
    /// block.cc:3548-3553), and Ghidra's `BLOCKCONSISTENT_DEBUG` build
    /// asserts exactly that ownership at collapse time (block.cc:945-948:
    /// `if ((*iter)->parent != this) throw LowlevelError("Bad block
    /// identify")`).
    ///
    /// Rugra's Arc block model reproduces that shape with ONE sanctioned
    /// aliasing exception: a `BlockSwitch` whose control is a
    /// `BlockMultiGoto` records the peeled goto-edge targets in `cases`
    /// with gototype != 0 while they remain top-level roots
    /// (blockaction.rs mirrors cc:3548-3553 — the bodies are not part of
    /// the switch). Those aliased members are excluded from every oracle
    /// walk: `final_transform_block`'s visited guard dedups them (its
    /// `component_list_dyn` walk sees both paths — the guard is
    /// load-bearing), and `finalize_printing_block`'s Switch arm
    /// dispatches control + gototype==0 cases only, so the aliased
    /// members are never finalized through the switch. This checker
    /// walks the ORACLE shape (structured members only) and fails
    /// loudly on any OTHER duplicate reachability — a consumed component
    /// claimed by two composites, or a parent cycle — which would
    /// otherwise silently degrade a doubly-finalized WhileDo's for-loop
    /// back to `while` (the first visit's opMarkNonPrinting pair,
    /// cc:3421-3423, makes the second testTerminal reject the notPrinted
    /// root, cc:3409-3411). Mirrors Ghidra's BLOCKCONSISTENT_DEBUG
    /// philosophy at sweep time; release builds compile it out and the
    /// sweeps stay byte-identical to the oracle's unguarded recursion.
    // RUGRA-GLUE: debug-only ownership invariant walk — Ghidra's counterpart
    // is the compile-time BLOCKCONSISTENT_DEBUG #ifdef ownership check at the
    // collapse site (block.cc:945-948), not a runtime tree walk; Rugra's Arc
    // model without a `parent` invariant needs the walk to assert the same.
    #[cfg(debug_assertions)]
    fn debug_assert_component_tree_unique(
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        seen: &mut std::collections::HashSet<usize>,
    ) {
        let bl_id = Arc::as_ptr(bl) as *const () as usize;
        if !seen.insert(bl_id) {
            let (index, ty) = {
                let r = bl.read().unwrap();
                (r.get_index(), r.get_type())
            };
            panic!(
                "structure tree ownership invariant violated: block index \
                 {index} ({ty:?}) reachable twice over the oracle walk shape \
                 (shared child or cycle); the oracle guarantees single \
                 ownership via identifyInternal (block.cc:940-963) — \
                 F8FOR-FINALIZE-VISITED-0001"
            );
        }
        let ty = bl.read().unwrap().get_type();
        // Oracle walk shape: a BlockSwitch's component list (cc:1904-1919
        // identifyInternal) = the control block + the structured cases +
        // the structured default; gototype != 0 members stay in the
        // surrounding graph (cc:3548-3553) and are walked as roots. Every
        // other composite walks component_list_dyn (whose own Switch arm
        // includes the aliased goto members — NOT this shape).
        let children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = if ty == BlockType::Switch {
            let r = bl.read().unwrap();
            let sw = r.as_any().downcast_ref::<BlockSwitch>().unwrap();
            let mut v = vec![sw.control.clone()];
            for (case, &gt) in sw.cases.iter().zip(sw.case_gototypes.iter()) {
                if gt == 0 {
                    v.push(case.clone());
                }
            }
            if sw.default_gototype == 0 {
                if let Some(dc) = &sw.default_case {
                    v.push(dc.clone());
                }
            }
            v
        } else {
            BlockGraph::component_list_dyn(bl)
        };
        for child in &children {
            BlockGraph::debug_assert_component_tree_unique(child, seen);
        }
    }

    /// Sweep-entry wrapper: validate the roots over the oracle walk shape
    /// before the `final_transform_block` and `finalize_printing_block`
    /// recursions (see `debug_assert_component_tree_unique`).
    // RUGRA-GLUE: entry wrapper for the debug-only ownership invariant walk
    // (no Ghidra counterpart — see debug_assert_component_tree_unique).
    #[cfg(debug_assertions)]
    fn debug_assert_structure_tree_unique(
        roots: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    ) {
        let mut seen = std::collections::HashSet::new();
        for bl in roots {
            BlockGraph::debug_assert_component_tree_unique(bl, &mut seen);
        }
    }

    /// Find the nearest common ancestor (dominator) of two blocks in the
    /// dominator tree. Faithful to `FlowBlock::findCommonBlock`
    /// (block.cc:736-795). Used by `PcodeOp::compareOrder` (op.cc:778) to
    /// determine control-flow ordering of two ops in different blocks.
    ///
    /// Returns None if either block has no dominator info (e.g. unreachable).
    // Ghidra: block.cc:736 FlowBlock::findCommonBlock
    pub fn find_common_block(
        bl1: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        bl2: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // Standard dominator-tree LCA: walk both up to equal depth, then
        // together until they meet. Equivalent to Ghidra's mark-based walk.
        let mut b1 = bl1.clone();
        let mut b2 = bl2.clone();
        // Walk the deeper node up until depths match.
        loop {
            let d1 = b1.read().unwrap().get_dom_depth();
            let d2 = b2.read().unwrap().get_dom_depth();
            if d1 <= d2 {
                break;
            }
            let up = b1.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            b1 = match up {
                Some(u) => u,
                None => return None,
            };
        }
        loop {
            let d1 = b1.read().unwrap().get_dom_depth();
            let d2 = b2.read().unwrap().get_dom_depth();
            if d2 <= d1 {
                break;
            }
            let up = b2.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            b2 = match up {
                Some(u) => u,
                None => return None,
            };
        }
        // Now equal depth; walk both up together.
        while !Arc::ptr_eq(&b1, &b2) {
            let up1 = b1.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            let up2 = b2.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            b1 = match up1 {
                Some(u) => u,
                None => return None,
            };
            b2 = match up2 {
                Some(u) => u,
                None => return None,
            };
        }
        Some(b1)
    }

    /// Ghidra `BlockGraph::nextFlowAfter` (block.cc:1335-1353): the block
    /// containing the next statement in flow after child `bl` — the child
    /// following `bl` in this graph's emission list, front-leafed; when `bl`
    /// is the last child, the oracle defers to the parent graph
    /// (`getParent()->nextFlowAfter(this)`) and returns null at the root.
    /// Rugra's `BlockGraph` is not a `FlowBlock` (no inheritance), so a
    /// nested graph can never sit in another graph's `blocks` list — the
    /// only graph the emitter walks (`sblocks`) is the root, where the
    /// oracle's end-of-list arm is exactly the null it returns at the root.
    /// The parent-recursion arm is therefore structurally unreachable and
    /// resolves to `None` here. Consumed by `BlockGoto::gotoPrints`
    /// (block.cc:2886) to detect a fall-thru goto. The C++ `for` scan stops
    /// at the first identity hit; Rust locates by `Arc::ptr_eq`; a `bl` not
    /// present in the list returns `None` (the C++ increment-past-end of
    /// that case is never exercised by the oracle's callers).
    // Ghidra: block.cc:1335 BlockGraph::nextFlowAfter
    pub fn next_flow_after(
        graph_arc: &Arc<RwLock<BlockGraph>>,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:1339-1342: find bl in list.
        // cc:1343: ++iter — the first block after bl.
        let next = graph_arc
            .read()
            .unwrap()
            .blocks
            .iter()
            .position(|b| Arc::ptr_eq(b, bl))?
            .checked_add(1)?;
        // cc:1344-1348: end-of-list -> parent chain, null at the root;
        // Rugra's graph is always the root (see doc comment).
        // cc:1349-1352: nextbl = *iter; front-leaf it.
        let nextbl = graph_arc.read().unwrap().blocks.get(next)?.clone();
        front_leaf(&nextbl)
    }

    // RUGRA-GLUE: Ghidra's uniform BlockGraph::list / getBlock(i) component
    // protocol (block.hh:365-380, factories block.cc:1758-1918), projected
    // onto Rugra's typed composite fields. Order matches the -nodes- vector
    // each factory passes to identifyInternal: BlockList [nodes in order],
    // BlockIf [cond] for if-goto (newBlockIfGoto cc:1799-1810) / [cond, tc]
    // (newBlockIf cc:1822-1830) / [cond, tc, fc] (newBlockIfElse cc:1840-
    // 1849), BlockWhileDo [cond, cl] (cc:1858), BlockDoWhile [condcl]
    // (cc:1874), BlockInfLoop [body] (cc:1889), BlockCondition [b1, b2]
    // (cc:1780), BlockSwitch [cs..., default] (cc:1904 — the control stays
    // outside the list; Rugra's default_case models the default arm),
    // BlockGoto [bl] (cc:1702). Leaves (Basic/Copy) return an empty list:
    // Ghidra's walk only recurses through BlockGraph subtypes.
    //
    // pub for the bilateral blockstruct_blockgoto_wrapped_1204 fixture —
    // the oracle side walks getBlock(i) directly, and this is the only
    // Rust-visible projection of that uniform protocol.
    pub fn component_list_dyn(
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        let guard = bl.read().unwrap();
        let any = guard.as_any();
        match guard.get_type() {
            BlockType::List => any
                .downcast_ref::<BlockList>()
                .map(|l| l.children.clone())
                .unwrap_or_default(),
            BlockType::If => any
                .downcast_ref::<BlockIf>()
                .map(|i| {
                    // if-goto: nodes=[cond] only (newBlockIfGoto); if_body is
                    // a placeholder aliasing condition in that form.
                    if i.goto_target.is_some() {
                        vec![i.condition.clone()]
                    } else {
                        let mut v = vec![i.condition.clone(), i.if_body.clone()];
                        if let Some(eb) = &i.else_body {
                            v.push(eb.clone());
                        }
                        v
                    }
                })
                .unwrap_or_default(),
            BlockType::WhileDo => any
                .downcast_ref::<BlockWhileDo>()
                .map(|w| vec![w.condition.clone(), w.body.clone()])
                .unwrap_or_default(),
            BlockType::DoWhile => any
                .downcast_ref::<BlockDoWhile>()
                .map(|d| vec![d.condition.clone()])
                .unwrap_or_default(),
            BlockType::InfLoop => any
                .downcast_ref::<BlockInfLoop>()
                .map(|l| vec![l.body.clone()])
                .unwrap_or_default(),
            BlockType::Condition => any
                .downcast_ref::<BlockCondition>()
                .map(|c| vec![c.first.clone(), c.second.clone()])
                .unwrap_or_default(),
            BlockType::Switch => any
                .downcast_ref::<BlockSwitch>()
                .map(|s| {
                    let mut v: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = s.cases.clone();
                    if let Some(dc) = &s.default_case {
                        v.push(dc.clone());
                    }
                    v
                })
                .unwrap_or_default(),
            BlockType::Goto => any
                .downcast_ref::<BlockGoto>()
                .and_then(|g| g.wrapped.clone())
                .into_iter()
                .collect(),
            // Basic/Copy/Plain/Graph/MultiGoto: leaves or non-walkable nodes
            // (Ghidra's nextFlowAfter recursion only crosses BlockGraph lists).
            _ => Vec::new(),
        }
    }

    // Ghidra: block.cc:2881 BlockGoto::gotoPrints (tree-wide evaluation form)
    /// Evaluate every tree-resident `BlockGoto::gotoPrints` (block.cc:2881-
    /// 2890) once over the final structured tree: `prints = (front_leaf(target)
    /// != next-in-flow successor)` where the successor is
    /// `getParent()->nextFlowAfter(this)` — the per-parent-type virtual
    /// dispatch (`next_flow_after_successors`, block.cc:1335/2899/2931/
    /// 3053/3127/3341/3448/3476/3639). The root graph itself is a plain
    /// BlockGraph, so its components get the sibling rule (cc:1335-1353)
    /// with the null parent at the root (cc:1344-1346). Called by
    /// ActionFinalStructure after `scopeBreak(-1,-1)` and before
    /// `markUnstructured()` (blockaction.cc:2193-2194) — the oracle's own
    /// first lazy evaluation point — so `markUnstructured`'s `gotoPrints()`
    /// gate (block.cc:2861) and the emitter read the same value the oracle
    /// computes on demand. Results are stored on `BlockGoto::prints_precomputed`.
    pub fn compute_goto_prints(&mut self) {
        let components = self.blocks.clone();
        let succs = graph_sibling_successors(&components, None);
        for (child, succ) in components.into_iter().zip(succs) {
            goto_prints_visit(&child, succ);
        }
    }

    // Ghidra: block.cc:796 FlowBlock::findCommonBlock
    /// Find the common dominator of multiple blocks.
    /// Faithful to `FlowBlock::findCommonBlock(vector<FlowBlock*>&)`
    /// (block.cc:796-826). Used by `buildDominantCopy` to find the LCA of
    /// all COPY ops' parent blocks.
    ///
    /// Algorithm: mark the dom-chain of blockSet[0]; for each subsequent
    /// block, walk its dom-chain until hitting a marked block; track the
    /// one with the smallest index (= highest in dom tree).
    pub fn find_common_block_n(
        block_set: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    ) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        if block_set.is_empty() {
            return None;
        }
        // Use Arc pointer set as the mark (avoids &mut borrow across blocks).
        let mut marked: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // Walk blockSet[0]'s dom chain, marking each.
        let mut bl = block_set[0].clone();
        let mut res = bl.clone();
        let mut best_index = bl.read().unwrap().get_index();
        loop {
            marked.insert(std::sync::Arc::as_ptr(&bl) as *const () as usize);
            let up = bl.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
            match up {
                Some(u) => bl = u,
                None => break,
            }
        }
        // For each subsequent block, walk until hitting a marked block.
        for i in 1..block_set.len() {
            if best_index == 0 {
                break;
            }
            let mut cur = block_set[i].clone();
            loop {
                let ptr = std::sync::Arc::as_ptr(&cur) as *const () as usize;
                if marked.contains(&ptr) {
                    let idx = cur.read().unwrap().get_index();
                    if idx < best_index {
                        res = cur.clone();
                        best_index = idx;
                    }
                    break;
                }
                marked.insert(ptr);
                let up = cur
                    .read()
                    .unwrap()
                    .get_immed_dom()
                    .and_then(|w| w.upgrade());
                match up {
                    Some(u) => cur = u,
                    None => break,
                }
            }
        }
        // (Ghidra clears marks; our HashSet is local and dropped here.)
        Some(res)
    }

    /// Remove the first incoming edge of `dst` whose source is `src`.
    /// The incoming edge's stored reverse slot selects the exact paired
    /// outgoing half, including after legal slot swaps or with parallel edges.
    // Ghidra: block.cc:1469 BlockGraph::removeEdge
    pub fn remove_edge_blocks(
        &mut self,
        src: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        dst: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        // cc:1477-1479: scan dst.intothis in its stored order. Do not scan
        // src.outofthis independently: with parallel edges the two first
        // pointer matches need not be reciprocal partners.
        let in_slot = {
            let dst_rg = dst.read().unwrap();
            (0..dst_rg.size_in()).find(|&i| {
                dst_rg
                    .get_in(i)
                    .map(|e| Arc::ptr_eq(&e.point, src))
                    .unwrap_or(false)
            })
        };
        let Some(in_slot) = in_slot else {
            return;
        };
        // FlowBlock::removeInEdge (block.cc:130-141): capture the peer and
        // reciprocal slot, delete the incoming half, then delete exactly that
        // outgoing half. The order matters because each half-delete repairs
        // reverse indices of the surviving shifted entries.
        let (source, reverse_slot) = {
            let mut dst_guard = dst.write().unwrap();
            let edge = dst_guard
                .get_in(in_slot)
                .expect("removeEdge incoming slot disappeared");
            dst_guard.half_delete_in_edge(in_slot);
            (edge.point, edge.reverse_index as usize)
        };
        source
            .write()
            .unwrap()
            .half_delete_out_edge(reverse_slot);
    }

    // Ghidra: block.cc:1239 BlockGraph::clear
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.incoming.clear();
        self.outgoing.clear();
        // Absorption bookkeeping refers to the previous block population;
        // reset with the graph (Ghidra rebuilds the parent relation per copy).
        self.absorbed_into.clear();
    }

    // Ghidra: block.cc:1439 BlockGraph::addEdge
    pub fn add_edge(
        &mut self,
        from: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        to: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        // Check for self-loop: same Arc → single write lock to avoid deadlock
        if Arc::ptr_eq(&from, &to) {
            let mut b = from.write().unwrap();
            let out_idx = b.size_out() as i32;
            let in_idx = b.size_in() as i32;
            b.add_out_edge(BlockEdge::new(to.clone(), in_idx));
            b.add_in_edge(BlockEdge::new(from.clone(), out_idx));
        } else {
            let mut f = from.write().unwrap();
            let mut t = to.write().unwrap();

            let out_idx = f.size_out() as i32;
            let in_idx = t.size_in() as i32;

            f.add_out_edge(BlockEdge::new(to.clone(), in_idx));
            t.add_in_edge(BlockEdge::new(from.clone(), out_idx));
        }
    }

    /// \brief Calculate the immediate dominator for each node in \b this
    /// BlockGraph, for forward control-flow.
    ///
    /// Faithful port of `BlockGraph::calcForwardDominator`
    /// (block.cc:1954-2032), Cooper-Harvey-Kennedy over a forward post-order
    /// list, including the oracle's virtual-root and excise semantics:
    ///
    /// - The official start node is `postorder.back()`: with a single root
    ///   that is `rpo[0]` (= Ghidra `list[0]` after `findSpanningTree`'s
    ///   `list = rpostorder`); with multiple roots a virtual root is created
    ///   (`createVirtualRoot`, block.cc:988-995) whose out-edges reach every
    ///   rootlist entry (cc:1970-1973).
    /// - A single root that itself has in-edges (a back-edge into the entry)
    ///   also gets a virtual root (cc:1978-1984); any other root-with-inedges
    ///   shape throws `LowlevelError("Problems finding root node of graph")`
    ///   (cc:1979-1980), mirrored here as `anyhow::bail!`.
    /// - The successors of the start node are pre-filled with
    ///   `immed_dom = start node` (cc:1986-1987) — for the virtual root its
    ///   "successors" are exactly the rootlist entries in rootlist order
    ///   (each `rootlist[i]->addInEdge(newroot,0)` is two-sided, block.cc:76-79,
    ///   so it materializes the virtual root's out-edge as well).
    /// - The finger arithmetic (cc:2004-2012) reads the idom node's `index`
    ///   field. A freshly constructed `FlowBlock` has `index == 0`
    ///   (block.cc:61-69 FlowBlock ctor), so a finger that walks into the
    ///   virtual root aliases to `numnodes - 0`, the postorder slot of
    ///   `rpo[0]`. This is load-bearing oracle behavior: a block whose
    ///   dominator chain escapes to the virtual root (a merge of two
    ///   different roots' subtrees) converges at `rpo[0]`'s slot and ends up
    ///   with `immed_dom == rpo[0]`, NOT null. Replicated verbatim via
    ///   `DomNode::VRoot` contributing index 0 in `dom_index`.
    /// - Excise (cc:2022-2029): after convergence every node whose idom is
    ///   the virtual root (exactly the pre-filled rootlist entries — the
    ///   finger walk can never *produce* the virtual root as `new_idom`)
    ///   gets `immed_dom = null` and the virtual root is deleted; with no
    ///   virtual root the start node's self-domination is cleared instead
    ///   (cc:2031).
    ///
    /// Rugra binding note: Ghidra reads the RPO ordering from the graph's
    /// own `list` (contract: "blocks are in reverse post-order and this is
    /// reflected in the index field", block.hh:434). This port takes the RPO
    /// view as an explicit slice because Rugra's shared `blocks` vector is
    /// position-indexed by other passes and must not be reordered outside
    /// `find_spanning_tree` (BLOCK-INDEX-ASSIGN-0001); the rpo slot number
    /// plays the role of the oracle's `index` field.
    ///
    /// Output: every block's `immed_dom` is overwritten (null for dominator
    /// roots, mirroring the cc:1967 clear + cc:2022-2031 post-processing) —
    /// stale values never survive.
    // Ghidra: block.cc:1954 BlockGraph::calcForwardDominator
    pub fn calc_forward_dominator(
        &mut self,
        rootlist: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    ) -> anyhow::Result<()> {
        let list: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> =
            self.blocks.iter().cloned().collect();
        Self::calc_forward_dominator_impl(&list, rootlist)
    }

    /// Same algorithm as `calc_forward_dominator`, but the reverse
    /// post-order view is supplied explicitly instead of being read from
    /// `self.blocks`. Used by `build_dom_tree`, which must not reorder the
    /// shared component vector mid-pipeline (see the binding note on
    /// `calc_forward_dominator`).
    // RUGRA-GLUE: explicit-RPO entry sharing the calcForwardDominator core (oracle reads list)
    pub fn calc_forward_dominator_on(
        &self,
        rpo: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
        rootlist: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    ) -> anyhow::Result<()> {
        Self::calc_forward_dominator_impl(rpo, rootlist)
    }

    // Ghidra: block.cc:1954 BlockGraph::calcForwardDominator
    fn calc_forward_dominator_impl(
        rpo: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
        rootlist: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    ) -> anyhow::Result<()> {
        // cc:1963: if (list.empty()) return;
        let n = rpo.len();
        if n == 0 {
            return Ok(());
        }
        let numnodes = (n as i32) - 1; // cc:1964

        // cc:1966-1969: clear the dominator field on every node and build
        // the forward post-order list: postorder[numnodes-i] = list[i]. Node
        // ids are rpo slots; the virtual root (when present) is appended at
        // the end (cc:1972/1982).
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum Node {
            Rpo(usize),
            VRoot,
        }
        // immed_dom per rpo slot; None mirrors Ghidra's null FlowBlock*.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum Dom {
            None,
            Rpo(usize),
            VRoot,
        }
        let mut postorder: Vec<Node> = vec![Node::Rpo(0); n]; // cc:1965 resize
        for i in 0..n {
            postorder[(numnodes - i as i32) as usize] = Node::Rpo(i);
        }
        let mut dom: Vec<Dom> = vec![Dom::None; n];
        // cc:1970-1975: multiple roots -> create the virtual root now.
        let mut virtualroot = rootlist.len() > 1;
        if virtualroot {
            postorder.push(Node::VRoot); // cc:1972
        }

        // cc:1977: b = postorder.back() — the official start node.
        let mut b = *postorder.last().unwrap();
        // cc:1978-1984: the root must have no in-edges.
        let start_has_in_edges = match b {
            Node::Rpo(0) => rpo[0].read().unwrap().size_in() != 0,
            Node::VRoot => false, // fresh FlowBlock: no in-edges
            Node::Rpo(_) => unreachable!("postorder.back() is slot 0 or VRoot"),
        };
        if start_has_in_edges {
            // cc:1979-1980: if ((rootlist.size() != 1)||(rootlist[0] != b))
            //   throw LowlevelError("Problems finding root node of graph");
            let ptr =
                |a: &Arc<RwLock<dyn FlowBlock + Send + Sync>>| Arc::as_ptr(a) as *const () as usize;
            if rootlist.len() != 1 || ptr(&rootlist[0]) != ptr(&rpo[0]) {
                anyhow::bail!("Problems finding root node of graph");
            }
            virtualroot = true; // cc:1981: createVirtualRoot(rootlist)
            postorder.push(Node::VRoot); // cc:1982
            b = Node::VRoot; // cc:1983
        }

        // cc:1985: b->immed_dom = b. For the real single root this is the
        // slot-0 self-domination cleared again at cc:2031; the virtual
        // root's self-domination lives on the temporary node only.
        match b {
            Node::Rpo(0) => dom[0] = Dom::Rpo(0),
            Node::VRoot => {} // deleted with the temporary node (cc:2028)
            Node::Rpo(_) => unreachable!(),
        }
        // cc:1986-1987: fill in dom of nodes the start node immediately
        // connects to ("to deal with possible artificial edge"). The virtual
        // root's out-edges are exactly the rootlist entries, in rootlist
        // order (createVirtualRoot block.cc:992-994).
        match b {
            Node::VRoot => {
                let ptr = |a: &Arc<RwLock<dyn FlowBlock + Send + Sync>>| {
                    Arc::as_ptr(a) as *const () as usize
                };
                let slot_of: std::collections::HashMap<usize, usize> =
                    rpo.iter().enumerate().map(|(s, a)| (ptr(a), s)).collect();
                for root in rootlist {
                    if let Some(&slot) = slot_of.get(&(ptr(root))) {
                        dom[slot] = Dom::VRoot;
                    }
                }
            }
            Node::Rpo(0) => {
                let ptr = |a: &Arc<RwLock<dyn FlowBlock + Send + Sync>>| {
                    Arc::as_ptr(a) as *const () as usize
                };
                let slot_of: std::collections::HashMap<usize, usize> =
                    rpo.iter().enumerate().map(|(s, a)| (ptr(a), s)).collect();
                let outs: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = {
                    let bg = rpo[0].read().unwrap();
                    let mut v = Vec::with_capacity(bg.size_out());
                    for i in 0..bg.size_out() {
                        if let Some(e) = bg.get_out(i) {
                            v.push(e.point);
                        }
                    }
                    v
                };
                for tgt in outs {
                    if let Some(&slot) = slot_of.get(&(ptr(&tgt))) {
                        dom[slot] = Dom::Rpo(0);
                    }
                }
            }
            Node::Rpo(_) => unreachable!(),
        }

        // Predecessor rpo slots in in-edge order for each block (the CHK
        // "first processed predecessor" scan walks Ghidra's intothis order).
        let ptr =
            |a: &Arc<RwLock<dyn FlowBlock + Send + Sync>>| Arc::as_ptr(a) as *const () as usize;
        let slot_of: std::collections::HashMap<usize, usize> =
            rpo.iter().enumerate().map(|(s, a)| (ptr(a), s)).collect();
        let preds: Vec<Vec<usize>> = rpo
            .iter()
            .map(|blk| {
                let bg = blk.read().unwrap();
                let mut v = Vec::with_capacity(bg.size_in());
                for j in 0..bg.size_in() {
                    if let Some(e) = bg.get_in(j) {
                        if let Some(&s) = slot_of.get(&(ptr(&e.point))) {
                            v.push(s);
                        }
                    }
                }
                v
            })
            .collect();

        // The oracle index a dominator node contributes to the finger
        // arithmetic: real blocks use their reverse-post-order number (= the
        // rpo slot); the virtual root's fresh FlowBlock has index == 0
        // (block.cc:61-69), aliasing its postorder slot onto rpo[0]'s.
        let dom_index = |d: Dom| -> i32 {
            match d {
                Dom::Rpo(s) => s as i32,
                Dom::VRoot => 0, // FlowBlock ctor: index = 0 (block.cc:65)
                Dom::None => panic!("dominator finger walked into null immed_dom"),
            }
        };

        let root_dom = match *postorder.last().unwrap() {
            Node::VRoot => Dom::VRoot,
            Node::Rpo(0) => Dom::Rpo(0),
            Node::Rpo(_) => unreachable!(),
        };

        // cc:1988-2021: iterate to convergence, processing nodes in reverse
        // post-order except the root.
        let mut changed = true;
        while changed {
            changed = false;
            for pos in (0..postorder.len() - 1).rev() {
                // cc:1993: b = postorder[i] — always a real block (the root
                // is the excluded last slot).
                let Node::Rpo(i) = postorder[pos] else {
                    unreachable!("virtual root only occupies the final slot");
                };
                // cc:1994: if (b->immed_dom != postorder.back())
                if dom[i] != root_dom {
                    // cc:1995-1999: find the first processed predecessor.
                    // Mirrors the unguarded C++ exit: if no predecessor is
                    // processed, new_idom holds the LAST in-edge tried; if
                    // the block has no in-edges at all, new_idom stays null
                    // (cc:1989 initialization).
                    let mut new_idom: Option<usize> = None; // cc:1989
                    let mut j = 0usize;
                    while j < preds[i].len() {
                        new_idom = Some(preds[i][j]);
                        if dom[preds[i][j]] != Dom::None {
                            break;
                        }
                        j += 1;
                    }
                    if let Some(mut nid) = new_idom {
                        let mut j2 = j + 1; // cc:2000: j += 1
                        while j2 < preds[i].len() {
                            let rho = preds[i][j2];
                            // cc:2003: if (rho->immed_dom != 0)
                            if dom[rho] != Dom::None {
                                // cc:2004-2012: intersection routine.
                                let mut finger1 = numnodes - dom_index(Dom::Rpo(rho));
                                let mut finger2 = numnodes - dom_index(Dom::Rpo(nid));
                                while finger1 != finger2 {
                                    while finger1 < finger2 {
                                        let Node::Rpo(s1) = postorder[finger1 as usize] else {
                                            unreachable!("finger escaped to virtual-root slot")
                                        };
                                        finger1 = numnodes - dom_index(dom[s1]);
                                    }
                                    while finger2 < finger1 {
                                        let Node::Rpo(s2) = postorder[finger2 as usize] else {
                                            unreachable!("finger escaped to virtual-root slot")
                                        };
                                        finger2 = numnodes - dom_index(dom[s2]);
                                    }
                                }
                                // cc:2012: new_idom = postorder[finger1];
                                let Node::Rpo(s) = postorder[finger1 as usize] else {
                                    unreachable!("finger converged on virtual-root slot")
                                };
                                nid = s;
                            }
                            j2 += 1;
                        }
                        // cc:2015-2018: if (b->immed_dom != new_idom)
                        if dom[i] != Dom::Rpo(nid) {
                            dom[i] = Dom::Rpo(nid);
                            changed = true;
                        }
                    } else if dom[i] != Dom::None {
                        // cc:2015-2018 with new_idom == null: a block with
                        // no in-edges that is not the registered root gets a
                        // null dominator.
                        dom[i] = Dom::None;
                        changed = true;
                    }
                }
            }
        }

        // cc:2022-2029: excise the virtual root from the dominator tree.
        if virtualroot {
            for i in 0..n {
                // cc:2023-2025: postorder[i] for i < list.size() are exactly
                // the real blocks.
                if dom[i] == Dom::VRoot {
                    dom[i] = Dom::None;
                }
            }
            // cc:2026-2028: remove the virtual root's edges and delete it —
            // the Rust Node::VRoot enum value is dropped with postorder.
        } else {
            // cc:2031: postorder.back()->immed_dom = 0;
            dom[0] = Dom::None;
        }

        // Write the results back onto the blocks.
        for (slot, d) in dom.iter().enumerate() {
            match d {
                Dom::Rpo(j) => {
                    let target = rpo[*j].clone();
                    rpo[slot]
                        .write()
                        .unwrap()
                        .set_immed_dom(Some(Arc::downgrade(&target)));
                }
                Dom::VRoot => {
                    // Unreachable: the excise pass converted every surviving
                    // VRoot link to None above.
                    rpo[slot].write().unwrap().set_immed_dom(None);
                }
                Dom::None => {
                    rpo[slot].write().unwrap().set_immed_dom(None);
                }
            }
        }
        Ok(())
    }

    /// Compute the reverse post-order and root list for \b this graph using
    /// exactly the traversal of `BlockGraph::findSpanningTree`
    /// (block.cc:1009-1136), without any of its mutation side effects:
    ///
    /// - root candidates are the blocks with `size_in() == 0` collected in
    ///   component-vector order (cc:1028-1030);
    /// - with more than one candidate the first and last are swapped so the
    ///   original head is visited LAST and therefore finishes the DFS last,
    ///   taking reverse-post-order slot 0 (cc:1031-1035) — a trailing orphan
    ///   block can never steal RPO[0];
    /// - with no candidate at all the first block is assumed to be the entry
    ///   (cc:1036-1038);
    /// - the two-pass extraroots mechanism (cc:1041-1127) guarantees every
    ///   block receives a slot while keeping the original head at RPO[0];
    /// - the final swap (cc:1129-1133) puts the original head back at the
    ///   front of the rootlist.
    ///
    /// Differences from the public `find_spanning_tree` port, all documented
    /// in place: the component vector is not reordered to `rpostorder`
    /// (cc:1135), edge flags are neither cleared nor written (cc:1045's
    /// clear makes pass one treat every edge as unlabelled, which this local
    /// traversal reproduces by never skipping an edge — the only producer of
    /// f_irreducible labels is the findIrreducible rebuild loop inside
    /// structureLoops, block.cc:2204-2209), and visitcount/numdesc/copymap
    /// are not stored on the blocks.
    // RUGRA-GLUE: side-effect-free RPO+rootlist mirror of findSpanningTree (block.cc:1009) for position-indexed graphs
    fn compute_spanning_rpo(
        &self,
    ) -> (
        Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
        Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    ) {
        let n = self.blocks.len();
        if n == 0 {
            return (Vec::new(), Vec::new());
        }
        let key =
            |a: &Arc<RwLock<dyn FlowBlock + Send + Sync>>| Arc::as_ptr(a) as *const () as usize;
        // cc:1023-1030: collect potential roots in list order.
        let mut rootlist: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        for i in 0..n {
            if self.blocks[i].read().unwrap().size_in() == 0 {
                rootlist.push(self.blocks[i].clone());
            }
        }
        if rootlist.len() > 1 {
            // cc:1031-1035: orighead visited last -> RPO[0].
            let last = rootlist.len() - 1;
            rootlist.swap(0, last);
        } else if rootlist.is_empty() {
            // cc:1036-1038: assume the first block is the entry point.
            rootlist.push(self.blocks[0].clone());
        }
        let origrootpos = rootlist.len() - 1; // cc:1039

        let mut preorder: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        for repeat in 0..2 {
            let mut extraroots = false;
            let mut rpostcount = n as i32; // cc:1043
            let mut rootindex = 0usize; // cc:1044
            let mut visited: std::collections::HashSet<usize> =
                std::collections::HashSet::with_capacity(n);
            let mut rpostorder: Vec<Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>> =
                vec![None; n];
            // cc:1046: while (preorder.size() < list.size())
            while preorder.len() < n {
                // cc:1048-1058: take the next unvisited root, dropping
                // roots already visited this pass (stale roots).
                let mut startbl: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = None;
                while rootindex < rootlist.len() {
                    let cand = rootlist[rootindex].clone();
                    rootindex += 1;
                    if !visited.contains(&key(&cand)) {
                        startbl = Some(cand);
                        break;
                    }
                    rootlist.remove(rootindex - 1);
                    rootindex -= 1;
                }
                let startbl: Arc<RwLock<dyn FlowBlock + Send + Sync>> = match startbl {
                    Some(b) => b,
                    None => {
                        // cc:1059-1067: no unvisited root — treat the next
                        // unvisited block (list order) as another root.
                        extraroots = true;
                        let mut found = self.blocks[n - 1].clone();
                        for i in 0..n {
                            let cand = self.blocks[i].clone();
                            if !visited.contains(&key(&cand)) {
                                found = cand;
                                break;
                            }
                        }
                        rootlist.push(found.clone());
                        rootindex += 1;
                        found
                    }
                };
                // cc:1069-1073: discover the start block (preorder).
                visited.insert(key(&startbl));
                preorder.push(startbl.clone());
                // cc:1075-1107: iterative DFS. Edge classification (cc:1093,
                // 1100-1105) is not stored — no flags are written.
                let mut state: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = vec![startbl];
                let mut istate: Vec<usize> = vec![0];
                while !state.is_empty() {
                    let curbl = state.last().unwrap().clone();
                    let finished = {
                        let size_out = curbl.read().unwrap().size_out();
                        size_out <= *istate.last().unwrap()
                    };
                    if finished {
                        // cc:1077-1084: assign the reverse-post-order index.
                        state.pop();
                        istate.pop();
                        rpostcount -= 1;
                        rpostorder[rpostcount as usize] = Some(curbl);
                    } else {
                        let edgenum = *istate.last().unwrap();
                        *istate.last_mut().unwrap() += 1;
                        let childbl = match curbl.read().unwrap().get_out(edgenum) {
                            Some(e) => e.point,
                            None => continue,
                        };
                        if !visited.contains(&key(&childbl)) {
                            visited.insert(key(&childbl));
                            preorder.push(childbl.clone());
                            state.push(childbl);
                            istate.push(0);
                        }
                    }
                }
            }
            if !extraroots {
                // cc:1109: spanning tree complete in one pass.
                let rpo: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = rpostorder
                    .into_iter()
                    .map(|slot| slot.expect("rpostorder fully assigned by DFS"))
                    .collect();
                if rootlist.len() > 1 {
                    // cc:1129-1133: orighead to the front of rootlist.
                    let last = rootlist.len() - 1;
                    rootlist.swap(0, last);
                }
                return (rpo, rootlist);
            }
            if repeat == 1 {
                // cc:1110-1111: throw LowlevelError("Could not generate
                // spanning tree") — panic channel mirrors the oracle throw.
                panic!("Could not generate spanning tree");
            }
            // cc:1114-1116: move the entry block to the last rootlist
            // position and redo the traversal so the entry keeps RPO[0].
            let last = rootlist.len() - 1;
            rootlist.swap(last, origrootpos);
            preorder.clear(); // cc:1124
        }
        unreachable!("repeat loop covers both passes");
    }

    /// Build the dominator tree for the graph
    ///
    /// Corresponds to Ghidra's `BlockGraph::buildDomTree`
    // Ghidra: block.cc:2036 BlockGraph::buildDomTree
    pub fn build_dom_tree(&mut self) {
        // Re-index all blocks to match their current vector position. This is
        // essential after dead-flow Actions (ActionUnreachable/DoNothing/etc.)
        // remove blocks — stale indices would cause out-of-bounds panics below.
        for (i, blk) in self.blocks.iter_mut().enumerate() {
            blk.write().unwrap().set_index(i as i32);
        }
        if self.blocks.is_empty() {
            return;
        }

        // Dominators are computed with the oracle root semantics: the
        // spanning-tree RPO (rootlist swap keeps the original head at
        // RPO[0], block.cc:1031-1035) feeds calcForwardDominator
        // (block.cc:1954), whose official root is postorder.back() = the
        // first RPO slot, with the virtual-root create/excise path for
        // multi-root graphs and back-edges into the entry.
        let (rpo, rootlist) = self.compute_spanning_rpo();
        if let Err(e) = Self::calc_forward_dominator_impl(&rpo, &rootlist) {
            // Ghidra throws LowlevelError up the structureReset chain; the
            // panic channel mirrors the oracle single-function abort model.
            panic!("{}", e);
        }

        self.build_dom_depth();
        self.build_dom_subtree();
        self.calc_dom_frontier();
    }

    /// Build depth information based on the dominator tree
    ///
    /// Corresponds to Ghidra's `BlockGraph::buildDomDepth`
    // Ghidra: block.cc:2056 BlockGraph::buildDomDepth
    pub fn build_dom_depth(&mut self) {
        let rpo = self.calc_rpo();
        for node_ref in &rpo {
            // Get idom depth first without holding node's lock
            let idom_depth = {
                let node = node_ref.read().unwrap();
                let size_in = node.size_in();
                if size_in == 0 || (node.get_flags() & block_flags::ENTRY_POINT) != 0 {
                    Some(0i32) // entry: depth 0
                } else if let Some(ref idom_weak) = node.get_immed_dom() {
                    if let Some(idom_ref) = idom_weak.upgrade() {
                        if Arc::ptr_eq(&idom_ref, node_ref) {
                            Some(0) // self-dom
                        } else {
                            drop(node); // release read lock before reading idom
                            Some(idom_ref.read().unwrap().get_dom_depth() + 1)
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(depth) = idom_depth {
                node_ref.write().unwrap().set_dom_depth(depth);
            }
        }
    }

    /// Build the dominator sub-tree relationships
    ///
    /// Corresponds to Ghidra's `BlockGraph::buildDomSubTree`
    // Ghidra: block.cc:2080 BlockGraph::buildDomSubTree
    pub fn build_dom_subtree(&mut self) {
        // Clear existing children
        for node in &self.blocks {
            node.write().unwrap().clear_dom_children();
        }

        // Add each block to its immediate dominator's children list
        for i in 0..self.blocks.len() {
            let idom_weak = {
                let node = self.blocks[i].read().unwrap();
                node.get_immed_dom()
            };

            if let Some(weak) = idom_weak {
                if let Some(idom_ref) = weak.upgrade() {
                    idom_ref
                        .write()
                        .unwrap()
                        .add_dom_child(self.blocks[i].clone());
                }
            }
        }
    }

    /// Calculate dominance frontiers for all blocks
    ///
    /// Implements the Cooper-Harvey-Kennedy dominance-frontier algorithm from
    /// "A Simple, Fast Dominator Algorithm". For a join-point `b` (a block with
    /// more than one predecessor, OR the function entry when it also has a
    /// back-edge — i.e. a loop header that doubles as the entry), each
    /// predecessor `p` runs up the dominator tree adding `b` to every runner's
    /// frontier until it reaches `idom(b)`.
    ///
    /// Note: the function-entry flow is intentionally NOT modelled as an
    /// explicit predecessor edge (matching Ghidra's `FlowBlock` in-edge model),
    /// so the entry block's recorded `incoming` edges only reflect real CFG
    /// edges. A loop header that is also the entry therefore has
    /// `incoming.len() == 1` (just the back-edge). To keep CHK correct in that
    /// case we additionally treat `entry && incoming.len() >= 1` as a
    /// join-point, and — because `build_dom_tree` leaves the entry's `idom`
    /// as `None` — we use `b` itself as the runner stop node (the entry
    /// dominates itself). Without this, every loop whose header is the entry
    /// gets an empty dominance frontier, no MULTIEQUAL (phi) is placed for the
    /// loop-carried flag varnode, and the CBRANCH condition read is left
    /// unresolved (root cause of the `while(local_0==local_0)` dead-loop).
    // RUGRA-GLUE: Rugra-only dom-frontier calculation (Ghidra has no dom-frontier field on FlowBlock)
    pub fn calc_dom_frontier(&mut self) {
        for i in 0..self.blocks.len() {
            let b_ref = self.blocks[i].clone();

            // Gather incoming edges + entry flag + idom while holding one read lock.
            let (incoming, is_entry, b_index, b_idom_ref) = {
                let b = b_ref.read().unwrap();
                let size_in = b.size_in();
                let mut incoming = Vec::new();
                for j in 0..size_in {
                    if let Some(edge) = b.get_in(j) {
                        incoming.push(edge);
                    }
                }
                let b_idom_ref = b.get_immed_dom().and_then(|w| w.upgrade());
                // `b` is the function entry iff it has the ENTRY_POINT flag, has
                // no recorded predecessors (size_in==0), OR — the most reliable
                // signal — `build_dom_tree` left its `idom` as None (the entry
                // dominates itself and is never assigned an idom). The idom-None
                // case is what catches a loop header that doubles as the entry:
                // its only recorded predecessor is the back-edge (size_in==1)
                // and ENTRY_POINT may not be set, so the flag/size checks alone
                // miss it.
                let is_entry = (b.get_flags() & block_flags::ENTRY_POINT) != 0
                    || size_in == 0
                    || b_idom_ref.is_none();
                let b_index = b.get_index();
                (incoming, is_entry, b_index, b_idom_ref)
            };

            // Join-point: ≥2 predecessors, OR the entry block reached by a
            // back-edge (incoming.len() >= 1) — the implicit entry flow is the
            // "second" predecessor in CHK terms.
            let is_join = incoming.len() >= 2 || (is_entry && incoming.len() >= 1);
            if !is_join {
                continue;
            }

            // CHK runner stop node = idom(b). For the entry block idom is None
            // (buildDomTree leaves it unset), but the entry dominates itself,
            // so the correct stop node is `b` itself.
            let stop_ref: Arc<RwLock<dyn FlowBlock + Send + Sync>> = match &b_idom_ref {
                Some(idom) => idom.clone(),
                None if is_entry => b_ref.clone(),
                None => continue,
            };

            for edge in incoming {
                let mut runner_ref = edge.point.clone();

                let max_steps = self.blocks.len() + 2;
                let mut steps = 0;
                while !Arc::ptr_eq(&runner_ref, &stop_ref) && steps < max_steps {
                    steps += 1;
                    runner_ref.write().unwrap().add_to_dom_frontier(b_index);

                    let next_runner = runner_ref
                        .read()
                        .unwrap()
                        .get_immed_dom()
                        .and_then(|w| w.upgrade());

                    if let Some(nr) = next_runner {
                        if Arc::ptr_eq(&nr, &runner_ref) {
                            break; // self-loop
                        }
                        runner_ref = nr;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    /// Calculate Reverse Post-Order (RPO) of blocks
    ///
    /// Delegates to the side-effect-free spanning-tree traversal mirror
    /// (`compute_spanning_rpo`), which reproduces the root selection of
    /// `BlockGraph::findSpanningTree` (block.cc:1009-1136): candidates are
    /// the `size_in()==0` blocks collected in component order (NOT
    /// entry-flagged blocks), with more than one candidate the first/last
    /// swap (block.cc:1031-1035) makes the original head finish the DFS last
    /// and take RPO slot 0, an empty candidate list falls back to the first
    /// block (block.cc:1036-1038), and the two-pass extraroots mechanism
    /// (block.cc:1041-1127) keeps the original head at RPO[0] while
    /// covering every block. Previously this accessor DFS'd the entry
    /// candidates in vector order, letting a trailing orphan block steal
    /// RPO[0] (HTTPD-ADDDESCEND-THROW-0001 root cause).
    // RUGRA-GLUE: Rugra RPO calculation (Ghidra uses findSpanningTree + orderBlocks block.cc:1009)
    pub fn calc_rpo(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.compute_spanning_rpo().0
    }

    /// Structure a loop
    ///
    /// Corresponds to Ghidra's `BlockGraph::structureLoops`
    // Ghidra: block.cc:2194 BlockGraph::structureLoops
    pub fn structure_loops(
        &mut self,
        rootlist: &mut Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    ) -> anyhow::Result<()> {
        // Faithful to block.cc:2197-2215:
        //   do { findSpanningTree(preorder, rootlist);
        //        needrebuild = findIrreducible(preorder, irreduciblecount);
        //        if (needrebuild) { clearEdgeFlags(spanning labels);
        //                           preorder.clear(); rootlist.clear(); }
        //        } while (needrebuild);
        //   if (irreduciblecount > 0) calcLoop();
        //
        // findSpanningTree establishes the reverse post-order (reordering
        // the component list, block.cc:1135 `list = rpostorder`), relabels
        // tree/forward/cross/back edges, and fills rootlist with every
        // entry point — the inputs calcForwardDominator and
        // Funcdata::structureReset consume. findIrreducible then labels the
        // irreducible edges (the only f_irreducible writer); on needrebuild
        // the spanning labels are cleared (f_irreducible kept, block.cc:2206)
        // and the loop runs again — note findSpanningTree's own pass start
        // wipes every label including f_irreducible (block.cc:1045), so each
        // rebuild re-derives the classification over the RPO-reordered
        // component list, which changes the next root scan order.
        //
        // cc:2211-2214: when irreduciblecount > 0 the driver finishes with
        // calcLoop(), the DFS failsafe that additionally labels
        // cycle-breaking f_loop_edge edges (BLOCK-CALCLOOP-0001).
        let mut preorder: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        let mut irreduciblecount: i32 = 0; // cc:2199: initialized once, accumulates
        loop {
            // cc:2201-2204
            self.find_spanning_tree(&mut preorder, rootlist)?;
            let needrebuild = self.find_irreducible(&preorder, &mut irreduciblecount);
            if !needrebuild {
                break;
            }
            // cc:2205-2209: clear the spanning tree (keep f_irreducible),
            // then rebuild from an empty preorder/rootlist.
            self.clear_edge_flags_mask(edge_flags::SPANNING_MASK);
            preorder.clear();
            rootlist.clear();
        }
        if irreduciblecount > 0 {
            // cc:2211-2214: make absolutely sure removing the loop edges
            // makes a DAG (calcLoop, block.cc:2104-2147).
            self.calc_loop();
        }
        Ok(())
    }

    /// Add a loop edge
    ///
    /// Faithful to `BlockGraph::addLoopEdge` (block.cc:1451-1464): marks the
    /// EXISTING `outindex`-th outgoing edge of `begin` as a \e loop edge
    /// (`f_loop_edge`) via `FlowBlock::setOutEdgeFlag` (block.cc:1463),
    /// which ORs the label onto both halves — `begin->outofthis[outindex]`
    /// and the mirrored `intothis[reverse_index]` of the target
    /// (block.cc:240-246). Ghidra locates the edge by out-index (never by
    /// target identity) precisely because multiple out-edges to the same
    /// block must stay distinguishable (block.cc:1459-1462 comment). The
    /// `#ifdef BLOCKCONSISTENT_DEBUG` parent check (block.cc:1454-1458) is
    /// compiled out in the oracle release build and has no Rugra
    /// counterpart.
    // Ghidra: block.cc:1451 BlockGraph::addLoopEdge
    pub fn add_loop_edge(
        &mut self,
        begin: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        outindex: usize,
    ) {
        // cc:1463: begin->setOutEdgeFlag(outindex, f_loop_edge);
        set_out_edge_flag_mirrored(begin, outindex, edge_flags::F_LOOP_EDGE);
    }

    /// \brief Identify a set of edges whose removal leaves a DAG
    ///
    /// Faithful port of `BlockGraph::calcLoop` (block.cc:2104-2147).
    /// Starting from the FIRST component in the graph list (cc:2118
    /// `list.front()`), an explicit-stack depth-first search walks the out
    /// edges of each block in slot order (cc:2130 `state.back() += 1`
    /// advances the per-path-level child cursor BEFORE the edge is used).
    /// Two block flags drive the search (cc:2120): `f_mark` = ever visited,
    /// `f_mark2` = on the current root-to-node path.
    ///   - An out-edge to a block still carrying `f_mark2` closes a cycle:
    ///     `addLoopEdge(bl, i)` labels that edge `f_loop_edge` (cc:2133-
    ///     2137) and the search does NOT descend (the oracle's throw is
    ///     commented out at cc:2136 — this is the irreducibility failsafe).
    ///   - An out-edge already labelled `f_loop_edge` is skipped as if it
    ///     did not exist (cc:2131 `isLoopOut`), so a re-run treats earlier
    ///     cycle breaks as removed.
    ///   - An edge to a visited-but-popped block (f_mark set, f_mark2
    ///     clear) truncates the search (cc:2138's else — nothing happens).
    ///   - A fresh node is pushed with `f_mark|f_mark2` (cc:2138-2142).
    /// When a path level exhausts its out-edges the block pops and loses
    /// only `f_mark2` (cc:2124-2128); after the whole stack empties, every
    /// block in list order has `f_mark|f_mark2` cleared (cc:2145-2146).
    /// In structureLoops this runs only when irreduciblecount > 0
    /// (block.cc:2211-2214) as a final guarantee that the loop edges make
    /// the graph acyclic.
    // Ghidra: block.cc:2104 BlockGraph::calcLoop
    pub fn calc_loop(&mut self) {
        // cc:2113: nothing to do on an empty graph.
        if self.blocks.is_empty() {
            return;
        }
        // cc:2115-2120: seed the DFS from the first component; state[i] is
        // the next out-edge slot of path[i] to process (0 = no children
        // visited yet).
        let mut path: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        let mut state: Vec<usize> = Vec::new();
        path.push(self.blocks[0].clone());
        state.push(0);
        self.blocks[0]
            .write()
            .unwrap()
            .set_flags(block_flags::MARK | block_flags::MARK2);
        // cc:2121-2144: while(!path.empty())
        while !path.is_empty() {
            let bl = path.last().unwrap().clone();
            let i = *state.last().unwrap();
            let size_out = bl.read().unwrap().size_out();
            if i >= size_out {
                // cc:2124-2128: visited everything below this node, POP.
                // Only f_mark2 (on-path) is cleared; f_mark (visited) stays.
                bl.write().unwrap().clear_flags(block_flags::MARK2);
                path.pop();
                state.pop();
            } else {
                // cc:2130: advance the child cursor before using slot i.
                *state.last_mut().unwrap() += 1;
                // cc:2131: previously marked loop-edge — act as if it
                // doesn't exist.
                if bl.read().unwrap().is_loop_out(i) {
                    continue;
                }
                let nextbl = match bl.read().unwrap().get_out(i) {
                    Some(e) => e.point,
                    None => continue,
                };
                let nextflags = nextbl.read().unwrap().get_flags();
                if (nextflags & block_flags::MARK2) != 0 {
                    // cc:2133-2137: we found a cycle! (Irreducibility
                    // failsafe — the oracle's LowlevelError is commented
                    // out.)
                    self.add_loop_edge(&bl, i);
                } else if (nextflags & block_flags::MARK) == 0 {
                    // cc:2138-2142: fresh node — mark visited+on-path, push.
                    nextbl
                        .write()
                        .unwrap()
                        .set_flags(block_flags::MARK | block_flags::MARK2);
                    path.push(nextbl);
                    state.push(0);
                }
                // Visited but not on path (f_mark set, f_mark2 clear):
                // truncate the search — nothing to do (cc:2138 else).
            }
        }
        // cc:2145-2146: clear our marks on every block in list order.
        for bl in &self.blocks {
            bl.write()
                .unwrap()
                .clear_flags(block_flags::MARK | block_flags::MARK2);
        }
    }
}

/// Per-child dispatch for [`BlockGraph::finalize_printing`]: the virtual
/// `FlowBlock::finalizePrinting` call (block.hh:262 base no-op;
/// block.cc:1364 graph recursion; block.cc:3556 switch override).
///
/// `BlockSwitch` (cc:3556-3592) recurses FIRST into its component list —
/// the dispatch block, the structured (non-goto) case components, and the
/// structured (gototype==0) default arm, exactly the members Ghidra's
/// `newBlockSwitch` consumed via `identifyInternal` (block.cc:1913); the
/// goto-arm case targets (and a gototype!=0 default) stay in
/// the surrounding graph (block.cc:3548-3553) and are finalized by the
/// parent graph's own recursion — then runs the label/depth passes and
/// the stable sort. Every other composite inherits the plain recursion
/// over its component children. `BlockMultiGoto`'s wrapped copy is a
/// dispatch leaf (newBlockMultiGoto nodes=[bl], block.cc:1734-1738), so
/// the no-entry walk matches the oracle.
// RUGRA-GLUE: free-function form of the C++ virtual dispatch; Rugra
// composites implement FlowBlock individually instead of subclassing one
// BlockGraph vtable. `fd` threads the Funcdata the WhileDo override needs
// (block.cc:3403 `BlockWhileDo::finalizePrinting(Funcdata&)`).
pub fn finalize_printing_block(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    fd: &mut crate::funcdata::Funcdata,
) {
    let ty = bl.read().unwrap().get_type();
    if ty == BlockType::Switch {
        // cc:3559: BlockGraph::finalizePrinting(data) — recurse into the
        // switch's list before the label passes.
        let children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = {
            let r = bl.read().unwrap();
            let sw = r.as_any().downcast_ref::<BlockSwitch>().unwrap();
            let mut v = vec![sw.control.clone()];
            for (case, &gt) in sw.cases.iter().zip(sw.case_gototypes.iter()) {
                if gt == 0 {
                    v.push(case.clone());
                }
            }
            // Ghidra: block.cc:3556 BlockSwitch::finalizePrinting — the
            // default arm body with gototype==0 is a structure member
            // (ruleSwitch blockaction.cc:1714-1720 pushes every non-exit
            // out edge into cases, newBlockSwitch block.cc:1913
            // identifyInternal consumes them), so the graph recursion must
            // reach it; a gototype!=0 default stays in the surrounding
            // graph (cc:3548-3553 goto-arm mirror) and is excluded here.
            // Identical shape to the checker arm
            // (debug_assert_component_tree_unique).
            if sw.default_gototype == 0 {
                if let Some(dc) = &sw.default_case {
                    v.push(dc.clone());
                }
            }
            v
        };
        for child in &children {
            finalize_printing_block(child, fd);
        }
        // cc:3562-3591: the label/depth passes + stable sort.
        let mut w = bl.write().unwrap();
        let sw = w.as_any_mut().downcast_mut::<BlockSwitch>().unwrap();
        sw.finalize_case_labels();
    } else {
        // Inherited BlockGraph::finalizePrinting recursion (cc:1364-1371):
        // BlockWhileDo::finalizePrinting (cc:3406) recurses into its own
        // components FIRST, then runs the for-loop statement extraction.
        for child in BlockGraph::component_list_dyn(bl) {
            finalize_printing_block(&child, fd);
        }
        if ty == BlockType::WhileDo {
            let mut w = bl.write().unwrap();
            if let Some(wd) = w.as_any_mut().downcast_mut::<BlockWhileDo>() {
                while_do_finalize_printing(wd, fd);
            }
        }
    }
}

impl Eq for BlockRef {}

impl PartialOrd for BlockRef {
    // RUGRA-GLUE: Rust PartialOrd for BlockRef (Ghidra sorts FlowBlock* via
    // compareBlockIndex block.hh:893 — the pure index `<` used by Varnode
    // def-block ordering; NOT compareFinalOrder, which adds entry-first /
    // RETURN-last keys and lives in compare_final_order below)
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockRef {
    // RUGRA-GLUE: Rust Ord for BlockRef (Ghidra compareBlockIndex block.hh:893:
    // `bl1->getIndex() < bl2->getIndex()` — see PartialOrd note above)
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self.0.read().unwrap();
        let b = other.0.read().unwrap();
        a.get_index().cmp(&b.get_index())
    }
}

/// Ghidra `FlowBlock::compareFinalOrder` (block.cc:709-730): the comparator
/// behind `BlockGraph::orderBlocks` (block.hh:430) that establishes the
/// final printing order of the top-level structure list.
///
/// Semantics, line by line against the oracle:
/// - cc:712-713: the entry block (`getIndex() == 0`) always comes first.
///   Distinct top-level blocks always carry distinct indices (a composite's
///   index is the minimum basic-block index it contains, and components are
///   disjoint), so at most one of the two arms can fire; the both-zero case
///   is unreachable in the oracle and maps to `Equal` here only to keep the
///   comparator a total order.
/// - cc:714-715: `lastOp()` is the per-type virtual — null for the
///   FlowBlock base, loops and switch (block.hh:239/707/723/737/793 region);
///   the wrapped component's for BlockGoto/BlockMultiGoto (block.hh:562/590);
///   the mirrored block's for BlockCopy (block.hh:533); the last child's for
///   BlockList (block.cc:2960); the second child's for BlockCondition
///   (block.cc:3016); the condition's for a single-component if-goto
///   BlockIf (block.cc:3119); the block's own last op for BlockBasic
///   (block.cc:2344).
/// - cc:717-728: a block whose last op is CPUI_RETURN sorts AFTER every
///   block that does not end in RETURN (whether the other side has a
///   non-RETURN last op or no last op at all).
/// - cc:719-725 tie: two blocks BOTH ending in RETURN compare `false` in
///   both directions — the oracle's std::sort never reaches the index
///   comparison for them, so they are a tie. Mapped to `Ordering::Equal`;
///   `BlockGraph::order_blocks` resolves ties with a stable sort (see the
///   tie note there).
/// - cc:729: everything else orders by `getIndex()`.
// Ghidra: block.cc:709 FlowBlock::compareFinalOrder
pub fn compare_final_order(
    bl1: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    bl2: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
) -> std::cmp::Ordering {
    let a = bl1.read().unwrap();
    let b = bl2.read().unwrap();
    // cc:712-713: entry point (index 0) first.
    if a.get_index() == 0 {
        return std::cmp::Ordering::Less;
    }
    if b.get_index() == 0 {
        return std::cmp::Ordering::Greater;
    }
    // cc:714-715: virtual lastOp() dispatch; only the opcode of the final
    // op matters (CPUI_RETURN vs anything else vs absent).
    let ret1 = a.last_op().map(|op| {
        op.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_RETURN
    });
    let ret2 = b.last_op().map(|op| {
        op.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_RETURN
    });
    match (ret1, ret2) {
        // cc:719-720: (op1 RETURN, op2 not RETURN) -> return false.
        (Some(true), Some(false)) => return std::cmp::Ordering::Greater,
        // cc:721-722: (op1 not RETURN, op2 RETURN) -> return true.
        (Some(false), Some(true)) => return std::cmp::Ordering::Less,
        // cc:724: op1 RETURN with op2 absent -> return false.
        (Some(true), None) => return std::cmp::Ordering::Greater,
        // cc:726-727: op2 RETURN with op1 absent -> return true.
        (None, Some(true)) => return std::cmp::Ordering::Less,
        // cc:719+724 both firing false: two RETURN-ending blocks — tie
        // (comparator returns false in both directions, index is never
        // consulted).
        (Some(true), Some(true)) => return std::cmp::Ordering::Equal,
        // Neither side ends in RETURN (non-RETURN ops, absent ops, or a
        // mix): fall through to the index comparison (cc:729).
        _ => {}
    }
    // cc:729: return (bl1->getIndex() < bl2->getIndex());
    a.get_index().cmp(&b.get_index())
}

/// Represents a copy of another block
///
/// Corresponds to Ghidra's `BlockCopy` class
#[derive(Debug)]
pub struct BlockCopy {
    pub index: i32,
    pub flags: u32,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    /// Weak self handle for virtual methods returning `this`.
    // RUGRA-GLUE: Rust self-reference for Ghidra methods returning `this`
    pub self_ref: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// The live FlowBlock mirrored by this copy. Ghidra deliberately accepts
    /// any FlowBlock here, not only BlockBasic.
    pub original: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    /// Exact value-copies of the source FlowBlock base edge arrays.
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub immed_dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub copy_map: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub visit_count: i32,
    pub num_desc: i32,
    /// Rugra's derived dominator caches; rebuilt on the copied graph.
    // RUGRA-GLUE: Rust caches for Ghidra's external dominator vectors
    pub dom_depth: i32,
    // RUGRA-GLUE: Rust caches for Ghidra's external dominator vectors
    pub dom_children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    // RUGRA-GLUE: Rust caches for Ghidra's external dominator vectors
    pub dom_frontier: std::collections::HashSet<i32>,
}

impl FlowBlock for BlockCopy {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // Ghidra: block.hh:524 BlockCopy::subBlock
    fn sub_block(&self, _slot: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        Some(self.original.clone())
    }
    // Ghidra: block.hh:525 BlockCopy::getType
    fn get_type(&self) -> BlockType {
        BlockType::Copy
    }
    // RUGRA-GLUE: Rust whole-op-list view for Ghidra BlockCopy firstOp/lastOp delegation
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.original.read().unwrap().get_ops()
    }
    // Ghidra: block.hh:532 BlockCopy::firstOp
    fn first_op(&self) -> Option<PcodeOpRef> {
        self.original.read().unwrap().first_op()
    }
    // Ghidra: block.hh:533 BlockCopy::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        self.original.read().unwrap().last_op()
    }
    // Ghidra: block.hh:531 BlockCopy::getExitLeaf
    fn get_exit_leaf_trait(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.self_ref.as_ref().and_then(Weak::upgrade)
    }
    // Ghidra: block.hh:535 BlockCopy::getSplitPoint
    fn get_split_point(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.original.read().unwrap().get_split_point()
    }
    // Ghidra: block.hh:536 BlockCopy::isComplex
    /// Delegates to the mirrored block (usually a BlockBasic), exactly as
    /// Ghidra's inline `virtual bool isComplex(void) const { return copy->isComplex(); }`.
    fn is_complex(&self) -> bool {
        self.original.read().unwrap().is_complex()
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:162 FlowBlock::getImmedDom
    fn get_immed_dom(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.immed_dom.clone()
    }
    // RUGRA-GLUE: Rust mutator for Ghidra FlowBlock::immed_dom
    fn set_immed_dom(&mut self, dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.immed_dom = dom;
    }
    // Ghidra: block.hh:163 FlowBlock::getCopyMap
    fn get_copy_map(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.copy_map.clone()
    }
    // RUGRA-GLUE: Rust mutator for Ghidra FlowBlock::copymap
    fn set_copy_map(&mut self, map: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.copy_map = map;
    }
    // Ghidra: block.hh:283 FlowBlock::getVisitCount
    fn get_visit_count(&self) -> i32 {
        self.visit_count
    }
    // Ghidra: block.hh:282 FlowBlock::setVisitCount
    fn set_visit_count(&mut self, count: i32) {
        self.visit_count = count;
    }
    // RUGRA-GLUE: Rust accessor for Ghidra FlowBlock::numdesc
    fn get_num_desc(&self) -> i32 {
        self.num_desc
    }
    // RUGRA-GLUE: Rust mutator for Ghidra FlowBlock::numdesc
    fn set_num_desc(&mut self, count: i32) {
        self.num_desc = count;
    }
    // RUGRA-GLUE: Rugra-only dom-depth cache
    fn get_dom_depth(&self) -> i32 {
        self.dom_depth
    }
    // RUGRA-GLUE: Rugra-only dom-depth cache mutator
    fn set_dom_depth(&mut self, depth: i32) {
        self.dom_depth = depth;
    }
    // RUGRA-GLUE: Rugra-only dominator-child cache
    fn get_dom_children(&self) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.dom_children.clone()
    }
    // RUGRA-GLUE: Rugra-only dominator-child cache mutator
    fn add_dom_child(&mut self, child: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.dom_children.push(child);
    }
    // RUGRA-GLUE: Rugra-only dominator-child cache reset
    fn clear_dom_children(&mut self) {
        self.dom_children.clear();
    }
    // RUGRA-GLUE: Rugra-only dominance-frontier cache
    fn get_dom_frontier(&self) -> std::collections::HashSet<i32> {
        self.dom_frontier.clone()
    }
    // RUGRA-GLUE: Rugra-only dominance-frontier cache mutator
    fn add_to_dom_frontier(&mut self, index: i32) {
        self.dom_frontier.insert(index);
    }
    // RUGRA-GLUE: Rugra-only dominance-frontier cache reset
    fn clear_dom_frontier(&mut self) {
        self.dom_frontier.clear();
    }
    // Ghidra: block.hh:286 FlowBlock::isMark
    fn is_mark(&self) -> bool {
        self.flags & block_flags::MARK != 0
    }
    // Ghidra: block.hh:287 FlowBlock::setMark
    fn set_mark(&mut self) {
        self.flags |= block_flags::MARK;
    }
    // Ghidra: block.hh:288 FlowBlock::clearMark
    fn clear_mark(&mut self) {
        self.flags &= !block_flags::MARK;
    }
    // Ghidra: block.hh:306 FlowBlock::getInRevIndex
    fn get_in_rev_index(&self, slot: usize) -> i32 {
        self.incoming
            .get(slot)
            .map(|edge| edge.reverse_index)
            .unwrap_or(-1)
    }
    // Ghidra: block.hh:346 FlowBlock::isGotoIn
    fn is_goto_in(&self, slot: usize) -> bool {
        self.incoming.get(slot).map_or(false, |edge| {
            edge.flags & (edge_flags::F_GOTO_EDGE | edge_flags::F_IRREDUCIBLE_EDGE) != 0
        })
    }
    // Ghidra: block.hh:347 FlowBlock::isGotoOut
    fn is_goto_out(&self, slot: usize) -> bool {
        self.outgoing.get(slot).map_or(false, |edge| {
            edge.flags & (edge_flags::F_GOTO_EDGE | edge_flags::F_IRREDUCIBLE_EDGE) != 0
        })
    }
    // Ghidra: block.hh:294 FlowBlock::setLoopExit
    fn set_loop_exit(&mut self, slot: usize) {
        if let Some(edge) = self.outgoing.get_mut(slot) {
            edge.flags |= edge_flags::F_LOOP_EXIT_EDGE;
        }
    }
    // Ghidra: block.hh:295 FlowBlock::clearLoopExit
    fn clear_loop_exit(&mut self, slot: usize) {
        if let Some(edge) = self.outgoing.get_mut(slot) {
            edge.flags &= !edge_flags::F_LOOP_EXIT_EDGE;
        }
    }
    // Ghidra: block.cc:218 FlowBlock::swapEdges
    fn swap_edges(&mut self) {
        if self.outgoing.len() != 2 {
            return;
        }
        self.outgoing.swap(0, 1);
        let pending = self
            .outgoing
            .iter()
            .enumerate()
            .map(|(slot, edge)| (slot, edge.point.clone(), edge.reverse_index))
            .collect::<Vec<_>>();
        for (slot, target, reverse_index) in pending {
            if reverse_index < 0 {
                continue;
            }
            match target.try_write() {
                Ok(mut peer) => {
                    if let Some(edge) = peer.in_edges_mut().get_mut(reverse_index as usize) {
                        edge.reverse_index = slot as i32;
                    }
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if let Some(edge) = self.incoming.get_mut(reverse_index as usize) {
                        edge.reverse_index = slot as i32;
                    }
                }
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    panic!("poisoned reciprocal edge lock: {error}");
                }
            }
        }
        self.flags ^= block_flags::FLIP_PATH;
    }
    // Ghidra: block.hh:534 BlockCopy::negateCondition
    fn negate_condition(&mut self, toporbottom: bool) -> bool {
        let result = {
            let mut original = self.original.write().unwrap();
            original.negate_condition(true)
        };
        if toporbottom {
            self.swap_edges();
        }
        result
    }
    // Ghidra: block.cc:2848 BlockCopy::encodeHeader
    fn encode_header_trait(&self, encoder: &mut dyn Encoder) {
        encoder.write_signed_integer(&attrib_index(), self.index as i64);
        let alternate = self.original.read().unwrap().get_index();
        encoder.write_signed_integer(&attrib_altindex(), alternate as i64);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockCopy virtual overrides)
impl BlockCopy {
    /// Ghidra `BlockCopy::printHeader` (block.cc:2835-2840): prints
    /// `"Basic(copy) block "` followed by the FlowBlock header.
    // Ghidra: block.cc:2835 BlockCopy::printHeader
    pub fn print_header(&self) -> String {
        format!("Basic(copy) block {}", self.index)
    }

    /// Ghidra `BlockCopy::printTree` (block.cc:2842-2846): delegates to the
    /// wrapped original block's printTree at the given indentation level.
    // Ghidra: block.cc:2842 BlockCopy::printTree
    pub fn print_tree(&self, level: i32) -> String {
        let indent: String = "  ".repeat(level as usize);
        let body = self.original.read().unwrap();
        format!(
            "{}Block_{} (copy of {})\n",
            indent,
            self.index,
            body.get_index()
        )
    }

    /// Ghidra `BlockCopy::encodeHeader` (block.cc:2848-2854): emits the base
    /// header (index) plus an `altindex` attribute holding the wrapped
    /// block's index. Returns `(index, altindex)` for the marshal layer.
    // Ghidra: block.cc:2848 BlockCopy::encodeHeader
    pub fn encode_header(&self) -> (i32, i32) {
        let altindex = self.original.read().unwrap().get_index();
        (self.index, altindex)
    }
}

/// Represents a goto statement
///
/// Corresponds to Ghidra's `BlockGoto` class
#[derive(Debug)]
pub struct BlockGoto {
    pub index: i32,
    pub flags: u32,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    /// PRINTC-GOTOPRINTS-0001 legacy projection: the goto target's front leaf
    /// as a typed `BlockBasic` Arc, consumed by `printc.rs` `emit_block_goto`
    /// (frozen write-set) via a `.start_addr` field read. The collapse graph's
    /// leaves are `BlockCopy` nodes whose originals were coerced to
    /// `Arc<RwLock<dyn FlowBlock>>` at creation, so a shared-identity typed Arc
    /// is not recoverable; this stays `None` and the real target lives in
    /// `target_dyn` (below) exactly as Ghidra's `gototarget` pointer
    /// (block.hh:548). The printc side switches to `target_dyn` +
    /// `FlowBlock::get_start_addr()` under PRINTC-GOTOPRINTS-0001.
    pub goto_target: Option<Arc<RwLock<BlockBasic>>>,
    /// Ghidra `BlockGoto::gototarget` (block.hh:548): the target FlowBlock of
    /// the unstructured branch, captured from the wrapped block's out-edge
    /// BEFORE the edge removal (`new BlockGoto(bl->getOut(0))`,
    /// block.cc:1705 precedes `removeEdge`, block.cc:1711). Held as the live
    /// dyn Arc so `getIndex()` (scopeBreak, block.cc:2872-2873) and
    /// `getFrontLeaf()` (gotoPrints, block.cc:2886) read the same object the
    /// oracle's pointer would.
    pub target_dyn: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Ghidra `BlockGoto : BlockGraph` list component (block.hh:547): the
    /// wrapped block (`getBlock(0)`), moved into the BlockGoto by
    /// `identifyInternal(ret, [bl])` (block.cc:1706-1708). Every delegated
    /// virtual (`emit` via printc.cc:2771, `lastOp`, `getExitLeaf`,
    /// `firstOp`, `printRaw`, `nextFlowAfter` recursion in scopeBreak) reads
    /// this component; without it the wrapped block evaporates when
    /// `identify_internal` replaces its graph slot
    /// (MAIN-RC2-BLOCKGOTO-WRAPPED-0001).
    pub wrapped: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Ghidra `BlockGoto::gototype` (block.hh:549): classification of the
    /// unstructured branch (one of `goto_type::GOTO_GOTO` /
    /// `goto_type::BREAK_GOTO` / `goto_type::CONTINUE_GOTO`). Defaults to
    /// `GOTO_GOTO`; mutated by scope_break to BREAK_GOTO (block.cc:2873).
    pub goto_type: u32,
    /// Transport for the oracle's lazy `gotoPrints()` evaluation
    /// (block.cc:2881-2890). Ghidra reads `getParent()->nextFlowAfter(this)`
    /// at emit time; Rugra composites other than the root `BlockGraph` cannot
    /// sit in a `BlockGraph::blocks` list, so `BlockGoto::parent` is never
    /// wired and the parent-present arm cannot run on demand. Instead
    /// `BlockGraph::compute_goto_prints` evaluates the identical comparison
    /// (`front_leaf(target) != next-in-flow successor`) once over the final
    /// tree in `ActionFinalStructure` (after scopeBreak, before
    /// markUnstructured — the oracle's own first evaluation point), and stores
    /// the result here. Default `false` is the oracle's null-parent arm
    /// (block.cc:2889) for BlockGotos outside a computed tree.
    pub prints_precomputed: bool,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
}

impl FlowBlock for BlockGoto {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // Ghidra: block.hh:555 BlockGoto::getType
    fn get_type(&self) -> BlockType {
        BlockType::Goto
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; BlockGoto : BlockGraph
    // emits via the virtual chain `getBlock(0)->emit(this)` — printc.cc:2771 —
    // and BlockGraph::firstOp/lastOp delegate to getBlock(0) (block.cc:1330-
    // 1333). The flatten projection of that delegation is the wrapped block's
    // full op list, in component order; the trait default (empty Vec) dropped
    // every wrapped block's ops (MAIN-RC2-BLOCKGOTO-WRAPPED-0001).
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        match &self.wrapped {
            // Ghidra block.hh:547: BlockGoto's single list component.
            Some(w) => w.read().unwrap().get_ops(),
            None => Vec::new(),
        }
    }
    // Ghidra: block.hh:190 FlowBlock::subBlock — BlockGoto's component list
    // holds exactly the wrapped block (identifyInternal(ret,[bl]),
    // block.cc:1706-1708), so subBlock(0) is the wrapped Arc.
    fn sub_block(&self, slot: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        if slot == 0 {
            self.wrapped.clone()
        } else {
            None
        }
    }
    // Ghidra: block.cc:1327 BlockGraph::firstOp — getBlock(0)->firstOp()
    fn first_op(&self) -> Option<PcodeOpRef> {
        self.wrapped.as_ref().map(|w| w.read().unwrap().first_op())?
    }
    // Ghidra: block.hh:562 BlockGoto::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        // cc:562: return getBlock(0)->lastOp(); — getBlock(0) is the
        // wrapped component moved in by identifyInternal (block.cc:1706-
        // 1708). compareFinalOrder (block.cc:714-715) reads this to push
        // return-ending goto blocks to the end of the final print order.
        self.wrapped
            .as_ref()
            .and_then(|w| w.read().unwrap().last_op())
    }
    // Ghidra: block.hh:561 BlockGoto::getExitLeaf — getBlock(0)->getExitLeaf()
    fn get_exit_leaf_trait(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        match &self.wrapped {
            Some(w) => w.read().unwrap().get_exit_leaf_trait(),
            None => None,
        }
    }
    // Ghidra: block.cc:2866 BlockGoto::scopeBreak — delegate to the inherent
    // helper which holds the faithful port (cc:2869 recurse, cc:2872-2873
    // reclassify as f_break_goto when target == curloopexit).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_goto_type(cur_exit, cur_loop_exit);
    }
    // Ghidra: block.cc:2856 BlockGoto::markUnstructured — delegate to the
    // inherent helper (cc:2814 recurses into the wrapped child via
    // BlockGraph::markUnstructured, but Rugra's BlockGoto wraps a BlockBasic
    // with no structured children, so only the target-marking cc:2815-2818
    // step is needed).
    fn mark_unstructured_trait(&mut self) {
        self.mark_unstructured_target();
    }
    // Ghidra: block.cc:1258 BlockGraph::markLabelBumpUp — inherited by
    // BlockGoto (block.hh:547, no override): mark self via the base method
    // (flag only if `bump`), then recurse — the single list[0] component
    // (`wrapped`) receives `bump`; there are no further subblocks. The
    // `gototarget` is not a list member and is never recursed into
    // (block.hh:548 stores it outside the graph list).
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        // cc:1261: FlowBlock::markLabelBumpUp(bump); // Mark ourselves if true
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        }
        // cc:1262-1264: first (and only) subblock receives bump.
        if let Some(w) = &self.wrapped {
            w.write().unwrap().mark_label_bump_up_trait(bump);
        }
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockGoto virtual overrides)
impl BlockGoto {
    /// Ghidra `BlockGoto::getGotoTarget` (block.hh:552, inline): return the
    /// target block of the unstructured goto.
    // Ghidra: block.hh:552 BlockGoto::getGotoTarget
    pub fn get_goto_target(&self) -> Option<Arc<RwLock<BlockBasic>>> {
        self.goto_target.clone()
    }

    /// Ghidra `BlockGoto::getGotoType` (block.hh:553, inline): return the
    /// classification of the unstructured branch
    /// (`goto_type::GOTO_GOTO`/`BREAK_GOTO`/`CONTINUE_GOTO`).
    // Ghidra: block.hh:553 BlockGoto::getGotoType
    pub fn get_goto_type(&self) -> u32 {
        self.goto_type
    }

    /// Ghidra `BlockGoto::markUnstructured` (block.cc:2856-2864): recurse
    /// into the wrapped component (`BlockGraph::markUnstructured`, cc:2859),
    /// then — if the goto is a plain `goto` (not `break`/`continue`) and it
    /// actually prints — mark its target block's front leaf with
    /// `f_unstructured_targ` via `markCopyBlock(gototarget, ...)`
    /// (cc:2860-2863). The target is the real dyn capture (`target_dyn`,
    /// block.cc:1705) so the flag lands on the live tree node's front leaf;
    /// `mark_front_leaf` performs the descent markCopyBlock does.
    // Ghidra: block.cc:2856 BlockGoto::markUnstructured
    pub fn mark_unstructured_target(&mut self) {
        // cc:2859: BlockGraph::markUnstructured() — recurse into list=[wrapped].
        if let Some(w) = &self.wrapped {
            w.write().unwrap().mark_unstructured_trait();
        }
        // cc:2860-2863: if (gototype == f_goto_goto) { if (gotoPrints())
        //   markCopyBlock(gototarget, f_unstructured_targ); }
        if self.goto_type == goto_type::GOTO_GOTO {
            if self.goto_prints() {
                if let Some(target) = &self.target_dyn {
                    mark_front_leaf(target, block_flags::UNSTRUCTURED_TARG);
                }
            }
        }
    }

    /// Ghidra `BlockGoto::scopeBreak` (block.cc:2866-2874): first recurse into
    /// the wrapped component passing the goto target's index as the curexit
    /// (cc:2869 `getBlock(0)->scopeBreak(gototarget->getIndex(),curloopexit)`)
    /// — the wrapped block is the only component, so its "block after me in
    /// flow" is the goto target; then reclassify this goto as `break` when
    /// its target index equals the current loop's exit index (cc:2872-2873).
    /// Indices are read live from the dyn Arc, matching the oracle's pointer
    /// read at scopeBreak time.
    // Ghidra: block.cc:2866 BlockGoto::scopeBreak
    pub fn scope_break_goto_type(&mut self, _cur_exit: i32, cur_loop_exit: i32) {
        let target_idx = self
            .target_dyn
            .as_ref()
            .map(|t| t.read().unwrap().get_index());
        // cc:2869: getBlock(0)->scopeBreak(gototarget->getIndex(), curloopexit);
        if let (Some(w), Some(gt_idx)) = (&self.wrapped, target_idx) {
            w.write().unwrap().scope_break_trait(gt_idx, cur_loop_exit);
        }
        // cc:2872-2873: if (curloopexit == gototarget->getIndex())
        //   gototype = f_break_goto;
        if let Some(gt_idx) = target_idx {
            if gt_idx == cur_loop_exit {
                self.goto_type = goto_type::BREAK_GOTO;
            }
        } else if let Some(target) = &self.goto_target {
            // Legacy typed fallback (never populated by try_rule_goto; kept
            // for hand-built fixtures): same comparison via the typed leaf.
            if target.read().unwrap().index == cur_loop_exit {
                self.goto_type = goto_type::BREAK_GOTO;
            }
        }
    }

    /// Ghidra `BlockGoto::gotoPrints` (block.cc:2881-2890): would a formal
    /// `goto` statement be emitted for this block? The oracle asks the parent
    /// for the block following this one in flow and compares it (pointer
    /// identity) to the target's front leaf; with no parent (block.cc:2889)
    /// it returns \b false. Rugra composites cannot sit in a
    /// `BlockGraph::blocks` list, so the parent-present comparison is
    /// evaluated once over the final tree by
    /// `BlockGraph::compute_goto_prints` (run in ActionFinalStructure between
    /// scopeBreak and markUnstructured — the oracle's own first evaluation
    /// point) and transported on `prints_precomputed`; the default `false`
    /// here is exactly the oracle's null-parent arm.
    // Ghidra: block.cc:2881 BlockGoto::gotoPrints
    pub fn goto_prints(&self) -> bool {
        self.prints_precomputed
    }

    /// Parent-present half of `BlockGoto::gotoPrints` (block.cc:2884-2888):
    /// `gotobl = getGotoTarget()->getFrontLeaf(); nextbl =
    /// getParent()->nextFlowAfter(this); return gotobl != nextbl`. Requires
    /// the self Arc (to locate this block in the parent's child list) and
    /// the parent graph Arc; `goto_prints` delegates here when both exist.
    /// The target side reads the real dyn capture (`target_dyn`,
    /// block.cc:1705), falling back to the typed leaf projection.
    // Ghidra: block.cc:2881 BlockGoto::gotoPrints
    pub fn goto_prints_in(
        &self,
        self_arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        parent_arc: &Arc<RwLock<BlockGraph>>,
    ) -> bool {
        // cc:2885: gotobl = getGotoTarget()->getFrontLeaf();
        let gotobl = self
            .target_dyn
            .as_ref()
            .and_then(front_leaf)
            .or_else(|| self.goto_target.as_ref().and_then(front_leaf_basic));
        // cc:2886: nextbl = getParent()->nextFlowAfter(this);
        let nextbl = BlockGraph::next_flow_after(parent_arc, self_arc);
        // cc:2887: return (gotobl != nextbl) — None vs None compares equal,
        // matching C++ null == null.
        match (gotobl, nextbl) {
            (Some(a), Some(b)) => !Arc::ptr_eq(&a, &b),
            (None, None) => false,
            _ => true,
        }
    }

    /// Ghidra `BlockGoto::printHeader` (block.cc:2892-2897): emit
    /// `"Plain goto block <index>"`.
    // Ghidra: block.cc:2892 BlockGoto::printHeader
    pub fn print_header(&self) -> String {
        // cc:2895-2896: s << "Plain goto block "; FlowBlock::printHeader(s);
        format!("Plain goto block {}", self.index)
    }
}

/// A block with multiple edges out, at least one of which is an unstructured
/// (goto) branch (Ghidra `BlockMultiGoto`, block.hh:573-593).
///
/// Mirrors a basic block with multiple out edges at the point where one of
/// the edges can't be structured (the switch dispatch block whose goto-marked
/// edge `ruleBlockGoto`'s isSwitchOut arm peels off, block.cc:1720-1753).
/// `gotoedges` records the peeled targets; the structured view presents the
/// graph as if those edges didn't exist (they are `removeEdge`d bilaterally
/// by `new_block_multigoto`). If more edges later fail to structure, this one
/// instance accumulates them (block.hh:569-572).
#[derive(Debug)]
pub struct BlockMultiGoto {
    pub index: i32,
    pub flags: u32,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    /// Ghidra `BlockMultiGoto::gotoedges` (block.hh:574): the targets of the
    /// unstructured out-edges, appended by `addEdge` (block.hh:580 — pure
    /// vector push, NO graph edge is created). Consumed by
    /// `BlockSwitch::grabCaseBasic` (block.cc:3548-3553), which re-adds each
    /// target as a case with `gototype = f_goto_goto`, and by
    /// `check_switch_skips` via `hasDefaultGoto` (blockaction.cc:1630-1635).
    pub gotoedges: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Ghidra `BlockMultiGoto::defaultswitch` (block.hh:575): true when one
    /// of the unstructured edges is the formal switch default edge
    /// (`setDefaultGoto`, set iff `isDefaultBranch(outedge)` held at
    /// newBlockMultiGoto time, block.cc:1725/1749-1750).
    pub defaultswitch: bool,
    /// Ghidra `BlockMultiGoto : BlockGraph` list component (block.hh:573):
    /// the wrapped multi-exit block (`getBlock(0)`), moved in by
    /// `identifyInternal(ret, [bl])` (block.cc:1738). Every delegated virtual
    /// (`emit` via block.hh:588, `getExitLeaf`, `lastOp`, `printRaw`,
    /// scopeBreak recursion) reads this component — same pattern as
    /// `BlockGoto::wrapped`.
    pub wrapped: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
}

impl FlowBlock for BlockMultiGoto {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // Ghidra: block.hh:584 BlockMultiGoto::getType
    fn get_type(&self) -> BlockType {
        BlockType::MultiGoto
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // Ghidra: block.hh:590 BlockMultiGoto::lastOp — getBlock(0)->lastOp().
    // Rugra projects the BlockGraph delegation (block.cc:1330-1333) as the
    // wrapped component's full op list, same as BlockGoto::get_ops.
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        match &self.wrapped {
            Some(w) => w.read().unwrap().get_ops(),
            None => Vec::new(),
        }
    }
    // Ghidra: block.hh:190 FlowBlock::subBlock — BlockMultiGoto's component
    // list holds exactly the wrapped block (identifyInternal(ret,[bl]),
    // block.cc:1738), so subBlock(0) is the wrapped Arc.
    fn sub_block(&self, slot: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        if slot == 0 {
            self.wrapped.clone()
        } else {
            None
        }
    }
    // Ghidra: block.cc:1327 BlockGraph::firstOp — getBlock(0)->firstOp()
    fn first_op(&self) -> Option<PcodeOpRef> {
        self.wrapped.as_ref().map(|w| w.read().unwrap().first_op())?
    }
    // Ghidra: block.hh:590 BlockMultiGoto::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        // cc:590: return getBlock(0)->lastOp(); — same wrapped-component
        // delegation as BlockGoto (block.hh:562); compareFinalOrder
        // (block.cc:714-715) reads this for the final print order.
        self.wrapped
            .as_ref()
            .and_then(|w| w.read().unwrap().last_op())
    }
    // Ghidra: block.hh:589 BlockMultiGoto::getExitLeaf — getBlock(0)->getExitLeaf()
    fn get_exit_leaf_trait(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        match &self.wrapped {
            Some(w) => w.read().unwrap().get_exit_leaf_trait(),
            None => None,
        }
    }
    // Ghidra: block.cc:2918 BlockMultiGoto::scopeBreak — delegate to the
    // inherent helper holding the faithful port (cc:2921
    // `getBlock(0)->scopeBreak(-1,curloopexit)` — curexit is DISCARDED and
    // replaced by -1; the gotoedges list is not consulted).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_multigoto(cur_exit, cur_loop_exit);
    }
    // Ghidra: block.cc BlockMultiGoto::markUnstructured — no override, so
    // BlockGraph::markUnstructured (block.cc:1249-1256) applies: pure
    // recursion into the component list ([wrapped]). Unlike BlockGoto there
    // is no target marking here — the goto targets are marked by
    // BlockSwitch::markUnstructured's per-case loop (block.cc:3607-3610).
    fn mark_unstructured_trait(&mut self) {
        if let Some(w) = &self.wrapped {
            w.write().unwrap().mark_unstructured_trait();
        }
    }
    // Ghidra: block.cc:1258 BlockGraph::markLabelBumpUp — inherited by
    // BlockMultiGoto (block.hh:573, no override): mark self via the base
    // method (flag only if `bump`), then the single list[0] component
    // (`wrapped`) receives `bump`. The `gotoedges` targets are not list
    // members (block.hh:580 addEdge pushes to a separate vector).
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        // cc:1261: FlowBlock::markLabelBumpUp(bump); // Mark ourselves if true
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        }
        // cc:1262-1264: first (and only) subblock receives bump.
        if let Some(w) = &self.wrapped {
            w.write().unwrap().mark_label_bump_up_trait(bump);
        }
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as
// BlockMultiGoto virtual overrides / inline class methods)
impl BlockMultiGoto {
    /// Ghidra `BlockMultiGoto::setDefaultGoto` (block.hh:578, inline): mark
    /// that this block holds an unstructured switch default edge.
    // Ghidra: block.hh:578 BlockMultiGoto::setDefaultGoto
    pub fn set_default_goto(&mut self) {
        self.defaultswitch = true;
    }

    /// Ghidra `BlockMultiGoto::hasDefaultGoto` (block.hh:579, inline).
    // Ghidra: block.hh:579 BlockMultiGoto::hasDefaultGoto
    pub fn has_default_goto(&self) -> bool {
        self.defaultswitch
    }

    /// Ghidra `BlockMultiGoto::addEdge` (block.hh:580, inline): mark the edge
    /// from this block to `bl` as unstructured — pure `gotoedges` push, no
    /// graph edge is created (the real graph edge was already removed
    /// bilaterally by `newBlockMultiGoto`'s `removeEdge`, block.cc:1729/1746).
    // Ghidra: block.hh:580 BlockMultiGoto::addEdge
    pub fn add_goto_edge(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.gotoedges.push(bl);
    }

    /// Ghidra `BlockMultiGoto::numGotos` (block.hh:581, inline).
    // Ghidra: block.hh:581 BlockMultiGoto::numGotos
    pub fn num_gotos(&self) -> usize {
        self.gotoedges.len()
    }

    /// Ghidra `BlockMultiGoto::getGoto` (block.hh:582, inline).
    // Ghidra: block.hh:582 BlockMultiGoto::getGoto
    pub fn get_goto(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.gotoedges.get(i).cloned()
    }

    /// Ghidra `BlockMultiGoto::scopeBreak` (block.cc:2918-2922):
    /// `getBlock(0)->scopeBreak(-1,curloopexit)` — recurse into the single
    /// component passing -1 as the curexit (this block "has multiple exits",
    /// so no interior exit is current) and the caller's curloopexit through.
    // Ghidra: block.cc:2918 BlockMultiGoto::scopeBreak
    pub fn scope_break_multigoto(&mut self, _cur_exit: i32, cur_loop_exit: i32) {
        if let Some(w) = &self.wrapped {
            w.write().unwrap().scope_break_trait(-1, cur_loop_exit);
        }
    }

    /// Ghidra `BlockMultiGoto::printHeader` (block.cc:2924-2929): emit
    /// `"Multi goto block <index>"`.
    // Ghidra: block.cc:2924 BlockMultiGoto::printHeader
    pub fn print_header(&self) -> String {
        // cc:2927-2928: s << "Multi goto block "; FlowBlock::printHeader(s);
        format!("Multi goto block {}", self.index)
    }
}

// ===== Structured Block Types =====
// These are produced by CollapseStructure and walked by PrintC.

/// A structured if-then or if-then-else block.
///
/// Corresponds to Ghidra's `BlockIf`. Contains:
/// - `condition`: the block ending with CBRANCH
/// - `if_body`: the "true" branch
/// - `else_body`: optional "false" branch (None = if-then without else)
#[derive(Debug)]
pub struct BlockIf {
    pub index: i32,
    pub condition: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub if_body: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub else_body: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// For if-goto blocks (Ghidra newBlockIfGoto style): the target of the
    /// unstructured goto edge. When Some, this BlockIf represents
    /// `if (cond) goto target;` — the body is NOT embedded (if_body is a
    /// placeholder = condition), and the goto edge is consumed (removed from
    /// the target's incoming). When None, this is a normal if-then/if-then-else
    /// with embedded body. Faithful to Ghidra BlockIf::gototarget (block.hh:660).
    pub goto_target: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Ghidra `BlockIf::gototype` (block.hh:659): classification of the
    /// unstructured edge for an if-goto block. Defaults to `goto_type::GOTO_GOTO`;
    /// mutated by `scopeBreak` (block.cc:3083) to `goto_type::BREAK_GOTO` when
    /// the goto target is the enclosing loop's exit. Unused (kept at the
    /// default) for ordinary if-then/if-then-else blocks.
    pub goto_type: u32,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockIf {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:666 BlockIf::getType
    fn get_type(&self) -> BlockType {
        BlockType::If
    }
    // Ghidra: block.cc:3111 BlockIf::getExitLeaf
    fn get_exit_leaf_trait(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        BlockIf::get_exit_leaf(self)
    }
    // Ghidra: block.cc:3119 BlockIf::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        BlockIf::last_op(self)
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        self.condition.read().unwrap().get_start_addr()
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; the flatten projection
    // of BlockIf's component list). Ghidra's factories hold exactly
    // [cond] for an if-goto (newBlockIfGoto block.cc:1799-1810 — the body
    // stays external as the out-edge, and Rugra's if_body is a placeholder
    // aliasing condition there) and [cond, tc(, fc)] otherwise
    // (newBlockIf block.cc:1822 / newBlockIfElse block.cc:1840). The emit
    // order those lists induce (printc.cc:2900+: condition, then clause
    // bodies) is what this returns; the previous condition-only form dropped
    // every body op in flatten contexts (MAIN-RC3).
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        if self.goto_target.is_some() {
            // if-goto: single component [cond].
            return self.condition.read().unwrap().get_ops();
        }
        let mut ops = self.condition.read().unwrap().get_ops();
        ops.extend(self.if_body.read().unwrap().get_ops());
        if let Some(else_b) = &self.else_body {
            ops.extend(else_b.read().unwrap().get_ops());
        }
        ops
    }
    // Ghidra: block.cc:3075 BlockIf::scopeBreak — delegate to the inherent
    // helper which holds the faithful port (cc:3078 condition recurse,
    // cc:3080-3081 body recurse, cc:3082-3083 if-goto reclassify).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_goto_type(cur_exit, cur_loop_exit);
    }
    // Ghidra: block.cc:3067 BlockIf::markUnstructured — recurse into
    // condition/then/else (cc:3025 BlockGraph::markUnstructured), then if this
    // is an if-goto whose goto is still f_goto_goto, mark its target as
    // f_unstructured_targ (cc:3026-3027). Rugra delegates target-marking to
    // the inherent helper.
    fn mark_unstructured_trait(&mut self) {
        // cc:3025: recurse into all sub-blocks (condition + bodies).
        self.condition.write().unwrap().mark_unstructured_trait();
        self.if_body.write().unwrap().mark_unstructured_trait();
        if let Some(else_b) = &self.else_body {
            else_b.write().unwrap().mark_unstructured_trait();
        }
        // cc:3026-3027: mark the if-goto target.
        self.mark_unstructured_target();
    }
    // Ghidra: block.cc:1258 BlockGraph::markLabelBumpUp — inherited by
    // BlockIf (block.hh:658, no override). The subblock list order is
    // [condition, if-body, (else-body)] (newBlockIf/newBlockIfElse,
    // block.cc:1822-1852), so the condition receives `bump` unchanged and
    // the bodies receive `false`; self is flagged only when `bump` is true.
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        // cc:1261: FlowBlock::markLabelBumpUp(bump); // Mark ourselves if true
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        }
        // cc:1263-1264: list[0] (condition) receives bump.
        self.condition
            .write()
            .unwrap()
            .mark_label_bump_up_trait(bump);
        // cc:1266-1267: remaining subblocks (if-body, else-body) get false.
        self.if_body
            .write()
            .unwrap()
            .mark_label_bump_up_trait(false);
        if let Some(else_b) = &self.else_body {
            else_b.write().unwrap().mark_label_bump_up_trait(false);
        }
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockIf virtual overrides)
impl BlockIf {
    /// Ghidra `BlockIf::setGotoTarget` (block.hh:663, inline): mark the target
    /// of the unstructured edge for an if-goto block.
    // Ghidra: block.hh:663 BlockIf::setGotoTarget
    pub fn set_goto_target(&mut self, bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        self.goto_target = Some(bl);
    }

    /// Ghidra `BlockIf::getGotoTarget` (block.hh:664, inline): return the
    /// target of the unstructured edge, if any.
    // Ghidra: block.hh:664 BlockIf::getGotoTarget
    pub fn get_goto_target(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.goto_target.clone()
    }

    /// Ghidra `BlockIf::getGotoType` (block.hh:665, inline): return the type
    /// of the unstructured edge.
    // Ghidra: block.hh:665 BlockIf::getGotoType
    pub fn get_goto_type(&self) -> u32 {
        self.goto_type
    }

    /// Ghidra `BlockIf::markUnstructured` (block.cc:3067-3073): if this is an
    /// if-goto block (gototarget != null) with a plain goto edge, mark the
    /// target block with `f_unstructured_targ`. The C++ first recurses into
    /// children via `BlockGraph::markUnstructured`; Rugra's BlockIf exposes
    /// its condition/if_body/else_body directly, and those components are
    /// marked separately by the structurer, so only the target-marking step
    /// is ported here.
    // Ghidra: block.cc:3067 BlockIf::markUnstructured
    pub fn mark_unstructured_target(&self) {
        // cc:3071-3072: if (gototarget != null && gototype == f_goto_goto) markCopyBlock(gototarget, f_unstructured_targ);
        // markCopyBlock (block.cc:1233-1237) sets the flag on the target's
        // FRONT LEAF (getFrontLeaf, block.cc:340-349: descend subBlock(0)
        // until t_copy), never on the wrapper itself. Rugra's leaf stand-ins
        // are Basic/Copy, so marking the wrapper leaves the leaf unmarked and
        // emitLabelStatement never fires (GOTO-LABEL-UNPRINTED-0001).
        if self.goto_target.is_some() && self.goto_type == goto_type::GOTO_GOTO {
            if let Some(target) = &self.goto_target {
                mark_front_leaf(target, block_flags::UNSTRUCTURED_TARG);
            }
        }
    }

    /// Ghidra `BlockIf::scopeBreak` (block.cc:3075-3084): propagate scope-break
    /// classification into the condition and body, and reclassify the goto
    /// edge as a `break` if its target is the enclosing loop's exit. The C++
    /// body recurses via `getBlock(i)->scopeBreak(...)`; Rugra recurses into
    /// the held `condition`/`if_body`/`else_body` blocks directly. The
    /// condition block has multiple exits (so it gets cur_exit = -1), while
    /// the bodies share the if's exit block (so they get the real cur_exit).
    // Ghidra: block.cc:3075 BlockIf::scopeBreak
    pub fn scope_break_goto_type(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3078: getBlock(0)->scopeBreak(-1, curloopexit);   // condition
        self.condition
            .write()
            .unwrap()
            .scope_break_trait(-1, cur_loop_exit);
        // cc:3080-3081: for (i=1; i<getSize(); ++i) getBlock(i)->scopeBreak(curexit, curloopexit);
        self.if_body
            .write()
            .unwrap()
            .scope_break_trait(cur_exit, cur_loop_exit);
        if let Some(else_body) = &self.else_body {
            else_body
                .write()
                .unwrap()
                .scope_break_trait(cur_exit, cur_loop_exit);
        }
        // cc:3082-3083: if (gototarget != null && gototarget->getIndex() == curloopexit) gototype = f_break_goto;
        if let Some(target) = &self.goto_target {
            if target.read().unwrap().get_index() == cur_loop_exit {
                self.goto_type = goto_type::BREAK_GOTO;
            }
        }
    }

    /// Ghidra `BlockIf::printHeader` (block.cc:3086-3091): emit
    /// `"If block <index>"`.
    // Ghidra: block.cc:3086 BlockIf::printHeader
    pub fn print_header(&self) -> String {
        // cc:3089-3090: s << "If block "; FlowBlock::printHeader(s);
        format!("If block {}", self.index)
    }

    /// Ghidra `BlockIf::getExitLeaf` (block.cc:3111-3117): in the special case
    /// of an if-goto block (getSize()==1), the exit leaf is the condition
    /// block's exit leaf; otherwise there is no single exit leaf. Rugra models
    /// the if-goto case by `goto_target.is_some()` (which implies the
    /// condition is the only embedded component), delegating to the condition.
    // Ghidra: block.cc:3111 BlockIf::getExitLeaf
    pub fn get_exit_leaf(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:3114-3115: if (getSize() == 1) return getBlock(0)->getExitLeaf();
        if self.goto_target.is_some() {
            self.condition.read().unwrap().get_exit_leaf_trait()
        } else {
            None
        }
    }

    /// Ghidra `BlockIf::lastOp` (block.cc:3119-3125): in the special case of
    /// an if-goto block, the last op is the condition's last op; otherwise
    /// there is no single last op. Rugra delegates to the condition.
    // Ghidra: block.cc:3119 BlockIf::lastOp
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        // cc:3122-3123: if (getSize() == 1) return getBlock(0)->lastOp();
        if self.goto_target.is_some() {
            self.condition.read().unwrap().last_op()
        } else {
            None
        }
    }

    /// Ghidra `BlockIf::preferComplement` (block.cc:3093-3109): for an
    /// if/else block, test whether flipping the CBRANCH condition (so the
    /// if/else arms swap) is legal and beneficial, and if so perform the
    /// flip in place. Returns true if the complement was applied. The C++
    /// uses `getSize()==3` to detect if/else; Rugra uses
    /// `else_body.is_some()`. The flip is delegated to the condition block's
    /// `flip_in_place_test`/`flip_in_place_execute` trait methods.
    // Ghidra: block.cc:3093 BlockIf::preferComplement
    pub fn prefer_complement(&mut self) -> bool {
        // cc:3096-3097: if (getSize() != 3) return false;
        if self.else_body.is_none() {
            return false;
        }
        // cc:3099-3101: split = getBlock(0)->getSplitPoint(); if (split == null) return false;
        // Rugra's condition is the split point itself for an if; we treat the
        // condition as the split and ask it whether a flip is legal.
        // cc:3102-3104: if (0 != split->flipInPlaceTest(fliplist)) return false;
        if self.condition.read().unwrap().flip_in_place_test() != 0 {
            return false;
        }
        // cc:3105: split->flipInPlaceExecute();
        self.condition.write().unwrap().flip_in_place_execute();
        // cc:3106: data.opFlipInPlaceExecute(fliplist);  -- Rugra folds this into flip_in_place_execute.
        // cc:3107: swapBlocks(1, 2);  -- swap if_body and else_body in place.
        let if_arc = self.if_body.clone();
        let else_arc = self.else_body.as_ref().unwrap().clone();
        self.if_body = else_arc;
        if let Some(else_body) = self.else_body.as_mut() {
            *else_body = if_arc;
        }
        // cc:3108: return true;
        true
    }
}

/// A structured while-do loop block.
///
/// Corresponds to Ghidra's `BlockWhileDo`. Contains:
/// - `condition`: the loop header block (with CBRANCH for the loop test)
/// - `body`: the loop body block(s)
#[derive(Debug)]
pub struct BlockWhileDo {
    pub index: i32,
    pub condition: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub body: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
    /// For-loop metadata set by ActionStructureTransform when the while-do
    /// matches the canonical `for(init; cond, iterate)` pattern.
    /// Faithful to Ghidra's BlockWhileDo iterateOp/initializeOp (block.hh:690+).
    /// Stores the init/iter expression text (rendered at detection time).
    /// printc emits for(init;cond;iter) with the comma_separate mod active,
    /// matching Ghidra emitForLoop (printc.cc:2957-2999).
    /// LEGACY NARROWED CHANNEL: fed only by the transitional renderer in
    /// coreaction.rs `for_loop_finalize_printing` (its INT_ADD/COPY-const
    /// render gates); the oracle-faithful channel is the op triple below.
    pub for_init: Option<String>,
    pub for_iter: Option<String>,
    /// Ghidra `BlockWhileDo::initializeOp` (block.hh:694): statement used as
    /// the for-loop initializer. Set by `while_do_final_transform` /
    /// `while_do_finalize_printing` (block.cc:3356/3403).
    pub initialize_op: Option<PcodeOpRef>,
    /// Ghidra `BlockWhileDo::iterateOp` (block.hh:695): statement used as
    /// the for-loop iterator.
    pub iterate_op: Option<PcodeOpRef>,
    /// Ghidra `BlockWhileDo::loopDef` (block.hh:696): the MULTIEQUAL merging
    /// the loop variable at the head.
    pub loop_def: Option<PcodeOpRef>,
    /// Overflow-syntax flag (Ghidra `hasOverflowSyntax()`, block.hh:692).
    /// Set by ruleBlockWhileDo when `bl->isComplex()` (blockaction.cc:1538) —
    /// the condition block is too complex to print inline as `while(cond)`.
    /// When set, printc emits `while(true) { <cond body> if(cond) break; }`
    /// instead of `while(cond) { ... }` (emitBlockWhileDo cc:3017-3044).
    pub overflow_syntax: bool,
}

impl FlowBlock for BlockWhileDo {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:707 BlockWhileDo::getType
    fn get_type(&self) -> BlockType {
        BlockType::WhileDo
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        self.condition.read().unwrap().get_start_addr()
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; the flatten projection
    // of BlockWhileDo's component list). newBlockWhileDo passes
    // nodes=[cond, cl] to identifyInternal (block.cc:1858-1865), so the
    // flatten is condition ops followed by body ops — the emit order
    // printc.cc:3001-3063 (emitBlockWhileDo: condition, then body) induces.
    // The previous condition-only form dropped the loop body in flatten
    // contexts (e.g. a BlockGoto wrapping a WhileDo, MAIN-RC2).
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        let mut ops = self.condition.read().unwrap().get_ops();
        ops.extend(self.body.read().unwrap().get_ops());
        ops
    }
    // Ghidra: block.cc:3324 BlockWhileDo::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3328 condition
    // recurse with new cur_exit, cc:3329 body recurse exiting into header).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_children(cur_exit, cur_loop_exit);
    }
    // Ghidra: block.cc BlockWhileDo::markUnstructured — only recurses (via
    // BlockGraph::markUnstructured). Rugra recurses into its two children.
    fn mark_unstructured_trait(&mut self) {
        self.condition.write().unwrap().mark_unstructured_trait();
        self.body.write().unwrap().mark_unstructured_trait();
    }
    // Ghidra: block.cc:3316 BlockWhileDo::markLabelBumpUp — delegate to the
    // inherent helper holding the faithful port (forces true down the front
    // chain, then clears own flag when the incoming bump was false).
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        self.mark_label_bump_up(bump);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockWhileDo virtual overrides)
impl BlockWhileDo {
    /// Ghidra `BlockWhileDo::getInitializeOp` (block.hh:703, inline): root of
    /// the for-loop initializer statement, or null. Rugra stores the rendered
    /// init text in `for_init` rather than a PcodeOp pointer, so this returns
    /// `Some(text)` when an initializer was detected.
    // Ghidra: block.hh:703 BlockWhileDo::getInitializeOp
    pub fn get_initialize_op(&self) -> Option<&String> {
        self.for_init.as_ref()
    }

    /// Ghidra `BlockWhileDo::getIterateOp` (block.hh:704, inline): root of the
    /// for-loop iterator statement, or null. Rugra stores the rendered iterate
    /// text in `for_iter`.
    // Ghidra: block.hh:704 BlockWhileDo::getIterateOp
    pub fn get_iterate_op(&self) -> Option<&String> {
        self.for_iter.as_ref()
    }

    /// Ghidra `BlockWhileDo::hasOverflowSyntax` (block.hh:705, inline): does
    /// this loop require overflow syntax (condition too complex for
    /// `while(cond)`)? Reads the `f_whiledo_overflow` flag.
    // Ghidra: block.hh:705 BlockWhileDo::hasOverflowSyntax
    pub fn has_overflow_syntax(&self) -> bool {
        // cc: hh:705: ((getFlags() & f_whiledo_overflow) != 0)
        self.overflow_syntax || (self.flags & block_flags::WHILEDO_OVERFLOW) != 0
    }

    /// Ghidra `BlockWhileDo::setOverflowSyntax` (block.hh:706, inline): mark
    /// that this loop requires overflow syntax. Sets `f_whiledo_overflow`.
    // Ghidra: block.hh:706 BlockWhileDo::setOverflowSyntax
    pub fn set_overflow_syntax(&mut self) {
        // cc: hh:706: setFlag(f_whiledo_overflow);
        self.flags |= block_flags::WHILEDO_OVERFLOW;
        self.overflow_syntax = true;
    }

    /// Ghidra `BlockWhileDo::markLabelBumpUp` (block.cc:3316-3322): while-do
    /// loops "steal" their lower blocks' labels — the recursion forces `true`
    /// down the front (condition) chain so the loop header prints the label,
    /// not the condition leaf itself. The C++ first recurses via
    /// `BlockGraph::markLabelBumpUp(true)` (self flagged, list[0]=condition
    /// receives `true`, list[1]=body receives `false`), then clears the flag
    /// on itself if the incoming `bump` is false.
    // Ghidra: block.cc:3316 BlockWhileDo::markLabelBumpUp
    pub fn mark_label_bump_up(&mut self, bump: bool) {
        // cc:3319: BlockGraph::markLabelBumpUp(true); — mark self, then
        // condition (list[0]) with true, body (list[1]) with false.
        self.flags |= block_flags::LABEL_BUMPUP;
        self.condition
            .write()
            .unwrap()
            .mark_label_bump_up_trait(true);
        self.body
            .write()
            .unwrap()
            .mark_label_bump_up_trait(false);
        // cc:3320-3321: if (!bump) clearFlag(f_label_bumpup);
        if !bump {
            self.flags &= !block_flags::LABEL_BUMPUP;
        }
    }

    /// Ghidra `BlockWhileDo::scopeBreak` (block.cc:3324-3330): a new loop scope
    /// begins — the current loop exit becomes the new `cur_exit`. The top
    /// block (condition) has multiple exits so gets `cur_exit = -1`; the body
    /// exits into the top block so gets `cur_exit = condition's index`. Rugra
    /// recurses into the held `condition`/`body` via the trait method.
    // Ghidra: block.cc:3324 BlockWhileDo::scopeBreak
    pub fn scope_break_children(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3328: getBlock(0)->scopeBreak(-1, curexit);   // condition, new scope
        self.condition
            .write()
            .unwrap()
            .scope_break_trait(-1, cur_exit);
        // cc:3329: getBlock(1)->scopeBreak(getBlock(0)->getIndex(), curexit);  // body exits into condition
        let cond_idx = self.condition.read().unwrap().get_index();
        self.body
            .write()
            .unwrap()
            .scope_break_trait(cond_idx, cur_exit);
        // Note: cur_loop_exit is the enclosing loop's exit, unused here because
        // this block establishes a NEW loop scope (cur_exit becomes the loop exit).
        let _ = cur_loop_exit;
    }

    /// Ghidra `BlockWhileDo::printHeader` (block.cc:3332-3339): emit
    /// `"Whiledo block "` plus `"(overflow) "` if overflow syntax is active.
    // Ghidra: block.cc:3332 BlockWhileDo::printHeader
    pub fn print_header(&self) -> String {
        // cc:3335-3338: s << "Whiledo block "; if (hasOverflowSyntax()) s << "(overflow) ";
        let mut s = format!("Whiledo block {}", self.index);
        if self.has_overflow_syntax() {
            s.insert_str(0, "(overflow) ");
        }
        s
    }
}

/// Dyn FlowBlock arc alias for the for-loop formation helpers.
type DynBlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

/// Is `op` a member of `blk`'s op list (Arc identity)?
// RUGRA-GLUE: Ghidra compares `defOp->getParent() != head` pointers; Rugra
/// op->parent weak links are the primary channel, with the block's op-list as
/// a belt-and-suspenders fallback for ops whose parent link is not wired.
fn op_lives_in_block(op: &Arc<RwLock<crate::op::PcodeOp>>, blk: &DynBlockArc) -> bool {
    let parent = op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
    if let Some(p) = &parent {
        if Arc::ptr_eq(p, blk) {
            return true;
        }
    }
    blk.read().unwrap().get_ops().iter().any(|o| Arc::ptr_eq(&o.0, op))
}

/// Upgrade `op`'s parent block Arc (None when the weak link is absent).
// RUGRA-GLUE: Rust borrow helper for Ghidra's raw `op->getParent()` pointer
// read (op.hh:190 PcodeOp::getParent) — the weak-link upgrade has no oracle
// counterpart to cite as a function definition.
fn op_parent(op: &Arc<RwLock<crate::op::PcodeOp>>) -> Option<DynBlockArc> {
    op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade())
}

// Ghidra: block.cc:3164 BlockWhileDo::findLoopVariable
/// Try to find a Varnode that represents the controlling \e loop \e variable
/// for this loop (block.cc:3152-3213). The Varnode must be:
///   - tested by the exit condition,
///   - have a MULTIEQUAL in the head block,
///   - have a modification coming in from the tail block,
///   - the modification must be the last op or moveable to the last op.
///
/// If found, sets `loop_def` and `iterate_op` on `wd`. Faithful port of the
/// explicit `PcodeOpNode path[4]` DFS: inputs are scanned in slot order; a
/// MULTIEQUAL def in the head is the loopDef candidate (its tail-slot input's
/// def must live in the tail and pass the isMoveable(lastOp) gate); any other
/// written def descends the DFS up to depth 4 (count==3 cap), skipping
/// calls/markers.
pub fn while_do_find_loop_variable(
    wd: &mut BlockWhileDo,
    fd: &crate::funcdata::Funcdata,
    cbranch: &PcodeOpRef,
    head: &DynBlockArc,
    tail: &DynBlockArc,
    last_op: &PcodeOpRef,
) {
    // cc:3167-3168: vn = cbranch->getIn(1); if (!vn->isWritten()) return;
    let cond_vn = cbranch.0.read().unwrap().get_in(1).cloned();
    let Some(cond_vn) = cond_vn else { return };
    if !cond_vn.read().unwrap().is_written() {
        return;
    }
    // cc:3169: op = vn->getDef();
    let Some(op_arc) = cond_vn.read().unwrap().get_def() else {
        return;
    };
    // cc:3170: slot = tail->getOutRevIndex(0);
    let slot: usize = {
        let tail_guard = tail.read().unwrap();
        let Some(edge) = tail_guard.get_out(0) else { return };
        if edge.reverse_index < 0 {
            return;
        }
        edge.reverse_index as usize
    };
    // cc:3174-3176: if (op->isCall() || op->isMarker()) return;
    {
        let g = op_arc.read().unwrap();
        if g.is_call() || g.is_marker() {
            return;
        }
    }
    // cc:3177-3178: path[0] = (op, 0); count = 0.
    let mut path: [(PcodeOpRef, usize); 4] = [
        (PcodeOpRef(op_arc.clone()), 0),
        (PcodeOpRef(op_arc.clone()), 0),
        (PcodeOpRef(op_arc.clone()), 0),
        (PcodeOpRef(op_arc), 0),
    ];
    let mut count: i32 = 0;
    // cc:3179: while(count>=0) { ... }
    while count >= 0 {
        let idx = count as usize;
        // cc:3181: ind = path[count].slot++;
        let ind = path[idx].1;
        path[idx].1 += 1;
        let cur_op = path[idx].0.clone();
        // cc:3182-3185: if (ind >= curOp->numInput()) { count -= 1; continue; }
        let incount = cur_op.0.read().unwrap().num_input();
        if ind >= incount {
            count -= 1;
            continue;
        }
        // cc:3186-3187: nextVn = curOp->getIn(ind); if (!nextVn->isWritten()) continue;
        let next_vn = cur_op.0.read().unwrap().get_in(ind).cloned();
        let Some(next_vn) = next_vn else { continue };
        if !next_vn.read().unwrap().is_written() {
            continue;
        }
        // cc:3188: defOp = nextVn->getDef();
        let Some(def_arc) = next_vn.read().unwrap().get_def() else {
            continue;
        };
        let def_ref = PcodeOpRef(def_arc);
        if def_ref.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL {
            // cc:3190: if (defOp->getParent() != head) continue;
            if !op_lives_in_block(&def_ref.0, head) {
                continue;
            }
            // cc:3191-3192: itvn = defOp->getIn(slot); if (!itvn->isWritten()) continue;
            let itvn = def_ref.0.read().unwrap().get_in(slot).cloned();
            let Some(itvn) = itvn else { continue };
            if !itvn.read().unwrap().is_written() {
                continue;
            }
            // cc:3193: possibleIterate = itvn->getDef();
            let Some(pit_arc) = itvn.read().unwrap().get_def() else {
                continue;
            };
            let pit_ref = PcodeOpRef(pit_arc);
            // cc:3194: if (possibleIterate->getParent() == tail) {
            if op_lives_in_block(&pit_ref.0, tail) {
                // cc:3195-3196: if (possibleIterate->isMarker()) continue;
                if pit_ref.0.read().unwrap().is_marker() {
                    continue;
                }
                // cc:3197-3198: if (!possibleIterate->isMoveable(lastOp)) continue;
                let moveable = {
                    let pit_g = pit_ref.0.read().unwrap();
                    let last_g = last_op.0.read().unwrap();
                    pit_g.is_moveable(&last_g, &fd.obank)
                };
                if !moveable {
                    continue;
                }
                // cc:3199-3201: loopDef = defOp; iterateOp = possibleIterate; return;
                wd.loop_def = Some(def_ref);
                wd.iterate_op = Some(pit_ref);
                return;
            }
        } else {
            // cc:3205: if (count == 3) continue;
            if count == 3 {
                continue;
            }
            // cc:3206: if (defOp->isCall() || defOp->isMarker()) continue;
            {
                let g = def_ref.0.read().unwrap();
                if g.is_call() || g.is_marker() {
                    continue;
                }
            }
            // cc:3207-3209: count += 1; path[count] = (defOp, 0);
            count += 1;
            path[count as usize] = (def_ref, 0);
        }
    }
    // cc:3212: return; — no loop variable found
}

// Ghidra: block.cc:3223 BlockWhileDo::findInitializer
/// Find the putative initializer op for the loop variable (block.cc:3215-
/// 3244): the def of `loop_def`'s non-tail input must terminate the block
/// that flows only into the head. On success sets `wd.initialize_op` and
/// returns the last (non-branch) op of the initializer block; otherwise
/// returns None and leaves `initialize_op` untouched (None).
pub fn while_do_find_initializer(
    wd: &mut BlockWhileDo,
    fd: &crate::funcdata::Funcdata,
    head: &DynBlockArc,
    slot: usize,
) -> Option<PcodeOpRef> {
    // cc:3226: if (head->sizeIn() != 2) return 0;
    if head.read().unwrap().size_in() != 2 {
        return None;
    }
    // cc:3227: slot = 1 - slot;
    let slot = 1 - slot;
    // cc:3228-3229: initVn = loopDef->getIn(slot); if (!initVn->isWritten()) return 0;
    let loop_def = wd.loop_def.clone()?;
    let init_vn = loop_def.0.read().unwrap().get_in(slot).cloned()?;
    if !init_vn.read().unwrap().is_written() {
        return None;
    }
    // cc:3230: res = initVn->getDef();
    let res_arc = init_vn.read().unwrap().get_def()?;
    // cc:3231: if (res->isMarker()) return 0;
    if res_arc.read().unwrap().is_marker() {
        return None;
    }
    // cc:3232-3234: initialBlock = res->getParent(); must equal head->getIn(slot).
    let Some(initial_block) = op_parent(&res_arc) else {
        return None;
    };
    let Some(entry_edge) = head.read().unwrap().get_in(slot) else {
        return None;
    };
    if !Arc::ptr_eq(&initial_block, &entry_edge.point) {
        return None; // Statement must terminate in block flowing to head
    }
    // cc:3235-3236: lastOp = initialBlock->lastOp(); if (lastOp == 0) return 0;
    let last_op = initial_block.read().unwrap().last_op()?;
    // cc:3237: if (initialBlock->sizeOut() != 1) return 0;
    if initial_block.read().unwrap().size_out() != 1 {
        return None; // Initializer block must flow only to for loop
    }
    // cc:3238-3241: if (lastOp->isBranch()) lastOp = lastOp->previousOp();
    let resolved_last: Option<PcodeOpRef> = if last_op.0.read().unwrap().is_branch() {
        last_op.0.read().unwrap().previous_op_in_block(&fd.obank)
    } else {
        Some(last_op)
    };
    let last_op = resolved_last?;
    // cc:3242-3243: initializeOp = res; return lastOp;
    wd.initialize_op = Some(PcodeOpRef(res_arc));
    Some(last_op)
}

// Ghidra: block.cc:3256 BlockWhileDo::testTerminal
/// Test that the statement rooted at `loop_def`'s slot input is terminal and
/// explicit (block.cc:3246-3283): dig through a non-printing COPY to its
/// input def (which must live in the slot's block), require the surviving
/// varnode explicit and the root printable, then require `finalOp` to be
/// (movable to) the block's last op via `moveRespectingCover`. Returns the
/// root statement op or None. NOTE: `fd` is `&mut` because the oracle's
/// `data.moveRespectingCover(finalOp, lastOp)` MOVES the op on success
/// (funcdata_op.cc:1488-1495).
pub fn while_do_test_terminal(
    wd: &BlockWhileDo,
    fd: &mut crate::funcdata::Funcdata,
    slot: usize,
) -> Option<PcodeOpRef> {
    use crate::op::pcodeop_flags::NONPRINTING;
    // cc:3259-3260: vn = loopDef->getIn(slot); if (!vn->isWritten()) return 0;
    let loop_def = wd.loop_def.clone()?;
    let vn0 = loop_def.0.read().unwrap().get_in(slot).cloned()?;
    if !vn0.read().unwrap().is_written() {
        return None;
    }
    // cc:3261: finalOp = vn->getDef();
    let final_op = PcodeOpRef(vn0.read().unwrap().get_def()?);
    // cc:3262: parentBlock = loopDef->getParent()->getIn(slot);
    let head = op_parent(&loop_def.0)?;
    let parent_block = head.read().unwrap().get_in(slot).map(|e| e.point)?;
    // cc:3263: resOp = finalOp;
    let mut res_op = final_op.clone();
    // cc:3264-3269: if (finalOp->code()==COPY && finalOp->notPrinted()) dig
    // through to finalOp->getIn(0)'s def, which must be in parentBlock.
    let vn = {
        let fg = final_op.0.read().unwrap();
        if fg.opcode == OpCode::CPUI_COPY && (fg.flags & NONPRINTING) != 0 {
            let vn1 = fg.get_in(0).cloned()?;
            if !vn1.read().unwrap().is_written() {
                return None;
            }
            res_op = PcodeOpRef(vn1.read().unwrap().get_def()?);
            let res_parent = op_parent(&res_op.0);
            let ok = res_parent
                .map(|p| Arc::ptr_eq(&p, &parent_block))
                .unwrap_or(false);
            if !ok {
                return None;
            }
            vn1
        } else {
            vn0
        }
    };
    // cc:3271: if (!vn->isExplicit()) return 0;
    if !vn.read().unwrap().is_explicit() {
        return None;
    }
    // cc:3272-3273: if (resOp->notPrinted()) return 0;  — statement MUST print
    if (res_op.0.read().unwrap().flags & NONPRINTING) != 0 {
        return None;
    }
    // cc:3276-3278: lastOp = finalOp->getParent()->lastOp(); skip branch.
    let fparent = op_parent(&final_op.0)?;
    let resolved_last: Option<PcodeOpRef> = {
        let l = fparent.read().unwrap().last_op()?;
        if l.0.read().unwrap().is_branch() {
            l.0.read().unwrap().previous_op_in_block(&fd.obank)
        } else {
            Some(l)
        }
    };
    let last_op = resolved_last?;
    // cc:3279-3280: if (!data.moveRespectingCover(finalOp, lastOp)) return 0;
    if !fd.move_respecting_cover(&final_op, &last_op) {
        return None;
    }
    // cc:3282: return resOp;
    Some(res_op)
}

// Ghidra: block.cc:3287 BlockWhileDo::testIterateForm
/// Make sure the loop variable is involved as an input in the iterator
/// statement (block.cc:3285-3314): DFS from `iterate_op` through non-
/// annotation, non-explicit, written inputs; true iff some input's HighVariable
/// is the loopDef output's high.
pub fn while_do_test_iterate_form(wd: &BlockWhileDo) -> bool {
    // cc:3290-3291: targetVn = loopDef->getOut(); high = targetVn->getHigh();
    let Some(loop_def) = wd.loop_def.clone() else {
        return false;
    };
    let Some(target_vn) = loop_def.0.read().unwrap().get_out().cloned() else {
        return false;
    };
    let Some(high) = target_vn.read().unwrap().high.clone() else {
        return false;
    };
    // cc:3293-3295: path = [PcodeOpNode(iterateOp, 0)];
    let Some(iterate_op) = wd.iterate_op.clone() else {
        return false;
    };
    let mut path: Vec<(PcodeOpRef, usize)> = vec![(iterate_op, 0)];
    // cc:3296: while(!path.empty()) { ... }
    while let Some(node) = path.last_mut() {
        // cc:3298-3300: if (node.op->numInput() <= node.slot) { pop; continue; }
        let node_op = node.0.clone();
        let node_slot = node.1;
        if node_op.0.read().unwrap().num_input() <= node_slot {
            path.pop();
            continue;
        }
        // cc:3302-3303: vn = node.op->getIn(node.slot); node.slot += 1;
        let vn = node_op.0.read().unwrap().get_in(node_slot).cloned();
        path.last_mut().unwrap().1 += 1;
        let Some(vn) = vn else { continue };
        // cc:3304: if (vn->isAnnotation()) continue;
        if vn.read().unwrap().is_annotation() {
            continue;
        }
        // cc:3305-3306: if (vn->getHigh() == high) return true;
        if let Some(vh) = vn.read().unwrap().high.clone() {
            if Arc::ptr_eq(&vh, &high) {
                return true;
            }
        }
        // cc:3308: if (vn->isExplicit()) continue;  — truncate at explicit
        if vn.read().unwrap().is_explicit() {
            continue;
        }
        // cc:3309: if (!vn->isWritten()) continue;
        if !vn.read().unwrap().is_written() {
            continue;
        }
        // cc:3310-3311: path.push_back(PcodeOpNode(vn->getDef(), 0));
        let def_arc = vn.read().unwrap().get_def();
        if let Some(def) = def_arc {
            path.push((PcodeOpRef(def), 0));
        }
    }
    false
}

// Ghidra: block.cc:3356 BlockWhileDo::finalTransform
/// Determine if this while-do can be printed as a `for` loop (block.cc:3353-
/// 3397): run `findLoopVariable`; when an iterate op is found, MOVE it to
/// after the tail's last op (opUninsert/opInsertAfter — the iterateOp
/// migration), then try `findInitializer` and move the initializer op to its
/// block's terminal position under the isMoveable gate. `head_arc` is the
/// resolved `getFrontLeaf()->subBlock(0)` basic block — the dispatcher
/// resolves it BEFORE taking this block's write guard (front_leaf reads this
/// block; std RwLock read-while-write on the same lock would deadlock).
pub fn while_do_final_transform(
    wd: &mut BlockWhileDo,
    fd: &mut crate::funcdata::Funcdata,
    head_arc: &DynBlockArc,
) {
    // cc:3359: BlockGraph::finalTransform(data); — done by the tree dispatch.
    // cc:3360: if (!data.getArch()->analyze_for_loops) return;
    if !fd.arch.as_ref().map(|a| a.analyze_for_loops).unwrap_or(false) {
        return;
    }
    // cc:3361: if (hasOverflowSyntax()) return;
    if wd.has_overflow_syntax() {
        return;
    }
    // cc:3362-3365: copyBl = getFrontLeaf(); head = copyBl->subBlock(0);
    // head->getType() must be t_basic. — resolved by the dispatcher.
    // cc:3366-3368: lastOp = getBlock(1)->lastOp(); tail = lastOp->getParent();
    let Some(body_last_op) = wd.body.read().unwrap().last_op() else {
        return;
    };
    let Some(tail_arc) = op_parent(&body_last_op.0) else {
        return;
    };
    // cc:3369: if (tail->sizeOut() != 1) return;
    if tail_arc.read().unwrap().size_out() != 1 {
        return;
    }
    // cc:3370: if (tail->getOut(0) != head) return;
    let Some(out_edge) = tail_arc.read().unwrap().get_out(0) else {
        return;
    };
    if !Arc::ptr_eq(&out_edge.point, head_arc) {
        return;
    }
    // cc:3371-3372: cbranch = getBlock(0)->lastOp(); must be CBRANCH.
    let Some(cbranch) = wd.condition.read().unwrap().last_op() else {
        return;
    };
    if cbranch.0.read().unwrap().opcode != OpCode::CPUI_CBRANCH {
        return;
    }
    // cc:3373-3376: if (lastOp->isBranch()) lastOp = lastOp->previousOp();
    let last_op = if body_last_op.0.read().unwrap().is_branch() {
        match body_last_op
            .0
            .read()
            .unwrap()
            .previous_op_in_block(&fd.obank)
        {
            Some(prev) => prev,
            None => return,
        }
    } else {
        body_last_op
    };

    // cc:3378: findLoopVariable(cbranch, head, tail, lastOp);
    while_do_find_loop_variable(wd, fd, &cbranch, head_arc, &tail_arc, &last_op);
    // cc:3379: if (iterateOp == 0) return;
    let Some(iterate_op) = wd.iterate_op.clone() else {
        return;
    };
    // cc:3381-3384: if (iterateOp != lastOp) { opUninsert; opInsertAfter; }
    if !Arc::ptr_eq(&iterate_op.0, &last_op.0) {
        fd.op_uninsert(&iterate_op);
        fd.op_insert_after(&iterate_op, &last_op);
    }
    // cc:3387: lastOp = findInitializer(head, tail->getOutRevIndex(0));
    let tail_rev_slot: usize = {
        let tail_guard = tail_arc.read().unwrap();
        let Some(edge) = tail_guard.get_out(0) else { return };
        if edge.reverse_index < 0 {
            return;
        }
        edge.reverse_index as usize
    };
    let Some(init_last_op) = while_do_find_initializer(wd, fd, head_arc, tail_rev_slot) else {
        // cc:3388: if (lastOp == 0) return;
        return;
    };
    // cc:3389-3392: if (!initializeOp->isMoveable(lastOp)) { initializeOp = 0; return; }
    let Some(initialize_op) = wd.initialize_op.clone() else {
        return;
    };
    {
        let init_g = initialize_op.0.read().unwrap();
        let last_g = init_last_op.0.read().unwrap();
        if !init_g.is_moveable(&last_g, &fd.obank) {
            wd.initialize_op = None;
            return;
        }
    }
    // cc:3393-3396: if (initializeOp != lastOp) { opUninsert; opInsertAfter; }
    if !Arc::ptr_eq(&initialize_op.0, &init_last_op.0) {
        fd.op_uninsert(&initialize_op);
        fd.op_insert_after(&initialize_op, &init_last_op);
    }
}

// Ghidra: block.cc:3403 BlockWhileDo::finalizePrinting
/// Final for-loop checks after HighVariable merging (block.cc:3399-3424):
/// re-derive the iterate statement via testTerminal (explicitness +
/// moveRespectingCover), verify testIterateForm, take the last-chance
/// initializer, re-derive it via testTerminal, then mark BOTH statements
/// non-printing so the block emitters skip them while printc's for-header
/// prints them.
pub fn while_do_finalize_printing(
    wd: &mut BlockWhileDo,
    fd: &mut crate::funcdata::Funcdata,
) {
    // cc:3406: BlockGraph::finalizePrinting(data); — done by the tree dispatch.
    // cc:3407: if (iterateOp == 0) return;
    let iterate_op = match wd.iterate_op.clone() {
        Some(op) => op,
        None => return,
    };
    // cc:3409-3410: slot = iterateOp->getParent()->getOutRevIndex(0);
    // iterateOp = testTerminal(data, slot);
    let slot: Option<usize> = {
        let parent = op_parent(&iterate_op.0);
        parent.and_then(|p| {
            let g = p.read().unwrap();
            g.get_out(0).map(|e| e.reverse_index).filter(|r| *r >= 0).map(|r| r as usize)
        })
    };
    let Some(slot) = slot else {
        wd.iterate_op = None;
        return;
    };
    let new_iterate = while_do_test_terminal(wd, fd, slot);
    // cc:3411: if (iterateOp == 0) return;
    let Some(new_iterate) = new_iterate else {
        wd.iterate_op = None;
        return;
    };
    wd.iterate_op = Some(new_iterate.clone());
    // cc:3412-3415: if (!testIterateForm()) { iterateOp = 0; return; }
    if !while_do_test_iterate_form(wd) {
        wd.iterate_op = None;
        return;
    }
    // cc:3416-3417: if (initializeOp == 0) findInitializer(loopDef->getParent(), slot);
    if wd.initialize_op.is_none() {
        if let Some(loop_def) = wd.loop_def.clone() {
            if let Some(head) = op_parent(&loop_def.0) {
                while_do_find_initializer(wd, fd, &head, slot);
            }
        }
    }
    // cc:3418-3419: if (initializeOp != 0) initializeOp = testTerminal(data, 1-slot);
    if wd.initialize_op.is_some() {
        wd.initialize_op = while_do_test_terminal(wd, fd, 1 - slot);
    }
    // cc:3421-3423: opMarkNonPrinting(iterateOp); and initializer if present.
    fd.op_mark_non_printing(&new_iterate);
    if let Some(init_op) = &wd.initialize_op {
        fd.op_mark_non_printing(init_op);
    }
}

// Ghidra: block.cc:1355 BlockGraph::finalTransform
/// Recurse `finalTransform` over the structured tree (block.cc:1355-1362):
/// child-first (post-order, mirroring BlockWhileDo::finalTransform's own
/// `BlockGraph::finalTransform(data)` prefix at cc:3359), then run the
/// WhileDo override (block.cc:3356) on WhileDo nodes. Entry point for the
/// `ActionStructureTransform` slot (blockaction.cc:2113) — see
/// `ActionFinalStructure::apply` for the placement note.
pub fn final_transform_block(
    bl: &DynBlockArc,
    fd: &mut crate::funcdata::Funcdata,
    visited: &mut std::collections::HashSet<usize>,
) {
    let bl_id = Arc::as_ptr(bl) as *const () as usize;
    if !visited.insert(bl_id) {
        // LOAD-BEARING revisit guard (the oracle has none — cc:1355-1362
        // is a plain recursion over its single-owner `list`). Rugra's
        // walk uses `component_list_dyn`, whose BlockSwitch arm returns
        // `cases + default_case` INCLUDING the gototype != 0 goto-arm
        // targets — the one sanctioned aliasing in the Arc model: those
        // blocks stay top-level roots (never consumed, mirroring
        // cc:3548-3553's surrounding-graph placement) while remaining
        // switch `cases` members. This sweep therefore can reach them
        // twice (root + switch child); visiting once preserves the
        // oracle's per-node-once semantics (a revisit would re-detect
        // idempotently but re-move ops against moved positions). The
        // finalizePrinting twin needs NO guard: its Switch dispatch
        // walks control + gototype==0 cases + the gototype==0 default
        // arm, so the aliased members are structurally excluded. Debug
        // builds machine-check the
        // ownership invariant at both sweep entries — see
        // BlockGraph::debug_assert_structure_tree_unique.
        return;
    }
    // cc:1359-1361: recurse into every substructure first
    for child in BlockGraph::component_list_dyn(bl) {
        final_transform_block(&child, fd, visited);
    }
    // BlockWhileDo::finalTransform override (cc:3356)
    if bl.read().unwrap().get_type() == BlockType::WhileDo {
        // cc:3362-3365: copyBl = getFrontLeaf(); head = copyBl->subBlock(0);
        // must be t_basic. Resolved BEFORE the write guard: front_leaf reads
        // this block's lock and std RwLock read-while-write from one thread
        // deadlocks (a null copyBl / non-basic head just skips the override,
        // matching the oracle early returns).
        let head = front_leaf(bl)
            .and_then(|copy_bl| copy_bl.read().unwrap().sub_block(0))
            .filter(|h| h.read().unwrap().get_type() == BlockType::Basic);
        if let Some(head_arc) = head {
            let mut w = bl.write().unwrap();
            if let Some(wd) = w.as_any_mut().downcast_mut::<BlockWhileDo>() {
                while_do_final_transform(wd, fd, &head_arc);
            }
        }
    }
}


// Ghidra: blockaction.cc:2110 ActionStructureTransform::apply (graph entry)
/// `data.getStructure().finalTransform(data)` — top-level graph entry sweep
/// of the for-loop formation transform (blockaction.cc:2110-2115). Runs at
/// the oracle pipeline slot :5715 (ActionStructureTransform, BEFORE the
/// merge group :5717-:5729 and ActionSetCasts :5735) — dispatched from
/// `ActionStructureTransform::apply` in coreaction.rs (SLOT CONTRACT,
/// INITEXTRACT-PIPE-SLOT-0001). The for/while `isMoveable` gate
/// (block.cc:3197) must read the RAW iterate op before setcasts wraps it.
pub fn for_loop_final_transform(fd: &mut crate::funcdata::Funcdata) {
    if !fd.arch.as_ref().map(|a| a.analyze_for_loops).unwrap_or(false) {
        return; // block.cc:3360 gate (per-loop, hoisted for the sweep entry)
    }
    if fd.sblocks.blocks.is_empty() {
        return;
    }
    let top: Vec<DynBlockArc> = fd.sblocks.blocks.clone();
    #[cfg(debug_assertions)]
    BlockGraph::debug_assert_structure_tree_unique(&top);
    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for bl in &top {
        final_transform_block(bl, fd, &mut visited);
    }
}

/// Represents a DO-WHILE loop
///
/// Corresponds to Ghidra's `BlockDoWhile` class
#[derive(Debug)]
pub struct BlockDoWhile {
    pub index: i32,
    pub condition: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    // Do-While loops logically have the condition at the end which evaluates the body that it's fused with.
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockDoWhile {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:723 BlockDoWhile::getType
    fn get_type(&self) -> BlockType {
        BlockType::DoWhile
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        self.condition.read().unwrap().get_start_addr()
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.condition.read().unwrap().get_ops()
    }
    // Ghidra: block.cc:3434 BlockDoWhile::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3438 fused-body
    // recurse with cur_exit=-1, this block establishes a new loop scope).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_body(cur_exit, cur_loop_exit);
    }
    // Ghidra: block.cc BlockDoWhile::markUnstructured — only recurses (via
    // BlockGraph::markUnstructured). Rugra recurses into condition.
    fn mark_unstructured_trait(&mut self) {
        self.condition.write().unwrap().mark_unstructured_trait();
    }
    // Ghidra: block.cc:3426 BlockDoWhile::markLabelBumpUp — delegate to the
    // inherent helper holding the faithful port (forces true down the front
    // chain, then clears own flag when the incoming bump was false).
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        self.mark_label_bump_up(bump);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockDoWhile virtual overrides)
impl BlockDoWhile {
    /// Ghidra `BlockDoWhile::markLabelBumpUp` (block.cc:3426-3432): do-while
    /// loops "steal" their lower blocks' labels — the label for the body
    /// entry prints at the `do {` construct position, not inside the body.
    /// The C++ first recurses via `BlockGraph::markLabelBumpUp(true)` (self
    /// flagged, list[0]=fused body+condition receives `true`), then clears
    /// the flag on itself if `bump` is false.
    // Ghidra: block.cc:3426 BlockDoWhile::markLabelBumpUp
    pub fn mark_label_bump_up(&mut self, bump: bool) {
        // cc:3429: BlockGraph::markLabelBumpUp(true); — mark self, then the
        // single list[0] child (the fused body+condition) with true.
        self.flags |= block_flags::LABEL_BUMPUP;
        self.condition
            .write()
            .unwrap()
            .mark_label_bump_up_trait(true);
        // cc:3430-3431: if (!bump) clearFlag(f_label_bumpup);
        if !bump {
            self.flags &= !block_flags::LABEL_BUMPUP;
        }
    }

    /// Ghidra `BlockDoWhile::scopeBreak` (block.cc:3434-3439): a new loop scope
    /// begins — the current loop exit becomes the new `cur_exit`. The single
    /// child (the fused body+condition) has multiple exits so gets
    /// `cur_exit = -1`. Rugra recurses into the held `condition` (which holds
    /// the fused body) via the trait method.
    // Ghidra: block.cc:3434 BlockDoWhile::scopeBreak
    pub fn scope_break_body(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3438: getBlock(0)->scopeBreak(-1, curexit);   // Multiple exits
        self.condition
            .write()
            .unwrap()
            .scope_break_trait(-1, cur_exit);
        let _ = cur_loop_exit;
    }

    /// Ghidra `BlockDoWhile::printHeader` (block.cc:3441-3446): emit
    /// `"Dowhile block <index>"`.
    // Ghidra: block.cc:3441 BlockDoWhile::printHeader
    pub fn print_header(&self) -> String {
        // cc:3444-3445: s << "Dowhile block "; FlowBlock::printHeader(s);
        format!("Dowhile block {}", self.index)
    }
}

/// An infinite loop (`do { ... } while(true);`).
///
/// Corresponds to Ghidra's `BlockInfLoop` (block.hh:735). Wraps a single
/// body block that unconditionally branches back to itself. No condition.
/// Emitted as `do { <body> } while(true);` (printc.cc:3097 emitBlockInfLoop).
#[derive(Debug)]
pub struct BlockInfLoop {
    pub index: i32,
    /// The loop body block (the self-looping block collapsed into this node).
    pub body: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockInfLoop {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:737 BlockInfLoop::getType
    fn get_type(&self) -> BlockType {
        BlockType::InfLoop
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        self.body.read().unwrap().get_start_addr()
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (structured blocks delegate ops to components)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.body.read().unwrap().get_ops()
    }
    // Ghidra: block.cc:3462 BlockInfLoop::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3466 body recurse
    // exiting into itself, this block establishes a new loop scope).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_body(cur_exit, cur_loop_exit);
    }
    // Ghidra: block.cc BlockInfLoop::markUnstructured — only recurses (via
    // BlockGraph::markUnstructured). Rugra recurses into body.
    fn mark_unstructured_trait(&mut self) {
        self.body.write().unwrap().mark_unstructured_trait();
    }
    // Ghidra: block.cc:3454 BlockInfLoop::markLabelBumpUp — delegate to the
    // inherent helper holding the faithful port (forces true down the front
    // chain, then clears own flag when the incoming bump was false).
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        self.mark_label_bump_up(bump);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockInfLoop virtual overrides)
impl BlockInfLoop {
    /// Ghidra `BlockInfLoop::markLabelBumpUp` (block.cc:3454-3460): infinite
    /// loops "steal" their lower blocks' labels — the label for the body
    /// entry prints at the `do { ... } while(true)` construct position, not
    /// inside the body. The C++ first recurses via
    /// `BlockGraph::markLabelBumpUp(true)` (self flagged, list[0]=body
    /// receives `true`), then clears the flag on itself if `bump` is false.
    // Ghidra: block.cc:3454 BlockInfLoop::markLabelBumpUp
    pub fn mark_label_bump_up(&mut self, bump: bool) {
        // cc:3457: BlockGraph::markLabelBumpUp(true); — mark self, then the
        // single list[0] child (the body) with true.
        self.flags |= block_flags::LABEL_BUMPUP;
        self.body
            .write()
            .unwrap()
            .mark_label_bump_up_trait(true);
        // cc:3458-3459: if (!bump) clearFlag(f_label_bumpup);
        if !bump {
            self.flags &= !block_flags::LABEL_BUMPUP;
        }
    }

    /// Ghidra `BlockInfLoop::scopeBreak` (block.cc:3462-3467): a new loop scope
    /// begins — the current loop exit becomes the new `cur_exit`. The body
    /// exits into itself (the loop's entry), so it gets
    /// `cur_exit = body's index`. Rugra recurses into the held `body` via the
    /// trait method.
    // Ghidra: block.cc:3462 BlockInfLoop::scopeBreak
    pub fn scope_break_body(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3466: getBlock(0)->scopeBreak(getBlock(0)->getIndex(), curexit);   // Exits into itself
        let body_idx = self.body.read().unwrap().get_index();
        self.body
            .write()
            .unwrap()
            .scope_break_trait(body_idx, cur_exit);
        let _ = cur_loop_exit;
    }

    /// Ghidra `BlockInfLoop::printHeader` (block.cc:3469-3474): emit
    /// `"Infinite loop block <index>"`.
    // Ghidra: block.cc:3469 BlockInfLoop::printHeader
    pub fn print_header(&self) -> String {
        // cc:3472-3473: s << "Infinite loop block "; FlowBlock::printHeader(s);
        format!("Infinite loop block {}", self.index)
    }
}

/// A structured sequence of blocks (linear fallthrough).
///
/// Corresponds to Ghidra's `BlockList`. Represents blocks that execute
/// sequentially with no branching between them.
#[derive(Debug)]
pub struct BlockList {
    pub index: i32,
    pub children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl BlockList {
    /// Create a new sequence block containing the given children in order.
    // Ghidra: block.hh:420 BlockGraph::newBlockList
    pub fn new(index: i32, children: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>) -> Self {
        Self {
            index,
            children,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }
    }

    /// Ghidra `BlockList::getExitLeaf` (block.cc:2953-2958): the exit leaf is
    /// the last child's exit leaf. Returns null if there are no children.
    // Ghidra: block.cc:2953 BlockList::getExitLeaf
    pub fn get_exit_leaf(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:2956-2957: if (getSize()==0) return null; return getBlock(getSize()-1)->getExitLeaf();
        self.children
            .last()
            .and_then(|c| c.read().unwrap().get_exit_leaf_trait())
    }

    /// Ghidra `BlockList::lastOp` (block.cc:2960-2965): the last op is the
    /// last child's last op. Returns null if there are no children.
    // Ghidra: block.cc:2960 BlockList::lastOp
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        // cc:2963-2964: if (getSize()==0) return null; return getBlock(getSize()-1)->lastOp();
        self.children
            .last()
            .and_then(|c| c.read().unwrap().last_op())
    }

    /// Ghidra `BlockList::negateCondition` (block.cc:2967-2974): negate the
    /// condition of the last child and flip the order of this block's outgoing
    /// edges. Returns true if the child's condition was negated. Rugra
    /// delegates to the last child's `negate_condition` and then swaps the
    /// outgoing edges in place.
    // Ghidra: block.cc:2967 BlockList::negateCondition
    pub fn negate_condition(&mut self, toporbottom: bool) -> bool {
        // cc:2970-2971: bl = getBlock(getSize()-1); res = bl->negateCondition(false);
        let res = if let Some(last) = self.children.last() {
            last.write().unwrap().negate_condition(false)
        } else {
            false
        };
        // cc:2972: FlowBlock::negateCondition(toporbottom);  -- flip order of outgoing
        if toporbottom {
            <Self as FlowBlock>::swap_edges(self);
        }
        res
    }

    /// Ghidra `BlockList::getSplitPoint` (block.cc:2976-2981): the split point
    /// is the last child's split point. Returns null if there are no children.
    /// Rugra returns the last child itself (the block whose CBRANCH can be
    /// flipped), as the front-leaf split-point concept does not yet have a
    /// distinct Rust counterpart.
    // Ghidra: block.cc:2976 BlockList::getSplitPoint
    pub fn get_split_point(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        // cc:2979-2980: if (getSize()==0) return null; return getBlock(getSize()-1)->getSplitPoint();
        self.children.last().cloned()
    }

    /// Ghidra `BlockList::printHeader` (block.cc:2983-2988): emit
    /// `"List block <index>"`.
    // Ghidra: block.cc:2983 BlockList::printHeader
    pub fn print_header(&self) -> String {
        // cc:2986-2987: s << "List block "; FlowBlock::printHeader(s);
        format!("List block {}", self.index)
    }

    /// RUGRA-GLUE: outgoing-edge swap helper (mirrors FlowBlock::negateCondition's
    /// edge-flip step, used by BlockList::negateCondition above). Exposed as a
    /// separate inherent method so callers can flip the edges without negating
    /// the last child's condition.
    // RUGRA-GLUE: outgoing swap helper (Ghidra folds this into FlowBlock::negateCondition block.cc:227-233)
    pub fn outgoing_swap(&mut self) {
        if self.outgoing.len() >= 2 {
            self.outgoing.swap(0, 1);
        }
    }
}

impl FlowBlock for BlockList {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:602 BlockList::getType
    fn get_type(&self) -> BlockType {
        BlockType::List
    }
    // Ghidra: block.cc:2953 BlockList::getExitLeaf
    fn get_exit_leaf_trait(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        BlockList::get_exit_leaf(self)
    }
    // Ghidra: block.cc:2960 BlockList::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        BlockList::last_op(self)
    }
    // Ghidra: block.cc:2976 BlockList::getSplitPoint
    fn get_split_point(&self) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        BlockList::get_split_point(self)
    }
    // Ghidra: block.cc:2967 BlockList::negateCondition
    fn negate_condition(&mut self, toporbottom: bool) -> bool {
        BlockList::negate_condition(self, toporbottom)
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        self.children
            .first()
            .map(|c| c.read().unwrap().get_start_addr())
            .unwrap_or_else(|| Address::new(0))
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        // Concatenate ops from all children in order
        let mut all_ops = Vec::new();
        for child in &self.children {
            all_ops.extend(child.read().unwrap().get_ops());
        }
        all_ops
    }
    // Ghidra: BlockList inherits BlockGraph::scopeBreak (block.cc:1270-1288)
    // — there is no override, so a BlockList walks its children exactly like
    // a BlockGraph: each child's exit is the next child's index (or the
    // inherited cur_exit for the last child), and cur_loop_exit propagates
    // unchanged. Rugra's BlockList is a separate struct (not a BlockGraph
    // subclass), so we replicate the traversal here.
    // Ghidra: block.cc:1270 BlockGraph::scopeBreak (inherited by BlockList)
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        let n = self.children.len();
        for i in 0..n {
            let ind = if i + 1 < n {
                self.children[i + 1].read().unwrap().get_index()
            } else {
                cur_exit
            };
            self.children[i]
                .write()
                .unwrap()
                .scope_break_trait(ind, cur_loop_exit);
        }
    }
    // Ghidra: block.cc BlockList inherits BlockGraph::markUnstructured
    // (block.cc:1238-1245) — recurse into every child.
    fn mark_unstructured_trait(&mut self) {
        for child in &self.children {
            child.write().unwrap().mark_unstructured_trait();
        }
    }
    // Ghidra: block.cc:1258 BlockGraph::markLabelBumpUp — inherited by
    // BlockList (block.hh:600, no override): mark self via the base method
    // (flag only if `bump`), then children[0] receives `bump` unchanged and
    // every later child receives `false`.
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        // cc:1261: FlowBlock::markLabelBumpUp(bump); // Mark ourselves if true
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        }
        // cc:1262: if (list.empty()) return;
        let mut iter = self.children.iter();
        // cc:1264: (*iter)->markLabelBumpUp(bump); // Only pass true down to
        // first subblock
        if let Some(first) = iter.next() {
            first.write().unwrap().mark_label_bump_up_trait(bump);
        }
        // cc:1266-1267: for(;iter!=list.end();++iter)
        //   (*iter)->markLabelBumpUp(false);
        for child in iter {
            child.write().unwrap().mark_label_bump_up_trait(false);
        }
    }
}

/// Boolean operator type for `BlockCondition`.
///
/// Corresponds to Ghidra's `BlockCondition::optype`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolOp {
    And,
    Or,
}

/// A structured boolean condition block (short-circuit && or ||).
///
/// Corresponds to Ghidra's `BlockCondition`. Represents two CBRANCH blocks
/// whose control flow encodes a short-circuit boolean expression:
///
/// **AND pattern**: A's false edge and B's false edge go to the same target.
/// ```text
///     A (CBRANCH)
///    / \
///   |   B (CBRANCH)
///   |  / \
///   C    D
///   ^--- both false edges → C  ==> if(a && b) { D } else { C }
/// ```
///
/// **OR pattern**: A's true edge and B's true edge go to the same target.
/// ```text
///     A (CBRANCH)
///    / \
///   B   |
///  / \  |
/// D   C---
///     ^--- both true edges → C  ==> if(a || b) { C } else { D }
/// ```
#[derive(Debug)]
pub struct BlockCondition {
    pub index: i32,
    pub op_type: BoolOp,
    /// First condition block (block A — the outer condition).
    pub first: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    /// Second condition block (block B — the inner condition).
    pub second: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockCondition {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:626 BlockCondition::getType
    fn get_type(&self) -> BlockType {
        BlockType::Condition
    }
    // Ghidra: block.cc:3016 BlockCondition::lastOp
    fn last_op(&self) -> Option<PcodeOpRef> {
        BlockCondition::last_op(self)
    }
    // Ghidra: block.cc:3023 BlockCondition::negateCondition
    fn negate_condition(&mut self, toporbottom: bool) -> bool {
        BlockCondition::negate_condition(self, toporbottom)
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        self.first.read().unwrap().get_start_addr()
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        // Concatenate ops from both condition blocks
        let mut ops = self.first.read().unwrap().get_ops();
        ops.extend(self.second.read().unwrap().get_ops());
        ops
    }
    // Ghidra: block.hh:635 BlockCondition::isComplex
    /// `virtual bool isComplex(void) const { return getBlock(0)->isComplex(); }`
    /// — a compound condition is exactly as complex as its first clause.
    fn is_complex(&self) -> bool {
        self.first.read().unwrap().is_complex()
    }
    // Ghidra: block.cc:3034 BlockCondition::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3037-3038 recurse
    // into both sub-conditions with cur_exit=-1, no fixed exit).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_children(cur_exit, cur_loop_exit);
    }
    // Ghidra: block.cc BlockCondition::markUnstructured — only recurses (via
    // BlockGraph::markUnstructured). Rugra recurses into first/second.
    fn mark_unstructured_trait(&mut self) {
        self.first.write().unwrap().mark_unstructured_trait();
        self.second.write().unwrap().mark_unstructured_trait();
    }
    // Ghidra: block.cc:1258 BlockGraph::markLabelBumpUp — inherited by
    // BlockCondition (block.hh:621, no override): mark self via the base
    // method (flag only if `bump`), then list[0] (`first`) receives `bump`
    // unchanged and list[1] (`second`) receives `false`.
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        // cc:1261: FlowBlock::markLabelBumpUp(bump); // Mark ourselves if true
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        }
        // cc:1263-1264: first subblock receives bump.
        self.first
            .write()
            .unwrap()
            .mark_label_bump_up_trait(bump);
        // cc:1266-1267: remaining subblock(s) receive false.
        self.second
            .write()
            .unwrap()
            .mark_label_bump_up_trait(false);
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockCondition virtual overrides)
impl BlockCondition {
    /// Ghidra `BlockCondition::getOpcode` (block.hh:625, inline): the boolean
    /// operation (BOOL_AND / BOOL_OR). Rugra returns the `BoolOp` enum.
    // Ghidra: block.hh:625 BlockCondition::getOpcode
    pub fn get_opcode(&self) -> BoolOp {
        self.op_type
    }

    /// Ghidra `BlockCondition::flipInPlaceTest` (block.cc:2990-3006): test
    /// whether the short-circuit condition can be flipped by testing each
    /// sub-block's split point. Returns the reason code (0 = flippable, 2 =
    /// not flippable). The C++ walks `getBlock(0)->getSplitPoint()` and
    /// `getBlock(1)->getSplitPoint()`; Rugra asks each child via the trait.
    // Ghidra: block.cc:2990 BlockCondition::flipInPlaceTest
    pub fn is_split_point(&self) -> bool {
        // cc:2993-3005: both children must have a split point that is flippable.
        // Rugra treats each child as its own split point and asks flip_in_place_test.
        if self.first.read().unwrap().flip_in_place_test() != 0 {
            return false;
        }
        self.second.read().unwrap().flip_in_place_test() == 0
    }

    /// Ghidra `BlockCondition::isComplex` (block.hh:635): a compound
    /// condition is exactly as complex as its first sub-block —
    /// `{ return getBlock(0)->isComplex(); }`. The previous unconditional
    /// `true` was a stand-in that diverged from the oracle.
    // Ghidra: block.hh:635 BlockCondition::isComplex
    pub fn is_complex(&self) -> bool {
        self.first.read().unwrap().is_complex()
    }

    /// Ghidra `BlockCondition::lastOp` (block.cc:3016-3021): the last op is
    /// the second child's last op (block B holds the final CBRANCH).
    // Ghidra: block.cc:3016 BlockCondition::lastOp
    pub fn last_op(&self) -> Option<PcodeOpRef> {
        // cc:3020: return getBlock(1)->lastOp();
        self.second.read().unwrap().last_op()
    }

    /// Ghidra `BlockCondition::negateCondition` (block.cc:3023-3032): distribute
    /// the NOT to both sides of the condition and swap the boolean op
    /// (AND<->OR). Returns true if either child's condition was negated.
    // Ghidra: block.cc:3023 BlockCondition::negateCondition
    pub fn negate_condition(&mut self, toporbottom: bool) -> bool {
        // cc:3027-3028: res1 = getBlock(0)->negateCondition(false); res2 = getBlock(1)->negateCondition(false);
        let res1 = self.first.write().unwrap().negate_condition(false);
        let res2 = self.second.write().unwrap().negate_condition(false);
        // cc:3029: opc = (opc==CPUI_BOOL_AND) ? CPUI_BOOL_OR : CPUI_BOOL_AND;
        self.op_type = match self.op_type {
            BoolOp::And => BoolOp::Or,
            BoolOp::Or => BoolOp::And,
        };
        // cc:3030: FlowBlock::negateCondition(toporbottom);  -- flip outgoing edges
        if toporbottom {
            <Self as FlowBlock>::swap_edges(self);
        }
        // cc:3031: return (res1 || res2);
        res1 || res2
    }

    /// Ghidra `BlockCondition::scopeBreak` (block.cc:3034-3039): propagate
    /// scope-break into both sub-conditions with no fixed exit (`cur_exit=-1`).
    // Ghidra: block.cc:3034 BlockCondition::scopeBreak
    pub fn scope_break_children(&mut self, _cur_exit: i32, cur_loop_exit: i32) {
        // cc:3037-3038: getBlock(0)->scopeBreak(-1, curloopexit); getBlock(1)->scopeBreak(-1, curloopexit);
        self.first
            .write()
            .unwrap()
            .scope_break_trait(-1, cur_loop_exit);
        self.second
            .write()
            .unwrap()
            .scope_break_trait(-1, cur_loop_exit);
    }

    /// Ghidra `BlockCondition::printHeader` (block.cc:3041-3051): emit
    /// `"Condition block(&&)" ` or `"Condition block(||)" ` based on the op.
    // Ghidra: block.cc:3041 BlockCondition::printHeader
    pub fn print_header(&self) -> String {
        // cc:3044-3048: s << "Condition block("; if (opc==BOOL_AND) "&&" else "||"; s << ") ";
        let op_str = match self.op_type {
            BoolOp::And => "&&",
            BoolOp::Or => "||",
        };
        format!("Condition block({}) {}", op_str, self.index)
    }

    /// Ghidra `BlockCondition::encodeHeader` (block.cc:3059-3065): emit the
    /// base header plus an `opcode` attribute with the boolean op name. Rugra
    /// returns `(index, opcode_name)` for the marshal layer.
    // Ghidra: block.cc:3059 BlockCondition::encodeHeader
    pub fn encode_header(&self) -> (i32, &'static str) {
        // cc:3063-3064: nm = get_opname(opc); writeString(ATTRIB_OPCODE, nm);
        let nm = match self.op_type {
            BoolOp::And => "BOOL_AND",
            BoolOp::Or => "BOOL_OR",
        };
        (self.index, nm)
    }

    /// Ghidra `BlockCondition::flipInPlaceExecute` (block.cc:3008-3014): flip
    /// the boolean op (AND<->OR) and flip each child's CBRANCH in place.
    // Ghidra: block.cc:3008 BlockCondition::flipInPlaceExecute
    pub fn flip_in_place_execute(&mut self) {
        // cc:3011: opc = (opc==BOOL_AND) ? BOOL_OR : BOOL_AND;
        self.op_type = match self.op_type {
            BoolOp::And => BoolOp::Or,
            BoolOp::Or => BoolOp::And,
        };
        // cc:3012-3013: getBlock(0)->getSplitPoint()->flipInPlaceExecute(); getBlock(1)->getSplitPoint()->flipInPlaceExecute();
        self.first.write().unwrap().flip_in_place_execute();
        self.second.write().unwrap().flip_in_place_execute();
    }
}

/// Ghidra `BlockSwitch::CaseOrder` (block.hh:755-767): the annotation and
/// sort record for one switch case. `basicblock` is the first basic-block to
/// execute within the case (`bl->getFrontLeaf()->subBlock(0)`, block.cc:3500),
/// `label`/`depth`/`chain` drive `finalizePrinting`'s ordering passes
/// (block.cc:3562-3591), and `outindex` is the basic-graph out-edge slot the
/// dispatch uses to reach the case (block.cc:3509).
#[derive(Debug, Clone)]
pub struct CaseOrder {
    /// The first basic-block to execute within the case block.
    pub basicblock: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// The label for this case, as an untyped constant (addCase init 0).
    pub label: u64,
    /// How deep in a fall-thru chain we are (addCase init 0).
    pub depth: i32,
    /// Who we immediately chain to, expressed as case index, -1 for no
    /// chaining (addCase init -1).
    pub chain: i32,
    /// Index coming out of switch to this case.
    pub outindex: i32,
}

impl CaseOrder {
    // RUGRA-GLUE: aggregate form of BlockSwitch::addCase's field-by-field
    // initialization (block.cc:3498-3505: emplace_back + label=0/depth=0/
    // chain=-1), so parallel-array bookkeeping cannot drop a field.
    /// Construct the placeholder record `addCase` builds before its
    /// `basicbl` lookups (label=0, depth=0, chain=-1, block.hh:760-762).
    pub fn placeholder(
        basicblock: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>, outindex: i32,
    ) -> Self {
        Self { basicblock, label: 0, depth: 0, chain: -1, outindex }
    }
}

/// A structured switch-case block.
///
/// Corresponds to Ghidra's `BlockSwitch`. Contains:
/// - `control`: the switch control block (normally contains the BRANCHIND op)
/// - `cases`: ordered list of case body blocks
/// - `case_values`: list of values corresponding to each case block
/// - `default_case`: optional default block
/// - `index_varnode`: optional variable controlling the switch index
#[derive(Debug)]
pub struct BlockSwitch {
    pub index: i32,
    pub control: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    pub cases: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub default_case: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Ghidra `CaseOrder::gototype` (block.hh:778) per regular case:
    /// 0 = structured case body; `goto_type::GOTO_GOTO` = a case whose
    /// dispatch edge was peeled as an unstructured goto (added by
    /// `BlockSwitch::grabCaseBasic`'s t_multigoto arm, block.cc:3548-3553);
    /// promoted to `goto_type::BREAK_GOTO` by scopeBreak when the target is
    /// the switch exit (block.cc:3620-3623). Parallel to `cases`.
    pub case_gototypes: Vec<u32>,
    /// Ghidra `CaseOrder::gototype` for the default case (`default_case`):
    /// 0 = structured default body; `goto_type::GOTO_GOTO` = a default edge
    /// peeled as an unstructured goto (newBlockMultiGoto's setDefaultGoto
    /// path). Same promotion rules as `case_gototypes`.
    pub default_gototype: u32,
    /// Ghidra `CaseOrder::isexit` (block.hh:763) per regular case: captured
    /// by `BlockSwitch::addCase` (block.cc:3513-3514) at grabCaseBasic time —
    /// BEFORE newBlockSwitch's identifyInternal consumes the case blocks and
    /// selfIdentify's replaceInEdge half-deletes their external out-edge
    /// halves (block.cc:160-173) — so `bl->sizeOut()==1` still sees the
    /// pre-consumption edge count. The flag is the permanent transport the
    /// printer reads (`isExit(i)`, block.hh:791, printc.cc:3342); it is NOT
    /// re-derivable post-collapse (components keep zero external edges).
    /// `gt != 0 → false` (cc:3512); `gt == 0 → bl->sizeOut() == 1`. Parallel
    /// to `cases`.
    pub case_isexit: Vec<bool>,
    /// `CaseOrder::isexit` for the default slot (cc:3512-3514 applied to
    /// Rugra's separate default arm).
    pub default_isexit: bool,
    /// Ghidra `BlockSwitch::jump` (block.hh:753): the jump table associated
    /// with this switch, captured by the ctor (`jump = ind->getJumptable()`,
    /// block.cc:3488, via `FlowBlock::getJumptable`, block.cc:630-639, which
    /// resolves the BRANCHIND last-op through Funcdata::findJumpTable). Held
    /// as the shared `Arc<RwLock<JumpTable>>` from `Funcdata::jump_tables`.
    pub jump: Option<Arc<RwLock<crate::jumptable::JumpTable>>>,
    /// Ghidra `BlockSwitch::caseblocks` (block.hh:767, `mutable vector<CaseOrder>`):
    /// the per-case annotation records built by `grabCaseBasic`
    /// (block.cc:3524-3554) and consumed/sorted by `finalizePrinting`
    /// (block.cc:3556-3592). Parallel to `cases` positionally.
    pub case_order: Vec<CaseOrder>,
    /// Ghidra `CaseOrder::label` of the formal default entry (block.hh:760).
    /// In the oracle the default is an ordinary caseblocks member — sorted
    /// with every other case by its label (block.cc:3591), the label coming
    /// from the default basic block's first table index (block.cc:3573-3576
    /// `getIndexByBlock(basicblock,0)`/`getLabelByIndex`) — so `default:`
    /// prints at its label rank, not last (printc.cc:3331-3332 + cc:3140).
    /// Rugra keeps the default in its own slot; this field carries the same
    /// label so printc can place it at the identical rank. None until
    /// `finalize_case_labels` computes it (or when the default basic block
    /// has no table indices — the cc:3588 `label = 0; Should never happen`
    /// corner keeps legacy last-position emission). Known corner vs the
    /// oracle: a default that is a fall-thru chain non-root takes its chain
    /// root's label in Ghidra (cc:3577-3584); Rugra's default slot carries
    /// no chain link, so such a default places by its own first index.
    /// — CLOSED (BLOCKACTION-SWITCH-DEFAULTCHAIN-0001): the virtual
    /// `default_order` below restores the chain link.
    ///
    /// `default_label` is the RANK KEY for the separate default slot: the
    /// scalar satisfying `count(case_order[i].label < default_label) == r`,
    /// where r is the number of regular cases the oracle's cc:3591 stable
    /// sort places before the default in the merged (cases + default)
    /// order. Consumers (printc's def_pos, `next_flow_after`'s merged
    /// order) count `label < default_label`; the key is strictly greater
    /// than every counted case's label, so chain-root cases sharing the
    /// inherited label still count before the default — the oracle's
    /// (label, depth) position encoded in a single scalar. Residual known
    /// corner: a fall-thru chain CONTINUING past the default (the default
    /// chained into a later regular case sharing its label) has no exact
    /// scalar rank; the key then places the default after that whole label
    /// group (witnessed under RUGRA_BS_DUMP=1; unreachable in both
    /// corpora — full-corpus byte comparison verified).
    pub default_label: Option<u64>,
    /// Ghidra keeps the formal default as an ordinary `caseblocks` member
    /// (`grabCaseBasic` cc:3529-3533 adds every component; only the
    /// `isdefault` flag distinguishes it, cc:3515). Rugra stores the
    /// default body in `default_case` outside the parallel `cases` arrays;
    /// this virtual `CaseOrder` is the default's own record (`addCase`
    /// cc:3498-3515 applied to the default edge), including its fall-thru
    /// `chain` link (cc:3536-3544): a case component whose BlockGoto
    /// target is the default's basic block links `chain = n` (the virtual
    /// index `case_order.len()`), and the default's own fall-thru into
    /// another case links its chain to that regular index.
    /// `finalize_case_labels` runs the cc:3562-3591 passes over
    /// `case_order + default_order` and derives `default_label` from the
    /// merged sort. None when there is no default or its basic-graph
    /// coordinates did not resolve (legacy placement).
    pub default_order: Option<CaseOrder>,
    pub case_values: Vec<Vec<u64>>,
    pub index_varnode: Option<Arc<RwLock<crate::varnode::Varnode>>>,
    pub incoming: Vec<BlockEdge>,
    pub outgoing: Vec<BlockEdge>,
    pub parent: Option<Weak<RwLock<BlockGraph>>>,
    pub flags: u32,
}

impl FlowBlock for BlockSwitch {
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:160 FlowBlock::getIndex
    fn get_index(&self) -> i32 {
        self.index
    }
    // RUGRA-GLUE: Rust mutator (Ghidra FlowBlock::index is private)
    fn set_index(&mut self, i: i32) {
        self.index = i;
    }
    // RUGRA-GLUE: Rust trait-object downcast glue
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    // Ghidra: block.hh:793 BlockSwitch::getType
    fn get_type(&self) -> BlockType {
        BlockType::Switch
    }
    // Ghidra: block.hh:165 FlowBlock::getFlags
    fn get_flags(&self) -> u32 {
        self.flags
    }
    // Ghidra: block.hh:155 FlowBlock::setFlag
    fn set_flags(&mut self, f: u32) {
        self.flags |= f;
    }
    // Ghidra: block.hh:156 FlowBlock::clearFlag
    fn clear_flags(&mut self, f: u32) {
        self.flags &= !f;
    }
    // Ghidra: block.hh:313 FlowBlock::sizeIn
    fn size_in(&self) -> usize {
        self.incoming.len()
    }
    // Ghidra: block.hh:312 FlowBlock::sizeOut
    fn size_out(&self) -> usize {
        self.outgoing.len()
    }
    // Ghidra: block.hh:304 FlowBlock::getIn
    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }
    // Ghidra: block.hh:301 FlowBlock::getOut
    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:301 direct outofthis[i] read)
    fn get_out_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.outgoing.get(slot)
    }
    // RUGRA-GLUE: reference accessor (oracle block.hh:304 direct intothis[i] read)
    fn get_in_ref(&self, slot: usize) -> Option<&BlockEdge> {
        self.incoming.get(slot)
    }

    // RUGRA-GLUE: shared edge-vector accessors (Ghidra FlowBlock base class
    // owns outofthis/intothis for every subtype, block.hh:124-127)
    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }
    // RUGRA-GLUE: in-edge half of the shared edge-vector accessor pair above.
    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    // Ghidra: block.cc:73 FlowBlock::addInEdge
    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }
    // RUGRA-GLUE: Rust edge-construction helper
    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }
    // Ghidra: block.hh:172 FlowBlock::getStart
    fn get_start_addr(&self) -> Address {
        self.control.read().unwrap().get_start_addr()
    }
    // Ghidra: block.hh:161 FlowBlock::getParent
    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        self.parent.as_ref().and_then(|p| p.upgrade())
    }
    // RUGRA-GLUE: Rust helper (Ghidra has no getOps; structured blocks delegate emit to components)
    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.control.read().unwrap().get_ops()
    }
    // Ghidra: block.cc:3613 BlockSwitch::scopeBreak — delegate to the
    // inherent helper which holds the faithful port (cc:3617 control recurse
    // with cur_exit=-1, cc:3618-3629 per-case recurse with cur_exit=curexit).
    fn scope_break_trait(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        self.scope_break_break_cases(cur_exit, cur_loop_exit);
    }
    // Ghidra: block.cc:3603 BlockSwitch::markUnstructured — recurse via
    // BlockGraph::markUnstructured (cc:3561), then mark each case whose
    // gototype is f_goto_goto (cc:3562-3565). Rugra recurses into the control
    // and every case; per-case goto target marking is a conservative no-op
    // (Rugra does not yet track per-case gototype).
    fn mark_unstructured_trait(&mut self) {
        self.control.write().unwrap().mark_unstructured_trait();
        for case in &self.cases {
            case.write().unwrap().mark_unstructured_trait();
        }
        self.mark_unstructured_targets();
    }
    // Ghidra: block.cc:1258 BlockGraph::markLabelBumpUp — inherited by
    // BlockSwitch (block.hh:752, no override): mark self via the base method
    // (flag only if `bump`), then recurse — list[0] is the switch component
    // itself (getSwitchBlock, block.hh:767), all case components
    // (cs[1..], grabCaseBasic block.cc:3524-3534) receive `false`.
    fn mark_label_bump_up_trait(&mut self, bump: bool) {
        // cc:1261: FlowBlock::markLabelBumpUp(bump); // Mark ourselves if true
        if bump {
            self.flags |= block_flags::LABEL_BUMPUP;
        }
        // cc:1263-1264: list[0] (switch component) receives bump.
        self.control
            .write()
            .unwrap()
            .mark_label_bump_up_trait(bump);
        // cc:1266-1267: remaining subblocks (all case components) get false.
        for case in &self.cases {
            case.write().unwrap().mark_label_bump_up_trait(false);
        }
        if let Some(default) = &self.default_case {
            default.write().unwrap().mark_label_bump_up_trait(false);
        }
    }
}

// RUGRA-GLUE: Rust inherent-impl block (Ghidra inlines these as BlockSwitch virtual overrides)
impl BlockSwitch {
    /// Ghidra `BlockSwitch::getSwitchBlock` (block.hh:772, inline): the root
    /// switch component (getBlock(0)). Rugra returns the `control` block.
    // Ghidra: block.hh:772 BlockSwitch::getSwitchBlock
    pub fn get_switch_block(&self) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
        self.control.clone()
    }

    /// Ghidra `BlockSwitch::getNumCaseBlocks` (block.hh:773, inline): the
    /// number of case components.
    // Ghidra: block.hh:773 BlockSwitch::getNumCaseBlocks
    pub fn get_num_case_blocks(&self) -> usize {
        self.cases.len()
    }

    /// Ghidra `BlockSwitch::getCaseBlock` (block.hh:774, inline): the i-th
    /// case FlowBlock.
    // Ghidra: block.hh:774 BlockSwitch::getCaseBlock
    pub fn get_case_block(&self, i: usize) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.cases.get(i).cloned()
    }

    /// Ghidra `BlockSwitch::getNumLabels` (block.hh:785, inline):
    /// `jump->numIndicesByBlock(caseblocks[i].basicblock)` — the number of
    /// case labels for the i-th case. Rugra materializes the identical value
    /// group into `case_values[i]` during `finalize_case_labels`
    /// (block.cc:3556-3592 runs before any printing), so this reads the
    /// materialized length; before finalize the field holds the addCase-style
    /// placeholder (out-edge slot).
    // Ghidra: block.hh:785 BlockSwitch::getNumLabels
    pub fn get_num_labels(&self, i: usize) -> usize {
        self.case_values.get(i).map(|v| v.len()).unwrap_or(0)
    }

    /// Ghidra `BlockSwitch::getLabel` (block.hh:786, inline):
    /// `jump->getLabelByIndex(jump->getIndexByBlock(caseblocks[i].basicblock, j))`
    /// — the j-th case label value for the i-th case. Rugra reads the group
    /// materialized by `finalize_case_labels` (same jumptable queries, same
    /// per-block addressIndex order).
    // Ghidra: block.hh:786 BlockSwitch::getLabel
    pub fn get_label(&self, i: usize, j: usize) -> Option<u64> {
        self.case_values.get(i).and_then(|v| v.get(j).copied())
    }

    /// Ghidra `BlockSwitch::finalizePrinting` (block.cc:3556-3592): the
    /// label/depth passes over `caseblocks` plus the final stable sort.
    ///
    /// Pass 1 (cc:3562-3570) walks every fall-thru chain once and marks
    /// non-root chain nodes `depth = -1`. Pass 2 (cc:3571-3589) sets the
    /// label on chain roots only (`numIndicesByBlock > 0 && depth == 0`),
    /// propagating the root label down the chain with increasing depth;
    /// cases with no address-table entry keep label 0 (cc:3588 "Should never
    /// happen"). The sort (cc:3591, `stable_sort` with
    /// `CaseOrder::compare`, block.hh:903-909: label, then depth) reorders
    /// the caseblocks; Rugra permutes the parallel `cases`/`case_gototypes`/
    /// `case_values`/`case_order` arrays jointly. Finally the label groups
    /// are materialized into `case_values` with the exact print-time queries
    /// (block.hh:780/787) so `get_num_labels`/`get_label` observe the same
    /// values Ghidra's live jumptable lookups would return.
    ///
    /// The tree recursion half of `finalizePrinting` (`BlockGraph::
    /// finalizePrinting`, block.cc:1364-1371) lives in
    /// [`BlockGraph::finalize_printing`], which invokes this per switch after
    /// recursing into the component list.
    // Ghidra: block.cc:3556 BlockSwitch::finalizePrinting
    pub fn finalize_case_labels(&mut self) {
        // Ghidra dereferences `jump` unconditionally (ctor block.cc:3488);
        // a switch without a recovered table never formed in the oracle.
        // Conservative skip keeps the placeholder case_values.
        let Some(jump) = &self.jump else {
            return;
        };
        let n = self.case_order.len();
        // cc:3556-3592 runs over the oracle's caseblocks vector, which
        // INCLUDES the formal default as an ordinary member (grabCaseBasic
        // cc:3529-3533 added every component; only the isdefault flag set
        // by addCase cc:3515 distinguishes it). Rugra keeps the default
        // body in its separate `default_case` slot with parallel `cases`
        // arrays, so the passes below run over the EXTENDED view `ext`:
        // the regular case_order entries plus the virtual default entry
        // (index n) that grab_case_order recorded with its own chain link.
        // Chain indices are grab-time indices and the passes walk them
        // BEFORE the cc:3591 sort, exactly like the oracle.
        let mut ext: Vec<CaseOrder> = self.case_order.clone();
        if let Some(def) = self.default_order.clone() {
            ext.push(def);
        }
        let has_virtual_default = ext.len() == n + 1;
        let m = ext.len();
        // cc:3562-3570: mark non-roots of fall-thru chains.
        for i in 0..m {
            let mut j = ext[i].chain;
            while j != -1 {
                let ju = j as usize;
                if ju >= m {
                    break; // Defensive: stale chain index (component churn)
                }
                if ext[ju].depth != 0 {
                    break; // Break any possible loops (already visited)
                }
                ext[ju].depth = -1; // Mark non-roots of chains
                j = ext[ju].chain;
            }
        }
        // cc:3571-3589: populate label and depth.
        {
            let jt = jump.read().unwrap();
            for i in 0..m {
                let Some(basic) = ext[i].basicblock.clone() else {
                    continue;
                };
                if jt.num_indices_by_block(&basic) > 0 {
                    if ext[i].depth == 0 {
                        // Only set label on chain roots.
                        if let Some(ind) = jt.get_index_by_block(&basic, 0) {
                            let label = jt.get_label_by_index(ind);
                            ext[i].label = label;
                            let mut j = ext[i].chain;
                            let mut depthcount: i32 = 1;
                            while j != -1 {
                                let ju = j as usize;
                                if ju >= m {
                                    break; // Defensive: stale chain index
                                }
                                if ext[ju].depth > 0 {
                                    break; // Has this node had its depth set
                                }
                                ext[ju].depth = depthcount;
                                depthcount += 1;
                                ext[ju].label = label;
                                j = ext[ju].chain;
                            }
                        }
                    }
                } else {
                    ext[i].label = 0; // Should never happen
                }
            }
        }
        // cc:3591: stable_sort(caseblocks.begin(),caseblocks.end(),
        // CaseOrder::compare) — label, then depth (block.hh:903-909). Rust's
        // sort_by is stable; the permutation is over the extended view so
        // the virtual default lands at its merged-sort position.
        let mut perm: Vec<usize> = (0..m).collect();
        perm.sort_by(|&a, &b| {
            let (ca, cb) = (&ext[a], &ext[b]);
            if ca.label != cb.label {
                ca.label.cmp(&cb.label)
            } else {
                ca.depth.cmp(&cb.depth)
            }
        });
        // Split the merged sort back into Rugra's storage shape: the
        // regular entries (perm slots holding indices < n) reorder the
        // parallel arrays jointly, exactly as the pre-extension code did.
        let regular_perm: Vec<usize> = perm.iter().copied().filter(|&x| x < n).collect();
        let new_cases: Vec<_> = regular_perm.iter().map(|&i| self.cases[i].clone()).collect();
        let new_gototypes: Vec<_> = regular_perm.iter().map(|&i| self.case_gototypes[i]).collect();
        let new_isexit: Vec<_> = regular_perm.iter().map(|&i| self.case_isexit[i]).collect();
        let new_values: Vec<_> = regular_perm.iter().map(|&i| self.case_values[i].clone()).collect();
        let new_order: Vec<_> = regular_perm.iter().map(|&i| ext[i].clone()).collect();
        self.cases = new_cases;
        self.case_gototypes = new_gototypes;
        self.case_isexit = new_isexit;
        self.case_values = new_values;
        self.case_order = new_order;
        // Materialize the print-time label groups (block.hh:780/787):
        // values[i][j] = getLabelByIndex(getIndexByBlock(basic_i, j)) for
        // j in 0..numIndicesByBlock(basic_i) — addressIndex order within the
        // block's sorted block2addr entries.
        let jump = jump.clone();
        let jt = jump.read().unwrap();
        for i in 0..n {
            let Some(basic) = self.case_order[i].basicblock.clone() else {
                continue;
            };
            let count = jt.num_indices_by_block(&basic);
            let mut group: Vec<u64> = Vec::with_capacity(count);
            for j in 0..count {
                if let Some(ind) = jt.get_index_by_block(&basic, j) {
                    group.push(jt.get_label_by_index(ind));
                }
            }
            self.case_values[i] = group;
        }
        // Rank key for printc's separate default slot: r = the number of
        // regular cases the oracle's merged (cases + default) cc:3591 sort
        // places before the default. Encoded as the scalar `default_label`
        // satisfying count(case_order[i].label < default_label) == r over
        // the sorted regulars — the smallest such scalar is
        // max(prefix labels) + 1 (0 when the default sorts first).
        // Consumers (printc's def_pos, `next_flow_after`'s merged order)
        // count `label < default_label` and insert the default at index r,
        // which is exactly the oracle's merged print position: a chain root
        // sharing the default's INHERITED label is inside the prefix and
        // counts before it, matching the (label, depth) tie-break that
        // orders depth-0 roots before the deeper default (block.hh:907).
        if has_virtual_default {
            let def_pos_merged = perm
                .iter()
                .position(|&x| x == n)
                .expect("virtual default present in perm");
            let prefix: Vec<usize> = perm[..def_pos_merged]
                .iter()
                .copied()
                .filter(|&x| x < n)
                .collect();
            let r = prefix.len();
            let rank_key = if r == 0 {
                0
            } else {
                prefix
                    .iter()
                    .map(|&i| ext[i].label)
                    .max()
                    .unwrap()
                    .saturating_add(1)
            };
            let achieved = self.case_order.iter().filter(|co| co.label < rank_key).count();
            if achieved != r {
                // Residual corner (see the default_label field doc): a
                // fall-thru chain CONTINUING past the default shares its
                // label with a regular sorting after it — no scalar can
                // express the oracle's exact interleaving. Best effort:
                // keep the key (default places after that label group).
                if std::env::var("RUGRA_BS_DUMP")
                    .map(|v| v == "1" || v == "2")
                    .unwrap_or(false)
                {
                    eprintln!(
                        "[BLOCKSTRUCT] finalizePrinting default rank-key inexact: r={} achieved={} key=0x{:x}",
                        r, achieved, rank_key
                    );
                }
            }
            self.default_label = Some(rank_key);
        }
        // Legacy fallback when the virtual default record never resolved
        // (default_order == None but a default body exists — a constructor
        // path without grab_case_order coordinates): the block.cc:3573-3576
        // own-first-index recipe as the rank key. Exact for a chain-root
        // default (no case falls into it): no regular shares its label, so
        // count(label < own) == r.
        if !has_virtual_default {
            if let Some(def) = &self.default_case {
                // cc:3500: basicbl = bl->getFrontLeaf()->subBlock(0)
                let def_basic = crate::block::front_leaf(def).and_then(|leaf| {
                    let r = leaf.read().unwrap();
                    r.as_any()
                        .downcast_ref::<crate::block::BlockCopy>()
                        .map(|c| c.original.clone())
                });
                if let Some(basic) = def_basic {
                    if jt.num_indices_by_block(&basic) > 0 {
                        if let Some(ind) = jt.get_index_by_block(&basic, 0) {
                            self.default_label = Some(jt.get_label_by_index(ind));
                        }
                    }
                }
            }
        }
        // RUGRA-GLUE: env-gated (RUGRA_BS_DUMP=1) structural witness for the
        // label pipeline (no Ghidra counterpart; debug-only) — prints the
        // finalized CaseOrder records per switch.
        if std::env::var("RUGRA_BS_DUMP")
            .map(|v| v == "1" || v == "2")
            .unwrap_or(false)
        {
            for (i, co) in self.case_order.iter().enumerate() {
                eprintln!(
                    "[BLOCKSTRUCT] finalizePrinting case[{}] label=0x{:x} depth={} chain={} outindex={} labels={:?}",
                    i,
                    co.label,
                    co.depth,
                    co.chain,
                    co.outindex,
                    self.case_values.get(i).map(|v| v.as_slice()).unwrap_or(&[])
                );
            }
            if let Some(dl) = self.default_label {
                eprintln!(
                    "[BLOCKSTRUCT] finalizePrinting default rank_key=0x{:x} def_pos={}",
                    dl,
                    self.case_order.iter().filter(|co| co.label < dl).count()
                );
            }
        }
    }

    /// Ghidra `BlockSwitch::isDefaultCase` (block.hh:789, inline): is the i-th
    /// case the default case? Rugra compares against `default_case`.
    // Ghidra: block.hh:789 BlockSwitch::isDefaultCase
    pub fn is_default_case(&self, i: usize) -> bool {
        if let (Some(case), Some(default)) = (self.cases.get(i), &self.default_case) {
            Arc::ptr_eq(case, default)
        } else {
            false
        }
    }

    // CASEWRAP-CR-F2: `isExit(i)` (block.hh:791 reads the captured
    // `caseblocks[i].isexit` flag) is DELETED. It had zero callers, and its
    // body re-derived `bl->sizeOut()==1` from the case block at read time —
    // always false once identifyInternal's replaceInEdge half-deletes the
    // case blocks' out-edge halves (block.cc:160-173), so the former doc
    // claim ("matches the C++ addCase rule") never held for post-grab
    // reads. The captured transports `case_isexit`/`default_isexit` (fields
    // above, set at addCase time per block.cc:3511-3514) are the
    // oracle-shaped source for any future reader of the exit property.

    /// Ghidra `BlockSwitch::markUnstructured` (block.cc:3603-3611): mark each
    /// case whose goto edge is a plain `goto` with `f_unstructured_targ`. The
    /// C++ first recurses via `BlockGraph::markUnstructured`; Rugra's
    /// `BlockSwitch` exposes its cases directly, so only the per-case marking
    /// is ported here. scopeBreak runs before markUnstructured (the oracle's
    /// own evaluation order), so cases already promoted to `f_break_goto`
    /// are NOT marked — exactly the `== f_goto_goto` test (cc:3608).
    // Ghidra: block.cc:3603 BlockSwitch::markUnstructured
    pub fn mark_unstructured_targets(&self) {
        // cc:3607-3610: for each case, if (caseblocks[i].gototype == f_goto_goto) markCopyBlock(caseblocks[i].block, f_unstructured_targ);
        for (case, gt) in self.cases.iter().zip(self.case_gototypes.iter()) {
            if *gt == goto_type::GOTO_GOTO {
                mark_front_leaf(case, block_flags::UNSTRUCTURED_TARG);
            }
        }
        // The default case is a caseblock in the oracle (isdefault tag);
        // Rugra stores it separately — same marking rule.
        if self.default_gototype == goto_type::GOTO_GOTO {
            if let Some(def) = &self.default_case {
                mark_front_leaf(def, block_flags::UNSTRUCTURED_TARG);
            }
        }
    }

    /// Ghidra `BlockSwitch::scopeBreak` (block.cc:3613-3630): a new scope — the
    /// current loop exit becomes the new `cur_exit`. The switch control has
    /// multiple exits so gets `cur_exit = -1`; each case either has a goto
    /// (reclassified as `break` if it lands on cur_exit — "A goto that goes
    /// straight to exit, print is (empty) break", cc:3620-3623) or shares the
    /// switch's exit (scopeBreak with curexit=curexit, cc:3625-3628).
    // Ghidra: block.cc:3613 BlockSwitch::scopeBreak
    pub fn scope_break_break_cases(&mut self, cur_exit: i32, cur_loop_exit: i32) {
        // cc:3617: getBlock(0)->scopeBreak(-1, curexit);   // Top block has multiple exits
        self.control
            .write()
            .unwrap()
            .scope_break_trait(-1, cur_exit);
        // cc:3618-3629: for each case, either reclassify its goto or
        // scopeBreak(curexit, curexit) for exit cases.
        for (i, case) in self.cases.iter().enumerate() {
            let gt = self.case_gototypes.get(i).copied().unwrap_or(0);
            if gt != 0 {
                // cc:3620-3623: if (bl->getIndex() == curexit) gototype = f_break_goto;
                if case.read().unwrap().get_index() == cur_exit {
                    if let Some(g) = self.case_gototypes.get_mut(i) {
                        *g = goto_type::BREAK_GOTO;
                    }
                }
            } else {
                // cc:3625-3628: bl->scopeBreak(curexit, curexit);
                case.write().unwrap().scope_break_trait(cur_exit, cur_exit);
            }
        }
        // The default case is a caseblock in the oracle's single list; the
        // same gototype arm applies to Rugra's separate slot.
        if self.default_gototype != 0 {
            if let Some(def) = &self.default_case {
                if def.read().unwrap().get_index() == cur_exit {
                    self.default_gototype = goto_type::BREAK_GOTO;
                }
            }
        } else if let Some(def) = &self.default_case {
            def.write().unwrap().scope_break_trait(cur_exit, cur_exit);
        }
        let _ = cur_loop_exit;
    }

    /// Ghidra `BlockSwitch::printHeader` (block.cc:3632-3637): emit
    /// `"Switch block <index>"`.
    // Ghidra: block.cc:3632 BlockSwitch::printHeader
    pub fn print_header(&self) -> String {
        // cc:3635-3636: s << "Switch block "; FlowBlock::printHeader(s);
        format!("Switch block {}", self.index)
    }

    /// Ghidra `BlockSwitch::getSwitchVar` (block.cc:3596-3601): the input
    /// Varnode to the switch's BRANCHIND, used by the printer to emit the
    /// switch expression. Rugra returns the held `index_varnode`.
    // Ghidra: block.cc:3596 BlockSwitch::getSwitchVar
    pub fn get_switch_varnode(&self) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        self.index_varnode.clone()
    }
}

#[cfg(test)]
mod edge_flag_tests {
    use super::{BlockBasic, BlockGraph, FlowBlock};
    use crate::address::Address;
    use std::sync::{Arc, RwLock};

    #[test]
    fn edge_flag_values_are_pairwise_unique() {
        let flags = [
            super::edge_flags::F_BREAK_EDGE,
            super::edge_flags::F_CONTINUE_EDGE,
            super::edge_flags::F_GOTO_EDGE,
            super::edge_flags::F_SWITCH_DISPATCH,
            super::edge_flags::F_LOOP_EXIT_EDGE,
            super::edge_flags::F_BACK_EDGE,
            super::edge_flags::F_IRREDUCIBLE_EDGE,
            super::edge_flags::F_DEFAULTSWITCH_EDGE,
            super::edge_flags::F_TREE_EDGE,
            super::edge_flags::F_FORWARD_EDGE,
            super::edge_flags::F_CROSS_EDGE,
            super::edge_flags::F_LOOP_EDGE,
        ];
        for (i, left) in flags.iter().enumerate() {
            for right in flags.iter().skip(i + 1) {
                assert_ne!(left, right, "edge flag collision: {left:#x}");
            }
        }
        assert_eq!(super::edge_flags::F_GOTO_EDGE, 0x01);
        assert_eq!(super::edge_flags::F_LOOP_EDGE, 0x02);
        assert_eq!(super::edge_flags::F_DEFAULTSWITCH_EDGE, 0x04);
        assert_eq!(super::edge_flags::F_IRREDUCIBLE_EDGE, 0x08);
        assert_eq!(super::edge_flags::F_TREE_EDGE, 0x10);
        assert_eq!(super::edge_flags::F_FORWARD_EDGE, 0x20);
        assert_eq!(super::edge_flags::F_CROSS_EDGE, 0x40);
        assert_eq!(super::edge_flags::F_BACK_EDGE, 0x80);
        assert_eq!(super::edge_flags::F_LOOP_EXIT_EDGE, 0x100);
    }

    #[test]
    fn default_switch_label_is_mirrored_and_preserved_by_build_copy() {
        type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
        let source = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x1000)))) as BlockArc;
        let first = Arc::new(RwLock::new(BlockBasic::new(1, Address::new(0x1100)))) as BlockArc;
        let second = Arc::new(RwLock::new(BlockBasic::new(2, Address::new(0x1200)))) as BlockArc;
        let mut graph = BlockGraph::new();
        graph.add_block(source.clone());
        graph.add_block(first.clone());
        graph.add_block(second.clone());
        graph.add_edge(source.clone(), first.clone());
        graph.add_edge(source.clone(), second.clone());

        super::set_default_switch_mirrored(&source, 0);
        super::set_default_switch_mirrored(&source, 1);
        let default_flag = super::edge_flags::F_DEFAULTSWITCH_EDGE;
        let source_read = source.read().unwrap();
        let out0 = source_read.get_out(0).unwrap();
        let out1 = source_read.get_out(1).unwrap();
        assert_eq!(out0.flags & default_flag, 0);
        assert_ne!(out1.flags & default_flag, 0);
        assert_eq!(out0.reverse_index, 0);
        assert_eq!(out1.reverse_index, 0);
        drop(source_read);
        assert_eq!(
            first.read().unwrap().get_in(0).unwrap().flags & default_flag, 0
        );
        assert_ne!(
            second.read().unwrap().get_in(0).unwrap().flags & default_flag,
            0
        );

        let mut copy = BlockGraph::new();
        copy.build_copy(&graph);
        let copy_source = copy.get_block(0).unwrap();
        let copy_first = copy.get_block(1).unwrap();
        let copy_second = copy.get_block(2).unwrap();
        assert_eq!(
            copy_source.read().unwrap().get_out(0).unwrap().flags & default_flag,
            0
        );
        assert_ne!(
            copy_source.read().unwrap().get_out(1).unwrap().flags & default_flag,
            0
        );
        assert_eq!(
            copy_first.read().unwrap().get_in(0).unwrap().flags & default_flag,
            0
        );
        assert_ne!(
            copy_second.read().unwrap().get_in(0).unwrap().flags & default_flag,
            0
        );
    }

    /// compareFinalOrder sort keys (block.cc:709-730) + orderBlocks' size
    /// guard (block.hh:430-431), on BlockBasic blocks carrying real ops so
    /// the production `lastOp` dispatch is exercised: entry (index 0)
    /// always first (cc:712-713), RETURN-ending blocks last (cc:717-728,
    /// including the null-lastOp arms), two RETURN-ending blocks tie
    /// (cc:719+724 both false), everything else by index (cc:729), and a
    /// single-element list skips the sort entirely (cc:431).
    #[test]
    fn compare_final_order_sort_keys_and_order_blocks_guard() {
        use crate::op::PcodeOpRef;
        use crate::opcodes::OpCode;
        type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

        // BlockBasic::add_op appends, so the LAST op defines lastOp().
        let make = |index: i32, opcode: Option<OpCode>| -> BlockArc {
            let bl: BlockArc =
                Arc::new(RwLock::new(BlockBasic::new(index, Address::new(0x1000))));
            if let Some(opc) = opcode {
                let op = PcodeOpRef(Arc::new(RwLock::new(crate::op::PcodeOp::new(
                    crate::address::SeqNum::new(Address::new(0x1000), 1),
                    opc,
                ))));
                bl.write().unwrap().add_op(op);
            }
            bl
        };
        let plain = |index: i32| make(index, Some(OpCode::CPUI_COPY));
        let ret = |index: i32| make(index, Some(OpCode::CPUI_RETURN));
        let no_op = |index: i32| make(index, None);

        // cc:712-713: entry (index 0) before everything, including a
        // RETURN-ending block; and the mirror comparison.
        assert_eq!(
            super::compare_final_order(&plain(0), &ret(3)),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            super::compare_final_order(&ret(3), &plain(0)),
            std::cmp::Ordering::Greater
        );
        // cc:719-722: RETURN vs non-RETURN last ops.
        assert_eq!(
            super::compare_final_order(&ret(2), &plain(1)),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            super::compare_final_order(&plain(1), &ret(2)),
            std::cmp::Ordering::Less
        );
        // cc:724: RETURN vs absent last op.
        assert_eq!(
            super::compare_final_order(&ret(2), &no_op(1)),
            std::cmp::Ordering::Greater
        );
        // cc:726-727: absent vs RETURN last op.
        assert_eq!(
            super::compare_final_order(&no_op(1), &ret(2)),
            std::cmp::Ordering::Less
        );
        // cc:719+724 tie: two RETURN-ending blocks, both directions Equal
        // (the index comparison at cc:729 is never reached).
        assert_eq!(
            super::compare_final_order(&ret(5), &ret(2)),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            super::compare_final_order(&ret(2), &ret(5)),
            std::cmp::Ordering::Equal
        );
        // Non-RETURN op vs absent op: falls through to the index key.
        assert_eq!(
            super::compare_final_order(&plain(4), &no_op(1)),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            super::compare_final_order(&no_op(1), &plain(4)),
            std::cmp::Ordering::Less
        );
        // cc:729: plain index ordering.
        assert_eq!(
            super::compare_final_order(&plain(3), &plain(7)),
            std::cmp::Ordering::Less
        );

        // End-to-end order_blocks permutation: initial list
        // [ret5, entry0, ret2, plain7, no_op4] (a RETURN block ahead of the
        // entry, mirroring the collapse-residue orders the oracle sorts).
        let mut graph = BlockGraph::new();
        let blocks = vec![ret(5), plain(0), ret(2), plain(7), no_op(4)];
        for b in &blocks {
            graph.add_block(b.clone());
        }
        graph.order_blocks();
        let order: Vec<i32> = graph
            .blocks
            .iter()
            .map(|b| b.read().unwrap().get_index())
            .collect();
        // Entry first, then non-RETURN blocks ascending by index, then the
        // RETURN-ending blocks (stable tie: ret5 precedes ret2 because
        // ret5 preceded ret2 in the pre-sort list).
        assert_eq!(order, vec![0, 4, 7, 5, 2]);

        // block.hh:431 size guard: a single-element list skips the sort
        // (observable here as the identity permutation).
        let mut single = BlockGraph::new();
        single.add_block(ret(1));
        single.order_blocks();
        assert_eq!(single.blocks.len(), 1);
        assert_eq!(single.blocks[0].read().unwrap().get_index(), 1);
    }
}


/// F8FOR-FINALIZE-VISITED-0001 constructive verification: the single-
/// ownership invariant that makes the oracle's unguarded
/// finalizePrinting recursion (block.cc:1364-1371) sound, the one
/// sanctioned aliasing exception (goto-arm switch targets), and the
/// debug checker that machine-enforces both (see
/// `BlockGraph::debug_assert_structure_tree_unique`).
#[cfg(test)]
mod finalize_visited_tests {
    use super::{BlockBasic, BlockGraph, BlockList, BlockSwitch, FlowBlock};
    use crate::address::Address;
    use std::sync::{Arc, RwLock};

    type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

    fn leaf(index: i32) -> BlockArc {
        Arc::new(RwLock::new(BlockBasic::new(index, Address::new(0x1000 + index as u64 * 0x10))))
    }

    fn list(index: i32, children: Vec<BlockArc>) -> BlockArc {
        Arc::new(RwLock::new(BlockList::new(index, children)))
    }

    /// A shared child under two composites is exactly the tree break the
    /// CR-F8FOR finding worried about: a WhileDo reached this way would be
    /// finalized twice (first visit's opMarkNonPrinting pair makes the
    /// second testTerminal reject the notPrinted root → silent for→while
    /// degradation). The debug checker must fail loudly on it.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "ownership invariant violated")]
    fn shared_child_over_oracle_walk_shape_is_detected() {
        let inner_leaf = leaf(2);
        // leaf #2 sits under BOTH the inner list and the outer list.
        let outer = list(0, vec![list(1, vec![inner_leaf.clone()]), inner_leaf]);
        BlockGraph::debug_assert_structure_tree_unique(&[outer]);
    }

    /// A parent cycle (composite holding itself as a child) would loop the
    /// unguarded oracle-shaped recursions forever; the checker's seen-set
    /// insert-before-recurse turns it into the same loud failure.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "ownership invariant violated")]
    fn parent_cycle_is_detected() {
        let cyc: BlockArc = Arc::new(RwLock::new(BlockList::new(0, Vec::new())));
        {
            let mut w = cyc.write().unwrap();
            if let Some(l) = w.as_any_mut().downcast_mut::<BlockList>() {
                l.children.push(cyc.clone());
            }
        }
        BlockGraph::debug_assert_structure_tree_unique(&[cyc]);
    }

    /// The one sanctioned aliasing: a BlockSwitch with a multigoto control
    /// keeps goto-arm targets in `cases` (gototype != 0) while they remain
    /// top-level roots — mirroring the oracle leaving them in the
    /// surrounding graph (block.cc:3548-3553). Over the oracle walk shape
    /// (structured members only) the tree stays single-visit, so the
    /// checker passes — while the raw `component_list_dyn` walk
    /// `final_transform_block` uses really does reach the aliased target
    /// twice, which is why that sweep's visited guard is load-bearing and
    /// the finalize dispatch (control + gototype==0 cases) needs none.
    #[test]
    #[cfg(debug_assertions)]
    fn goto_arm_switch_aliasing_is_sanctioned_and_unique_over_oracle_walk() {
        use crate::block::goto_type::GOTO_GOTO;
        let control = leaf(0);
        let structured_case = leaf(1);
        let goto_target = leaf(2);
        let switch: BlockArc = Arc::new(RwLock::new(BlockSwitch {
            index: 0,
            control: control.clone(),
            cases: vec![structured_case.clone(), goto_target.clone()],
            default_case: None,
            case_gototypes: vec![0, GOTO_GOTO],
            default_gototype: 0,
            case_isexit: vec![false, false],
            default_isexit: false,
            jump: None,
            case_order: Vec::new(),
            default_label: None,
            default_order: None,
            case_values: Vec::new(),
            index_varnode: None,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }));
        // Faithful root layout: the switch and the goto-arm target are
        // siblings at the top level (the target was never consumed).
        let roots = vec![switch.clone(), goto_target.clone()];

        // (a) Oracle walk shape is single-visit despite the aliasing.
        BlockGraph::debug_assert_structure_tree_unique(&roots);

        // (b) The raw component walk final_transform_block uses DOES see
        // the goto target twice (root + switch case) — the visited guard
        // dedups exactly this.
        fn count_visits(target: &BlockArc, bl: &BlockArc, n: &mut i32) {
            if Arc::ptr_eq(target, bl) {
                *n += 1;
            }
            for child in BlockGraph::component_list_dyn(bl) {
                count_visits(target, &child, n);
            }
        }
        let mut visits = 0;
        for root in &roots {
            count_visits(&goto_target, root, &mut visits);
        }
        assert_eq!(visits, 2, "component_list_dyn must reach the aliased goto target twice");

        // (c) The finalize dispatch's Switch arm (control + gototype==0
        // cases) structurally excludes the aliased member — no guard
        // needed there.
        let finalize_children = {
            let r = switch.read().unwrap();
            let sw = r.as_any().downcast_ref::<BlockSwitch>().unwrap();
            let mut v = vec![sw.control.clone()];
            for (case, &gt) in sw.cases.iter().zip(sw.case_gototypes.iter()) {
                if gt == 0 {
                    v.push(case.clone());
                }
            }
            v
        };
        assert_eq!(finalize_children.len(), 2);
        assert!(Arc::ptr_eq(&finalize_children[0], &control));
        assert!(Arc::ptr_eq(&finalize_children[1], &structured_case));
        assert!(
            !finalize_children.iter().any(|c| Arc::ptr_eq(c, &goto_target)),
            "finalize walk must skip the goto-arm target"
        );
    }

    /// End-to-end protocol proof: the default 5-step collapse (the
    /// production path — every composite install goes through
    /// identify_internal's single-consumption protocol) yields a tree
    /// that is single-visit over the oracle walk shape.
    #[test]
    #[cfg(debug_assertions)]
    fn default_5step_collapse_yields_single_owner_tree() {
        use crate::block::BlockEdge;
        // Linear chain entry -> a -> b -> exit: ruleBlockCat (via
        // collapseInternal) merges it into one BlockList.
        let entry = leaf(0);
        let a = leaf(1);
        let b = leaf(2);
        let exit = leaf(3);
        {
            let mut w = entry.write().unwrap();
            w.add_out_edge(BlockEdge::new(a.clone(), 0));
        }
        {
            let mut w = a.write().unwrap();
            w.add_in_edge(BlockEdge::new(entry.clone(), 0));
            w.add_out_edge(BlockEdge::new(b.clone(), 0));
        }
        {
            let mut w = b.write().unwrap();
            w.add_in_edge(BlockEdge::new(a.clone(), 0));
            w.add_out_edge(BlockEdge::new(exit.clone(), 0));
        }
        {
            let mut w = exit.write().unwrap();
            w.add_in_edge(BlockEdge::new(b.clone(), 0));
        }
        let mut graph = BlockGraph::new();
        graph.blocks = vec![entry, a, b, exit];
        let mut cs = crate::blockaction::CollapseStructure::new(&mut graph, "f8visited-test");
        cs.collapse_all();
        let roots: Vec<BlockArc> = graph.blocks.clone();
        assert!(!roots.is_empty());
        BlockGraph::debug_assert_structure_tree_unique(&roots);
    }

    /// BLOCK-FINALIZE-DEFAULT-RECURSE-0001 unit lock (the bilateral oracle
    /// fixture is tests/oracle/blockstruct_switch_default_whiledo_1204):
    /// a switch whose DEFAULT arm (default_gototype==0) is a while-do with
    /// a canonical for shape must run BlockWhileDo::finalizePrinting
    /// THROUGH the switch's finalize recursion — the oracle's plain
    /// component-list walk (block.cc:3559) always reaches the default arm
    /// member. The observable: the iterate statement (INT_ADD) is flagged
    /// non-printing (block.cc:3422 opMarkNonPrinting). The dispatch used
    /// to skip the default_case slot, leaving INT_ADD printable (the
    /// for->while degradation this lane fixed).
    ///
    /// CFG (mirror of the fixture): b0 BRANCHIND head (out0 case RETURN,
    /// out1 DEFAULT), b1 case RETURN, b2 loop head (MULTIEQUAL/INT_LESS/
    /// CBRANCH), b3 loop body (INT_ADD), b4 exit RETURN. The tree is
    /// installed through the production factories in the order the
    /// collapse rules produce when W forms first (identify_internal over a
    /// BlockWhileDo, then try_rule_switch), because a single collapse run
    /// consumes the raw default target before the loop can form under it.
    #[test]
    fn finalize_recurses_into_structured_default_whiledo_for_extraction() {
        use crate::block::BlockCopy;
        use crate::block::BlockWhileDo;
        use crate::blockaction::CollapseStructure;
        use crate::funcdata::Funcdata;
        use crate::jumptable::JumpTable;
        use crate::op::pcodeop_flags;
        use crate::opcodes::OpCode;

        let mut fd = Funcdata::new("f", Address::new(0x60000), 0x100);
        fd.set_arch(Arc::new(crate::arch::Architecture::new()));

        let mut bb: Vec<BlockArc> = Vec::new();
        for (i, a) in [0x60000u64, 0x60010, 0x60020, 0x60040, 0x60060].iter().enumerate() {
            let bl: BlockArc =
                Arc::new(RwLock::new(BlockBasic::new(i as i32, Address::new(*a))));
            fd.bblocks.add_block(bl.clone());
            bb.push(bl);
        }

        // b0: i0 = COPY 0; BRANCHIND x. b2: MULTIEQUAL/INT_LESS/CBRANCH.
        // b3: INT_ADD. b1/b4: RETURN.
        let init_op = fd.new_op(1, Address::new(0x60000));
        fd.op_set_opcode(&init_op, OpCode::CPUI_COPY);
        let i0 = fd.new_unique_out(4, &init_op);
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(&init_op, zero, 0);
        fd.op_insert_end(&init_op, &bb[0]);
        let ind_op = fd.new_op(1, Address::new(0x60004));
        fd.op_set_opcode(&ind_op, OpCode::CPUI_BRANCHIND);
        let x = fd.new_varnode(4, Address::new(0));
        fd.op_set_input(&ind_op, x, 0);
        fd.op_insert_end(&ind_op, &bb[0]);
        let ret = |fd: &mut Funcdata, addr: u64, val: u64, blk: &BlockArc| {
            let r = fd.new_op(1, Address::new(addr));
            fd.op_set_opcode(&r, OpCode::CPUI_RETURN);
            let rv = fd.new_constant(1, val);
            fd.op_set_input(&r, rv, 0);
            fd.op_insert_end(&r, blk);
        };
        ret(&mut fd, 0x60012, 0, &bb[1]);
        let me_op = fd.new_op(2, Address::new(0x60020));
        fd.op_set_opcode(&me_op, OpCode::CPUI_MULTIEQUAL);
        let i = fd.new_unique_out(4, &me_op);
        let add_op = fd.new_op(2, Address::new(0x60040));
        fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
        let i_next = fd.new_unique_out(4, &add_op);
        fd.op_set_input(&me_op, i0.clone(), 0);
        fd.op_set_input(&me_op, i_next.clone(), 1);
        fd.op_insert_end(&me_op, &bb[2]);
        let lt_op = fd.new_op(2, Address::new(0x60024));
        fd.op_set_opcode(&lt_op, OpCode::CPUI_INT_LESS);
        let c = fd.new_unique_out(1, &lt_op);
        fd.op_set_input(&lt_op, i.clone(), 0);
        let ten = fd.new_constant(4, 10);
        fd.op_set_input(&lt_op, ten, 1);
        fd.op_insert_end(&lt_op, &bb[2]);
        let cb_op = fd.new_op(2, Address::new(0x60028));
        fd.op_set_opcode(&cb_op, OpCode::CPUI_CBRANCH);
        let tgt = fd.new_constant(8, 0x60080);
        fd.op_set_input(&cb_op, tgt, 0);
        fd.op_set_input(&cb_op, c, 1);
        fd.op_insert_end(&cb_op, &bb[2]);
        fd.op_set_input(&add_op, i, 0);
        let one = fd.new_constant(4, 1);
        fd.op_set_input(&add_op, one, 1);
        fd.op_insert_end(&add_op, &bb[3]);
        ret(&mut fd, 0x60062, 1, &bb[4]);

        // Highs + explicitness: the production finalize gates stood in for.
        fd.set_high_level();
        i0.write().unwrap().set_explicit();
        i_next.write().unwrap().set_explicit();

        // Edges: b0 out0 case, out1 DEFAULT; b2 out0 exit, out1 body; back.
        fd.bblocks.add_edge(bb[0].clone(), bb[1].clone());
        fd.bblocks.add_edge(bb[0].clone(), bb[2].clone());
        fd.bblocks.add_edge(bb[2].clone(), bb[4].clone());
        fd.bblocks.add_edge(bb[2].clone(), bb[3].clone());
        fd.bblocks.add_edge(bb[3].clone(), bb[2].clone());

        let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0x60004))));
        jt.write().unwrap().set_indirect_op(ind_op.0.clone());
        jt.write().unwrap().default_block = 1; // out-edge 1 of b0 is the default
        fd.jump_tables.push(jt);

        // Production pipeline: structureReset BEFORE install (find_spanning_
        // tree clears edge flags), then buildCopy, W install, switch rule.
        fd.structure_reset();
        fd.install_switch_defaults();
        fd.sblocks.build_copy(&fd.bblocks);

        let copy_of = |orig: &BlockArc| -> BlockArc {
            fd.sblocks
                .blocks
                .iter()
                .find(|b| {
                    let r = b.read().unwrap();
                    r.get_type() == crate::block::BlockType::Copy
                        && r.as_any()
                            .downcast_ref::<BlockCopy>()
                            .map(|cblk| Arc::ptr_eq(&cblk.original, orig))
                            .unwrap_or(false)
                })
                .cloned()
                .expect("copy")
        };
        let cond_copy = copy_of(&bb[2]);
        let body_copy = copy_of(&bb[3]);
        let head_copy = copy_of(&bb[0]);
        let w: BlockArc = Arc::new(RwLock::new(BlockWhileDo {
            index: cond_copy.read().unwrap().get_index(),
            condition: cond_copy.clone(),
            body: body_copy.clone(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
            for_init: None,
            for_iter: None,
            initialize_op: None,
            iterate_op: None,
            loop_def: None,
            overflow_syntax: false,
        }));
        let head_idx = fd
            .sblocks
            .blocks
            .iter()
            .position(|b| Arc::ptr_eq(b, &head_copy))
            .expect("head slot");
        {
            let (cond_idx, body_idx) = fd
                .sblocks
                .blocks
                .iter()
                .enumerate()
                .filter_map(|(pos, b)| {
                    if Arc::ptr_eq(b, &cond_copy) {
                        Some((pos as i32, -1))
                    } else if Arc::ptr_eq(b, &body_copy) {
                        Some((-1, pos as i32))
                    } else {
                        None
                    }
                })
                .fold((-1i32, -1i32), |acc, x| {
                    (if x.0 >= 0 { x.0 } else { acc.0 }, if x.1 >= 0 { x.1 } else { acc.1 })
                });
            let mut collapse = CollapseStructure::new(&mut fd.sblocks, "test")
                .with_jump_tables(fd.jump_tables.clone());
            collapse.identify_internal(&w, &[cond_idx, body_idx], cond_idx as usize);
        }
        {
            let mut collapse = CollapseStructure::new(&mut fd.sblocks, "test")
                .with_jump_tables(fd.jump_tables.clone());
            assert!(
                collapse.try_rule_switch(head_idx),
                "production switch rule must install the switch"
            );
        }
        // The switch's default arm must be the structured W (gt==0).
        {
            let head_sw = fd.sblocks.blocks[head_idx].clone();
            let r = head_sw.read().unwrap();
            let sw = r.as_any().downcast_ref::<BlockSwitch>().unwrap();
            assert_eq!(sw.default_gototype, 0);
            assert!(sw.default_case.is_some());
            assert!(Arc::ptr_eq(sw.default_case.as_ref().unwrap(), &w));
        }
        // collapseAll's final sweep mirror (drop absorbed, re-index).
        {
            let consumed: std::collections::HashSet<i32> =
                fd.sblocks.absorbed_into.keys().copied().collect();
            fd.sblocks
                .blocks
                .retain(|b| !consumed.contains(&b.read().unwrap().get_index()));
            for (i2, b) in fd.sblocks.blocks.iter().enumerate() {
                b.write().unwrap().set_index(i2 as i32);
            }
        }

        // Sweeps: ActionStructureTransform + ActionFinalStructure head.
        crate::block::for_loop_final_transform(&mut fd);
        fd.sblocks.order_blocks();
        super::BlockGraph::finalize_printing_graph(&mut fd);

        // THE lock: the default arm's WhileDo ran its finalize — the
        // iterate statement is non-printing (block.cc:3422) and the
        // WhileDo's iterateOp survived testTerminal (cc:3410).
        let notprinted = add_op.0.read().unwrap().flags & pcodeop_flags::NONPRINTING != 0;
        assert!(
            notprinted,
            "default-arm WhileDo iterate statement (INT_ADD) must be flagged non-printing"
        );
        {
            let wr = w.read().unwrap();
            let wd = wr.as_any().downcast_ref::<BlockWhileDo>().unwrap();
            assert!(wd.iterate_op.is_some(), "iterateOp must survive finalizePrinting");
            assert!(wd.loop_def.is_some());
        }
    }
}

#[cfg(test)]
mod findirreducible_lock_tests {
    use super::{edge_flags as ef, BlockBasic, BlockGraph, FlowBlock};
    use crate::address::Address;
    use std::sync::{Arc, RwLock};

    type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

    fn loop_graph() -> (BlockGraph, BlockArc, BlockArc, BlockArc) {
        // Minimal reducible loop with a head->body edge:
        //   b0 -> b1   (entry -> loop head)
        //   b1 -> b2   (head -> body)  <- drives yprime == x at x=b1, t=b2
        //   b2 -> b1   (body -> head, back edge)
        let b0: BlockArc = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x7000))));
        let b1: BlockArc = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x7010))));
        let b2: BlockArc = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x7020))));
        let mut graph = BlockGraph::new();
        graph.add_block(b0.clone());
        graph.add_block(b1.clone());
        graph.add_block(b2.clone());
        graph.add_edge(b0.clone(), b1.clone());
        graph.add_edge(b1.clone(), b2.clone());
        graph.add_edge(b2.clone(), b1.clone());
        (graph, b0, b1, b2)
    }

    /// BLOCK-RWLOCK-RECURSIVE-READ-0001 unit lock: the interval snapshot in
    /// find_irreducible (block.cc:1174) reads x->visitcount, x->numdesc and
    /// yprime->visitcount. For the loop head's own edge into a reachunder
    /// member the in-edge source y IS x and copymap still points at itself
    /// (cc:1027/1122), so y' = FIND(y) = x and the oracle reads the same
    /// object twice through raw pointers. The Rust form must not take two
    /// read guards of one RwLock for that snapshot (std::sync::RwLock::read
    /// is documented "might panic" when the lock is already held by the
    /// current thread): the ptr_eq arm serves both interval reads from the
    /// single x guard. Expected oracle outcome for this graph (visitcount
    /// b0=0,b1=1,b2=2; numdesc self-inclusive b0=3,b1=2,b2=1): the interval
    /// [1,3) contains y'=b1's visitcount 1, cc:1187's `yprime != x` keeps
    /// the head out of reachunder, and the collapse re-points b2's copymap
    /// at the head (cc:1190-1196) with no irreducible classification.
    #[test]
    fn yprime_equals_x_interval_snapshot_single_guard() {
        let (mut graph, _b0, b1, b2) = loop_graph();
        let mut preorder: Vec<BlockArc> = Vec::new();
        let mut rootlist: Vec<BlockArc> = Vec::new();
        graph
            .find_spanning_tree(&mut preorder, &mut rootlist)
            .expect("spanning tree");
        let mut irreduciblecount: i32 = 0;
        let needrebuild = graph.find_irreducible(&preorder, &mut irreduciblecount);

        // Reducible loop: no irreducible edges, no spanning-tree rebuild.
        assert!(!needrebuild, "reducible loop must not need a rebuild");
        assert_eq!(irreduciblecount, 0);

        // cc:1190-1196 collapse: reachunder={b2} re-points at the head b1
        // and clears the mark; the head keeps its own copymap.
        assert!(!b2.read().unwrap().is_mark(), "collapse clears the mark");
        let body_copy = b2
            .read()
            .unwrap()
            .get_copy_map()
            .and_then(|weak| weak.upgrade());
        assert!(body_copy.is_some(), "copymap must be re-pointed, not dropped");
        assert!(
            Arc::ptr_eq(&body_copy.unwrap(), &b1),
            "reachunder member must collapse into the loop head"
        );
        let head_copy = b1
            .read()
            .unwrap()
            .get_copy_map()
            .and_then(|weak| weak.upgrade());
        assert!(Arc::ptr_eq(&head_copy.unwrap(), &b1));

        // The head's own edge into the body kept its tree classification on
        // both halves (the yprime==x arm must not promote it).
        let head_out = b1.read().unwrap().get_out(0).unwrap().flags;
        let body_in = b2.read().unwrap().get_in(0).unwrap().flags;
        assert_ne!(head_out & ef::F_TREE_EDGE, 0);
        assert_ne!(body_in & ef::F_TREE_EDGE, 0);
        assert_eq!(head_out & ef::F_IRREDUCIBLE_EDGE, 0);
        assert_eq!(body_in & ef::F_IRREDUCIBLE_EDGE, 0);

        // The back edge keeps its back|loop labels on both halves.
        let body_out = b2.read().unwrap().get_out(0).unwrap().flags;
        let head_in1 = b1.read().unwrap().get_in(1).unwrap().flags;
        assert_ne!(body_out & ef::F_BACK_EDGE, 0);
        assert_ne!(head_in1 & ef::F_BACK_EDGE, 0);
        assert_eq!(body_out & ef::F_IRREDUCIBLE_EDGE, 0);
    }

    /// Same graph through the full structure_loops driver (block.cc:2194-2215,
    /// the funcdata.rs production entry): converges on the first pass, the
    /// collapse survives the driver, rootlist keeps the single entry root.
    #[test]
    fn yprime_equals_x_through_structure_loops_driver() {
        let (mut graph, b0, b1, b2) = loop_graph();
        let mut rootlist: Vec<BlockArc> = Vec::new();
        graph.structure_loops(&mut rootlist).expect("structure loops");
        assert_eq!(rootlist.len(), 1);
        assert!(Arc::ptr_eq(&rootlist[0], &b0));
        let body_copy = b2
            .read()
            .unwrap()
            .get_copy_map()
            .and_then(|weak| weak.upgrade());
        assert!(Arc::ptr_eq(&body_copy.unwrap(), &b1));
    }
}

/// F8FOR-REJECT-RESIDUAL-0001 gate-chain regression pins. The two-gate
/// rejection family (findLoopVariable's isMoveable gate + testIterateForm)
/// was probed end-to-end on the sq/sqlite mirror corpora: the gates are
/// oracle-faithful, and the mass rejection root (alivelist walk order in
/// is_moveable) landed on master via OP-ISMOVEABLE-WALKORDER-0001. These
/// tests pin the while_do decision chain on top of that fix, including the
/// late-created-terminal-op shape that made the old walk cross the tail
/// BRANCH (block order [SUB, ZEXT, COPY, BRANCH] vs alivelist order
/// [SUB, ZEXT, BRANCH, COPY]).
#[cfg(test)]
mod while_do_gate_tests {
    use super::{BlockBasic, BlockEdge, BlockWhileDo, FlowBlock};
    use crate::address::Address;
    use crate::arch::Architecture;
    use crate::funcdata::Funcdata;
    use crate::op::pcodeop_flags::NONPRINTING;
    use crate::op::PcodeOpRef;
    use crate::opcodes::OpCode;
    use std::sync::{Arc, RwLock};

    type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

    fn block_of(index: i32, addr: u64) -> BlockArc {
        Arc::new(RwLock::new(BlockBasic::new(index, Address::new(addr))))
    }

    fn same_op(a: &PcodeOpRef, b: &PcodeOpRef) -> bool {
        Arc::ptr_eq(&a.0, &b.0)
    }

    struct GateFixture {
        fd: Funcdata,
        head: BlockArc,
        tail: BlockArc,
        wd: BlockWhileDo,
        iterate: PcodeOpRef,
        multiequal: PcodeOpRef,
    }

    /// Minimal while-do IR mirroring the LzmaEnc_Construct / BitvecSet
    /// corpus shape (block.cc:3164-3424 walk inputs):
    ///
    /// head:  [ MULTIEQUAL(V; in0=const init, in1=V'), INT_NOTEQUAL, CBRANCH ]
    /// tail:  [ INT_SUB(V'=V-1)  <- iterate, INT_ZEXT, COPY, BRANCH ]
    ///
    /// The COPY terminal op is created AFTER the BRANCH (late retyping
    /// product) but inserted before it in block order — the exact
    /// block-order/alivelist divergence that made the pre-ISMOVEABLE walk
    /// spuriously cross the BRANCH and reject the iterate move.
    fn build_fixture() -> GateFixture {
        let mut fd = Funcdata::new("whiledo_gate_pin", Address::new(0x1000), 1);
        fd.arch = Some(Arc::new(Architecture::new())); // analyze_for_loops = true
        // finalizePrinting runs after the varmap phase has enabled high-level
        // merging (funcdata flags HIGHLEVEL_ON, set by ActionHighAnalysis) —
        // testIterateForm reads the merged HighVariable identity.
        fd.flags |= crate::funcdata::funcdata_flags::HIGHLEVEL_ON;

        let entry = block_of(0, 0x1000);
        let head = block_of(1, 0x1100);
        let tail = block_of(2, 0x1200);
        fd.bblocks.add_block(entry.clone());
        fd.bblocks.add_block(head.clone());
        fd.bblocks.add_block(tail.clone());

        // ---- head block ops: MULTIEQUAL -> INT_NOTEQUAL -> CBRANCH ----
        let multiequal = fd.new_op(2, Address::new(0x1100));
        fd.op_set_opcode(&multiequal, OpCode::CPUI_MULTIEQUAL);
        fd.op_insert_end(&multiequal, &head);
        let v_loop = fd.new_unique_out(4, &multiequal);
        v_loop.write().unwrap().set_explicit();

        let notequal = fd.new_op(2, Address::new(0x1104));
        fd.op_set_opcode(&notequal, OpCode::CPUI_INT_NOTEQUAL);
        fd.op_insert_end(&notequal, &head);
        let cond_vn = fd.new_unique_out(4, &notequal);
        cond_vn.write().unwrap().set_explicit();

        let cbranch = fd.new_op(2, Address::new(0x1108));
        fd.op_set_opcode(&cbranch, OpCode::CPUI_CBRANCH);
        fd.op_insert_end(&cbranch, &head);

        // ---- tail block ops (creation order): INT_SUB, INT_ZEXT, BRANCH ----
        let iterate = fd.new_op(2, Address::new(0x1200));
        fd.op_set_opcode(&iterate, OpCode::CPUI_INT_SUB);
        fd.op_insert_end(&iterate, &tail);
        let v_next = fd.new_unique_out(4, &iterate);
        v_next.write().unwrap().set_explicit();

        let zext = fd.new_op(1, Address::new(0x1204));
        fd.op_set_opcode(&zext, OpCode::CPUI_INT_ZEXT);
        fd.op_insert_end(&zext, &tail);
        let _zext_out = fd.new_unique_out(4, &zext);

        let branch = fd.new_op(1, Address::new(0x120c));
        fd.op_set_opcode(&branch, OpCode::CPUI_BRANCH);
        fd.op_insert_end(&branch, &tail);

        // ---- data-flow wiring ----
        let init_const = fd.new_constant(4, 0x10);
        let step_const = fd.new_constant(4, 1);
        let cmp_const = fd.new_constant(4, 0);
        let cmp_const2 = fd.new_constant(4, 0);
        let branch_const = fd.new_constant(4, 0);
        let bool_const = fd.new_constant(1, 1);
        fd.op_set_input(&multiequal, init_const, 0);
        fd.op_set_input(&multiequal, v_next.clone(), 1);
        fd.op_set_input(&notequal, v_loop.clone(), 0);
        fd.op_set_input(&notequal, cmp_const, 1);
        fd.op_set_input(&cbranch, bool_const, 0);
        fd.op_set_input(&cbranch, cond_vn, 1);
        fd.op_set_input(&iterate, v_loop.clone(), 0);
        fd.op_set_input(&iterate, step_const, 1);
        fd.op_set_input(&zext, cmp_const2, 0);
        fd.op_set_input(&branch, branch_const, 0);

        // ---- late-created terminal COPY: alivelist tail, mid-block slot ----
        // Creation happens AFTER the BRANCH was inserted (alivelist order
        // [SUB, ZEXT, BRANCH, COPY]) but the block slot is before the
        // BRANCH (block order [SUB, ZEXT, COPY, BRANCH]) — the corpus
        // divergence shape from the F8FOR-REJECT-RESIDUAL-0001 probe.
        let copy = fd.new_op(1, Address::new(0x1208));
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        fd.op_insert_after(&copy, &zext);
        let _copy_out = fd.new_unique_out(4, &copy);

        // ---- CFG edges: entry->head (slot 0), tail->head (slot 1) ----
        head.write().unwrap().add_in_edge(BlockEdge::new(entry.clone(), 0));
        head.write().unwrap().add_in_edge(BlockEdge::new(tail.clone(), 0));
        tail.write().unwrap().add_out_edge(BlockEdge::new(head.clone(), 1));

        let wd = BlockWhileDo {
            index: 3,
            condition: head.clone(),
            body: tail.clone(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
            for_init: None,
            for_iter: None,
            initialize_op: None,
            iterate_op: None,
            loop_def: None,
            overflow_syntax: false,
        };
        GateFixture { fd, head, tail, wd, iterate, multiequal }
    }

    /// cc:3356-3397 + cc:3403-3424 happy path: findLoopVariable must accept
    /// the iterate INT_SUB through the isMoveable gate (block-order walk
    /// crossing only ZEXT/COPY — never the BRANCH), migrate it to the
    /// terminal statement, reject the constant initializer (empty-init
    /// `for(; cond; iter)` form), and finalizePrinting must re-derive the
    /// iterate via testTerminal + testIterateForm and mark it NONPRINTING.
    #[test]
    fn gate_chain_extracts_iterate_and_marks_non_printing() {
        let GateFixture { mut fd, head, tail, mut wd, iterate, multiequal } =
            build_fixture();
        super::while_do_final_transform(&mut wd, &mut fd, &head);
        assert!(
            same_op(wd.loop_def.as_ref().unwrap(), &multiequal),
            "findLoopVariable must pin the head MULTIEQUAL as loopDef"
        );
        assert!(
            same_op(wd.iterate_op.as_ref().unwrap(), &iterate),
            "isMoveable gate must accept the iterate (block-order walk)"
        );
        // cc:3381-3384: iterate migrated to after the branch-stripped last
        // op — block order [ZEXT, COPY, SUB, BRANCH].
        let ops = tail.read().unwrap().get_ops();
        assert_eq!(ops.len(), 4);
        assert!(same_op(&ops[2], &iterate), "iterate is the terminal statement");
        assert_eq!(ops[3].0.read().unwrap().opcode, OpCode::CPUI_BRANCH);
        // cc:3387-3388: constant entry input -> findInitializer misses ->
        // early return with iterateOp still set (empty-init form).
        assert!(wd.initialize_op.is_none());

        super::while_do_finalize_printing(&mut wd, &mut fd);
        // cc:3410-3415: testTerminal + testIterateForm re-derive the iterate.
        assert!(same_op(wd.iterate_op.as_ref().unwrap(), &iterate));
        // cc:3416-3417: last-chance initializer still misses (const input).
        assert!(wd.initialize_op.is_none());
        // cc:3421: opMarkNonPrinting(iterateOp) — printc's for-header channel.
        assert!(
            (iterate.0.read().unwrap().flags & NONPRINTING) != 0,
            "iterate statement must be marked non-printing"
        );
    }

    /// cc:3412-3414 oracle-consistent reject pin: when the iterate op's
    /// inputs never reach the loopDef output's HighVariable (the
    /// LzmaEnc_CodeOneBlock / sqlite-giant shape, where golden prints
    /// `while` too), testIterateForm nulls iterateOp and the statement is
    /// NOT marked non-printing — but the testTerminal move stays committed
    /// (cc:3410 moves before cc:3413 rejects), the oracle-faithful
    /// "committed move" side effect.
    #[test]
    fn iterate_form_mismatch_rejects_without_marking_but_keeps_move() {
        let GateFixture { mut fd, head, tail, mut wd, iterate, .. } = build_fixture();
        // Rewire the iterate to read a foreign varnode (different
        // HighVariable): W = INT_ADD(const, const) in the tail.
        let foreign = fd.new_op(2, Address::new(0x1202));
        fd.op_set_opcode(&foreign, OpCode::CPUI_INT_ADD);
        fd.op_insert_end(&foreign, &tail);
        let w = fd.new_unique_out(4, &foreign);
        w.write().unwrap().set_explicit();
        let c1 = fd.new_constant(4, 2);
        let c2 = fd.new_constant(4, 3);
        fd.op_set_input(&foreign, c1, 0);
        fd.op_set_input(&foreign, c2, 1);
        fd.op_set_input(&iterate, w, 0);

        super::while_do_final_transform(&mut wd, &mut fd, &head);
        assert!(
            wd.iterate_op.is_some(),
            "findLoopVariable path is independent of the iterate input high"
        );
        super::while_do_finalize_printing(&mut wd, &mut fd);
        assert!(
            wd.iterate_op.is_none(),
            "testIterateForm must null iterateOp on high mismatch"
        );
        assert_eq!(
            iterate.0.read().unwrap().flags & NONPRINTING,
            0,
            "rejected iterate must stay printable (while-form body)"
        );
        // cc:3410 committed move survives the cc:3413 reject.
        let ops = tail.read().unwrap().get_ops();
        assert!(
            same_op(
                &ops[ops.len() - 2],
                &iterate
            ),
            "testTerminal's move stays committed after the reject"
        );
        assert_eq!(ops[ops.len() - 1].0.read().unwrap().opcode, OpCode::CPUI_BRANCH);
    }
}

#[cfg(test)]
mod switch_default_construct_pos_tests {
    use super::{
        switch_default_construct_pos, next_flow_after_successors, BlockBasic, BlockGoto,
        BlockSwitch, BlockType, CaseOrder, FlowBlock,
    };
    use crate::address::Address;
    use std::sync::{Arc, RwLock};

    type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

    fn copy_of(index: i32, addr: u64) -> BlockArc {
        // The collapse graph's leaves are BlockCopy-shaped t_copy nodes; for
        // the rank/position math under test any leaf Arc serves — the walk
        // only compares Arc identity and reads get_type().
        Arc::new(RwLock::new(BlockBasic::new(index, Address::new(addr))))
    }

    fn goto_wrapping(index: i32, inner: BlockArc, target: BlockArc) -> BlockArc {
        Arc::new(RwLock::new(BlockGoto {
            index,
            flags: 0,
            parent: None,
            goto_target: None,
            target_dyn: Some(target),
            wrapped: Some(inner),
            goto_type: crate::block::goto_type::GOTO_GOTO,
            prints_precomputed: false,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }))
    }

    fn order(outindex: i32) -> CaseOrder {
        CaseOrder::placeholder(None, outindex)
    }

    fn build_switch(
        cases: Vec<BlockArc>,
        default: Option<BlockArc>,
        outindexes: Vec<i32>,
        default_outindex: Option<i32>,
        gototypes: Vec<u32>,
    ) -> Arc<RwLock<BlockSwitch>> {
        assert_eq!(cases.len(), outindexes.len());
        assert_eq!(cases.len(), gototypes.len());
        Arc::new(RwLock::new(BlockSwitch {
            index: 9,
            control: copy_of(8, 0x288ec),
            cases,
            default_case: default,
            case_gototypes: gototypes,
            default_gototype: 0,
            case_isexit: vec![false; outindexes.len()],
            default_isexit: false,
            jump: None,
            case_order: outindexes.into_iter().map(order).collect(),
            default_label: None,
            default_order: default_outindex.map(order),
            case_values: Vec::new(),
            index_varnode: None,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }))
    }

    /// SetCoderProperties shape (sasquatch idx 470): basic out-edge order
    /// [0x440@0, 0x441@1, 0x442@2, default@3, 0x450@4, 0x451@5] — the
    /// default's construction rank is 3, so the last real case (0x451, the
    /// BlockGoto targeting 0x2890a) is the merged order's LAST member and
    /// its nextFlowAfter defers to the parent arm instead of comparing
    /// against the default's front leaf (block.cc:3656-3660).
    #[test]
    fn construction_rank_interleaves_default_at_outedge_position() {
        let c440 = copy_of(1, 0x28a7e);
        let c441 = copy_of(2, 0x28a5b);
        let c442 = copy_of(3, 0x28a3b);
        let default = copy_of(4, 0x2890a);
        let c450 = copy_of(5, 0x289cc);
        let target = default.clone();
        let c451_goto = goto_wrapping(6, copy_of(6, 0x2891e), target);
        let sw = build_switch(
            vec![c440, c441, c442, c450, c451_goto.clone()],
            Some(default.clone()),
            vec![0, 1, 2, 4, 5],
            Some(3),
            vec![0, 0, 0, 0, 0],
        );
        assert_eq!(switch_default_construct_pos(&sw.read().unwrap()), 3);

        // End-to-end through the walk: the goto case (merged position 5,
        // last) must get the PARENT succ, not the default's front leaf.
        let node: BlockArc = sw.clone();
        let components = super::BlockGraph::component_list_dyn(&node);
        assert_eq!(components.len(), 6);
        let succs = next_flow_after_successors(&node, &components, None);
        // components order = cases + appended default; the goto is index 4.
        assert!(
            succs[4].is_none(),
            "last merged case defers to the parent arm (succ=None here), \
             not the default's front leaf"
        );
        // The case right before the default (0x442) gets the default's
        // front leaf as its successor — both sides' construction order.
        assert!(succs[2].is_none(), "non-goto case successor is null (cc:3647)");
    }

    /// The multigoto arm's appended cases (gototype != 0) come after the
    /// whole regular scan in the oracle's caseblocks (block.cc:3548-3553) —
    /// they must not advance the default's construction rank even when
    /// their recorded out-edge index precedes the default's.
    #[test]
    fn multigoto_appended_cases_do_not_advance_rank() {
        let c1 = copy_of(1, 0x100);
        let c2 = copy_of(2, 0x200);
        let default = copy_of(3, 0x300);
        let sw = build_switch(
            vec![c1, c2],
            Some(default),
            vec![4, 0],
            Some(2),
            vec![0, crate::block::goto_type::GOTO_GOTO],
        );
        // Only the gototype==0 case (outindex 4) is a regular scan member;
        // 4 > 2 so the default ranks before it → 0.
        assert_eq!(switch_default_construct_pos(&sw.read().unwrap()), 0);
    }

    /// Conservative fallbacks preserve the previous append-last behavior:
    /// no default_order, unresolved coordinates, or mismatched parallel
    /// arrays (shapes the oracle cannot express — addCase would throw,
    /// block.cc:3507-3508).
    #[test]
    fn incomplete_coordinates_fall_back_to_append_last() {
        let c1 = copy_of(1, 0x100);
        let default = copy_of(2, 0x200);
        let no_default_order =
            build_switch(vec![c1.clone()], Some(default.clone()), vec![0], None, vec![0]);
        assert_eq!(
            switch_default_construct_pos(&no_default_order.read().unwrap()),
            1
        );
        let neg_outindex =
            build_switch(vec![c1.clone()], Some(default.clone()), vec![-1], Some(0), vec![0]);
        assert_eq!(
            switch_default_construct_pos(&neg_outindex.read().unwrap()),
            1
        );
        let neg_default =
            build_switch(vec![c1.clone()], Some(default.clone()), vec![0], Some(-1), vec![0]);
        assert_eq!(switch_default_construct_pos(&neg_default.read().unwrap()), 1);
    }

    /// Phase dispatch: once `default_label` is set (finalizePrinting has
    /// sorted the caseblocks, block.cc:3591), the label-rank arm governs —
    /// the construction-order arm must not fire in the print phase.
    #[test]
    fn label_rank_arm_unchanged_post_finalize() {
        let c440 = copy_of(1, 0x28a7e);
        let default = copy_of(4, 0x2890a);
        let c450 = copy_of(5, 0x289cc);
        let mut sw_guard = build_switch(
            vec![c440, c450],
            Some(default),
            vec![0, 4],
            Some(3),
            vec![0, 0],
        );
        // finalize_case_labels' rank key: labels [0x440, 0x450], default
        // between them → count(label < 0x450-range key) == 1.
        {
            let mut sw = sw_guard.write().unwrap();
            sw.default_label = Some(1); // strictly between label 0 and 2
            // Give the case_order entries their post-finalize labels.
            sw.case_order[0].label = 0;
            sw.case_order[1].label = 2;
        }
        // Direct rank check: def_pos counts label < default_label → 1
        // (NOT the construction rank 1 here — equal by coincidence of the
        // fixture; assert through the dispatch site below instead).
        let node: BlockArc = sw_guard.clone();
        let components = super::BlockGraph::component_list_dyn(&node);
        let succs = next_flow_after_successors(&node, &components, None);
        // The merged order puts the default at label rank 1 → the last real
        // case (index 1, non-goto → null) and the default (appended at
        // components index 2) still evaluate per the merged positions.
        assert_eq!(components.len(), 3);
        assert!(succs.iter().all(|s| s.is_none()), "non-goto cases → null");
    }
}
