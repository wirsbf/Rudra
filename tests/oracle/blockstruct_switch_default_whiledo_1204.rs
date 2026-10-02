//! BLOCK-FINALIZE-DEFAULT-RECURSE-0001: Rugra comparand for the locked
//! Ghidra 12.0.4 finalizePrinting-recursion oracle over a switch default
//! arm (block.cc:3556-3559 BlockSwitch::finalizePrinting ->
//! block.cc:1364-1371 BlockGraph::finalizePrinting ->
//! block.cc:3403-3424 BlockWhileDo::finalizePrinting).
//!
//! Mirrors tests/oracle/blockstruct_switch_default_whiledo_1204.cc case
//! for case: the same synthetic function (switch head carrying the
//! for-initializer COPY + BRANCHIND, one RETURN case, and a default edge
//! into a while-loop `i = MULTIEQUAL(i0, i_next); c = INT_LESS(i, 10);
//! CBRANCH` / `i_next = INT_ADD(i, 1)`), driven through the production
//! Funcdata/BlockGraph APIs and the production sweeps
//! (ActionBlockStructure install + ActionStructureTransform +
//! ActionFinalStructure head). The observation is the same sorted fact
//! lines: structure tree node facts + per-block op notPrinted flags.
//!
//! THE DEFECT THIS FIXTURE LOCKS: Rugra's finalize_printing_block Switch
//! arm used to walk control + gototype==0 cases only, skipping the
//! default_case slot — the WhileDo inside the default arm never ran
//! BlockWhileDo::finalizePrinting, so its iterate statement (INT_ADD)
//! stayed printable (for -> while degradation). The oracle's plain
//! component-list recursion (block.cc:3559) always reaches the default
//! arm member: `op blk2#0 INT_ADD notprinted=1` is the decisive line.
//!
//! Structure install (both sides): the corpus has no switch whose
//! default arm carries a loop (the latent-defect premise), and a single
//! CollapseStructure run consumes the raw default target before the loop
//! can form under it (ruleSwitch's obvious-exit scan takes any 2-in
//! successor). The tree is installed through the production factories in
//! the order the collapse rules produce when W forms first: the
//! newBlockWhileDo component install (blockaction.cc:1526-1546 ->
//! block.cc:1856-1868; Rust CollapseStructure::identify_internal over a
//! BlockWhileDo), then ruleBlockSwitch's full production install
//! (Rugra CollapseStructure::try_rule_switch — grab_case_order +
//! identify_internal + case reference update, blockaction.cc:1714-1721 /
//! block.cc:1904-1919). finalize_printing_graph itself runs unmodified.
//!
//! Order-sensitive mirror details (see the .cc):
//!   - structureReset runs BEFORE install_switch_defaults:
//!     structure_loops -> find_spanning_tree clears ALL edge flags
//!     (block.cc:1047 clearEdgeFlags(~0)), so the default-edge mark must
//!     land after the reset, like production.
//!   - Copies resolve through the original->copy mirror (Rugra: scan
//!     sblocks for BlockCopy.original identity) — structure_loops
//!     reordered the list into reverse post order, so positional indices
//!     are NOT creation indices.
//!   - i0/i_next carry set_explicit() standing in for varmap's
//!     explicitness marking (testTerminal gate, block.cc:3231).
//!   - The oracle's own findInitializer gate rejects this shape
//!     (`Initializer block must flow only to for loop`, block.cc:3336:
//!     the initializer COPY lives in the 2-out-edge switch head), so
//!     initialize stays `-` on BOTH sides — the iterate mark is the
//!     fixture's decisive observable.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{
    BlockBasic, BlockCopy, BlockGraph, BlockSwitch, BlockType, BlockWhileDo, FlowBlock,
};
use rudra::blockaction::CollapseStructure;
use rudra::funcdata::Funcdata;
use rudra::jumptable::JumpTable;
use rudra::op::pcodeop_flags;
use rudra::opcodes::OpCode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn type_name(bt: BlockType) -> &'static str {
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

/// Oracle get_opname rendering: Ghidra 12 renamed MULTIEQUAL to BUILD
/// (typeop.cc:1945 TypeOpMulti); Rugra's opcode table keeps the P-code
/// spelling — normalized here (registered in the fixture metadata).
fn op_name(opc: OpCode) -> &'static str {
    match opc {
        OpCode::CPUI_MULTIEQUAL => "BUILD",
        other => other.name(),
    }
}

fn op_not_printed(op: &rudra::op::PcodeOpRef) -> u32 {
    let o = op.0.read().unwrap();
    let mask = pcodeop_flags::MARKER | pcodeop_flags::NONPRINTING
        | pcodeop_flags::NORETURN;
    if (o.flags & mask) != 0 {
        1
    } else {
        0
    }
}

fn children_of(bl: &BlockRef) -> Vec<BlockRef> {
    // The C++ walk recurses getBlock(i) over BlockGraph members. Rugra's
    // parallel model: Switch = control + cases + default_case (the
    // members identify_internal consumed); WhileDo = condition + body;
    // BlockList/If/... via component_list_dyn; copies are leaves.
    let r = bl.read().unwrap();
    let ty = r.get_type();
    let any = r.as_any();
    match ty {
        BlockType::Switch => {
            let sw = any.downcast_ref::<BlockSwitch>().unwrap();
            let mut v = vec![sw.control.clone()];
            v.extend(sw.cases.iter().cloned());
            if let Some(dc) = &sw.default_case {
                v.push(dc.clone());
            }
            v
        }
        BlockType::WhileDo => {
            let wd = any.downcast_ref::<BlockWhileDo>().unwrap();
            vec![wd.condition.clone(), wd.body.clone()]
        }
        BlockType::Copy | BlockType::Basic => Vec::new(),
        _ => BlockGraph::component_list_dyn(bl),
    }
}

fn collect_tree_lines(bl: &BlockRef, lines: &mut Vec<String>) {
    let r = bl.read().unwrap();
    let ty = r.get_type();
    let any = r.as_any();
    match ty {
        BlockType::WhileDo => {
            let wd = any.downcast_ref::<BlockWhileDo>().unwrap();
            let fmt = |o: &Option<rudra::op::PcodeOpRef>| -> String {
                o.as_ref()
                    .map(|x| op_name(x.0.read().unwrap().opcode).to_string())
                    .unwrap_or_else(|| "-".to_string())
            };
            lines.push(format!(
                "node whiledo iterate={} initialize={} loopdef={}",
                fmt(&wd.iterate_op),
                fmt(&wd.initialize_op),
                fmt(&wd.loop_def)
            ));
        }
        BlockType::Switch => {
            let sw = any.downcast_ref::<BlockSwitch>().unwrap();
            let mut member_types: Vec<&'static str> =
                children_of(bl).iter().map(|c| type_name(c.read().unwrap().get_type())).collect();
            member_types.sort_unstable();
            // The oracle keeps the default as an ordinary CaseOrder member
            // (caseblocks entry tagged isdefault, block.cc:3515); Rugra's
            // separate default slot contributes the same counts.
            let default_present = sw.default_case.is_some();
            let caseblocks = sw.case_order.len() + usize::from(default_present);
            lines.push(format!(
                "node switch members={} caseblocks={} defaultcases={}",
                member_types.join(","),
                caseblocks,
                usize::from(default_present)
            ));
        }
        _ => lines.push(format!("node {}", type_name(ty))),
    }
    for child in children_of(bl) {
        collect_tree_lines(&child, lines);
    }
}

/// Find the sblocks copy mirroring the given original basic block
/// (buildCopy's copymap walk, block.cc:1930).
fn copy_of(graph: &BlockGraph, original: &BlockRef) -> Option<BlockRef> {
    for bl in &graph.blocks {
        let r = bl.read().unwrap();
        if r.get_type() == BlockType::Copy {
            if let Some(c) = r.as_any().downcast_ref::<BlockCopy>() {
                if Arc::ptr_eq(&c.original, original) {
                    return Some(bl.clone());
                }
            }
        }
    }
    None
}

fn main() {
    let mut fd = Funcdata::new("f", Address::new(0x60000), 0x100);
    fd.set_arch(Arc::new(Architecture::new()));

    let mut bb: Vec<BlockRef> = Vec::new();
    let addrs = [0x60000u64, 0x60010, 0x60020, 0x60040, 0x60060];
    for (i, a) in addrs.iter().enumerate() {
        let bl: BlockRef = Arc::new(RwLock::new(BlockBasic::new(i as i32, Address::new(*a))));
        fd.bblocks.add_block(bl.clone());
        bb.push(bl);
    }

    // b0: i0 = COPY 0;  BRANCHIND x
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
    // b1: RETURN
    let ret1 = fd.new_op(1, Address::new(0x60012));
    fd.op_set_opcode(&ret1, OpCode::CPUI_RETURN);
    let rv0 = fd.new_constant(1, 0);
    fd.op_set_input(&ret1, rv0, 0);
    fd.op_insert_end(&ret1, &bb[1]);
    // b2: i = MULTIEQUAL(i0, i_next); c = INT_LESS(i, 10); CBRANCH
    let me_op = fd.new_op(2, Address::new(0x60020));
    fd.op_set_opcode(&me_op, OpCode::CPUI_MULTIEQUAL);
    let i = fd.new_unique_out(4, &me_op);
    let add_op = fd.new_op(2, Address::new(0x60040)); // early: i_next feeds the MULTIEQUAL
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
    let target = fd.new_constant(8, 0x60080);
    fd.op_set_input(&cb_op, target, 0);
    fd.op_set_input(&cb_op, c, 1);
    fd.op_insert_end(&cb_op, &bb[2]);
    // b3: i_next = INT_ADD(i, 1)
    let one = fd.new_constant(4, 1);
    fd.op_set_input(&add_op, i, 0);
    fd.op_set_input(&add_op, one, 1);
    fd.op_insert_end(&add_op, &bb[3]);
    // b4: RETURN
    let ret2 = fd.new_op(1, Address::new(0x60062));
    fd.op_set_opcode(&ret2, OpCode::CPUI_RETURN);
    let rv1 = fd.new_constant(1, 1);
    fd.op_set_input(&ret2, rv1, 0);
    fd.op_insert_end(&ret2, &bb[4]);

    // Production runs finalizePrinting after HighVariable merging; the
    // highlevel_on gate stands in for that phase (setHighLevel assigns
    // every Varnode a HighVariable, funcdata_varnode.cc:48-56/600).
    fd.set_high_level();

    // Explicitness: varmap's marking stood in for (testTerminal gate).
    i0.write().unwrap().set_explicit();
    i_next.write().unwrap().set_explicit();

    // Edges (order fixes slot semantics) — same order as the .cc.
    fd.bblocks.add_edge(bb[0].clone(), bb[1].clone()); // b0 out0: case
    fd.bblocks.add_edge(bb[0].clone(), bb[2].clone()); // b0 out1: DEFAULT (b2 in0)
    fd.bblocks.add_edge(bb[2].clone(), bb[4].clone()); // b2 out0: loop exit (fallthru)
    fd.bblocks.add_edge(bb[2].clone(), bb[3].clone()); // b2 out1: loop body (true)
    fd.bblocks.add_edge(bb[3].clone(), bb[2].clone()); // b3 out0: back edge (b2 in1)

    // bb[0] carries SWITCH_OUT automatically when the BRANCHIND lands
    // (BlockBasic::insert, block.cc:2394-2396; Rugra funcdata op insert
    // mirrors). The jumptable-recovery stand-in is the registered table:
    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0x60004))));
    jt.write().unwrap().set_indirect_op(ind_op.0.clone());
    jt.write().unwrap().default_block = 1; // out-edge 1 of bb[0] is the default
    fd.jump_tables.push(jt);

    // ActionBlockStructure (blockaction.cc:2170-2183). structureReset
    // FIRST: find_spanning_tree clears all edge flags, so the default-edge
    // mark lands after the reset, like production.
    fd.structure_reset();
    fd.install_switch_defaults();
    fd.sblocks.build_copy(&fd.bblocks);

    // ruleBlockWhileDo's component install (block.cc:1856-1868): W over
    // [cond copy, body copy] through the production identify_internal.
    let cond_copy = copy_of(&fd.sblocks, &bb[2]).expect("cond copy");
    let body_copy = copy_of(&fd.sblocks, &bb[3]).expect("body copy");
    let w: BlockRef = Arc::new(RwLock::new(BlockWhileDo {
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
    let head_copy = copy_of(&fd.sblocks, &bb[0]).expect("head copy");
    let head_idx = fd
        .sblocks
        .blocks
        .iter()
        .position(|b| Arc::ptr_eq(b, &head_copy))
        .expect("head slot");
    {
        let cond_idx = fd
            .sblocks
            .blocks
            .iter()
            .position(|b| Arc::ptr_eq(b, &cond_copy))
            .expect("cond slot") as i32;
        let body_idx = fd
            .sblocks
            .blocks
            .iter()
            .position(|b| Arc::ptr_eq(b, &body_copy))
            .expect("body slot") as i32;
        let cond_slot = cond_idx as usize;
        let mut collapse =
            CollapseStructure::new(&mut fd.sblocks, "f").with_jump_tables(fd.jump_tables.clone());
        collapse.identify_internal(&w, &[cond_idx, body_idx], cond_slot);
    }
    // ruleBlockSwitch's full production install over cs=[head, caseA, W]:
    // default routing via the installSwitchDefaults-marked original edge.
    {
        let mut collapse =
            CollapseStructure::new(&mut fd.sblocks, "f").with_jump_tables(fd.jump_tables.clone());
        if !collapse.try_rule_switch(head_idx) {
            eprintln!("try_rule_switch failed to install the switch");
            std::process::exit(3);
        }
    }

    // collapseAll's final sweep (blockaction.rs finalize_structure, the
    // stand-in for Ghidra's incremental list compaction block.cc:953-960):
    // drop blocks absorbed into composites and re-index survivors. The
    // hand-installed tree skipped collapse_all, so the fixture mirrors the
    // sweep on the pub fields (absorbed_into + re-index), byte-for-byte the
    // same retain/set_index body.
    {
        let consumed: std::collections::HashSet<i32> =
            fd.sblocks.absorbed_into.keys().copied().collect();
        fd.sblocks.blocks.retain(|b| {
            let idx = b.read().unwrap().get_index();
            !consumed.contains(&idx)
        });
        for (i, b) in fd.sblocks.blocks.iter().enumerate() {
            b.write().unwrap().set_index(i as i32);
        }
    }

    // ActionStructureTransform (blockaction.cc:2109-2115).
    rudra::block::for_loop_final_transform(&mut fd);
    // ActionFinalStructure head (blockaction.cc:2185-2192).
    fd.sblocks.order_blocks();
    rudra::block::BlockGraph::finalize_printing_graph(&mut fd);

    // ---- Observation (identical format to the .cc) ----
    let mut lines: Vec<String> = Vec::new();
    println!("case switch_default_whiledo");
    let analyze_for_loops = fd
        .arch
        .as_ref()
        .map(|a| a.analyze_for_loops)
        .unwrap_or(false);
    println!("analyze_for_loops={}", usize::from(analyze_for_loops));
    println!("structure_roots={}", fd.sblocks.blocks.len());
    for root in fd.sblocks.blocks.clone() {
        collect_tree_lines(&root, &mut lines);
    }
    for (b, blk) in fd.bblocks.blocks.iter().enumerate() {
        for (ordinal, op) in blk.read().unwrap().get_ops().iter().enumerate() {
            let name = op_name(op.0.read().unwrap().opcode);
            lines.push(format!(
                "op blk{}#{} {} notprinted={}",
                b,
                ordinal,
                name,
                op_not_printed(op)
            ));
        }
    }
    lines.sort();
    for l in &lines {
        println!("{}", l);
    }
    println!("end");
}
