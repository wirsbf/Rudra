// BLOCKSTRUCT-MULTIGOTO-0001: Rugra comparand for the locked Ghidra 12.0.4
// BlockMultiGoto oracle (block.hh:573-593, block.cc:1720-1753
// newBlockMultiGoto / 2918-2951 scopeBreak; blockaction.cc:1456-1458
// ruleBlockGoto isSwitchOut arm). Mirrors blockmultigoto_1204.cc case for
// case:
//  - family A drives the production collapse_all (the rule path);
//  - family A2 (loop_exit_conflict, B2-MG-RESID-2) builds WhileDo[cond=h,
//    body=List[mg(s), gt(t→e)]] through literals over a production
//    new_block_multigoto peel, then scope_break(-1,-1) + compute_goto_prints
//    — BlockGoto gets promoted to BREAK_GOTO while the multigoto's
//    gotoedges are never reclassified (block.cc:2918-2922);
//  - family B calls new_block_multigoto directly (the pure-function
//    contract: pre-mutation isDefaultBranch capture, identifyInternal
//    self-edge absorption + forceOutputNum(sizeOut()+1) restore, the
//    already-t_multigoto addEdge branch, setDefaultGoto, bilateral
//    removeEdge, scopeBreak's -1 curexit discard);
//  - family C (copy_switch_consumption, B2-MG-RESID-1) mirrors
//    newBlockSwitch's recording over cs=[mg, cA, cB] on a build_copy graph:
//    the multigoto becomes BlockSwitch::control, regular cases first, then
//    the grabCaseBasic t_multigoto append arm (block.cc:3548-3553) re-adds
//    the peeled gotoedge target as a case with gototype f_goto_goto.
// Observation lines are sorted before printing (slot-install vs append order
// is a registered bilateral normalization; the per-multigoto facts are
// order-free).

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{
    set_default_switch_mirrored, BlockBasic, BlockCopy, BlockGraph, BlockList, BlockMultiGoto,
    BlockSwitch, BlockWhileDo, BlockGoto, BlockType, FlowBlock, block_flags, edge_flags,
};

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

struct Graph {
    graph: BlockGraph,
    created: Vec<BlockRef>,
    base: u64,
}

impl Graph {
    fn new(base: u64) -> Self {
        Graph { graph: BlockGraph::new(), created: Vec::new(), base }
    }

    fn make_block(&mut self) -> BlockRef {
        // Unique index per vertex, mirroring the oracle's graph.addBlock
        // assignment (block.cc:862-875); new_block_multigoto's
        // identify_internal consumed-set logic is index-keyed, so the
        // blockgoto_wrapped fixture's all-zero scheme does not apply here.
        let bl: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            self.created.len() as i32,
            Address::new(self.base + (self.created.len() as u64) * 0x10),
        )));
        self.graph.add_block(bl.clone());
        self.created.push(bl.clone());
        bl
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.graph.add_edge(from.clone(), to.clone());
    }

    fn label_of(&self, bl: &BlockRef, toplist: &[BlockRef]) -> String {
        // Resolve BlockCopy nodes through their original (mirrors the C++
        // nameOf's t_copy recursion via BlockCopy::getCopy()).
        let original = {
            let r = bl.read().unwrap();
            if r.get_type() == BlockType::Copy {
                r.as_any()
                    .downcast_ref::<BlockCopy>()
                    .map(|c| c.original.clone())
            } else {
                None
            }
        };
        if let Some(orig) = original {
            return self.label_of(&orig, toplist);
        }
        for (i, cand) in self.created.iter().enumerate() {
            if Arc::ptr_eq(cand, bl) {
                return format!("b{}", i);
            }
        }
        for (i, cand) in toplist.iter().enumerate() {
            if Arc::ptr_eq(cand, bl) {
                return format!("c{}", i);
            }
        }
        format!("t{}", bl.read().unwrap().get_index())
    }

    fn observe(&self, g: &BlockRef, toplist: &[BlockRef]) -> String {
        let r = g.read().unwrap();
        let mg = r.as_any().downcast_ref::<BlockMultiGoto>().unwrap();
        let wrapped_name = mg
            .wrapped
            .as_ref()
            .map(|w| {
                let wr = w.read().unwrap();
                format!("{}:{}", self.label_of(w, toplist), type_name(wr.get_type()))
            })
            .unwrap_or_else(|| "none".to_string());
        let gotos = mg
            .gotoedges
            .iter()
            .map(|t| {
                let tr = t.read().unwrap();
                format!("{}:{}", self.label_of(t, toplist), type_name(tr.get_type()))
            })
            .collect::<Vec<_>>()
            .join(",");
        let outs = (0..r.size_out())
            .filter_map(|i| r.get_out(i).map(|e| self.label_of(&e.point, toplist)))
            .collect::<Vec<_>>()
            .join(",");
        let loops = (0..r.size_out()).filter(|&i| r.is_loop_out(i)).count();
        format!(
            "multigoto idx={} sizein={} sizeout={} wrapped={} numgotos={} gotos={} hasdefault={} outs={} loopouts={}",
            r.get_index(),
            r.size_in(),
            r.size_out(),
            wrapped_name,
            mg.num_gotos(),
            gotos,
            if mg.has_default_goto() { 1 } else { 0 },
            outs,
            loops
        )
    }

    /// Name a BlockCopy by its original synthetic vertex.
    fn label_of_copy(&self, bl: &BlockRef) -> String {
        let original = {
            let r = bl.read().unwrap();
            r.as_any()
                .downcast_ref::<BlockCopy>()
                .map(|c| c.original.clone())
        };
        match original {
            Some(orig) => self.label_of(&orig, &[]),
            None => self.label_of(bl, &[]),
        }
    }

    /// Family C: rule pipeline over a BlockCopy graph — observe the
    /// BlockSwitch's per-case gototypes (grabCaseBasic's t_multigoto arm).
    fn run_switch(&mut self, case_name: &str) {
        let mut rootlist: Vec<BlockRef> = Vec::new();
        self.graph.structure_loops(&mut rootlist);

        {
            let mut collapse =
                rudra::blockaction::CollapseStructure::new(&mut self.graph, case_name);
            collapse.collapse_all();
        }
        self.graph.scope_break(-1, -1);

        let toplist: Vec<BlockRef> = self.graph.blocks.clone();
        let mut lines: Vec<String> = Vec::new();
        let mut sws: Vec<BlockRef> = Vec::new();
        for root in &toplist {
            let mut mgs = Vec::new();
            collect_multigotos(root, &mut mgs, 0);
            for m in &mgs {
                lines.push(format!("residual_multigoto {}", self.label_of_copy(m)));
            }
            let mut found = Vec::new();
            collect_switches(root, &mut found, 0);
            sws.extend(found);
        }
        for sw in &sws {
            let r = sw.read().unwrap();
            let bs = r.as_any().downcast_ref::<BlockSwitch>().unwrap();
            let mut detail = format!("switch numcases={}", bs.cases.len());
            for (c, case) in bs.cases.iter().enumerate() {
                let gt = bs.case_gototypes.get(c).copied().unwrap_or(0);
                let cty = case.read().unwrap().get_type();
                detail.push_str(&format!(
                    " case{}={}:{}/gt{}/def0",
                    c,
                    self.label_of_copy(case),
                    type_name(cty),
                    gt
                ));
            }
            if let Some(def) = &bs.default_case {
                let dty = def.read().unwrap().get_type();
                detail.push_str(&format!(
                    " default={}:{}/gt{}/def1",
                    self.label_of_copy(def),
                    type_name(dty),
                    bs.default_gototype
                ));
            }
            lines.push(detail);
        }
        let switches = sws.len();
        lines.sort();
        println!("case {}", case_name);
        println!("switches={}", switches);
        for l in lines {
            println!("{}", l);
        }
        println!("end");
    }

    fn run(&mut self, case_name: &str) {
        let mut rootlist: Vec<BlockRef> = Vec::new();
        self.graph.structure_loops(&mut rootlist);

        let mut collapse =
            rudra::blockaction::CollapseStructure::new(&mut self.graph, case_name);
        collapse.collapse_all();

        // ActionFinalStructure tail (blockaction.cc:2193).
        self.graph.scope_break(-1, -1);

        let toplist: Vec<BlockRef> = self.graph.blocks.clone();
        let mut lines: Vec<String> = Vec::new();
        let mut total = 0;
        for root in &toplist {
            let mut found = Vec::new();
            collect_multigotos(root, &mut found, 0);
            for g in found {
                total += 1;
                lines.push(self.observe(&g, &toplist));
            }
        }
        lines.sort();
        println!("case {}", case_name);
        println!("multigotos={}", total);
        for l in lines {
            println!("{}", l);
        }
        println!("end");
    }

    fn run_direct(&mut self, case_name: &str) {
        let mut rootlist: Vec<BlockRef> = Vec::new();
        self.graph.structure_loops(&mut rootlist);

        let _t0 = self.make_block();
        let _t1 = self.make_block();
        let _dflt = self.make_block();
        let s = self.make_block();
        self.edge(&s, &_t0);
        self.edge(&s, &_t1);
        self.edge(&s, &_dflt);
        self.edge(&s, &s); // self edge — identify_internal absorbs it
        s.write().unwrap().set_flags(block_flags::SWITCH_OUT);
        set_default_switch_mirrored(&s, 2);
        let s_slot = 3usize;
        let toplist: Vec<BlockRef> = self.graph.blocks.clone();

        // Peel 1 (fresh wrap, cc:1733-1751): non-default edge s->t1 (slot 1).
        {
            let mut collapse =
                rudra::blockaction::CollapseStructure::new(&mut self.graph, case_name);
            collapse.new_block_multigoto(s_slot, 1);
        }
        let mg = self.graph.get_block(s_slot).expect("multigoto installed at slot");
        {
            let r = mg.read().unwrap();
            let m = r.as_any().downcast_ref::<BlockMultiGoto>().unwrap();
            let loops = (0..r.size_out()).filter(|&i| r.is_loop_out(i)).count();
            println!(
                "peel1 type={} sizeout={} numgotos={} gotos={} hasdefault={} t1_sizein={} loopouts={}",
                type_name(r.get_type()),
                r.size_out(),
                m.num_gotos(),
                self.label_of(m.get_goto(0).as_ref().unwrap(), &toplist),
                if m.has_default_goto() { 1 } else { 0 },
                _t1.read().unwrap().size_in(),
                loops
            );
        }

        // Peel 2 (already-t_multigoto branch, cc:1726-1732): the default edge.
        let dslot = {
            let r = mg.read().unwrap();
            (0..r.size_out())
                .find(|&i| {
                    r.get_out(i)
                        .map(|e| Arc::ptr_eq(&e.point, &_dflt))
                        .unwrap_or(false)
                })
        };
        let dslot = dslot.expect("default edge still present");
        {
            let mut collapse =
                rudra::blockaction::CollapseStructure::new(&mut self.graph, case_name);
            collapse.new_block_multigoto(s_slot, dslot);
        }
        let mg2 = self.graph.get_block(s_slot).unwrap();
        {
            let r = mg2.read().unwrap();
            let m = r.as_any().downcast_ref::<BlockMultiGoto>().unwrap();
            println!(
                "peel2 type={} sizeout={} numgotos={} gotos={},{} hasdefault={} dflt_sizein={}",
                type_name(r.get_type()),
                r.size_out(),
                m.num_gotos(),
                self.label_of(m.get_goto(0).as_ref().unwrap(), &toplist),
                self.label_of(m.get_goto(1).as_ref().unwrap(), &toplist),
                if m.has_default_goto() { 1 } else { 0 },
                _dflt.read().unwrap().size_in()
            );
        }

        // scopeBreak (block.cc:2918-2922): curesxit discarded (-1 down),
        // gotoedges untouched.
        mg2.write().unwrap().scope_break_trait(7, 9);
        let r = mg2.read().unwrap();
        let m = r.as_any().downcast_ref::<BlockMultiGoto>().unwrap();
        println!(
            "after_scopebreak numgotos={} hasdefault={}",
            m.num_gotos(),
            if m.has_default_goto() { 1 } else { 0 }
        );
        println!("case {}", case_name);
        println!("end");
    }

    /// Family A2 (loop_exit_conflict, B2-MG-RESID-2): mirrors the oracle's
    /// runLoopExit — WhileDo[cond=h, body=List[mg(s), gt(t→e)]], roots
    /// [wd, e]. scope_break(-1,-1) must promote ONLY the contrast BlockGoto
    /// (BREAK_GOTO) — the multigoto's gotoedges are never reclassified
    /// (block.cc:2918-2922) — and compute_goto_prints stores the contrast
    /// goto's prints through the promoted WhileDo dispatch.
    fn run_loop_exit(&mut self, case_name: &str) {
        let mut rootlist: Vec<BlockRef> = Vec::new();
        self.graph.structure_loops(&mut rootlist);

        let h = self.make_block(); // b0
        let s = self.make_block(); // b1
        let t = self.make_block(); // b2
        let e = self.make_block(); // b3
        self.edge(&h, &s); // loop head flows into the multi-exit body block
        self.edge(&s, &h); // backedge
        self.edge(&s, &e); // the switch-out edge peeled as the gotoedge
        self.edge(&t, &e); // the contrast goto's own edge to the loop exit
        s.write().unwrap().set_flags(block_flags::SWITCH_OUT);

        // Production peel: s at slot 1, outedge 1 (s outs = [h, e]).
        let s_slot = 1usize;
        {
            let mut collapse =
                rudra::blockaction::CollapseStructure::new(&mut self.graph, case_name);
            collapse.new_block_multigoto(s_slot, 1);
        }
        let mg = self.graph.get_block(s_slot).expect("multigoto installed at slot").clone();

        // Contrast goto (mirrors newBlockGoto(t)): wraps t, targets e,
        // gototype f_goto_goto.
        let gt: BlockRef = Arc::new(RwLock::new(BlockGoto {
            index: 10,
            flags: 0,
            parent: None,
            goto_target: None,
            target_dyn: Some(e.clone()),
            wrapped: Some(t.clone()),
            goto_type: rudra::block::goto_type::GOTO_GOTO,
            prints_precomputed: false,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }));
        let body: BlockRef = Arc::new(RwLock::new(BlockList::new(11, vec![mg.clone(), gt.clone()])));
        let wd: BlockRef = Arc::new(RwLock::new(BlockWhileDo {
            index: 12,
            condition: h.clone(),
            body: body.clone(),
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

        // Canonical root order [wd, e] (production orderBlocks intent): the
        // factories append, so arrange explicitly.
        self.graph.blocks = vec![wd.clone(), e.clone()];
        self.graph.scope_break(-1, -1); // ActionFinalStructure tail (cc:2193)
        self.graph.compute_goto_prints();

        let toplist: Vec<BlockRef> = self.graph.blocks.clone();
        let mut lines: Vec<String> = Vec::new();
        let mut total = 0;
        for root in &toplist {
            let mut mgs = Vec::new();
            collect_multigotos(root, &mut mgs, 0);
            for g in &mgs {
                total += 1;
                let r = g.read().unwrap();
                let m = r.as_any().downcast_ref::<BlockMultiGoto>().unwrap();
                let wrapped_name = m
                    .wrapped
                    .as_ref()
                    .map(|w| {
                        let wr = w.read().unwrap();
                        format!("{}:{}", self.label_of(w, &toplist), type_name(wr.get_type()))
                    })
                    .unwrap_or_else(|| "none".to_string());
                let gotoedges = m
                    .gotoedges
                    .iter()
                    .map(|tg| {
                        let tr = tg.read().unwrap();
                        format!("{}:{}", self.label_of(tg, &toplist), type_name(tr.get_type()))
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                // Degrees/outs are NOT observed here (identifyInternal
                // bubbles the multigoto's edges up to the List/WhileDo
                // level on the oracle side, while the Rust mirror builds
                // those composites as literals — degree bookkeeping is
                // family B's observation territory).
                lines.push(format!(
                    "loopmg wrapped={} numgotos={} gotoedges={} hasdefault={}",
                    wrapped_name,
                    m.num_gotos(),
                    gotoedges,
                    if m.has_default_goto() { 1 } else { 0 }
                ));
            }
            // Contrast goto facts: the promoted dispatch stores prints.
            let mut gotos = Vec::new();
            collect_gotos(root, &mut gotos);
            for g in &gotos {
                let r = g.read().unwrap();
                let bg = r.as_any().downcast_ref::<BlockGoto>().unwrap();
                let target = bg
                    .target_dyn
                    .clone()
                    .map(|tg| {
                        let tr = tg.read().unwrap();
                        format!("{}:{}", self.label_of(&tg, &toplist), type_name(tr.get_type()))
                    })
                    .unwrap_or_else(|| "null".to_string());
                lines.push(format!(
                    "loopgoto target={} gototype={} prints={}",
                    target,
                    bg.goto_type,
                    if bg.prints_precomputed { 1 } else { 0 }
                ));
            }
        }
        lines.sort();
        println!("case {}", case_name);
        println!("multigotos={}", total);
        for l in lines {
            println!("{}", l);
        }
        println!("end");
    }

    /// Family C (copy_switch_consumption, B2-MG-RESID-1): mirrors the
    /// oracle's CopyGraph case — build_copy graph, production multigoto
    /// peel over the head copy, then the BlockSwitch recording over
    /// cs=[mg, cA, cB] (regular cases first, then the appended gotoedge
    /// case with gototype f_goto_goto, block.cc:3548-3553). Roots
    /// [switch, after, gotoedge-target] keep the appended case's raw
    /// f_goto_goto through scope_break (cc:3620-3623 does not fire).
    fn run_copy_switch(&mut self, case_name: &str) {
        let mk = |i: i32| -> BlockRef {
            Arc::new(RwLock::new(BlockBasic::new(
                i,
                Address::new(self.base + (i as u64) * 0x10),
            )))
        };
        let mut orig_graph = BlockGraph::new();
        let originals: Vec<BlockRef> = (0..5).map(mk).collect();
        for o in &originals {
            orig_graph.add_block(o.clone());
        }
        // Mirror of the oracle fixture's original-graph edges: dispatch
        // edges head→cA/cB/gtgt (b4 = `after` keeps no edges).
        orig_graph.add_edge(originals[0].clone(), originals[1].clone());
        orig_graph.add_edge(originals[0].clone(), originals[2].clone());
        orig_graph.add_edge(originals[0].clone(), originals[3].clone());
        // Production buildCopy: BlockCopy leaves with remapped edges, head
        // at slot 0.
        self.graph.build_copy(&orig_graph);
        let c: Vec<BlockRef> =
            (0..5).map(|i| self.graph.get_block(i).unwrap().clone()).collect();
        self.created = originals;

        // Production peel over the head copy, outedge 2 (→c[3]).
        {
            let mut collapse =
                rudra::blockaction::CollapseStructure::new(&mut self.graph, case_name);
            collapse.new_block_multigoto(0, 2);
        }
        let mg = self.graph.get_block(0).expect("multigoto installed at slot").clone();

        // newBlockSwitch's recording over cs=[mg, cA, cB]: control = mg,
        // cases = [cA, cB] + the appended gotoedge target c[3] with
        // gototype f_goto_goto (block.cc:3548-3553).
        let sw: BlockRef = Arc::new(RwLock::new(BlockSwitch {
            index: 11,
            control: mg.clone(),
            cases: vec![c[1].clone(), c[2].clone(), c[3].clone()],
            default_case: None,
            case_gototypes: vec![0, 0, rudra::block::goto_type::GOTO_GOTO],
            default_gototype: 0,
            // Pre-label bystander defaults (same as printc_switch_emit_1204
            // and the goto_prints fixture): the oracle fixture's hollow
            // jumptable keeps jump null, and the observation is the case
            // order + gototypes — never the label pipeline state
            // (JUMPTABLE-TABLEAPI-0001 domain). case_isexit/default_isexit/
            // default_label/default_order are the post-CASEWRAP/
            // post-DEFAULTCHAIN bystander transports (filled by the
            // production grab path; hollow fixtures keep the defaults).
            jump: None,
            case_order: Vec::new(),
            case_isexit: vec![false, false, false],
            default_isexit: false,
            default_label: None,
            default_order: None,
            case_values: vec![vec![0], vec![1], vec![2]],
            index_varnode: None,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }));

        // Canonical roots [switch, after, gotoedge-target].
        self.graph.blocks = vec![sw.clone(), c[4].clone(), c[3].clone()];
        self.graph.scope_break(-1, -1); // ActionFinalStructure tail (cc:2193)

        let toplist: Vec<BlockRef> = self.graph.blocks.clone();
        let mut lines: Vec<String> = Vec::new();
        let mut sws: Vec<BlockRef> = Vec::new();
        for root in &toplist {
            let mut mgs = Vec::new();
            collect_multigotos(root, &mut mgs, 0);
            for m in &mgs {
                lines.push(format!("residual_multigoto {}", self.label_of_copy(m)));
            }
            let mut found = Vec::new();
            collect_switches(root, &mut found, 0);
            sws.extend(found);
        }
        for swb in &sws {
            let r = swb.read().unwrap();
            let bs = r.as_any().downcast_ref::<BlockSwitch>().unwrap();
            let mut detail = format!("switch numcases={}", bs.cases.len());
            for (ci, case) in bs.cases.iter().enumerate() {
                let gt = bs.case_gototypes.get(ci).copied().unwrap_or(0);
                let cty = case.read().unwrap().get_type();
                detail.push_str(&format!(
                    " case{}={}:{}/gt{}/def0",
                    ci,
                    self.label_of_copy(case),
                    type_name(cty),
                    gt
                ));
            }
            lines.push(detail);
        }
        let switches = sws.len();
        lines.sort();
        println!("case {}", case_name);
        println!("switches={}", switches);
        for l in lines {
            println!("{}", l);
        }
        println!("end");
    }
}

fn collect_switches(bl: &BlockRef, out: &mut Vec<BlockRef>, depth: usize) {
    if depth > 8 {
        return;
    }
    if bl.read().unwrap().get_type() == BlockType::Switch {
        out.push(bl.clone());
    }
    for child in rudra::block::BlockGraph::component_list_dyn(bl) {
        collect_switches(&child, out, depth + 1);
    }
}

fn w_read_target(swcopy: &BlockRef) -> BlockRef {
    swcopy.read().unwrap().get_out(0).map(|e| e.point).unwrap()
}

/// DFS collecting every tree-resident BlockMultiGoto (depth-capped like the
/// C++ walk; synthetic trees are shallow).
fn collect_multigotos(bl: &BlockRef, out: &mut Vec<BlockRef>, depth: usize) {
    if depth > 8 {
        return;
    }
    if bl.read().unwrap().get_type() == BlockType::MultiGoto {
        out.push(bl.clone());
    }
    for child in rudra::block::BlockGraph::component_list_dyn(bl) {
        collect_multigotos(&child, out, depth + 1);
    }
}

/// DFS collecting every tree-resident BlockGoto (mirrors the oracle's
/// collectGotos).
fn collect_gotos(bl: &BlockRef, out: &mut Vec<BlockRef>) {
    if bl.read().unwrap().get_type() == BlockType::Goto {
        out.push(bl.clone());
    }
    for child in rudra::block::BlockGraph::component_list_dyn(bl) {
        collect_gotos(&child, out);
    }
}

fn main() {
    // Family A case 1: double_back with the multi-exit block b2 marked as a
    // switch — ruleBlockGoto's isSwitchOut arm must multigoto-wrap. b4 gives
    // b3 a second predecessor so ruleBlockSwitch rejects (cc:1700) and the
    // multigoto stays observable at top level.
    {
        let mut inner = Graph::new(0x1000);
        let b0 = inner.make_block();
        let b1 = inner.make_block();
        let b2 = inner.make_block();
        let b3 = inner.make_block();
        inner.edge(&b0, &b1);
        inner.edge(&b1, &b2);
        inner.edge(&b2, &b0);
        inner.edge(&b2, &b3);
        inner.edge(&b3, &b1);
        b2.write().unwrap().set_flags(block_flags::SWITCH_OUT);
        let mut g = Graph::new(0x0);
        g.graph.build_copy(&inner.graph);
        g.created = inner.created.clone();
        g.run_switch("switch_double_back_multigoto");
    }
    // Family A2: loop_exit_conflict same-shape closure (B2-MG-RESID-2).
    {
        let mut g = Graph::new(0x4000);
        g.run_loop_exit("loop_exit_conflict");
    }
    // Family B: direct new_block_multigoto semantics.
    {
        let mut g = Graph::new(0xa000);
        g.run_direct("direct_newblockmultigoto");
    }
    // Family C: copy_switch_consumption same-shape closure
    // (B2-MG-RESID-1) — the multigoto is consumed into the BlockSwitch;
    // the gotoedge target re-appears as the appended f_goto_goto case.
    {
        let mut g = Graph::new(0xc000);
        g.run_copy_switch("copy_switch_consumption");
    }
}
