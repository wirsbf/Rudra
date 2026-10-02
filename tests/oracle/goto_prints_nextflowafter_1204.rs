// GOTO-PRINTS-NEXTFLOWAFTER-ARMS-0001: Rudra side of the locked Ghidra
// 12.0.4 nextFlowAfter bilateral fixture. Mirrors
// goto_prints_nextflowafter_1204.cc case for case: the same hand-built
// copy-level trees (BlockCopy leaves so front_leaf is non-null and the
// dispatch is discriminative), driven through the production machinery
// only — `BlockGraph::scope_break(-1,-1)` (the ActionFinalStructure tail,
// blockaction.cc:2193), `BlockGraph::compute_goto_prints()` (the
// tree-wide gotoPrints evaluation), and the promoted dispatch
// `rudra::block::next_flow_after_successors` / `graph_sibling_successors`
// (the exact code ActionFinalStructure's walk runs) — never a
// fixture-local reimplementation of the dispatch.
//
// The switch_multigoto_gotoedge case additionally drives the production
// `CollapseStructure::new_block_multigoto` peel and mirrors
// grabCaseBasic's t_multigoto append arm (block.cc:3548-3553) as the
// BlockSwitch literal's recorded case order/gototypes.
//
// Observation per (composite, component) pair: the successor the dispatch
// gives that component (identity+type). Switch slots are printed with the
// ORACLE indexing — the dispatch root (BlockSwitch::control, which Rust
// keeps outside the component list) as slot 0 with its arm-① null, cases
// offset by one — so both sides emit identical text. Observation per
// tree-resident BlockGoto: target + gototype + prints_precomputed (the
// value compute_goto_prints stored). Lines sorted before printing.

use rudra::address::Address;
use rudra::block::{
    BlockBasic, BlockDoWhile, BlockGoto, BlockGraph, BlockIf, BlockInfLoop, BlockList,
    BlockMultiGoto, BlockSwitch, BlockType, BlockWhileDo, FlowBlock, graph_sibling_successors,
    next_flow_after_successors,
};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

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

struct Fixture {
    names: BTreeMap<usize, String>,
    lines: Vec<String>,
}

impl Fixture {
    fn name(&mut self, bl: &BlockArc, nm: &str) {
        self.names.insert(Arc::as_ptr(bl) as *const u8 as usize, nm.to_string());
    }
    fn desc(&self, bl: &Option<BlockArc>) -> String {
        match bl {
            None => "null:null".to_string(),
            Some(b) => format!(
                "{}:{}",
                self.names
                    .get(&(Arc::as_ptr(b) as *const u8 as usize))
                    .cloned()
                    .unwrap_or_else(|| "anon".to_string()),
                type_name(b.read().unwrap().get_type())
            ),
        }
    }

    // Components of a composite: the same component_list_dyn projection
    // the production walk uses (block.rs). Switch: cases(+default), no
    // control — the oracle's cs[0] stays outside the list on this side.
    fn components(bl: &BlockArc) -> Vec<BlockArc> {
        let rg = bl.read().unwrap();
        let any = rg.as_any();
        match rg.get_type() {
            BlockType::List => any
                .downcast_ref::<BlockList>()
                .map(|l| l.children.clone())
                .unwrap_or_default(),
            BlockType::If => any
                .downcast_ref::<BlockIf>()
                .map(|i| {
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
            BlockType::Switch => any
                .downcast_ref::<BlockSwitch>()
                .map(|s| {
                    let mut v = s.cases.clone();
                    if let Some(dc) = &s.default_case {
                        v.push(dc.clone());
                    }
                    v
                })
                .unwrap_or_default(),
            // Oracle cs[0] descent for the multigoto gotoedge variant
            // (block.cc:3548-3553): the oracle's component walk descends
            // into the BlockMultiGoto dispatch root (a BlockGraph with the
            // single wrapped component), so the fixture mirrors [wrapped]
            // here. Production component_list_dyn keeps MultiGoto empty
            // (the wrapped head is a basic leaf holding no BlockGoto), so
            // this arm exists only for the observation walk.
            BlockType::MultiGoto => any
                .downcast_ref::<BlockMultiGoto>()
                .and_then(|m| m.wrapped.clone())
                .into_iter()
                .collect(),
            BlockType::Goto => any
                .downcast_ref::<BlockGoto>()
                .and_then(|g| g.wrapped.clone())
                .into_iter()
                .collect(),
            _ => Vec::new(),
        }
    }

    // The full per-(composite, component) dispatch observation, using the
    // production promoted dispatch (the same fn compute_goto_prints
    // calls). Switch slots are printed with the oracle's indexing: the
    // dispatch root (control) as slot 0 with its arm-① null (block.cc
    // 3642-3643 — Rust keeps the root outside the walked component list),
    // then the cases from slot 1.
    fn observe_dispatch(&mut self, node: &BlockArc, succ: &Option<BlockArc>) {
        let (bt, control) = {
            let rg = node.read().unwrap();
            let control = if rg.get_type() == BlockType::Switch {
                rg.as_any()
                    .downcast_ref::<BlockSwitch>()
                    .map(|s| s.control.clone())
            } else {
                None
            };
            (rg.get_type(), control)
        };
        if let Some(ctrl) = control {
            self.lines.push(format!(
                "dispatch parent={}[{}] comp={} next=null:null",
                type_name(bt),
                0,
                self.desc(&Some(ctrl))
            ));
        }
        let components = Self::components(node);
        if components.is_empty() {
            return;
        }
        let succs = next_flow_after_successors(node, &components, succ.clone());
        let base = if bt == BlockType::Switch { 1 } else { 0 };
        for (i, (comp, next)) in components.iter().zip(succs).enumerate() {
            self.lines.push(format!(
                "dispatch parent={}[{}] comp={} next={}",
                type_name(bt),
                i + base,
                self.desc(&Some(comp.clone())),
                self.desc(&next)
            ));
        }
    }

    fn collect_all(node: &BlockArc, out: &mut Vec<BlockArc>) {
        out.push(node.clone());
        for c in Self::components(node) {
            Self::collect_all(&c, out);
        }
    }

    fn observe_gotos(&mut self, roots: &[BlockArc]) {
        let mut all = Vec::new();
        for r in roots {
            Self::collect_all(r, &mut all);
        }
        for bl in all {
            if bl.read().unwrap().get_type() != BlockType::Goto {
                continue;
            }
            let (target, gt, prints) = {
                let rg = bl.read().unwrap();
                let g = rg.as_any().downcast_ref::<BlockGoto>().unwrap();
                (g.target_dyn.clone(), g.goto_type, g.prints_precomputed)
            };
            self.lines.push(format!(
                "goto {} target={} gototype={} prints={}",
                self.desc(&Some(bl.clone())),
                self.desc(&target),
                gt,
                if prints { 1 } else { 0 }
            ));
        }
    }

    // The same observation walk the fixture performs on the dispatch,
    // mirroring the oracle's collectAll+observeDispatch recursion.
    fn observe_walk(&mut self, roots: &[BlockArc]) {
        let root_succs = graph_sibling_successors(roots, None);
        for (root, succ) in roots.iter().zip(root_succs) {
            self.visit(root, &succ);
        }
    }

    fn visit(&mut self, node: &BlockArc, succ: &Option<BlockArc>) {
        self.observe_dispatch(node, succ);
        let control_mg = {
            let rg = node.read().unwrap();
            if rg.get_type() == BlockType::Switch {
                rg.as_any()
                    .downcast_ref::<BlockSwitch>()
                    .map(|s| s.control.clone())
                    .filter(|c| c.read().unwrap().get_type() == BlockType::MultiGoto)
            } else {
                None
            }
        };
        // Oracle cs[0] descent for the multigoto gotoedge variant: the
        // oracle's collectAll walks into the BlockSwitch's absorbed
        // component list, whose cs[0] entry IS the BlockMultiGoto (Rudra
        // keeps it as `control`, outside the walked cases). Its successor
        // is the arm-① null of block.cc:3642-3643, so it is visited with
        // succ=None; the multigoto arm (block.cc:2931-2936) is null for
        // the wrapped head either way.
        if let Some(mg) = control_mg {
            self.visit(&mg, &None);
        }
        let components = Self::components(node);
        if components.is_empty() {
            return;
        }
        let succs = next_flow_after_successors(node, &components, succ.clone());
        for (child, child_succ) in components.iter().zip(succs) {
            self.visit(child, &child_succ);
        }
    }

    fn emit(&mut self, case: &str, roots: &[BlockArc]) {
        self.observe_walk(roots);
        self.observe_gotos(roots);
        self.lines.sort();
        println!("case {}", case);
        for l in self.lines.clone() {
            println!("{}", l);
        }
        println!("end");
    }
}

fn copy_leaf(f: &mut Fixture, graph: &mut BlockGraph, idx: i32, nm: &str) -> BlockArc {
    // Original with an explicit index (drives the scopeBreak threading,
    // exactly as the oracle fixture sets orig->index).
    let orig: BlockArc = Arc::new(RwLock::new(BlockBasic::new(
        idx,
        Address::new(0x1000 + (idx as u64) * 0x10),
    )));
    let copy = graph.new_block_copy(orig);
    f.name(&copy, nm);
    copy
}

fn goto_block(idx: i32, wrapped: BlockArc, target: BlockArc) -> BlockArc {
    Arc::new(RwLock::new(BlockGoto {
        index: idx,
        flags: 0,
        parent: None,
        goto_target: None,
        target_dyn: Some(target),
        wrapped: Some(wrapped),
        goto_type: rudra::block::goto_type::GOTO_GOTO,
        prints_precomputed: false,
        incoming: Vec::new(),
        outgoing: Vec::new(),
    }))
}

fn list_block(idx: i32, children: Vec<BlockArc>) -> BlockArc {
    Arc::new(RwLock::new(BlockList::new(idx, children)))
}

// The production ActionFinalStructure sequence over the root graph:
// scopeBreak(-1,-1) then the tree-wide gotoPrints evaluation
// (compute_goto_prints), then observation.
fn run_case(f: &mut Fixture, case: &str, roots: Vec<BlockArc>) {
    let mut graph = BlockGraph::new();
    graph.blocks = roots.clone();
    graph.scope_break(-1, -1);
    graph.compute_goto_prints();
    f.emit(case, &roots);
}

fn main() {
    // while_tail_break_goto: WhileDo[cond=b0, body=List[b1, goto(b2→b3)]],
    // b3 after the loop. gotoPrints compares the target b3 against the
    // loop head b0 → prints=1; scopeBreak converts to break (gototype=2).
    {
        let mut graph = BlockGraph::new();
        let mut f = Fixture { names: BTreeMap::new(), lines: Vec::new() };
        let b0 = copy_leaf(&mut f, &mut graph, 0, "b0");
        let b1 = copy_leaf(&mut f, &mut graph, 1, "b1");
        let b2 = copy_leaf(&mut f, &mut graph, 2, "b2");
        let b3 = copy_leaf(&mut f, &mut graph, 3, "b3");
        let g0 = goto_block(10, b2.clone(), b3.clone());
        f.name(&g0, "g0");
        let body = list_block(11, vec![b1.clone(), g0.clone()]);
        f.name(&body, "body");
        let wd: BlockArc = Arc::new(RwLock::new(BlockWhileDo {
            index: 12,
            condition: b0.clone(),
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
        f.name(&wd, "wd");
        run_case(&mut f, "while_tail_break_goto", vec![wd.clone(), b3.clone()]);
    }
    // infloop_backedge_goto: InfLoop[body=List[b0, goto(b1→b0)]] —
    // explicit backedge to the head; dispatch gives the head → prints=0.
    {
        let mut graph = BlockGraph::new();
        let mut f = Fixture { names: BTreeMap::new(), lines: Vec::new() };
        let b0 = copy_leaf(&mut f, &mut graph, 0, "b0");
        let b1 = copy_leaf(&mut f, &mut graph, 1, "b1");
        let g0 = goto_block(10, b1.clone(), b0.clone());
        f.name(&g0, "g0");
        let body = list_block(11, vec![b0.clone(), g0.clone()]);
        f.name(&body, "body");
        let il: BlockArc = Arc::new(RwLock::new(BlockInfLoop {
            index: 12,
            body: body.clone(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }));
        f.name(&il, "il");
        run_case(&mut f, "infloop_backedge_goto", vec![il.clone()]);
    }
    // switch_fallthru_goto: Switch[control=head, cases=[goto(c0→c1),
    // c1, c2]] — the fallthru goto case: dispatch gives front_leaf(c1)
    // → prints=0; control slot null (arm ①); non-t_goto cases null.
    {
        let mut graph = BlockGraph::new();
        let mut f = Fixture { names: BTreeMap::new(), lines: Vec::new() };
        let head = copy_leaf(&mut f, &mut graph, 0, "head");
        let c0 = copy_leaf(&mut f, &mut graph, 1, "c0");
        let c1 = copy_leaf(&mut f, &mut graph, 2, "c1");
        let c2 = copy_leaf(&mut f, &mut graph, 3, "c2");
        let g0 = goto_block(10, c0.clone(), c1.clone());
        f.name(&g0, "g0");
        let sw: BlockArc = Arc::new(RwLock::new(BlockSwitch {
            index: 11,
            control: head.clone(),
            cases: vec![g0.clone(), c1.clone(), c2.clone()],
            default_case: None,
            case_gototypes: vec![0, 0, 0],
            default_gototype: 0,
            // Pre-label bystander defaults (same as printc_switch_emit_1204):
            // the oracle fixture's hollow jumptable keeps jump null and this
            // fixture never reaches finalizePrinting's case_order sort —
            // labels stay 0 by construction (JUMPTABLE-TABLEAPI-0001 domain).
            // case_isexit/default_isexit/default_label/default_order are the
            // post-CASEWRAP/post-DEFAULTCHAIN bystander transports.
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
        f.name(&sw, "sw");
        run_case(&mut f, "switch_fallthru_goto", vec![sw.clone()]);
    }
    // goto_wrapping_goto: g_out wraps List[g_in(→b2)]; the inner goto's
    // dispatch crosses the Goto arm → next = front_leaf(b2) → prints=0.
    {
        let mut graph = BlockGraph::new();
        let mut f = Fixture { names: BTreeMap::new(), lines: Vec::new() };
        let b0 = copy_leaf(&mut f, &mut graph, 0, "b0");
        let b2 = copy_leaf(&mut f, &mut graph, 2, "b2");
        let g_in = goto_block(10, b0.clone(), b2.clone());
        f.name(&g_in, "g_in");
        let inner = list_block(11, vec![g_in.clone()]);
        f.name(&inner, "inner");
        let g_out = goto_block(12, inner.clone(), b2.clone());
        f.name(&g_out, "g_out");
        run_case(&mut f, "goto_wrapping_goto", vec![g_out.clone()]);
    }
    // if_else_tail_goto: If[b0, tc=List[b1, goto(b2→b4)], fc=b3] — tc-tail
    // goto's dispatch: If slot!=0 → parent arm → b4 (never fc b3).
    {
        let mut graph = BlockGraph::new();
        let mut f = Fixture { names: BTreeMap::new(), lines: Vec::new() };
        let b0 = copy_leaf(&mut f, &mut graph, 0, "b0");
        let b1 = copy_leaf(&mut f, &mut graph, 1, "b1");
        let b2 = copy_leaf(&mut f, &mut graph, 2, "b2");
        let b3 = copy_leaf(&mut f, &mut graph, 3, "b3");
        let b4 = copy_leaf(&mut f, &mut graph, 4, "b4");
        let g0 = goto_block(10, b2.clone(), b4.clone());
        f.name(&g0, "g0");
        let tc = list_block(11, vec![b1.clone(), g0.clone()]);
        f.name(&tc, "tc");
        let bif: BlockArc = Arc::new(RwLock::new(BlockIf {
            index: 12,
            condition: b0.clone(),
            if_body: tc.clone(),
            else_body: Some(b3.clone()),
            goto_target: None,
            goto_type: rudra::block::goto_type::GOTO_GOTO,
            parent: None,
            flags: 0,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }));
        f.name(&bif, "if");
        run_case(&mut f, "if_else_tail_goto", vec![bif.clone(), b4.clone()]);
    }
    // dowhile_tail_goto: DoWhile[List[b0, goto(b1→b2)]], b2 after the
    // loop. DoWhile arm → null → prints=1; scopeBreak converts (target
    // == the DoWhile's next-root index).
    {
        let mut graph = BlockGraph::new();
        let mut f = Fixture { names: BTreeMap::new(), lines: Vec::new() };
        let b0 = copy_leaf(&mut f, &mut graph, 0, "b0");
        let b1 = copy_leaf(&mut f, &mut graph, 1, "b1");
        let b2 = copy_leaf(&mut f, &mut graph, 2, "b2");
        let g0 = goto_block(10, b1.clone(), b2.clone());
        f.name(&g0, "g0");
        let body = list_block(11, vec![b0.clone(), g0.clone()]);
        f.name(&body, "body");
        let dw: BlockArc = Arc::new(RwLock::new(BlockDoWhile {
            index: 12,
            condition: body.clone(),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }));
        f.name(&dw, "dw");
        run_case(&mut f, "dowhile_tail_goto", vec![dw.clone(), b2.clone()]);
    }
    // switch_multigoto_gotoedge: the switch's dispatch root is a
    // BlockMultiGoto (the isSwitchOut peel over the head copy; gotoedge =
    // head's slot-2 target c3). grabCaseBasic's t_multigoto arm (block.cc
    // 3548-3553) appends c3 as a case with gototype f_goto_goto AFTER the
    // regular cases, so g0's nextFlowAfter falls through into the appended
    // case (front leaf c3), NOT to g0's own target `out`; the multigoto
    // arm is null for the wrapped head (block.cc:2931-2936); scopeBreak
    // promotes the appended case to f_break_goto (cc:3620-3623 — its
    // target c3 is the switch exit) while g0 stays f_goto_goto.
    {
        let mut orig_graph = BlockGraph::new();
        let mk = |i: i32| -> BlockArc {
            Arc::new(RwLock::new(BlockBasic::new(
                i,
                Address::new(0x1000 + (i as u64) * 0x10),
            )))
        };
        let head_o = mk(0);
        let ca_o = mk(1);
        let cb_o = mk(2);
        let c3_o = mk(3);
        let out_o = mk(4);
        for o in [&head_o, &ca_o, &cb_o, &c3_o, &out_o] {
            orig_graph.add_block(o.clone());
        }
        // Mirror of the oracle fixture's original-graph edges: dispatch
        // edges head→cA/cB/c3 plus cB's own out-edge to `out`.
        orig_graph.add_edge(head_o.clone(), ca_o.clone());
        orig_graph.add_edge(head_o.clone(), cb_o.clone());
        orig_graph.add_edge(head_o.clone(), c3_o.clone());
        orig_graph.add_edge(cb_o.clone(), out_o.clone());
        // Production buildCopy: BlockCopy leaves with remapped edges, in
        // creation order (head at slot 0).
        let mut graph = BlockGraph::new();
        graph.build_copy(&orig_graph);
        let head = graph.get_block(0).unwrap().clone();
        let c_a = graph.get_block(1).unwrap().clone();
        let c_b = graph.get_block(2).unwrap().clone();
        let c3 = graph.get_block(3).unwrap().clone();
        let out = graph.get_block(4).unwrap().clone();
        let mut f = Fixture { names: BTreeMap::new(), lines: Vec::new() };
        f.name(&head, "head");
        f.name(&c_a, "cA");
        f.name(&c_b, "cB");
        f.name(&c3, "c3");
        f.name(&out, "out");
        // Production peel (newBlockMultiGoto over the head copy, slot 2):
        // mg wraps head, gotoedges=[c3], the head→c3 out edge is removed
        // bilaterally.
        {
            let mut collapse = rudra::blockaction::CollapseStructure::new(
                &mut graph,
                "switch_multigoto_gotoedge",
            );
            collapse.new_block_multigoto(0, 2);
        }
        let mg = graph.get_block(0).unwrap().clone();
        f.name(&mg, "mg");
        // g0 mirrors the oracle's newBlockGoto(cB): wraps cB, targets
        // `out` (cB's own out-edge), gototype f_goto_goto.
        let g0 = goto_block(10, c_b.clone(), out.clone());
        f.name(&g0, "g0");
        // Mirrors newBlockSwitch's recording over cs=[mg, cA, g0]:
        // regular cases first, then the t_multigoto arm's appended
        // gotoedge case (block.cc:3548-3553) with gototype f_goto_goto.
        let sw: BlockArc = Arc::new(RwLock::new(BlockSwitch {
            index: 11,
            control: mg.clone(),
            cases: vec![c_a.clone(), g0.clone(), c3.clone()],
            default_case: None,
            case_gototypes: vec![0, 0, rudra::block::goto_type::GOTO_GOTO],
            default_gototype: 0,
            // Pre-label bystander defaults (see switch_fallthru_goto above):
            // the multigoto append arm's observation is the case ORDER +
            // gototypes in `cases`/`case_gototypes`; the label pipeline
            // fields stay at their pre-finalizePrinting defaults.
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
        f.name(&sw, "sw");
        run_case(&mut f, "switch_multigoto_gotoedge", vec![sw.clone(), c3.clone(), out.clone()]);
    }
}
