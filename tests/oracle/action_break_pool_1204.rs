//! ACTION-EXECUTOR-BREAKPOOL-0001 Rust comparand.
//!
//! Scripted leaves and Rules supply only deterministic changes. The observed
//! state transitions are Rudra's production Action/Group/Pool executor.

use rudra::action::{
    break_flags, rule_flags, Action, ActionGroup, ActionGroupList, ActionPool, ActionRestartGroup,
    ActionState, Rule, RuleState, build_default_pipeline, default_groups, universal_action,
};
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy)]
struct Step {
    changes: i32,
    result: i32,
}

#[derive(Default)]
struct ActionProbe {
    cursor: usize,
    calls: u32,
    resets: u32,
}

struct ScriptAction {
    name: String,
    flags: u32,
    script: Vec<Step>,
    probe: Rc<RefCell<ActionProbe>>,
    trace: Option<Rc<RefCell<Vec<String>>>>,
}

impl ScriptAction {
    fn new(
        flags: u32,
        name: &str,
        script: Vec<Step>,
        trace: Option<Rc<RefCell<Vec<String>>>>,
    ) -> Self {
        Self {
            name: name.to_string(),
            flags,
            script,
            probe: Rc::new(RefCell::new(ActionProbe::default())),
            trace,
        }
    }

    fn handle(&self) -> Rc<RefCell<ActionProbe>> {
        Rc::clone(&self.probe)
    }
}

impl Action for ScriptAction {
    fn apply(&mut self, _fd: &mut Funcdata) -> rudra::Result<i32> {
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(self.name.clone());
        }
        let mut probe = self.probe.borrow_mut();
        probe.calls += 1;
        let step = self
            .script
            .get(probe.cursor)
            .copied()
            .unwrap_or(Step { changes: 0, result: 0 });
        if probe.cursor < self.script.len() {
            probe.cursor += 1;
        }
        if step.result < 0 {
            Ok(step.result)
        } else {
            Ok(step.changes)
        }
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn reset(&mut self, _fd: &mut Funcdata) {
        self.probe.borrow_mut().resets += 1;
    }

    fn get_flags(&self) -> u32 {
        self.flags
    }
}

fn print_action_state(
    kind: &str,
    event: &str,
    result: i32,
    state: &ActionState,
    calls: u32,
) {
    println!(
        "{kind}|event={event}|return={result}|status={}|count={}|lcount={}|tests={}|applies={}|bp={}|flags={}|calls={calls}",
        state.status,
        state.count,
        state.lcount,
        state.count_tests,
        state.count_apply,
        state.breakpoint,
        state.flags,
    );
}

fn run_leaf(fd: &mut Funcdata) -> rudra::Result<()> {
    let mut leaf = ScriptAction::new(
        rudra::action::action_flags::RULE_REPEATAPPLY,
        "leaf",
        vec![Step { changes: 2, result: 0 }, Step { changes: 0, result: 0 }],
        None,
    );
    let probe = leaf.handle();
    let mut state = ActionState::new(rudra::action::action_flags::RULE_REPEATAPPLY);
    leaf.reset_for_function(fd, &mut state);
    leaf.set_warning(&mut state, true, "leaf");
    leaf.set_break_point(
        &mut state,
        break_flags::BREAK_START
            | break_flags::TMPBREAK_START
            | break_flags::BREAK_ACTION
            | break_flags::TMPBREAK_ACTION,
        "leaf",
    );
    let result = leaf.perform(fd, &mut state)?;
    print_action_state("leaf", "start_break", result, &state, probe.borrow().calls);
    let result = leaf.perform(fd, &mut state)?;
    print_action_state("leaf", "action_break", result, &state, probe.borrow().calls);
    let result = leaf.perform(fd, &mut state)?;
    print_action_state("leaf", "resume_complete", result, &state, probe.borrow().calls);
    let result = leaf.perform(fd, &mut state)?;
    print_action_state("leaf", "persistent_start", result, &state, probe.borrow().calls);
    leaf.reset_for_function(fd, &mut state);
    print_action_state("leaf", "reset", 999, &state, probe.borrow().calls);
    leaf.clear_break_points(&mut state);
    let result = leaf.perform(fd, &mut state)?;
    print_action_state("leaf", "after_clear", result, &state, probe.borrow().calls);
    Ok(())
}

fn run_group(fd: &mut Funcdata) -> rudra::Result<()> {
    let trace = Rc::new(RefCell::new(Vec::<String>::new()));
    let first = ScriptAction::new(
        0,
        "first",
        vec![Step { changes: 1, result: 0 }],
        Some(Rc::clone(&trace)),
    );
    let first_probe = first.handle();
    let second = ScriptAction::new(
        0,
        "second",
        vec![Step { changes: 1, result: 0 }],
        Some(Rc::clone(&trace)),
    );
    let second_probe = second.handle();
    let mut group = ActionGroup::with_flags("group", 0);
    group.add_action(Box::new(first));
    group.add_action(Box::new(second));
    let mut state = ActionState::new(0);
    group.reset_for_function(fd, &mut state);
    group.set_warning(&mut state, true, "group");
    group.set_break_point(&mut state, break_flags::BREAK_ACTION, "group");
    for call in 1..=4 {
        let begin = trace.borrow().len();
        let result = group.perform(fd, &mut state)?;
        let delta = trace.borrow()[begin..].join(">");
        println!(
            "group|call={call}|return={result}|cursor={}|trace={delta}|status={}|count={}|lcount={}|tests={}|applies={}|bp={}|child_calls={},{}",
            group.current_index(),
            state.status,
            state.count,
            state.lcount,
            state.count_tests,
            state.count_apply,
            state.breakpoint,
            first_probe.borrow().calls,
            second_probe.borrow().calls,
        );
    }

    let child = ScriptAction::new(
        0,
        "partial",
        vec![Step { changes: 0, result: -7 }, Step { changes: 2, result: 0 }],
        Some(Rc::clone(&trace)),
    );
    let child_probe = child.handle();
    let mut partial = ActionGroup::with_flags("partial_group", 0);
    partial.add_action(Box::new(child));
    let mut partial_state = ActionState::new(0);
    partial.reset_for_function(fd, &mut partial_state);
    for call in 1..=2 {
        let begin = trace.borrow().len();
        let result = partial.perform(fd, &mut partial_state)?;
        let delta = trace.borrow()[begin..].join(">");
        println!(
            "group_partial|call={call}|return={result}|cursor={}|trace={delta}|child_calls={}",
            partial.current_index(),
            child_probe.borrow().calls,
        );
    }
    Ok(())
}

struct LookupRule {
    name: String,
}

impl LookupRule {
    fn new(name: &str) -> Self {
        Self { name: name.to_string() }
    }
}

impl Rule for LookupRule {
    fn apply_op(
        &self,
        _op: &Arc<RwLock<PcodeOp>>,
        _fd: &mut Funcdata,
    ) -> rudra::Result<i32> {
        Ok(0)
    }
    fn get_name(&self) -> &str {
        &self.name
    }
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_COPY]
    }
}

fn run_lookup() {
    let mut ambiguous = ActionGroup::with_flags("ambiguous", 0);
    ambiguous.add_action(Box::new(ScriptAction::new(0, "dup", vec![], None)));
    ambiguous.add_action(Box::new(ScriptAction::new(0, "dup", vec![], None)));
    let mut unique = ActionGroup::with_flags("unique", 0);
    unique.add_action(Box::new(ScriptAction::new(0, "dup", vec![], None)));
    let mut actions = ActionGroup::with_flags("root", 0);
    actions.add_action(Box::new(ambiguous));
    actions.add_action(Box::new(unique));
    let mut action_state = ActionState::new(0);
    let action_local = actions.set_break_point(&mut action_state, break_flags::BREAK_START, "dup");
    let action_qualified = actions.set_break_point(
        &mut action_state,
        break_flags::BREAK_ACTION,
        "root:ambiguous:dup",
    );
    let ambiguous = actions.child_actions()[0].as_action_group().unwrap();
    let unique = actions.child_actions()[1].as_action_group().unwrap();
    let action_bp = format!(
        "{},{},{}",
        ambiguous.child_state(0).unwrap().breakpoint,
        ambiguous.child_state(1).unwrap().breakpoint,
        unique.child_state(0).unwrap().breakpoint,
    );

    let mut amb_pool = ActionPool::with_flags("amb_pool", 0);
    amb_pool.add_rule(Box::new(LookupRule::new("same_rule")));
    amb_pool.add_rule(Box::new(LookupRule::new("same_rule")));
    let mut unique_pool = ActionPool::with_flags("unique_pool", 0);
    unique_pool.add_rule(Box::new(LookupRule::new("same_rule")));
    let mut rules = ActionGroup::with_flags("rule_root", 0);
    rules.add_action(Box::new(amb_pool));
    rules.add_action(Box::new(unique_pool));
    let rule_local = rules.disable_rule("same_rule");
    let rule_qualified = rules.set_break_point(
        &mut ActionState::new(0),
        break_flags::BREAK_ACTION,
        "rule_root:amb_pool:same_rule",
    );
    let amb_pool = rules.child_actions()[0].as_action_pool().unwrap();
    let unique_pool = rules.child_actions()[1].as_action_pool().unwrap();
    println!(
        "lookup|action_local={}|action_qualified={}|action_bp={action_bp}|rule_local={}|rule_qualified={}|rule_disabled={},{},{}|rule_bp={},{},{}",
        u8::from(action_local),
        u8::from(action_qualified),
        u8::from(rule_local),
        u8::from(rule_qualified),
        u8::from(amb_pool.rule_state(0).unwrap().is_disabled()),
        u8::from(amb_pool.rule_state(1).unwrap().is_disabled()),
        u8::from(unique_pool.rule_state(0).unwrap().is_disabled()),
        amb_pool.rule_state(0).unwrap().breakpoint,
        amb_pool.rule_state(1).unwrap().breakpoint,
        unique_pool.rule_state(0).unwrap().breakpoint,
    );
}

#[derive(Default)]
struct LiveProbe {
    trace: Vec<String>,
    mutated: bool,
    resets: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveKind {
    Mutate,
    Audit,
    Disabled,
}

struct LiveRule {
    name: String,
    kind: LiveKind,
    probe: Rc<RefCell<LiveProbe>>,
}

impl LiveRule {
    fn new(name: &str, kind: LiveKind, probe: Rc<RefCell<LiveProbe>>) -> Self {
        Self { name: name.to_string(), kind, probe }
    }
}

impl Rule for LiveRule {
    fn apply_op(
        &self,
        op: &Arc<RwLock<PcodeOp>>,
        fd: &mut Funcdata,
    ) -> rudra::Result<i32> {
        let address = op.read().unwrap().get_addr().as_u64();
        self.probe
            .borrow_mut()
            .trace
            .push(format!("{}@{address}", self.name));
        if self.kind != LiveKind::Mutate
            || self.probe.borrow().mutated
            || address != 0x1000
        {
            return Ok(0);
        }
        self.probe.borrow_mut().mutated = true;
        let block = op
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .expect("live fixture current op must be integrated");
        let low = fd.new_op(0, Address::new(0x900));
        fd.op_set_opcode(&low, OpCode::CPUI_COPY);
        fd.op_insert_end(&low, &block);
        let high = fd.new_op(0, Address::new(0x2000));
        fd.op_set_opcode(&high, OpCode::CPUI_COPY);
        fd.op_insert_end(&high, &block);
        fd.op_destroy(&PcodeOpRef(Arc::clone(op)));
        Ok(3)
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_COPY]
    }

    fn reset(&mut self, _fd: &mut Funcdata) {
        self.probe.borrow_mut().resets += 1;
    }
}

fn tree_state(fd: &Funcdata) -> String {
    fd.obank
        .optree
        .iter()
        .map(|op| {
            let op = op.0.read().unwrap();
            format!(
                "{}@{}:{}",
                op.get_addr().as_u64(),
                op.get_time(),
                u8::from(op.is_dead()),
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn pool_cursor(pool: &ActionPool, fd: &Funcdata) -> String {
    match pool.resume_state(fd).0 {
        Some(seq) => format!("{}@{}", seq.get_addr().as_u64(), seq.get_time()),
        None => "end".to_string(),
    }
}

fn print_pool_event(
    event: &str,
    result: i32,
    pool: &ActionPool,
    state: &ActionState,
    fd: &Funcdata,
    probe: &Rc<RefCell<LiveProbe>>,
    trace_begin: usize,
) {
    let probe = probe.borrow();
    let disabled = pool.rule_state(0).unwrap();
    let mutate = pool.rule_state(1).unwrap();
    let audit = pool.rule_state(2).unwrap();
    println!(
        "pool|event={event}|return={result}|cursor={}|rule_index={}|trace={}|tree={}|status={}|count={}|lcount={}|tests={}|applies={}|bp={}|flags={}|rule_stats={}/{},{}/{},{}/{}|rule_bp={},{},{}|rule_flags={},{},{}",
        pool_cursor(pool, fd),
        pool.resume_state(fd).1,
        probe.trace[trace_begin..].join(">"),
        tree_state(fd),
        state.status,
        state.count,
        state.lcount,
        state.count_tests,
        state.count_apply,
        state.breakpoint,
        state.flags,
        disabled.count_tests,
        disabled.count_apply,
        mutate.count_tests,
        mutate.count_apply,
        audit.count_tests,
        audit.count_apply,
        disabled.breakpoint,
        mutate.breakpoint,
        audit.breakpoint,
        disabled.flags,
        mutate.flags,
        audit.flags,
    );
}

fn run_pool(fd: &mut Funcdata) -> rudra::Result<()> {
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
        BlockBasic::new(0, Address::new(0x800)),
    ));
    fd.bblocks.add_block(Arc::clone(&block));
    let initial_dead = fd.new_op(0, Address::new(0x800));
    fd.op_set_opcode(&initial_dead, OpCode::CPUI_COPY);
    let root = fd.new_op(0, Address::new(0x1000));
    fd.op_set_opcode(&root, OpCode::CPUI_COPY);
    fd.op_insert_end(&root, &block);
    let tail = fd.new_op(0, Address::new(0x3000));
    fd.op_set_opcode(&tail, OpCode::CPUI_COPY);
    fd.op_insert_end(&tail, &block);

    let probe = Rc::new(RefCell::new(LiveProbe::default()));
    let mut pool = ActionPool::with_flags("live_pool", 0);
    pool.add_rule(Box::new(LiveRule::new(
        "disabled",
        LiveKind::Disabled,
        Rc::clone(&probe),
    )));
    pool.add_rule(Box::new(LiveRule::new(
        "mutate",
        LiveKind::Mutate,
        Rc::clone(&probe),
    )));
    pool.add_rule(Box::new(LiveRule::new(
        "audit",
        LiveKind::Audit,
        Rc::clone(&probe),
    )));
    pool.disable_rule("live_pool:disabled");
    let mut state = ActionState::new(0);
    pool.set_warning(&mut state, true, "live_pool:mutate");
    pool.set_break_point(
        &mut state,
        break_flags::BREAK_START
            | break_flags::TMPBREAK_START
            | break_flags::BREAK_ACTION
            | break_flags::TMPBREAK_ACTION,
        "live_pool:mutate",
    );
    pool.set_warning(&mut state, true, "live_pool");
    pool.set_break_point(&mut state, break_flags::TMPBREAK_ACTION, "live_pool");
    pool.reset_for_function(fd, &mut state);

    for event in ["rule_break", "pool_break", "pool_resume", "fresh_pass"] {
        let begin = probe.borrow().trace.len();
        let result = pool.perform(fd, &mut state)?;
        print_pool_event(event, result, &pool, &state, fd, &probe, begin);
    }
    pool.reset_for_function(fd, &mut state);
    print_pool_event("reset", 999, &pool, &state, fd, &probe, probe.borrow().trace.len());
    pool.reset_stats(&mut state);
    print_pool_event(
        "reset_stats",
        999,
        &pool,
        &state,
        fd,
        &probe,
        probe.borrow().trace.len(),
    );
    Ok(())
}

#[derive(Default)]
struct ResetProbe {
    calls: u32,
    resets: u32,
}

struct ResetRule {
    name: String,
    probe: Rc<RefCell<ResetProbe>>,
    call_base: bool,
}

impl ResetRule {
    fn new(name: &str, probe: Rc<RefCell<ResetProbe>>, call_base: bool) -> Self {
        Self { name: name.to_string(), probe, call_base }
    }
}

impl Rule for ResetRule {
    fn apply_op(
        &self,
        _op: &Arc<RwLock<PcodeOp>>,
        _fd: &mut Funcdata,
    ) -> rudra::Result<i32> {
        self.probe.borrow_mut().calls += 1;
        Ok(1)
    }
    fn get_name(&self) -> &str {
        &self.name
    }
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_COPY]
    }
    fn reset(&mut self, _fd: &mut Funcdata) {
        self.probe.borrow_mut().resets += 1;
    }
    fn reset_for_function(&mut self, fd: &mut Funcdata, state: &mut RuleState) {
        if self.call_base {
            state.reset_for_function();
        }
        self.reset(fd);
    }
}

fn run_virtual_reset() -> rudra::Result<()> {
    let mut fd = Funcdata::new("virtual_reset", Address::new(0x5000), 0x20);
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
        BlockBasic::new(0, Address::new(0x5000)),
    ));
    fd.bblocks.add_block(Arc::clone(&block));
    let op = fd.new_op(0, Address::new(0x5000));
    fd.op_set_opcode(&op, OpCode::CPUI_COPY);
    fd.op_insert_end(&op, &block);
    let base_probe = Rc::new(RefCell::new(ResetProbe::default()));
    let no_base_probe = Rc::new(RefCell::new(ResetProbe::default()));
    let mut pool = ActionPool::with_flags("reset_pool", 0);
    pool.add_rule(Box::new(ResetRule::new(
        "base_reset",
        Rc::clone(&base_probe),
        true,
    )));
    pool.add_rule(Box::new(ResetRule::new(
        "no_base_reset",
        Rc::clone(&no_base_probe),
        false,
    )));
    let mut state = ActionState::new(0);
    pool.set_warning(&mut state, true, "base_reset");
    pool.set_warning(&mut state, true, "no_base_reset");
    pool.perform(&mut fd, &mut state)?;
    let base = pool.rule_state(0).unwrap();
    let no_base = pool.rule_state(1).unwrap();
    println!(
        "virtual_reset|event=before|flags={},{}|stats={}/{},{}/{}|calls={},{}|resets={},{}",
        base.flags,
        no_base.flags,
        base.count_tests,
        base.count_apply,
        no_base.count_tests,
        no_base.count_apply,
        base_probe.borrow().calls,
        no_base_probe.borrow().calls,
        base_probe.borrow().resets,
        no_base_probe.borrow().resets,
    );
    pool.reset_for_function(&mut fd, &mut state);
    let base = pool.rule_state(0).unwrap();
    let no_base = pool.rule_state(1).unwrap();
    println!(
        "virtual_reset|event=after|flags={},{}|stats={}/{},{}/{}|calls={},{}|resets={},{}",
        base.flags,
        no_base.flags,
        base.count_tests,
        base.count_apply,
        no_base.count_tests,
        no_base.count_apply,
        base_probe.borrow().calls,
        no_base_probe.borrow().calls,
        base_probe.borrow().resets,
        no_base_probe.borrow().resets,
    );
    Ok(())
}

// The two production Rules whose locked-oracle reset override deliberately
// omits Rule::reset (subflow.cc:1742-1746, double.cc:3198-3202), driven
// through the real ActionPool reset dispatch plus a rule-level probe for
// RuleSubvarSext's derived field.
fn run_production_reset_seam() -> rudra::Result<()> {
    let mut arch = Architecture::new();
    arch.aggressive_ext_trim = true;
    let mut fd = Funcdata::new("seam", Address::new(0x6000), 0x10);
    fd.set_arch(Arc::new(arch));
    let mut pool = ActionPool::with_flags("seam_pool", 0);
    pool.add_rule(Box::new(rudra::subflow::RuleSubvarSext::new()));
    pool.add_rule(Box::new(rudra::double_precis::RuleDoubleIn::new()));
    let mut state = ActionState::new(0);
    pool.set_warning(&mut state, true, "seam_pool:subvar_sext");
    pool.set_warning(&mut state, true, "seam_pool:doublein");
    // Simulate already-issued warnings (normally set by issue_warning).
    pool.rule_state_mut(0).unwrap().flags |= rule_flags::WARNINGS_GIVEN;
    pool.rule_state_mut(1).unwrap().flags |= rule_flags::WARNINGS_GIVEN;
    pool.reset_for_function(&mut fd, &mut state);
    let sext_flags = pool.rule_state(0).unwrap().flags;
    let din_flags = pool.rule_state(1).unwrap().flags;

    // Rule-level probe mirroring the oracle's direct derived reset.
    let mut probe = rudra::subflow::RuleSubvarSext::new();
    let mut probe_state = RuleState::new(0);
    probe_state.flags |= rule_flags::WARNINGS_GIVEN;
    probe.reset_for_function(&mut fd, &mut probe_state);
    println!(
        "production_reset|sext_flags={sext_flags}|din_flags={din_flags}|probe_sext_flags={}|probe_aggressive={}|double_precis={}",
        probe_state.flags,
        u8::from(probe.fixture_is_aggressive()),
        u8::from(fd.is_double_precis_on()),
    );
    Ok(())
}

// ActionRestartGroup forwards its inherited Action base fields into the
// embedded ActionGroup child boundary (action.cc:517/560).
fn run_restart_break() -> rudra::Result<()> {
    let mut fd = Funcdata::new("restart_break", Address::new(0x7000), 0x10);
    fd.set_arch(Arc::new(Architecture::new()));
    let child = ScriptAction::new(0, "maker", vec![Step { changes: 3, result: 0 }], None);
    let child_probe = child.handle();
    let mut restart = ActionRestartGroup::new("restart_probe", 0, 1);
    restart.add_action(Box::new(child));
    let mut state = ActionState::new(0);
    restart.reset_for_function(&mut fd, &mut state);
    restart.set_break_point(&mut state, break_flags::BREAK_ACTION, "restart_probe");
    for call in 1..=3 {
        let result = restart.perform(&mut fd, &mut state)?;
        println!(
            "restart_break|call={call}|return={result}|status={}|count={}|lcount={}|tests={}|applies={}|bp={}|cursor={}|curstart={}|calls={}",
            state.status,
            state.count,
            state.lcount,
            state.count_tests,
            state.count_apply,
            state.breakpoint,
            restart.as_action_group().unwrap().current_index(),
            restart.fixture_curstart(),
            child_probe.borrow().calls,
        );
    }
    Ok(())
}

// Depth-first projection of an Action tree: one line per Action node and,
// for ActionPool nodes, one line per registered Rule in insertion order.
fn walk_action(act: &dyn Action, depth: usize) {
    println!("dtree|{depth}:{}", act.get_name());
    if let Some(group) = act.as_action_group() {
        for child in group.child_actions() {
            walk_action(child.as_ref(), depth + 1);
        }
    } else if let Some(pool) = act.as_action_pool() {
        for rule in pool.rules() {
            println!("dtree|{}:{}", depth + 1, rule.get_name());
        }
    }
}

// The root derivations: raw universal tree plus the
// decompile/jumptable/register grouplist clones (action.cc:1145-1160,
// coreaction.cc:5419-5458/5462-5738).
fn run_derived_trees() {
    println!("dtree_root|raw");
    let raw = universal_action(None).expect("raw universal root");
    walk_action(&raw, 0);
    println!("dtree_root|decompile");
    let decompile = build_default_pipeline();
    walk_action(&decompile, 0);
    println!("dtree_root|jumptable");
    let jumptable = universal_action(Some(&ActionGroupList::from_members(
        default_groups::JUMPTABLE,
    )))
    .expect("jumptable root keeps children");
    walk_action(&jumptable, 0);
    println!("dtree_root|register");
    let register = universal_action(Some(&ActionGroupList::from_members(
        default_groups::REGISTER,
    )))
    .expect("register root keeps children");
    walk_action(&register, 0);
}

fn main() -> rudra::Result<()> {
    println!(
        "schema=1|fixture=ACTION-EXECUTOR-BREAKPOOL-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    let mut fd = Funcdata::new("break_pool", Address::new(0x800), 0x4000);
    fd.set_arch(Arc::new(Architecture::new()));
    run_leaf(&mut fd)?;
    run_group(&mut fd)?;
    run_lookup();
    run_pool(&mut fd)?;
    run_virtual_reset()?;
    run_production_reset_seam()?;
    run_restart_break()?;
    run_derived_trees();
    Ok(())
}
