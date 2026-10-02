//! ACTIONPOOL-CLONE-FILTER-0001 Rust comparand.
//!
//! This drives production ActionDatabase derivation and ActionPool cloning.
//! Only the synthetic Rule supplies its own virtual clone, exactly like a
//! concrete Ghidra Rule; no hand-written expected output is embedded.

use rudra::action::{
    action_flags, status_flags, Action, ActionDatabase, ActionGroupList, ActionPool, ActionState,
    Rule,
};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::Result;
use std::sync::{Arc, RwLock};

struct ScriptRule {
    group: &'static str,
    constructor_flags: u32,
    name: &'static str,
    opcodes: Vec<OpCode>,
    runtime_flags: u32,
    breakpoint: u32,
    count_tests: u32,
    count_apply: u32,
}

impl ScriptRule {
    fn new(
        group: &'static str,
        constructor_flags: u32,
        name: &'static str,
        opcodes: Vec<OpCode>,
        dirty: bool,
        ordinal: u32,
    ) -> Self {
        Self {
            group,
            constructor_flags,
            name,
            opcodes,
            runtime_flags: if dirty {
                constructor_flags | 1 | 4 | 8
            } else {
                constructor_flags
            },
            breakpoint: if dirty { 9 + ordinal } else { 0 },
            count_tests: if dirty { 30 + ordinal } else { 0 },
            count_apply: if dirty { 20 + ordinal } else { 0 },
        }
    }
}

impl Rule for ScriptRule {
    fn apply_op(&self, _op: &Arc<RwLock<PcodeOp>>, _fd: &mut Funcdata) -> Result<i32> {
        Ok(0)
    }

    fn get_name(&self) -> &str {
        self.name
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        self.opcodes.clone()
    }

    fn clone_for_groups(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Rule>> {
        if !grouplist.contains(self.group) {
            return None;
        }
        Some(Box::new(Self::new(
            self.group,
            self.constructor_flags,
            self.name,
            self.opcodes.clone(),
            false,
            0,
        )))
    }

    fn get_group(&self) -> &str {
        self.group
    }
    fn get_rule_flags(&self) -> u32 {
        self.runtime_flags
    }
    fn get_breakpoint(&self) -> u32 {
        self.breakpoint
    }
    fn get_num_tests(&self) -> u32 {
        self.count_tests
    }
    fn get_num_apply(&self) -> u32 {
        self.count_apply
    }
}

fn opcode_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_COPY => "copy",
        OpCode::CPUI_INT_ADD => "int_add",
        OpCode::CPUI_INT_SUB => "int_sub",
        _ => "unknown",
    }
}

fn build_source() -> ActionPool {
    let mut pool = ActionPool::with_flags(
        "universal",
        action_flags::RULE_REPEATAPPLY
            | action_flags::RULE_ONCEPERFUNC
            | action_flags::RULE_WARNINGS_GIVEN,
    );
    pool.add_rule(Box::new(ScriptRule::new(
        "alpha",
        2,
        "a",
        vec![OpCode::CPUI_COPY, OpCode::CPUI_INT_ADD],
        true,
        0,
    )));
    pool.add_rule(Box::new(ScriptRule::new(
        "beta",
        0,
        "b",
        vec![OpCode::CPUI_INT_ADD],
        true,
        1,
    )));
    pool.add_rule(Box::new(ScriptRule::new(
        "alpha",
        4,
        "c",
        vec![OpCode::CPUI_COPY],
        true,
        2,
    )));
    pool.add_rule(Box::new(ScriptRule::new(
        "gamma",
        0,
        "d",
        vec![OpCode::CPUI_INT_SUB, OpCode::CPUI_COPY],
        true,
        3,
    )));
    pool
}

fn emit_pool(case_name: &str, action: Option<&dyn Action>, state: Option<&ActionState>) {
    let Some(pool) = action.and_then(Action::as_action_pool) else {
        println!("case={case_name} null=1");
        return;
    };
    let state = state.expect("non-null pool state");
    println!(
        "case={case_name} null=0 name={} flags={} status={} breakpoint={} tests={} apply={} rules={}",
        pool.get_name(),
        state.flags,
        state.status,
        state.breakpoint,
        state.count_tests,
        state.count_apply,
        pool.rules().len(),
    );
    for (index, rule) in pool.rules().iter().enumerate() {
        let opcodes = rule
            .get_opcodes()
            .into_iter()
            .map(opcode_name)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "rule={case_name}:{index} name={} group={} flags={} breakpoint={} tests={} apply={} opcodes={opcodes}",
            rule.get_name(),
            pool.rule_group(index),
            rule.get_rule_flags(),
            rule.get_breakpoint(),
            rule.get_num_tests(),
            rule.get_num_apply(),
        );
    }
    for opcode in [
        OpCode::CPUI_COPY,
        OpCode::CPUI_INT_ADD,
        OpCode::CPUI_INT_SUB,
    ] {
        println!(
            "perop={case_name}:{} rules={}",
            opcode_name(opcode),
            pool.rule_names_for_opcode(opcode).join(","),
        );
    }
}

fn derive_and_emit(database: &mut ActionDatabase, name: &str) {
    let was_absent = !database.has_action_entry(name);
    database.set_current(name);
    let first = database
        .get_action(name)
        .map(|action| action as *const dyn Action as *const ());
    database.set_current(name);
    let second = database
        .get_action(name)
        .map(|action| action as *const dyn Action as *const ());
    let entry = database.has_action_entry(name);
    let cached = was_absent && entry && first == second;
    println!(
        "derive={name} entry={} cached={} current={}",
        u8::from(entry),
        u8::from(cached),
        database.get_current_name(),
    );
    let action = database.get_action(name);
    let state = action.map(|action| ActionState::new(action.get_flags()));
    emit_pool(name, action, state.as_ref());
}

fn main() {
    let source = build_source();
    let mut source_state = ActionState::new(source.get_flags());
    source_state.status = status_flags::STATUS_MID;
    source_state.breakpoint = 5;
    source_state.count_tests = 17;
    source_state.count_apply = 11;
    emit_pool("source", Some(&source), Some(&source_state));

    let mut database = ActionDatabase::new();
    database.register_action(Box::new(source));
    database.set_group("all", &["alpha", "beta", "gamma"]);
    database.set_group("custom", &["alpha", "gamma"]);
    database.set_group("empty", &[]);

    derive_and_emit(&mut database, "all");
    derive_and_emit(&mut database, "custom");
    derive_and_emit(&mut database, "empty");
}
