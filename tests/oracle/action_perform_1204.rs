//! PIPE-0000 Rust comparand for the locked Action executor fixture.
//!
//! ScriptedAction supplies only deterministic `apply()` observations.  The
//! state machine under test is Rugra's public `Action::perform` and
//! `ActionGroup` API.

use rudra::action::{action_flags, status_flags, Action, ActionGroup, ActionState};
use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::Result;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Copy)]
struct ScriptStep {
    changes: i32,
    result: i32,
}

impl ScriptStep {
    const fn new(changes: i32, result: i32) -> Self {
        Self { changes, result }
    }
}

struct ProbeData {
    script: Vec<ScriptStep>,
    cursor: usize,
    apply_calls: u32,
    reset_calls: u32,
    observed_changes: Vec<i32>,
}

impl ProbeData {
    fn new(script: Vec<ScriptStep>) -> Self {
        Self {
            script,
            cursor: 0,
            apply_calls: 0,
            reset_calls: 0,
            observed_changes: Vec::new(),
        }
    }
}

struct ScriptedAction {
    name: String,
    flags: u32,
    probe: Rc<RefCell<ProbeData>>,
    trace: Option<Rc<RefCell<Vec<String>>>>,
}

impl ScriptedAction {
    fn new(
        flags: u32,
        name: &str,
        script: Vec<ScriptStep>,
        trace: Option<Rc<RefCell<Vec<String>>>>,
    ) -> Self {
        Self {
            name: name.to_string(),
            flags,
            probe: Rc::new(RefCell::new(ProbeData::new(script))),
            trace,
        }
    }

    fn handle(&self) -> Rc<RefCell<ProbeData>> {
        Rc::clone(&self.probe)
    }
}

impl Action for ScriptedAction {
    fn apply(&mut self, _fd: &mut Funcdata) -> Result<i32> {
        if let Some(trace) = &self.trace {
            trace.borrow_mut().push(self.name.clone());
        }
        let mut probe = self.probe.borrow_mut();
        probe.apply_calls += 1;
        let step = if probe.cursor < probe.script.len() {
            let step = probe.script[probe.cursor];
            probe.cursor += 1;
            step
        } else {
            ScriptStep::new(0, 0)
        };
        probe.observed_changes.push(step.changes);
        if step.result < 0 {
            Ok(step.result)
        } else {
            // Rust actions report their change count as the positive apply
            // result; Action::perform adapts this to Ghidra's protected count.
            Ok(step.changes)
        }
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn reset(&mut self, _fd: &mut Funcdata) {
        self.probe.borrow_mut().reset_calls += 1;
    }

    fn get_flags(&self) -> u32 {
        self.flags
    }
}

fn reset_action(action: &mut dyn Action, state: &mut ActionState, fd: &mut Funcdata) {
    // Rugra keeps Ghidra's inherited Action fields in the public ActionState
    // companion, so the caller applies Action::reset's status/flag mutation.
    state.status = status_flags::STATUS_START;
    state.flags &= !action_flags::RULE_WARNINGS_GIVEN;
    action.reset(fd);
}

fn json_string(output: &mut String, value: &str) {
    output.push('"');
    for ch in value.bytes() {
        match ch {
            b'"' => output.push_str("\\\""),
            b'\\' => output.push_str("\\\\"),
            b'\x08' => output.push_str("\\b"),
            b'\x0c' => output.push_str("\\f"),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'\t' => output.push_str("\\t"),
            0x00..=0x1f => {
                use std::fmt::Write;
                write!(output, "\\u00{ch:02x}").expect("write to String");
            }
            _ => output.push(char::from(ch)),
        }
    }
    output.push('"');
}

fn number_array<T: std::fmt::Display>(output: &mut String, values: &[T]) {
    use std::fmt::Write;
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(output, "{value}").expect("write to String");
    }
    output.push(']');
}

fn string_array(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        json_string(output, value);
    }
    output.push(']');
}

fn write_snapshot(output: &mut String, state: &ActionState) {
    use std::fmt::Write;
    write!(
        output,
        "{{\"status\":{},\"count\":{},\"lcount\":{},\"count_tests\":{},\"count_apply\":{}}}",
        state.status, state.count, state.lcount, state.count_tests, state.count_apply
    )
    .expect("write to String");
}

fn write_leaf_state(
    output: &mut String,
    name: &str,
    state: &ActionState,
    probe: &Rc<RefCell<ProbeData>>,
) {
    use std::fmt::Write;
    let probe = probe.borrow();
    output.push_str("{\"name\":");
    json_string(output, name);
    output.push_str(",\"executor\":");
    write_snapshot(output, state);
    write!(
        output,
        ",\"apply_calls\":{},\"reset_calls\":{},\"script_cursor\":{}}}",
        probe.apply_calls, probe.reset_calls, probe.cursor
    )
    .expect("write to String");
}

fn write_leaf_event(
    output: &mut String,
    label: &str,
    result: i32,
    name: &str,
    state: &ActionState,
    probe: &Rc<RefCell<ProbeData>>,
    change_begin: usize,
) {
    use std::fmt::Write;
    output.push_str("{\"label\":");
    json_string(output, label);
    write!(output, ",\"return\":{result},\"changes\":").expect("write to String");
    number_array(output, &probe.borrow().observed_changes[change_begin..]);
    output.push_str(",\"action\":");
    write_leaf_state(output, name, state, probe);
    output.push('}');
}

fn write_reset_event(
    output: &mut String,
    label: &str,
    name: &str,
    state: &ActionState,
    probe: &Rc<RefCell<ProbeData>>,
) {
    output.push_str("{\"label\":");
    json_string(output, label);
    output.push_str(",\"return\":null,\"changes\":[],\"action\":");
    write_leaf_state(output, name, state, probe);
    output.push('}');
}

fn write_repeat_case(output: &mut String, fd: &mut Funcdata) -> Result<()> {
    let mut action = ScriptedAction::new(
        action_flags::RULE_REPEATAPPLY,
        "repeat_leaf",
        vec![
            ScriptStep::new(2, 0),
            ScriptStep::new(1, 0),
            ScriptStep::new(0, 0),
        ],
        None,
    );
    let probe = action.handle();
    let mut state = ActionState::new(action_flags::RULE_REPEATAPPLY);
    reset_action(&mut action, &mut state, fd);
    output.push_str("{\"id\":\"repeatapply\",\"flags\":4,\"events\":[");
    let mut begin = probe.borrow().observed_changes.len();
    let mut result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_1",
        result,
        "repeat_leaf",
        &state,
        &probe,
        begin,
    );
    output.push(',');
    begin = probe.borrow().observed_changes.len();
    result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_2",
        result,
        "repeat_leaf",
        &state,
        &probe,
        begin,
    );
    output.push_str("]}");
    Ok(())
}

fn write_once_case(output: &mut String, fd: &mut Funcdata) -> Result<()> {
    let mut action = ScriptedAction::new(
        action_flags::RULE_ONCEPERFUNC,
        "once_leaf",
        vec![ScriptStep::new(0, 0), ScriptStep::new(5, 0)],
        None,
    );
    let probe = action.handle();
    let mut state = ActionState::new(action_flags::RULE_ONCEPERFUNC);
    reset_action(&mut action, &mut state, fd);
    output.push_str("{\"id\":\"once_per_func\",\"flags\":8,\"events\":[");
    let mut begin = probe.borrow().observed_changes.len();
    let mut result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_1",
        result,
        "once_leaf",
        &state,
        &probe,
        begin,
    );
    output.push(',');
    begin = probe.borrow().observed_changes.len();
    result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_2",
        result,
        "once_leaf",
        &state,
        &probe,
        begin,
    );
    output.push(',');
    reset_action(&mut action, &mut state, fd);
    write_reset_event(output, "reset", "once_leaf", &state, &probe);
    output.push(',');
    begin = probe.borrow().observed_changes.len();
    result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_3",
        result,
        "once_leaf",
        &state,
        &probe,
        begin,
    );
    output.push_str("]}");
    Ok(())
}

fn write_one_act_case(output: &mut String, fd: &mut Funcdata) -> Result<()> {
    let mut action = ScriptedAction::new(
        action_flags::RULE_ONEACTPERFUNC,
        "oneact_leaf",
        vec![
            ScriptStep::new(0, 0),
            ScriptStep::new(4, 0),
            ScriptStep::new(9, 0),
        ],
        None,
    );
    let probe = action.handle();
    let mut state = ActionState::new(action_flags::RULE_ONEACTPERFUNC);
    reset_action(&mut action, &mut state, fd);
    output.push_str("{\"id\":\"one_act_per_func\",\"flags\":16,\"events\":[");
    let mut begin = probe.borrow().observed_changes.len();
    let mut result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_1",
        result,
        "oneact_leaf",
        &state,
        &probe,
        begin,
    );
    output.push(',');
    begin = probe.borrow().observed_changes.len();
    result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_2",
        result,
        "oneact_leaf",
        &state,
        &probe,
        begin,
    );
    output.push(',');
    begin = probe.borrow().observed_changes.len();
    result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_3",
        result,
        "oneact_leaf",
        &state,
        &probe,
        begin,
    );
    output.push(',');
    reset_action(&mut action, &mut state, fd);
    write_reset_event(output, "reset", "oneact_leaf", &state, &probe);
    output.push(',');
    begin = probe.borrow().observed_changes.len();
    result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_4",
        result,
        "oneact_leaf",
        &state,
        &probe,
        begin,
    );
    output.push_str("]}");
    Ok(())
}

fn write_partial_leaf_case(output: &mut String, fd: &mut Funcdata) -> Result<()> {
    let mut action = ScriptedAction::new(
        0,
        "partial_leaf",
        vec![ScriptStep::new(0, -7), ScriptStep::new(2, 0)],
        None,
    );
    let probe = action.handle();
    let mut state = ActionState::new(0);
    reset_action(&mut action, &mut state, fd);
    output.push_str("{\"id\":\"partial_leaf_resume\",\"flags\":0,\"events\":[");
    let mut begin = probe.borrow().observed_changes.len();
    let mut result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_1",
        result,
        "partial_leaf",
        &state,
        &probe,
        begin,
    );
    output.push(',');
    begin = probe.borrow().observed_changes.len();
    result = action.perform(fd, &mut state)?;
    write_leaf_event(
        output,
        "perform_2",
        result,
        "partial_leaf",
        &state,
        &probe,
        begin,
    );
    output.push_str("]}");
    Ok(())
}

fn write_group_children(
    output: &mut String,
    group: &ActionGroup,
    names: &[String],
    probes: &[Rc<RefCell<ProbeData>>],
) {
    output.push('[');
    for index in 0..names.len() {
        if index != 0 {
            output.push(',');
        }
        let state = group
            .child_state(index)
            .unwrap_or_else(|| panic!("missing ActionGroup child state {index}"));
        write_leaf_state(output, &names[index], state, &probes[index]);
    }
    output.push(']');
}

#[allow(clippy::too_many_arguments)]
fn write_group_event(
    output: &mut String,
    label: &str,
    result: i32,
    group: &ActionGroup,
    group_state: &ActionState,
    names: &[String],
    probes: &[Rc<RefCell<ProbeData>>],
    trace: &Rc<RefCell<Vec<String>>>,
    trace_begin: usize,
    change_begin: [usize; 3],
) {
    use std::fmt::Write;
    output.push_str("{\"label\":");
    json_string(output, label);
    write!(output, ",\"return\":{result},\"trace\":").expect("write to String");
    string_array(output, &trace.borrow()[trace_begin..]);
    output.push_str(",\"changes\":[");
    for index in 0..3 {
        if index != 0 {
            output.push(',');
        }
        number_array(
            output,
            &probes[index].borrow().observed_changes[change_begin[index]..],
        );
    }
    write!(
        output,
        "],\"group_state_index\":{},\"group\":",
        group.current_index()
    )
    .expect("write to String");
    write_snapshot(output, group_state);
    output.push_str(",\"children\":");
    write_group_children(output, group, names, probes);
    output.push('}');
}

#[allow(clippy::too_many_arguments)]
fn write_group_reset_event(
    output: &mut String,
    label: &str,
    group: &ActionGroup,
    group_state: &ActionState,
    names: &[String],
    probes: &[Rc<RefCell<ProbeData>>],
    trace: &Rc<RefCell<Vec<String>>>,
    trace_begin: usize,
    change_begin: [usize; 3],
) {
    use std::fmt::Write;
    output.push_str("{\"label\":");
    json_string(output, label);
    output.push_str(",\"return\":null,\"trace\":");
    string_array(output, &trace.borrow()[trace_begin..]);
    output.push_str(",\"changes\":[");
    for index in 0..3 {
        if index != 0 {
            output.push(',');
        }
        number_array(
            output,
            &probes[index].borrow().observed_changes[change_begin[index]..],
        );
    }
    write!(
        output,
        "],\"group_state_index\":{},\"group\":",
        group.current_index()
    )
    .expect("write to String");
    write_snapshot(output, group_state);
    output.push_str(",\"children\":");
    write_group_children(output, group, names, probes);
    output.push('}');
}

fn write_group_case(output: &mut String, fd: &mut Funcdata) -> Result<()> {
    let trace = Rc::new(RefCell::new(Vec::new()));
    let first = ScriptedAction::new(
        0,
        "group_first",
        vec![ScriptStep::new(1, 0)],
        Some(Rc::clone(&trace)),
    );
    let partial = ScriptedAction::new(
        0,
        "group_partial",
        vec![ScriptStep::new(0, -7), ScriptStep::new(2, 0)],
        Some(Rc::clone(&trace)),
    );
    let last = ScriptedAction::new(
        0,
        "group_last",
        vec![ScriptStep::new(4, 0)],
        Some(Rc::clone(&trace)),
    );
    let probes = vec![first.handle(), partial.handle(), last.handle()];
    let names = vec![
        "group_first".to_string(),
        "group_partial".to_string(),
        "group_last".to_string(),
    ];
    let mut group = ActionGroup::with_flags("partial_group", 0);
    group.add_action(Box::new(first));
    group.add_action(Box::new(partial));
    group.add_action(Box::new(last));
    let mut state = ActionState::new(0);
    reset_action(&mut group, &mut state, fd);

    output.push_str("{\"id\":\"group_partial_resume\",\"flags\":0,\"child_order\":");
    string_array(output, &names);
    output.push_str(",\"events\":[");

    let mut trace_begin = trace.borrow().len();
    let mut change_begin = [
        probes[0].borrow().observed_changes.len(),
        probes[1].borrow().observed_changes.len(),
        probes[2].borrow().observed_changes.len(),
    ];
    let mut result = group.perform(fd, &mut state)?;
    write_group_event(
        output,
        "perform_1",
        result,
        &group,
        &state,
        &names,
        &probes,
        &trace,
        trace_begin,
        change_begin,
    );
    output.push(',');

    trace_begin = trace.borrow().len();
    change_begin = [
        probes[0].borrow().observed_changes.len(),
        probes[1].borrow().observed_changes.len(),
        probes[2].borrow().observed_changes.len(),
    ];
    result = group.perform(fd, &mut state)?;
    write_group_event(
        output,
        "perform_2",
        result,
        &group,
        &state,
        &names,
        &probes,
        &trace,
        trace_begin,
        change_begin,
    );

    output.push(',');
    trace_begin = trace.borrow().len();
    change_begin = [
        probes[0].borrow().observed_changes.len(),
        probes[1].borrow().observed_changes.len(),
        probes[2].borrow().observed_changes.len(),
    ];
    reset_action(&mut group, &mut state, fd);
    write_group_reset_event(
        output,
        "reset_after_complete",
        &group,
        &state,
        &names,
        &probes,
        &trace,
        trace_begin,
        change_begin,
    );

    output.push(',');
    trace_begin = trace.borrow().len();
    change_begin = [
        probes[0].borrow().observed_changes.len(),
        probes[1].borrow().observed_changes.len(),
        probes[2].borrow().observed_changes.len(),
    ];
    result = group.perform(fd, &mut state)?;
    write_group_event(
        output,
        "perform_3",
        result,
        &group,
        &state,
        &names,
        &probes,
        &trace,
        trace_begin,
        change_begin,
    );
    output.push_str("]}");
    Ok(())
}

fn run() -> Result<String> {
    let mut fd = Funcdata::new("GetStr", Address::new(14_032), 0);
    let mut output = String::new();
    output.push_str("{\"schema\":1,\"fixture\":\"PIPE-0000\",\"function\":{\"name\":");
    json_string(&mut output, &fd.name);
    use std::fmt::Write;
    write!(
        output,
        ",\"entry\":{},\"size\":{}}},\"cases\":[",
        fd.baseaddr.as_u64(),
        fd.size
    )
    .expect("write to String");
    write_repeat_case(&mut output, &mut fd)?;
    output.push(',');
    write_once_case(&mut output, &mut fd)?;
    output.push(',');
    write_one_act_case(&mut output, &mut fd)?;
    output.push(',');
    write_partial_leaf_case(&mut output, &mut fd)?;
    output.push(',');
    write_group_case(&mut output, &mut fd)?;
    output.push_str("]}\n");
    Ok(output)
}

fn main() {
    match run() {
        Ok(output) => print!("{output}"),
        Err(error) => {
            eprintln!("action_perform_1204 Rust fixture failed: {error}");
            std::process::exit(1);
        }
    }
}
