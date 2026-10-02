//! PIPE-ACTION-COUNT-0001A Rust comparand for real coreaction leaves.
//!
//! InstrumentedAction only counts virtual calls and forwards the complete
//! Action interface.  Executor state is Rudra's public ActionState companion;
//! the actions under test are the production coreaction implementations.

use rudra::action::{action_flags, status_flags, Action, ActionGroup, ActionState};
use rudra::address::Address;
use rudra::coreaction::{
    ActionDefaultParams, ActionExtraPopSetup, ActionFuncLink, ActionFuncLinkOutOnly,
    ActionInternalStorage, ActionPrototypeTypes, ActionStartTypes,
};
use rudra::funcdata::Funcdata;
use rudra::Result;
use std::cell::RefCell;
use std::fmt::Write;
use std::rc::Rc;

#[derive(Default)]
struct Probe {
    apply_calls: u32,
    reset_calls: u32,
}

struct InstrumentedAction {
    inner: Box<dyn Action>,
    probe: Rc<RefCell<Probe>>,
}

impl InstrumentedAction {
    fn new(inner: Box<dyn Action>) -> Self {
        Self {
            inner,
            probe: Rc::new(RefCell::new(Probe::default())),
        }
    }

    fn handle(&self) -> Rc<RefCell<Probe>> {
        Rc::clone(&self.probe)
    }
}

impl Action for InstrumentedAction {
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        self.probe.borrow_mut().apply_calls += 1;
        self.inner.apply(fd)
    }

    fn get_name(&self) -> &str {
        self.inner.get_name()
    }

    fn reset(&mut self, fd: &mut Funcdata) {
        self.probe.borrow_mut().reset_calls += 1;
        self.inner.reset(fd);
    }

    fn get_flags(&self) -> u32 {
        self.inner.get_flags()
    }

    fn take_count_delta(&mut self) -> i32 {
        self.inner.take_count_delta()
    }

    fn prepare_apply(&mut self, status: u32) {
        self.inner.prepare_apply(status);
    }
}

struct TypeObserver {
    phases: Rc<RefCell<Vec<bool>>>,
}

impl TypeObserver {
    fn new(phases: Rc<RefCell<Vec<bool>>>) -> Self {
        Self { phases }
    }
}

impl Action for TypeObserver {
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        self.phases
            .borrow_mut()
            .push(fd.has_type_recovery_started());
        Ok(0)
    }

    fn get_name(&self) -> &str {
        "typeobserver"
    }
}

fn reset_action(action: &mut dyn Action, state: &mut ActionState, fd: &mut Funcdata) {
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
                write!(output, "\\u00{ch:02x}").expect("write to String");
            }
            _ => output.push(char::from(ch)),
        }
    }
    output.push('"');
}

fn bool_array(output: &mut String, values: &[bool]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(if *value { "true" } else { "false" });
    }
    output.push(']');
}

fn write_snapshot(output: &mut String, state: &ActionState) {
    write!(
        output,
        "{{\"status\":{},\"count\":{},\"lcount\":{},\"count_tests\":{},\"count_apply\":{}}}",
        state.status, state.count, state.lcount, state.count_tests, state.count_apply
    )
    .expect("write to String");
}

fn write_data(output: &mut String, fd: &Funcdata) {
    let proto = fd.get_func_proto();
    write!(
        output,
        "{{\"type_recovery_on\":{},\"type_recovery_started\":{},\"calls\":{},\"alive_ops\":{},\"blocks\":{},\"varnodes\":{},\"model_locked\":{},\"input_locked\":{},\"output_locked\":{},\"model\":",
        fd.is_type_recovery_on(),
        fd.has_type_recovery_started(),
        fd.num_calls(),
        fd.obank.alivelist.len(),
        fd.bblocks.get_size(),
        fd.vbank.num_varnodes(),
        proto.is_model_locked(),
        proto.is_input_locked(),
        proto.is_output_locked(),
    )
    .expect("write to String");
    json_string(output, proto.get_model_name());
    write!(
        output,
        ",\"active_output\":{}}}",
        fd.active_output.is_some()
    )
    .expect("write to String");
}

fn write_leaf_state(
    output: &mut String,
    raw_flags: u32,
    state: &ActionState,
    probe: &Rc<RefCell<Probe>>,
) {
    let probe = probe.borrow();
    write!(
        output,
        "{{\"raw_flags\":{raw_flags},\"effective_flags\":{},\"executor\":",
        state.flags
    )
    .expect("write to String");
    write_snapshot(output, state);
    write!(
        output,
        ",\"apply_calls\":{},\"reset_calls\":{}}}",
        probe.apply_calls, probe.reset_calls
    )
    .expect("write to String");
}

struct StartEvent<'a> {
    label: &'a str,
    result: Option<i32>,
    phase_begin: usize,
    group: &'a ActionState,
    observer: &'a ActionState,
    start: &'a ActionState,
    observer_probe: &'a Rc<RefCell<Probe>>,
    start_probe: &'a Rc<RefCell<Probe>>,
}

fn write_start_event(
    output: &mut String,
    event: StartEvent<'_>,
    phases: &Rc<RefCell<Vec<bool>>>,
    fd: &Funcdata,
) {
    output.push_str("{\"label\":");
    json_string(output, event.label);
    output.push_str(",\"return\":");
    match event.result {
        Some(result) => write!(output, "{result}").expect("write to String"),
        None => output.push_str("null"),
    }
    output.push_str(",\"observed_started\":");
    bool_array(output, &phases.borrow()[event.phase_begin..]);
    output.push_str(",\"group\":");
    write_snapshot(output, event.group);
    output.push_str(",\"observer\":");
    write_leaf_state(output, 0, event.observer, event.observer_probe);
    output.push_str(",\"starttypes\":");
    write_leaf_state(output, 0, event.start, event.start_probe);
    output.push_str(",\"data\":");
    write_data(output, fd);
    output.push('}');
}

fn write_starttypes_case(output: &mut String, fd: &mut Funcdata) -> Result<()> {
    let phases = Rc::new(RefCell::new(Vec::new()));
    let observer = InstrumentedAction::new(Box::new(TypeObserver::new(Rc::clone(&phases))));
    let observer_probe = observer.handle();
    let start = InstrumentedAction::new(Box::new(ActionStartTypes::new()));
    let start_probe = start.handle();
    let mut group = ActionGroup::with_flags("fullloop_starttypes", action_flags::RULE_REPEATAPPLY);
    group.add_action(Box::new(observer));
    group.add_action(Box::new(start));
    let mut group_state = ActionState::new(action_flags::RULE_REPEATAPPLY);

    output.push_str("{\"id\":\"fullloop_starttypes\",\"child_order\":[\"typeobserver\",\"starttypes\"],\"events\":[");
    reset_action(&mut group, &mut group_state, fd);
    write_start_event(
        output,
        StartEvent {
            label: "reset_1",
            result: None,
            phase_begin: phases.borrow().len(),
            group: &group_state,
            observer: group.child_state(0).expect("observer state"),
            start: group.child_state(1).expect("starttypes state"),
            observer_probe: &observer_probe,
            start_probe: &start_probe,
        },
        &phases,
        fd,
    );
    output.push(',');

    let phase_begin = phases.borrow().len();
    let result = group.perform(fd, &mut group_state)?;
    write_start_event(
        output,
        StartEvent {
            label: "perform_1",
            result: Some(result),
            phase_begin,
            group: &group_state,
            observer: group.child_state(0).expect("observer state"),
            start: group.child_state(1).expect("starttypes state"),
            observer_probe: &observer_probe,
            start_probe: &start_probe,
        },
        &phases,
        fd,
    );
    output.push(',');

    reset_action(&mut group, &mut group_state, fd);
    write_start_event(
        output,
        StartEvent {
            label: "reset_2",
            result: None,
            phase_begin: phases.borrow().len(),
            group: &group_state,
            observer: group.child_state(0).expect("observer state"),
            start: group.child_state(1).expect("starttypes state"),
            observer_probe: &observer_probe,
            start_probe: &start_probe,
        },
        &phases,
        fd,
    );
    output.push(',');

    let phase_begin = phases.borrow().len();
    let result = group.perform(fd, &mut group_state)?;
    write_start_event(
        output,
        StartEvent {
            label: "perform_2",
            result: Some(result),
            phase_begin,
            group: &group_state,
            observer: group.child_state(0).expect("observer state"),
            start: group.child_state(1).expect("starttypes state"),
            observer_probe: &observer_probe,
            start_probe: &start_probe,
        },
        &phases,
        fd,
    );
    output.push_str("]}");
    Ok(())
}

fn write_once_event(
    output: &mut String,
    label: &str,
    result: Option<i32>,
    raw_flags: u32,
    state: &ActionState,
    probe: &Rc<RefCell<Probe>>,
    fd: &Funcdata,
) {
    output.push_str("{\"label\":");
    json_string(output, label);
    output.push_str(",\"return\":");
    match result {
        Some(result) => write!(output, "{result}").expect("write to String"),
        None => output.push_str("null"),
    }
    output.push_str(",\"action\":");
    write_leaf_state(output, raw_flags, state, probe);
    output.push_str(",\"data\":");
    write_data(output, fd);
    output.push('}');
}

fn write_once_action(
    output: &mut String,
    id: &str,
    inner: Box<dyn Action>,
    fd: &mut Funcdata,
) -> Result<()> {
    let raw_flags = inner.get_flags();
    let mut action = InstrumentedAction::new(inner);
    let probe = action.handle();
    let mut state = ActionState::new(raw_flags);

    output.push_str("{\"id\":");
    json_string(output, id);
    output.push_str(",\"events\":[");
    reset_action(&mut action, &mut state, fd);
    write_once_event(output, "reset_1", None, raw_flags, &state, &probe, fd);
    output.push(',');
    let result = action.perform(fd, &mut state)?;
    write_once_event(
        output,
        "perform_1",
        Some(result),
        raw_flags,
        &state,
        &probe,
        fd,
    );
    output.push(',');
    let result = action.perform(fd, &mut state)?;
    write_once_event(
        output,
        "perform_2",
        Some(result),
        raw_flags,
        &state,
        &probe,
        fd,
    );
    output.push(',');
    reset_action(&mut action, &mut state, fd);
    write_once_event(output, "reset_2", None, raw_flags, &state, &probe, fd);
    output.push(',');
    let result = action.perform(fd, &mut state)?;
    write_once_event(
        output,
        "perform_3",
        Some(result),
        raw_flags,
        &state,
        &probe,
        fd,
    );
    output.push_str("]}");
    Ok(())
}

fn write_once_case(output: &mut String, fd: &mut Funcdata) -> Result<()> {
    output.push_str("{\"id\":\"once_zero_work\",\"action_order\":[\"prototypetypes\",\"defaultparams\",\"extrapopsetup\",\"funclink\",\"funclink_outonly\",\"internalstorage\"],\"actions\":[");
    write_once_action(
        output,
        "prototypetypes",
        Box::new(ActionPrototypeTypes::new()),
        fd,
    )?;
    output.push(',');
    write_once_action(
        output,
        "defaultparams",
        Box::new(ActionDefaultParams::new()),
        fd,
    )?;
    output.push(',');
    write_once_action(
        output,
        "extrapopsetup",
        Box::new(ActionExtraPopSetup::new()),
        fd,
    )?;
    output.push(',');
    write_once_action(output, "funclink", Box::new(ActionFuncLink::new()), fd)?;
    output.push(',');
    write_once_action(
        output,
        "funclink_outonly",
        Box::new(ActionFuncLinkOutOnly::new()),
        fd,
    )?;
    output.push(',');
    write_once_action(
        output,
        "internalstorage",
        Box::new(ActionInternalStorage::new()),
        fd,
    )?;
    output.push_str("]}");
    Ok(())
}

fn run() -> Result<String> {
    let mut fd = Funcdata::new("GetStr", Address::new(14_032), 0);
    fd.funcp.set_model_name("__stdcall");
    fd.funcp.set_model_lock(true);
    fd.funcp.set_input_lock(true);
    fd.funcp.set_output_lock(true);

    let mut output = String::new();
    output
        .push_str("{\"schema\":1,\"fixture\":\"PIPE-ACTION-COUNT-0001A\",\"function\":{\"name\":");
    json_string(&mut output, &fd.name);
    write!(
        output,
        ",\"entry\":{},\"size\":{}}},\"cases\":[",
        fd.baseaddr.as_u64(),
        fd.size
    )
    .expect("write to String");
    write_starttypes_case(&mut output, &mut fd)?;
    output.push(',');
    write_once_case(&mut output, &mut fd)?;
    output.push_str("]}\n");
    Ok(output)
}

fn main() {
    match run() {
        Ok(output) => print!("{output}"),
        Err(error) => {
            eprintln!("action_leaf_count_1204 Rust fixture failed: {error}");
            std::process::exit(1);
        }
    }
}
