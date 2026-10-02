use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

use rudra::action::{Action, ActionPool, Rule};
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;

#[derive(Default)]
struct ProbeState {
    trace: Vec<String>,
    tests: BTreeMap<String, u32>,
    applies: BTreeMap<String, u32>,
}

struct ScriptRule {
    name: String,
    state: Rc<RefCell<ProbeState>>,
    trigger: OpCode,
    replacement: OpCode,
    mutate: bool,
    result: i32,
}

impl ScriptRule {
    fn new(
        name: &str,
        state: Rc<RefCell<ProbeState>>,
        trigger: OpCode,
        replacement: OpCode,
        mutate: bool,
        result: i32,
    ) -> Self {
        Self {
            name: name.to_string(),
            state,
            trigger,
            replacement,
            mutate,
            result,
        }
    }
}

impl Rule for ScriptRule {
    fn apply_op(
        &self,
        op: &Arc<RwLock<PcodeOp>>,
        fd: &mut Funcdata,
    ) -> rudra::Result<i32> {
        {
            let mut state = self.state.borrow_mut();
            state.trace.push(self.name.clone());
            *state.tests.entry(self.name.clone()).or_insert(0) += 1;
        }
        if self.mutate {
            let op_ref = PcodeOpRef(op.clone());
            fd.op_remove_input(&op_ref, 1);
            fd.op_set_opcode(&op_ref, self.replacement);
        }
        if self.result > 0 {
            *self
                .state
                .borrow_mut()
                .applies
                .entry(self.name.clone())
                .or_insert(0) += 1;
        }
        Ok(self.result)
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![self.trigger]
    }
}

fn counter(table: &BTreeMap<String, u32>, name: &str) -> u32 {
    table.get(name).copied().unwrap_or(0)
}

fn run_case(case_name: &str, change_result: i32) {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
        BlockBasic::new(0, Address::new(0x1000)),
    ));
    fd.bblocks.add_block(block.clone());

    let source = fd
        .vbank
        .create_with_space(2, AddressSpace::Register, 0x20);
    let source = fd.set_input_varnode(source);
    let offset = fd.new_constant(4, 0);
    let op = fd.new_op(2, Address::new(0x1000));
    fd.op_set_opcode(&op, OpCode::CPUI_SUBPIECE);
    fd.op_set_input(&op, source, 0);
    fd.op_set_input(&op, offset.clone(), 1);
    fd.new_unique_out(4, &op);
    fd.op_insert_end(&op, &block);

    let state = Rc::new(RefCell::new(ProbeState::default()));
    let mut pool = ActionPool::new("fixture_pool");
    pool.add_rule(Box::new(ScriptRule::new(
        "change",
        state.clone(),
        OpCode::CPUI_SUBPIECE,
        OpCode::CPUI_INT_ZEXT,
        true,
        change_result,
    )));
    pool.add_rule(Box::new(ScriptRule::new(
        "old_tail",
        state.clone(),
        OpCode::CPUI_SUBPIECE,
        OpCode::CPUI_SUBPIECE,
        false,
        0,
    )));
    pool.add_rule(Box::new(ScriptRule::new(
        "new_head",
        state.clone(),
        OpCode::CPUI_INT_ZEXT,
        OpCode::CPUI_INT_ZEXT,
        false,
        0,
    )));
    pool.add_rule(Box::new(ScriptRule::new(
        "new_tail",
        state.clone(),
        OpCode::CPUI_INT_ZEXT,
        OpCode::CPUI_INT_ZEXT,
        false,
        0,
    )));

    let apply_result = pool.apply(&mut fd).expect("ActionPool fixture apply");
    let state = state.borrow();
    let op_guard = op.0.read().unwrap();
    let output_size = op_guard.output.as_ref().unwrap().read().unwrap().get_size();
    let input0 = op_guard.inrefs[0].read().unwrap();
    let parent_matches = op_guard
        .parent
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .is_some_and(|parent| Arc::ptr_eq(&parent, &block));
    println!(
        "case={case_name}|trace={}|apply_return={apply_result}|action_count=unavailable|action_status=unavailable|rule_stats=change:{}/{},old_tail:{}/{},new_head:{}/{},new_tail:{}/{}|op=opcode:{},eval_flags:{},inputs:{},output_size:{},input0_size:{},input0_space:{},input0_offset:{},dead:{},parent:{},address:{},time:{},order:{},alive_bank:{},dead_bank:{},removed_input_desc_empty:{}",
        state.trace.join(">"),
        counter(&state.tests, "change"),
        counter(&state.applies, "change"),
        counter(&state.tests, "old_tail"),
        counter(&state.applies, "old_tail"),
        counter(&state.tests, "new_head"),
        counter(&state.applies, "new_head"),
        counter(&state.tests, "new_tail"),
        counter(&state.applies, "new_tail"),
        op_guard.opcode as i32,
        op_guard.get_eval_type(),
        op_guard.num_input(),
        output_size,
        input0.get_size(),
        input0.get_space().name(),
        input0.get_offset(),
        u8::from(op_guard.is_dead()),
        u8::from(parent_matches),
        op_guard.get_addr().as_u64(),
        op_guard.get_time(),
        op_guard.get_seq_num().get_order(),
        fd.obank.alivelist.len(),
        fd.obank.deadlist.len(),
        u8::from(offset.read().unwrap().has_no_descend()),
    );
}

fn main() {
    run_case("positive_change", 1);
    run_case("zero_change", 0);
}
