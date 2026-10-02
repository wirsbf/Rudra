//! RULE-IDENTITYEL-OPCODESET-0001: Rust twin of the locked Ghidra 12.0.4
//! RuleIdentityEl fixture.
//!
//! The production RuleIdentityEl is registered through the production
//! ActionPool and driven through Action::perform. Fixture-only counters wrap
//! the Rule without changing its opcode list or mutation behavior. Rust's
//! production ActionPool currently lacks Ghidra's getSubRule API; the lookup
//! record makes that known whole-observation mismatch explicit while the
//! remaining records are compared byte-for-byte with the oracle.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use rudra::action::{Action, ActionPool, ActionState, Rule};
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::ruleaction::RuleIdentityEl;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

struct CaseRecord {
    name: &'static str,
    op: PcodeOpRef,
    lhs: VarnodeRef,
    rhs: VarnodeRef,
    output: VarnodeRef,
}

#[derive(Default)]
struct RuleCounters {
    tests: AtomicU32,
    apply: AtomicU32,
}

struct CountingIdentityEl {
    inner: RuleIdentityEl,
    counters: Arc<RuleCounters>,
}

impl Rule for CountingIdentityEl {
    fn apply_op(
        &self,
        op: &Arc<RwLock<rudra::op::PcodeOp>>,
        fd: &mut Funcdata,
    ) -> rudra::Result<i32> {
        self.counters.tests.fetch_add(1, Ordering::SeqCst);
        let result = self.inner.apply_op(op, fd)?;
        if result > 0 {
            self.counters.apply.fetch_add(1, Ordering::SeqCst);
        }
        Ok(result)
    }

    fn get_name(&self) -> &str {
        self.inner.get_name()
    }

    fn get_opcodes(&self) -> Vec<OpCode> {
        self.inner.get_opcodes()
    }
}

fn new_input(fd: &mut Funcdata, size: usize, next_register: &mut u64) -> VarnodeRef {
    let vn = fd
        .vbank
        .create_with_space(size, AddressSpace::Register, *next_register);
    *next_register += 0x10;
    fd.set_input_varnode(vn)
}

fn make_case(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    next_address: &mut u64,
    name: &'static str,
    opcode: OpCode,
    lhs: VarnodeRef,
    rhs: VarnodeRef,
    output_size: usize,
) -> CaseRecord {
    let op = fd.new_op(2, Address::new(*next_address));
    *next_address += 1;
    fd.op_set_opcode(&op, opcode);
    fd.op_set_input(&op, lhs.clone(), 0);
    fd.op_set_input(&op, rhs.clone(), 1);
    let output = fd.new_unique_out(output_size, &op);
    fd.op_insert_end(&op, block);
    CaseRecord {
        name,
        op,
        lhs,
        rhs,
        output,
    }
}

fn case_name(op: &Arc<RwLock<rudra::op::PcodeOp>>, cases: &[CaseRecord]) -> &'static str {
    cases
        .iter()
        .find(|record| Arc::ptr_eq(&record.op.0, op))
        .map_or("?", |record| record.name)
}

fn descend_order(vn: &VarnodeRef, cases: &[CaseRecord]) -> String {
    vn.read()
        .unwrap()
        .descend_iter()
        .map(|op| case_name(&op, cases))
        .collect::<Vec<_>>()
        .join(",")
}

fn block_order(block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, cases: &[CaseRecord]) -> String {
    block
        .read()
        .unwrap()
        .get_ops()
        .iter()
        .map(|op| case_name(&op.0, cases))
        .collect::<Vec<_>>()
        .join(",")
}

fn slot_identity(op: &rudra::op::PcodeOp, slot: usize, record: &CaseRecord) -> &'static str {
    let Some(vn) = op.get_in(slot) else {
        return "-";
    };
    if Arc::ptr_eq(vn, &record.lhs) {
        "lhs"
    } else if Arc::ptr_eq(vn, &record.rhs) {
        "rhs"
    } else {
        "other"
    }
}

fn emit_case(record: &CaseRecord, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
    let op = record.op.0.read().unwrap();
    let output_def = record
        .output
        .read()
        .unwrap()
        .get_def()
        .is_some_and(|definition| Arc::ptr_eq(&definition, &record.op.0));
    let parent_same = op
        .parent
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .is_some_and(|parent| Arc::ptr_eq(&parent, block));
    println!(
        "case={}|opcode={}|inputs={}|slot0={}|slot1={}|output_same={}|output_def={}|rhs_desc={}|parent_same={}|dead={}",
        record.name,
        op.opcode as i32,
        op.num_input(),
        slot_identity(&op, 0, record),
        slot_identity(&op, 1, record),
        usize::from(
            op.output
                .as_ref()
                .is_some_and(|output| Arc::ptr_eq(output, &record.output)),
        ),
        usize::from(output_def),
        record.rhs.read().unwrap().count_descends(),
        usize::from(parent_same),
        usize::from(op.is_dead()),
    );
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    let block = fd.create_new_block();
    let mut next_address = 0x6100;
    let mut next_register = 0x400;
    let x4 = new_input(&mut fd, 4, &mut next_register);
    let b1 = new_input(&mut fd, 1, &mut next_register);
    let mut cases = Vec::new();

    let rhs = fd.new_constant(4, 0);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "int_add_zero",
        OpCode::CPUI_INT_ADD,
        x4.clone(),
        rhs,
        4,
    ));
    let rhs = fd.new_constant(4, 0);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "int_xor_zero",
        OpCode::CPUI_INT_XOR,
        x4.clone(),
        rhs,
        4,
    ));
    let rhs = fd.new_constant(4, 0);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "int_or_zero",
        OpCode::CPUI_INT_OR,
        x4.clone(),
        rhs,
        4,
    ));
    let rhs = fd.new_constant(1, 0);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "bool_xor_zero",
        OpCode::CPUI_BOOL_XOR,
        b1.clone(),
        rhs,
        1,
    ));
    let rhs = fd.new_constant(1, 0);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "bool_or_zero",
        OpCode::CPUI_BOOL_OR,
        b1.clone(),
        rhs,
        1,
    ));
    let rhs = fd.new_constant(4, 0);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "mult_zero",
        OpCode::CPUI_INT_MULT,
        x4.clone(),
        rhs,
        4,
    ));
    let rhs = fd.new_constant(4, 1);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "mult_one",
        OpCode::CPUI_INT_MULT,
        x4.clone(),
        rhs,
        4,
    ));
    let rhs = fd.new_constant(4, 2);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "mult_two_guard",
        OpCode::CPUI_INT_MULT,
        x4.clone(),
        rhs,
        4,
    ));
    let rhs = fd.new_constant(4, 0);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "int_sub_zero_dispatch_neg",
        OpCode::CPUI_INT_SUB,
        x4.clone(),
        rhs,
        4,
    ));
    let rhs = fd.new_constant(4, 0);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "int_and_zero_dispatch_neg",
        OpCode::CPUI_INT_AND,
        x4.clone(),
        rhs,
        4,
    ));
    let rhs = new_input(&mut fd, 4, &mut next_register);
    cases.push(make_case(
        &mut fd,
        &block,
        &mut next_address,
        "int_add_nonconst_guard",
        OpCode::CPUI_INT_ADD,
        x4.clone(),
        rhs,
        4,
    ));

    let counters = Arc::new(RuleCounters::default());
    let mut pool = ActionPool::new("identity_pool");
    pool.add_rule(Box::new(CountingIdentityEl {
        inner: RuleIdentityEl::new(),
        counters: counters.clone(),
    }));

    let opcodes = RuleIdentityEl::new().get_opcodes();
    println!(
        "oplist={}|count={}",
        opcodes
            .iter()
            .map(|opcode| format!("{}", *opcode as i32))
            .collect::<Vec<_>>()
            .join(","),
        opcodes.len(),
    );
    let compat_new = pool
        .rules()
        .iter()
        .filter(|rule| rule.get_name() == "identityel")
        .count();
    let compat_old = pool
        .rules()
        .iter()
        .filter(|rule| rule.get_name() == "identity_el")
        .count();
    println!(
        "lookup=missing|new={}|old={}",
        usize::from(compat_new == 1),
        usize::from(compat_old != 0),
    );
    println!("rule_name={}", pool.rules()[0].get_name());
    println!("desc=x4|stage=before|ops={}", descend_order(&x4, &cases));
    println!("desc=b1|stage=before|ops={}", descend_order(&b1, &cases));
    println!("block|stage=before|ops={}", block_order(&block, &cases));

    let mut state = ActionState::new(rudra::action::action_flags::RULE_REPEATAPPLY);
    let result = pool
        .perform(&mut fd, &mut state)
        .expect("ActionPool perform");
    println!(
        "pool|perform={}|status={}|tests={}|apply={}|rule_tests={}|rule_apply={}",
        result,
        state.status,
        state.count_tests,
        state.count_apply,
        counters.tests.load(Ordering::SeqCst),
        counters.apply.load(Ordering::SeqCst),
    );
    for record in &cases {
        emit_case(record, &block);
    }
    println!("desc=x4|stage=after|ops={}", descend_order(&x4, &cases));
    println!("desc=b1|stage=after|ops={}", descend_order(&b1, &cases));
    println!("block|stage=after|ops={}", block_order(&block, &cases));
}

fn main() {
    run();
}
