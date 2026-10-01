//! RULE-PORT-EARLYREMOVAL-0001: Rust twin of the locked Ghidra 12.0.4
//! RuleEarlyRemoval fixture.
//!
//! Covered records are compared byte-for-byte.  Records beginning with
//! `residual=` deliberately expose unrepresentable raw opcode buckets,
//! nullable post-destroy input slots, and the untested full Heritage-manager
//! closure; they are excluded from the narrow MATCH projection but retained
//! in the raw MISMATCH observation.

use std::sync::{Arc, RwLock};

use rugra::action::{Action, ActionPool, ActionState, Rule};
use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::block::FlowBlock;
use rugra::funcdata::Funcdata;
use rugra::op::{pcodeop_flags, PcodeOp, PcodeOpRef};
use rugra::opcodes::OpCode;
use rugra::ruleaction::RuleEarlyRemoval;
use rugra::space::{AddressSpace, SPACEID_OTHER};
use rugra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type OpRef = Arc<RwLock<PcodeOp>>;
type VnRef = Arc<RwLock<Varnode>>;

struct Graph {
    fd: Funcdata,
    block: BlockRef,
    next_pc: u64,
    next_other: u64,
}

impl Graph {
    fn new(name: &str, base: u64, pass: i32) -> Self {
        let mut fd = Funcdata::new(name, Address::new(base), 0x100);
        let mut arch = Architecture::new();
        arch.archid = "x86:LE:64:default:gcc".to_string();
        fd.set_arch(Arc::new(arch));
        let block = fd.create_new_block();
        fd.heritage.build_info_list();
        fd.heritage.pass = pass;
        Self {
            fd,
            block,
            next_pc: base,
            next_other: 0x9000,
        }
    }

    fn new_op(
        &mut self,
        opcode: OpCode,
        input_count: usize,
        with_output: bool,
        space: AddressSpace,
    ) -> PcodeOpRef {
        let op = self.fd.new_op(input_count, Address::new(self.next_pc));
        self.next_pc += 1;
        self.fd.op_set_opcode(&op, opcode);
        if input_count > 0 {
            let input = self.fd.new_constant(4, self.next_pc);
            self.fd.op_set_input(&op, input, 0);
        }
        if with_output {
            if space == AddressSpace::Unique {
                self.fd.new_unique_out(4, &op);
            } else {
                let output = self.fd.vbank.create_with_space(4, space, self.next_other);
                self.next_other += 1;
                self.fd.op_set_output(&op, output);
            }
        }
        self.fd.op_insert_end(&op, &self.block);
        op
    }
}

#[derive(Clone, Copy)]
struct CaseSpec {
    name: &'static str,
    opcode: OpCode,
    pass: i32,
    dead_delay: i32,
    with_output: bool,
    indirect_source: bool,
    descendant: bool,
    write_mask: bool,
    auto_live: bool,
    other_space: bool,
}

fn bank_contains_op(bank: &[PcodeOpRef], needle: &OpRef) -> bool {
    bank.iter().any(|op| Arc::ptr_eq(&op.0, needle))
}

fn bank_contains_vn(fd: &Funcdata, needle: &VnRef) -> bool {
    fd.vbank
        .loc_tree
        .iter()
        .any(|vn| Arc::ptr_eq(&vn.0, needle))
}

fn block_contains(block: &BlockRef, needle: &OpRef) -> bool {
    block
        .read()
        .unwrap()
        .get_ops()
        .iter()
        .any(|op| Arc::ptr_eq(&op.0, needle))
}

fn dead_removed(fd: &Funcdata, space: AddressSpace) -> i32 {
    fd.heritage
        .infolist
        .iter()
        .find(|info| info.space == space)
        .map_or(-1, |info| info.deadremoved)
}

fn run_case(spec: CaseSpec, base: u64) {
    let mut graph = Graph::new(spec.name, base, spec.pass);
    let out_space = if spec.other_space {
        AddressSpace::Other(SPACEID_OTHER)
    } else {
        AddressSpace::Unique
    };
    graph
        .fd
        .heritage
        .set_dead_code_delay(out_space, spec.dead_delay);
    let op = graph.new_op(spec.opcode, 1, spec.with_output, out_space);
    if spec.indirect_source {
        op.0.write().unwrap().flags |= pcodeop_flags::INDIRECT_SOURCE;
    }
    let input = op.0.read().unwrap().get_in(0).unwrap().clone();
    let output = op.0.read().unwrap().output.clone();
    if let Some(output) = &output {
        let mut value = output.write().unwrap();
        if spec.write_mask {
            value.set_write_mask();
        }
        if spec.auto_live {
            value.set_auto_live_hold();
        }
    }
    if spec.descendant {
        let output = output.as_ref().expect("descendant case requires output");
        let sink = graph.new_op(OpCode::CPUI_COPY, 1, true, AddressSpace::Unique);
        graph.fd.op_set_input(&sink, output.clone(), 0);
    }

    let desc_before = output
        .as_ref()
        .map_or(-1, |value| value.read().unwrap().count_descends() as i32);
    let input_desc_before = input.read().unwrap().count_descends();
    let (call_before, indirect_before) = {
        let value = op.0.read().unwrap();
        (value.is_call(), value.is_indirect_source())
    };
    let write_before = output
        .as_ref()
        .is_some_and(|value| value.read().unwrap().is_write_mask());
    let auto_before = output
        .as_ref()
        .is_some_and(|value| value.read().unwrap().is_auto_live());
    let space_deadcode = output
        .as_ref()
        .is_some_and(|value| value.read().unwrap().get_space().does_deadcode());

    let result = RuleEarlyRemoval::new()
        .apply_op(&op.0, &mut graph.fd)
        .expect("RuleEarlyRemoval apply");
    let input_desc_after = input.read().unwrap().count_descends();
    let alive = bank_contains_op(&graph.fd.obank.alivelist, &op.0);
    let dead = bank_contains_op(&graph.fd.obank.deadlist, &op.0);
    let block_member = block_contains(&graph.block, &op.0);
    let output_present = output
        .as_ref()
        .is_some_and(|value| bank_contains_vn(&graph.fd, value));
    let output_attached = op.0.read().unwrap().output.is_some();

    println!(
        "case={}|result={}|pass={}|delay={}|call={}|indirect={}|output={}|desc={}|writemask={}|autolive={}|space_deadcode={}|deadremoved={}|alive={}|dead={}|block={}|output_present={}|output_attached={}|input_desc={}->{}",
        spec.name,
        result,
        spec.pass,
        spec.dead_delay,
        usize::from(call_before),
        usize::from(indirect_before),
        usize::from(output.is_some()),
        desc_before,
        usize::from(write_before),
        usize::from(auto_before),
        usize::from(space_deadcode),
        dead_removed(&graph.fd, out_space),
        usize::from(alive),
        usize::from(dead),
        usize::from(block_member),
        usize::from(output_present),
        usize::from(output_attached),
        input_desc_before,
        input_desc_after,
    );

    if spec.name == "neither_allowed" {
        println!(
            "residual=nullable_input_arity|post_num_inputs={}|slot0_null=unrepresentable|status=MISMATCH",
            op.0.read().unwrap().num_input(),
        );
    }
}

fn opcode_list(opcodes: &[OpCode]) -> String {
    opcodes
        .iter()
        .map(|opcode| (*opcode as i32).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn run_dispatch() {
    let mut graph = Graph::new("typed_dispatch", 0x7200, 1);
    graph
        .fd
        .heritage
        .set_dead_code_delay(AddressSpace::Unique, 0);
    let typed = RuleEarlyRemoval::new().get_opcodes();
    println!("typed_oplist={}|count={}", opcode_list(&typed), typed.len());
    println!(
        "residual=raw_dispatch|raw=unavailable|count=unavailable|untyped=0,45|status=MISMATCH"
    );

    for opcode in &typed {
        graph.new_op(*opcode, 0, true, AddressSpace::Unique);
    }
    let mut pool = ActionPool::with_flags("earlyremoval_dispatch", 0);
    pool.add_rule(Box::new(RuleEarlyRemoval::new()));
    let mut state = ActionState::new(0);
    let result = pool
        .perform(&mut graph.fd, &mut state)
        .expect("ActionPool perform");
    let rule_state = pool.rule_state(0).expect("registered rule state");
    let alive = graph
        .fd
        .obank
        .iter_alive()
        .map(|op| (op.0.read().unwrap().opcode as i32).to_string())
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "dispatch|perform={}|status={}|tests={}|apply={}|alive={}|dead_count={}|deadremoved={}",
        result,
        state.status,
        rule_state.count_tests,
        rule_state.count_apply,
        alive,
        graph.fd.obank.deadlist.len(),
        dead_removed(&graph.fd, AddressSpace::Unique),
    );
}

fn main() {
    let cases = [
        CaseSpec {
            name: "call_guard",
            opcode: OpCode::CPUI_CALL,
            pass: 1,
            dead_delay: 0,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: false,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "indirect_guard",
            opcode: OpCode::CPUI_COPY,
            pass: 1,
            dead_delay: 0,
            with_output: true,
            indirect_source: true,
            descendant: false,
            write_mask: false,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "no_output_guard",
            opcode: OpCode::CPUI_COPY,
            pass: 1,
            dead_delay: 0,
            with_output: false,
            indirect_source: false,
            descendant: false,
            write_mask: false,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "descendant_guard",
            opcode: OpCode::CPUI_COPY,
            pass: 1,
            dead_delay: 0,
            with_output: true,
            indirect_source: false,
            descendant: true,
            write_mask: false,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "autolive_only",
            opcode: OpCode::CPUI_COPY,
            pass: 1,
            dead_delay: 0,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: false,
            auto_live: true,
            other_space: false,
        },
        CaseSpec {
            name: "write_and_autolive",
            opcode: OpCode::CPUI_COPY,
            pass: 1,
            dead_delay: 0,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: true,
            auto_live: true,
            other_space: false,
        },
        CaseSpec {
            name: "write_mask_only",
            opcode: OpCode::CPUI_COPY,
            pass: 1,
            dead_delay: 0,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: true,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "neither_allowed",
            opcode: OpCode::CPUI_COPY,
            pass: 1,
            dead_delay: 0,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: false,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "delay_zero_equal",
            opcode: OpCode::CPUI_COPY,
            pass: 0,
            dead_delay: 0,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: false,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "delay_one_equal",
            opcode: OpCode::CPUI_COPY,
            pass: 1,
            dead_delay: 1,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: false,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "delay_one_after",
            opcode: OpCode::CPUI_COPY,
            pass: 2,
            dead_delay: 1,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: false,
            auto_live: false,
            other_space: false,
        },
        CaseSpec {
            name: "no_deadcode_other",
            opcode: OpCode::CPUI_COPY,
            pass: 0,
            dead_delay: 0,
            with_output: true,
            indirect_source: false,
            descendant: false,
            write_mask: false,
            auto_live: false,
            other_space: true,
        },
    ];
    for (index, case) in cases.into_iter().enumerate() {
        run_case(case, 0x7000 + index as u64 * 0x20);
    }
    run_dispatch();
    println!(
        "residual=heritage_manager_projection|scope=full_manager_state_and_late_generation_warning|status=UNTESTED"
    );
}
