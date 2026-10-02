use std::collections::HashMap;
use std::sync::Arc;

use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;

struct Fixture {
    fd: Funcdata,
    block: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    ops: Vec<PcodeOpRef>,
    names: HashMap<usize, &'static str>,
    tracked: Option<PcodeOpRef>,
    tracked_input: Option<Arc<std::sync::RwLock<rudra::varnode::Varnode>>>,
    tracked_output: Option<Arc<std::sync::RwLock<rudra::varnode::Varnode>>>,
}

impl Fixture {
    fn new() -> Self {
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 74);
        let block = fd.create_new_block();
        Self {
            fd,
            block,
            ops: Vec::new(),
            names: HashMap::new(),
            tracked: None,
            tracked_input: None,
            tracked_output: None,
        }
    }

    fn make(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(0x1000));
        self.fd.op_set_opcode(&op, opcode);
        self.names.insert(Arc::as_ptr(&op.0) as usize, name);
        self.ops.push(op.clone());
        op
    }

    fn order(&self, ops: &[PcodeOpRef]) -> String {
        ops.iter()
            .filter_map(|op| self.names.get(&(Arc::as_ptr(&op.0) as usize)).copied())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn parents(&self) -> String {
        self.ops
            .iter()
            .filter_map(|op| {
                self.names.get(&(Arc::as_ptr(&op.0) as usize)).map(|name| {
                    let parent =
                        op.0.read()
                            .unwrap()
                            .parent
                            .as_ref()
                            .and_then(std::sync::Weak::upgrade)
                            .map(|parent| parent.read().unwrap().get_index())
                            .unwrap_or(-1);
                    format!("{name}:{parent}")
                })
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn op_state(&self) -> String {
        use rudra::op::pcodeop_flags;

        self.ops
            .iter()
            .filter_map(|op| {
                self.names.get(&(Arc::as_ptr(&op.0) as usize)).map(|name| {
                    let op = op.0.read().unwrap();
                    format!(
                        "{name}:{}/{}/{}/{}/{}/{}/{}/{}",
                        op.get_eval_type(),
                        u8::from(op.is_branch()),
                        u8::from(op.is_call()),
                        u8::from(op.is_marker()),
                        u8::from(op.is_bool_output()),
                        u8::from(op.is_flow_break()),
                        u8::from((op.flags & pcodeop_flags::CODEREF) != 0),
                        u8::from(
                            (op.flags
                                & (pcodeop_flags::MARKER
                                    | pcodeop_flags::NONPRINTING
                                    | pcodeop_flags::NORETURN))
                                != 0
                        ),
                    )
                })
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn dump(&self, stage: &str, include_order: bool) {
        let tracked = self.tracked.as_ref().unwrap();
        let tracked_guard = tracked.0.read().unwrap();
        let parent = tracked_guard
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .map(|parent| parent.read().unwrap().get_index())
            .unwrap_or(-1);
        let tracked_dead = tracked_guard.is_dead();
        let tracked_order = tracked_guard.start.get_order();
        drop(tracked_guard);

        let block_ops = self.block.read().unwrap().get_ops();
        let block_flags = self.block.read().unwrap().get_flags();
        let input_descend = self
            .tracked_input
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .descend
            .iter()
            .filter(|weak| weak.upgrade().is_some())
            .count();
        let output_def = self
            .tracked_output
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .def
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .map(|definition| Arc::ptr_eq(&definition, &tracked.0))
            .unwrap_or(false);

        print!(
            "{stage}|block={}|alive={}|dead={}|parents={}|opstate={}|flags={block_flags}|tracked_dead={}|tracked_parent={parent}|tracked_input_desc={input_descend}|tracked_output_def={}",
            self.order(&block_ops),
            self.order(&self.fd.obank.alivelist),
            self.order(&self.fd.obank.deadlist),
            self.parents(),
            self.op_state(),
            u8::from(tracked_dead),
            u8::from(output_def),
        );
        if include_order {
            print!("|tracked_order={tracked_order}");
        }
        println!();
    }
}

fn main() {
    let mut fixture = Fixture::new();
    let terminal = fixture.make("terminal", OpCode::CPUI_BRANCHIND, 0);
    let target = fixture.make("target", OpCode::CPUI_STORE, 0);
    let head = fixture.make("head", OpCode::CPUI_COPY, 0);
    let phi_a = fixture.make("phi_a", OpCode::CPUI_MULTIEQUAL, 0);
    let phi_b = fixture.make("phi_b", OpCode::CPUI_MULTIEQUAL, 0);
    let after_phi = fixture.make("after_phi", OpCode::CPUI_COPY, 0);
    let indirect = fixture.make("indirect", OpCode::CPUI_INDIRECT, 2);
    let before_target = fixture.make("before_target", OpCode::CPUI_COPY, 1);
    let after_indirect = fixture.make("after_indirect", OpCode::CPUI_COPY, 0);
    let end_normal = fixture.make("end_normal", OpCode::CPUI_COPY, 0);

    fixture.tracked = Some(before_target.clone());
    let tracked_input = fixture.fd.new_constant(8, 0x1234);
    fixture
        .fd
        .op_set_input(&before_target, tracked_input.clone(), 0);
    let tracked_output = fixture.fd.new_unique_out(8, &before_target);
    fixture.tracked_input = Some(tracked_input);
    fixture.tracked_output = Some(tracked_output);
    let indirect_zero = fixture.fd.new_constant(8, 0);
    fixture.fd.op_set_input(&indirect, indirect_zero, 0);
    let target_iop = fixture.fd.new_varnode_iop(&target);
    fixture.fd.op_set_input(&indirect, target_iop, 1);
    fixture.dump("created", false);

    fixture.fd.op_insert_end(&terminal, &fixture.block);
    fixture.fd.op_insert_end(&target, &fixture.block);
    fixture.fd.op_insert_begin(&head, &fixture.block);
    fixture.fd.op_insert_begin(&phi_a, &fixture.block);
    fixture.fd.op_insert_begin(&phi_b, &fixture.block);
    fixture.fd.op_insert_after(&after_phi, &phi_b);
    fixture.fd.op_insert_before(&indirect, &target);
    fixture.fd.op_insert_before(&before_target, &target);
    fixture.fd.op_insert_after(&after_indirect, &indirect);
    fixture.fd.op_insert_end(&end_normal, &fixture.block);
    fixture.dump("inserted", true);

    fixture.fd.op_uninsert(&before_target);
    fixture.dump("uninserted", true);

    fixture.fd.op_insert_after(&before_target, &head);
    fixture.dump("reinserted", true);
}
