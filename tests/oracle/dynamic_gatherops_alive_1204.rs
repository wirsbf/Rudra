//! DYNAMIC-GATHEROPS-ALIVE-0001 Rudra comparand.
//!
//! The fixture mirrors the locked Ghidra lifecycle: explicit SeqNum creation
//! starts dead, op_insert_end transitions selected ops alive, and the target
//! address retains one dead op between two alive ops in SeqNum order.

use rudra::address::{Address, SeqNum};
use rudra::dynamic::DynamicHash;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use std::collections::HashMap;
use std::sync::Arc;

struct Fixture {
    fd: Funcdata,
    block: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    names: HashMap<usize, &'static str>,
}

impl Fixture {
    fn new() -> Self {
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 74);
        let block = fd.create_new_block();
        Self {
            fd,
            block,
            names: HashMap::new(),
        }
    }

    fn make(&mut self, name: &'static str, offset: u64, time: u32) -> PcodeOpRef {
        let op = self
            .fd
            .new_op_with_seq(0, &SeqNum::new(Address::new(offset), time));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        self.names.insert(Arc::as_ptr(&op.0) as usize, name);
        op
    }

    fn name(&self, op: &Arc<std::sync::RwLock<rudra::op::PcodeOp>>) -> &'static str {
        self.names[&(Arc::as_ptr(op) as usize)]
    }

    fn pointer_order(&self, ops: &[Arc<std::sync::RwLock<rudra::op::PcodeOp>>]) -> String {
        ops.iter()
            .map(|op| self.name(op))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn ref_order<'a>(&self, ops: impl IntoIterator<Item = &'a PcodeOpRef>) -> String {
        ops.into_iter()
            .filter_map(|op| self.names.get(&(Arc::as_ptr(&op.0) as usize)).copied())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn alive_order(&self) -> String {
        self.ref_order(&self.fd.obank.alivelist)
    }

    fn dead_order(&self) -> String {
        self.ref_order(&self.fd.obank.deadlist)
    }

    fn tree_order(&self) -> String {
        self.ref_order(&self.fd.obank.optree)
    }

    fn block_order(&self) -> String {
        let ops = self.block.read().unwrap().get_ops();
        self.ref_order(&ops)
    }

    fn parent_state(&self) -> String {
        self.fd
            .obank
            .optree
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
}

fn main() {
    let mut fixture = Fixture::new();
    let before = fixture.make("before", 0x0fff, 40);
    let late = fixture.make("late", 0x1000, 30);
    let dead = fixture.make("dead", 0x1000, 20);
    let early = fixture.make("early", 0x1000, 10);
    let after = fixture.make("after", 0x1001, 0);

    fixture.fd.op_insert_end(&late, &fixture.block);
    fixture.fd.op_insert_end(&before, &fixture.block);
    fixture.fd.op_insert_end(&after, &fixture.block);
    fixture.fd.op_insert_end(&early, &fixture.block);

    println!(
        "bank|alive={}|dead={}|tree={}|block={}",
        fixture.alive_order(),
        fixture.dead_order(),
        fixture.tree_order(),
        fixture.block_order(),
    );

    let mut target_result = vec![before.0.clone()];
    DynamicHash::gather_ops_at_address(&mut target_result, &fixture.fd, Address::new(0x1000));
    println!(
        "target|result={}|early_time={}|late_time={}|dead_filtered={}",
        fixture.pointer_order(&target_result),
        early.0.read().unwrap().start.get_time(),
        late.0.read().unwrap().start.get_time(),
        u8::from(dead.0.read().unwrap().is_dead()),
    );

    let mut empty_result = vec![after.0.clone()];
    DynamicHash::gather_ops_at_address(&mut empty_result, &fixture.fd, Address::new(0x2000));
    println!("empty|result={}", fixture.pointer_order(&empty_result));

    println!(
        "post|alive={}|dead={}|tree={}|block={}|parents={}|before_dead={}|early_dead={}|late_dead={}|after_dead={}",
        fixture.alive_order(),
        fixture.dead_order(),
        fixture.tree_order(),
        fixture.block_order(),
        fixture.parent_state(),
        u8::from(before.0.read().unwrap().is_dead()),
        u8::from(early.0.read().unwrap().is_dead()),
        u8::from(late.0.read().unwrap().is_dead()),
        u8::from(after.0.read().unwrap().is_dead()),
    );
}
