//! PIPE-STACKSTALL-COUNT-0001 Rust comparand for the stackstall fixed-point
//! count feedback.  Mirrors tests/oracle/stackstall_count_1204.cc: the real
//! default pipeline root is built through `build_default_pipeline` (the
//! derived tree behind `ActionDatabase::set_default_actions`), the stackstall
//! group is addressed by its tree path, and the group is driven through one
//! external mirror of `Action::perform`'s do-while loop, printing per pass
//! the group's lcount/count and every child Action's
//! status/count/lcount/count_tests/count_apply.  After the fixed point the
//! group is reset and driven a second time (ActionStackPtrFlow re-analysis).

use std::sync::{Arc, RwLock};

use rudra::action::{
    action_flags, build_default_pipeline, status_flags, Action, ActionGroup,
    ActionRestartGroup,
};
use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<RwLock<Varnode>>;
type OpRef = Arc<RwLock<PcodeOp>>;

/// Ghidra get_opname (op.cc) names; MULTIEQUAL prints as BUILD.
fn op_name(opcode: OpCode) -> String {
    match opcode {
        OpCode::CPUI_MULTIEQUAL => "BUILD".to_string(),
        other => format!("{other:?}").trim_start_matches("CPUI_").to_string(),
    }
}

struct Graph {
    fd: Funcdata,
    base: u64,
    ops: Vec<(OpRef, &'static str)>,
    vns: Vec<(VnRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            ops: Vec::new(),
            vns: Vec::new(),
        }
    }

    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            index,
            Address::new(self.base),
        )));
        self.fd.bblocks.add_block(block.clone());
        block
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
    }

    // Op whose PC offset is pinned (several ops may share one offset; the
    // shadowvar trio must all sit at the block's start address).
    fn make_op_at(&mut self, name: &'static str, opcode: OpCode, inputs: usize, offset: u64) -> OpRef {
        let pc = Address::new(self.base + offset);
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        self.ops.push((op.0.clone(), name));
        op.0.clone()
    }

    fn unique_out(&mut self, name: &'static str, size: usize, op: &OpRef) -> VnRef {
        let vn = self
            .fd
            .new_unique_out(size, &rudra::op::PcodeOpRef(op.clone()));
        self.vns.push((vn.clone(), name));
        vn
    }

    // Output varnode living at a register address (the clog INT_ADD's output
    // sits at the stack-pointer register location).
    fn reg_out(&mut self, name: &'static str, size: usize, regoffset: u64, op: &OpRef) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, regoffset);
        self.fd
            .op_set_output(&rudra::op::PcodeOpRef(op.clone()), vn.clone());
        self.vns.push((vn.clone(), name));
        vn
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

    fn input(&mut self, name: &'static str, offset: u64, size: usize) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        let vn = self.fd.set_input_varnode(vn);
        self.vns.push((vn.clone(), name));
        vn
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd.op_insert_input(
            &rudra::op::PcodeOpRef(op.clone()),
            vn.clone(),
            slot,
        );
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd
            .op_insert_end(&rudra::op::PcodeOpRef(op.clone()), block);
    }

    fn ir_text(&self) -> String {
        let mut ops = String::from("[");
        let mut first = true;
        for (op_arc, name) in &self.ops {
            let op = op_arc.read().unwrap();
            if !first {
                ops.push(',');
            }
            first = false;
            ops.push_str(&format!(
                "{name}={}/{},dead={}",
                op_name(op.opcode),
                op.get_seq_num().get_order(),
                u8::from(op.is_dead()),
            ));
        }
        ops.push(']');
        let mut vns = String::from("[");
        let mut first = true;
        for (vn_arc, name) in &self.vns {
            let vn = vn_arc.read().unwrap();
            if !first {
                vns.push(',');
            }
            first = false;
            vns.push_str(&format!(
                "{name}:in={},wr={},sb={}",
                u8::from(vn.is_input()),
                u8::from(vn.is_written()),
                u8::from(vn.is_spacebase()),
            ));
        }
        vns.push(']');
        format!("ops={ops}|vns={vns}")
    }
}

// External mirror of Action::perform's do-while (action.cc:303-350) for a
// rule_repeatapply group, printing the per-pass executor statistics of the
// group and of each child after that pass's ActionGroup::apply.  `stats`
// carries the group-level count_tests/count_apply accumulation across runs
// (Ghidra's members live on the Action object; only `count` resets at each
// run's status_start visit).
fn run_stackstall(stack: &mut ActionGroup, fd: &mut Funcdata, run: usize, stats: &mut (u32, u32)) {
    let flags = stack.get_flags();
    let mut count: i32 = 0;
    let count_tests = &mut stats.0;
    let count_apply = &mut stats.1;
    let mut pass = 0;
    loop {
        pass += 1;
        if pass == 1 {
            count = 0;          // action.cc:306
            *count_tests += 1;   // action.cc:311
        }
        let lcount = count;     // action.cc:314
        stack.prepare_apply(status_flags::STATUS_REPEAT); // apply() restarts its child iterator
        let res = stack.apply(fd).unwrap(); // action.cc:319
        count += stack.take_count_delta(); // ActionGroup::apply's count += res
        if lcount < count {
            *count_apply += 1; // action.cc:327-329
        }
        println!("run={run}|pass={pass}|lcount={lcount}|count={count}|res={res}");
        for index in 0..stack.num_actions() {
            let state = stack.child_state(index).unwrap();
            println!(
                "run={run}|pass={pass}|child={}|status={}|count={}|lcount={}|tests={}|apply={}",
                stack.child_actions()[index].get_name(),
                state.status,
                state.count,
                state.lcount,
                state.count_tests,
                state.count_apply,
            );
        }
        if res < 0 {
            break; // action.cc:323-326
        }
        if !((lcount < count) && (flags & action_flags::RULE_REPEATAPPLY) != 0) {
            break; // action.cc:350
        }
    }
    println!(
        "run={run}|converged_passes={pass}|final_count={count}|tests={count_tests}|apply={count_apply}"
    );
}

fn main() {
    println!("schema=1|fixture=PIPE-STACKSTALL-COUNT-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // Real default derive (ActionDatabase::set_default_actions tree).
    let mut root: ActionRestartGroup = build_default_pipeline();
    // Official ':' name-path addressing (Ghidra Action::getSubAction).
    let stackstall: &mut ActionGroup = root
        .as_action_group_mut().unwrap()               // universal
        .child_actions_mut()                          // [head..., fullloop, ...]
        .iter_mut()
        .find(|child| child.get_name() == "fullloop")
        .expect("fullloop group must exist")
        .as_action_group_mut().unwrap()               // fullloop
        .child_actions_mut()
        .iter_mut()
        .find(|child| child.get_name() == "mainloop")
        .expect("mainloop group must exist")
        .as_action_group_mut().unwrap()               // mainloop
        .child_actions_mut()
        .iter_mut()
        .find(|child| child.get_name() == "stackstall")
        .expect("stackstall group must exist")
        .as_action_group_mut().unwrap();              // stackstall

    // --- Function IR ------------------------------------------------------
    let mut g = Graph::new("stackstall_count", 0x6000);

    let sp = g.input("sp", 0, 8);       // stack pointer input (register 0)
    let x = g.input("x", 0x100, 8);
    let y = g.input("y", 0x108, 8);
    let u = g.input("u", 0x110, 8);
    let v = g.input("v", 0x118, 8);

    // Block b0: shadowvar trigger — m1 and m2 share inputs and sit at the
    // block's start address; the INT_ADD p1 between them stops MultiCse's
    // scan (coreaction.cc:834-835) but not ShadowVar's address-group walk.
    let b0 = g.make_block(0);
    let m1 = g.make_op_at("m1", OpCode::CPUI_MULTIEQUAL, 2, 0x10);
    g.set_input(&m1, &x, 0);
    g.set_input(&m1, &y, 1);
    g.unique_out("t1", 8, &m1);
    let p1 = g.make_op_at("p1", OpCode::CPUI_INT_ADD, 2, 0x10);
    g.set_input(&p1, &sp, 0);
    let c16 = g.constant(8, 16);
    g.set_input(&p1, &c16, 1);
    let ptr = g.unique_out("ptr", 8, &p1);
    let m2 = g.make_op_at("m2", OpCode::CPUI_MULTIEQUAL, 2, 0x10);
    g.set_input(&m2, &x, 0);
    g.set_input(&m2, &y, 1);
    g.unique_out("t2", 8, &m2);
    g.insert_end(&m1, &b0);
    g.insert_end(&p1, &b0);
    g.insert_end(&m2, &b0);
    // Production establishes the block's start address in followFlow; the
    // Rust ShadowVar port reads the block's first-op address, which is the
    // same 0x6010 group the Ghidra fixture pins via setBasicBlockRange.

    // Block b1: stackptrflow clog — STORE(sp+16, 0x10) before the matching
    // LOAD, then INT_ADD(sp, loaded) whose output lives at the sp register.
    let b1 = g.make_block(1);
    let st = g.make_op_at("st", OpCode::CPUI_STORE, 3, 0x20);
    let ramid = g.constant(8, 3);
    g.set_input(&st, &ramid, 0);
    g.set_input(&st, &ptr, 1);
    let cval = g.constant(8, 0x10);
    g.set_input(&st, &cval, 2);
    g.insert_end(&st, &b1);
    let ld = g.make_op_at("ld", OpCode::CPUI_LOAD, 2, 0x21);
    g.set_input(&ld, &ramid, 0);
    g.set_input(&ld, &ptr, 1);
    let loaded = g.unique_out("loaded", 8, &ld);
    g.insert_end(&ld, &b1);
    let cadd = g.make_op_at("cadd", OpCode::CPUI_INT_ADD, 2, 0x22);
    g.set_input(&cadd, &sp, 0);
    g.set_input(&cadd, &loaded, 1);
    g.reg_out("sp2", 8, 0, &cadd);
    g.insert_end(&cadd, &b1);

    // Block b2: multicse trigger — two functionally equivalent MULTIEQUALs
    // lead the block so ActionMultiCse's scan reaches both.
    let b2 = g.make_block(2);
    let m3 = g.make_op_at("m3", OpCode::CPUI_MULTIEQUAL, 2, 0x30);
    g.set_input(&m3, &u, 0);
    g.set_input(&m3, &v, 1);
    g.unique_out("t3", 8, &m3);
    let m4 = g.make_op_at("m4", OpCode::CPUI_MULTIEQUAL, 2, 0x30);
    g.set_input(&m4, &u, 0);
    g.set_input(&m4, &v, 1);
    g.unique_out("t4", 8, &m4);
    g.insert_end(&m3, &b2);
    g.insert_end(&m4, &b2);

    g.edge(&b0, &b1);
    g.edge(&b1, &b2);

    // Precondition 1: per-space heritage info (production startProcessing,
    // funcdata.cc:166) so RuleEarlyRemoval's deadcode gate matches.
    g.fd.heritage.build_info_list();
    // Precondition 2: the spacebase flag on the sp input (ActionSpacebase,
    // mainloop :5506, runs before stackstall in production).
    g.fd.stack_pointer_space = AddressSpace::Register;
    g.fd.stack_pointer_offset = 0;
    g.fd.stack_pointer_size = 8;
    g.fd.spacebase();

    println!("pre|{}", g.ir_text());

    let mut group_stats: (u32, u32) = (0, 0); // (count_tests, count_apply) accumulation
    run_stackstall(stackstall, &mut g.fd, 1, &mut group_stats);
    println!("post_run1|{}", g.ir_text());

    // Reset (ActionGroup::reset -> ActionStackPtrFlow::reset clears
    // analysis_finished, coreaction.hh:99) and drive a second fixed point.
    stackstall.reset(&mut g.fd);
    run_stackstall(stackstall, &mut g.fd, 2, &mut group_stats);
    println!("post_run2|{}", g.ir_text());
}
