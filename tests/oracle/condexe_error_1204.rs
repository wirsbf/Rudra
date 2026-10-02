//! CONDEXE-ERROR-0006 Rudra comparand — the ConditionalExecution error
//! channel (condexe.cc:242-262 resolveIblockRead, condexe.cc:291-315
//! getReplacementRead, condexe.cc:320-357 doReplacement, condexe.cc:457-476
//! execute, condexe.cc:478-503 ActionConditionalExe::apply), mirroring
//! tests/oracle/condexe_error_1204.cc case for case against the locked
//! Ghidra 12.0.4 oracle. Records: err/state E1, E2 (LowlevelError aborts
//! with verbatim messages and pinned partial state), ret/state E3 (verify
//! failure -> apply returns 0, untouched Funcdata), pre/ret/state E4
//! (unreachable-blocks guard: structure_reset sets the cached flag via the
//! two-root path, apply returns 0 before any mutation, condexe.cc:485-486).
//!
//! The C++ side catches LowlevelError out of apply; the Rust side maps the
//! `Err` out of `Action::apply` — same abort protocol, byte-identical
//! projections.

use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::condexe::ActionConditionalExe;
use rudra::Error;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

struct Fixture {
    blocks: Vec<BlockRef>,
    next_pc: u64,
}

impl Fixture {
    fn new() -> Self {
        Fixture { blocks: Vec::new(), next_pc: 0x20000 }
    }

    fn make_block(&mut self, fd: &mut Funcdata) -> BlockRef {
        let b = fd.create_new_block();
        self.blocks.push(b.clone());
        b
    }

    fn edge(&self, fd: &mut Funcdata, from: &BlockRef, to: &BlockRef) {
        fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn alloc_pc(&mut self) -> Address {
        let a = Address::new(self.next_pc);
        self.next_pc += 8;
        a
    }

    /// Written varnode at an explicit address: the fixture's own IR-builder
    /// leg, mirroring the C++ fixture's `fd.newVarnodeOut(size,
    /// Address(space, offset), op)` (Rudra's `create_def_with_space` does
    /// not set the op's output field, so it is set here exactly like the
    /// oracle's newVarnodeOut does).
    fn make_out(
        &self,
        fd: &mut Funcdata,
        size: usize,
        space: AddressSpace,
        offset: u64,
        op: &rudra::op::PcodeOpRef,
    ) -> VarnodeRef {
        let vn = fd.vbank.create_def_with_space(size, space, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    fn make_cbranch_at(
        &mut self,
        fd: &mut Funcdata,
        blk: &BlockRef,
        boolvn: &VarnodeRef,
        at: Address,
    ) {
        let op = fd.new_op(2, at);
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, 0x4000);
        fd.op_set_input(&op, target, 0);
        fd.op_set_input(&op, boolvn.clone(), 1);
        fd.op_insert_end(&op, blk);
    }

    fn block_op_count(blk: &BlockRef) -> usize {
        blk.read().unwrap().get_ops().len()
    }

    fn inventory(&self) -> String {
        self.blocks
            .iter()
            .enumerate()
            .map(|(i, b)| format!("b{}:{}", i, Fixture::block_op_count(b)))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn ops_of(blk: &BlockRef) -> String {
        let ops = blk.read().unwrap().get_ops();
        ops.iter()
            .map(|o| o.0.read().unwrap().opcode.name().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The shared E-cases diamond (see the C++ fixture's `Diamond` for the full
/// shape comment): b0 init [COPY bool, CBRANCH bool] -> b1/b2 -> b3 iblock
/// [COPY vnY <- vnW, CBRANCH bool] -> b4 posta [COPY reader] / b5 postb;
/// b6 floats and writes vnW with a COPY (outside the iblock,
/// non-MULTIEQUAL — passes testOpRead but is illegal for
/// resolveIblockRead). `reader_dom_ib`: b4's immed_dom = b3 (E1) or b0
/// (E2, the walk advances once then leaves the graph at the entry).
/// `correlate`: same written boolean for both CBRANCHes (E1/E2) or an
/// uncorrelated constant for the iblock CBRANCH (E3).
struct Diamond {
    ib: BlockRef,
    vn_y: VarnodeRef,
    fixture: Fixture,
}

fn build_diamond(fd: &mut Funcdata, reader_dom_ib: bool, correlate: bool) -> Diamond {
    let mut f = Fixture::new();
    let b: Vec<BlockRef> = (0..7).map(|_| f.make_block(fd)).collect();
    f.edge(fd, &b[0], &b[1]);
    f.edge(fd, &b[0], &b[2]);
    f.edge(fd, &b[1], &b[3]);
    f.edge(fd, &b[2], &b[3]);
    f.edge(fd, &b[3], &b[4]);
    f.edge(fd, &b[3], &b[5]);
    // Shared written boolean defined in b0, read by both CBRANCHes
    // (BooleanExpressionMatch -> SAME, condexe.cc:88-93).
    let boolvn = {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let out = f.make_out(fd, 1, AddressSpace::Unique, 0x900, &op);
        let c = fd.new_constant(1, 1);
        fd.op_set_input(&op, c, 0);
        fd.op_insert_end(&op, &b[0]);
        out
    };
    let at = f.alloc_pc();
    f.make_cbranch_at(fd, &b[0], &boolvn, at);
    // b6: floating writer of vnW (outside the iblock, non-MULTIEQUAL).
    let vn_w = {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let out = f.make_out(fd, 4, AddressSpace::Unique, 0x1000, &op);
        let c = fd.new_constant(4, 0x41);
        fd.op_set_input(&op, c, 0);
        fd.op_insert_end(&op, &b[6]);
        out
    };
    // b3 iblock: COPY vnY <- vnW, then CBRANCH bool.
    let vn_y = {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let out = f.make_out(fd, 4, AddressSpace::Unique, 0x2000, &op);
        fd.op_set_input(&op, vn_w, 0);
        fd.op_insert_end(&op, &b[3]);
        out
    };
    let at_ib = f.alloc_pc();
    if correlate {
        f.make_cbranch_at(fd, &b[3], &boolvn, at_ib);
    } else {
        let other = fd.new_constant(1, 0x7a);
        let op = fd.new_op(2, at_ib);
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, 0x4000);
        fd.op_set_input(&op, target, 0);
        fd.op_set_input(&op, other, 1);
        fd.op_insert_end(&op, &b[3]);
    }
    // b4 posta reader: COPY reading vnY.
    {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        fd.op_set_input(&op, vn_y.clone(), 0);
        fd.op_insert_end(&op, &b[4]);
    }
    // Test-only dominator wiring (b0/b3 immed_dom stay unset: the entry has
    // no dominator, which is what makes the E2 walk leave the graph).
    let dom = if reader_dom_ib { &b[3] } else { &b[0] };
    b[4].write().unwrap().set_immed_dom(Some(Arc::downgrade(dom)));
    Diamond { ib: b[3].clone(), vn_y, fixture: f }
}

fn print_state(case_id: &str, fd: &mut Funcdata, d: &Diamond) {
    let ib_ops = Fixture::ops_of(&d.ib);
    let (ib_in, ib_out) = {
        let rg = d.ib.read().unwrap();
        (rg.size_in(), rg.size_out())
    };
    let copy_desc = d.vn_y.read().unwrap().descend_iter().count();
    // The iblock is the 4th created block in both fixtures (C++ name()
    // resolves it to "b3" by creation order).
    println!(
        "state|case={case_id}|nblocks={}|blocks={}|ib=b3|ib_ops={ib_ops}|ib_in={ib_in}|ib_out={ib_out}|copy_desc={copy_desc}",
        fd.bblocks.get_size(),
        d.fixture.inventory(),
    );
}

fn run_error_case(case_id: &str, reader_dom_ib: bool) {
    let mut fd = Funcdata::new(case_id, Address::new(0x60000), 0x100);
    let d = build_diamond(&mut fd, reader_dom_ib, true);
    let mut action = ActionConditionalExe::new();
    match action.apply(&mut fd) {
        Ok(r) => println!("ret|case={case_id}|apply={r}|msg=none"),
        Err(e) => {
            // The C++ side catches LowlevelError; only Error::Lowlevel maps
            // to kind=lowlevel so a Rudra-internal error would surface as a
            // projection difference instead of passing silently.
            let kind = if matches!(e, Error::Lowlevel(_)) { "lowlevel" } else { "internal" };
            println!("err|case={case_id}|kind={kind}|msg={e}");
        }
    }
    print_state(case_id, &mut fd, &d);
}

fn run_verify_fail_case() {
    let case_id = "E3";
    let mut fd = Funcdata::new(case_id, Address::new(0x60000), 0x100);
    let d = build_diamond(&mut fd, true, false);
    let mut action = ActionConditionalExe::new();
    match action.apply(&mut fd) {
        Ok(r) => println!("ret|case={case_id}|apply={r}|msg=none"),
        Err(e) => {
            let kind = if matches!(e, Error::Lowlevel(_)) { "lowlevel" } else { "internal" };
            println!("err|case={case_id}|kind={kind}|msg={e}");
        }
    }
    print_state(case_id, &mut fd, &d);
}

/// E4: the condexe.cc:485-486 unreachable-blocks guard. The diamond is the
/// E1 shape (the data flow that aborts with the illegal-op LowlevelError
/// when the guard is absent), but before apply() the fixture runs the
/// production flag-set path: structure_reset's spanning-tree pass collects
/// every sizeIn()==0 block as a root (block.cc:1028), so the floating b6
/// yields TWO roots and funcdata_block.cc:713-714 sets blocks_unreachable.
/// The pre-line echoes the cached flag so a fixture bug that failed to set
/// it cannot pass the gate vacuously (an unset flag would reproduce the E1
/// abort, not a clean ret).
fn run_unreachable_guard_case() {
    let case_id = "E4";
    let mut fd = Funcdata::new(case_id, Address::new(0x60000), 0x100);
    let d = build_diamond(&mut fd, true, true);
    fd.structure_reset();
    println!("pre|case={case_id}|unreach={}", if fd.has_unreachable_blocks() { 1 } else { 0 });
    let mut action = ActionConditionalExe::new();
    match action.apply(&mut fd) {
        Ok(r) => println!("ret|case={case_id}|apply={r}|msg=none"),
        Err(e) => {
            let kind = if matches!(e, Error::Lowlevel(_)) { "lowlevel" } else { "internal" };
            println!("err|case={case_id}|kind={kind}|msg={e}");
        }
    }
    print_state(case_id, &mut fd, &d);
}

fn main() {
    run_error_case("E1", true); // illegal iblock op (condexe.cc:261)
    run_error_case("E2", false); // could not find dominator (condexe.cc:303)
    run_verify_fail_case(); // verify failure -> trial false, no change
    run_unreachable_guard_case(); // unreachable blocks -> guard return 0 (condexe.cc:485-486)
}
