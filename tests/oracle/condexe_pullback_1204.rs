//! CONDEXE-PULLBACK-0005 Rudra comparand — ConditionalExecution::pullbackOp
//! (condexe.cc:160-190) storage/insert-position semantics and its
//! testOpRead admission gate (condexe.cc:107-142), mirroring
//! tests/oracle/condexe_pullback_1204.cc case for case against the locked
//! Ghidra 12.0.4 oracle. Records: pullback (P0/P1/P1b/P3, P2, P5), gate
//! (G1-G8).
//!
//! Projections per pullback case: block position (which block, index within
//! it, op count), SeqNum order (pc:time), and storage address
//! (space:offset/size) of the duplicate's output and inputs.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::condexe::ConditionalExecution;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
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
    /// Address(space, offset), op)` minus the assignHigh/laned/queryProperties
    /// legs (no-ops on a fresh Funcdata: highlevel off, no laned specs, empty
    /// local map). Funcdata::new_varnode_out cannot be used because Rudra's
    /// split Address model pins Register there; the fixture must build
    /// unique-space originals exactly like the oracle side.
    fn make_out(
        &self,
        fd: &mut Funcdata,
        size: usize,
        space: AddressSpace,
        offset: u64,
        op: &PcodeOpRef,
    ) -> VarnodeRef {
        let vn = fd.vbank.create_def_with_space(size, space, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    fn make_free(&self, fd: &mut Funcdata, offset: u64, size: usize) -> VarnodeRef {
        fd.new_varnode(size, Address::new(offset))
    }

    fn make_cbranch(
        &mut self,
        fd: &mut Funcdata,
        blk: &BlockRef,
        boolvn: &VarnodeRef,
    ) -> PcodeOpRef {
        let op = fd.new_op(2, self.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, 0x4000);
        fd.op_set_input(&op, target, 0);
        fd.op_set_input(&op, boolvn.clone(), 1);
        fd.op_insert_end(&op, blk);
        op
    }

    fn block_op_count(blk: &BlockRef) -> usize {
        blk.read().unwrap().get_ops().len()
    }

    fn name(&self, b: &BlockRef) -> String {
        match self.blocks.iter().position(|x| Arc::ptr_eq(x, b)) {
            Some(i) => format!("b{i}"),
            None => "x".to_string(),
        }
    }
}

fn vn_desc(vn: &VarnodeRef) -> String {
    let r = vn.read().unwrap();
    format!("{}:{:x}/{}", r.get_space().name(), r.get_offset(), r.get_size())
}

/// Three decisive projections of a pullback_op call: block position, SeqNum
/// order, and storage address of the duplicate's output and inputs.
fn record_pullback(case_id: &str, f: &Fixture, out_vn: &VarnodeRef) {
    let op = {
        let r = out_vn.read().unwrap();
        r.def.as_ref().and_then(|w| w.upgrade()).expect("pullback output must be written")
    };
    let parent = {
        let r = op.read().unwrap();
        r.parent.as_ref().and_then(|w| w.upgrade()).expect("pullback op must be inserted")
    };
    let (idx, nops, opcode, seq, in0, in1) = {
        let ops = parent.read().unwrap().get_ops();
        let idx = ops
            .iter()
            .position(|o| Arc::ptr_eq(&o.0, &op))
            .map(|i| i as i64)
            .unwrap_or(-1);
        let r = op.read().unwrap();
        let sq = r.get_seq_num().clone();
        let in0 = vn_desc(r.get_in(0).expect("duplicate keeps input 0"));
        let in1 = vn_desc(r.get_in(1).expect("duplicate keeps input 1"));
        (idx, ops.len(), r.opcode, sq, in0, in1)
    };
    println!(
        "pullback|case={case_id}|block={}|idx={idx}|nops={nops}|opc={}|seq={:x}:{}|out={}|in0={in0}|in1={in1}",
        f.name(&parent),
        opcode.name(),
        seq.get_addr().as_u64(),
        seq.get_time(),
        vn_desc(out_vn),
    );
}

/// P1/P1b/P3: SUBPIECE in the iblock reading a MULTIEQUAL in the iblock.
/// prea and preb each hold a leading COPY plus a trailing CBRANCH so the
/// END insertion (before the flow break, after the COPY) is distinguishable
/// from op_insert_begin (which would land at idx 0, before the COPY).
/// One ConditionalExecution instance spans P1/P1b/P3 exactly like the C++
/// fixture reuses one `condexe` object (P3 pins the pullback cache,
/// condexe.cc:163-165).
fn run_multiequal_pullback(fd: &mut Funcdata) {
    let mut f = Fixture::new();
    let prea = f.make_block(fd);
    let preb = f.make_block(fd);
    let ib = f.make_block(fd);
    f.edge(fd, &prea, &ib); // ib in[0]
    f.edge(fd, &preb, &ib); // ib in[1]

    // prea: COPY then CBRANCH
    let vn_a = {
        let copy_a = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&copy_a, OpCode::CPUI_COPY);
        let vn_a = f.make_out(fd, 4, AddressSpace::Unique, 0x1000, &copy_a);
        let c = fd.new_constant(4, 0x41);
        fd.op_set_input(&copy_a, c, 0);
        fd.op_insert_end(&copy_a, &prea);
        let bv = f.make_free(fd, 0x900, 1);
        f.make_cbranch(fd, &prea, &bv);
        vn_a
    };
    // preb: COPY then CBRANCH
    let vn_b = {
        let copy_b = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&copy_b, OpCode::CPUI_COPY);
        let vn_b = f.make_out(fd, 4, AddressSpace::Unique, 0x1100, &copy_b);
        let c = fd.new_constant(4, 0x42);
        fd.op_set_input(&copy_b, c, 0);
        fd.op_insert_end(&copy_b, &preb);
        let bv = f.make_free(fd, 0x908, 1);
        f.make_cbranch(fd, &preb, &bv);
        vn_b
    };
    // ib: MULTIEQUAL, SUBPIECE, CBRANCH
    let sub = {
        let mq = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&mq, OpCode::CPUI_MULTIEQUAL);
        let vn_m = f.make_out(fd, 4, AddressSpace::Unique, 0x1200, &mq);
        fd.op_set_input(&mq, vn_a.clone(), 0);
        fd.op_set_input(&mq, vn_b.clone(), 1);
        fd.op_insert_end(&mq, &ib);

        let sub = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&sub, OpCode::CPUI_SUBPIECE);
        let vn_s = f.make_out(fd, 4, AddressSpace::Register, 0x300, &sub);
        fd.op_set_input(&sub, vn_m, 0);
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(&sub, zero, 1);
        fd.op_insert_end(&sub, &ib);

        let bv = f.make_free(fd, 0x910, 1);
        f.make_cbranch(fd, &ib, &bv);
        println!(
            "pullback|case=P0|ib_nops={}|out={}",
            Fixture::block_op_count(&ib),
            vn_desc(&vn_s),
        );
        sub
    };
    {
        let mut ce = ConditionalExecution::new(fd);
        let out1 = ce
            .fixture_pullback_op(ib.clone(), sub.clone(), 0)
            .expect("P1 pullback must succeed");
        record_pullback("P1", &f, &out1);
        let out1b = ce
            .fixture_pullback_op(ib.clone(), sub.clone(), 1)
            .expect("P1b pullback must succeed");
        record_pullback("P1b", &f, &out1b);
        // P3: cached pullback for inbranch 0 returns the SAME Varnode, no new op.
        let again = ce
            .fixture_pullback_op(ib.clone(), sub.clone(), 0)
            .expect("P3 cached pullback");
        println!(
            "pullback|case=P3|same_ptr={}|prea_nops={}|ib_nops={}|out={}",
            u8::from(Arc::ptr_eq(&again, &out1)),
            Fixture::block_op_count(&prea),
            Fixture::block_op_count(&ib),
            vn_desc(&again),
        );
    }
}

/// P2: SUBPIECE whose input 0 is defined outside the iblock: the duplicate
/// lands in the iblock's immediate dominator (condexe.cc:175) and preserves a
/// UNIQUE-space original output address (condexe.cc:182).
fn run_cross_block_pullback(fd: &mut Funcdata) {
    let mut f = Fixture::new();
    let writer = f.make_block(fd);
    let ib = f.make_block(fd);
    f.edge(fd, &writer, &ib);
    let vn_c = {
        let copy_c = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&copy_c, OpCode::CPUI_COPY);
        let vn_c = f.make_out(fd, 8, AddressSpace::Unique, 0x2000, &copy_c);
        let c = fd.new_constant(8, 0x1122334455667788);
        fd.op_set_input(&copy_c, c, 0);
        fd.op_insert_end(&copy_c, &writer);
        let bv = f.make_free(fd, 0x918, 1);
        f.make_cbranch(fd, &writer, &bv);
        vn_c
    };
    let sub2 = {
        let sub2 = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&sub2, OpCode::CPUI_SUBPIECE);
        f.make_out(fd, 4, AddressSpace::Unique, 0x2800, &sub2);
        fd.op_set_input(&sub2, vn_c, 0);
        let one = fd.new_constant(4, 1);
        fd.op_set_input(&sub2, one, 1);
        fd.op_insert_end(&sub2, &ib);
        let bv = f.make_free(fd, 0x920, 1);
        f.make_cbranch(fd, &ib, &bv);
        sub2
    };
    // Test-only dominator wiring (the C++ fixture assigns immed_dom directly).
    ib.write()
        .unwrap()
        .set_immed_dom(Some(Arc::downgrade(&writer)));
    let out2 = {
        let mut ce = ConditionalExecution::new(fd);
        ce.fixture_pullback_op(ib.clone(), sub2, 1)
            .expect("P2 pullback must succeed")
    };
    record_pullback("P2", &f, &out2);
}

/// P5: SUBPIECE whose input 0 is a constant (not written): bl = immedDom
/// (condexe.cc:177-179); the target block holds only a CBRANCH, so END
/// insertion must still precede the flow break (idx 0, nops 2).
fn run_const_input_pullback(fd: &mut Funcdata) {
    let mut f = Fixture::new();
    let writer = f.make_block(fd);
    let ib = f.make_block(fd);
    f.edge(fd, &writer, &ib);
    {
        let bv = f.make_free(fd, 0x928, 1);
        f.make_cbranch(fd, &writer, &bv);
    }
    let sub5 = {
        let sub5 = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&sub5, OpCode::CPUI_SUBPIECE);
        f.make_out(fd, 4, AddressSpace::Register, 0x340, &sub5);
        let c0 = fd.new_constant(4, 0x1234);
        fd.op_set_input(&sub5, c0, 0);
        let c1 = fd.new_constant(4, 0);
        fd.op_set_input(&sub5, c1, 1);
        fd.op_insert_end(&sub5, &ib);
        let bv = f.make_free(fd, 0x930, 1);
        f.make_cbranch(fd, &ib, &bv);
        sub5
    };
    ib.write()
        .unwrap()
        .set_immed_dom(Some(Arc::downgrade(&writer)));
    let out5 = {
        let mut ce = ConditionalExecution::new(fd);
        ce.fixture_pullback_op(ib.clone(), sub5, 0)
            .expect("P5 pullback must succeed")
    };
    record_pullback("P5", &f, &out5);
}

/// Mirrors the C++ fixture's `makeWrite` lambda: a 2-input writeOp in ib with
/// a unique-space output at an explicit offset.
fn make_write(
    fd: &mut Funcdata,
    f: &mut Fixture,
    ib: &BlockRef,
    opc: OpCode,
    in0: &VarnodeRef,
    in1: &VarnodeRef,
    out_off: u64,
) -> PcodeOpRef {
    let op = fd.new_op(2, f.alloc_pc());
    fd.op_set_opcode(&op, opc);
    f.make_out(fd, 4, AddressSpace::Unique, out_off, &op);
    fd.op_set_input(&op, in0.clone(), 0);
    fd.op_set_input(&op, in1.clone(), 1);
    fd.op_insert_end(&op, ib);
    op
}

fn make_reader(fd: &mut Funcdata, f: &mut Fixture, reader_blk: &BlockRef, vn: &VarnodeRef) -> PcodeOpRef {
    let op = fd.new_op(1, f.alloc_pc());
    fd.op_set_opcode(&op, OpCode::CPUI_COPY);
    fd.op_set_input(&op, vn.clone(), 0);
    fd.op_insert_end(&op, reader_blk);
    op
}

fn fixture_gate(fd: &mut Funcdata, ib: &BlockRef, w: &PcodeOpRef, r: &PcodeOpRef) -> bool {
    let vn = w.0.read().unwrap().output.clone().expect("writeOp output");
    let mut ce = ConditionalExecution::new(fd);
    ce.fixture_test_op_read(ib.clone(), vn, r.clone())
}

/// G1..G8: the testOpRead admission gate (condexe.cc:107-142) driven
/// directly. writeOps live in ib, readers live outside; vn is the writeOp's
/// output.
fn run_gate(fd: &mut Funcdata) {
    let mut f = Fixture::new();
    let ib = f.make_block(fd);
    let reader_blk = f.make_block(fd);
    let dom_blk = f.make_block(fd);
    let mut results = [false; 8];

    // Shared written input defined OUTSIDE ib (upop parent != iblock -> pass).
    let vn_x = {
        let copy_x = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&copy_x, OpCode::CPUI_COPY);
        let vn_x = f.make_out(fd, 4, AddressSpace::Unique, 0x3000, &copy_x);
        let c = fd.new_constant(4, 0x55);
        fd.op_set_input(&copy_x, c, 0);
        fd.op_insert_end(&copy_x, &dom_blk);
        vn_x
    };
    let free_reg = f.make_free(fd, 0x4000, 4);
    // Distinct free varnode for G4: free varnodes allow at most one descendant.
    let free_reg2 = f.make_free(fd, 0x4010, 4);

    // G1: INT_ADD with constant input 1 -> admitted.
    {
        let c1 = fd.new_constant(4, 0x10);
        let w = make_write(fd, &mut f, &ib, OpCode::CPUI_INT_ADD, &vn_x, &c1, 0x3100);
        let out = w.0.read().unwrap().output.clone().expect("w output");
        let r = make_reader(fd, &mut f, &reader_blk, &out);
        results[0] = fixture_gate(fd, &ib, &w, &r);
    }
    // G2: INT_ADD with NON-constant input 1 -> rejected (cc:126-128).
    {
        let w = make_write(fd, &mut f, &ib, OpCode::CPUI_INT_ADD, &vn_x, &free_reg, 0x3200);
        let out = w.0.read().unwrap().output.clone().expect("w output");
        let r = make_reader(fd, &mut f, &reader_blk, &out);
        results[1] = fixture_gate(fd, &ib, &w, &r);
    }
    // G3: PTRSUB with constant input 1 -> admitted.
    {
        let c1 = fd.new_constant(8, 0x10);
        let w = make_write(fd, &mut f, &ib, OpCode::CPUI_PTRSUB, &vn_x, &c1, 0x3300);
        let out = w.0.read().unwrap().output.clone().expect("w output");
        let r = make_reader(fd, &mut f, &reader_blk, &out);
        results[2] = fixture_gate(fd, &ib, &w, &r);
    }
    // G4: PTRSUB with NON-constant input 1 -> rejected.
    {
        let w = make_write(fd, &mut f, &ib, OpCode::CPUI_PTRSUB, &vn_x, &free_reg2, 0x3400);
        let out = w.0.read().unwrap().output.clone().expect("w output");
        let r = make_reader(fd, &mut f, &reader_blk, &out);
        results[3] = fixture_gate(fd, &ib, &w, &r);
    }
    // G5: SUBPIECE whose input 0 is defined by a non-MULTIEQUAL op INSIDE the
    // iblock -> rejected (cc:131-133).
    {
        let c1 = fd.new_constant(4, 0);
        let w = make_write(fd, &mut f, &ib, OpCode::CPUI_SUBPIECE, &vn_x, &c1, 0x3500);
        let c1u = fd.new_constant(4, 2);
        let up = make_write(fd, &mut f, &ib, OpCode::CPUI_INT_ADD, &vn_x, &c1u, 0x3600);
        let inner = up.0.read().unwrap().output.clone().expect("up output");
        fd.op_set_input(&w, inner, 0);
        let out = w.0.read().unwrap().output.clone().expect("w output");
        let r = make_reader(fd, &mut f, &reader_blk, &out);
        results[4] = fixture_gate(fd, &ib, &w, &r);
    }
    // G6: SUBPIECE with constant (free) input 0 -> rejected (cc:135-136:
    // constants are free, is_free() == ((written|input) flags) == 0).
    {
        let c0 = fd.new_constant(4, 0x1234);
        let c1 = fd.new_constant(4, 0);
        let w = make_write(fd, &mut f, &ib, OpCode::CPUI_SUBPIECE, &c0, &c1, 0x3700);
        let out = w.0.read().unwrap().output.clone().expect("w output");
        let r = make_reader(fd, &mut f, &reader_blk, &out);
        results[5] = fixture_gate(fd, &ib, &w, &r);
    }
    // G7: SUBPIECE whose input 0 is an iblock MULTIEQUAL output -> admitted
    // (cc:131-133 exception).
    {
        let mq = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&mq, OpCode::CPUI_MULTIEQUAL);
        let mqout = f.make_out(fd, 4, AddressSpace::Unique, 0x3800, &mq);
        fd.op_set_input(&mq, vn_x.clone(), 0);
        fd.op_set_input(&mq, vn_x.clone(), 1);
        fd.op_insert_begin(&mq, &ib); // MULTIEQUALs lead the block
        let c1 = fd.new_constant(4, 0);
        let w = make_write(fd, &mut f, &ib, OpCode::CPUI_SUBPIECE, &mqout, &c1, 0x3900);
        let out = w.0.read().unwrap().output.clone().expect("w output");
        let r = make_reader(fd, &mut f, &reader_blk, &out);
        results[6] = fixture_gate(fd, &ib, &w, &r);
    }
    // G8: COPY writeOp -> admitted unconditionally (cc:123).
    {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        f.make_out(fd, 4, AddressSpace::Unique, 0x3a00, &op);
        fd.op_set_input(&op, vn_x, 0);
        fd.op_insert_end(&op, &ib);
        let out = op.0.read().unwrap().output.clone().expect("op output");
        let r = make_reader(fd, &mut f, &reader_blk, &out);
        results[7] = fixture_gate(fd, &ib, &op, &r);
    }
    let names = ["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8"];
    let descs = [
        "intadd_const_in1",
        "intadd_var_in1",
        "ptrsub_const_in1",
        "ptrsub_var_in1",
        "subpiece_upop_in_ib",
        "subpiece_const_in0",
        "subpiece_mq_in0",
        "copy_writeop",
    ];
    for i in 0..8 {
        println!("gate|case={}|shape={}|ok={}", names[i], descs[i], u8::from(results[i]));
    }
}

fn main() {
    let mut fd = Funcdata::new("condexe_pullback", Address::new(0x60000), 0x100);
    run_multiequal_pullback(&mut fd);
    run_cross_block_pullback(&mut fd);
    run_const_input_pullback(&mut fd);
    run_gate(&mut fd);
}
