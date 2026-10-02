//! JUMPTABLE-PARENTFACTS-FIXTURE-0001 — Rust-side twin of
//! tests/oracle/jt_parentfacts_1204.cc: both JumpParentFacts channels of
//! `JumpTable::recover_model` (e27e985).
//!
//!   M1 — multistage partial-table channel: `analyze_guards` usenzmask
//!        (jumptable.cc:1052) reads `JumpParentFacts::partial_table`; the
//!        SUBPIECE nzmask rescue (rangeutil.cc:1053-1065) adds a third
//!        guard record only on non-partial recoveries. Stage order:
//!        recoverAddresses (fresh) -> checkForMultistage (override mark)
//!        -> recoverMultistage (partial=true) -> matchModel (partial
//!        cleared again).
//!   P1/P0 — sibling BRANCHIND identity channel (jumptable.cc:1083-1091):
//!        JumpBasic2's guard walk above the calc-path block compares the
//!        sibling edge's BRANCHIND against `JumpParentFacts::indirect` by
//!        identity. P1: sibling is THIS switch (guard continues, 6
//!        records); P0: sibling is a different BRANCHIND (break, 3
//!        records).
//!
//! Every case mirrors the C++ fixture case-for-case and prints the same
//! record grammar so the runner can diff the two stdouts byte for byte.

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::jumptable::{
    JumpBasic, JumpBasic2, JumpBasicOverride, JumpModelTrivial, JumpTable,
    NO_LABEL,
};
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

struct Fixture {
    blocks: Vec<BlockRef>,
    next_pc: u64,
    names: HashMap<usize, String>,
}

impl Fixture {
    fn new() -> Self {
        Fixture { blocks: Vec::new(), next_pc: 0x30000, names: HashMap::new() }
    }

    fn make_block(&mut self, fd: &mut Funcdata) -> BlockRef {
        let b = fd.create_new_block();
        self.blocks.push(b.clone());
        b
    }

    fn edge(&self, fd: &mut Funcdata, from: &BlockRef, to: &BlockRef) {
        fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn alloc_pc(&mut self) -> rudra::address::Address {
        let a = rudra::address::Address::new(self.next_pc);
        self.next_pc += 8;
        a
    }

    fn make_out(
        &self,
        fd: &mut Funcdata,
        size: usize,
        offset: u64,
        op: &PcodeOpRef,
    ) -> VarnodeRef {
        let vn = fd
            .vbank
            .create_def_with_space(size, rudra::space::AddressSpace::Unique, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    fn make_op1(
        &mut self,
        fd: &mut Funcdata,
        blk: &BlockRef,
        oc: OpCode,
        in0: &VarnodeRef,
        uoff: u64,
        osize: usize,
    ) -> PcodeOpRef {
        let op = fd.new_op(1, self.alloc_pc());
        fd.op_set_opcode(&op, oc);
        let _ = self.make_out(fd, osize, uoff, &op);
        fd.op_set_input(&op, in0.clone(), 0);
        fd.op_insert_end(&op, blk);
        op
    }

    fn make_op2(
        &mut self,
        fd: &mut Funcdata,
        blk: &BlockRef,
        oc: OpCode,
        in0: &VarnodeRef,
        in1: VarnodeRef,
        uoff: u64,
        osize: usize,
    ) -> PcodeOpRef {
        let op = fd.new_op(2, self.alloc_pc());
        fd.op_set_opcode(&op, oc);
        let _ = self.make_out(fd, osize, uoff, &op);
        fd.op_set_input(&op, in0.clone(), 0);
        fd.op_set_input(&op, in1, 1);
        fd.op_insert_end(&op, blk);
        op
    }

    fn make_cbranch(&mut self, fd: &mut Funcdata, blk: &BlockRef, boolvn: &VarnodeRef) -> PcodeOpRef {
        let op = fd.new_op(2, self.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, 0x4000);
        fd.op_set_input(&op, target, 0);
        fd.op_set_input(&op, boolvn.clone(), 1);
        fd.op_insert_end(&op, blk);
        op
    }

    fn name_vn(&mut self, vn: &VarnodeRef, n: &str) {
        self.names.insert(Arc::as_ptr(vn) as usize, n.to_string());
    }

    fn name_of(&self, vn: &VarnodeRef) -> String {
        self.names
            .get(&(Arc::as_ptr(vn) as usize))
            .cloned()
            .unwrap_or_else(|| "?".to_string())
    }

    fn name_blk(&self, b: &BlockRef) -> String {
        match self.blocks.iter().position(|x| Arc::ptr_eq(x, b)) {
            Some(i) => format!("b{i}"),
            None => "x".to_string(),
        }
    }

    fn block_of_op(&self, op: &PcodeOpRef) -> Option<BlockRef> {
        op.0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(|w| w.upgrade())
    }
}

fn opcode_name(op: &OpCode) -> String {
    match op {
        OpCode::CPUI_MULTIEQUAL => "BUILD".to_string(),
        other => format!("{other:?}").trim_start_matches("CPUI_").to_string(),
    }
}

/// Model kind via the `as_any` downcast hook (Ghidra twin uses
/// dynamic_cast on `jt.jmodel`).
fn model_kind(jt: &JumpTable) -> String {
    let Some(m) = jt.jmodel.as_ref() else { return "null".to_string() };
    let any = m.as_any();
    if any.downcast_ref::<JumpBasic2>().is_some() {
        return "basic2".to_string();
    }
    if any.downcast_ref::<JumpBasic>().is_some() {
        return "basic".to_string();
    }
    if any.downcast_ref::<JumpBasicOverride>().is_some() {
        return "override".to_string();
    }
    if any.downcast_ref::<rudra::jumptable::JumpAssisted>().is_some() {
        return "assisted".to_string();
    }
    if any.downcast_ref::<JumpModelTrivial>().is_some() {
        return "trivial".to_string();
    }
    "other".to_string()
}

/// Guard records of the active model (JumpBasic2 keeps them on `base`).
fn guards_of(jt: &JumpTable) -> Option<&Vec<rudra::jumptable::GuardRecord>> {
    let m = jt.jmodel.as_ref()?;
    let any = m.as_any();
    if let Some(m2) = any.downcast_ref::<JumpBasic2>() {
        return Some(&m2.base.selectguards);
    }
    any.downcast_ref::<JumpBasic>().map(|b| &b.selectguards)
}

fn dump_stage(id: &str, phase: &str, jt: &JumpTable, f: &Fixture) {
    let guards = guards_of(jt);
    println!(
        "stage|id={id}|phase={phase}|model={}|isPartial={}|guards={}|addrN={}",
        model_kind(jt),
        if jt.is_partial() { 1 } else { 0 },
        guards.map_or(-1, |g| g.len() as i64),
        jt.num_entries(),
    );
    let Some(guards) = guards else { return };
    for (i, g) in guards.iter().enumerate() {
        print!("guard|id={id}|phase={phase}|i={i}|clear={}", if g.cbranch.is_none() { 1 } else { 0 });
        if let Some(cbr) = &g.cbranch {
            let blk = f.block_of_op(&PcodeOpRef(cbr.clone()));
            if let Some(blk) = blk {
                print!("|cbrBlk={}", f.name_blk(&blk));
            }
        }
        if let Some(read) = &g.read_op {
            print!("|readOp={}", opcode_name(&read.read().unwrap().opcode));
        }
        let vn_name = g.vn.as_ref().map(|v| f.name_of(v)).unwrap_or_else(|| "?".to_string());
        println!("|vn={vn_name}|rngSz={}", g.range.get_size());
    }
}

fn dump_tail(id: &str, jt: &JumpTable) {
    print!("labels|id={id}|n={}", jt.label.len());
    for (i, lab) in jt.label.iter().enumerate() {
        let l = if *lab == NO_LABEL { NO_LABEL } else { *lab };
        print!("{}lab{i}=0x{l:x}", if i == 0 { "|" } else { ";" });
    }
    println!();
}

/// M1 — multistage partial-table channel.
fn run_m1() {
    let id = "M1";
    let mut fd = Funcdata::new("jt_parentfacts_M1", rudra::address::Address::new(0x60000), 0x100);
    let mut f = Fixture::new();

    let b_entry = f.make_block(&mut fd);
    let b_g = f.make_block(&mut fd);
    let b_def = f.make_block(&mut fd);
    let b_sw = f.make_block(&mut fd);
    let b_out = f.make_block(&mut fd);
    f.edge(&mut fd, &b_entry, &b_g);
    f.edge(&mut fd, &b_g, &b_def);
    f.edge(&mut fd, &b_g, &b_sw);
    f.edge(&mut fd, &b_sw, &b_out);
    f.edge(&mut fd, &b_def, &b_out);

    let w = fd.new_varnode(4, rudra::address::Address::new(0x800));
    f.name_vn(&w, "w");
    let cp0 = f.make_op1(&mut fd, &b_g, OpCode::CPUI_COPY, &w, 0x808, 4);
    let w2 = cp0.0.read().unwrap().output.clone().unwrap();
    f.name_vn(&w2, "w2");
    let cff = fd.new_constant(4, 0xff);
    let and_op = f.make_op2(&mut fd, &b_g, OpCode::CPUI_INT_AND, &w2, cff, 0x810, 4);
    let x = and_op.0.read().unwrap().output.clone().unwrap();
    f.name_vn(&x, "x");
    let sub_op = fd.new_op(2, f.alloc_pc());
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    let y = f.make_out(&mut fd, 1, 0x820, &sub_op);
    fd.op_set_input(&sub_op, x.clone(), 0);
    let c0 = fd.new_constant(1, 0);
    fd.op_set_input(&sub_op, c0, 1);
    fd.op_insert_end(&sub_op, &b_g);
    f.name_vn(&y, "y");
    let c5 = fd.new_constant(1, 5);
    let eq_op = f.make_op2(&mut fd, &b_g, OpCode::CPUI_INT_EQUAL, &y, c5, 0x830, 1);
    let g = eq_op.0.read().unwrap().output.clone().unwrap();
    f.name_vn(&g, "g");
    f.make_cbranch(&mut fd, &b_g, &g);

    let zext_op = f.make_op1(&mut fd, &b_sw, OpCode::CPUI_INT_ZEXT, &y, 0x840, 4);
    let z = zext_op.0.read().unwrap().output.clone().unwrap();
    f.name_vn(&z, "z");
    let c8 = fd.new_constant(4, 8);
    let mult_op = f.make_op2(&mut fd, &b_sw, OpCode::CPUI_INT_MULT, &z, c8, 0x850, 4);
    let a = mult_op.0.read().unwrap().output.clone().unwrap();
    f.name_vn(&a, "a");
    let cbase = fd.new_constant(4, 0x30000);
    let add_op = f.make_op2(&mut fd, &b_sw, OpCode::CPUI_INT_ADD, &a, cbase, 0x860, 4);
    let t = add_op.0.read().unwrap().output.clone().unwrap();
    f.name_vn(&t, "t");
    let ind_op = fd.new_op(1, f.alloc_pc());
    fd.op_set_opcode(&ind_op, OpCode::CPUI_BRANCHIND);
    fd.op_set_input(&ind_op, t.clone(), 0);
    fd.op_insert_end(&ind_op, &b_sw);

    fd.calc_nz_mask();
    println!("case|id={id}");
    println!("nzmask|id={id}|vn=x|mask=0x{:x}", x.read().unwrap().get_nz_mask());

    let mut jt = JumpTable::new(ind_op.0.read().unwrap().get_addr());
    jt.set_indirect_op(ind_op.0.clone());
    fd.localoverride
        .insert_multistage_jump(ind_op.0.read().unwrap().get_addr());
    if let Err(e) = jt.recover_addresses_classified(&fd) {
        println!("exception|id={id}");
        return;
    }
    dump_stage(id, "stage1", &jt, &f);
    let more = jt.check_for_multistage(&fd);
    println!(
        "multistage|id={id}|ret={}|isPartial={}",
        if more { 1 } else { 0 },
        if jt.is_partial() { 1 } else { 0 }
    );
    jt.recover_multistage(&fd);
    dump_stage(id, "stage2", &jt, &f);
    if let Err(_e) = jt.match_model(&mut fd) {
        println!("exception|id={id}");
        return;
    }
    dump_stage(id, "match", &jt, &f);
    if let Err(_e) = jt.recover_labels(&fd) {
        println!("exception|id={id}");
        return;
    }
    dump_tail(id, &jt);
    let folded = jt.fold_in_guards(&mut fd);
    println!(
        "fold|id={id}|ret={}|defaultBlock={}|numEntries={}",
        if folded { 1 } else { 0 },
        jt.get_default_block(),
        jt.num_entries()
    );
}

/// P1/P0 — JumpBasic2 sibling BRANCHIND identity channel.
fn run_p(same_sib: bool) {
    let id = if same_sib { "P1" } else { "P0" };
    let mut fd = Funcdata::new(
        &format!("jt_parentfacts_{id}"),
        rudra::address::Address::new(0x60000),
        0x100,
    );
    let mut f = Fixture::new();

    let b_entry = f.make_block(&mut fd);
    let b_g2 = f.make_block(&mut fd);
    let b_alt = f.make_block(&mut fd);
    let b_calc = f.make_block(&mut fd);
    let b_else = f.make_block(&mut fd);
    let b_sw = f.make_block(&mut fd);
    let b_def2 = f.make_block(&mut fd);
    let b_out = f.make_block(&mut fd);

    if same_sib {
        f.edge(&mut fd, &b_entry, &b_g2);
        f.edge(&mut fd, &b_g2, &b_sw);
        f.edge(&mut fd, &b_g2, &b_calc);
        f.edge(&mut fd, &b_calc, &b_else);
        f.edge(&mut fd, &b_calc, &b_sw);
        f.edge(&mut fd, &b_sw, &b_out);
        f.edge(&mut fd, &b_else, &b_out);
    } else {
        f.edge(&mut fd, &b_entry, &b_g2);
        f.edge(&mut fd, &b_entry, &b_def2);
        f.edge(&mut fd, &b_g2, &b_alt);
        f.edge(&mut fd, &b_g2, &b_calc);
        f.edge(&mut fd, &b_calc, &b_else);
        f.edge(&mut fd, &b_calc, &b_sw);
        f.edge(&mut fd, &b_def2, &b_sw);
        f.edge(&mut fd, &b_sw, &b_out);
        f.edge(&mut fd, &b_else, &b_out);
        f.edge(&mut fd, &b_alt, &b_out);
    }

    println!("case|id={id}");

    let x = fd.new_varnode(4, rudra::address::Address::new(0x800));
    f.name_vn(&x, "x");

    let cd_home = if same_sib { &b_g2 } else { &b_def2 };
    let cd_op = fd.new_op(1, f.alloc_pc());
    fd.op_set_opcode(&cd_op, OpCode::CPUI_COPY);
    let cd = f.make_out(&mut fd, 4, 0x820, &cd_op);
    let cdef = fd.new_constant(4, 0x7777);
    fd.op_set_input(&cd_op, cdef, 0);
    fd.op_insert_end(&cd_op, cd_home);
    f.name_vn(&cd, "cd");

    if !same_sib {
        let alt_op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&alt_op, OpCode::CPUI_BRANCHIND);
        let altv = fd.new_varnode(4, rudra::address::Address::new(0x860));
        fd.op_set_input(&alt_op, altv, 0);
        fd.op_insert_end(&alt_op, &b_alt);
    }

    let cq = fd.new_op(1, f.alloc_pc());
    fd.op_set_opcode(&cq, OpCode::CPUI_COPY);
    let q = f.make_out(&mut fd, 4, 0x808, &cq);
    fd.op_set_input(&cq, x.clone(), 0);
    fd.op_insert_end(&cq, &b_g2);
    f.name_vn(&q, "q");
    let c10 = fd.new_constant(4, 10);
    let lt2 = f.make_op2(&mut fd, &b_g2, OpCode::CPUI_INT_LESS, &q, c10, 0x818, 1);
    let g2b = lt2.0.read().unwrap().output.clone().unwrap();
    f.name_vn(&g2b, "g2b");
    f.make_cbranch(&mut fd, &b_g2, &g2b);

    let cf0 = fd.new_constant(4, 0xfff);
    let cf1 = fd.new_constant(4, 0xff);
    let z_op = fd.new_op(2, f.alloc_pc());
    fd.op_set_opcode(&z_op, OpCode::CPUI_INT_AND);
    let z = f.make_out(&mut fd, 4, 0x830, &z_op);
    fd.op_set_input(&z_op, cf0, 0);
    fd.op_set_input(&z_op, cf1, 1);
    fd.op_insert_end(&z_op, &b_calc);
    f.name_vn(&z, "z");
    let cz2 = fd.new_op(1, f.alloc_pc());
    fd.op_set_opcode(&cz2, OpCode::CPUI_COPY);
    let z2 = f.make_out(&mut fd, 4, 0x838, &cz2);
    fd.op_set_input(&cz2, z.clone(), 0);
    fd.op_insert_end(&cz2, &b_calc);
    f.name_vn(&z2, "z2");
    let c30 = fd.new_constant(4, 0x30);
    let eq1 = f.make_op2(&mut fd, &b_calc, OpCode::CPUI_INT_EQUAL, &z2, c30, 0x840, 1);
    let g1b = eq1.0.read().unwrap().output.clone().unwrap();
    f.name_vn(&g1b, "g1b");
    f.make_cbranch(&mut fd, &b_calc, &g1b);

    let me_op = fd.new_op(2, f.alloc_pc());
    fd.op_set_opcode(&me_op, OpCode::CPUI_MULTIEQUAL);
    let me = f.make_out(&mut fd, 4, 0x850, &me_op);
    if same_sib {
        fd.op_set_input(&me_op, cd.clone(), 0);
        fd.op_set_input(&me_op, z.clone(), 1);
    } else {
        fd.op_set_input(&me_op, z.clone(), 0);
        fd.op_set_input(&me_op, cd.clone(), 1);
    }
    fd.op_insert_begin(&me_op, &b_sw);
    f.name_vn(&me, "me");
    let ind_op = fd.new_op(1, f.alloc_pc());
    fd.op_set_opcode(&ind_op, OpCode::CPUI_BRANCHIND);
    fd.op_set_input(&ind_op, me.clone(), 0);
    fd.op_insert_end(&ind_op, &b_sw);

    fd.calc_nz_mask();

    let mut jt = JumpTable::new(ind_op.0.read().unwrap().get_addr());
    jt.set_indirect_op(ind_op.0.clone());
    if let Err(_e) = jt.recover_addresses_classified(&fd) {
        println!("exception|id={id}");
        return;
    }
    dump_stage(id, "stage1", &jt, &f);
    let sw_size_in = b_sw.read().unwrap().size_in();
    let g2_out0 = b_g2
        .read()
        .unwrap()
        .get_out(0)
        .map(|e| f.name_blk(&e.point))
        .unwrap_or_else(|| "x".to_string());
    println!("topo|id={id}|swSizeIn={sw_size_in}|g2Out0={g2_out0}");
    if let Err(_e) = jt.match_model(&mut fd) {
        println!("exception|id={id}");
        return;
    }
    dump_stage(id, "match", &jt, &f);
    if let Err(_e) = jt.recover_labels(&fd) {
        println!("exception|id={id}");
        return;
    }
    dump_tail(id, &jt);
    let folded = jt.fold_in_guards(&mut fd);
    println!(
        "fold|id={id}|ret={}|defaultBlock={}|numEntries={}",
        if folded { 1 } else { 0 },
        jt.get_default_block(),
        jt.num_entries()
    );
}

fn main() -> ExitCode {
    run_m1();
    run_p(true);
    run_p(false);
    ExitCode::SUCCESS
}
