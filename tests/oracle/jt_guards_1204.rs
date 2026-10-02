//! JT-GUARDS-1204 (JUMPTABLE-GUARDS-0001) Rugra comparand.
//!
//! Mirrors tests/oracle/jt_guards_1204.cc: observes JumpBasic::analyze_guards
//! (jumptable.cc:1046-1112), checkUnrolledGuard via the sizeIn>1 walk-back
//! path, GuardRecord::valueMatch (jumptable.cc:637-680) and quasiCopy
//! (jumptable.cc:719-786) on synthetic guard CFGs. Output format is
//! byte-identical to the C++ fixture.

use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::jumptable::{quasi_copy, GuardRecord, JumpBasic, JumpTable};
use rudra::opcodes::OpCode;
use rudra::rangeutil::CircleRange;
use rudra::varnode::Varnode;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type Var = Arc<RwLock<Varnode>>;
type Op = Arc<RwLock<rudra::op::PcodeOp>>;

struct Lab {
    fd: Funcdata,
    var_name: HashMap<usize, String>,
    op_name: HashMap<usize, String>,
    seq: i32,
}

impl Lab {
    fn new() -> Self {
        Self {
            fd: Funcdata::new("GetStr", Address::new(0x36d0), 0),
            var_name: HashMap::new(),
            op_name: HashMap::new(),
            seq: 0,
        }
    }
    fn blk(&mut self, name: &str) -> (Block, String) {
        let b = self.fd.create_new_block();
        let _ = name;
        (b.clone(), name.to_string())
    }
    fn var(&mut self, name: &str, size: usize) -> Var {
        let vn = self.fd.new_unique(size);
        self.var_name.insert(Arc::as_ptr(&vn) as usize, name.to_string());
        vn
    }
    fn cnst(&mut self, name: &str, size: usize, val: u64) -> Var {
        let vn = self.fd.new_constant(size, val);
        self.var_name.insert(Arc::as_ptr(&vn) as usize, name.to_string());
        vn
    }
    fn coderef(&mut self, name: &str, off: u64) -> Var {
        let vn = self.fd.new_code_ref(Address::new(off));
        self.var_name.insert(Arc::as_ptr(&vn) as usize, name.to_string());
        vn
    }
    fn op(&mut self, name: &str, block: &Block, opc: OpCode, inputs: usize) -> Op {
        let op = self.fd.new_op(inputs, Address::new(0x500000 + self.seq as u64));
        self.seq += 1;
        self.fd.op_set_opcode(&op, opc);
        self.fd.op_insert_end(&op, block);
        let arc = op.0.clone();
        self.op_name.insert(Arc::as_ptr(&arc) as usize, name.to_string());
        arc
    }
    fn out(&mut self, name: &str, op: &Op, size: usize) -> Var {
        let opref = rudra::op::PcodeOpRef(op.clone());
        let vn = self.fd.new_unique_out(size, &opref);
        self.var_name.insert(Arc::as_ptr(&vn) as usize, name.to_string());
        vn
    }
    fn input(&mut self, op: &Op, vn: &Var, slot: usize) {
        let opref = rudra::op::PcodeOpRef(op.clone());
        self.fd.op_set_input(&opref, vn.clone(), slot);
    }
    fn set_input(&mut self, vn: &Var) {
        let _ = self.fd.set_input_varnode(vn.clone());
    }
    fn edge(&mut self, a: &Block, b: &Block) {
        self.fd.bblocks.add_edge(a.clone(), b.clone());
    }
    fn vn_name(&self, vn: Option<&Var>) -> String {
        match vn {
            None => "null".to_string(),
            Some(vn) => self
                .var_name
                .get(&(Arc::as_ptr(vn) as usize))
                .cloned()
                .unwrap_or_else(|| "?".to_string()),
        }
    }
    fn op_name_of(&self, op: &Option<Op>) -> String {
        match op {
            None => "null".to_string(),
            Some(op) => self
                .op_name
                .get(&(Arc::as_ptr(op) as usize))
                .cloned()
                .unwrap_or_else(|| "?".to_string()),
        }
    }
    fn range_raw(rng: &CircleRange) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            rng.get_left(),
            rng.get_right(),
            rng.get_mask(),
            rng.get_step(),
            i32::from(rng.is_empty())
        )
    }
    fn quasi(&self, name: &str, vn: &Var) -> String {
        let (base, bits) = quasi_copy(vn);
        format!("q:{}={}/{}", name, self.vn_name(base.as_ref()), bits)
    }
}

fn report(label: &str, lab: &Lab, basic: &JumpBasic, candidates: &[Var]) {
    let mut s = String::new();
    let _ = write!(s, "{label}|count={}", basic.selectguards.len());
    for (i, g) in basic.selectguards.iter().enumerate() {
        let _ = write!(
            s,
            "|g{i}:cb={},ro={},ip={},rng={},unr={}",
            lab.op_name_of(&g.get_branch()),
            lab.op_name_of(&g.get_read_op()),
            g.get_path(),
            Lab::range_raw(g.get_range()),
            i32::from(g.is_unrolled())
        );
    }
    for (i, g) in basic.selectguards.iter().enumerate() {
        for (j, cand) in candidates.iter().enumerate() {
            let (base, bits) = quasi_copy(cand);
            let _ = write!(s, "|vm{i}_{j}={}", g.value_match(cand, &base, bits));
        }
    }
    println!("{s}");
}

// SC1: two chained range guards (x>2 && x<10) over a 4-byte switch
// variable.
fn scenario_chain_range(lab: &mut Lab) {
    let x = lab.var("x", 4);
    lab.set_input(&x);
    let (e, _) = lab.blk("E");
    let (b, _) = lab.blk("B");
    let (s, _) = lab.blk("S");
    let (d, _) = lab.blk("D");
    let (d2, _) = lab.blk("D2");
    let cmp1 = lab.op("E.cmp1", &e, OpCode::CPUI_INT_LESS, 2);
    let b0 = lab.out("b0", &cmp1, 1);
    lab.input(&cmp1, &x, 0);
    let c10 = lab.cnst("c10", 4, 10);
    lab.input(&cmp1, &c10, 1);
    let cb_e = lab.op("E.cb", &e, OpCode::CPUI_CBRANCH, 2);
    let ref_e = lab.coderef("refE", 0x6000);
    lab.input(&cb_e, &ref_e, 0);
    lab.input(&cb_e, &b0, 1);
    let cmp2 = lab.op("B.cmp2", &b, OpCode::CPUI_INT_SLESS, 2);
    let b1 = lab.out("b1", &cmp2, 1);
    let c3 = lab.cnst("c3", 4, 3);
    lab.input(&cmp2, &c3, 0);
    lab.input(&cmp2, &x, 1);
    let cb_b = lab.op("B.cb", &b, OpCode::CPUI_CBRANCH, 2);
    let ref_b = lab.coderef("refB", 0x6010);
    lab.input(&cb_b, &ref_b, 0);
    lab.input(&cb_b, &b1, 1);
    let bi_s = lab.op("S.bi", &s, OpCode::CPUI_BRANCHIND, 1);
    let swtarget = lab.var("swtarget", 4);
    lab.input(&bi_s, &swtarget, 0);
    lab.edge(&e, &b);
    lab.edge(&e, &d);
    lab.edge(&b, &s);
    lab.edge(&b, &d2);

    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0))));
    jt.write().unwrap().set_indirect_op(bi_s.clone());
    let mut basic = JumpBasic::new(jt.clone());
    basic.analyze_guards(&s, -1);
    report("sc1_chain_range", lab, &basic, &[x, b0, b1]);
}

// SC2: unrolled guard across two blocks joining at M.
fn scenario_unrolled(lab: &mut Lab) {
    let x2 = lab.var("x2", 4);
    lab.set_input(&x2);
    let (u1, _) = lab.blk("U1");
    let (u2, _) = lab.blk("U2");
    let (m, _) = lab.blk("M");
    let (du, _) = lab.blk("DU");
    let (s2, _) = lab.blk("S2");
    let cmp_u1 = lab.op("U1.cmp", &u1, OpCode::CPUI_INT_LESS, 2);
    let bu1 = lab.out("bU1", &cmp_u1, 1);
    lab.input(&cmp_u1, &x2, 0);
    let c5 = lab.cnst("c5", 4, 5);
    lab.input(&cmp_u1, &c5, 1);
    let cb_u1 = lab.op("U1.cb", &u1, OpCode::CPUI_CBRANCH, 2);
    let ref_u1 = lab.coderef("refU1", 0x6100);
    lab.input(&cb_u1, &ref_u1, 0);
    lab.input(&cb_u1, &bu1, 1);
    let cmp_u2 = lab.op("U2.cmp", &u2, OpCode::CPUI_INT_LESS, 2);
    let bu2 = lab.out("bU2", &cmp_u2, 1);
    lab.input(&cmp_u2, &x2, 0);
    let c5b = lab.cnst("c5b", 4, 5);
    lab.input(&cmp_u2, &c5b, 1);
    let cb_u2 = lab.op("U2.cb", &u2, OpCode::CPUI_CBRANCH, 2);
    let ref_u2 = lab.coderef("refU2", 0x6110);
    lab.input(&cb_u2, &ref_u2, 0);
    lab.input(&cb_u2, &bu2, 1);
    let phi = lab.op("M.phi", &m, OpCode::CPUI_MULTIEQUAL, 2);
    let mout = lab.out("mout", &phi, 1);
    lab.input(&phi, &bu1, 0);
    lab.input(&phi, &bu2, 1);
    let bi_s2 = lab.op("S2.bi", &s2, OpCode::CPUI_BRANCHIND, 1);
    let swtarget2 = lab.var("swtarget2", 4);
    lab.input(&bi_s2, &swtarget2, 0);
    lab.edge(&u1, &m);
    lab.edge(&u1, &du);
    lab.edge(&u2, &m);
    lab.edge(&u2, &du);
    lab.edge(&m, &s2);

    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0))));
    jt.write().unwrap().set_indirect_op(bi_s2.clone());
    let mut basic = JumpBasic::new(jt.clone());
    basic.analyze_guards(&s2, -1);
    report("sc2_unrolled", lab, &basic, &[x2, bu1, bu2, mout]);
}

// SC3: single guard with a negative signed constant (x >=s -5).
fn scenario_neg_const(lab: &mut Lab) {
    let x3 = lab.var("x3", 4);
    let (g3, _) = lab.blk("G3");
    let (s3, _) = lab.blk("S3");
    let (d3, _) = lab.blk("D3");
    let cmp3 = lab.op("G3.cmp", &g3, OpCode::CPUI_INT_SLESS, 2);
    let b3 = lab.out("b3", &cmp3, 1);
    lab.input(&cmp3, &x3, 0);
    let cneg5 = lab.cnst("cneg5", 4, 0xfffffffb);
    lab.input(&cmp3, &cneg5, 1);
    let cb_g3 = lab.op("G3.cb", &g3, OpCode::CPUI_CBRANCH, 2);
    let ref_g3 = lab.coderef("refG3", 0x6200);
    lab.input(&cb_g3, &ref_g3, 0);
    lab.input(&cb_g3, &b3, 1);
    let bi_s3 = lab.op("S3.bi", &s3, OpCode::CPUI_BRANCHIND, 1);
    let swtarget3 = lab.var("swtarget3", 4);
    lab.input(&bi_s3, &swtarget3, 0);
    lab.edge(&g3, &s3);
    lab.edge(&g3, &d3);

    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0))));
    jt.write().unwrap().set_indirect_op(bi_s3.clone());
    let mut basic = JumpBasic::new(jt.clone());
    basic.analyze_guards(&s3, -1);
    report("sc3_neg_const", lab, &basic, &[x3, b3]);
}

// SC4: at i!=0 the OTHER out-edge leads to a foreign BRANCHIND:
// analyzeGuards must break.
fn scenario_other_switch(lab: &mut Lab) {
    let x4 = lab.var("x4", 4);
    lab.set_input(&x4);
    let (x4b, _) = lab.blk("X4");
    let (a4, _) = lab.blk("A4");
    let (o4, _) = lab.blk("O4");
    let (s4, _) = lab.blk("S4");
    let (d4, _) = lab.blk("D4");
    let cmp4 = lab.op("X4.cmp", &x4b, OpCode::CPUI_INT_LESS, 2);
    let b4 = lab.out("b4", &cmp4, 1);
    lab.input(&cmp4, &x4, 0);
    let c7 = lab.cnst("c7", 4, 7);
    lab.input(&cmp4, &c7, 1);
    let cb_x4 = lab.op("X4.cb", &x4b, OpCode::CPUI_CBRANCH, 2);
    let ref_x4 = lab.coderef("refX4", 0x6300);
    lab.input(&cb_x4, &ref_x4, 0);
    lab.input(&cb_x4, &b4, 1);
    let cmp4b = lab.op("A4.cmp", &a4, OpCode::CPUI_INT_LESS, 2);
    let b4b = lab.out("b4b", &cmp4b, 1);
    lab.input(&cmp4b, &x4, 0);
    let c3b = lab.cnst("c3b", 4, 3);
    lab.input(&cmp4b, &c3b, 1);
    let cb_a4 = lab.op("A4.cb", &a4, OpCode::CPUI_CBRANCH, 2);
    let ref_a4 = lab.coderef("refA4", 0x6310);
    lab.input(&cb_a4, &ref_a4, 0);
    lab.input(&cb_a4, &b4b, 1);
    let bi_o4 = lab.op("O4.bi", &o4, OpCode::CPUI_BRANCHIND, 1);
    let foreigntarget = lab.var("foreigntarget", 4);
    lab.input(&bi_o4, &foreigntarget, 0);
    let bi_s4 = lab.op("S4.bi", &s4, OpCode::CPUI_BRANCHIND, 1);
    let swtarget4 = lab.var("swtarget4", 4);
    lab.input(&bi_s4, &swtarget4, 0);
    lab.edge(&x4b, &a4);
    lab.edge(&x4b, &o4);
    lab.edge(&a4, &s4);
    lab.edge(&a4, &d4);

    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0))));
    jt.write().unwrap().set_indirect_op(bi_s4.clone());
    let mut basic = JumpBasic::new(jt.clone());
    basic.analyze_guards(&s4, -1);
    report("sc4_other_switch", lab, &basic, &[x4, b4, b4b]);
}

// SC5: pathout stepping (JumpBasic2 style): analyzeGuards(X5,1).
fn scenario_pathout(lab: &mut Lab) {
    let x5 = lab.var("x5", 4);
    lab.set_input(&x5);
    let (w5, _) = lab.blk("W5");
    let (x5b, _) = lab.blk("X5");
    let (a5, _) = lab.blk("A5");
    let (ex5, _) = lab.blk("EX5");
    let (s5, _) = lab.blk("S5");
    let cmp5 = lab.op("W5.cmp", &w5, OpCode::CPUI_INT_LESS, 2);
    let b5 = lab.out("b5", &cmp5, 1);
    lab.input(&cmp5, &x5, 0);
    let c20 = lab.cnst("c20", 4, 20);
    lab.input(&cmp5, &c20, 1);
    let cb_w5 = lab.op("W5.cb", &w5, OpCode::CPUI_CBRANCH, 2);
    let ref_w5 = lab.coderef("refW5", 0x6400);
    lab.input(&cb_w5, &ref_w5, 0);
    lab.input(&cb_w5, &b5, 1);
    let cmp5b = lab.op("X5.cmp", &x5b, OpCode::CPUI_INT_LESS, 2);
    let b5b = lab.out("b5b", &cmp5b, 1);
    lab.input(&cmp5b, &x5, 0);
    let c8 = lab.cnst("c8", 4, 8);
    lab.input(&cmp5b, &c8, 1);
    let cb_x5 = lab.op("X5.cb", &x5b, OpCode::CPUI_CBRANCH, 2);
    let ref_x5 = lab.coderef("refX5", 0x6410);
    lab.input(&cb_x5, &ref_x5, 0);
    lab.input(&cb_x5, &b5b, 1);
    let bi_ex5 = lab.op("EX5.bi", &ex5, OpCode::CPUI_BRANCHIND, 1);
    let exittarget = lab.var("exittarget", 4);
    lab.input(&bi_ex5, &exittarget, 0);
    let bi_s5 = lab.op("S5.bi", &s5, OpCode::CPUI_BRANCHIND, 1);
    let swtarget5 = lab.var("swtarget5", 4);
    lab.input(&bi_s5, &swtarget5, 0);
    lab.edge(&w5, &x5b);
    lab.edge(&w5, &ex5);
    lab.edge(&x5b, &a5);
    lab.edge(&x5b, &s5);

    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0))));
    jt.write().unwrap().set_indirect_op(bi_s5.clone());
    let mut basic = JumpBasic::new(jt.clone());
    basic.analyze_guards(&x5b, 1);
    report("sc5_pathout", lab, &basic, &[x5, b5, b5b]);
}

// SC6: quasiCopy walks and valueMatch deep branches after calc_nz_mask.
fn scenario_quasi_value_match(lab: &mut Lab) {
    let y = lab.var("y", 4);
    lab.set_input(&y);
    let (q, _) = lab.blk("Q");
    let and1 = lab.op("Q.and1", &q, OpCode::CPUI_INT_AND, 2);
    let v1 = lab.out("v1", &and1, 4);
    lab.input(&and1, &y, 0);
    let cf = lab.cnst("cf", 4, 0xf);
    lab.input(&and1, &cf, 1);
    let and2 = lab.op("Q.and2", &q, OpCode::CPUI_INT_AND, 2);
    let v2 = lab.out("v2", &and2, 4);
    lab.input(&and2, &y, 0);
    let cfb = lab.cnst("cfb", 4, 0xf);
    lab.input(&and2, &cfb, 1);
    let add1 = lab.op("Q.add1", &q, OpCode::CPUI_INT_ADD, 2);
    let w1 = lab.out("w1", &add1, 4);
    lab.input(&add1, &y, 0);
    let c4 = lab.cnst("c4", 4, 4);
    lab.input(&add1, &c4, 1);
    let add2 = lab.op("Q.add2", &q, OpCode::CPUI_INT_ADD, 2);
    let w2 = lab.out("w2", &add2, 4);
    lab.input(&add2, &y, 0);
    let c4b = lab.cnst("c4b", 4, 4);
    lab.input(&add2, &c4b, 1);
    let add3 = lab.op("Q.add3", &q, OpCode::CPUI_INT_ADD, 2);
    let w3 = lab.out("w3", &add3, 4);
    lab.input(&add3, &y, 0);
    let c6 = lab.cnst("c6", 4, 6);
    lab.input(&add3, &c6, 1);
    let copy1 = lab.op("Q.copy1", &q, OpCode::CPUI_COPY, 1);
    let u1 = lab.out("u1", &copy1, 4);
    lab.input(&copy1, &y, 0);
    let copy2 = lab.op("Q.copy2", &q, OpCode::CPUI_COPY, 1);
    let u2 = lab.out("u2", &copy2, 4);
    lab.input(&copy2, &y, 0);
    let z = lab.var("z", 8);
    lab.set_input(&z);
    let padd1 = lab.op("Q.padd1", &q, OpCode::CPUI_INT_ADD, 2);
    let p1 = lab.out("p1", &padd1, 8);
    lab.input(&padd1, &z, 0);
    let c8_64 = lab.cnst("c8_64", 8, 8);
    lab.input(&padd1, &c8_64, 1);
    let padd2 = lab.op("Q.padd2", &q, OpCode::CPUI_INT_ADD, 2);
    let p2 = lab.out("p2", &padd2, 8);
    lab.input(&padd2, &z, 0);
    let c8b_64 = lab.cnst("c8b_64", 8, 8);
    lab.input(&padd2, &c8b_64, 1);
    let padd3 = lab.op("Q.padd3", &q, OpCode::CPUI_INT_ADD, 2);
    let p3 = lab.out("p3", &padd3, 8);
    lab.input(&padd3, &z, 0);
    let c16_64 = lab.cnst("c16_64", 8, 16);
    lab.input(&padd3, &c16_64, 1);
    let sp1 = lab.cnst("sp1", 8, 0x2);
    let sp1b = lab.cnst("sp1b", 8, 0x2);
    let load1 = lab.op("Q.load1", &q, OpCode::CPUI_LOAD, 2);
    let l1 = lab.out("l1", &load1, 4);
    lab.input(&load1, &sp1, 0);
    lab.input(&load1, &p1, 1);
    let load2 = lab.op("Q.load2", &q, OpCode::CPUI_LOAD, 2);
    let l2 = lab.out("l2", &load2, 4);
    lab.input(&load2, &sp1b, 0);
    lab.input(&load2, &p2, 1);
    let load3 = lab.op("Q.load3", &q, OpCode::CPUI_LOAD, 2);
    let l3 = lab.out("l3", &load3, 4);
    lab.input(&load3, &sp1, 0);
    lab.input(&load3, &p3, 1);
    let sext = lab.op("Q.sext", &q, OpCode::CPUI_INT_SEXT, 1);
    let s1 = lab.out("s1", &sext, 8);
    lab.input(&sext, &y, 0);
    let sub = lab.op("Q.sub", &q, OpCode::CPUI_SUBPIECE, 2);
    let t1 = lab.out("t1", &sub, 4);
    lab.input(&sub, &z, 0);
    let c0 = lab.cnst("c0", 8, 0);
    lab.input(&sub, &c0, 1);
    let dummy = lab.op("Q.dummy", &q, OpCode::CPUI_COPY, 1);
    lab.input(&dummy, &y, 0);
    let k1 = lab.cnst("k1", 4, 5);
    let k2 = lab.cnst("k2", 4, 9);
    let k3 = lab.cnst("k3", 4, 6);

    // Compute non-zero masks so INT_AND's quasiCopy mask walk is live.
    lab.fd.calc_nz_mask();

    let mut s = String::from("sc6_quasi_vm");
    s.push('|');
    s.push_str(&lab.quasi("y", &y));
    s.push('|');
    s.push_str(&lab.quasi("v1", &v1));
    s.push('|');
    s.push_str(&lab.quasi("v2", &v2));
    s.push('|');
    s.push_str(&lab.quasi("u1", &u1));
    s.push('|');
    s.push_str(&lab.quasi("s1", &s1));
    s.push('|');
    s.push_str(&lab.quasi("t1", &t1));
    s.push('|');
    s.push_str(&lab.quasi("p1", &p1));
    s.push('|');
    s.push_str(&lab.quasi("l1", &l1));

    let guard_and = GuardRecord::new(dummy.clone(), dummy.clone(), 0, CircleRange::boolean(true), v1.clone(), false);
    let (base, bits) = quasi_copy(&v2);
    let _ = write!(s, "|vm_and_samebase={}", guard_and.value_match(&v2, &base, bits));
    let (base, bits) = quasi_copy(&y);
    let _ = write!(s, "|vm_and_y={}", guard_and.value_match(&y, &base, bits));
    let (base, bits) = quasi_copy(&v1);
    let _ = write!(s, "|vm_and_samevn={}", guard_and.value_match(&v1, &base, bits));

    let guard_add = GuardRecord::new(dummy.clone(), dummy.clone(), 0, CircleRange::boolean(true), w1.clone(), false);
    let (base, bits) = quasi_copy(&w2);
    let _ = write!(s, "|vm_add_oneoff={}", guard_add.value_match(&w2, &base, bits));
    let (base, bits) = quasi_copy(&w3);
    let _ = write!(s, "|vm_add_offconst={}", guard_add.value_match(&w3, &base, bits));

    let guard_copy = GuardRecord::new(dummy.clone(), dummy.clone(), 0, CircleRange::boolean(false), u1.clone(), false);
    let (base, bits) = quasi_copy(&u2);
    let _ = write!(s, "|vm_copy_samebase={}", guard_copy.value_match(&u2, &base, bits));

    let guard_load = GuardRecord::new(dummy.clone(), dummy.clone(), 0, CircleRange::boolean(true), l1.clone(), false);
    let (base, bits) = quasi_copy(&l2);
    let _ = write!(s, "|vm_load_equiv={}", guard_load.value_match(&l2, &base, bits));
    let (base, bits) = quasi_copy(&l3);
    let _ = write!(s, "|vm_load_offdiff={}", guard_load.value_match(&l3, &base, bits));

    let guard_const = GuardRecord::new(dummy.clone(), dummy.clone(), 0, CircleRange::boolean(true), k1.clone(), false);
    let (base, bits) = quasi_copy(&k2);
    let _ = write!(s, "|vm_const_bitsdiff={}", guard_const.value_match(&k2, &base, bits));
    let (base, bits) = quasi_copy(&k3);
    let _ = write!(s, "|vm_const_basediff={}", guard_const.value_match(&k3, &base, bits));
    println!("{s}");
}

fn main() {
    let mut lab = Lab::new();
    scenario_chain_range(&mut lab);
    scenario_unrolled(&mut lab);
    scenario_neg_const(&mut lab);
    scenario_other_switch(&mut lab);
    scenario_pathout(&mut lab);
    scenario_quasi_value_match(&mut lab);
}
