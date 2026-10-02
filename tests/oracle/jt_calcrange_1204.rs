//! JT-CALCRANGE-1204 (JUMPTABLE-CALCRANGE-0001) Rudra comparand.
//!
//! Mirrors tests/oracle/jt_calcrange_1204.cc: observes
//! JumpBasic::calc_range (jumptable.cc:1120-1156),
//! JumpBasic::mark_foldable_guards (jumptable.cc:1239-1251) and
//! JumpBasic::mark_model (jumptable.cc:1254-1267) on synthetic guard CFGs.
//! Output format is byte-identical to the C++ fixture.

use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::jumptable::{JumpBasic, JumpModel, JumpTable};
use rudra::opcodes::OpCode;
use rudra::rangeutil::CircleRange;
use rudra::varnode::Varnode;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>;
type Var = Arc<RwLock<Varnode>>;
type Op = Arc<RwLock<rudra::op::PcodeOp>>;

/// Mirrors Ghidra's PcodeOp::mark bit as tracked by Rudra's jumptable
/// module (MARK_FLAG in src/jumptable.rs).
const MARK_FLAG: u32 = 1;

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
    fn is_marked(op: &Op) -> i32 {
        i32::from((op.read().unwrap().addlflags & MARK_FLAG) != 0)
    }
}

fn dump_guards(lab: &Lab, s: &mut String, guards: &[rudra::jumptable::GuardRecord]) {
    let _ = write!(s, "|count={}", guards.len());
    for (i, g) in guards.iter().enumerate() {
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
}

// SC1: two chained unsigned range guards (x<8 and x<10) over a 4-byte
// switch variable fed straight into BRANCHIND.
fn scenario_range_guard(lab: &mut Lab) {
    let x = lab.var("x", 4);
    lab.set_input(&x);
    let u = lab.var("u", 4);
    lab.set_input(&u);
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
    let cmp2 = lab.op("B.cmp2", &b, OpCode::CPUI_INT_LESS, 2);
    let b1 = lab.out("b1", &cmp2, 1);
    lab.input(&cmp2, &x, 0);
    let c8 = lab.cnst("c8", 4, 8);
    lab.input(&cmp2, &c8, 1);
    let cb_b = lab.op("B.cb", &b, OpCode::CPUI_CBRANCH, 2);
    let ref_b = lab.coderef("refB", 0x6010);
    lab.input(&cb_b, &ref_b, 0);
    lab.input(&cb_b, &b1, 1);
    let bi_s = lab.op("S.bi", &s, OpCode::CPUI_BRANCHIND, 1);
    lab.input(&bi_s, &x, 0);
    lab.edge(&e, &d); // out(0): default path
    lab.edge(&e, &b); // out(1): switch path
    lab.edge(&b, &d2); // out(0): default path
    lab.edge(&b, &s); // out(1): switch path

    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0))));
    jt.write().unwrap().set_indirect_op(bi_s.clone());
    let mut basic = JumpBasic::new(jt.clone());
    // recover_model now returns Result<bool, JumpTableRecoveryError> (the
    // LowlevelError channel Ghidra raises as an exception). In these scenarios
    // the channel must stay silent; a raised error mirrors the C++ uncaught
    // LowlevelError abort, so propagate it loudly instead of printing ok=0.
    let ok = basic
        .recover_model(&lab.fd, &bi_s, 0, 500)
        .expect("sc1 recover_model error channel must stay silent");

    let mut s = String::new();
    let _ = write!(s, "sc1_range_guard|ok={}", i32::from(ok));
    dump_guards(lab, &mut s, &basic.selectguards);
    let mut rng = CircleRange::empty();
    basic.calc_range(&x, &mut rng);
    let _ = write!(s, "|cr_x={}", Lab::range_raw(&rng));
    basic.calc_range(&b0, &mut rng);
    let _ = write!(s, "|cr_b0={}", Lab::range_raw(&rng));
    basic.calc_range(&b1, &mut rng);
    let _ = write!(s, "|cr_b1={}", Lab::range_raw(&rng));
    basic.calc_range(&u, &mut rng);
    let _ = write!(s, "|cr_u={}", Lab::range_raw(&rng));
    let vr = basic.jrange.as_ref().expect("jrange allocated by recover_model");
    let _ = write!(
        s,
        "|jsz={}|jsvn={}|jsop={}",
        vr.get_size(),
        lab.vn_name(vr.get_start_varnode().as_ref()),
        lab.op_name_of(&vr.get_start_op())
    );
    println!("{s}");
}

// SC2: constant varnode as the CBRANCH boolean.
fn scenario_constant_input(lab: &mut Lab) {
    let (g, _) = lab.blk("G");
    let (s2, _) = lab.blk("S");
    let (d3, _) = lab.blk("D");
    let k1 = lab.cnst("k1", 1, 1);
    let cb_g = lab.op("G.cb", &g, OpCode::CPUI_CBRANCH, 2);
    let ref_g = lab.coderef("refG", 0x6200);
    lab.input(&cb_g, &ref_g, 0);
    lab.input(&cb_g, &k1, 1);
    let bi_s = lab.op("S.bi", &s2, OpCode::CPUI_BRANCHIND, 1);
    let w = lab.var("w", 4);
    lab.input(&bi_s, &w, 0);
    lab.edge(&g, &d3); // out(0): default path
    lab.edge(&g, &s2); // out(1): switch path

    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0))));
    jt.write().unwrap().set_indirect_op(bi_s.clone());
    let mut basic = JumpBasic::new(jt.clone());
    basic.analyze_guards(&s2, -1);

    let mut s = String::from("sc2_constant_input");
    dump_guards(lab, &mut s, &basic.selectguards);
    let mut rng = CircleRange::empty();
    basic.calc_range(&k1, &mut rng);
    let _ = write!(s, "|cr_k1={}", Lab::range_raw(&rng));
    let k2 = lab.cnst("k2", 4, 0x90000000);
    basic.calc_range(&k2, &mut rng);
    let _ = write!(s, "|cr_k2={}", Lab::range_raw(&rng));
    println!("{s}");
}

// SC3: markModel skip semantics.
fn scenario_mark_model_skip(lab: &mut Lab) {
    let x = lab.var("x", 4);
    lab.set_input(&x);
    let (e, _) = lab.blk("E");
    let (b, _) = lab.blk("B");
    let (s3, _) = lab.blk("S");
    let (d, _) = lab.blk("D");
    let (d2, _) = lab.blk("D2");
    let cmp1 = lab.op("E.cmp1", &e, OpCode::CPUI_INT_LESS, 2);
    let b0 = lab.out("b0", &cmp1, 1);
    lab.input(&cmp1, &x, 0);
    let c10 = lab.cnst("c10", 4, 10);
    lab.input(&cmp1, &c10, 1);
    let cb_e = lab.op("E.cb", &e, OpCode::CPUI_CBRANCH, 2);
    let ref_e = lab.coderef("refE", 0x6300);
    lab.input(&cb_e, &ref_e, 0);
    lab.input(&cb_e, &b0, 1);
    let cmp2 = lab.op("B.cmp2", &b, OpCode::CPUI_INT_LESS, 2);
    let b1 = lab.out("b1", &cmp2, 1);
    lab.input(&cmp2, &x, 0);
    let c8 = lab.cnst("c8", 4, 8);
    lab.input(&cmp2, &c8, 1);
    let cb_b = lab.op("B.cb", &b, OpCode::CPUI_CBRANCH, 2);
    let ref_b = lab.coderef("refB", 0x6310);
    lab.input(&cb_b, &ref_b, 0);
    lab.input(&cb_b, &b1, 1);
    let bi_s = lab.op("S.bi", &s3, OpCode::CPUI_BRANCHIND, 1);
    lab.input(&bi_s, &x, 0);
    lab.edge(&e, &d);
    lab.edge(&e, &b);
    lab.edge(&b, &d2);
    lab.edge(&b, &s3);

    let jt = Arc::new(RwLock::new(JumpTable::new(Address::new(0))));
    jt.write().unwrap().set_indirect_op(bi_s.clone());
    let mut basic = JumpBasic::new(jt.clone());
    // Same Result adaptation as sc1: the error channel must stay silent.
    let ok = basic
        .recover_model(&lab.fd, &bi_s, 0, 500)
        .expect("sc3 recover_model error channel must stay silent");

    let mut s = String::new();
    let _ = write!(s, "sc3_markmodel_skip|ok={}", i32::from(ok));
    for (i, g) in basic.selectguards.iter().enumerate() {
        let _ = write!(s, "|gn{i}={}", i32::from(g.get_branch().is_none()));
    }
    basic.mark_model(true);
    let _ = write!(
        s,
        "|on_Sbi={}|on_Bcmp2={}|on_Ecmp1={}|on_Bcb={}|on_Ecb={}",
        Lab::is_marked(&bi_s),
        Lab::is_marked(&cmp2),
        Lab::is_marked(&cmp1),
        Lab::is_marked(&cb_b),
        Lab::is_marked(&cb_e)
    );
    basic.mark_model(false);
    let _ = write!(
        s,
        "|off_Sbi={}|off_Bcmp2={}|off_Ecmp1={}|off_Bcb={}|off_Ecb={}",
        Lab::is_marked(&bi_s),
        Lab::is_marked(&cmp2),
        Lab::is_marked(&cmp1),
        Lab::is_marked(&cb_b),
        Lab::is_marked(&cb_e)
    );
    println!("{s}");
}

fn main() {
    let mut lab = Lab::new();
    scenario_range_guard(&mut lab);
    scenario_constant_input(&mut lab);
    scenario_mark_model_skip(&mut lab);
}
