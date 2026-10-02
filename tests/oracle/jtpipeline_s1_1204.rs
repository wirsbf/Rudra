//! JT-PIPELINE-S1-1204 (JUMPTABLE-PIPELINE-0001 segment 1) Rudra comparand.
//!
//! Mirrors tests/oracle/jtpipeline_s1_1204.cc case-for-case: model
//! selection chain (override → Assisted → Basic → Basic2, no Trivial),
//! recover_model → find_normalized call shape, EmulateFunction LoadImage
//! bridge and typed error channels (LOAD DataUnavail / BRANCH / RETURN /
//! CBRANCH / MULTIEQUAL lastOp). Output is byte-identical to the C++
//! fixture; message-embedded addresses are normalized to <A> on both
//! sides.

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::funcdata::Funcdata;
use rudra::jumptable::{
    EmulateFunction, JumpTable, JumpTableRecoveryError, PcodeOpNode, PathMeld,
};
use rudra::loadimage::RawLoadImage;
use rudra::opcodes::OpCode;
use rudra::varnode::Varnode;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>;
type Var = Arc<RwLock<Varnode>>;
type Op = Arc<RwLock<rudra::op::PcodeOp>>;

struct Lab {
    fd: Funcdata,
    seq: i32,
}

impl Lab {
    fn new(curl_bytes: Vec<u8>) -> Self {
        let mut arch = Architecture::new();
        // Loader bridge (JUMPTABLE-EMULFN-0001): the same curl image the
        // BfdArchitecture-backed C++ fixture reads. curl is a PIE whose
        // R-segments have vaddr == file offset, so vma=0 mirrors BFD.
        arch.set_loader(Arc::new(RawLoadImage::from_bytes("curl", 0, curl_bytes)));
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        fd.set_arch(Arc::new(arch));
        Self { fd, seq: 0 }
    }
    fn blk(&mut self) -> Block {
        self.fd.create_new_block()
    }
    fn var(&mut self, size: usize) -> Var {
        self.fd.new_unique(size)
    }
    fn cnst(&mut self, size: usize, val: u64) -> Var {
        self.fd.new_constant(size, val)
    }
    fn coderef(&mut self, off: u64) -> Var {
        self.fd.new_code_ref(Address::new(off))
    }
    fn op(&mut self, block: &Block, opc: OpCode, inputs: usize) -> Op {
        let op = self.fd.new_op(inputs, Address::new(0x500000 + self.seq as u64));
        self.seq += 1;
        self.fd.op_set_opcode(&op, opc);
        self.fd.op_insert_end(&op, block);
        op.0.clone()
    }
    fn out(&mut self, op: &Op, size: usize) -> Var {
        let opref = rudra::op::PcodeOpRef(op.clone());
        self.fd.new_unique_out(size, &opref)
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
}

fn canon(msg: &str) -> String {
    match msg.find(" at ") {
        None => msg.to_string(),
        Some(pos) => match msg[pos + 4..].find('.') {
            None => format!("{}<A>", &msg[..pos + 4]),
            Some(dotrel) => format!("{}<A>{}", &msg[..pos + 4], &msg[pos + 4 + dotrel..]),
        },
    }
}

fn hx(v: u64) -> String {
    format!("{:x}", v)
}

fn run_table(out: &mut String, label: &str, lab: &Lab, jt: &mut JumpTable, load_collect: bool) {
    let _ = write!(out, "{}|collect={}", label, i32::from(load_collect));
    jt.set_load_collect(load_collect);
    match jt.recover_addresses_classified(&lab.fd) {
        Ok(()) => {
            let _ = write!(out, "|ok=1|n={}", jt.num_entries());
            for i in 0..jt.num_entries() {
                let _ = write!(out, "|a{}={}", i, hx(jt.get_address_by_index(i).as_u64()));
            }
        }
        Err(err) => {
            let mode = match &err {
                JumpTableRecoveryError::Thunk { .. } => 2,
                JumpTableRecoveryError::Lowlevel { .. } => 1,
            };
            let _ = write!(out, "|ok=0|mode={}|msg={}", mode, canon(err.message()));
        }
    }
    out.push('\n');
}

// sel_basic: guarded switch x in [0,4); BRANCHIND target = x + 0x7000.
fn scenario_basic(out: &mut String, lab: &mut Lab) {
    let x = lab.var(4);
    lab.set_input(&x);
    let g = lab.blk();
    let s = lab.blk();
    let d = lab.blk();
    let cmp = lab.op(&g, OpCode::CPUI_INT_LESS, 2);
    let b0 = lab.out(&cmp, 1);
    lab.input(&cmp, &x, 0);
    let c4 = lab.cnst(4, 4);
    lab.input(&cmp, &c4, 1);
    let cb = lab.op(&g, OpCode::CPUI_CBRANCH, 2);
    let r = lab.coderef(0x6000);
    lab.input(&cb, &r, 0);
    lab.input(&cb, &b0, 1);
    let bi = lab.op(&s, OpCode::CPUI_BRANCHIND, 1);
    let add = lab.op(&s, OpCode::CPUI_INT_ADD, 2);
    let t = lab.out(&add, 4);
    lab.input(&add, &x, 0);
    let c7000 = lab.cnst(4, 0x7000);
    lab.input(&add, &c7000, 1);
    lab.input(&bi, &t, 0);
    lab.edge(&g, &d); // out(0) = default (b0 == 0)
    lab.edge(&g, &s); // out(1) = switch   (b0 == 1)
    lab.fd.calc_nz_mask();

    let mut jt = JumpTable::new(bi.read().unwrap().get_addr());
    jt.set_indirect_op(bi.clone());
    run_table(out, "sel_basic", lab, &mut jt, false);
}

// sel_override: manual override wins before any model analysis.
fn scenario_override(out: &mut String, lab: &mut Lab) {
    let s = lab.blk();
    let bi = lab.op(&s, OpCode::CPUI_BRANCHIND, 1);
    let rawt = lab.var(4);
    lab.input(&bi, &rawt, 0);
    lab.fd.calc_nz_mask();

    let mut jt = JumpTable::new(bi.read().unwrap().get_addr());
    jt.set_indirect_op(bi.clone());
    jt.set_override(&[Address::new(0x2000), Address::new(0x2100)], Address::new(0), 0, 0);
    run_table(out, "sel_override", lab, &mut jt, false);
}

// sel_basic2_default: BRANCHIND target = MULTIEQUAL(default-copy, x) + 0x3000.
// JumpBasic fails (join is a marker prune, range unbounded); JumpBasic2
// recovers with the guarded x range and appends the default value entry.
fn scenario_basic2(out: &mut String, lab: &mut Lab) {
    let x = lab.var(4);
    lab.set_input(&x);
    let a = lab.blk();
    let c = lab.blk();
    let s = lab.blk();
    let d = lab.blk();
    let cmp = lab.op(&a, OpCode::CPUI_INT_LESS, 2);
    let b0 = lab.out(&cmp, 1);
    lab.input(&cmp, &x, 0);
    let c4 = lab.cnst(4, 4);
    lab.input(&cmp, &c4, 1);
    let cb = lab.op(&a, OpCode::CPUI_CBRANCH, 2);
    let r = lab.coderef(0x6100);
    lab.input(&cb, &r, 0);
    lab.input(&cb, &b0, 1);
    let cp = lab.op(&c, OpCode::CPUI_COPY, 1);
    let c1 = lab.out(&cp, 4);
    let cdef = lab.cnst(4, 0x4141);
    lab.input(&cp, &cdef, 0);
    let me = lab.op(&s, OpCode::CPUI_MULTIEQUAL, 2);
    let j = lab.out(&me, 4);
    lab.input(&me, &c1, 0);
    lab.input(&me, &x, 1);
    let bi = lab.op(&s, OpCode::CPUI_BRANCHIND, 1);
    let add = lab.op(&s, OpCode::CPUI_INT_ADD, 2);
    let t2 = lab.out(&add, 4);
    lab.input(&add, &j, 0);
    let c3000 = lab.cnst(4, 0x3000);
    lab.input(&add, &c3000, 1);
    lab.input(&bi, &t2, 0);
    lab.edge(&a, &d); // A out(0) = default guard target
    lab.edge(&c, &s); // S in(0) = C (const path) -- ME.in(0) = c1 must flow from in(0)
    lab.edge(&a, &s); // A out(1) = switch (b0 == 1); S in(1) = A -- ME.in(1) = x
    lab.fd.calc_nz_mask();

    let mut jt = JumpTable::new(bi.read().unwrap().get_addr());
    jt.set_indirect_op(bi.clone());
    run_table(out, "sel_basic2_default", lab, &mut jt, false);
}

// sel_allfail: def-less raw register read, no guard: every model rejects.
fn scenario_allfail(out: &mut String, lab: &mut Lab) {
    let e = lab.blk();
    let s = lab.blk();
    let bi = lab.op(&s, OpCode::CPUI_BRANCHIND, 1);
    let raw8 = lab.var(8);
    lab.input(&bi, &raw8, 0);
    let dummy = lab.op(&e, OpCode::CPUI_COPY, 1);
    let dv = lab.var(4);
    lab.input(&dummy, &dv, 0);
    lab.edge(&e, &s);
    lab.fd.calc_nz_mask();

    let mut jt = JumpTable::new(bi.read().unwrap().get_addr());
    jt.set_indirect_op(bi.clone());
    run_table(out, "sel_allfail", lab, &mut jt, false);
}

// emulfn_load_ok / emulfn_load_dataunavail: guarded x in [0,4);
// target = ZEXT(LOAD(space-id, base + x), 1->4) + 0x8000.
fn scenario_load(out: &mut String, lab: &mut Lab, label: &str, base: u64) {
    let x = lab.var(4);
    lab.set_input(&x);
    let g = lab.blk();
    let s = lab.blk();
    let d = lab.blk();
    let cmp = lab.op(&g, OpCode::CPUI_INT_LESS, 2);
    let b0 = lab.out(&cmp, 1);
    lab.input(&cmp, &x, 0);
    let c4 = lab.cnst(4, 4);
    lab.input(&cmp, &c4, 1);
    let cb = lab.op(&g, OpCode::CPUI_CBRANCH, 2);
    let r = lab.coderef(0x6200);
    lab.input(&cb, &r, 0);
    lab.input(&cb, &b0, 1);
    let addp = lab.op(&g, OpCode::CPUI_INT_ADD, 2);
    let ptr = lab.out(&addp, 4);
    lab.input(&addp, &x, 0);
    let lbase = lab.cnst(4, base);
    lab.input(&addp, &lbase, 1);
    let ld = lab.op(&g, OpCode::CPUI_LOAD, 2);
    let lv = lab.out(&ld, 1);
    // Rudra encodes the LOAD space-id as a SpaceId constant (Ram = 3);
    // Ghidra encodes the AddrSpace pointer (varnode.hh:426) — same ram space.
    let lspc = lab.cnst(1, rudra::space::AddressSpace::Ram.space_id() as u64);
    lab.input(&ld, &lspc, 0);
    lab.input(&ld, &ptr, 1);
    let zx = lab.op(&g, OpCode::CPUI_INT_ZEXT, 1);
    let zv = lab.out(&zx, 4);
    lab.input(&zx, &lv, 0);
    let bi = lab.op(&s, OpCode::CPUI_BRANCHIND, 1);
    let add2 = lab.op(&s, OpCode::CPUI_INT_ADD, 2);
    let t3 = lab.out(&add2, 4);
    lab.input(&add2, &zv, 0);
    let c8000 = lab.cnst(4, 0x8000);
    lab.input(&add2, &c8000, 1);
    lab.input(&bi, &t3, 0);
    lab.edge(&g, &d);
    lab.edge(&g, &s);
    lab.fd.calc_nz_mask();

    let mut jt = JumpTable::new(bi.read().unwrap().get_addr());
    jt.set_indirect_op(bi.clone());
    run_table(out, label, lab, &mut jt, true);
}

// Direct EmulateFunction::emulate_path channel probes.
fn scenario_channels(out: &mut String, lab: &mut Lab) {
    let mut s = String::new();
    let _ = write!(s, "emulfn_channels");

    // (a) BRANCH inside the meld -> LowlevelError (jumptable.cc:126-130).
    {
        let v = lab.cnst(4, 0x33);
        let b1 = lab.blk();
        let br = lab.op(&b1, OpCode::CPUI_BRANCH, 1);
        let bo = lab.out(&br, 4);
        lab.input(&br, &v, 0);
        let b2 = lab.blk();
        let bi = lab.op(&b2, OpCode::CPUI_BRANCHIND, 1);
        lab.input(&bi, &bo, 0);
        let mut pm = PathMeld::default();
        pm.set_path(&[
            PcodeOpNode { op: bi.clone(), slot: 0 },
            PcodeOpNode { op: br.clone(), slot: 0 },
        ]);
        let mut emul = EmulateFunction::new(&lab.fd);
        match emul.emulate_path(1, &pm, &br, &v) {
            Ok(res) => {
                let _ = write!(s, "|a=ok:{}", hx(res));
            }
            Err(e) => {
                let _ = write!(s, "|a=err:{}", e.message());
            }
        }
    }
    // (b) RETURN inside the meld -> "Indirect branch encountered ..."
    {
        let v = lab.cnst(4, 0x44);
        let b1 = lab.blk();
        let ret = lab.op(&b1, OpCode::CPUI_RETURN, 1);
        let ro = lab.out(&ret, 4);
        lab.input(&ret, &v, 0);
        let b2 = lab.blk();
        let bi = lab.op(&b2, OpCode::CPUI_BRANCHIND, 1);
        lab.input(&bi, &ro, 0);
        let mut pm = PathMeld::default();
        pm.set_path(&[
            PcodeOpNode { op: bi.clone(), slot: 0 },
            PcodeOpNode { op: ret.clone(), slot: 0 },
        ]);
        let mut emul = EmulateFunction::new(&lab.fd);
        match emul.emulate_path(1, &pm, &ret, &v) {
            Ok(res) => {
                let _ = write!(s, "|b=ok:{}", hx(res));
            }
            Err(e) => {
                let _ = write!(s, "|b=err:{}", e.message());
            }
        }
    }
    // (c) CBRANCH taken (cond const 1) -> branch error; not taken (cond 0)
    // falls through and the final value reads back.
    for variant in 0..2 {
        let v = lab.cnst(4, 0x55);
        let cond = lab.cnst(1, variant);
        let bb = lab.blk();
        let cb = lab.op(&bb, OpCode::CPUI_CBRANCH, 2);
        let r = lab.coderef(0x6300);
        lab.input(&cb, &r, 0);
        lab.input(&cb, &cond, 1);
        let bd = lab.blk();
        let bi = lab.op(&bd, OpCode::CPUI_BRANCHIND, 1);
        lab.input(&bi, &v, 0);
        let mut pm = PathMeld::default();
        pm.set_path(&[
            PcodeOpNode { op: bi.clone(), slot: 0 },
            PcodeOpNode { op: cb.clone(), slot: 0 },
        ]);
        let mut emul = EmulateFunction::new(&lab.fd);
        match emul.emulate_path(1, &pm, &cb, &v) {
            Ok(res) => {
                let _ = write!(s, "|c{}=ok:{}", variant, hx(res));
            }
            Err(e) => {
                let _ = write!(s, "|c{}=err:{}", variant, e.message());
            }
        }
    }
    // (d) MULTIEQUAL whose parent block has no in-edge from lastOp's block
    // -> "Could not execute MULTIEQUAL" (emulateutil.cc:100-105).
    {
        let z = lab.blk();
        let m = lab.blk(); // two in-edges, neither from Z
        let w1 = lab.blk();
        let w2 = lab.blk();
        lab.edge(&w1, &m);
        lab.edge(&w2, &m);
        let v = lab.cnst(4, 0x66);
        let cp = lab.op(&z, OpCode::CPUI_COPY, 1);
        let w = lab.out(&cp, 4);
        lab.input(&cp, &v, 0);
        let me = lab.op(&m, OpCode::CPUI_MULTIEQUAL, 2);
        let mo = lab.out(&me, 4);
        lab.input(&me, &w, 0);
        let mw2 = lab.var(4);
        lab.input(&me, &mw2, 1);
        let bi = lab.op(&m, OpCode::CPUI_BRANCHIND, 1);
        lab.input(&bi, &mo, 0);
        let mut pm = PathMeld::default();
        pm.set_path(&[
            PcodeOpNode { op: bi.clone(), slot: 0 },
            PcodeOpNode { op: me.clone(), slot: 0 },
            PcodeOpNode { op: cp.clone(), slot: 0 },
        ]);
        let mut emul = EmulateFunction::new(&lab.fd);
        match emul.emulate_path(0x77, &pm, &cp, &v) {
            Ok(res) => {
                let _ = write!(s, "|d=ok:{}", hx(res));
            }
            Err(e) => {
                let _ = write!(s, "|d=err:{}", e.message());
            }
        }
    }
    // (e) MULTIEQUAL success: in-edge from lastOp's block exists (Z->M).
    {
        let z = lab.blk();
        let m = lab.blk();
        let w3 = lab.blk();
        lab.edge(&z, &m);
        lab.edge(&w3, &m);
        let v = lab.cnst(4, 0x88);
        let cp = lab.op(&z, OpCode::CPUI_COPY, 1);
        let w = lab.out(&cp, 4);
        lab.input(&cp, &v, 0);
        let me = lab.op(&m, OpCode::CPUI_MULTIEQUAL, 2);
        let mo = lab.out(&me, 4);
        lab.input(&me, &w, 0); // slot 0 = edge index of Z in M's in-list (0)
        let mw4 = lab.var(4);
        lab.input(&me, &mw4, 1);
        let bi = lab.op(&m, OpCode::CPUI_BRANCHIND, 1);
        lab.input(&bi, &mo, 0);
        let mut pm = PathMeld::default();
        pm.set_path(&[
            PcodeOpNode { op: bi.clone(), slot: 0 },
            PcodeOpNode { op: me.clone(), slot: 0 },
            PcodeOpNode { op: cp.clone(), slot: 0 },
        ]);
        let mut emul = EmulateFunction::new(&lab.fd);
        match emul.emulate_path(0x99, &pm, &cp, &v) {
            Ok(res) => {
                let _ = write!(s, "|e=ok:{}", hx(res));
            }
            Err(e) => {
                let _ = write!(s, "|e=err:{}", e.message());
            }
        }
    }
    s.push('\n');
    out.push_str(&s);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: jtpipeline_s1_1204_rust CURL_BINARY");
        std::process::exit(2);
    }
    let curl_bytes = match std::fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fixture error: cannot read {}: {}", args[1], e);
            std::process::exit(1);
        }
    };
    let mut lab = Lab::new(curl_bytes);
    let mut out = String::new();
    scenario_basic(&mut out, &mut lab);
    scenario_override(&mut out, &mut lab);
    scenario_basic2(&mut out, &mut lab);
    scenario_allfail(&mut out, &mut lab);
    scenario_load(&mut out, &mut lab, "emulfn_load_ok", 0x6100);
    scenario_load(&mut out, &mut lab, "emulfn_load_dataunavail", 0x9000000);
    scenario_channels(&mut out, &mut lab);
    // Module-level environment note (identical on both stacks): the fixture
    // hand-builds the stageJumpTable environment; production wiring is the
    // registered segment-2 residual.
    out.push_str(
        "pipeline_env_note|stageJumpTable=MISSING_segment2|\
raw_fd_recover=fail_closed_parent_contract|\
jumpassist_payload=NO_ORACLE\n",
    );
    print!("{}", out);
}
