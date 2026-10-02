// NODEJOIN-F2/F3/F4/F5: Rugra comparand for the locked Ghidra 12.0.4
// ConditionalJoin behavior oracle (blockaction.cc:1912-2102, 2326-2364).
// Mirrors tests/oracle/nodejoin_condjoin_1204.cc case for case: drives
// ActionNodeJoin::apply over the same synthetic diamond CFGs and prints the
// identical structural projection (count, reordered block list, in/out
// neighbor indices, per-block ops with structural varnode descriptors).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::action::Action;
use rudra::coreaction::ActionNodeJoin;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<RwLock<Varnode>>;

// Ghidra get_opname table entries used by this fixture (opcodes.cc:45+);
// MULTIEQUAL prints as "BUILD".
fn op_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_COPY => "COPY",
        OpCode::CPUI_CBRANCH => "CBRANCH",
        OpCode::CPUI_INT_LESS => "INT_LESS",
        OpCode::CPUI_INT_ADD => "INT_ADD",
        OpCode::CPUI_INT_NEGATE => "INT_NEGATE",
        OpCode::CPUI_SUBPIECE => "SUBPIECE",
        OpCode::CPUI_MULTIEQUAL => "BUILD",
        _ => "OTHER",
    }
}

struct Fixture {
    fd: Funcdata,
    labels: HashMap<usize, String>, // Varnode Arc ptr -> label
    next_index: i32,
}

impl Fixture {
    // RUGRA-GLUE: fixture block mirror of BlockGraph::newBlockBasic + attach
    fn mk_block(&mut self, off: u64) -> BlockRef {
        let b = Arc::new(RwLock::new(BlockBasic::new(
            self.next_index,
            Address::new(off),
        )));
        self.next_index += 1;
        self.fd.bblocks.add_block(b.clone());
        b
    }
    fn mk_const(&mut self, val: u64) -> VnRef {
        self.fd.new_constant(8, val)
    }
    // RUGRA-GLUE: fixture mirror of Funcdata::newOp/opSetOpcode/newUniqueOut/
    // opSetInput/opInsertEnd (identical call order to the C++ driver)
    fn mk_written(
        &mut self,
        label: &str,
        opcode: OpCode,
        ins: Vec<VnRef>,
        blk: &BlockRef,
        opoff: u64,
    ) -> VnRef {
        let op = self.fd.new_op(ins.len(), Address::new(opoff));
        self.fd.op_set_opcode(&op, opcode);
        let out = self.fd.new_unique_out(8, &op);
        for (i, vn) in ins.into_iter().enumerate() {
            self.fd.op_set_input(&op, vn, i);
        }
        self.fd.op_insert_end(&op, blk);
        self.labels.insert(Arc::as_ptr(&out) as usize, label.to_string());
        out
    }
    fn mk_cbranch(&mut self, blk: &BlockRef, cond: VnRef, opoff: u64, flip: bool) {
        let cb = self.fd.new_op(2, Address::new(opoff));
        self.fd.op_set_opcode(&cb, OpCode::CPUI_CBRANCH);
        let target = self.mk_const(0x3000);
        self.fd.op_set_input(&cb, target, 0);
        self.fd.op_set_input(&cb, cond, 1);
        if flip {
            cb.0.write().unwrap().flags |= rudra::op::pcodeop_flags::BOOLEAN_FLIP;
        }
        self.fd.op_insert_end(&cb, blk);
    }
    fn vdesc(&self, vn: &VnRef) -> String {
        if let Some(label) = self.labels.get(&(Arc::as_ptr(vn) as usize)) {
            return label.clone();
        }
        let (is_constant, off, size) = {
            let v = vn.read().unwrap();
            (v.is_constant(), v.get_offset(), v.get_size())
        };
        if is_constant {
            return format!("const:0x{:x}:{}", off, size);
        }
        let def = vn.read().unwrap().get_def();
        if let Some(def) = def {
            let parent = def
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            if let Some(parent) = parent {
                let mut bpos = -1i64;
                for i in 0..self.fd.bblocks.get_size() {
                    if let Some(b) = self.fd.bblocks.get_block(i) {
                        if Arc::ptr_eq(&b, &parent) {
                            bpos = i as i64;
                            break;
                        }
                    }
                }
                let mut opos = -1i64;
                for (pos, o) in parent.read().unwrap().get_ops().iter().enumerate() {
                    if Arc::ptr_eq(&o.0, &def) {
                        opos = pos as i64;
                        break;
                    }
                }
                return format!("def:B{}:{}", bpos, opos);
            }
            return "def:dead".to_string();
        }
        format!("vn:0x{:x}:{}", off, size)
    }
    fn print(&self, name: &str, count: i32) {
        let mut out = String::new();
        out.push_str(&format!("== case {}\n", name));
        out.push_str(&format!("count={}\n", count));
        out.push_str(&format!("blocks={}\n", self.fd.bblocks.get_size()));
        for i in 0..self.fd.bblocks.get_size() {
            let bl = self.fd.bblocks.get_block(i).expect("block");
            let rg = bl.read().unwrap();
            out.push_str(&format!("block {}:", i));
            out.push_str(" in=[");
            for e in 0..rg.size_in() {
                if e > 0 {
                    out.push(',');
                }
                if let Some(edge) = rg.get_in(e) {
                    let target = edge.point.clone();
                    let mut npos = -1i64;
                    for j in 0..self.fd.bblocks.get_size() {
                        if let Some(b) = self.fd.bblocks.get_block(j) {
                            if Arc::ptr_eq(&b, &target) {
                                npos = j as i64;
                                break;
                            }
                        }
                    }
                    out.push_str(&npos.to_string());
                }
            }
            out.push_str("] out=[");
            for e in 0..rg.size_out() {
                if e > 0 {
                    out.push(',');
                }
                if let Some(edge) = rg.get_out(e) {
                    // Positional neighbor identity (FlowBlock::index is only
                    // assigned by a spanning-tree pass on the Ghidra side).
                    let target = edge.point.clone();
                    let mut npos = -1i64;
                    for j in 0..self.fd.bblocks.get_size() {
                        if let Some(b) = self.fd.bblocks.get_block(j) {
                            if Arc::ptr_eq(&b, &target) {
                                npos = j as i64;
                                break;
                            }
                        }
                    }
                    out.push_str(&npos.to_string());
                }
            }
            out.push_str("] ops=[");
            for (pos, op) in rg.get_ops().iter().enumerate() {
                if pos > 0 {
                    out.push(';');
                }
                let o = op.0.read().unwrap();
                out.push_str(&format!("{}(", op_name(o.opcode)));
                for s in 0..o.num_input() {
                    if s > 0 {
                        out.push(',');
                    }
                    if let Some(vn) = o.get_in(s) {
                        out.push_str(&self.vdesc(vn));
                    }
                }
                out.push(')');
                if let Some(outvn) = &o.output {
                    out.push_str(&format!("->{}", self.vdesc(outvn)));
                }
            }
            out.push_str("]\n");
        }
        print!("{}", out);
    }
}

// Per-side def specification for diamond() (mirror of the C++ DefSpec).
struct DefSpec {
    present: bool,
    opc: OpCode,
    ins: Vec<VnRef>,
    outlabel: &'static str,
}
fn nodef() -> DefSpec {
    DefSpec {
        present: false,
        opc: OpCode::CPUI_COPY,
        ins: vec![],
        outlabel: "",
    }
}
fn def(opc: OpCode, ins: Vec<VnRef>, label: &'static str) -> DefSpec {
    DefSpec {
        present: true,
        opc,
        ins,
        outlabel: label,
    }
}

impl Fixture {
    // Mirror of the C++ Fixture::diamond: b1=[def1?,cbranch], b2=[def2?,
    // cbranch], exita=[MULTIEQUAL(v1,v2)?, INT_ADD stop?], exitb=[].
    fn diamond(
        &mut self,
        d1: DefSpec,
        cond1: Option<VnRef>,
        flip1: bool,
        d2: DefSpec,
        cond2: Option<VnRef>,
        flip2: bool,
        vdef1: DefSpec,
        vdef2: DefSpec,
    ) {
        let b1 = self.mk_block(0x1000);
        let b2 = self.mk_block(0x2000);
        let exita = self.mk_block(0x3000);
        let exitb = self.mk_block(0x4000);
        let mut cond1 = cond1;
        let mut cond2 = cond2;
        if d1.present {
            let out = self.mk_written(d1.outlabel, d1.opc, d1.ins, &b1, 0x1100);
            if cond1.is_none() {
                cond1 = Some(out);
            }
        }
        if d2.present {
            let out = self.mk_written(d2.outlabel, d2.opc, d2.ins, &b2, 0x2100);
            if cond2.is_none() {
                cond2 = Some(out);
            }
        }
        let mut v1: Option<VnRef> = None;
        let mut v2: Option<VnRef> = None;
        if vdef1.present {
            v1 = Some(self.mk_written(vdef1.outlabel, vdef1.opc, vdef1.ins, &b1, 0x1110));
        }
        if vdef2.present {
            v2 = Some(self.mk_written(vdef2.outlabel, vdef2.opc, vdef2.ins, &b2, 0x2110));
        }
        self.mk_cbranch(&b1, cond1.expect("cond1"), 0x1010, flip1);
        self.mk_cbranch(&b2, cond2.expect("cond2"), 0x2010, flip2);
        if let (Some(v1), Some(v2)) = (v1, v2) {
            let me = self.fd.new_op(2, Address::new(0x3010));
            self.fd.op_set_opcode(&me, OpCode::CPUI_MULTIEQUAL);
            self.fd.op_set_input(&me, v1, 0);
            self.fd.op_set_input(&me, v2, 1);
            self.fd.op_insert_end(&me, &exita);
            let stop = self.fd.new_op(2, Address::new(0x3020));
            self.fd.op_set_opcode(&stop, OpCode::CPUI_INT_ADD);
            let c1 = self.mk_const(1);
            let c2 = self.mk_const(2);
            self.fd.op_set_input(&stop, c1, 0);
            self.fd.op_set_input(&stop, c2, 1);
            self.fd.op_insert_end(&stop, &exita);
        }
        self.fd.bblocks.add_edge(b1.clone(), exita.clone());
        self.fd.bblocks.add_edge(b1, exitb.clone());
        self.fd.bblocks.add_edge(b2.clone(), exita);
        self.fd.bblocks.add_edge(b2, exitb);
    }
}

fn run_case(name: &str) {
    let mut fx = Fixture {
        fd: Funcdata::new(name, Address::new(0x5000), 0x40),
        labels: HashMap::new(),
        next_index: 1,
    };
    match name {
        "A_samecond" => {
            let pre = fx.mk_block(0x0800);
            let k1 = fx.mk_const(1);
            let k2 = fx.mk_const(2);
            let cond = fx.mk_written("cond", OpCode::CPUI_INT_LESS, vec![k1, k2], &pre, 0x0810);
            fx.diamond(nodef(), Some(cond.clone()), false, nodef(), Some(cond), false, nodef(), nodef());
        }
        "B_mergeable" => {
            let k1 = fx.mk_const(1);
            let k2 = fx.mk_const(2);
            let c7 = fx.mk_const(7);
            let c8 = fx.mk_const(8);
            fx.diamond(
                def(OpCode::CPUI_INT_LESS, vec![k1.clone(), k2.clone()], "cond1"),
                None,
                false,
                def(OpCode::CPUI_INT_LESS, vec![k1, k2], "cond2"),
                None,
                false,
                def(OpCode::CPUI_COPY, vec![c7], "v1"),
                def(OpCode::CPUI_COPY, vec![c8], "v2"),
            );
        }
        "C_flip" => {
            // Mirror of the C++ shape: the two defs live in their own
            // isolated blocks created BEFORE the diamond blocks.
            let b1v = fx.mk_block(0x1000);
            let b2v = fx.mk_block(0x2000);
            let k1 = fx.mk_const(1);
            let k2 = fx.mk_const(2);
            let cond1 = fx.mk_written("cond1", OpCode::CPUI_INT_LESS, vec![k1.clone(), k2.clone()], &b1v, 0x1100);
            let cond2 = fx.mk_written("cond2", OpCode::CPUI_INT_LESS, vec![k1, k2], &b2v, 0x2100);
            fx.diamond(nodef(), Some(cond1), true, nodef(), Some(cond2), false, nodef(), nodef());
        }
        "D_unwritten" => {
            let c1 = fx.mk_const(11);
            let c2 = fx.mk_const(22);
            fx.diamond(nodef(), Some(c1), false, nodef(), Some(c2), false, nodef(), nodef());
        }
        "E_spacebase" => {
            // Mirror of the C++ shape: defs in isolated blocks; cond1 gets
            // the spacebase flag (Varnode::setFlags spacebase).
            let b1v = fx.mk_block(0x1000);
            let b2v = fx.mk_block(0x2000);
            let k1 = fx.mk_const(1);
            let k2 = fx.mk_const(2);
            let cond1 = fx.mk_written("cond1", OpCode::CPUI_INT_LESS, vec![k1.clone(), k2.clone()], &b1v, 0x1100);
            cond1
                .write()
                .unwrap()
                .set_flags(rudra::varnode::varnode_flags::SPACEBASE);
            let cond2 = fx.mk_written("cond2", OpCode::CPUI_INT_LESS, vec![k1, k2], &b2v, 0x2100);
            fx.diamond(nodef(), Some(cond1), false, nodef(), Some(cond2), false, nodef(), nodef());
        }
        "F_fel2" => {
            let pre = fx.mk_block(0x0800);
            let c1 = fx.mk_const(1);
            let r1 = fx.mk_written(
                "r1",
                OpCode::CPUI_INT_NEGATE,
                vec![c1],
                &pre,
                0x0810,
            );
            let c2 = fx.mk_const(2);
            let r2 = fx.mk_written(
                "r2",
                OpCode::CPUI_INT_NEGATE,
                vec![c2],
                &pre,
                0x0820,
            );
            let c3 = fx.mk_const(3);
            let r3 = fx.mk_written(
                "r3",
                OpCode::CPUI_INT_NEGATE,
                vec![c3],
                &pre,
                0x0830,
            );
            let c4 = fx.mk_const(4);
            let r4 = fx.mk_written(
                "r4",
                OpCode::CPUI_INT_NEGATE,
                vec![c4],
                &pre,
                0x0840,
            );
            fx.diamond(
                def(OpCode::CPUI_INT_ADD, vec![r1, r2], "cond1"),
                None,
                false,
                def(OpCode::CPUI_INT_ADD, vec![r3, r4], "cond2"),
                None,
                false,
                nodef(),
                nodef(),
            );
        }
        "G_subpiece" | "H_copy" => {
            let x = fx.mk_const(5);
            let opc = if name == "G_subpiece" {
                OpCode::CPUI_SUBPIECE
            } else {
                OpCode::CPUI_COPY
            };
            let mut ins = vec![x.clone()];
            let mut ins2 = vec![x];
            if opc == OpCode::CPUI_SUBPIECE {
                ins.push(fx.mk_const(0));
                ins2.push(fx.mk_const(0));
            }
            fx.diamond(
                def(opc, ins, "cond1"),
                None,
                false,
                def(opc, ins2, "cond2"),
                None,
                false,
                nodef(),
                nodef(),
            );
        }
        "I_triple" => {
            let pre = fx.mk_block(0x0800);
            let k1 = fx.mk_const(1);
            let k2 = fx.mk_const(2);
            let cond = fx.mk_written("cond", OpCode::CPUI_INT_LESS, vec![k1, k2], &pre, 0x0810);
            let b1 = fx.mk_block(0x1000);
            let b2 = fx.mk_block(0x2000);
            let b3 = fx.mk_block(0x2800);
            let exita = fx.mk_block(0x3000);
            let exitb = fx.mk_block(0x4000);
            fx.mk_cbranch(&b1, cond.clone(), 0x1010, false);
            fx.mk_cbranch(&b2, cond.clone(), 0x2010, false);
            fx.mk_cbranch(&b3, cond, 0x2810, false);
            fx.fd.bblocks.add_edge(b1.clone(), exita.clone());
            fx.fd.bblocks.add_edge(b1, exitb.clone());
            fx.fd.bblocks.add_edge(b2.clone(), exita.clone());
            fx.fd.bblocks.add_edge(b2, exitb.clone());
            fx.fd.bblocks.add_edge(b3.clone(), exita);
            fx.fd.bblocks.add_edge(b3, exitb);
        }
        _ => {
            eprintln!("unknown case {}", name);
            return;
        }
    }

    let mut ajoin = ActionNodeJoin::new();
    let _ = ajoin.apply(&mut fx.fd).expect("apply");
    fx.print(name, ajoin.count);
}

fn main() {
    let cases: Vec<String> = std::env::args().skip(1).collect();
    let cases: Vec<String> = if cases.is_empty() {
        [
            "A_samecond",
            "B_mergeable",
            "C_flip",
            "D_unwritten",
            "E_spacebase",
            "F_fel2",
            "G_subpiece",
            "H_copy",
            "I_triple",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    } else {
        cases
    };
    for c in cases {
        run_case(&c);
    }
}
