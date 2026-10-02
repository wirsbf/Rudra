//! CONDEXE-TRUEOUT-0002 Rugra comparand — get_true_out/get_false_out purely
//! positional semantics and their condexe consumers, mirroring
//! tests/oracle/condexe_trueout_1204.cc case for case against the locked
//! Ghidra 12.0.4 oracle. Records: helper/helper_neg (H1-H4), findinit
//! (F1-F7), verify (V1-V4), zeropath (Z1-Z7).

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::condexe::{ConditionalExecution, RuleOrPredicate};
use rudra::funcdata::Funcdata;
use rudra::op::pcodeop_flags::BOOLEAN_FLIP;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

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

    fn make_cbranch(
        &mut self,
        fd: &mut Funcdata,
        blk: &BlockRef,
        boolvn: &Arc<RwLock<rudra::varnode::Varnode>>,
        flip: bool,
    ) -> PcodeOpRef {
        let op = fd.new_op(2, Address::new(self.next_pc));
        self.next_pc += 8;
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, 0x4000);
        fd.op_set_input(&op, target, 0);
        fd.op_set_input(&op, boolvn.clone(), 1);
        fd.op_insert_end(&op, blk);
        if flip {
            op.0.write().unwrap().flags ^= BOOLEAN_FLIP;
        }
        op
    }

    fn make_multiequal(&mut self, fd: &mut Funcdata, blk: &BlockRef) -> PcodeOpRef {
        let op = fd.new_op(2, Address::new(self.next_pc));
        self.next_pc += 8;
        fd.op_set_opcode(&op, OpCode::CPUI_MULTIEQUAL);
        fd.op_insert_end(&op, blk);
        op
    }

    fn make_bool_varnode(
        &self,
        fd: &mut Funcdata,
        offset: u64,
    ) -> Arc<RwLock<rudra::varnode::Varnode>> {
        fd.new_varnode(1, Address::new(offset))
    }

    fn name(&self, b: &Option<BlockRef>) -> String {
        match b {
            None => "-".to_string(),
            Some(b) => match self.blocks.iter().position(|x| Arc::ptr_eq(x, b)) {
                Some(i) => format!("b{i}"),
                None => "x".to_string(),
            },
        }
    }
}

fn toggle_flip(op: &PcodeOpRef) {
    op.0.write().unwrap().flags ^= BOOLEAN_FLIP;
}

fn is_flip(op: &PcodeOpRef) -> bool {
    op.0.read().unwrap().is_boolean_flip()
}

fn helper_record(
    kind: &str,
    case_id: &str,
    f: &Fixture,
    h: &BlockRef,
    t1: &BlockRef,
    t2: &BlockRef,
    cb: &PcodeOpRef,
) {
    let (true_out, false_out, out0, out1, rev0, rev1) = {
        let hg = h.read().unwrap();
        (
            hg.get_true_out(cb),
            hg.get_false_out(cb),
            hg.get_out(0).map(|e| e.point),
            hg.get_out(1).map(|e| e.point),
            hg.get_out(0).map(|e| e.reverse_index).unwrap_or(-1),
            hg.get_out(1).map(|e| e.reverse_index).unwrap_or(-1),
        )
    };
    let (t1_inrev, t2_inrev) = {
        let t1g = t1.read().unwrap();
        let t2g = t2.read().unwrap();
        (
            t1g.get_in(0).map(|e| e.reverse_index).unwrap_or(-1),
            t2g.get_in(0).map(|e| e.reverse_index).unwrap_or(-1),
        )
    };
    println!(
        "{kind}|case={case_id}|flip={}|true={}|false={}|out0={}|out1={}|rev0={rev0}|rev1={rev1}|t1_inrev={t1_inrev}|t2_inrev={t2_inrev}",
        u8::from(is_flip(cb)),
        f.name(&true_out),
        f.name(&false_out),
        f.name(&out0),
        f.name(&out1),
    );
}

fn run_helper(fd: &mut Funcdata) {
    let mut f = Fixture::new();
    let h = f.make_block(fd);
    let t1 = f.make_block(fd);
    let t2 = f.make_block(fd);
    let bv = f.make_bool_varnode(fd, 0x100);
    let cb = f.make_cbranch(fd, &h, &bv, false);
    f.edge(fd, &h, &t1);
    f.edge(fd, &h, &t2);
    helper_record("helper", "H1", &f, &h, &t1, &t2, &cb);
    toggle_flip(&cb);
    helper_record("helper", "H2", &f, &h, &t1, &t2, &cb);
    h.write().unwrap().negate_condition(true);
    helper_record("helper_neg", "H3", &f, &h, &t1, &t2, &cb);
    h.write().unwrap().negate_condition(true);
    helper_record("helper_neg", "H4", &f, &h, &t1, &t2, &cb);
}

#[derive(Clone, Copy)]
enum FindInitVariant {
    A2Prea,
    A2Preb,
    Slot1,
    Direct,
    Negative,
}

fn run_findinit_case(
    fd: &mut Funcdata,
    case_id: &str,
    variant: FindInitVariant,
    init_flip: bool,
    prea_inslot: i32,
) {
    let mut f = Fixture::new();
    let variant_name = match variant {
        FindInitVariant::A2Prea => "a2prea",
        FindInitVariant::A2Preb => "a2preb",
        FindInitVariant::Slot1 => "slot1",
        FindInitVariant::Direct => "direct",
        FindInitVariant::Negative => "negative",
    };
    let offset = match variant {
        FindInitVariant::A2Prea => 0x110,
        FindInitVariant::A2Preb => 0x120,
        FindInitVariant::Slot1 => 0x130,
        FindInitVariant::Direct => 0x140,
        FindInitVariant::Negative => 0x150,
    };
    let ib = match variant {
        FindInitVariant::A2Prea | FindInitVariant::A2Preb | FindInitVariant::Slot1 => {
            let init = f.make_block(fd);
            let prea = f.make_block(fd);
            let preb = f.make_block(fd);
            let ib = f.make_block(fd);
            let bv = f.make_bool_varnode(fd, offset);
            f.make_cbranch(fd, &init, &bv, init_flip);
            match variant {
                FindInitVariant::A2Prea | FindInitVariant::Slot1 => {
                    f.edge(fd, &init, &preb); // init out[0]
                    f.edge(fd, &init, &prea); // init out[1] -> prea chain
                }
                _ => {
                    f.edge(fd, &init, &prea); // init out[0]
                    f.edge(fd, &init, &preb); // init out[1] -> preb, NOT prea
                }
            }
            if matches!(variant, FindInitVariant::Slot1) {
                f.edge(fd, &preb, &ib); // ib in[0] is preb
                f.edge(fd, &prea, &ib); // ib in[1] is prea
            } else {
                f.edge(fd, &prea, &ib); // ib in[0]
                f.edge(fd, &preb, &ib); // ib in[1]
            }
            ib
        }
        FindInitVariant::Direct => {
            let init = f.make_block(fd);
            let ib = f.make_block(fd);
            let bv = f.make_bool_varnode(fd, offset);
            f.make_cbranch(fd, &init, &bv, init_flip);
            f.edge(fd, &init, &ib); // both out edges straight into ib
            f.edge(fd, &init, &ib);
            ib
        }
        FindInitVariant::Negative => {
            let a = f.make_block(fd);
            let b = f.make_block(fd);
            let c1 = f.make_block(fd);
            let c2 = f.make_block(fd);
            let ib = f.make_block(fd);
            let extra_a = f.make_block(fd);
            let extra_b = f.make_block(fd);
            // Distinct boolean varnodes: findInitPre never correlates them,
            // and a free (unwritten) varnode may not have two descendants.
            let bv1 = f.make_bool_varnode(fd, offset);
            let bv2 = f.make_bool_varnode(fd, offset + 8);
            f.make_cbranch(fd, &a, &bv1, init_flip);
            f.make_cbranch(fd, &b, &bv2, init_flip);
            f.edge(fd, &a, &c1);
            f.edge(fd, &a, &extra_a);
            f.edge(fd, &b, &c2);
            f.edge(fd, &b, &extra_b);
            f.edge(fd, &c1, &ib);
            f.edge(fd, &c2, &ib);
            ib
        }
    };
    let (ok, init2a) = {
        let mut ce = ConditionalExecution::new(fd);
        ce.fixture_find_init_pre(ib.clone(), prea_inslot)
    };
    // init2a_true is indeterminate in Ghidra when findInitPre fails (the ctor
    // leaves it unassigned; condexe.cc:72 runs only on the success path);
    // project it only when ok.
    if ok {
        println!(
            "findinit|case={case_id}|variant={variant_name}|init_flip={}|prea_inslot={prea_inslot}|ok=1|init2a_true={}",
            u8::from(init_flip),
            u8::from(init2a),
        );
    } else {
        println!(
            "findinit|case={case_id}|variant={variant_name}|init_flip={}|prea_inslot={prea_inslot}|ok=0",
            u8::from(init_flip),
        );
    }
}

fn run_verify(fd: &mut Funcdata) {
    let mut f = Fixture::new();
    // Writer block producing the shared boolean varnode (a WRITTEN varnode may
    // have multiple descendants; both CBRANCHes read it, giving the SAME
    // correlation in BooleanMatch::evaluate via pointer equality).
    let writer = f.make_block(fd);
    let init = f.make_block(fd);
    let prea = f.make_block(fd);
    let preb = f.make_block(fd);
    let ib = f.make_block(fd);
    let posta = f.make_block(fd);
    let postb = f.make_block(fd);
    let bv = {
        let wop = fd.new_op(1, Address::new(f.next_pc));
        f.next_pc += 8;
        fd.op_set_opcode(&wop, OpCode::CPUI_COPY);
        let one = fd.new_constant(1, 1);
        fd.op_set_input(&wop, one, 0);
        let bv = fd.new_unique_out(1, &wop);
        fd.op_insert_end(&wop, &writer);
        bv
    };
    let init_cb = f.make_cbranch(fd, &init, &bv, false);
    let ib_cb = f.make_cbranch(fd, &ib, &bv, false);
    f.edge(fd, &init, &preb); // init out[0] -> preb (true edge goes to prea)
    f.edge(fd, &init, &prea); // init out[1] -> prea; raw init2a_true = true
    f.edge(fd, &prea, &ib); // ib in[0] = prea (verify forces prea_inslot=0)
    f.edge(fd, &preb, &ib); // ib in[1] = preb
    f.edge(fd, &ib, &posta); // ib out[0] -> posta; iblock2posta_true = false
    f.edge(fd, &ib, &postb); // ib out[1] -> postb
    let ib_flips = [false, false, true, true];
    let init_flips = [false, true, false, true];
    for i in 0..4 {
        if ib_flips[i] {
            toggle_flip(&ib_cb);
        }
        if init_flips[i] {
            toggle_flip(&init_cb);
        }
        let (ok, init2a, camp, posta_blk, postb_blk) = {
            let mut ce = ConditionalExecution::new(fd);
            ce.fixture_verify(ib.clone(), ib_cb.clone())
        };
        println!(
            "verify|case=V{}|ib_flip={}|init_flip={}|ok={}|init2a_true={}|camethruposta_slot={camp}|posta={}|postb={}",
            i + 1,
            u8::from(ib_flips[i]),
            u8::from(init_flips[i]),
            u8::from(ok),
            u8::from(init2a),
            f.name(&posta_blk),
            f.name(&postb_blk),
        );
        if ib_flips[i] {
            toggle_flip(&ib_cb);
        }
        if init_flips[i] {
            toggle_flip(&init_cb);
        }
    }
}

fn run_zero_path(fd: &mut Funcdata) {
    let mut f = Fixture::new();
    let cond = f.make_block(fd);
    let z1 = f.make_block(fd);
    let z2 = f.make_block(fd);
    let bv = f.make_bool_varnode(fd, 0x170);
    let cb = f.make_cbranch(fd, &cond, &bv, false);
    let mq1 = f.make_multiequal(fd, &z1);
    let mq2 = f.make_multiequal(fd, &z2);
    f.edge(fd, &cond, &z1); // cond out[0] (false out)
    f.edge(fd, &cond, &z2); // cond out[1] (true out)
    struct ZCase<'a> {
        case_id: &'a str,
        zero_block: &'a BlockRef,
        op: &'a PcodeOpRef,
        flip: bool,
    }
    let cases = [
        ZCase { case_id: "Z1", zero_block: &z2, op: &mq2, flip: false },
        ZCase { case_id: "Z2", zero_block: &z2, op: &mq2, flip: true },
        ZCase { case_id: "Z3", zero_block: &z1, op: &mq2, flip: false },
        ZCase { case_id: "Z4", zero_block: &z1, op: &mq2, flip: true },
        ZCase { case_id: "Z5", zero_block: &cond, op: &mq2, flip: false },
        ZCase { case_id: "Z6", zero_block: &cond, op: &mq2, flip: true },
        ZCase { case_id: "Z7", zero_block: &cond, op: &mq1, flip: false },
    ];
    for case in &cases {
        if case.flip {
            toggle_flip(&cb);
        }
        let zero_path_is_true = RuleOrPredicate::fixture_discover_path_is_true(
            cond.clone(),
            case.zero_block.clone(),
            case.op.clone(),
            cb.clone(),
        );
        println!(
            "zeropath|case={}|flip={}|zero_path_is_true={}",
            case.case_id,
            u8::from(case.flip),
            u8::from(zero_path_is_true),
        );
        if case.flip {
            toggle_flip(&cb);
        }
    }
}

fn main() {
    let mut fd = Funcdata::new("condexe_trueout", Address::new(0x60000), 0x100);
    run_helper(&mut fd);
    run_findinit_case(&mut fd, "F1", FindInitVariant::A2Prea, false, 0);
    run_findinit_case(&mut fd, "F2", FindInitVariant::A2Prea, true, 0);
    run_findinit_case(&mut fd, "F3", FindInitVariant::A2Preb, false, 0);
    run_findinit_case(&mut fd, "F4", FindInitVariant::A2Preb, true, 0);
    run_findinit_case(&mut fd, "F5", FindInitVariant::Slot1, false, 1);
    run_findinit_case(&mut fd, "F6", FindInitVariant::Direct, false, 0);
    run_findinit_case(&mut fd, "F7", FindInitVariant::Negative, false, 0);
    run_verify(&mut fd);
    run_zero_path(&mut fd);
}
