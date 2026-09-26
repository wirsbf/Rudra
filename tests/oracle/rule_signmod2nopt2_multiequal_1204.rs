//! RULE-SIGNMOD2NOPT2-ME-0001: Rugra side of the locked 12.0.4 oracle
//! fixture for RuleSignMod2nOpt2::applyOp's MULTIEQUAL path —
//! `checkMultiequalForm` (ruleaction.cc:8941-8985) — the
//! `V = (V s< 0) ? V + 2^n-1 : V` adjusted-dividend recognition
//! (WORKPKG-UNMAP-RULEADJ-0013).
//!
//! Mirrors `rule_signmod2nopt2_multiequal_1204.cc` case-for-case (same
//! names, same observation format):
//!   case=<name>|me_apply=<0/1>
//!     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
//!     blk=<k>|in=<n>|out=<n>
//!   endcase
//!
//! The CFG is the oracle's compiled diamond: decision D branches to inner N
//! (INT_ADD block) and DIRECTLY to merge M; M's other in-edge must be D
//! itself (cc:8960-8972). In/out-edge ORDER comes from add_edge call order;
//! MULTIEQUAL input slot i corresponds to M's in-edge i. The negative
//! branch is D.out[1] (no flip) / D.out[0] (flip), per block.hh:299-300.

use std::sync::{Arc, RwLock};

use rugra::action::Rule;
use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::block::{BlockBasic, FlowBlock};
use rugra::funcdata::Funcdata;
use rugra::op::pcodeop_flags;
use rugra::opcodes::OpCode;
use rugra::ruleaction::RuleSignMod2nOpt2;
use rugra::varnode::Varnode;

type VnRef = Arc<RwLock<Varnode>>;
type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn vn_class(vn: Option<&VnRef>) -> char {
    match vn {
        None => '_',
        Some(v) => {
            let v = v.read().unwrap();
            if v.is_constant() {
                'c'
            } else if v.is_written() {
                'w'
            } else {
                'o'
            }
        }
    }
}

fn print_op_line(op: &rugra::op::PcodeOpRef) {
    let g = op.0.read().unwrap();
    let addr = g.get_addr().to_space_address().get_offset();
    let mut line = format!("  op={}@0x{:x}|nin={}", g.opcode as i32, addr, g.num_input());
    let sentinel = rugra::op::null_slot_sentinel();
    for i in 0..2 {
        let vn = g.get_in(i).filter(|v| !Arc::ptr_eq(*v, &sentinel));
        match vn {
            Some(v) => {
                let r = v.read().unwrap();
                line += &format!(
                    "|in{i}={}|{}|0x{:x}",
                    vn_class(Some(&v)),
                    r.get_size(),
                    r.get_offset()
                );
            }
            None => line += &format!("|in{i}=_|0|0x0"),
        }
    }
    let out_size = g
        .output
        .as_ref()
        .map(|v| v.read().unwrap().get_size() as i64)
        .unwrap_or(-1);
    line += &format!("|out={out_size}");
    println!("{line}");
}

fn dump_case_window(fd: &Funcdata, lo: u64, hi: u64) {
    for op in fd.begin_op_all() {
        let a = op.0.read().unwrap().get_addr().to_space_address().get_offset();
        if a < lo || hi < a {
            continue;
        }
        print_op_line(op);
    }
}

fn dump_blocks(blocks: &[BlockRef]) {
    for (k, bl) in blocks.iter().enumerate() {
        let g = bl.read().unwrap();
        println!("  blk={k}|in={}|out={}", g.size_in(), g.size_out());
    }
}

struct CaseSpec {
    name: &'static str,
    base: u64,
    edge_kind: char,
    slot: i32,          // MULTIEQUAL slot carrying addOut (-1 = 3-input case)
    flip: bool,
    add_const: u64,
    other_base: bool,
    sless_on_x2: bool,
    sless_const: u64,
    no_cbranch: bool,
    inner_extra_out: bool,
    no_diamond: bool,
}

fn mk_block(fd: &Funcdata, addr: u64) -> BlockRef {
    Arc::new(RwLock::new(BlockBasic::new(
        fd.bblocks.blocks.len() as i32,
        Address::new(addr),
    )))
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));

    let cases: Vec<CaseSpec> = vec![
        CaseSpec { name: "me_pos_slot0_noflip", base: 0x610000, edge_kind: 'a', slot: 0, flip: false, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_pos_slot1_noflip", base: 0x610100, edge_kind: 'b', slot: 1, flip: false, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_pos_flip", base: 0x610200, edge_kind: 'd', slot: 0, flip: true, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_lax_sless_in0", base: 0x610300, edge_kind: 'a', slot: 0, flip: false, add_const: 3, other_base: false, sless_on_x2: true, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_rej_addconst", base: 0x611000, edge_kind: 'a', slot: 0, flip: false, add_const: 5, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_rej_otherbase", base: 0x611100, edge_kind: 'a', slot: 0, flip: false, add_const: 3, other_base: true, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_rej_inner_extra", base: 0x611200, edge_kind: 'a', slot: 0, flip: false, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: true, no_diamond: false },
        CaseSpec { name: "me_rej_no_diamond", base: 0x611300, edge_kind: 'a', slot: 0, flip: false, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: true },
        CaseSpec { name: "me_rej_not_cbranch", base: 0x611400, edge_kind: 'a', slot: 0, flip: false, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: true, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_rej_sless_const", base: 0x611500, edge_kind: 'a', slot: 0, flip: false, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 1, no_cbranch: false, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_rej_negslot", base: 0x611600, edge_kind: 'a', slot: 0, flip: true, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: false },
        CaseSpec { name: "me_rej_3inputs", base: 0x611700, edge_kind: 'a', slot: -1, flip: false, add_const: 3, other_base: false, sless_on_x2: false, sless_const: 0, no_cbranch: false, inner_extra_out: false, no_diamond: false },
    ];

    for spec in cases {
        let b = spec.base;

        // Written non-const atoms: base and x2 (COPY writers in their own
        // throwaway blocks, mirroring the .cc fixture).
        let w1_block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            fd.bblocks.blocks.len() as i32,
            Address::new(b + 0x08),
        )));
        fd.bblocks.add_block(w1_block.clone());
        let w1 = fd.new_op(1, Address::new(b + 0x08));
        fd.op_set_opcode(&w1, OpCode::CPUI_COPY);
        let base_vn = fd.new_unique_out(8, &w1);
        let c1 = fd.new_constant(8, 0x1234);
        fd.op_set_input(&w1, c1, 0);
        fd.op_insert_end(&w1, &w1_block);

        let w2_block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            fd.bblocks.blocks.len() as i32,
            Address::new(b + 0x10),
        )));
        fd.bblocks.add_block(w2_block.clone());
        let w2 = fd.new_op(1, Address::new(b + 0x10));
        fd.op_set_opcode(&w2, OpCode::CPUI_COPY);
        let x2 = fd.new_unique_out(8, &w2);
        let c2 = fd.new_constant(8, 0x5678);
        fd.op_set_input(&w2, c2, 0);
        fd.op_insert_end(&w2, &w2_block);

        // Blocks: D (decision), N (inner/INT_ADD), M (merge).
        let d_blk = mk_block(&fd, b + 0x20);
        let n_blk = mk_block(&fd, b + 0x30);
        let m_blk = mk_block(&fd, b + 0x40);
        let mut blocks: Vec<BlockRef> = vec![d_blk.clone(), n_blk.clone(), m_blk.clone()];
        fd.bblocks.add_block(d_blk.clone());
        fd.bblocks.add_block(n_blk.clone());
        fd.bblocks.add_block(m_blk.clone());

        // D: sless + cbranch (+ optional dummy last op).
        let sless = fd.new_op(2, Address::new(b + 0x20));
        fd.op_set_opcode(&sless, OpCode::CPUI_INT_SLESS);
        let sless_out = fd.new_unique_out(1, &sless);
        fd.op_set_input(&sless, if spec.sless_on_x2 { x2.clone() } else { base_vn.clone() }, 0);
        let slc = fd.new_constant(8, spec.sless_const);
        fd.op_set_input(&sless, slc, 1);
        fd.op_insert_end(&sless, &d_blk);
        let cb = fd.new_op(2, Address::new(b + 0x28));
        fd.op_set_opcode(&cb, OpCode::CPUI_CBRANCH);
        let tgt = fd.new_constant(8, b + 0x80);
        fd.op_set_input(&cb, tgt, 0);
        fd.op_set_input(&cb, sless_out, 1);
        fd.op_insert_end(&cb, &d_blk);
        if spec.flip {
            // Funcdata::opFlipCondition (funcdata.hh:489).
            cb.0.write().unwrap().flags |= pcodeop_flags::BOOLEAN_FLIP;
        }
        if spec.no_cbranch {
            let dummy = fd.new_op(2, Address::new(b + 0x2c));
            fd.op_set_opcode(&dummy, OpCode::CPUI_INT_ADD);
            fd.new_unique_out(8, &dummy);
            fd.op_set_input(&dummy, base_vn.clone(), 0);
            let dc = fd.new_constant(8, 1);
            fd.op_set_input(&dummy, dc, 1);
            fd.op_insert_end(&dummy, &d_blk);
        }

        // N: add = INT_ADD(base, #add_const).
        let add = fd.new_op(2, Address::new(b + 0x30));
        fd.op_set_opcode(&add, OpCode::CPUI_INT_ADD);
        let add_out = fd.new_unique_out(8, &add);
        fd.op_set_input(&add, base_vn.clone(), 0);
        let ac = fd.new_constant(8, spec.add_const);
        fd.op_set_input(&add, ac, 1);
        fd.op_insert_end(&add, &n_blk);

        // M: MULTIEQUAL + and + mpy + root.
        let n_in = if spec.slot < 0 { 3 } else { 2 };
        let mult = fd.new_op(n_in, Address::new(b + 0x40));
        fd.op_set_opcode(&mult, OpCode::CPUI_MULTIEQUAL);
        let mult_out = fd.new_unique_out(8, &mult);
        if spec.slot < 0 {
            fd.op_set_input(&mult, add_out.clone(), 0);
            fd.op_set_input(&mult, base_vn.clone(), 1);
            fd.op_set_input(&mult, x2.clone(), 2);
        } else if spec.slot == 0 {
            fd.op_set_input(&mult, add_out.clone(), 0);
            fd.op_set_input(&mult, if spec.other_base { x2.clone() } else { base_vn.clone() }, 1);
        } else {
            fd.op_set_input(&mult, base_vn.clone(), 0);
            fd.op_set_input(&mult, add_out.clone(), 1);
        }
        fd.op_insert_end(&mult, &m_blk);
        let andop = fd.new_op(2, Address::new(b + 0x48));
        fd.op_set_opcode(&andop, OpCode::CPUI_INT_AND);
        let and_out = fd.new_unique_out(8, &andop);
        fd.op_set_input(&andop, mult_out, 0);
        let maskc = fd.new_constant(8, 0xfffffffffffffffc);
        fd.op_set_input(&andop, maskc, 1);
        fd.op_insert_end(&andop, &m_blk);
        let mpy = fd.new_op(2, Address::new(b + 0x50));
        fd.op_set_opcode(&mpy, OpCode::CPUI_INT_MULT);
        let mpy_out = fd.new_unique_out(8, &mpy);
        fd.op_set_input(&mpy, and_out, 0);
        let neg1 = fd.new_constant(8, 0xffffffffffffffff);
        fd.op_set_input(&mpy, neg1, 1);
        fd.op_insert_end(&mpy, &m_blk);
        let root = fd.new_op(2, Address::new(b + 0x58));
        fd.op_set_opcode(&root, OpCode::CPUI_INT_ADD);
        fd.new_unique_out(8, &root);
        fd.op_set_input(&root, mpy_out, 0);
        fd.op_set_input(&root, base_vn.clone(), 1);
        fd.op_insert_end(&root, &m_blk);

        // Edges (order is the semantics under test).
        let x_blk: Option<BlockRef> = if spec.inner_extra_out {
            let x = mk_block(&fd, b + 0x90);
            fd.bblocks.add_block(x.clone());
            blocks.push(x.clone());
            Some(x)
        } else {
            None
        };
        let e_blk: Option<BlockRef> = if spec.no_diamond {
            let e = mk_block(&fd, b + 0x98);
            fd.bblocks.add_block(e.clone());
            blocks.push(e.clone());
            Some(e)
        } else {
            None
        };
        match spec.edge_kind {
            'a' => {
                fd.bblocks.add_edge(n_blk.clone(), m_blk.clone());
                fd.bblocks.add_edge(
                    if spec.no_diamond { e_blk.clone().unwrap() } else { d_blk.clone() },
                    m_blk.clone(),
                );
                fd.bblocks.add_edge(d_blk.clone(), n_blk.clone());
            }
            'b' => {
                fd.bblocks.add_edge(d_blk.clone(), m_blk.clone());
                fd.bblocks.add_edge(n_blk.clone(), m_blk.clone());
                fd.bblocks.add_edge(d_blk.clone(), n_blk.clone());
            }
            'c' => {
                fd.bblocks.add_edge(d_blk.clone(), n_blk.clone());
                fd.bblocks.add_edge(d_blk.clone(), m_blk.clone());
                fd.bblocks.add_edge(n_blk.clone(), m_blk.clone());
            }
            _ => {
                fd.bblocks.add_edge(n_blk.clone(), m_blk.clone());
                fd.bblocks.add_edge(d_blk.clone(), n_blk.clone());
                fd.bblocks.add_edge(d_blk.clone(), m_blk.clone());
            }
        }
        if spec.inner_extra_out {
            fd.bblocks.add_edge(n_blk.clone(), x_blk.clone().unwrap());
        }

        let rule = RuleSignMod2nOpt2::new();
        let apply = rule.apply_op(&mpy.0, &mut fd).expect("signmod2n apply");
        println!("case={}|me_apply={apply}", spec.name);
        dump_case_window(&fd, b, b + 0x100);
        dump_blocks(&blocks);
        println!("endcase");
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode != "normal" {
        eprintln!("unknown mode: {mode}");
        std::process::exit(2);
    }
    run();
}
