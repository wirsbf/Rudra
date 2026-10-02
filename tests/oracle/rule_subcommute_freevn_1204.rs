//! RULE-SUBCOMMUTE-FREEVN-0001: Rudra side of the locked 12.0.4 oracle
//! fixture for the RuleSubCommute generic tail commute loop
//! (ruleaction.cc:4631-4652) on free-varnode and constant inputs
//! (BINSWEEP-SUBCOMMUTE-FREEVARNODE-0001, CR-SUBCOMMUTE finding 3).
//!
//! Mirrors `rule_subcommute_freevn_1204.cc` case-for-case (same names,
//! same observation format):
//!   case=<name>|sub_apply=<0/1>
//!     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<in0_size>|0x<in0_off>|out=<n>
//!     keep=<c0|c1|f0|f1|w0|w1>|readers=<n>|descends=<n>
//!   endcase
//!
//! The opSetInput order under test: cc:4640 frees vn from longform slot i
//! (opSetInput(longform,newVn,i)) BEFORE cc:4641 attaches vn to newsub
//! (opSetInput(newsub,vn,0) — "vn may be free, so set as input after
//! setting newVn"), so a free varnode never gains a second descendant
//! (varnode.cc:330-340) and a constant keeps its identity instead of
//! taking the Funcdata::opSetInput dedup copy (funcdata_op.cc:108-115).
//!
//! Modes: `normal` (golden diff), `trap_dupfree` (same free varnode in
//! both XOR slots: both sides must crash with "Free varnode has multiple
//! descendants" — oracle LowlevelError rc=1 vs Rust panic rc=101 at
//! varnode.rs:2716; form comparison only, no golden).

use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::ruleaction::RuleSubCommute;
use rudra::varnode::Varnode;

type VnRef = Arc<RwLock<Varnode>>;

fn constant_input(fd: &mut Funcdata, value: u64, size: usize) -> VnRef {
    fd.new_constant(size, value)
}

fn print_op_line(op: &rudra::op::PcodeOpRef) {
    let g = op.0.read().unwrap();
    let addr = g.get_addr().to_space_address().get_offset();
    let mut line = format!("  op={}@0x{:x}|nin={}", g.opcode as i32, addr, g.num_input());
    // Ghidra's destroyed/mislinked slots read as null (op.cc:98 clearInput);
    // Rudra's shared null_slot_sentinel is the same observable — render as `_`.
    let in0 = g.get_in(0).filter(|v| {
        !std::sync::Arc::ptr_eq(*v, &rudra::op::null_slot_sentinel())
    });
    if let Some(in0) = in0 {
        let i = in0.read().unwrap();
        let cls = if i.is_constant() {
            'c'
        } else if i.is_written() {
            'w'
        } else {
            'o'
        };
        line += &format!("|in0={cls}|{}|0x{:x}", i.get_size(), i.get_offset());
    } else {
        line += "|in0=_|0|0x0";
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

fn dump_keep_lines(
    fd: &Funcdata,
    keeps: &[VnRef],
    tags: &[String],
    lo: u64,
    hi: u64,
) {
    for (k, vn) in keeps.iter().enumerate() {
        let mut readers = 0;
        for op in fd.begin_op_all() {
            let g = op.0.read().unwrap();
            let a = g.get_addr().to_space_address().get_offset();
            if a < lo || hi < a {
                continue;
            }
            if g.opcode != OpCode::CPUI_SUBPIECE {
                continue;
            }
            if let Some(in0) = g.get_in(0) {
                if std::sync::Arc::ptr_eq(&in0, vn) {
                    readers += 1;
                }
            }
        }
        let descends = vn.read().unwrap().count_descends();
        println!("  keep={}|readers={readers}|descends={descends}", tags[k]);
    }
}

// ---- case builder (mirrors the .cc builder 1:1) ----------------------------

// slotKind per longform slot: 0=free (COPY writer, unset after wiring),
// 1=constant, 4=written (COPY writer kept alive), 3=same vn as slot 0
// freed afterwards (trap_dupfree only), 5=same vn as slot 0 kept written
// (dup-reuse leg). extra_kind: 0=none, 1=ZEXT overlap reader on outvn
// (cc:4623-4628 reject), 2=second SUBPIECE reader on base (cc:4621 reject).
struct CaseBuilt {
    sub_op: rudra::op::PcodeOpRef,
    keeps: Vec<VnRef>,
    tags: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn tail_commute_case(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opc: OpCode,
    base: u64,
    slot_kind: [i32; 2],
    slot_val: [u64; 2],
    long_size: usize,
    out_size: usize,
    offset: u64,
    extra_kind: i32,
) -> CaseBuilt {
    let nin = if opc == OpCode::CPUI_INT_NEGATE { 1 } else { 2 };
    let mut ins: Vec<Option<VnRef>> = vec![None, None];
    let mut writers: Vec<Option<rudra::op::PcodeOpRef>> = vec![None, None];
    for slot in 0..nin {
        if slot_kind[slot] == 3 || slot_kind[slot] == 5 {
            ins[slot] = ins[0].clone();
            continue;
        }
        if slot_kind[slot] == 1 {
            ins[slot] = Some(constant_input(fd, slot_val[slot], long_size));
            continue;
        }
        let writer = fd.new_op(1, Address::new(base + 0x10 + 0x8 * slot as u64));
        fd.op_set_opcode(&writer, OpCode::CPUI_COPY);
        let fv = fd.new_unique_out(long_size, &writer);
        let c_arg = constant_input(fd, slot_val[slot], long_size);
        fd.op_set_input(&writer, c_arg, 0);
        fd.op_insert_end(&writer, block);
        writers[slot] = Some(writer);
        ins[slot] = Some(fv);
    }
    let longform = fd.new_op(nin, Address::new(base + 0x30));
    fd.op_set_opcode(&longform, opc);
    fd.new_unique_out(long_size, &longform);
    fd.op_set_input(&longform, ins[0].clone().unwrap(), 0);
    if nin > 1 {
        fd.op_set_input(&longform, ins[1].clone().unwrap(), 1);
    }
    fd.op_insert_end(&longform, block);
    let sub_op = fd.new_op(2, Address::new(base + 0x40));
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    fd.new_unique_out(out_size, &sub_op);
    let addout = longform.0.read().unwrap().output.as_ref().unwrap().clone();
    fd.op_set_input(&sub_op, addout, 0);
    let off_const = constant_input(fd, offset, 4);
    fd.op_set_input(&sub_op, off_const, 1);
    fd.op_insert_end(&sub_op, block);
    // Free the COPY outputs: fv keeps descend=[longform(,longform)] but
    // loses WRITTEN — the exact free-varnode state the ip corpus hit.
    for slot in 0..nin {
        if slot_kind[slot] == 0 {
            fd.op_unset_output(&writers[slot].clone().unwrap());
        }
    }
    if extra_kind == 1 {
        // outvn->loneDescend() is a ZEXT back to insize: cc:4626-4627 reject.
        let zx = fd.new_op(1, Address::new(base + 0x50));
        fd.op_set_opcode(&zx, OpCode::CPUI_INT_ZEXT);
        fd.new_unique_out(long_size, &zx);
        let subout = sub_op.0.read().unwrap().output.as_ref().unwrap().clone();
        fd.op_set_input(&zx, subout, 0);
        fd.op_insert_end(&zx, block);
    } else if extra_kind == 2 {
        // A second SUBPIECE reads base: base->loneDescend() != op reject.
        let sub2 = fd.new_op(2, Address::new(base + 0x50));
        fd.op_set_opcode(&sub2, OpCode::CPUI_SUBPIECE);
        fd.new_unique_out(out_size, &sub2);
        let addout = longform.0.read().unwrap().output.as_ref().unwrap().clone();
        fd.op_set_input(&sub2, addout, 0);
        let off_const = constant_input(fd, offset, 4);
        fd.op_set_input(&sub2, off_const, 1);
        fd.op_insert_end(&sub2, block);
    }
    let mut keeps = Vec::new();
    let mut tags = Vec::new();
    for slot in 0..nin {
        keeps.push(ins[slot].clone().unwrap());
        let ch = match slot_kind[slot] {
            1 => 'c',
            4 | 5 => 'w',
            _ => 'f',
        };
        tags.push(format!("{ch}{slot}"));
    }
    CaseBuilt { sub_op, keeps, tags }
}

struct CaseSpec {
    name: &'static str,
    base: u64,
    opc: i32, // 0 ADD, 1 MULT, 2 AND, 3 OR, 4 XOR, 5 NEGATE
    slot_kind: [i32; 2],
    slot_val: [u64; 2],
    long_size: usize,
    out_size: usize,
    offset: u64,
    extra_kind: i32,
}

fn opc_of(spec: &CaseSpec) -> OpCode {
    match spec.opc {
        0 => OpCode::CPUI_INT_ADD,
        1 => OpCode::CPUI_INT_MULT,
        2 => OpCode::CPUI_INT_AND,
        3 => OpCode::CPUI_INT_OR,
        4 => OpCode::CPUI_INT_XOR,
        _ => OpCode::CPUI_INT_NEGATE,
    }
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(block.clone());

    let cases: Vec<CaseSpec> = vec![
        // The ip-corpus panic form: both longform inputs free varnodes.
        CaseSpec { name: "add_free_free", base: 0x510000, opc: 0, slot_kind: [0, 0], slot_val: [0x11, 0x22], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 },
        // Const tail inputs: identity must survive (no opSetInput dedup copy
        // once cc:4640 frees the slot first).
        CaseSpec { name: "add_free_const", base: 0x510100, opc: 0, slot_kind: [0, 1], slot_val: [0x11, 0x64], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 },
        CaseSpec { name: "add_const_free", base: 0x510200, opc: 0, slot_kind: [1, 0], slot_val: [0x64, 0x22], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 },
        CaseSpec { name: "add_const_const", base: 0x510300, opc: 0, slot_kind: [1, 1], slot_val: [0x64, 0xc8], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 },
        // Other commuting opcodes with free tails.
        CaseSpec { name: "mult_free_free", base: 0x510400, opc: 1, slot_kind: [0, 0], slot_val: [7, 6], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 },
        CaseSpec { name: "and_free_free", base: 0x510500, opc: 2, slot_kind: [0, 0], slot_val: [0xf0, 0x0f], long_size: 8, out_size: 2, offset: 0, extra_kind: 0 },
        CaseSpec { name: "or_free16", base: 0x510600, opc: 3, slot_kind: [0, 0], slot_val: [0xa1, 0xb2], long_size: 16, out_size: 8, offset: 0, extra_kind: 0 },
        // Single-input arm.
        CaseSpec { name: "negate_free", base: 0x510700, opc: 5, slot_kind: [0, 0], slot_val: [0x33, 0], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 },
        // Bitwise commutes at a non-zero subpiece offset.
        CaseSpec { name: "xor_free_off4", base: 0x510800, opc: 4, slot_kind: [0, 0], slot_val: [0x44, 0x55], long_size: 8, out_size: 4, offset: 4, extra_kind: 0 },
        CaseSpec { name: "mult_free_const", base: 0x510900, opc: 1, slot_kind: [0, 1], slot_val: [9, 3], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 },
        // dup-reuse leg: the SAME written vn feeds both slots — only one
        // new SUBPIECE is created (cc:4636 guard, cc:4646 reuse).
        CaseSpec { name: "xor_same_written", base: 0x510a00, opc: 4, slot_kind: [4, 5], slot_val: [0x66, 0x66], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 },
        // cc:4623-4628 reject: outvn feeds a ZEXT back to insize.
        CaseSpec { name: "add_free_zext_overlap", base: 0x510b00, opc: 0, slot_kind: [0, 0], slot_val: [0x11, 0x22], long_size: 8, out_size: 4, offset: 0, extra_kind: 1 },
        // cc:4621 reject: a second SUBPIECE also reads base.
        CaseSpec { name: "add_two_readers", base: 0x510c00, opc: 0, slot_kind: [0, 0], slot_val: [0x11, 0x22], long_size: 8, out_size: 4, offset: 0, extra_kind: 2 },
    ];

    let mode = std::env::args().nth(1).unwrap_or_default();
    let run_cases: Vec<CaseSpec> = if mode == "trap_dupfree" {
        vec![CaseSpec { name: "trap_dupfree", base: 0x520000, opc: 4, slot_kind: [0, 3], slot_val: [0x77, 0x77], long_size: 8, out_size: 4, offset: 0, extra_kind: 0 }]
    } else if mode == "normal" {
        cases
    } else {
        eprintln!("unknown mode: {mode}");
        std::process::exit(2);
    };

    for spec in run_cases {
        let base = spec.base;
        let built = tail_commute_case(
            &mut fd,
            &block,
            opc_of(&spec),
            base,
            spec.slot_kind,
            spec.slot_val,
            spec.long_size,
            spec.out_size,
            spec.offset,
            spec.extra_kind,
        );
        let sub_commute = RuleSubCommute::new();
        let apply = sub_commute
            .apply_op(&built.sub_op.0, &mut fd)
            .expect("subcommute apply");
        println!("case={}|sub_apply={apply}", spec.name);
        dump_case_window(&fd, base, base + 0x80);
        dump_keep_lines(&fd, &built.keeps, &built.tags, base, base + 0x80);
        println!("endcase");
    }
}

fn main() {
    run();
}
