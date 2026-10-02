//! RULE-SUBCOMMUTE-CANCELEXT-0001: Rugra side of the locked 12.0.4 oracle
//! fixture for `RuleSubCommute::cancelExtensions` (ruleaction.cc:4483-4512)
//! via the INT_DIV/INT_REM (ZEXT, cc:4542-4568) and INT_SDIV/INT_SREM
//! (SEXT, cc:4570-4602) arms (WORKPKG-UNMAP-RULEADJ-0013; closes
//! RULEACTION-SUBCOMMUTE-ZEXT-PARTIAL-0001 on the Rust side).
//!
//! Mirrors `rule_subcommute_cancelext_1204.cc` case-for-case (same names,
//! same observation format):
//!   case=<name>|ce_apply=<0/1>
//!     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
//!     keep=<tag>|<cls>|<size>|readers=<n>|descends=<n>
//!   endcase
//!
//! The partial commute under test: SUBPIECE(longform,0) with an extension
//! input wider than the SUBPIECE output — cancelExtensions rebinds longform
//! to the raw extension inputs (shortening the narrow side's extension via
//! shortenExtension, cc:4463-4472), gives longform a fresh maxSize output,
//! and leaves the SUBPIECE reading the truncated longform (cc:4506-4511).

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

fn print_op_line(op: &rudra::op::PcodeOpRef) {
    let g = op.0.read().unwrap();
    let addr = g.get_addr().to_space_address().get_offset();
    let mut line = format!("  op={}@0x{:x}|nin={}", g.opcode as i32, addr, g.num_input());
    let sentinel = rudra::op::null_slot_sentinel();
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

fn dump_keep_lines(fd: &Funcdata, keeps: &[VnRef], tags: &[&str], lo: u64, hi: u64) {
    for (k, vn) in keeps.iter().enumerate() {
        let mut readers = 0;
        for op in fd.begin_op_all() {
            let g = op.0.read().unwrap();
            let a = g.get_addr().to_space_address().get_offset();
            if a < lo || hi < a {
                continue;
            }
            for s in 0..g.num_input() {
                if let Some(v) = g.get_in(s) {
                    if Arc::ptr_eq(&v, vn) {
                        readers += 1;
                    }
                }
            }
        }
        let descends = vn.read().unwrap().count_descends();
        println!(
            "  keep={}|{}|{}|readers={readers}|descends={descends}",
            tags[k],
            vn_class(Some(vn)),
            vn.read().unwrap().get_size()
        );
    }
}

struct CaseBuilt {
    sub_op: rudra::op::PcodeOpRef,
    keeps: Vec<VnRef>,
    tags: Vec<&'static str>,
}

#[allow(clippy::too_many_arguments)]
fn cancel_ext_case(
    fd: &mut Funcdata,
    block: &BlockRef,
    base: u64,
    opc: i32,
    asz: usize,
    bsz: usize,
    ext_size: usize,
    out_size: usize,
    extra_kind: i32,
) -> CaseBuilt {
    let ext_opc = if opc == 0 || opc == 1 {
        OpCode::CPUI_INT_ZEXT
    } else {
        OpCode::CPUI_INT_SEXT
    };
    let long_opc = match opc {
        0 => OpCode::CPUI_INT_DIV,
        1 => OpCode::CPUI_INT_REM,
        2 => OpCode::CPUI_INT_SDIV,
        _ => OpCode::CPUI_INT_SREM,
    };
    let vals: [u64; 2] = [0x33, 0x55];
    let sizes = [asz, bsz];
    let mut ins: Vec<VnRef> = Vec::new();
    let mut writers: Vec<rudra::op::PcodeOpRef> = Vec::new();
    for slot in 0..2 {
        let writer = fd.new_op(1, Address::new(base + 0x10 + 0x8 * slot as u64));
        fd.op_set_opcode(&writer, OpCode::CPUI_COPY);
        let fv = fd.new_unique_out(sizes[slot], &writer);
        let c = fd.new_constant(sizes[slot], vals[slot]);
        fd.op_set_input(&writer, c, 0);
        fd.op_insert_end(&writer, block);
        writers.push(writer);
        ins.push(fv);
    }
    let mut ext_outs: Vec<VnRef> = Vec::new();
    for slot in 0..2 {
        let ext = fd.new_op(1, Address::new(base + 0x20 + 0x8 * slot as u64));
        fd.op_set_opcode(&ext, ext_opc);
        let eo = fd.new_unique_out(ext_size, &ext);
        fd.op_set_input(&ext, ins[slot].clone(), 0);
        fd.op_insert_end(&ext, block);
        ext_outs.push(eo);
    }
    let longform = fd.new_op(2, Address::new(base + 0x30));
    fd.op_set_opcode(&longform, long_opc);
    fd.new_unique_out(ext_size, &longform);
    fd.op_set_input(&longform, ext_outs[0].clone(), 0);
    fd.op_set_input(&longform, ext_outs[1].clone(), 1);
    fd.op_insert_end(&longform, block);
    let sub_op = fd.new_op(2, Address::new(base + 0x40));
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    fd.new_unique_out(out_size, &sub_op);
    let lout = longform.0.read().unwrap().output.as_ref().unwrap().clone();
    fd.op_set_input(&sub_op, lout, 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&sub_op, zero, 1);
    fd.op_insert_end(&sub_op, block);
    if extra_kind == 1 {
        // cc:4488: longform output has a second reader besides sub_op.
        let sub2 = fd.new_op(2, Address::new(base + 0x50));
        fd.op_set_opcode(&sub2, OpCode::CPUI_SUBPIECE);
        fd.new_unique_out(out_size, &sub2);
        let lout = longform.0.read().unwrap().output.as_ref().unwrap().clone();
        fd.op_set_input(&sub2, lout, 0);
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(&sub2, zero, 1);
        fd.op_insert_end(&sub2, block);
    } else if extra_kind == 2 {
        // cc:4489-4493: free the ext0 input (COPY writer unset, descend kept).
        fd.op_unset_output(&writers[0]);
    } else if extra_kind == 3 {
        // cc:4499: the SHORTENED side's extension output has a second reader.
        let sub2 = fd.new_op(2, Address::new(base + 0x50));
        fd.op_set_opcode(&sub2, OpCode::CPUI_SUBPIECE);
        fd.new_unique_out(4, &sub2);
        fd.op_set_input(&sub2, ext_outs[0].clone(), 0);
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(&sub2, zero, 1);
        fd.op_insert_end(&sub2, block);
    }
    CaseBuilt {
        sub_op,
        keeps: ins.clone(),
        tags: vec!["a", "b"],
    }
}

struct CaseSpec {
    name: &'static str,
    base: u64,
    opc: i32,
    asz: usize,
    bsz: usize,
    ext_size: usize,
    out_size: usize,
    extra_kind: i32,
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    let block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x8000))));
    fd.bblocks.add_block(block.clone());

    let cases: Vec<CaseSpec> = vec![
        CaseSpec { name: "div_partial_eq", base: 0x810000, opc: 0, asz: 8, bsz: 8, ext_size: 16, out_size: 4, extra_kind: 0 },
        CaseSpec { name: "div_partial_shorten0", base: 0x810100, opc: 0, asz: 4, bsz: 8, ext_size: 16, out_size: 4, extra_kind: 0 },
        CaseSpec { name: "rem_partial_shorten1", base: 0x810200, opc: 1, asz: 8, bsz: 4, ext_size: 16, out_size: 4, extra_kind: 0 },
        CaseSpec { name: "sdiv_partial_eq", base: 0x810300, opc: 2, asz: 8, bsz: 8, ext_size: 16, out_size: 4, extra_kind: 0 },
        CaseSpec { name: "srem_partial_shorten0", base: 0x810400, opc: 3, asz: 4, bsz: 8, ext_size: 16, out_size: 4, extra_kind: 0 },
        CaseSpec { name: "div_partial_two_readers", base: 0x811000, opc: 0, asz: 8, bsz: 8, ext_size: 16, out_size: 4, extra_kind: 1 },
        CaseSpec { name: "div_partial_free_in", base: 0x811100, opc: 0, asz: 8, bsz: 8, ext_size: 16, out_size: 4, extra_kind: 2 },
        CaseSpec { name: "div_partial_shorten_reader", base: 0x811200, opc: 0, asz: 4, bsz: 8, ext_size: 16, out_size: 4, extra_kind: 3 },
        CaseSpec { name: "div_fallthrough_full", base: 0x812000, opc: 0, asz: 4, bsz: 4, ext_size: 8, out_size: 4, extra_kind: 0 },
    ];

    for spec in cases {
        let built = cancel_ext_case(
            &mut fd,
            &block,
            spec.base,
            spec.opc,
            spec.asz,
            spec.bsz,
            spec.ext_size,
            spec.out_size,
            spec.extra_kind,
        );
        let rule = RuleSubCommute::new();
        let apply = rule.apply_op(&built.sub_op.0, &mut fd).expect("subcommute apply");
        println!("case={}|ce_apply={apply}", spec.name);
        dump_case_window(&fd, spec.base, spec.base + 0x80);
        dump_keep_lines(&fd, &built.keeps, &built.tags, spec.base, spec.base + 0x80);
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
