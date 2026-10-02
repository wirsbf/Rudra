//! Rust counterpart of the locked `flow_overlap_hlt_1204` oracle fixture
//! (Ghidra 12.0.4, FLOW-339E-OVERLAP-HLT-0001).
//!
//! Mirrors the C++ projection exactly, per case: block count, per-block
//! first-op address delta with in/out edge address deltas
//! (`BlockGraph::get_block` order), call specs (op/entry deltas,
//! `is_no_return`/`is_inline`), warning comments (through the shared
//! in-memory CommentDatabaseInternal attached via `Funcdata::set_arch`),
//! and every op in SeqNum order (address delta, opcode, startbasic,
//! halt-type flag nibble, input(0) token).
//!
//! The callee flow-effect data source mirrors the C++ side's
//! `Funcdata::getFuncProto()` flags exactly: the fixture feeds the
//! per-callee `FuncProto` table through
//! `follow_flow_with_callee_protos`. The `ohlt_user_plain` case passes a
//! clean (flag-clear) entry — the golden_dump_1204 per-function fixture
//! environment, whose BfdArchitecture + readLoaderSymbols loader has no
//! analyzer-side attributes, which is why flow falls through the direct
//! call into the overlap tail and lifts `hlt` as the self-loop block. The
//! `ohlt_user_marked` case passes the setNoReturn(true) entry — the
//! "Non-Returning Functions - Known" analyzer DB attribute of the
//! full-analysis environment — so
//! `FlowInfo::check_for_flow_modification` (flow.cc:636-651) inserts the
//! noreturn artificial halt at the CALL and the tail is never lifted.

use rudra::address::Address;
use rudra::comment::comment_type;
use rudra::comment::CommentDatabaseInternal;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::flow::follow_flow_with_callee_protos;
use rudra::fspec::FuncProto;
use rudra::funcdata::Funcdata;
use rudra::op::pcodeop_flags;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::sync::Arc;
use std::sync::RwLock;

fn parse_u64(value: &str) -> Result<u64, Box<dyn Error>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    Ok(u64::from_str_radix(value, 16)?)
}

fn delta_string(offset: u64, base: u64) -> String {
    (offset as i64 - base as i64).to_string()
}

fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

fn space_name(space: rudra::space::AddressSpace) -> String {
    match space {
        rudra::space::AddressSpace::Ram => "ram",
        rudra::space::AddressSpace::Register => "register",
        rudra::space::AddressSpace::Unique => "unique",
        rudra::space::AddressSpace::Const => "const",
        rudra::space::AddressSpace::Stack => "stack",
        rudra::space::AddressSpace::Join => "join",
        rudra::space::AddressSpace::Iop => "iop",
        rudra::space::AddressSpace::Overlay => "overlay",
        rudra::space::AddressSpace::Other(_) => "other",
    }
    .to_string()
}

fn input0_token(op: &PcodeOp, base: u64) -> String {
    let Some(input) = op.inrefs.first() else {
        return "none".to_string();
    };
    let varnode = input.read().expect("varnode read lock");
    match varnode.get_space() {
        rudra::space::AddressSpace::Iop => "callspec".to_string(),
        rudra::space::AddressSpace::Const => {
            if op.opcode == OpCode::CPUI_LOAD || op.opcode == OpCode::CPUI_STORE {
                // Space reference encoded as a constant: Ghidra's value is a
                // per-run heap pointer, Rugra's a stable SPACEID_* index;
                // project the referenced space name instead (same
                // normalization as flow_tailcall_overtrace_1204).
                let space = rudra::space::AddressSpace::from_id(varnode.get_offset() as u8);
                return format!("spc:{}", space_name(space));
            }
            format!("const:{}", varnode.get_offset())
        }
        rudra::space::AddressSpace::Ram => {
            format!("ram:{}", delta_string(varnode.get_offset(), base))
        }
        rudra::space::AddressSpace::Unique => {
            // Allocator-relative SLEIGH temporaries carry no addressable
            // meaning on either side; project the bare space name (the
            // C++ side's IPTR_INTERNAL arm).
            "unique".to_string()
        }
        other => format!("{}:{}", space_name(other), varnode.get_offset()),
    }
}

/// The halt-type nibble, mirroring Ghidra `PcodeOp::getHaltType()`
/// (op.hh:171): flags & (halt|badinstruction|unimplemented|noreturn|missing).
fn halt_type(op: &PcodeOp) -> u32 {
    op.flags
        & (pcodeop_flags::HALT
            | pcodeop_flags::BADINSTRUCTION
            | pcodeop_flags::UNIMPLEMENTED
            | pcodeop_flags::NORETURN
            | pcodeop_flags::MISSING)
}

fn block_addr_delta(
    blk: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    base: u64,
) -> String {
    let rg = blk.read().expect("block read lock");
    match rg.first_op() {
        Some(op) => delta_string(op.0.read().expect("op read lock").get_addr().as_u64(), base),
        None => "none".to_string(),
    }
}

fn print_warnings(db: &Arc<RwLock<CommentDatabaseInternal>>, base: u64) {
    let db_ref = db.read().expect("commentdb read lock");
    let comments: Vec<&rudra::comment::Comment> =
        db_ref.comments_for_function(Address::new(base)).collect();
    for (index, comment) in comments.iter().enumerate() {
        let ty = comment.get_type();
        let type_token = if (ty & comment_type::WARNINGHEADER) != 0 {
            "warningheader"
        } else if (ty & comment_type::WARNING) != 0 {
            "warning"
        } else {
            "other"
        };
        println!(
            "warn={} type={} addr_delta={} text={}",
            index,
            type_token,
            delta_string(comment.get_addr().as_u64(), base),
            comment.get_text()
        );
    }
}

fn print_ops(fd: &Funcdata, base: u64) {
    for (index, op_ref) in fd.obank.optree.iter().enumerate() {
        let op = op_ref.0.read().expect("op read lock");
        println!(
            "op={} addr={} opcode={} sb={} halt={} in0={}",
            index,
            delta_string(op.get_addr().as_u64(), base),
            op.get_opcode() as i32,
            if (op.flags & pcodeop_flags::STARTBASIC) != 0 { 1 } else { 0 },
            halt_type(&op),
            input0_token(&op, base)
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn observe(
    name: &str,
    image: &[u8],
    image_base: u64,
    address: u64,
    size: usize,
    symbols: &[(u64, &str)],
    callee_protos: &BTreeMap<u64, FuncProto>,
) -> Result<(), Box<dyn Error>> {
    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(image, image_base)?;
    let mut fd = Funcdata::new(name, Address::new(address), size as i32);
    let mut arch = rudra::arch::Architecture::new();
    let db = Arc::new(RwLock::new(CommentDatabaseInternal::new()));
    arch.set_commentdb(db.clone());
    fd.set_arch(Arc::new(arch));
    // The queryFunction seed (flow.cc:660) + the callee funcp slice
    // (otherfunc->getFuncProto(), flow.cc:663-664).
    for (sym_addr, sym_name) in symbols {
        fd.add_symbol(*sym_addr, sym_name.to_string());
    }
    follow_flow_with_callee_protos(
        &mut fd,
        &mut lifter,
        Address::new(address),
        u64::MAX,
        callee_protos,
    )?;

    let base = address;
    println!("case={}", name);
    println!("blocks={}", fd.bblocks.get_size());
    for i in 0..fd.bblocks.get_size() {
        let blk = fd
            .bblocks
            .get_block(i)
            .ok_or("block index out of range")?;
        let addr = block_addr_delta(&blk, base);
        let rg = blk.read().expect("block read lock");
        let n_in = rg.size_in();
        let n_out = rg.size_out();
        let ins: Vec<String> = (0..n_in)
            .filter_map(|j| rg.get_in(j))
            .map(|e| block_addr_delta(&e.point, base))
            .collect();
        let outs: Vec<String> = (0..n_out)
            .filter_map(|j| rg.get_out(j))
            .map(|e| block_addr_delta(&e.point, base))
            .collect();
        println!("blk={} addr={} in=[{}] out=[{}]", i, addr, ins.join(" "), outs.join(" "));
    }
    println!("calls={}", fd.num_calls());
    for i in 0..fd.num_calls() {
        if let Some(fc) = fd.get_call_specs(i) {
            let entry = match fc.entry_addr {
                Some(a) => delta_string(a.as_u64(), base),
                None => "invalid".to_string(),
            };
            println!(
                "spec={} op_delta={} entry={} noret={} inline={}",
                i,
                delta_string(fc.op_addr.as_u64(), base),
                entry,
                u8::from(fc.is_no_return()),
                u8::from(fc.is_inline())
            );
        }
    }
    print_warnings(&db, base);
    print_ops(&fd, base);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect::<Vec<_>>();
    if args.len() != 9 {
        return Err("usage: flow_overlap_hlt_1204 TEXT TEXT_BASE PLAIN_USER_ADDR PLAIN_USER_SIZE MARKED_USER_ADDR MARKED_USER_SIZE PLAIN_CALLEE_SYM MARKED_CALLEE_SYM".into());
    }

    let image = fs::read(&args[1])?;
    let image_base = parse_u64(&args[2])?;
    let plain_user = parse_u64(&args[3])?;
    let plain_size = parse_u64(&args[4])? as usize;
    let marked_user = parse_u64(&args[5])?;
    let marked_size = parse_u64(&args[6])? as usize;
    let plain_callee = parse_u64(&args[7])?;
    let marked_callee = parse_u64(&args[8])?;

    // Case 1: unmarked callee (golden_dump_1204 fixture environment).
    // Expect the fall-through chain past the direct call into the overlap
    // tail: 3 blocks, hlt self-loop, no halt op, no warning.
    let clean_protos = BTreeMap::from([(plain_callee, FuncProto::new(String::new(), void_type()))]);
    observe(
        "ohlt_user_plain",
        &image,
        image_base,
        plain_user,
        plain_size,
        &[
            (plain_user, "ohlt_user_plain"),
            (plain_callee, "ohlt_callee_plain"),
        ],
        &clean_protos,
    )?;

    // Case 2: analyzer-marked callee ("Non-Returning Functions - Known").
    // Expect the artificial halt at the CALL: 2 blocks, no tail, warning.
    let mut marked_proto = FuncProto::new(String::new(), void_type());
    marked_proto.set_no_return(true);
    let marked_protos = BTreeMap::from([(marked_callee, marked_proto)]);
    observe(
        "ohlt_user_marked",
        &image,
        image_base,
        marked_user,
        marked_size,
        &[
            (marked_user, "ohlt_user_marked"),
            (marked_callee, "ohlt_callee_marked"),
        ],
        &marked_protos,
    )?;
    Ok(())
}
