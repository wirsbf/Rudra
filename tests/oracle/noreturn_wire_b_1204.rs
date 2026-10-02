//! Rust counterpart of the locked `noreturn_wire_b_1204` oracle fixture
//! (Ghidra 12.0.4, CALLSPEC-NORETURN-WIRE-0001 slice (b)).
//!
//! Mirrors the C++ projection exactly, per case: call specs (op/entry
//! deltas, resolved display name, the is_no_return/is_inline bits
//! `query_call`'s `copy_flow_effects` propagated, and the hasModel gate
//! input), warning comments (through the shared in-memory
//! CommentDatabaseInternal attached via `Funcdata::set_arch`), and every op
//! in SeqNum order (address delta, opcode, startbasic, halt-type flag
//! nibble, input(0) token).
//!
//! The callee flow-effect data source mirrors the C++ side's
//! `Funcdata::getFuncProto()` flags exactly: the fixture feeds the
//! per-callee `FuncProto` table through
//! `follow_flow_with_callee_protos` — the channel
//! FLOW-NORETURN-DATA-0001's driver will populate in production.
//! `truncate_indirect_jump` and the `copy_flow_effects` lifecycle are
//! driven directly, like the C++ side's hand-constructed FlowInfo.

use rudra::address::Address;
use rudra::comment::comment_type;
use rudra::comment::CommentDatabaseInternal;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::flow::follow_flow_with_callee_protos;
use rudra::flow::FlowInfo;
use rudra::fspec::FuncCallSpecs;
use rudra::fspec::FuncProto;
use rudra::funcdata::Funcdata;
use rudra::jumptable::RecoveryMode;
use rudra::op::pcodeop_flags;
use rudra::op::PcodeOp;
use rudra::op::PcodeOpRef;
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

/// A bare op for the direct-drive cases: mirrors the C++ fixture's
/// `newOp(1, base); opSetOpcode(..); opSetInput(newConstant(8,0), 0)` —
/// input(0) is the index/target varnode a decoded BRANCHIND/CALLIND
/// carries (Ghidra's getCallSpecs(op) reads it, funcdata.cc:490).
fn make_op(fd: &mut Funcdata, addr: u64, opcode: OpCode) -> PcodeOpRef {
    let op = fd.new_op(1, Address::new(addr));
    fd.op_set_opcode(&op, opcode);
    let c = fd.new_constant(8, 0);
    fd.op_set_input(&op, c, 0);
    op
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

fn spec_line(index: usize, fc: &FuncCallSpecs, base: u64, with_name: bool, with_hasmodel: bool) -> String {
    let entry = match fc.entry_addr {
        Some(a) => delta_string(a.as_u64(), base),
        None => "invalid".to_string(),
    };
    // The truncate case projects neither name nor hasmodel: a Ghidra
    // CALLIND spec's name is address-derived and its noParams arm binds a
    // model, while Rugra seeds the spec from the caller's funcp (name) and
    // keeps the arm as CALLSPEC-0001 (no model).
    let name = if with_name {
        format!(" name={}", fc.prototype.name)
    } else {
        String::new()
    };
    let hasmodel = if with_hasmodel {
        format!(" hasmodel={}", u8::from(fc.has_model()))
    } else {
        String::new()
    };
    format!(
        "spec={} op_delta={} entry={}{} noret={} inline={}{}",
        index,
        delta_string(fc.op_addr.as_u64(), base),
        entry,
        name,
        u8::from(fc.is_no_return()),
        u8::from(fc.is_inline()),
        hasmodel
    )
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
    );

    let base = address;
    println!("case={}", name);
    println!("calls={}", fd.num_calls());
    for i in 0..fd.num_calls() {
        if let Some(fc) = fd.get_call_specs(i) {
            println!("{}", spec_line(i, &fc, base, true, true));
        }
    }
    print_warnings(&db, base);
    print_ops(&fd, base);
    Ok(())
}

fn observe_truncate(address: u64) -> Result<(), Box<dyn Error>> {
    let mut lifter = SleighLifter::new();
    let mut fd = Funcdata::new("wireb_trunc_target", Address::new(address), 16);
    let mut arch = rudra::arch::Architecture::new();
    let db = Arc::new(RwLock::new(CommentDatabaseInternal::new()));
    arch.set_commentdb(db.clone());
    fd.set_arch(Arc::new(arch));

    // The op the recovery loop (flow.cc:1443-1445) hands over: a BRANCHIND
    // at the target's entry, dead like a decoded op.
    let op = make_op(&mut fd, address, OpCode::CPUI_BRANCHIND);
    let mut flow = FlowInfo::new(&mut fd, &mut lifter, address, address + 0x100);
    flow.truncate_indirect_jump(&op, RecoveryMode::FailCallother);

    let base = address;
    println!("case=truncate_fail_callother");
    println!("calls={}", fd.num_calls());
    for i in 0..fd.num_calls() {
        if let Some(fc) = fd.get_call_specs(i) {
            // hasModel is deliberately NOT projected here: the C++ side's
            // noParams arm (flow.cc:757-762) binds glb->defaultfp through
            // setInternal; Rugra keeps that arm as CALLSPEC-0001.
            println!("{}", spec_line(i, &fc, base, false, false));
        }
    }
    print_warnings(&db, base);
    print_ops(&fd, base);
    Ok(())
}

fn observe_copy_flow_effects(address: u64) {
    let mut fc = FuncCallSpecs::new(Address::new(address), FuncProto::new(String::new(), void_type()));
    fc.set_no_return(true);
    fc.set_inline(true);
    println!("case=copy_flow_effects_oneway");
    println!(
        "stage=set_both noret={} inline={}",
        u8::from(fc.is_no_return()),
        u8::from(fc.is_inline())
    );
    let clean = FuncProto::new(String::new(), void_type());
    fc.copy_flow_effects(&clean);
    println!(
        "stage=copy_clean noret={} inline={}",
        u8::from(fc.is_no_return()),
        u8::from(fc.is_inline())
    );
    let mut both = FuncProto::new(String::new(), void_type());
    both.set_inline(true);
    both.set_no_return(true);
    fc.copy_flow_effects(&both);
    println!(
        "stage=copy_both noret={} inline={}",
        u8::from(fc.is_no_return()),
        u8::from(fc.is_inline())
    );
    let mut inline_only = FuncProto::new(String::new(), void_type());
    inline_only.set_inline(true);
    fc.copy_flow_effects(&inline_only);
    println!(
        "stage=copy_inline_only noret={} inline={}",
        u8::from(fc.is_no_return()),
        u8::from(fc.is_inline())
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 15 {
        return Err("usage: noreturn_wire_b_1204 TEXT TEXT_BASE NORET_CALLEE_SYM INLINE_USER_SYM PLAIN_CALLEE_SYM NORET_USER_SYM PLAIN_USER_SYM NORET_USER_ADDR NORET_USER_SIZE INLINE_USER_ADDR INLINE_USER_SIZE PLAIN_USER_ADDR PLAIN_USER_SIZE TRUNC_ADDR".into());
    }

    let image = fs::read(&args[1])?;
    let image_base = parse_u64(&args[2])?;
    let noret_callee_sym = parse_u64(&args[3])?;
    let inline_user_sym = parse_u64(&args[4])?;
    let plain_callee_sym = parse_u64(&args[5])?;
    let noret_user_sym = parse_u64(&args[6])?;
    let plain_user_sym = parse_u64(&args[7])?;

    // Case 1: noreturn callee -> spec bit propagation + artificial halt +
    // "Subroutine does not return" warning.
    let mut noret_proto = FuncProto::new(String::new(), void_type());
    noret_proto.set_no_return(true);
    let noret_protos = BTreeMap::from([(noret_callee_sym, noret_proto)]);
    observe(
        "wireb_noret_user",
        &image,
        image_base,
        parse_u64(&args[8])?,
        parse_u64(&args[9])? as usize,
        &[
            (noret_user_sym, "wireb_noret_user"),
            (noret_callee_sym, "wireb_callee_noret"),
        ],
        &noret_protos,
    )?;

    // Case 2: inline self-call -> inline bit propagation, injection refused
    // by the self-recursion guard ("Could not inline here").
    let mut inline_proto = FuncProto::new(String::new(), void_type());
    inline_proto.set_inline(true);
    let inline_protos = BTreeMap::from([(inline_user_sym, inline_proto)]);
    observe(
        "wireb_inline_user",
        &image,
        image_base,
        parse_u64(&args[10])?,
        parse_u64(&args[11])? as usize,
        &[(inline_user_sym, "wireb_inline_user")],
        &inline_protos,
    )?;

    // Case 3: plain callee -> no bits, no halt, no warning.
    let clean_protos = BTreeMap::from([(plain_callee_sym, FuncProto::new(String::new(), void_type()))]);
    observe(
        "wireb_plain_user",
        &image,
        image_base,
        parse_u64(&args[12])?,
        parse_u64(&args[13])? as usize,
        &[
            (plain_user_sym, "wireb_plain_user"),
            (plain_callee_sym, "wireb_callee_plain"),
        ],
        &clean_protos,
    )?;

    // Case 4: truncate fail_callother -> setNoReturn(true) + halt.
    observe_truncate(parse_u64(&args[14])?)?;

    // Case 5: copy_flow_effects one-way overwrite lifecycle.
    observe_copy_flow_effects(parse_u64(&args[14])?);
    Ok(())
}
