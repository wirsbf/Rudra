//! Rust counterpart of the locked `flow_containedcall_1204` oracle fixture
//! (Ghidra 12.0.4, flow.cc:1361 FlowInfo::checkContainedCall).
//!
//! Mirrors the C++ projection exactly: call specs, warning comments (via a
//! shared in-memory CommentDatabaseInternal attached through
//! `Funcdata::set_arch`, the analogue of Ghidra's Architecture::commentdb),
//! the block graph and every op in bank order. Address spelling inside the
//! PIC warning text is projected to a base-relative delta on both sides
//! (Rudra's legacy flow Address has no space tag; ADDRESS-0001).

use rudra::address::Address;
use rudra::block::{block_flags, FlowBlock};
use rudra::comment::comment_type;
use rudra::comment::CommentDatabaseInternal;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::flow::follow_flow;
use rudra::fspec::FuncCallSpecs;
use rudra::funcdata::Funcdata;
use rudra::op::pcodeop_flags;
use rudra::space::AddressSpace;
use std::env;
use std::error::Error;
use std::fs;
use std::sync::{Arc, RwLock};

type DynBlock = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

const CASES: [&str; 11] = [
    "containedcall_getpc",
    "containedcall_mid",
    "containedcall_fwd",
    "containedcall_offcut",
    "containedcall_beyond",
    "containedcall_multi",
    "containedcall_back",
    "containedcall_afterc",
    "containedcall_before",
    "containedcall_callind",
    "containedcall_extern",
];

fn parse_u64(value: &str) -> Result<u64, Box<dyn Error>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    Ok(u64::from_str_radix(value, 16)?)
}

fn ordinal_of(blocks: &[DynBlock], needle: &DynBlock) -> i32 {
    blocks
        .iter()
        .position(|block| Arc::ptr_eq(block, needle))
        .map_or(-1, |index| index as i32)
}

fn format_edges(blocks: &[DynBlock], block: &DynBlock, outgoing: bool) -> String {
    let block = block.read().expect("block read lock");
    let count = if outgoing {
        block.size_out()
    } else {
        block.size_in()
    };
    let mut edges = Vec::with_capacity(count);
    for slot in 0..count {
        let edge = if outgoing {
            block.get_out(slot)
        } else {
            block.get_in(slot)
        }
        .expect("edge slot must exist");
        edges.push(format!(
            "{}:{}",
            ordinal_of(blocks, &edge.point),
            edge.reverse_index
        ));
    }
    format!("[{}]", edges.join(","))
}

fn delta_string(offset: u64, base: u64) -> String {
    (offset as i64 - base as i64).to_string()
}

/// Same projection rule as the C++ side: the PIC header warning embeds the
/// call address; both sides reduce it to a base-relative delta so the
/// printRaw-vs-Display spelling difference (ADDRESS-0001) drops out.
fn project_text(text: &str, base: u64) -> String {
    let prefix = "WARNING: Possible PIC construction at ";
    let suffix = ": Changing call to branch";
    if let Some(token) = text.strip_prefix(prefix) {
        if let Some(digits) = token.strip_suffix(suffix) {
            let digits = digits
                .strip_prefix("ram:")
                .or_else(|| digits.strip_prefix("0x"))
                .unwrap_or(digits);
            let offset = u64::from_str_radix(digits, 16).unwrap_or(0);
            return format!("pic:{}", delta_string(offset, base));
        }
    }
    if text == "WARNING: Call to offcut address within same function" {
        return "offcut".to_string();
    }
    text.to_string()
}

fn space_name(space: AddressSpace) -> String {
    match space {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Overlay => "overlay",
        AddressSpace::Other(_) => "other",
    }
    .to_string()
}

fn input0_token(op: &rudra::op::PcodeOp, base: u64) -> String {
    let Some(input) = op.inrefs.first() else {
        return "none".to_string();
    };
    let varnode = input.read().expect("varnode read lock");
    match varnode.get_space() {
        // Ghidra stores the call-spec annotation in the Fspec space
        // (IPTR_FSPEC). Rudra's pointer-shaped Iop annotation carries a typed,
        // non-owning Weak handle to the Funcdata-owned Arc; this fixture only
        // projects the two space encodings to one token and does not claim an
        // identity proof from either the token or numeric offset.
        AddressSpace::Iop => "callspec".to_string(),
        AddressSpace::Const => {
            if op.opcode == rudra::opcodes::OpCode::CPUI_LOAD
                || op.opcode == rudra::opcodes::OpCode::CPUI_STORE
            {
                // Space reference encoded as a constant: Ghidra's value is a
                // per-run heap pointer, Rudra's a stable SPACEID_* index;
                // project the referenced space name instead.
                let space = AddressSpace::from_id(varnode.get_offset() as u8);
                return format!("spc:{}", space_name(space));
            }
            format!("const:{}", varnode.get_offset())
        }
        AddressSpace::Ram => format!("ram:{}", delta_string(varnode.get_offset(), base)),
        other => format!("{}:{}", space_name(other), varnode.get_offset()),
    }
}

fn spec_line(index: usize, fc: &FuncCallSpecs, base: u64) -> String {
    let entry = match fc.entry_addr {
        Some(a) => delta_string(a.as_u64(), base),
        None => "invalid".to_string(),
    };
    format!(
        "spec={} op_delta={} entry={}",
        index,
        delta_string(fc.op_addr.as_u64(), base),
        entry
    )
}

fn observe(
    name: &str,
    image: &[u8],
    image_base: u64,
    address: u64,
    size: usize,
) -> Result<(), Box<dyn Error>> {
    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(image, image_base)?;
    let mut fd = Funcdata::new(name, Address::new(address), size as i32);
    // Ghidra's Funcdata writes warnings into Architecture::commentdb; attach
    // the shared in-memory database the same way before following flow.
    let mut arch = rudra::arch::Architecture::new();
    let db = Arc::new(RwLock::new(CommentDatabaseInternal::new()));
    arch.set_commentdb(db.clone());
    fd.set_arch(Arc::new(arch));
    follow_flow(&mut fd, &mut lifter, Address::new(address), u64::MAX);

    let base = address;
    println!("case={}", name);
    println!("calls={}", fd.num_calls());
    for i in 0..fd.num_calls() {
        if let Some(fc) = fd.get_call_specs(i) {
            println!("{}", spec_line(i, &fc, base));
        }
    }

    {
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
                project_text(comment.get_text(), base)
            );
        }
    }

    let blocks = fd.bblocks.blocks.clone();
    let entry = fd
        .bblocks
        .get_start_block()
        .ok_or("missing official entry block")?;
    let entry_count = blocks
        .iter()
        .filter(|block| block.read().expect("block read lock").is_entry_point())
        .count();

    println!(
        "blocks={} entry_ordinal={} entry_count={}",
        blocks.len(),
        ordinal_of(&blocks, &entry),
        entry_count
    );
    for (ordinal, block) in blocks.iter().enumerate() {
        let (ops, start, stop) = {
            let block = block.read().expect("block read lock");
            (
                block.get_ops().len(),
                block.get_start_addr().as_u64(),
                block
                    .as_any()
                    .downcast_ref::<rudra::block::BlockBasic>()
                    .map(|basic| basic.get_stop_addr().as_u64())
                    .unwrap_or(0),
            )
        };
        println!(
            "block={} ops={} start={} stop={} in={} out={}",
            ordinal,
            ops,
            delta_string(start, base),
            delta_string(stop, base),
            format_edges(&blocks, block, false),
            format_edges(&blocks, block, true)
        );
    }

    // Ghidra iterates fd->beginOpAll()/endOpAll() = the PcodeOpTree ordered
    // by SeqNum (address, then time) — not creation order. Rudra's obank
    // optree is the same BTreeSet with the same SeqNum ordering.
    for (index, op_ref) in fd.obank.optree.iter().enumerate() {
        let op = op_ref.0.read().expect("op read lock");
        let blk = op
            .parent
            .as_ref()
            .and_then(|weak| weak.upgrade())
            .map(|parent| {
                blocks
                    .iter()
                    .position(|block| Arc::ptr_eq(block, &parent))
                    .map_or(-1, |position| position as i32)
            })
            .unwrap_or(-1);
        println!(
            "op={} blk={} opcode={} sb={} in0={}",
            index,
            blk,
            op.get_opcode() as i32,
            if (op.flags & pcodeop_flags::STARTBASIC) != 0 {
                1
            } else {
                0
            },
            input0_token(&op, base)
        );
    }

    if blocks[0].read().expect("block read lock").get_flags() & block_flags::ENTRY_POINT == 0 {
        return Err("list[0] is not the official entry block".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 25 {
        return Err(
            "usage: flow_containedcall_1204 TEXT TEXT_BASE ADDR0 SIZE0 ... ADDR10 SIZE10".into(),
        );
    }

    let image = fs::read(&args[1])?;
    let image_base = parse_u64(&args[2])?;
    for (case_index, name) in CASES.iter().enumerate() {
        let address = parse_u64(&args[3 + 2 * case_index])?;
        let size = parse_u64(&args[4 + 2 * case_index])? as usize;
        observe(name, &image, image_base, address, size)?;
    }
    Ok(())
}
