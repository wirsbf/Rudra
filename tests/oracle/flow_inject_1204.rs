//! Rust counterpart of the locked `flow_inject_1204` oracle fixture
//! (Ghidra 12.0.4, FlowInfo P-code injection path: flow.cc:1177-1355 +
//! generateOps hasInject wiring flow.cc:794-795/819-820).
//!
//! Mirrors the C++ construction exactly: the real SLEIGH lift over the
//! fixture .text, a per-case CALLOTHER-fixup payload compiled by Rudra's
//! snippet compiler, an InjectedUserOp descriptor, a synthetic CALLOTHER at
//! the probe entry (const index + const operand + ram:0x40 output +
//! startbasic flag), a seeded injectlist (via the documented
//! `fixture_queue_inject` observation hook — the C++ fixture writes the
//! private injectlist directly because the pinned x86-64 SLEIGH declares no
//! user-defined p-code ops), then the real `generate_ops`/`generate_blocks`
//! and the identical stdout projections.

use rudra::address::Address;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::flow::FlowInfo;
use rudra::funcdata::Funcdata;
use rudra::op::pcodeop_flags;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use std::env;
use std::error::Error;
use std::fs;
use std::sync::{Arc, RwLock};

type DynBlock = Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>;

/// `inject_cpuid` runs the REAL production path: the x86-64 SLEIGH engine
/// emits CALLOTHER(44) for the `cpuid` instruction, so the fixup registered
/// under that index is queued by `xref_control_flow`'s CALLOTHER arm on its
/// own and expanded by `generate_ops`' `hasInject` gate (flow.cc:344-348 /
/// 794-795). The seeded cases install synthetic userops beyond the engine's
/// userop-name table (Rudra's UserOpManage has no SLEIGH-driven initialize,
/// so the fixture registers the descriptor directly; Ghidra's fixture uses
/// explicit-instantiation access to UserOpManage::registerOp).
const CASES: [(&str, &str, i32, &str); 3] = [
    ("inject_cpuid", "cpuid", 44, "out = in0;"),
    ("inject_add", "inject_add_op", 2001, "out = in0 + 0x10:4;"),
    (
        "inject_label",
        "inject_label_op",
        2002,
        "if (in0) goto <over>; out = 0x1:4; <over> out = 0x2:4;",
    ),
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

/// Space name canonicalized to Ghidra's spellings (the unique space is
/// named "uniq" in the oracle).
fn space_name(space: AddressSpace) -> &'static str {
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
}

fn varnode_token(
    vn: Option<&std::sync::Arc<RwLock<rudra::varnode::Varnode>>>,
    space_ref: bool,
) -> String {
    match vn {
        None => "none".to_string(),
        Some(vn) => {
            let varnode = vn.read().expect("varnode read lock");
            let space = varnode.get_space();
            if space == AddressSpace::Const && space_ref {
                // A LOAD/STORE space reference is encoded as a constant
                // (Ghidra: an AddrSpace heap pointer; Rudra: the stable
                // SPACEID_* index); project the referenced space name,
                // like the flow_containedcall_1204 fixture.
                let referenced = AddressSpace::from_id(varnode.get_offset() as u8);
                return format!("spc:{}", space_name(referenced));
            }
            let name = space_name(space);
            format!("{}:0x{:x}", name, varnode.get_offset())
        }
    }
}

fn language_ready_injectlib() -> Arc<RwLock<rudra::pcodeinject::PcodeInjectLibrary>> {
    use rudra::pcodeparse::{PredefinedJumpSymbols, SleighSymbolLookup};
    struct EmptyHost;
    impl SleighSymbolLookup for EmptyHost {
        fn find_symbol(&self, _name: &str) -> Option<rudra::pcodeparse::SleighSymbol> {
            None
        }
    }
    let mut lib = rudra::pcodeinject::PcodeInjectLibrary::new(0x200);
    lib.set_sleigh_lookup(Arc::new(PredefinedJumpSymbols::new(EmptyHost)));
    Arc::new(RwLock::new(lib))
}

/// Synthetic CALLOTHER at the probe entry: const index + const operand,
/// output in ram:0x40, block-start flagged (mirroring the C++ fixture's
/// newOp/newConstant/newVarnodeOut/opMarkStartBasic construction).
fn construct_callother(
    fd: &mut Funcdata,
    address: u64,
    userop_index: i32,
) -> rudra::op::PcodeOpRef {
    let callother = fd.obank.create(OpCode::CPUI_CALLOTHER, 2, Address::new(address));
    let index_vn = fd.vbank.create_constant(4, userop_index as u64);
    fd.op_set_input(&callother, index_vn, 0);
    let operand_vn = fd.vbank.create_constant(4, 0x20);
    fd.op_set_input(&callother, operand_vn, 1);
    let out_vn = fd
        .vbank
        .create_def_with_space(4, AddressSpace::Ram, 0x40, &callother.0);
    callother.0.write().expect("op write lock").output = Some(out_vn);
    callother.0.write().expect("op write lock").flags |= pcodeop_flags::STARTBASIC;
    callother
}

fn observe(
    name: &str,
    opname: &str,
    userop_index: i32,
    snippet: &str,
    image: &[u8],
    image_base: u64,
    address: u64,
    size: usize,
) -> Result<(), Box<dyn Error>> {
    // Architecture with the injected userop + compiled payload, mirroring
    // manualCallOtherFixup + InjectedUserOp registration.
    let inject_lib = language_ready_injectlib();
    let injectid = inject_lib.write().expect("lock poisoned").manual_call_other_fixup(
        opname,
        "out",
        &["in0".to_string()],
        snippet,
    )?;
    let mut userops = rudra::userop::UserOpManage::new();
    let descriptor = rudra::userop::UserPcodeOp::new(
        opname.to_string(),
        rudra::userop::UserOpType::Injected,
        userop_index,
    );
    userops.register_user_op(descriptor).expect("index free");
    userops
        .get_op_mut(userop_index)
        .expect("just registered")
        .inject_id = injectid;
    let mut arch = rudra::arch::Architecture::new();
    arch.userops = Some(Arc::new(RwLock::new(userops)));
    arch.pcodeinjectlib = Some(inject_lib);

    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(image, image_base)?;
    let mut fd = Funcdata::new(name, Address::new(address), size as i32);
    fd.set_arch(Arc::new(arch));

    let callother = if userop_index == 44 {
        // Production path: no seeding; follow_flow lifts the `cpuid`
        // instruction (whose p-code contains CALLOTHER(44)) and the
        // CALLOTHER arm queues + expands the fixup on its own.
        rudra::flow::follow_flow(&mut fd, &mut lifter, Address::new(address), u64::MAX);
        None
    } else {
        Some(construct_callother(&mut fd, address, userop_index))
    };

    let inject_pending = match callother {
        None => 0,
        Some(callother) => {
            // Hand-driven FlowInfo with the seeded injectlist. The
            // pending-inject flag is read before the scope ends (hasInject
            // on the drained list); everything else is observed through the
            // owning Funcdata.
            let pending;
            {
                let mut flow = FlowInfo::new(&mut fd, &mut lifter, address, u64::MAX);
                flow.fixture_queue_inject(&callother);
                flow.generate_ops(Address::new(address));
                flow.generate_blocks();
                pending = if flow.has_inject() { 1 } else { 0 };
            }
            pending
        }
    };

    println!("case={}", name);
    println!("callspecs={}", fd.num_calls());
    println!("inject_pending={}", inject_pending);

    let blocks = fd.bblocks.blocks.clone();
    let entry = fd
        .bblocks
        .get_start_block()
        .ok_or("missing official entry block")?;
    println!("blocks={} entry={}", blocks.len(), ordinal_of(&blocks, &entry));
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
            "block={} ops={} d0={} d1={} in={} out={}",
            ordinal,
            ops,
            delta_string(start, address),
            delta_string(stop, address),
            format_edges(&blocks, block, false),
            format_edges(&blocks, block, true),
        );
    }

    let base = address;
    let operations: Vec<&rudra::op::PcodeOpRef> = fd.obank.optree.iter().collect();
    println!("ops={}", operations.len());
    for (index, op_ref) in operations.iter().enumerate() {
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
        let space_ref = matches!(op.opcode, OpCode::CPUI_LOAD | OpCode::CPUI_STORE);
        let in0 = op.inrefs.first();
        let in1 = op.inrefs.get(1);
        println!(
            "op={} d={} t={} opc={} sb={} blk={} in0={} in1={} out={}",
            index,
            delta_string(op.get_addr().as_u64(), base),
            op.get_time(),
            op.get_opcode() as i32,
            if (op.flags & pcodeop_flags::STARTBASIC) != 0 { 1 } else { 0 },
            blk,
            varnode_token(in0, space_ref),
            varnode_token(in1, space_ref),
            varnode_token(op.output.as_ref(), false),
        );
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 9 {
        return Err("usage: flow_inject_1204 TEXT TEXT_BASE ADDR0 SIZE0 ADDR1 SIZE1 ADDR2 SIZE2".into());
    }

    let image = fs::read(&args[1])?;
    let image_base = parse_u64(&args[2])?;
    for (case_index, (name, opname, userop_index, snippet)) in CASES.iter().enumerate() {
        let address = parse_u64(&args[3 + 2 * case_index])?;
        let size = parse_u64(&args[4 + 2 * case_index])? as usize;
        observe(name, opname, *userop_index, snippet, &image, image_base, address, size)?;
    }
    Ok(())
}
