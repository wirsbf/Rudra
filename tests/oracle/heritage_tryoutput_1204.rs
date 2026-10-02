// HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS: Rudra comparand for the locked
// Ghidra 12.0.4 oracle. Mirrors tests/oracle/heritage_tryoutput_1204.cc
// case for case:
//  - stack_output_contains_full: the production
//    Heritage::try_output_stack_guard output-contains branch
//    (src/heritage.rs, heritage.cc:1406-1430) driven directly on a real
//    Funcdata with one CALL op over the six trigger geometries. The
//    projection prints every op of the call block in insertion order with
//    the SUBPIECE in[1] constants — cc:1420, the fourth justifiedContain
//    touchpoint (LE start distances 0/2/4; BE end distances pinned by
//    case=cc1420_constant) — the created-vs-reused call output (cc:1411-
//    1416), the caller-perspective translation of the return storage
//    (cc:1407-1410: 0x1000 storage + 0x10 diff -> 0x1010), the write-list
//    entries with the vnFinal active-heritage flag (cc:1426-1429), and the
//    cc:1430 return value (true even for the no-op geometry 5).
//    The pre-state is the production one end to end: the call spec's
//    FuncProto carries a locked non-void output whose proto-store storage
//    is installed by set_output_parameter (ProtoStoreInternal::setOutput
//    shape, fspec.cc:3380-3387) in the stack space; the return storage
//    itself and the outputCharacter classification are read back through
//    the production accessors — FuncCallSpecs::get_output_storage (the
//    getOutput() cc:1407/cc:1410 reads now live inside
//    try_output_stack_guard) and FuncProto::characterize_as_output's
//    locked branch (fspec.cc:4339-4353). No staged tuples remain.
//  - cc1420_constant: the exact cc:1420 call shape
//    retAddr.justifiedContain(retSize, addr, size, false) through
//    rudra::fspec::justified_contain_range on the caller-perspective
//    return storage in both endian routings — LE rows take the stack
//    space's endianness exactly as src/heritage.rs does, BE rows pass true
//    (helper-level big-endian pinning; the transitional enum space cannot
//    stage a BE stack, the same convention as
//    heritage_subpiece_const_1204).
//  - output_storage_projection: the locked-output storage reads of the
//    newly ported fspec locked branches —
//    FuncProto::characterize_as_output (fspec.cc:4339-4353) and
//    FuncProto::get_biggest_contained_output (fspec.cc:4495-4506) — over
//    five containment geometries against the recorded (stack, 0x1000, 8)
//    storage: justified subrange, unjustified subrange, disjoint range,
//    a 16-byte range containing the storage (the cc:1398
//    getBiggestContainedOutput trigger), and a partial overlap.
//  - production_entry_guardcalls: the full production entry — the
//    ActionFuncLink::funcLinkOutput producer (coreaction.cc:1538-1553:
//    reads the locked outparam storage; spacebase storage ->
//    setStackOutputLock(true) and the output varnode is delayed; register
//    storage -> newVarnodeOut immediately) followed by
//    Heritage::guard_calls (heritage.cc:1443-1527) over the guarded stack
//    range with the cc:1466 spacebase rebase (stackoffset 0x10). The
//    stack-lock geometry upgrades the effect to unaffected: NO INDIRECT
//    op, the call output is created caller-perspective and truncated by
//    SUBPIECE; the register-storage control geometry keeps
//    unknown_effect: an INDIRECT op guards the range (cc:1511-1519).

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::coreaction::ActionFuncLink;
use rudra::fspec::containment;
use rudra::fspec::{FuncCallSpecs, FuncProto, ParameterPieces};
use rudra::funcdata::Funcdata;
use rudra::heritage::Heritage;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<rudra::varnode::Varnode>>;

fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

// The locked return type: a base int of the given size (the C++ oracle's
// arch.types->getBase(retsz, TYPE_INT)).
fn int_type(size: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        format!("int{size}"),
        size,
        TypeMetatype::Int,
    )))
}

// Varnode descriptor shared with the C++ oracle (see its file header):
//   constant -> c<size>(<value>); iop -> IOP;
//   other    -> <hexoffset>:<size>:<I|W|F>{ah}
// Space letters are not printed (the transitional new_varnode_out register
// space divergence is a registered projected-away residual).
fn vn_descriptor(vn: Option<&VnRef>) -> String {
    let Some(vn) = vn else {
        return "-".to_string();
    };
    let value = vn.read().unwrap();
    if value.is_constant() {
        return format!("c{}({})", value.size, value.get_offset());
    }
    if value.get_space() == AddressSpace::Iop {
        return "IOP".to_string();
    }
    let state = if value.is_input() {
        'I'
    } else if value.is_written() {
        'W'
    } else {
        'F'
    };
    let flags = if value.is_active_heritage() { "ah" } else { "" };
    format!("{:x}:{}:{}{{{}}}", value.get_offset(), value.size, state, flags)
}

// The guarded range lives at caller stack 0x101x; the callee perspective is
// 0x100x (stackoffset 0x10, the guardCalls cc:1466-1468 rebase shape), and
// the locked return storage sits at callee 0x1000 with 8 bytes — the
// caller perspective return storage is [0x1010, 0x1018).
const STACK_DIFF: u64 = 0x10;
const RET_STORAGE: u64 = 0x1000;

#[derive(Clone, Copy)]
struct ToGeom {
    addr: u64,
    size: i32,
    retsz: i32,
    pre_out: bool,
}

// The same six trigger geometries as the C++ oracle, in the same order.
const TO: [ToGeom; 6] = [
    ToGeom { addr: 0x1010, size: 4, retsz: 8, pre_out: false },
    ToGeom { addr: 0x1012, size: 4, retsz: 8, pre_out: false },
    ToGeom { addr: 0x1014, size: 4, retsz: 8, pre_out: false },
    ToGeom { addr: 0x1010, size: 8, retsz: 8, pre_out: false },
    ToGeom { addr: 0x1010, size: 4, retsz: 8, pre_out: true },
    ToGeom { addr: 0x1010, size: 8, retsz: 8, pre_out: true },
];

// Install the production pre-state of the guardCalls cc:1487 gate on a
// fresh call spec: a locked non-void output whose proto-store storage
// (space, offset) is recorded through set_output_parameter — the
// FuncCallSpecs::setOutput + setOutputLock shape of the C++ oracle's
// runTryCase (ProtoStoreInternal::setOutput installs the address,
// fspec.cc:3385). Returns the call spec index.
fn install_locked_output(
    fd: &mut Funcdata,
    call: &rudra::op::PcodeOpRef,
    retsz: usize,
    storage_space: AddressSpace,
    storage_off: u64,
) -> usize {
    let mut proto = FuncProto::new(String::new(), void_type());
    let pieces = ParameterPieces {
        addr: Address::new(storage_off),
        ty: Some(int_type(retsz)),
        flags: 0,
    };
    proto.set_output_parameter(pieces, storage_space);
    proto.set_output_lock(true);
    let fc = FuncCallSpecs::new_for_op(call, proto);
    fd.add_call_specs(fc)
}

// Print every op of the call block in insertion order plus the write
// entries — the shared projection of cases 1 and 4.
fn print_block_projection(block: &BlockRef, write: &[VnRef]) {
    let ops = block.read().unwrap().get_ops();
    for (pos, op) in ops.iter().enumerate() {
        let o = op.0.read().unwrap();
        let mut inputs = String::new();
        for slot in 0..o.num_input() {
            if slot != 0 {
                inputs.push(',');
            }
            inputs.push_str(&vn_descriptor(o.get_in(slot)));
        }
        // Opcode number, not name (mirrors the C++ oracle: CALL=7,
        // INDIRECT=61, SUBPIECE=63 are identical on both sides).
        println!(
            "  op{pos} {} in=[{inputs}] out={}",
            o.opcode as i32,
            vn_descriptor(o.output.as_ref())
        );
    }
    for (i, entry) in write.iter().enumerate() {
        println!("  write{i} {}", vn_descriptor(Some(entry)));
    }
}

// Drive the production try_output_stack_guard on one geometry and print
// the full op projection of the call block plus the write entries.
fn run_try_case(index: usize, g: ToGeom) {
    let base = 0x6000 + 0x10 * index as u64;
    let mut fd = Funcdata::new("to", Address::new(base), 0x20);
    let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
        0,
        Address::new(base),
    )));
    fd.bblocks.add_block(block.clone());
    let call = fd.new_op(1, Address::new(base));
    fd.op_set_opcode(&call, OpCode::CPUI_CALL);
    // FuncCallSpecs::new_for_op reads the direct-call target from in(0).
    let target = fd.new_constant(8, 0x4000);
    fd.op_set_input(&call, target, 0);
    fd.op_insert_end(&call, &block);
    if g.pre_out {
        fd.new_varnode_out(g.retsz as usize, Address::new(RET_STORAGE + STACK_DIFF), &call);
    }

    // Production pre-state (see install_locked_output): the storage is
    // read back by the production accessors below, nothing is staged.
    let fc_idx = install_locked_output(&mut fd, &call, g.retsz as usize, AddressSpace::Stack, RET_STORAGE);

    // Production outputCharacter: the cc:1488 call shape
    // fc.characterizeAsOutput(transAddr, size) — the locked branch reads
    // the recorded storage (fspec.cc:4339-4353). Every geometry of this
    // fixture is contained, mirroring the guardCalls cc:1489 gate.
    let trans = g.addr - STACK_DIFF;
    let occ = fd
        .get_call_specs(fc_idx)
        .map(|fc| fc.characterize_as_output(AddressSpace::Stack, trans, g.size))
        .unwrap_or(containment::NO_CONTAINMENT);

    let mut write: Vec<VnRef> = Vec::new();
    let mut heritage = Heritage::new();
    let res = heritage.try_output_stack_guard(
        &mut fd,
        fc_idx,
        AddressSpace::Stack,
        Address::new(g.addr),
        trans,
        g.size,
        occ,
        &mut write,
    );

    println!(
        "to geom={index} addr={:x} size={} ret={:x} retsz={} diff={} retc={:x} occ={} res={}",
        g.addr, g.size, RET_STORAGE, g.retsz, STACK_DIFF, RET_STORAGE + STACK_DIFF, occ,
        u8::from(res)
    );
    print_block_projection(&block, &write);
}

// Containment geometries for the locked-branch storage reads (offsets are
// callee-perspective; storage = (stack, 0x1000, 8)):
//   0: justified subrange      -> contains_justified, biggest=-
//   1: unjustified at +2       -> contains_unjustified, biggest=-
//   2: disjoint at +8          -> no_containment, biggest=-
//   3: 16-byte range holding   -> contained_by, biggest=1000:8
//      the storage (the cc:1398 getBiggestContainedOutput trigger)
//   4: partial overlap at +2/8 -> no_containment, biggest=-
#[derive(Clone, Copy)]
struct PrGeom {
    off: u64,
    size: i32,
}
const PR: [PrGeom; 5] = [
    PrGeom { off: 0x1000, size: 4 },
    PrGeom { off: 0x1002, size: 4 },
    PrGeom { off: 0x1008, size: 4 },
    PrGeom { off: 0x0ff8, size: 16 },
    PrGeom { off: 0x1002, size: 8 },
];

// Drive the production locked-output storage reads —
// FuncProto::characterize_as_output and get_biggest_contained_output —
// over the containment geometries (the C++ oracle's fc->
// characterizeAsOutput / fc->getBiggestContainedOutput locked branches).
fn run_projection_case() {
    let mut fd = Funcdata::new("pr", Address::new(0x6800), 0x20);
    let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
        0,
        Address::new(0x6800),
    )));
    fd.bblocks.add_block(block.clone());
    let call = fd.new_op(1, Address::new(0x6800));
    fd.op_set_opcode(&call, OpCode::CPUI_CALL);
    let target = fd.new_constant(8, 0x4000);
    fd.op_set_input(&call, target, 0);
    fd.op_insert_end(&call, &block);
    let fc_idx = install_locked_output(&mut fd, &call, 8, AddressSpace::Stack, RET_STORAGE);

    for (index, g) in PR.iter().enumerate() {
        let (occ, biggest) = match fd.get_call_specs(fc_idx) {
            Some(fc) => (
                fc.characterize_as_output(AddressSpace::Stack, g.off, g.size),
                fc.prototype
                    .get_biggest_contained_output(AddressSpace::Stack, g.off, g.size),
            ),
            None => (containment::NO_CONTAINMENT, None),
        };
        let biggest_text = match biggest {
            Some((_, off, size)) => format!("{off:x}:{size}"),
            None => "-".to_string(),
        };
        println!("  pr geom={index} off={:x} size={} occ={occ} biggest={biggest_text}", g.off, g.size);
    }
}

// Drive the full production entry for one call spec: the
// ActionFuncLink::funcLinkOutput producer (coreaction.cc:1538-1553) then
// Heritage::guard_calls over the guarded stack range (heritage.cc:1443-
// 1527, fl=0, stackoffset 0x10). stack_space=true stages the locked
// storage in the spacebase space (the setStackOutputLock path); false
// stages it in the register space (the immediate-newVarnodeOut control).
fn run_guard_case(index: usize, stack_space: bool) {
    let base = 0x6100 + 0x10 * index as u64;
    let mut fd = Funcdata::new("gc", Address::new(base), 0x20);
    let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
        0,
        Address::new(base),
    )));
    fd.bblocks.add_block(block.clone());
    let call = fd.new_op(1, Address::new(base));
    fd.op_set_opcode(&call, OpCode::CPUI_CALL);
    let target = fd.new_constant(8, 0x4000);
    fd.op_set_input(&call, target, 0);
    fd.op_insert_end(&call, &block);

    let (space, off) = if stack_space {
        (AddressSpace::Stack, RET_STORAGE)
    } else {
        (AddressSpace::Register, 0x0)
    };
    let fc_idx = install_locked_output(&mut fd, &call, 8, space, off);
    // cc:1466-1465: the spacebase rebase offset (FuncCallSpecs::
    // setSpacebaseRelative shape) — caller 0x101x == callee 0x100x + 0x10.
    if let Some(mut fc) = fd.get_call_specs_mut(fc_idx) {
        fc.set_spacebase_offset(STACK_DIFF as i64);
    }
    // The producer: coreaction.cc:1521 funcLinkOutput. For the spacebase
    // storage this sets the stack-output lock and delays the output
    // varnode; for the register storage it creates the output varnode
    // immediately at the recorded offset.
    ActionFuncLink::func_link_output(&mut fd, fc_idx, &call);
    let (stacklock, pre_out) = match fd.get_call_specs(fc_idx) {
        Some(fc) => (
            u8::from(fc.is_stack_output_lock()),
            u8::from(call.0.read().unwrap().output.is_some()),
        ),
        None => (0, 0),
    };
    println!(
        "gc geom={index} stackspace={} stacklock={stacklock} pre_out={pre_out}",
        u8::from(stack_space)
    );

    let mut write: Vec<VnRef> = Vec::new();
    let mut heritage = Heritage::new();
    heritage.guard_calls(
        &mut fd,
        0,
        AddressSpace::Stack,
        Address::new(0x1010),
        4,
        &mut write,
    );
    print_block_projection(&block, &write);
}

fn main() {
    println!("schema=1|fixture=HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // ---- case 1: production try_output_stack_guard, output-contains ----
    println!("case=stack_output_contains_full");
    for (index, g) in TO.iter().enumerate() {
        run_try_case(index, *g);
    }

    // ---- case 2: cc:1420 constants in LE and BE routings ----------------
    println!("case=cc1420_constant");
    for (index, g) in TO.iter().enumerate() {
        let retc = RET_STORAGE + STACK_DIFF;
        // The exact cc:1420 call shape: container = the caller-perspective
        // return storage, contained = the guarded range, forceleft=false.
        // LE rows take the stack space's endianness exactly as the fixed
        // src/heritage.rs does, BE rows pass true.
        let amt = |be: bool| {
            rudra::fspec::justified_contain_range(retc, g.retsz, g.addr, g.size, false, be)
        };
        println!(
            "  sp geom={index} le={} be={}",
            amt(AddressSpace::Stack.is_big_endian()),
            amt(true),
        );
    }

    // ---- case 3: locked-output storage reads (fspec locked branches) ----
    println!("case=output_storage_projection");
    run_projection_case();

    // ---- case 4: production entry — funcLinkOutput + guardCalls ---------
    println!("case=production_entry_guardcalls");
    run_guard_case(0, true);
    run_guard_case(1, false);
}
