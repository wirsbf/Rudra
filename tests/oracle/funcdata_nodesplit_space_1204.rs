//! FUNCDATA-NODESPLIT-SPACE-0001 Rudra comparand — Funcdata::node_split /
//! CloneBlockOps::build_varnode_output full-address clone semantics,
//! mirroring tests/oracle/funcdata_nodesplit_space_1204.cc case for case
//! against the locked Ghidra 12.0.4 oracle. Records: blocks/clone/orig
//! projections for N1 (inedge=0, full matrix), N2 (inedge=1), N3 (minimal).

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::addl_flags;
use rudra::varnode::varnode_flags;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

/// build_varnode_output copy mask (funcdata_block.cc:990-993) plus
/// out-of-mask sentinels that must NOT reach the clone: mapped, directwrite,
/// unaffected.
const VFLAG_PROJ: u32 = varnode_flags::EXTERNREF
    | varnode_flags::VOLATIL
    | varnode_flags::INCIDENTAL_COPY
    | varnode_flags::READONLY
    | varnode_flags::PERSIST
    | varnode_flags::ADDRTIED
    | varnode_flags::ADDRFORCE
    | varnode_flags::NOLOCALALIAS
    | varnode_flags::SPACEBASE
    | varnode_flags::INDIRECT_CREATION
    | varnode_flags::RETURN_ADDRESS
    | varnode_flags::PRECISLO
    | varnode_flags::PRECISHI
    | varnode_flags::MAPPED
    | varnode_flags::DIRECTWRITE
    | varnode_flags::UNAFFECTED;
/// addlflag fold mask (funcdata_block.cc:996) plus out-of-mask sentinels:
/// ptrcheck, activeheritage.
const AFL_PROJ: u16 = addl_flags::WRITE_MASK
    | addl_flags::PTR_FLOW
    | addl_flags::STACK_STORE
    | addl_flags::PTR_CHECK
    | addl_flags::ACTIVE_HERITAGE;

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

    fn alloc_pc(&mut self) -> Address {
        let a = Address::new(self.next_pc);
        self.next_pc += 8;
        a
    }

    /// Written varnode at an explicit address — the fixture's IR-builder leg
    /// mirroring the C++ fixture's `fd.newVarnodeOut(size, Address(space,
    /// offset), op)`. Uses the space-preserving port so fixture originals are
    /// built exactly like the oracle's (assignHigh/laned/queryProperties legs
    /// are no-ops on a fresh Funcdata: highlevel off, no laned specs, empty
    /// scopes).
    fn make_out(
        &self,
        fd: &mut Funcdata,
        size: usize,
        space: AddressSpace,
        offset: u64,
        op: &PcodeOpRef,
    ) -> VarnodeRef {
        fd.new_varnode_out_full(size, space, Address::new(offset), op)
    }
}

fn vn_desc(vn: Option<&VarnodeRef>) -> String {
    match vn {
        None => "-".to_string(),
        Some(vn) => {
            let r = vn.read().unwrap();
            format!("{}:{:x}/{}", r.get_space().name(), r.get_offset(), r.get_size())
        }
    }
}

fn op_seq(op: &PcodeOpRef) -> String {
    let r = op.0.read().unwrap();
    let sq = r.get_seq_num();
    format!("{:x}:{}", sq.get_addr().as_u64(), sq.get_time())
}

fn ptr_eq(a: &VarnodeRef, b: &VarnodeRef) -> bool {
    Arc::ptr_eq(a, b)
}

/// Input provenance against the PRE-SPLIT snapshot: "clone<k>" when the
/// pointer equals a cloned op output (patchInputs cc:1078-1084 remap),
/// "same" when it equals the original op's same-slot input (constant/plain
/// share cc:1071-1072/1085), "orig<k>.<i>" when it equals another pre-split
/// original input (MULTIEQUAL->COPY inedge pick cc:1056), else "ext".
fn input_source(
    vn: &VarnodeRef,
    clone_outs: &[Option<VarnodeRef>],
    orig_ins: &[Vec<Option<VarnodeRef>>],
    slot: usize,
) -> String {
    for (k, out) in clone_outs.iter().enumerate() {
        if let Some(out) = out {
            if ptr_eq(vn, out) {
                return format!("clone{k}");
            }
        }
    }
    for (k, ins) in orig_ins.iter().enumerate() {
        for (i, cand) in ins.iter().enumerate() {
            if let Some(cand) = cand {
                if ptr_eq(vn, cand) {
                    if i == slot {
                        return "same".to_string();
                    }
                    return format!("orig{k}.{i}");
                }
            }
        }
    }
    "ext".to_string()
}

struct Snapshot {
    ops: Vec<PcodeOpRef>,
    ins: Vec<Vec<Option<VarnodeRef>>>,
}

fn run_case(case_id: &str, inedge: usize, full: bool, baseaddr: u64) {
    let mut fd = Funcdata::new(&format!("nodesplit_{case_id}"), Address::new(baseaddr), 0x100);
    let mut f = Fixture::new();

    let prea = f.make_block(&mut fd); // b in[0]
    let preb = f.make_block(&mut fd); // b in[1]
    let b = f.make_block(&mut fd);
    f.edge(&mut fd, &prea, &b);
    f.edge(&mut fd, &preb, &b);

    // Exterior writers (outside b; their varnodes must be SHARED into clones).
    let vn_a;
    let vn_b;
    let vn_ext;
    {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        vn_a = f.make_out(&mut fd, 4, AddressSpace::Unique, 0x1000, &op);
        let c11 = fd.new_constant(4, 0x11);
        fd.op_set_input(&op, c11, 0);
        fd.op_insert_end(&op, &prea);
    }
    {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        vn_ext = f.make_out(&mut fd, 4, AddressSpace::Unique, 0x5000, &op);
        let c55 = fd.new_constant(4, 0x55);
        fd.op_set_input(&op, c55, 0);
        fd.op_insert_end(&op, &prea);
    }
    {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        vn_b = f.make_out(&mut fd, 4, AddressSpace::Unique, 0x2000, &op);
        let c22 = fd.new_constant(4, 0x22);
        fd.op_set_input(&op, c22, 0);
        fd.op_insert_end(&op, &preb);
    }

    // op0: MULTIEQUAL (patch_inputs turns it into a single-input COPY on both
    // the clone and the original).
    let mq_out;
    let mut add_out: Option<VarnodeRef> = None;
    {
        let mq = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&mq, OpCode::CPUI_MULTIEQUAL);
        mq_out = f.make_out(&mut fd, 4, AddressSpace::Unique, 0x3000, &mq);
        fd.op_set_input(&mq, vn_a.clone(), 0);
        fd.op_set_input(&mq, vn_b.clone(), 1);
        fd.op_insert_end(&mq, &b);
    }
    if full {
        // op1: INT_ADD reading the in-block MULTIEQUAL output (clone input
        // must remap to the clone's own COPY output).
        let add = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&add, OpCode::CPUI_INT_ADD);
        add_out = Some(f.make_out(&mut fd, 4, AddressSpace::Unique, 0x4000, &add));
        fd.op_set_input(&add, mq_out.clone(), 0);
        let c41 = fd.new_constant(4, 0x41);
        fd.op_set_input(&add, c41, 1);
        fd.op_insert_end(&add, &b);
        // op2: COPY with a ram persist|addrtied output — the F1 global
        // write-back shape (mapped|unaffected are out-of-mask sentinels).
        let cp = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&cp, OpCode::CPUI_COPY);
        let ram_out = f.make_out(&mut fd, 8, AddressSpace::Ram, 0x1000, &cp);
        ram_out.write().unwrap().set_flags(
            varnode_flags::PERSIST
                | varnode_flags::ADDRTIED
                | varnode_flags::MAPPED
                | varnode_flags::UNAFFECTED,
        );
        fd.op_set_input(&cp, vn_ext.clone(), 0);
        fd.op_insert_end(&cp, &b);
        // op3: COPY with a register output carrying in-mask (volatil) and
        // out-of-mask (directwrite) flags plus in-mask (writemask|ptrflow|
        // stack_store) and out-of-mask (ptrcheck) addlflags.
        let cr = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&cr, OpCode::CPUI_COPY);
        let reg_out = f.make_out(&mut fd, 4, AddressSpace::Register, 0x200, &cr);
        reg_out
            .write()
            .unwrap()
            .set_flags(varnode_flags::VOLATIL | varnode_flags::DIRECTWRITE);
        reg_out.write().unwrap().addlflags |= addl_flags::WRITE_MASK
            | addl_flags::PTR_FLOW
            | addl_flags::STACK_STORE
            | addl_flags::PTR_CHECK;
        let c77 = fd.new_constant(4, 0x77);
        fd.op_set_input(&cr, c77, 0);
        fd.op_insert_end(&cr, &b);
    }
    {
        // last op: STORE (no output — build_varnode_output early-return path).
        let st = fd.new_op(3, f.alloc_pc());
        fd.op_set_opcode(&st, OpCode::CPUI_STORE);
        fd.op_set_input(&st, vn_ext.clone(), 0);
        let c9000 = fd.new_constant(8, 0x9000);
        fd.op_set_input(&st, c9000, 1);
        let value = add_out.as_ref().unwrap_or(&mq_out).clone();
        fd.op_set_input(&st, value, 2);
        fd.op_insert_end(&st, &b);
    }

    // Pre-split snapshot.
    let snap = {
        let ops = {
            let rg = b.read().unwrap();
            match rg.as_any().downcast_ref::<rudra::block::BlockBasic>() {
                Some(bb) => bb.get_ops(),
                None => Vec::new(),
            }
        };
        let ins = ops
            .iter()
            .map(|op| {
                let r = op.0.read().unwrap();
                (0..r.num_input()).map(|i| r.get_in(i).cloned()).collect()
            })
            .collect();
        Snapshot { ops, ins }
    };
    // ARENAFLIP-(e): edge points are bank ids — resolve the source block
    // through the owning graph's bank.
    let a = b
        .read()
        .unwrap()
        .get_in(inedge)
        .map(|e| fd.bblocks.bank.expect_arc(e.point));
    let Some(a) = a else { panic!("split edge source missing") };

    fd.node_split(&b, inedge);

    // node_split_block_edge switched a's out edge to bprime; prea/preb each
    // have exactly one out edge, so bprime is a's sole out target.
    let bprime = {
        let rg = a.read().unwrap();
        rg.get_out(0)
            .map(|e| fd.bblocks.bank.expect_arc(e.point))
            .expect("split edge source lost its out edge")
    };

    let (bin, bprimein, bops, bprimeops) = {
        let br = b.read().unwrap();
        let pr = bprime.read().unwrap();
        (br.size_in(), pr.size_in(), block_op_count(&b), block_op_count(&bprime))
    };
    println!("blocks|case={case_id}|bin={bin}|bprimein={bprimein}|bops={bops}|bprimeops={bprimeops}");

    // Clone projections.
    let clone_ops = {
        let rg = bprime.read().unwrap();
        match rg.as_any().downcast_ref::<rudra::block::BlockBasic>() {
            Some(bb) => bb.get_ops(),
            None => Vec::new(),
        }
    };
    let clone_outs: Vec<Option<VarnodeRef>> = clone_ops
        .iter()
        .map(|op| op.0.read().unwrap().output.clone())
        .collect();
    for (k, op) in clone_ops.iter().enumerate() {
        let out = &clone_outs[k];
        let (opcode, seq, nin, inputs) = {
            let r = op.0.read().unwrap();
            let sq = r.get_seq_num().clone();
            let ins: Vec<VarnodeRef> =
                (0..r.num_input()).map(|i| r.get_in(i).cloned().unwrap()).collect();
            (r.opcode, sq, r.num_input(), ins)
        };
        let (fl, afl) = match out {
            Some(vn) => {
                let r = vn.read().unwrap();
                (r.flags & VFLAG_PROJ, r.addlflags & AFL_PROJ)
            }
            None => (0, 0),
        };
        let mut line = format!(
            "clone|case={case_id}|op={k}|opc={}|seq={}|out={}|fl=0x{fl:x}|afl=0x{afl:x}|nin={nin}",
            opcode.name(),
            format!("{:x}:{}", seq.get_addr().as_u64(), seq.get_time()),
            vn_desc(out.as_ref()),
        );
        for (i, vn) in inputs.iter().enumerate() {
            line.push_str(&format!(
                "|in{i}={}:{}",
                input_source(vn, &clone_outs, &snap.ins, i),
                vn_desc(Some(vn))
            ));
        }
        println!("{line}");
    }

    // Original-block projections after the split.
    let post_ops = {
        let rg = b.read().unwrap();
        match rg.as_any().downcast_ref::<rudra::block::BlockBasic>() {
            Some(bb) => bb.get_ops(),
            None => Vec::new(),
        }
    };
    for (k, op) in post_ops.iter().enumerate() {
        let (opcode, nin, ins) = {
            let r = op.0.read().unwrap();
            let ins: Vec<VarnodeRef> =
                (0..r.num_input()).map(|i| r.get_in(i).cloned().unwrap()).collect();
            (r.opcode, r.num_input(), ins)
        };
        let mut line =
            format!("orig|case={case_id}|op={k}|opc={}|nin={nin}", opcode.name());
        for (i, vn) in ins.iter().enumerate() {
            line.push_str(&format!("|in{i}={}", vn_desc(Some(vn))));
        }
        println!("{line}");
    }
}

fn block_op_count(blk: &BlockRef) -> usize {
    let rg = blk.read().unwrap();
    match rg.as_any().downcast_ref::<rudra::block::BlockBasic>() {
        Some(bb) => bb.get_ops().len(),
        None => 0,
    }
}

fn main() {
    run_case("N1", 0, true, 0x60000);
    run_case("N2", 1, true, 0x61000);
    run_case("N3", 0, false, 0x62000);
}
