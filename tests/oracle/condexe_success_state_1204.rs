//! CONDEXE-SUCCESS-STATE-0001 Rudra comparand — the ConditionalExecution
//! success channel (condexe.cc:23-37 buildHeritageArray, condexe.cc:392 the
//! heritageyes gate, condexe.cc:339-349 the space-preserving RETURN
//! replacement, condexe.cc:478-503 live BlockGraph traversal and
//! numhits -> Action::count), mirroring
//! tests/oracle/condexe_success_state_1204.cc case for case against the
//! locked Ghidra 12.0.4 oracle. Records: heritage S1p0..S1p3 (per-space
//! array at heritage pass 0/1/2/3), pre/ret/state/multi/edges S2 (the
//! 3-diamond chain whose live index walk folds A, B, C — count=3, reciprocal
//! pre->post relinks), ret/return S3 (RETURN input preservation through a
//! unique-space COPY), ret S4p0/S4p1 (the cc:392 heritageyes gate rejects
//! at pass 0 and admits at pass 1).

use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::condexe::{ActionConditionalExe, ConditionalExecution};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

fn space_name(spc: AddressSpace) -> &'static str {
    match spc {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        _ => "other",
    }
}

fn vname(vn: &VarnodeRef) -> String {
    let r = vn.read().unwrap();
    format!("{}:0x{:x}:{}", space_name(r.get_space()), r.get_offset(), r.get_size())
}

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

    /// Written varnode at an explicit address: the fixture's own IR-builder
    /// leg, mirroring the C++ fixture's `fd.newVarnodeOut(size,
    /// Address(space, offset), op)` (Rudra's `create_def_with_space` does
    /// not set the op's output field, so it is set here exactly like the
    /// oracle's newVarnodeOut does).
    fn make_out(
        &self,
        fd: &mut Funcdata,
        size: usize,
        space: AddressSpace,
        offset: u64,
        op: &rudra::op::PcodeOpRef,
    ) -> VarnodeRef {
        let vn = fd.vbank.create_def_with_space(size, space, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    fn make_cbranch_at(
        &mut self,
        fd: &mut Funcdata,
        blk: &BlockRef,
        boolvn: &VarnodeRef,
        at: Address,
    ) {
        let op = fd.new_op(2, at);
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, 0x4000);
        fd.op_set_input(&op, target, 0);
        fd.op_set_input(&op, boolvn.clone(), 1);
        fd.op_insert_end(&op, blk);
    }

    fn name_of(&self, blk: &BlockRef) -> String {
        for (i, b) in self.blocks.iter().enumerate() {
            if Arc::ptr_eq(b, blk) {
                return format!("b{i}");
            }
        }
        "x".to_string()
    }

    /// Current-graph inventory: iterates the LIVE block list, naming each
    /// block by its creation ordinal.
    fn graph_inventory(&self, fd: &Funcdata) -> String {
        let mut parts = Vec::new();
        for i in 0..fd.bblocks.get_size() {
            if let Some(bb) = fd.bblocks.get_block(i) {
                let n = self.blocks.iter().enumerate()
                    .find(|(_, b)| Arc::ptr_eq(b, &bb))
                    .map(|(idx, _)| format!("b{idx}"))
                    .unwrap_or_else(|| "x".to_string());
                let count = bb.read().unwrap().get_ops().len();
                parts.push(format!("{n}:{count}"));
            }
        }
        parts.join(",")
    }

    fn ops_of(blk: &BlockRef) -> String {
        let ops = blk.read().unwrap().get_ops();
        ops.iter()
            .map(|o| o.0.read().unwrap().opcode.name().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The MULTIEQUAL ops still alive in a block: (output unique offset for
    /// creation-order sorting, input projection list), in op-list order.
    fn multis_of(blk: &BlockRef) -> Vec<(u64, String)> {
        let ops = blk.read().unwrap().get_ops();
        let mut result = Vec::new();
        for o in &ops {
            let (opcode, out, ins) = {
                let r = o.0.read().unwrap();
                (r.opcode, r.output.clone(), {
                    let mut v = Vec::new();
                    for i in 0..r.num_input() {
                        if let Some(vn) = r.get_in(i) {
                            v.push(vname(vn));
                        }
                    }
                    v.join("+")
                })
            };
            if opcode != OpCode::CPUI_MULTIEQUAL {
                continue;
            }
            let off = out.map(|o| o.read().unwrap().get_offset()).unwrap_or(0);
            result.push((off, ins));
        }
        result
    }
}

// ---------------------------------------------------------------------------
// S1: per-space buildHeritageArray (condexe.cc:23-37), heritage pass 0..3.
// ---------------------------------------------------------------------------
fn run_heritage_case(case_id: &str, pass: i32) {
    let mut fd = Funcdata::new(case_id, Address::new(0x60000), 0x100);
    // The C++ fixture calls fd.heritage.buildInfoList() and drives the pass
    // counter (heritage.cc:218-224, cc:2664-2672); Rudra mirrors both.
    fd.heritage.build_info_list();
    fd.heritage.pass = pass;
    let names = ConditionalExecution::fixture_heritage_space_names();
    let arr = ConditionalExecution::fixture_heritage_array(&fd);
    // The shared heritaged spaces both sides model, in the fixed print
    // order: ram, register, unique, stack (CONDEXE_SPACE_LIST indices
    // 0/1/2/4).
    let print_idx = [0usize, 1, 2, 4];
    let mut line = format!("heritage|case={case_id}");
    for &i in &print_idx {
        line.push_str(&format!("|{}={}", names[i], if arr[i] { 1 } else { 0 }));
    }
    println!("{line}");
}

// ---------------------------------------------------------------------------
// S2: live BlockGraph traversal + numhits -> Action::count
// (condexe.cc:487-501). See the C++ fixture's Chain comment for the full
// 19-block creation-order / edge-order contract.
// ---------------------------------------------------------------------------
struct Chain {
    fixture: Fixture,
    init: Vec<BlockRef>,
    ib: Vec<BlockRef>,
    merge: Vec<BlockRef>,
    pre1: Vec<BlockRef>,
    pre2: Vec<BlockRef>,
}

fn build_chain(fd: &mut Funcdata) -> Chain {
    let mut f = Fixture::new();
    let b: Vec<BlockRef> = (0..19).map(|_| f.make_block(fd)).collect();
    // Edges in EXACTLY this order (slot 0/1 assignment is load-bearing for
    // init2a_true / camethruposta_slot / the reciprocal relinks).
    for d in 0..3 {
        // init[d] -> pre1[d], pre2[d]; pre -> ib; ib -> posta/postb.
        // Diamond in-edges:  b0/b1/b2 (A), b8/b9/b10 (B), b13/b14/b15 (C).
        let (i0, p1, p2, ib) = match d {
            0 => (0usize, 1usize, 2usize, 3usize),
            1 => (8, 9, 10, 4),
            _ => (13, 14, 15, 5),
        };
        let (posta, postb) = match d {
            0 => (6usize, 7usize),
            1 => (11, 12),
            _ => (16, 17),
        };
        f.edge(fd, &b[i0], &b[p1]);
        f.edge(fd, &b[i0], &b[p2]);
        f.edge(fd, &b[p1], &b[ib]);
        f.edge(fd, &b[p2], &b[ib]);
        f.edge(fd, &b[ib], &b[posta]);
        f.edge(fd, &b[ib], &b[postb]);
    }
    // A's posts flow into B's init; B's into C's init; C's into exit_merge.
    f.edge(fd, &b[6], &b[8]);
    f.edge(fd, &b[7], &b[8]);
    f.edge(fd, &b[11], &b[13]);
    f.edge(fd, &b[12], &b[13]);
    f.edge(fd, &b[16], &b[18]);
    f.edge(fd, &b[17], &b[18]);
    // Per-diamond ops: bool COPY + init CBRANCH, iblock MULTIEQUAL +
    // CBRANCH, reader COPY in the next merge block.
    let mut boolvns: Vec<VarnodeRef> = Vec::new();
    let inits = [0usize, 8, 13];
    for (d, &i0) in inits.iter().enumerate() {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let out = f.make_out(fd, 1, AddressSpace::Unique, 0x900 + 0x10 * d as u64, &op);
        let c = fd.new_constant(1, d as u64 + 1);
        fd.op_set_input(&op, c, 0);
        fd.op_insert_end(&op, &b[i0]);
        boolvns.push(out);
    }
    let ibs = [3usize, 4, 5];
    let merges = [8usize, 13, 18];
    for (d, (&ib, &mg)) in ibs.iter().zip(merges.iter()).enumerate() {
        let multi = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&multi, OpCode::CPUI_MULTIEQUAL);
        let vn_x = f.make_out(fd, 4, AddressSpace::Unique, 0x2000 + 0x10 * d as u64, &multi);
        let c1 = fd.new_constant(4, 5);
        let c2 = fd.new_constant(4, 9);
        fd.op_set_input(&multi, c1, 0);
        fd.op_set_input(&multi, c2, 1);
        fd.op_insert_end(&multi, &b[ib]);
        let at = f.alloc_pc();
        f.make_cbranch_at(fd, &b[ib], &boolvns[d], at);
        let reader = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&reader, OpCode::CPUI_COPY);
        fd.op_set_input(&reader, vn_x, 0);
        fd.op_insert_end(&reader, &b[mg]);
        let at_init = f.alloc_pc();
        f.make_cbranch_at(fd, &b[inits[d]], &boolvns[d], at_init);
    }
    Chain {
        init: inits.iter().map(|&i| b[i].clone()).collect(),
        ib: ibs.iter().map(|&i| b[i].clone()).collect(),
        merge: merges.iter().map(|&i| b[i].clone()).collect(),
        pre1: [1usize, 9, 14].iter().map(|&i| b[i].clone()).collect(),
        pre2: [2usize, 10, 15].iter().map(|&i| b[i].clone()).collect(),
        fixture: f,
    }
}

fn run_live_traversal_case() {
    let case_id = "S2";
    let mut fd = Funcdata::new(case_id, Address::new(0x60000), 0x100);
    // The C++ fixture calls fd.heritage.buildInfoList() before apply (the
    // oracle Heritage::getInfo indexes the lazy infolist bare).
    fd.heritage.build_info_list();
    let chain = build_chain(&mut fd);
    // Production dominator computation before apply (single entry b0 ->
    // one root -> the cc:485-486 guard does NOT fire, proven by pre).
    fd.structure_reset();
    println!(
        "pre|case={case_id}|nblocks={}|order={}|unreach={}",
        fd.bblocks.get_size(),
        chain.fixture.graph_inventory(&fd),
        if fd.has_unreachable_blocks() { 1 } else { 0 }
    );
    let mut action = ActionConditionalExe::new();
    let r = action.apply(&mut fd).unwrap_or_else(|e| panic!("S2 apply failed: {e}"));
    // numhits -> Action::count (condexe.cc:501), harvested exactly like
    // Action::perform does (action.rs take_count_delta).
    let count = action.take_count_delta();
    println!("ret|case={case_id}|apply={r}|count={count}");
    println!(
        "state|case={case_id}|nblocks={}|blocks={}",
        fd.bblocks.get_size(),
        chain.fixture.graph_inventory(&fd),
    );
    // The three new MULTIEQUALs (one per merge block), sorted by their
    // output unique offset = creation order: A (round 1), B (round 1 after
    // the post-A relist), C (round 1 after the post-B relist) — b8, b13,
    // b18. The order is computed side-locally (monotonic unique allocator),
    // so the projection stays pointer-free while pinning the fold sequence.
    let mut entries: Vec<(u64, String, String)> = Vec::new(); // (off, block, detail)
    for (d, mg) in chain.merge.iter().enumerate() {
        for (off, ins) in Fixture::multis_of(mg) {
            let name = chain.fixture.name_of(mg);
            entries.push((off, name.clone(), format!("{name}_in={ins}")));
            let _ = d;
        }
    }
    entries.sort_by_key(|(off, _, _)| *off);
    let order = entries.iter().map(|(_, b, _)| b.clone()).collect::<Vec<_>>().join(",");
    let mut line = format!("multi|case={case_id}|order={order}");
    for (_, _, detail) in &entries {
        line.push('|');
        line.push_str(detail);
    }
    println!("{line}");
    // Reciprocal pre->post relinks of the three removeFromFlowSplit calls
    // (swap=false: In(0)->Out(0)=posta, In(1)->Out(1)=postb, block.cc:1584-1589).
    let mut edges = format!("edges|case={case_id}");
    for d in 0..3 {
        let mut pair = String::new();
        for pre in [&chain.pre1[d], &chain.pre2[d]] {
            let p_name = chain.fixture.name_of(pre);
            let out0 = {
                let r = pre.read().unwrap();
                r.get_out(0).map(|e| chain.fixture.name_of(&e.point)).unwrap_or_else(|| "-".to_string())
            };
            if !pair.is_empty() {
                pair.push(';');
            }
            pair.push_str(&format!("{p_name}={out0}"));
        }
        edges.push('|');
        edges.push_str(&pair);
    }
    println!("{edges}");
}

// ---------------------------------------------------------------------------
// S3: space-preserving RETURN replacement (condexe.cc:339-349).
// ---------------------------------------------------------------------------
fn run_return_case() {
    let case_id = "S3";
    let mut fd = Funcdata::new(case_id, Address::new(0x60000), 0x100);
    fd.heritage.build_info_list();
    let mut f = Fixture::new();
    let b: Vec<BlockRef> = (0..6).map(|_| f.make_block(&mut fd)).collect();
    f.edge(&mut fd, &b[0], &b[1]);
    f.edge(&mut fd, &b[0], &b[2]);
    f.edge(&mut fd, &b[1], &b[3]);
    f.edge(&mut fd, &b[2], &b[3]);
    f.edge(&mut fd, &b[3], &b[4]);
    f.edge(&mut fd, &b[3], &b[5]);
    let boolvn = {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let out = f.make_out(&mut fd, 1, AddressSpace::Unique, 0x900, &op);
        let c = fd.new_constant(1, 1);
        fd.op_set_input(&op, c, 0);
        fd.op_insert_end(&op, &b[0]);
        out
    };
    let vn_r = {
        let multi = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&multi, OpCode::CPUI_MULTIEQUAL);
        let out = f.make_out(&mut fd, 4, AddressSpace::Unique, 0x2000, &multi);
        let c1 = fd.new_constant(4, 5);
        let c2 = fd.new_constant(4, 9);
        fd.op_set_input(&multi, c1, 0);
        fd.op_set_input(&multi, c2, 1);
        fd.op_insert_end(&multi, &b[3]);
        out
    };
    let at = f.alloc_pc();
    f.make_cbranch_at(&mut fd, &b[3], &boolvn, at);
    {
        let ret = fd.new_op(2, f.alloc_pc());
        fd.op_set_opcode(&ret, OpCode::CPUI_RETURN);
        let c = fd.new_constant(1, 0);
        fd.op_set_input(&ret, c, 0);
        fd.op_set_input(&ret, vn_r.clone(), 1);
        fd.op_insert_end(&ret, &b[4]);
    }
    let at_init = f.alloc_pc();
    f.make_cbranch_at(&mut fd, &b[0], &boolvn, at_init);
    fd.structure_reset();
    let mut action = ActionConditionalExe::new();
    let r = action.apply(&mut fd).unwrap_or_else(|e| panic!("S3 apply failed: {e}"));
    let count = action.take_count_delta();
    println!("ret|case={case_id}|apply={r}|count={count}");
    // Find the RETURN and the COPY feeding its input 1 (the new COPY is
    // inserted immediately before the RETURN, cc:345).
    let mut ret_in1 = String::new();
    let mut copy_out = String::new();
    let mut copy_in0 = String::new();
    {
        let ops = b[4].read().unwrap().get_ops();
        for o in &ops {
            let code = o.0.read().unwrap().opcode;
            if code == OpCode::CPUI_RETURN {
                let in1 = o.0.read().unwrap().get_in(1).cloned();
                if let Some(vn) = in1 {
                    ret_in1 = vname(&vn);
                }
            }
            if code == OpCode::CPUI_COPY {
                let r = o.0.read().unwrap();
                if let Some(out) = r.output.clone() {
                    copy_out = vname(&out);
                }
                if let Some(in0) = r.get_in(0).cloned() {
                    copy_in0 = vname(&in0);
                }
            }
        }
    }
    println!(
        "return|case={case_id}|ret_in1={ret_in1}|copy_out={copy_out}|copy_in0={copy_in0}|posta_ops={}|nblocks={}",
        Fixture::ops_of(&b[4]),
        fd.bblocks.get_size(),
    );
}

// ---------------------------------------------------------------------------
// S4: the cc:392 heritageyes gate at heritage pass 0 / 1.
// ---------------------------------------------------------------------------
struct GateDiamond {
    ib: BlockRef,
    fixture: Fixture,
}

fn build_gate_diamond(fd: &mut Funcdata) -> GateDiamond {
    let mut f = Fixture::new();
    let b: Vec<BlockRef> = (0..6).map(|_| f.make_block(fd)).collect();
    f.edge(fd, &b[0], &b[1]);
    f.edge(fd, &b[0], &b[2]);
    f.edge(fd, &b[1], &b[3]);
    f.edge(fd, &b[2], &b[3]);
    f.edge(fd, &b[3], &b[4]);
    f.edge(fd, &b[3], &b[5]);
    let boolvn = {
        let op = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let out = f.make_out(fd, 1, AddressSpace::Unique, 0x900, &op);
        let c = fd.new_constant(1, 1);
        fd.op_set_input(&op, c, 0);
        fd.op_insert_end(&op, &b[0]);
        out
    };
    // COPY with NO descendants: testRemovability's non-MULTIEQUAL branch
    // reaches the heritageyes[space] read (cc:392). (A no-descendant
    // MULTIEQUAL would bypass the gate — the cc:368 branch has no heritage
    // check.)
    {
        let copyop = fd.new_op(1, f.alloc_pc());
        fd.op_set_opcode(&copyop, OpCode::CPUI_COPY);
        let _vn_x = f.make_out(fd, 4, AddressSpace::Unique, 0x2000, &copyop);
        let c1 = fd.new_constant(4, 5);
        fd.op_set_input(&copyop, c1, 0);
        fd.op_insert_end(&copyop, &b[3]);
    }
    let at = f.alloc_pc();
    f.make_cbranch_at(fd, &b[3], &boolvn, at);
    let at_init = f.alloc_pc();
    f.make_cbranch_at(fd, &b[0], &boolvn, at_init);
    GateDiamond { ib: b[3].clone(), fixture: f }
}

fn run_gate_case(case_id: &str, pass: i32) {
    let mut fd = Funcdata::new(case_id, Address::new(0x60000), 0x100);
    let d = build_gate_diamond(&mut fd);
    fd.heritage.build_info_list();
    fd.heritage.pass = pass;
    let mut action = ActionConditionalExe::new();
    let r = action.apply(&mut fd).unwrap_or_else(|e| panic!("{case_id} apply failed: {e}"));
    let count = action.take_count_delta();
    // The iblock leaves the graph after a successful fold; probe residency
    // before touching it.
    let ib_ops = {
        let mut found = false;
        for i in 0..fd.bblocks.get_size() {
            if let Some(bb) = fd.bblocks.get_block(i) {
                if Arc::ptr_eq(&bb, &d.ib) {
                    found = true;
                    break;
                }
            }
        }
        if found { Fixture::ops_of(&d.ib) } else { "(gone)".to_string() }
    };
    println!(
        "ret|case={case_id}|apply={r}|count={count}|nblocks={}|ib_ops={ib_ops}",
        fd.bblocks.get_size(),
    );
}

fn main() {
    run_heritage_case("S1p0", 0); // no heritage yet: all false
    run_heritage_case("S1p1", 1); // delay-0 spaces true, stack false
    run_heritage_case("S1p2", 2); // stack (delay 1) turns true
    run_heritage_case("S1p3", 3);
    run_live_traversal_case(); // live traversal + count (A,B,C)
    run_return_case(); // space-preserving RETURN replacement
    run_gate_case("S4p0", 0); // cc:392 rejects: no heritage
    run_gate_case("S4p1", 1); // cc:392 admits: fold proceeds
}
