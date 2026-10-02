//! MERGE-TRIM-LANE-0001 — Rust-side twin of tests/oracle/merge_trim_lane_1204.cc
//! (RULE-PROPCOPY-ADDRTIED-0001): the phi(X, f(X)) lane-trim chain of
//! ActionMergeRequired — Funcdata::set_high_level's lazy Varnode cover
//! rebuild (varnode.cc:233 updateCover) feeding Merge::mergeMarker ->
//! Merge::mergeOp (merge.cc:719) -> trimOpInput (merge.cc:692) COPYs at the
//! END of each MULTIEQUAL lane's incoming block.
//!
//! Every case mirrors the Ghidra fixture case-for-case and prints the same
//! record grammar so the runner can diff the two stdouts byte for byte.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::merge::Merge;
use rudra::op::{pcodeop_flags, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

struct Fixture {
    blocks: Vec<BlockRef>,
    next_pc: u64,
    /// Stable fixture identities keyed by Varnode Arc pointer (the C++ twin
    /// keys by Varnode*; pointer identity is equivalent here because every
    /// named varnode is a distinct allocation on both sides).
    names: HashMap<usize, String>,
}

impl Fixture {
    fn new() -> Self {
        Fixture { blocks: Vec::new(), next_pc: 0x20000, names: HashMap::new() }
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

    /// Written varnode at an explicit address (mirrors the C++ fixture's
    /// fd.newVarnodeOut(size, Address(space, offset), op) leg).
    fn make_out(
        &self,
        fd: &mut Funcdata,
        size: usize,
        space: AddressSpace,
        offset: u64,
        op: &PcodeOpRef,
    ) -> VarnodeRef {
        let vn = fd.vbank.create_def_with_space(size, space, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    fn name_vn(&mut self, vn: &VarnodeRef, n: &str) {
        self.names.insert(Arc::as_ptr(vn) as usize, n.to_string());
    }

    fn name_of(&self, vn: &VarnodeRef) -> String {
        self.names
            .get(&(Arc::as_ptr(vn) as usize))
            .cloned()
            .unwrap_or_else(|| "?".to_string())
    }

    fn name_blk(&self, b: &BlockRef) -> String {
        match self.blocks.iter().position(|x| Arc::ptr_eq(x, b)) {
            Some(i) => format!("b{i}"),
            None => "x".to_string(),
        }
    }
}

fn opcode_name(op: &OpCode) -> String {
    // Ghidra's get_opname (opcodes.cc) names; MULTIEQUAL prints as "BUILD".
    match op {
        OpCode::CPUI_MULTIEQUAL => "BUILD".to_string(),
        other => format!("{:?}", other).trim_start_matches("CPUI_").to_string(),
    }
}

/// Ghidra-side coverPairChar: max CoverBlock intersect character across the
/// common blocks of the two Varnode covers (0 none, 1 boundary, 2 interval).
fn cover_pair_char(a: &VarnodeRef, b: &VarnodeRef) -> i32 {
    Varnode::update_cover_locked(a);
    Varnode::update_cover_locked(b);
    let (ca, cb) = {
        let ar = a.read().unwrap();
        let br = b.read().unwrap();
        (ar.cover.clone(), br.cover.clone())
    };
    let (Some(ca), Some(cb)) = (ca, cb) else { return -1 };
    let mut res = 0;
    for blk in 0..16i32 {
        let ch = ca.intersect_by_block(blk, &cb);
        if ch > res {
            res = ch;
        }
    }
    res
}

fn record_cover(case_id: &str, vn_name: &str, vn: &VarnodeRef) {
    Varnode::update_cover_locked(vn);
    let nonempty = vn
        .read()
        .unwrap()
        .cover
        .as_ref()
        .map(|c| !c.blocks.is_empty())
        .unwrap_or(false);
    println!("cover|case={case_id}|vn={vn_name}|nonempty={}", if nonempty { 1 } else { 0 });
}

fn record_ops(case_id: &str, f: &Fixture, blk: &BlockRef) {
    let blk_guard = blk.read().unwrap();
    let bb = blk_guard
        .as_any()
        .downcast_ref::<BlockBasic>()
        .expect("basic block");
    let mut list = String::new();
    let mut first = true;
    for op in bb.get_ops() {
        if !first {
            list.push(';');
        }
        first = false;
        let o = op.0.read().unwrap();
        list.push_str(&opcode_name(&o.opcode));
        if let Some(out) = &o.output {
            list.push('(');
            list.push_str(&f.name_of(out));
            list.push(')');
        }
        if !o.inrefs.is_empty() {
            list.push('<');
            for (i, inp) in o.inrefs.iter().enumerate() {
                if i > 0 {
                    list.push(',');
                }
                list.push_str(&f.name_of(inp));
            }
            list.push('>');
        }
    }
    println!("ops|case={case_id}|blk={}|list={}", f.name_blk(blk), list);
}

fn record_copy_np(case_id: &str, f: &Fixture, blk: &BlockRef) {
    let blk_guard = blk.read().unwrap();
    let bb = blk_guard
        .as_any()
        .downcast_ref::<BlockBasic>()
        .expect("basic block");
    for (idx, op) in bb.get_ops().iter().enumerate() {
        let o = op.0.read().unwrap();
        if o.opcode != OpCode::CPUI_COPY {
            continue;
        }
        let np = (o.flags & pcodeop_flags::NONPRINTING) != 0;
        let reads = o
            .inrefs
            .first()
            .map(|v| f.name_of(v))
            .unwrap_or_else(|| "?".to_string());
        println!("np|case={case_id}|blk={}|idx={idx}|np={}|reads={}", f.name_blk(blk), if np { 1 } else { 0 }, reads);
    }
}

fn run_case(fd: &mut Funcdata, f: &mut Fixture, case_id: &str, fx_in_then: bool) {
    let b0 = f.make_block(fd);
    let b1 = f.make_block(fd);
    let b2 = f.make_block(fd);
    let b3 = f.make_block(fd);
    let b4 = f.make_block(fd);
    f.edge(fd, &b0, &b1); // b1 in[0]
    f.edge(fd, &b1, &b2); // b2 in[0]   (b1 out[0] — fall-through/then)
    f.edge(fd, &b1, &b3); // b3 in[0]   (b1 out[1] — branch/skip)
    f.edge(fd, &b2, &b3); // b3 in[1]
    f.edge(fd, &b3, &b4); // b4 in[0]

    let def_x = fd.new_op(1, f.alloc_pc());
    fd.op_set_opcode(&def_x, OpCode::CPUI_COPY);
    let x = f.make_out(fd, 4, AddressSpace::Register, 0x20, &def_x);
    let c1234 = fd.new_constant(4, 0x1234);
    fd.op_set_input(&def_x, c1234, 0);
    fd.op_insert_end(&def_x, &b0);
    f.name_vn(&x, "X");

    let boolvn = fd.new_varnode(1, Address::new(0x900));
    let fx_op = fd.new_op(2, f.alloc_pc());
    fd.op_set_opcode(&fx_op, OpCode::CPUI_INT_RIGHT);
    let fx = f.make_out(fd, 4, AddressSpace::Unique, 0x910, &fx_op);
    fd.op_set_input(&fx_op, x.clone(), 0);
    let c16 = fd.new_constant(4, 16);
    fd.op_set_input(&fx_op, c16, 1);
    fd.op_insert_end(&fx_op, if fx_in_then { &b2 } else { &b1 });
    f.name_vn(&fx, "fX");

    let cbranch = fd.new_op(2, f.alloc_pc());
    fd.op_set_opcode(&cbranch, OpCode::CPUI_CBRANCH);
    let ctarget = fd.new_constant(8, 0x4000);
    fd.op_set_input(&cbranch, ctarget, 0);
    fd.op_set_input(&cbranch, boolvn, 1);
    fd.op_insert_end(&cbranch, &b1);

    let phi = fd.new_op(2, f.alloc_pc());
    fd.op_set_opcode(&phi, OpCode::CPUI_MULTIEQUAL);
    let phi_out = f.make_out(fd, 4, AddressSpace::Register, 0x20, &phi);
    fd.op_set_input(&phi, x.clone(), 0); // lane 0 arrives via b1 (skip edge)
    fd.op_set_input(&phi, fx.clone(), 1); // lane 1 arrives via b2 (then edge)
    fd.op_insert_begin(&phi, &b3);
    f.name_vn(&phi_out, "phiout");

    let reader = fd.new_op(2, f.alloc_pc());
    fd.op_set_opcode(&reader, OpCode::CPUI_INT_AND);
    let y = f.make_out(fd, 4, AddressSpace::Unique, 0x920, &reader);
    fd.op_set_input(&reader, phi_out.clone(), 0);
    let cff = fd.new_constant(4, 0xff);
    fd.op_set_input(&reader, cff, 1);
    fd.op_insert_end(&reader, &b4);
    f.name_vn(&y, "y");

    // ActionAssignHigh (coreaction.hh:346): Funcdata::setHighLevel.
    fd.set_high_level();
    record_cover(case_id, "X", &x);
    record_cover(case_id, "fX", &fx);
    record_cover(case_id, "phiout", &phi_out);
    println!("intersect|case={case_id}|pair=X_fX|char={}", cover_pair_char(&x, &fx));
    println!("intersect|case={case_id}|pair=X_phiout|char={}", cover_pair_char(&x, &phi_out));
    println!("intersect|case={case_id}|pair=fX_phiout|char={}", cover_pair_char(&fx, &phi_out));

    // ActionMergeRequired (coreaction.hh:369): mergeAddrTied; groupPartials;
    // mergeMarker. Rudra's mergeOp phase-3 skip-on-failure mirrors the
    // observable IR artifacts the Ghidra fixture records after its
    // LowlevelError catch (trims + trimOpOutput are already applied).
    {
        let mut merge = Merge::new();
        let _ = merge.try_merge_addr_tied(fd);
        merge.merge_marker(fd);
    }
    record_ops(case_id, f, &b0);
    record_ops(case_id, f, &b1);
    record_ops(case_id, f, &b2);
    record_ops(case_id, f, &b3);
    record_ops(case_id, f, &b4);
    // Lane projection: trim-COPY lanes print copy@<block>(<reads>).
    for slot in 0..2usize {
        let lane = phi.0.read().unwrap().inrefs[slot].clone();
        let mut desc = f.name_of(&lane);
        if desc == "?" {
            let def = lane.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            if let Some(def_op) = def {
                let is_copy = def_op.read().unwrap().opcode == OpCode::CPUI_COPY;
                if is_copy {
                    let parent = def_op
                        .read()
                        .unwrap()
                        .parent
                        .as_ref()
                        .and_then(|w| w.upgrade())
                        .expect("copy has parent");
                    let in0 = def_op.read().unwrap().inrefs[0].clone();
                    desc = format!("copy@{}({})", f.name_blk(&parent), f.name_of(&in0));
                }
            }
        }
        println!("phi|case={case_id}|lane{slot}={desc}");
    }

    // ActionCopyMarker (coreaction.hh:1015): markInternalCopies.
    {
        let mut merge = Merge::new();
        merge.mark_internal_copies(fd);
    }
    record_copy_np(case_id, f, &b0);
    record_copy_np(case_id, f, &b1);
    record_copy_np(case_id, f, &b2);
    record_copy_np(case_id, f, &b3);
    record_copy_np(case_id, f, &b4);
}

fn main() {
    let mut fd = Funcdata::new("merge_trim_lane_T1", Address::new(0x60000), 0x100);
    let mut f = Fixture::new();
    run_case(&mut fd, &mut f, "T1", false);
    let mut fd = Funcdata::new("merge_trim_lane_T2", Address::new(0x62000), 0x100);
    let mut f = Fixture::new();
    run_case(&mut fd, &mut f, "T2", true);
}
