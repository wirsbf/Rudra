// MERGE-PREEXISTING-GATES-0001: Rudra comparand for the locked Ghidra 12.0.4
// merge-gates oracle. Mirrors tests/oracle/merge_gates_1204.cc case for case:
// the same synthetic def-use/CFG graphs are built through the production
// Funcdata APIs and the merge-family Actions run exactly as the production
// pipeline performs them (coreaction.rs applies construct a fresh
// `Merge::new()` per Action, with the cross-Action channels round-tripping
// through the persistent `Funcdata::merge_state` mount; Ghidra uses the one
// persistent `getMerge()` object).
//
// Cases:
//   indirect_addrforce  Merge::mergeIndirect (merge.cc:846-882) — isAddrForce
//                       gate, INPUT-surviving merge attempts,
//                       snipOutputInterference + allocateCopyTrim fallback.
//   dominant_copy       buildDominantCopy (merge.cc:1151-1238) — domCopyIsNew
//                       branch closing with the direct null-testCache
//                       speculative HighVariable::merge at :1236 (pinned by
//                       the absorbed unique's mergeGroup class = 1).
//   multientry_gate     mergeMultiEntry (merge.cc:908-963) — the
//                       mergeTestRequired gate with setMergeProblems /
//                       setUnmerged and the exact warningHeader text.
//   cross_space_order   HighVariable::compareJustLoc (variable.cc:439-443)
//                       as the Address total order — raw comparator booleans
//                       plus the merged instance order after mergecopy.

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::merge::Merge;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::{varnode_flags, Varnode};

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;

fn space_letter(space: &AddressSpace) -> String {
    match space {
        AddressSpace::Unique => "u".to_string(),
        AddressSpace::Iop => "iop".to_string(),
        AddressSpace::Const => "k".to_string(),
        other => other.space_id().to_string(),
    }
}

fn vn_text(vn: Option<&VnRef>) -> String {
    let Some(vn) = vn else { return "none".to_string() };
    let readable = vn.read().unwrap();
    match readable.get_space() {
        AddressSpace::Const => format!("k{}", readable.get_offset()),
        AddressSpace::Iop => "iop".to_string(),
        AddressSpace::Unique => "u".to_string(),
        other => format!("{}:{:x}", other.space_id(), readable.get_offset()),
    }
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_pc: u64,
    /// Strongly-typed block list (keeps immed_dom/ops writable without dyn
    /// downcasts); coerced to BlockRef for the Funcdata calls.
    blocks: Vec<Arc<std::sync::RwLock<BlockBasic>>>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x100),
            base,
            next_pc: 0,
            blocks: Vec::new(),
        }
    }

    fn make_block(&mut self, index: i32) -> Arc<std::sync::RwLock<BlockBasic>> {
        let block: Arc<std::sync::RwLock<BlockBasic>> =
            Arc::new(std::sync::RwLock::new(BlockBasic::new(index, Address::new(self.base))));
        let dyn_block: BlockRef = block.clone();
        self.fd.bblocks.add_block(dyn_block);
        self.blocks.push(block.clone());
        block
    }

    fn set_dom(
        &mut self,
        child: &Arc<std::sync::RwLock<BlockBasic>>,
        parent: &Arc<std::sync::RwLock<BlockBasic>>,
    ) {
        // Production computes immediate dominators in BlockGraph::
        // calcReachable/buildDomTree; the fixture installs the diamond
        // dominators directly (BlockBasic::immed_dom is pub in Rust; the C++
        // side writes FlowBlock::immed_dom under private=public) so
        // find_common_block behaves as in production.
        let parent_dyn: BlockRef = parent.clone();
        child.write().unwrap().immed_dom = Some(Arc::downgrade(&parent_dyn));
    }

    fn edge(
        &mut self,
        from: &Arc<std::sync::RwLock<BlockBasic>>,
        to: &Arc<std::sync::RwLock<BlockBasic>>,
    ) {
        let from_dyn: BlockRef = from.clone();
        let to_dyn: BlockRef = to.clone();
        self.fd.bblocks.add_edge(from_dyn, to_dyn);
    }

    fn make_op(&mut self, opcode: OpCode, inputs: usize) -> PcodeOpRef {
        let pc = Address::new(self.base + self.next_pc);
        self.next_pc += 1;
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        op
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

    fn set_input(&mut self, op: &PcodeOpRef, vn: &VnRef, slot: usize) {
        self.fd.op_insert_input(op, vn.clone(), slot);
    }

    fn register_out(&mut self, size: usize, offset: u64, op: &PcodeOpRef) -> VnRef {
        self.fd.new_varnode_out(size, Address::new(offset), op)
    }

    fn unique_out(&mut self, size: usize, offset: u64, op: &PcodeOpRef) -> VnRef {
        // C++ newVarnodeOut at Address(unique, offset); Rust's
        // new_varnode_out hardcodes the register space, so drive the bank
        // directly and wire the output the same way new_varnode_out does
        // (op_set_output rejects an already-def varnode).
        let vn = self
            .fd
            .vbank
            .create_def_with_space(size, AddressSpace::Unique, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        self.fd.set_varnode_properties(&vn);
        vn
    }

    fn iop_const(&mut self, op: &PcodeOpRef) -> VnRef {
        // Funcdata::newVarnodeIop (funcdata_varnode.cc:176): varnode in the
        // iop space whose offset is the op pointer — matching
        // Funcdata::get_op_from_const's decoding (funcdata.rs:2512).
        self.fd.vbank.create_with_space(
            8,
            AddressSpace::Iop,
            Arc::as_ptr(&op.0) as u64,
        )
    }

    fn insert_end(&mut self, op: &PcodeOpRef, block: &Arc<std::sync::RwLock<BlockBasic>>) {
        let dyn_block: BlockRef = block.clone();
        self.fd.op_insert_end(op, &dyn_block);
    }

    fn insert_before(&mut self, op: &PcodeOpRef, follow: &PcodeOpRef) {
        self.fd.op_insert_before(op, follow);
    }

    fn ops_text(&self) -> String {
        let mut out = String::new();
        for (b, block) in self.blocks.iter().enumerate() {
            if b != 0 {
                out.push(' ');
            }
            out.push_str(&format!("b{}=[", b));
            let readable = block.read().unwrap();
            let mut first = true;
            for op in &readable.ops {
                if !first {
                    out.push(';');
                }
                first = false;
                out.push_str(&op_text(op));
            }
            drop(readable);
            out.push(']');
        }
        out
    }

    fn high_shape_text(&self, vn: &VnRef) -> String {
        let readable = vn.read().unwrap();
        let Some(high) = readable.high.clone() else {
            return "[]".to_string();
        };
        drop(readable);
        let high = high.read().unwrap();
        let mut out = String::from("[");
        for (i, inst) in high.instances.iter().enumerate() {
            if i != 0 {
                out.push('/');
            }
            let inst_rg = inst.read().unwrap();
            let defcode = inst_rg
                .get_def()
                .map(|d| d.read().unwrap().opcode as i32)
                .unwrap_or(-1);
            out.push_str(&format!("{}:{}", defcode, inst_rg.mergegroup));
        }
        out.push(']');
        out
    }

    fn observe(&self, case_name: &str, stage: &str, names: &[&str], vns: &[VnRef]) {
        let mut grouping = String::new();
        for (i, vn) in vns.iter().enumerate() {
            if i != 0 {
                grouping.push('/');
            }
            let readable = vn.read().unwrap();
            let count = readable
                .high
                .as_ref()
                .map(|h| h.read().unwrap().instances.len())
                .unwrap_or(0);
            grouping.push_str(&format!("{}:{}", names[i], count));
        }
        let mut same_high = String::new();
        for i in 0..vns.len() {
            for j in i + 1..vns.len() {
                let h_i = vns[i].read().unwrap().high.clone();
                let h_j = vns[j].read().unwrap().high.clone();
                let same = match (h_i, h_j) {
                    (Some(a), Some(b)) => Arc::ptr_eq(&a, &b) as u8,
                    _ => 0,
                };
                same_high.push_str(&format!("{}{}={},", names[i], names[j], same));
            }
        }
        if same_high.ends_with(',') {
            same_high.pop();
        }
        let mut groups = String::new();
        for (i, vn) in vns.iter().enumerate() {
            if i != 0 {
                groups.push('/');
            }
            groups.push_str(&format!(
                "{}:{}",
                names[i],
                vn.read().unwrap().mergegroup
            ));
        }
        let mut shapes = String::new();
        for (i, vn) in vns.iter().enumerate() {
            if i != 0 {
                shapes.push('/');
            }
            shapes.push_str(&format!("{}{}", names[i], self.high_shape_text(vn)));
        }
        println!(
            "case={case_name}|stage={stage}|instances={grouping}|groups={groups}|same_high={same_high}|ops={}|shape={shapes}",
            self.ops_text()
        );
    }
}

fn op_text(op: &PcodeOpRef) -> String {
    let readable = op.0.read().unwrap();
    let mut out = format!("{}(", readable.opcode as i32);
    for i in 0..readable.num_input() {
        if i != 0 {
            out.push(',');
        }
        out.push_str(&vn_text(readable.get_in(i)));
    }
    out.push_str(")->");
    out.push_str(&vn_text(readable.output.as_ref()));
    out
}

// The production Action sequence (coreaction.rs ActionMergeRequired, one
// Merge with three calls; then the leaf Actions with fresh Merge::new()
// exactly like the applies perform them — coreaction.cc:5717-5727).
fn run_mergerequired(graph: &mut Graph) {
    let mut merge = Merge::new();
    merge.merge_addr_tied(&mut graph.fd);
    merge.group_partials(&mut graph.fd);
    merge.merge_marker(&mut graph.fd);
}

fn set_type_lock(vn: &VnRef, dtype: Arc<rudra::type_system::datatype::Datatype>) {
    // C++ Varnode::updateType(ct, /*locktype=*/true, /*locksize=*/true).
    let mut w = vn.write().unwrap();
    w.v_type = Some(dtype);
    w.flags |= varnode_flags::TYPELOCK;
}

// -------------------------------------------------------------------------
fn run_indirect_addrforce() {
    let mut g = Graph::new("indirect_addrforce", 0x7400);
    let b0 = g.make_block(0);

    // b0: op1 A = COPY const
    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_a = g.register_out(4, 0x10, &op1);
    let c1 = g.constant(4, 0x51);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);
    // b0: opE E = LOAD(const, const) — the op causing the indirect effect
    let op_e = g.make_op(OpCode::CPUI_LOAD, 2);
    let _vn_e = g.register_out(4, 0x30, &op_e);
    let c_spc = g.constant(8, 3);
    g.set_input(&op_e, &c_spc, 0);
    let c_addr = g.constant(8, 0x90);
    g.set_input(&op_e, &c_addr, 1);
    g.insert_end(&op_e, &b0);
    // b0: indop I = INDIRECT(A, iop(opE)), placed BEFORE the effect op
    // (Funcdata::newIndirectOp, funcdata_op.cc:696).
    let indop = g.make_op(OpCode::CPUI_INDIRECT, 2);
    let vn_i = g.register_out(4, 0x20, &indop);
    g.set_input(&indop, &vn_a, 0);
    let iop = g.iop_const(&op_e);
    g.set_input(&indop, &iop, 1);
    g.insert_before(&indop, &op_e);
    vn_i.write().unwrap().set_addr_force();
    // b0: R = INT_ADD A, 1 (keeps A live past the INDIRECT -> cover clash)
    let op_r = g.make_op(OpCode::CPUI_INT_ADD, 2);
    let _vn_r = g.register_out(4, 0x40, &op_r);
    g.set_input(&op_r, &vn_a, 0);
    let c_one = g.constant(4, 1);
    g.set_input(&op_r, &c_one, 1);
    g.insert_end(&op_r, &b0);

    let names = ["A", "I"];
    let vns = [vn_a, vn_i];

    g.fd.set_high_level();
    g.observe("indirect_addrforce", "assignhigh", &names, &vns);
    run_mergerequired(&mut g);
    g.observe("indirect_addrforce", "mergerequired", &names, &vns);
}

// -------------------------------------------------------------------------
fn run_dominant_copy() {
    let mut g = Graph::new("dominant_copy", 0x7500);
    let b0 = g.make_block(0);
    let b1 = g.make_block(1);
    let b2 = g.make_block(2);
    let b3 = g.make_block(3);
    g.edge(&b0, &b1);
    g.edge(&b0, &b2);
    g.edge(&b1, &b3);
    g.edge(&b2, &b3);
    g.set_dom(&b1, &b0);
    g.set_dom(&b2, &b0);
    g.set_dom(&b3, &b0);

    let ct_int = Arc::new(rudra::type_system::Datatype::Base(
        rudra::type_system::TypeBase::new("int4".to_string(), 4, rudra::type_system::TypeMetatype::Int),
    ));
    let ct_uint = Arc::new(rudra::type_system::Datatype::Base(
        rudra::type_system::TypeBase::new("uint4".to_string(), 4, rudra::type_system::TypeMetatype::Uint),
    ));

    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_v = g.register_out(4, 0x10, &op1);
    let c1 = g.constant(4, 0x61);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);
    set_type_lock(&vn_v, ct_int);

    let me = g.make_op(OpCode::CPUI_MULTIEQUAL, 2);
    let vn_o = g.register_out(4, 0x20, &me);
    g.set_input(&me, &vn_v, 0);
    g.set_input(&me, &vn_v, 1);
    g.insert_end(&me, &b3);
    set_type_lock(&vn_o, ct_uint);

    let names = ["V", "O"];
    let vns = [vn_v, vn_o];

    g.fd.set_high_level();
    g.observe("dominant_copy", "assignhigh", &names, &vns);
    run_mergerequired(&mut g);
    g.observe("dominant_copy", "mergerequired", &names, &vns);
    {
        let mut merge = Merge::new();
        merge.merge_opcode(&mut g.fd, OpCode::CPUI_COPY);
    }
    g.observe("dominant_copy", "mergecopy", &names, &vns);
    {
        let mut merge = Merge::new();
        merge.process_copy_trims(&mut g.fd);
    }
    g.observe("dominant_copy", "dominantcopy", &names, &vns);
    {
        let mut merge = Merge::new();
        merge.merge_adjacent(&mut g.fd);
    }
    g.observe("dominant_copy", "mergeadjacent", &names, &vns);
}

// -------------------------------------------------------------------------
fn run_multientry_gate() {
    use rudra::address::RangeList;
    use rudra::database::{Symbol, SymbolEntry};

    let mut g = Graph::new("multientry_gate", 0x7600);
    let b0 = g.make_block(0);

    // Funcdata::arch with a comment database so Funcdata::warning_header
    // stores the text (Ghidra writes into glb->commentdb, funcdata.cc:143)
    // instead of falling back to stderr.
    let arch = {
        let mut a = rudra::arch::Architecture::new();
        a.commentdb = Some(Arc::new(std::sync::RwLock::new(
            rudra::comment::CommentDatabaseInternal::new(),
        )));
        Arc::new(a)
    };
    g.fd.set_arch(arch.clone());

    let ct_int = Arc::new(rudra::type_system::Datatype::Base(
        rudra::type_system::TypeBase::new("int8".to_string(), 8, rudra::type_system::TypeMetatype::Int),
    ));
    let ct_uint = Arc::new(rudra::type_system::Datatype::Base(
        rudra::type_system::TypeBase::new("uint8".to_string(), 8, rudra::type_system::TypeMetatype::Uint),
    ));

    let op1 = g.make_op(OpCode::CPUI_LOAD, 2);
    let vn_m1 = g.unique_out(8, 0x100, &op1);
    let c_spc = g.constant(8, 3);
    g.set_input(&op1, &c_spc, 0);
    let c_a1 = g.constant(8, 0x1000);
    g.set_input(&op1, &c_a1, 1);
    g.insert_end(&op1, &b0);
    set_type_lock(&vn_m1, ct_int);

    let op2 = g.make_op(OpCode::CPUI_LOAD, 2);
    let vn_m2 = g.unique_out(8, 0x200, &op2);
    let c_spc2 = g.constant(8, 3);
    g.set_input(&op2, &c_spc2, 0);
    let c_a2 = g.constant(8, 0x2000);
    g.set_input(&op2, &c_a2, 1);
    g.insert_end(&op2, &b0);
    set_type_lock(&vn_m2, ct_uint);

    // One Symbol, two whole-size entries at the varnode storage locations
    // (mirrors the C++ side's ScopeLocal addSymbol + addMapPoint; the Rust
    // merge_multi_entry reconstruction groups by the Varnodes' mapentry
    // back-pointers and requires ≥ 2 distinct entry addresses per Symbol).
    let sym = Arc::new(std::sync::RwLock::new(Symbol::new(0, "multi", "long")));
    let entry1 = Arc::new(std::sync::RwLock::new(SymbolEntry::new_static(
        sym.clone(),
        0,
        Address::new(0x100),
        0,
        8,
        RangeList::new(),
    )));
    let entry2 = Arc::new(std::sync::RwLock::new(SymbolEntry::new_static(
        sym.clone(),
        0,
        Address::new(0x200),
        0,
        8,
        RangeList::new(),
    )));
    vn_m1.write().unwrap().mapentry = Some(entry1);
    vn_m2.write().unwrap().mapentry = Some(entry2);

    let names = ["M1", "M2"];
    let vns = [vn_m1.clone(), vn_m2.clone()];

    g.fd.set_high_level();
    g.observe("multientry_gate", "assignhigh", &names, &vns);
    run_mergerequired(&mut g);
    g.observe("multientry_gate", "mergerequired", &names, &vns);
    {
        let mut merge = Merge::new();
        merge.merge_multi_entry(&mut g.fd);
    }
    let merge_problems =
        (sym.read().unwrap().dispflags & rudra::database::display_flags::MERGE_PROBLEMS) != 0;
    let unmerged_m2 = vns[1]
        .read()
        .unwrap()
        .high
        .as_ref()
        .map(|h| h.read().unwrap().is_unmerged())
        .unwrap_or(false);
    let warn = {
        let a = arch.as_ref();
        let mut texts: Vec<String> = Vec::new();
        if let Some(cdb) = &a.commentdb {
            for c in cdb.read().unwrap().all_comments() {
                if c.get_type() == rudra::comment::comment_type::WARNINGHEADER {
                    texts.push(c.get_text().to_string());
                }
            }
        }
        format!("[{}]", texts.join(";"))
    };
    println!(
        "case=multientry_gate|stage=multientry|merge_problems={}|unmerged_M2={}|warn={}",
        if merge_problems { 1 } else { 0 },
        if unmerged_m2 { 1 } else { 0 },
        warn
    );
    g.observe("multientry_gate", "postmultientry", &names, &vns);
}

// -------------------------------------------------------------------------
fn run_cross_space_order() {
    use rudra::variable::HighVariable;

    let mut g = Graph::new("cross_space_order", 0x7700);
    let b0 = g.make_block(0);

    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_v = g.register_out(4, 0x10, &op1);
    let c1 = g.constant(4, 0x71);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);

    let op2 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_t = g.unique_out(4, 0x5000, &op2);
    g.set_input(&op2, &vn_v, 0);
    g.insert_end(&op2, &b0);

    {
        let v_rg = vn_v.read().unwrap();
        let t_rg = vn_t.read().unwrap();
        // compareJustLoc(T, V): unique (index 2) < register (index 4) despite
        // the larger offset — Address::operator< orders by space first.
        let cmp_tv = HighVariable::compare_just_loc(&t_rg, &v_rg);
        let cmp_vt = HighVariable::compare_just_loc(&v_rg, &t_rg);
        let cmp_vv = HighVariable::compare_just_loc(&v_rg, &v_rg);
        println!(
            "case=cross_space_order|stage=cmp|cmp_TV={}|cmp_VT={}|cmp_VV={}",
            cmp_tv as u8, cmp_vt as u8, cmp_vv as u8
        );
    }

    let names = ["V", "T"];
    let vns = [vn_v, vn_t];

    g.fd.set_high_level();
    g.observe("cross_space_order", "assignhigh", &names, &vns);
    {
        let mut merge = Merge::new();
        merge.merge_opcode(&mut g.fd, OpCode::CPUI_COPY);
    }
    g.observe("cross_space_order", "mergecopy", &names, &vns);
}

fn main() {
    run_indirect_addrforce();
    run_dominant_copy();
    run_multientry_gate();
    run_cross_space_order();
}
