// MERGE-PERSISTENT-STATE-0001: Rudra comparand for the locked Ghidra 12.0.4
// persistent Merge oracle.  Mirrors tests/oracle/merge_persistent_1204.cc
// case for case: the same synthetic def-use/CFG graphs are built through the
// production Funcdata APIs and the merge-family Action sequence runs exactly
// as the production pipeline performs it (coreaction.rs applies construct a
// fresh `Merge::new()` per Action, exactly like the Actions do), so the
// cross-Action channels must round-trip through the persistent
// `Funcdata::merge_state` mount for the later Actions to observe the state
// the earlier ones produced — Ghidra gets this for free from the by-value
// `Funcdata::covermerge` member (funcdata.hh:96).
//
// Current projection status (pinned in metadata.json): all seven cases
// byte-match the locked oracle on every projected line (29/29).  Overall
// status remains MISMATCH: Java/CPOOL local types and persistent
// cache/trim/protoPartial/clear channels are not closed
// (TYPEOP-LOCALTYPE-DISPATCH-0001, MERGE-PERSISTENCE-CHANNELS-0001).
// The copy-shadow family merge and
// the mergeadjacent single-accept (tC only) both require: the persistent
// cover premise (set_high_level calcCover), the transitive copy_shadow
// (VARNODE-COPYSHADOW-ARC-0001, fixed at e87ebfc), the mergeTestAdjacent +
// outputTypeLocal==inputTypeLocal gate chain (merge.cc:996-1007), and the
// post-merge high-cover union rebuild (variable.cc:660-663 mergeInternal
// coverdirty, absorbed from MERGE-HIGHCOVER-UNION-0001).  pipeline_tail
// additionally drives ActionMergeType's real entry (merge_all) end to end,
// closing the nested-attach blind spot that the depth counter now guards.

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::merge::Merge;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;

fn endpoint(value: u32) -> String {
    if value == 0 {
        "b".to_string()
    } else if value == u32::MAX {
        "e".to_string()
    } else {
        value.to_string()
    }
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_pc: u64,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x100),
            base,
            next_pc: 0,
        }
    }

    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
            index,
            Address::new(self.base),
        )));
        self.fd.bblocks.add_block(block.clone());
        block
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
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

    fn insert_end(&mut self, op: &PcodeOpRef, block: &BlockRef) {
        self.fd.op_insert_end(op, block);
    }

    fn cover_text(vn: &VnRef) -> String {
        {
            let readable = vn.read().unwrap();
            if !readable.has_cover() {
                return "[nocover]".to_string();
            }
        }
        Varnode::update_cover_locked(vn);
        let value = vn.read().unwrap();
        let Some(cover) = value.cover.as_deref() else {
            return "[null]".to_string();
        };
        let mut out = String::from("[");
        let mut first = true;
        for (index, block) in cover.blocks.iter() {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(&index.to_string());
            out.push(':');
            out.push_str(&endpoint(block.start));
            out.push('-');
            out.push_str(&endpoint(block.end));
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
            grouping.push_str(&count.to_string());
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
                same_high.push_str(names[i]);
                same_high.push_str(names[j]);
                same_high.push('=');
                same_high.push_str(&same.to_string());
                same_high.push(',');
            }
        }
        if same_high.ends_with(',') {
            same_high.pop();
        }
        // Per-Varnode forced merge group (varnode.hh:186 getMergeGroup):
        // speculative absorption moves absorbed members into separate
        // merge classes (variable.cc:640-646), exposing the survivor side
        // and the class semantics (merge.cc:1571 isspeculative).
        let mut groups = String::new();
        for (i, vn) in vns.iter().enumerate() {
            if i != 0 {
                groups.push('/');
            }
            groups.push_str(names[i]);
            groups.push(':');
            groups.push_str(&vn.read().unwrap().mergegroup.to_string());
        }
        let mut covers = String::new();
        for (i, vn) in vns.iter().enumerate() {
            if i != 0 {
                covers.push(' ');
            }
            covers.push_str(names[i]);
            covers.push('=');
            covers.push_str(&Self::cover_text(vn));
        }
        println!(
            "case={case_name}|stage={stage}|instances={grouping}|groups={groups}|same_high={same_high}|covers={covers}"
        );
    }

    // The production Action sequence (coreaction.rs ActionMergeRequired:913,
    // ActionMergeCopy:982, ActionMergeAdjacent:947): one fresh Merge::new()
    // per Action apply, so the cross-Action channels only survive through
    // the Funcdata merge_state mount (Ghidra: one persistent getMerge()).
    fn run_actions(&mut self, case_name: &str, names: &[&str], vns: &[VnRef]) {
        self.fd.set_high_level(); // ActionAssignHigh (:5717)
        self.observe(case_name, "assignhigh", names, vns);
        {
            // ActionMergeRequired (:5718) — one Merge, three calls
            let mut merge = Merge::new();
            merge.merge_addr_tied(&mut self.fd);
            merge.group_partials(&mut self.fd);
            merge.merge_marker(&mut self.fd);
        }
        self.observe(case_name, "mergerequired", names, vns);
        {
            // ActionMergeCopy (:5722) — fresh Merge
            let mut merge = Merge::new();
            merge.merge_opcode(&mut self.fd, OpCode::CPUI_COPY);
        }
        self.observe(case_name, "mergecopy", names, vns);
        {
            // ActionMergeAdjacent (:5726) — fresh Merge
            let mut merge = Merge::new();
            merge.merge_adjacent(&mut self.fd);
        }
        self.observe(case_name, "mergeadjacent", names, vns);
    }
}

fn run_copy_shadow_ladder() {
    let mut g = Graph::new("copy_shadow_ladder", 0x7000);
    let b0 = g.make_block(0);
    let b1 = g.make_block(1);
    g.edge(&b0, &b1);

    // b0: op1 vnP = COPY const
    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_p = g.register_out(4, 0x10, &op1);
    let c1 = g.constant(4, 0x11);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);
    // b1: op2 vnQ1 = COPY vnP
    let op2 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_q1 = g.register_out(4, 0x20, &op2);
    g.set_input(&op2, &vn_p, 0);
    g.insert_end(&op2, &b1);
    // b1: op3 vnQ2 = COPY vnP
    let op3 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_q2 = g.register_out(4, 0x30, &op3);
    g.set_input(&op3, &vn_p, 0);
    g.insert_end(&op3, &b1);
    // b1: op4 tA = INT_ADD vnP, const (keeps vnP live past op3)
    let op4 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    let t_a = g.register_out(4, 0x40, &op4);
    g.set_input(&op4, &vn_p, 0);
    let c2 = g.constant(4, 1);
    g.set_input(&op4, &c2, 1);
    g.insert_end(&op4, &b1);
    // b1: op5 tB = INT_ADD vnQ2, const (last read of vnQ2)
    let op5 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    let t_b = g.register_out(4, 0x50, &op5);
    g.set_input(&op5, &vn_q2, 0);
    let c3 = g.constant(4, 2);
    g.set_input(&op5, &c3, 1);
    g.insert_end(&op5, &b1);
    // b1: op6 tC = INT_ADD vnQ1, const (last read of vnQ1, after vnQ2's)
    let op6 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    let t_c = g.register_out(4, 0x60, &op6);
    g.set_input(&op6, &vn_q1, 0);
    let c4 = g.constant(4, 3);
    g.set_input(&op6, &c4, 1);
    g.insert_end(&op6, &b1);

    g.run_actions(
        "copy_shadow_ladder",
        &["P", "Q1", "Q2", "tA", "tB", "tC"],
        &[vn_p, vn_q1, vn_q2, t_a, t_b, t_c],
    );
}

fn run_disjoint_copy() {
    let mut g = Graph::new("disjoint_copy", 0x7100);
    let b0 = g.make_block(0);
    // b0: op1 vnX = COPY const
    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_x = g.register_out(4, 0x10, &op1);
    let c1 = g.constant(4, 0x21);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);
    // b0: op2 vnY = COPY vnX (mergecopy candidate, no other reads)
    let op2 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_y = g.register_out(4, 0x20, &op2);
    g.set_input(&op2, &vn_x, 0);
    g.insert_end(&op2, &b0);

    g.run_actions("disjoint_copy", &["X", "Y"], &[vn_x, vn_y]);
}

// case_pipeline_tail: the ladder graph driven through the production
// Action entries exactly as coreaction.rs performs them — staged Actions
// with fresh Merge::new() instances, then ActionMergeType's merge_all
// (which must attach to the persistent mount across every boundary).
fn run_pipeline_tail() {
    let mut g = Graph::new("pipeline_tail", 0x7200);
    let b0 = g.make_block(0);
    let b1 = g.make_block(1);
    g.edge(&b0, &b1);

    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_p = g.register_out(4, 0x10, &op1);
    let c1 = g.constant(4, 0x31);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);
    let op2 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_q1 = g.register_out(4, 0x20, &op2);
    g.set_input(&op2, &vn_p, 0);
    g.insert_end(&op2, &b1);
    let op3 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_q2 = g.register_out(4, 0x30, &op3);
    g.set_input(&op3, &vn_p, 0);
    g.insert_end(&op3, &b1);
    let op4 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    let t_a = g.register_out(4, 0x40, &op4);
    g.set_input(&op4, &vn_p, 0);
    let c2 = g.constant(4, 1);
    g.set_input(&op4, &c2, 1);
    g.insert_end(&op4, &b1);
    let op5 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    let t_b = g.register_out(4, 0x50, &op5);
    g.set_input(&op5, &vn_q2, 0);
    let c3 = g.constant(4, 2);
    g.set_input(&op5, &c3, 1);
    g.insert_end(&op5, &b1);
    let op6 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    let t_c = g.register_out(4, 0x60, &op6);
    g.set_input(&op6, &vn_q1, 0);
    let c4 = g.constant(4, 3);
    g.set_input(&op6, &c4, 1);
    g.insert_end(&op6, &b1);

    let names = ["P", "Q1", "Q2", "tA", "tB", "tC"];
    let vns = [vn_p, vn_q1, vn_q2, t_a, t_b, t_c];

    g.fd.set_high_level();
    g.observe("pipeline_tail", "assignhigh", &names, &vns);
    {
        let mut merge = Merge::new();
        merge.merge_addr_tied(&mut g.fd);
        merge.group_partials(&mut g.fd);
        merge.merge_marker(&mut g.fd);
    }
    g.observe("pipeline_tail", "mergerequired", &names, &vns);
    {
        let mut merge = Merge::new();
        merge.merge_opcode(&mut g.fd, OpCode::CPUI_COPY);
    }
    g.observe("pipeline_tail", "mergecopy", &names, &vns);
    {
        let mut merge = Merge::new();
        merge.merge_adjacent(&mut g.fd);
    }
    g.observe("pipeline_tail", "mergeadjacent", &names, &vns);
    {
        // ActionMergeType (:5727) — the production fold entry.
        let mut merge = Merge::new();
        merge.merge_all(&mut g.fd);
    }
    // MERGE-PERSISTENT round-2 Rust regression canary (NOT bilateral oracle
    // evidence): the nested attach/detach
    // sequence inside merge_all must return the persistent channels to the
    // Funcdata mount (depth-balanced). If an inner early-return leaked +1,
    // live_set would come back empty and the intersection cache empty.
    {
        let (cache_entries, _trims, live) = g.fd.merge_state.channel_sizes();
        assert!(
            live > 0,
            "merge_all leaked attach_depth: live channel lost (live={live})"
        );
        assert!(
            cache_entries > 0,
            "merge_all leaked attach_depth: testCache channel lost (cache={cache_entries})"
        );
    }
    g.observe("pipeline_tail", "mergetype", &names, &vns);
}

// case_type_gate: pins the merge.cc:1001 canonical-type gate — INT_LEFT
// shift amount of size != 1 passes (getBaseNoChar == getBase outside the
// registered 1-byte int, type.cc:3619-3626) and FLOAT_TRUNC same-size
// float input is rejected (typeop.cc:1913 (TYPE_INT, TYPE_FLOAT)).
fn run_type_gate() {
    let mut g = Graph::new("type_gate", 0x7300);
    let b0 = g.make_block(0);

    let vn_big = {
        let vn = g
            .fd
            .vbank
            .create_with_space(8, AddressSpace::Register, 0x08);
        g.fd.vbank.set_input(vn.clone()).expect("fresh input varnode");
        vn
    };
    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_sh = g.register_out(4, 0x10, &op1);
    let c1 = g.constant(4, 0x41);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);
    let op2 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_f = g.register_out(4, 0x18, &op2);
    let c2 = g.constant(4, 0x42);
    g.set_input(&op2, &c2, 0);
    g.insert_end(&op2, &b0);
    let op3 = g.make_op(OpCode::CPUI_INT_LEFT, 2);
    let t_sh = g.register_out(4, 0x30, &op3);
    g.set_input(&op3, &vn_big, 0);
    g.set_input(&op3, &vn_sh, 1);
    g.insert_end(&op3, &b0);
    let op4 = g.make_op(OpCode::CPUI_FLOAT_TRUNC, 1);
    let t_f = g.register_out(4, 0x38, &op4);
    g.set_input(&op4, &vn_f, 0);
    g.insert_end(&op4, &b0);

    g.run_actions(
        "type_gate",
        &["SH", "F", "TSH", "TF"],
        &[vn_sh, vn_f, t_sh, t_f],
    );
}

// case_float_trunc_cast: isolates the merge.cc:1001 FLOAT_TRUNC gate entry
// with a cast-shaped same-size op — a wrong (Int,Int) pair would let TF
// merge with F2; the locked (Int,Float) pair (typeop.cc:1913) rejects it.
fn run_float_trunc_cast() {
    let mut g = Graph::new("float_trunc_cast", 0x7400);
    let b0 = g.make_block(0);

    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_shx = g.register_out(4, 0x10, &op1);
    let c1 = g.constant(4, 0x51);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);
    let op2 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_f2 = g.register_out(4, 0x18, &op2);
    let c2 = g.constant(4, 0x52);
    g.set_input(&op2, &c2, 0);
    g.insert_end(&op2, &b0);
    let op3 = g.make_op(OpCode::CPUI_FLOAT_TRUNC, 1);
    let t_f = g.register_out(4, 0x30, &op3);
    g.set_input(&op3, &vn_f2, 0);
    g.insert_end(&op3, &b0);
    let op4 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_c = g.register_out(4, 0x38, &op4);
    g.set_input(&op4, &vn_shx, 0);
    g.insert_end(&op4, &b0);

    g.run_actions(
        "float_trunc_cast",
        &["SHX", "F2", "TF", "C"],
        &[vn_shx, vn_f2, t_f, vn_c],
    );
}

// case_char_gate_null / case_char_gate_char: the 1-byte Int char
// determination of type.cc:3619-3626. `register_char_core` mirrors the
// Ghidra fixture's second architecture by mounting a TypeFactory with
// deliberately custom-named non-ASCII/ASCII 1-byte INT core types. This
// proves `Merge::factory_nochar_distinct` reads canonical factory identity,
// not "int1"/"char" names. Without it (arch=None →
// no factory registration) the null world applies: getBaseNoChar(1,INT)
// IS getBase(1,INT) (type.cc:3624) and the 1-byte shift amount T1/SH1
// merges like the 4-byte control; with it the registered type_nochar
// differs from the char (type.cc:3220-3229) and the 1-byte pair is
// rejected while T4/SH4 (size!=1) still merges.
fn run_char_gate(case_name: &str, base: u64, register_char_core: bool) {
    let mut g = Graph::new(case_name, base);
    if register_char_core {
        let mut arch = rudra::arch::Architecture::new();
        let mut custom_factory = rudra::type_system::typefactory::TypeFactory::new(8);
        custom_factory.clear();
        custom_factory.set_core_type(
            "signed_byte_custom",
            1,
            rudra::type_system::TypeMetatype::Int,
            false,
        );
        custom_factory.set_core_type(
            "ascii_glyph_custom",
            1,
            rudra::type_system::TypeMetatype::Int,
            true,
        );
        custom_factory.cache_core_types();
        let factory = std::sync::Arc::new(std::sync::RwLock::new(custom_factory));
        arch.set_types(factory);
        g.fd.set_arch(std::sync::Arc::new(arch));
    }
    let b0 = g.make_block(0);

    let vn_big = {
        let vn = g
            .fd
            .vbank
            .create_with_space(8, AddressSpace::Register, 0x08);
        g.fd.vbank.set_input(vn.clone()).expect("fresh input varnode");
        vn
    };
    let op1 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_sh1 = g.register_out(1, 0x10, &op1);
    let c1 = g.constant(1, 0x61);
    g.set_input(&op1, &c1, 0);
    g.insert_end(&op1, &b0);
    let op2 = g.make_op(OpCode::CPUI_COPY, 1);
    let vn_sh4 = g.register_out(4, 0x20, &op2);
    let c2 = g.constant(4, 0x62);
    g.set_input(&op2, &c2, 0);
    g.insert_end(&op2, &b0);
    let op3 = g.make_op(OpCode::CPUI_INT_LEFT, 2);
    let t1 = g.register_out(1, 0x30, &op3);
    g.set_input(&op3, &vn_big, 0);
    g.set_input(&op3, &vn_sh1, 1);
    g.insert_end(&op3, &b0);
    let op4 = g.make_op(OpCode::CPUI_INT_LEFT, 2);
    let t4 = g.register_out(4, 0x38, &op4);
    g.set_input(&op4, &vn_big, 0);
    g.set_input(&op4, &vn_sh4, 1);
    g.insert_end(&op4, &b0);

    g.run_actions(
        case_name,
        &["SH1", "T1", "SH4", "T4"],
        &[vn_sh1, t1, vn_sh4, t4],
    );
}

fn main() {
    run_copy_shadow_ladder();
    run_disjoint_copy();
    run_pipeline_tail();
    run_type_gate();
    run_float_trunc_cast();
    run_char_gate("char_gate_null", 0x7500, false);
    run_char_gate("char_gate_char", 0x7600, true);
}
