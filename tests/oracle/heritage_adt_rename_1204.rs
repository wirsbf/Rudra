// HERITAGE-ADT-RENAME-0001: Rugra comparand for the locked Ghidra 12.0.4
// placeMultiequals/rename per-object phi oracle. Mirrors
// tests/oracle/heritage_adt_rename_1204.cc case for case: the same
// synthetic CFG/def-use graphs are built through the production Funcdata
// APIs, three consecutive `op_heritage` boundary calls (pass 0 -> 1 -> 2
// -> 3) run on the same `&mut Funcdata`, and the complete state
// projection (pass counter, per-object phi projection with
// reverse-predecessor slots, op list with per-slot input classes,
// Varnode-bank multiset) is printed in the shared observation format.
//
// The Rust fixture additionally ASSERTS the ownership internals the C++
// side cannot print: maxdepth == -1 at construction with exactly one ADT
// rebuild across the three passes, and the persistent globaldisjoint
// cover surviving every mem::take round-trip of the Heritage object.

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;
type OpRef = Arc<std::sync::RwLock<PcodeOp>>;

fn opcode_name(opc: OpCode) -> &'static str {
    match opc {
        OpCode::CPUI_COPY => "COPY",
        OpCode::CPUI_INT_ADD => "INT_ADD",
        OpCode::CPUI_INT_OR => "INT_OR",
        OpCode::CPUI_INT_MULT => "INT_MULT",
        OpCode::CPUI_MULTIEQUAL => "MULTIEQUAL",
        OpCode::CPUI_PIECE => "PIECE",
        OpCode::CPUI_SUBPIECE => "SUBPIECE",
        _ => "OTHER",
    }
}

// Varnode descriptor shared with the C++ oracle fixture:
//   constant -> C<size>; register -> R<hex-offset>:<size>:<I|W|F>[+<def-op>];
//   unique -> U<size>:<I|W|F>[+<def-op>]. Written varnodes carry their
//   defining opcode so phi input identity is observable.
fn vn_descriptor(vn: &VnRef) -> String {
    let value = vn.read().unwrap();
    if value.is_constant() {
        // Constant VALUE is printed so same-size constants stay
        // distinguishable (the refine case's SUBPIECE offset constants
        // 0/2 must differ for the within-group order witness).
        return format!("C{}:{:x}", value.size, value.loc.as_u64());
    }
    let code = match value.address_space {
        AddressSpace::Stack => 'S',
        AddressSpace::Register => 'R',
        AddressSpace::Unique => 'U',
        AddressSpace::Ram => 'M',
        _ => 'X',
    };
    let head = if matches!(
        value.address_space,
        AddressSpace::Stack | AddressSpace::Register | AddressSpace::Ram
    ) {
        format!("{code}{}:{}", format!("{:x}", value.loc.as_u64()), value.size)
    } else {
        format!("{code}{}", value.size)
    };
    if value.is_input() {
        format!("{head}:I")
    } else if value.is_written() {
        let def_name = value
            .def
            .as_ref()
            .and_then(|w| w.upgrade())
            .map(|d| opcode_name(d.read().unwrap().opcode))
            .unwrap_or("NODEF");
        format!("{head}:W+{def_name}")
    } else {
        format!("{head}:F")
    }
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    ops: Vec<(OpRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            next_offset: 0,
            ops: Vec::new(),
        }
    }

    // Ghidra's synthetic blocks have an empty address-range cover, so
    // BlockBasic::getStart() returns the null Address (block.cc:2319-2326)
    // and the MULTIEQUAL ops created by placeMultiequals carry null-pc
    // SeqNums sorting first in the op tree. The Rust mirror passes
    // start_addr = Address(0) (Rugra's Address is offset-only).
    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
            index,
            Address::new(0),
        )));
        self.fd.bblocks.add_block(block.clone());
        block
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn make_op(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> OpRef {
        let pc = Address::new(self.base + self.next_offset);
        self.next_offset += 1;
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        self.ops.push((op.0.clone(), name));
        op.0.clone()
    }

    fn unique_out(&mut self, size: usize, op: &OpRef) -> VnRef {
        self.fd
            .new_unique_out(size, &rudra::op::PcodeOpRef(op.clone()))
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

    fn free_register(&mut self, offset: u64, size: usize) -> VnRef {
        self.fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset)
    }

    fn written_register(&mut self, offset: u64, size: usize, op: &OpRef) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.fd
            .op_set_output(&rudra::op::PcodeOpRef(op.clone()), vn.clone());
        vn
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd
            .op_set_input(&rudra::op::PcodeOpRef(op.clone()), vn.clone(), slot);
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd
            .op_insert_end(&rudra::op::PcodeOpRef(op.clone()), block);
    }

    /// IOP-space Varnode aliasing an op pointer (PcodeOp::getOpFromConst
    /// round-trips this address).
    fn iop_alias(&mut self, target: &OpRef) -> VnRef {
        let ptr = std::sync::Arc::as_ptr(target) as usize as u64;
        self.fd.vbank.create_with_space(4, AddressSpace::Iop, ptr)
    }

    /// Create, insert, then destroy an op so it stays in the bank (dead
    /// list) but leaves its block — the dead-target state of cc:268-269.
    fn dead_target(&mut self, block: &BlockRef) -> OpRef {
        let c1 = self.constant(4, 31);
        let c2 = self.constant(4, 33);
        let t = self.make_op("t", OpCode::CPUI_INT_ADD, 2);
        self.set_input(&t, &c1, 0);
        self.set_input(&t, &c2, 1);
        self.unique_out(8, &t);
        self.insert_end(&t, block);
        self.fd.op_destroy(&rudra::op::PcodeOpRef(t.clone()));
        t
    }

    /// INDIRECT marker with a 2-byte register output (previous-heritage
    /// evidence smaller than its range) and an IOP input aliasing target.
    fn indirect_marker(&mut self, offset: u64, target: &OpRef, block: &BlockRef) -> OpRef {
        let c = self.constant(4, 35);
        let iop = self.iop_alias(target);
        let i = self.make_op("i", OpCode::CPUI_INDIRECT, 2);
        self.set_input(&i, &c, 0);
        self.set_input(&i, &iop, 1);
        self.written_register(offset, 2, &i);
        self.insert_end(&i, block);
        i
    }

    fn label_of(&self, op: &OpRef) -> &'static str {
        for (candidate, name) in &self.ops {
            if Arc::ptr_eq(candidate, op) {
                return name;
            }
        }
        "phi"
    }

    /// Production pre-state (as in the ownership fixture):
    /// `Funcdata::structureReset` (funcdata_block.cc:703) runs
    /// `structureLoops(rootlist)` then `calcForwardDominator(rootlist)`
    /// before ActionHeritage, and startProcessing builds the Heritage
    /// info list (funcdata.cc:166). structureLoops' first step is
    /// `BlockGraph::findSpanningTree` (block.cc:1009-1135), which assigns
    /// reverse-post-order FlowBlock indices and reorders the block list —
    /// the merge/augment walk compares those indices, and the diamond and
    /// two-join cases get b1/b2 swapped relative to creation order. The
    /// Rust mirror runs the ported `find_spanning_tree`
    /// (BLOCK-INDEX-ASSIGN-0001) first; `findIrreducible` is not ported
    /// (BLOCK-FINDIRREDUCIBLE-0001) but returns no-rebuild for these
    /// reducible graphs on the oracle side, and `build_dom_tree` is the
    /// dominator producer standing in for calcForwardDominator
    /// (mathematically identical immediate dominators).
    fn prepare_structure(&mut self) {
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        self.fd
            .bblocks
            .find_spanning_tree(&mut preorder, &mut rootlist)
            .expect("find_spanning_tree");
        self.fd.bblocks.build_dom_tree();
        self.fd.heritage.build_info_list();
    }

    /// Three consecutive op_heritage boundary calls, asserting the
    /// Rust-side ownership internals after each pass. `expect_gd` holds
    /// the per-pass persistent globaldisjoint entry count (the refine
    /// case's cover grows as refinement splits the register entry in
    /// pass 1 and the driver scan picks the new unique ranges up in
    /// pass 2, then stabilizes).
    fn run_three_passes(&mut self, expect_maxdepth: i32, expect_gd: [usize; 3]) -> Vec<i32> {
        self.run_three_passes_with(expect_maxdepth, expect_gd, None)
    }

    /// Three boundary calls with an optional injection after the first
    /// pass (mirrors the C++ default-argument hook): the revisit case
    /// injects previous-heritage markers between the first and second
    /// boundary calls, mirroring the inter-Action state that produces an
    /// OLD range with fresh free reads (cc:2708-2730).
    fn run_three_passes_with(
        &mut self,
        expect_maxdepth: i32,
        expect_gd: [usize; 3],
        mid_pass1: Option<fn(&mut Graph)>,
    ) -> Vec<i32> {
        self.prepare_structure();
        assert_eq!(self.fd.heritage.maxdepth, -1, "ctor sentinel maxdepth=-1");
        let mut seq = Vec::new();
        for pass in 0..3 {
            self.fd.op_heritage();
            if pass == 0 {
                if let Some(inject) = mid_pass1 {
                    inject(self);
                }
            }
            seq.push(self.fd.num_heritage_passes());
            assert_eq!(self.fd.heritage.maxdepth, expect_maxdepth);
            assert_eq!(
                self.fd.heritage.globaldisjoint.themap.len(),
                expect_gd[pass],
                "persistent globaldisjoint must survive every mem::take round-trip (pass {})",
                pass
            );
        }
        seq
    }

    fn op_list(&self) -> String {
        let mut parts = Vec::new();
        for op_ref in &self.fd.obank.optree {
            let op = op_ref.0.read().unwrap();
            // Dead ops keep NULL input slots in Ghidra's tree and are
            // bank internals, not live p-code; excluded on both sides.
            if (op.flags & rudra::op::pcodeop_flags::DEAD) != 0 {
                continue;
            }
            let mut part = format!(
                "{}.{}(",
                self.label_of(&op_ref.0),
                opcode_name(op.opcode)
            );
            for (slot, input) in op.inrefs.iter().enumerate() {
                if slot != 0 {
                    part.push(',');
                }
                part.push_str(&vn_descriptor(input));
            }
            part.push(')');
            parts.push(part);
        }
        parts.join(";")
    }

    fn op_count(&self) -> usize {
        self.fd.obank.optree.len()
    }

    /// Per-object phi projection mirroring the C++ oracle: for every
    /// parented MULTIEQUAL, in block index order and block op position
    /// order, print the output storage, each input's descriptor, and the
    /// merge block's in-edge j predecessor index for phi slot j.
    fn phi_projection(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        let size = self.fd.bblocks.get_size();
        for b in 0..size {
            let Some(bl) = self.fd.bblocks.get_block(b as usize) else {
                continue;
            };
            let ops = bl.read().unwrap().get_ops();
            for (pos, op_ref) in ops.iter().enumerate() {
                let op = op_ref.0.read().unwrap();
                if op.opcode != OpCode::CPUI_MULTIEQUAL {
                    continue;
                }
                let mut part = format!("b{b}@p{pos}(");
                if let Some(out_vn) = &op.output {
                    let v = out_vn.read().unwrap();
                    let code = match v.address_space {
                        AddressSpace::Register => 'R',
                        AddressSpace::Unique => 'U',
                        AddressSpace::Stack => 'S',
                        AddressSpace::Ram => 'M',
                        _ => 'X',
                    };
                    part.push_str(&format!(
                        "{code}{}:{}",
                        format!("{:x}", v.loc.as_u64()),
                        v.size
                    ));
                }
                part.push_str(")[");
                for (j, input) in op.inrefs.iter().enumerate() {
                    if j != 0 {
                        part.push(',');
                    }
                    let pred = bl.read().unwrap().get_in(j).map(|e| e.point.clone());
                    let pred_idx = pred
                        .map(|p| p.read().unwrap().get_index())
                        .unwrap_or(-1);
                    part.push_str(&format!(
                        "s{j}<{}>#p{}",
                        vn_descriptor(input),
                        pred_idx
                    ));
                }
                part.push(']');
                parts.push(part);
            }
        }
        parts.join(";")
    }

    fn phi_count(&self) -> usize {
        self.fd
            .obank
            .optree
            .iter()
            .filter(|o| o.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL)
            .count()
    }

    /// Creation-order witness mirroring the C++ oracle: MULTIEQUAL
    /// parent blocks in op-tree (SeqNum/uniq) order, i.e. the order
    /// placeMultiequals created them. The oracle's order comes from the
    /// depth-ordered PriorityQueue + augment walk (calcMultiequals
    /// cc:2448-2463, visitIncr cc:2394-2428), NOT block index.
    fn phi_seq_order(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for op_ref in &self.fd.obank.optree {
            let op = op_ref.0.read().unwrap();
            if op.opcode != OpCode::CPUI_MULTIEQUAL {
                continue;
            }
            let idx = op
                .parent
                .as_ref()
                .and_then(|p| p.upgrade())
                .map(|p| p.read().unwrap().get_index())
                .unwrap_or(-1);
            parts.push(format!("{idx}"));
        }
        parts.join(",")
    }

    fn vn_list(&self) -> String {
        let mut parts: Vec<String> = self
            .fd
            .vbank
            .loc_tree
            .iter()
            .map(|entry| vn_descriptor(&entry.0))
            .collect();
        parts.sort();
        parts.join(",")
    }

    fn vn_count(&self) -> usize {
        self.fd.vbank.loc_tree.len()
    }

    /// Per-block op-order witness mirroring the C++ oracle: every
    /// parented op's label (fixture name or opcode) in BLOCK LIST order —
    /// the decisive projection for the concatPieces/splitPieces
    /// element-anchor insertion semantics (cc:516-518/582-587/546/602).
    fn block_order(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        let size = self.fd.bblocks.get_size();
        for b in 0..size {
            let Some(bl) = self.fd.bblocks.get_block(b as usize) else {
                continue;
            };
            let ops = bl.read().unwrap().get_ops();
            let mut seq = format!("b{b}=");
            for (i, op_ref) in ops.iter().enumerate() {
                if i != 0 {
                    seq.push(',');
                }
                let op = op_ref.0.read().unwrap();
                let mut part = format!(
                    "{}.{}(",
                    self.label_of(&op_ref.0),
                    opcode_name(op.opcode)
                );
                for (slot, input) in op.inrefs.iter().enumerate() {
                    if slot != 0 {
                        part.push(',');
                    }
                    part.push_str(&vn_descriptor(input));
                }
                part.push(')');
                seq.push_str(&part);
            }
            parts.push(seq);
        }
        parts.join(";")
    }
}


/// Revisit-marker injection mirroring the C++ oracle case: three ranges,
/// each with a fresh free read plus a previous-heritage marker whose
/// 2-byte output is collect's removal evidence (cc:329-333).
fn inject_revisit_markers(g: &mut Graph) {
    let b1 = g.fd.bblocks.get_block(1).expect("b1");
    let b2 = g.fd.bblocks.get_block(2).expect("b2");
    let b3 = g.fd.bblocks.get_block(3).expect("b3");
    let c4 = g.constant(4, 37);
    // Range A (0x90:4, OLD): fresh free read + mid-block dead-target
    // INDIRECT marker in b1.
    let f2 = g.free_register(0x90, 4);
    let a2 = g.make_op("a2", OpCode::CPUI_INT_MULT, 2);
    g.set_input(&a2, &f2, 0);
    g.set_input(&a2, &c4, 1);
    g.unique_out(8, &a2);
    g.insert_end(&a2, &b1);
    let ta = g.dead_target(&b1);
    g.indirect_marker(0x90, &ta, &b1);
    let f2op = g.make_op("f2", OpCode::CPUI_INT_OR, 2);
    g.set_input(&f2op, &c4, 0);
    g.set_input(&f2op, &c4, 1);
    g.unique_out(8, &f2op);
    g.insert_end(&f2op, &b1);
    // Range B (0x98:4, NEW): fresh free read + dead-target INDIRECT at
    // the block tail of b2.
    let fb = g.free_register(0x98, 4);
    let a3 = g.make_op("a3", OpCode::CPUI_INT_ADD, 2);
    g.set_input(&a3, &fb, 0);
    g.set_input(&a3, &c4, 1);
    g.unique_out(8, &a3);
    g.insert_end(&a3, &b2);
    let tb = g.dead_target(&b2);
    g.indirect_marker(0x98, &tb, &b2);
    // Range C (0xa0:4, NEW): a 2-byte MULTIEQUAL marker followed by a
    // full-size MULTIEQUAL (kept) and a reader, in b3.
    let fc1 = g.free_register(0xa0, 4);
    let fc2 = g.free_register(0xa0, 4);
    let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 2);
    g.set_input(&m, &fc1, 0);
    g.set_input(&m, &fc2, 1);
    g.written_register(0xa0, 2, &m);
    g.insert_end(&m, &b3);
    let fd1 = g.free_register(0xa0, 4);
    let fd2 = g.free_register(0xa0, 4);
    let m2 = g.make_op("m2", OpCode::CPUI_MULTIEQUAL, 2);
    g.set_input(&m2, &fd1, 0);
    g.set_input(&m2, &fd2, 1);
    g.written_register(0xa0, 4, &m2);
    g.insert_end(&m2, &b3);
    let f4 = g.free_register(0xa0, 4);
    let x = g.make_op("x", OpCode::CPUI_INT_MULT, 2);
    g.set_input(&x, &f4, 0);
    g.set_input(&x, &c4, 1);
    g.unique_out(8, &x);
    g.insert_end(&x, &b3);
}
fn pass_text(seq: &[i32]) -> String {
    format!("{},{},{}", seq[0], seq[1], seq[2])
}

fn main() {
    println!("schema=1|fixture=HERITAGE-ADT-RENAME-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // case=adt_diamond_phi: diamond join with three heritaged register
    // ranges written on both arms and free-read after the join.
    {
        let mut g = Graph::new("adt_diamond_phi", 0x5300);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        let b3 = g.make_block(3);
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        let c8 = g.constant(8, 5);
        let d0 = g.make_op("d0", OpCode::CPUI_COPY, 1);
        g.set_input(&d0, &c8, 0);
        g.unique_out(8, &d0);
        g.insert_end(&d0, &b0);
        // Arm 1: three writes (0x10:8 ADD, 0x20:4 MULT, 0x30:1 COPY).
        let f1a = g.free_register(0x10, 8);
        let f1b = g.free_register(0x20, 4);
        let f1c = g.free_register(0x30, 1);
        let c41 = g.constant(4, 7);
        let w1a = g.make_op("w1a", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&w1a, &f1a, 0);
        g.set_input(&w1a, &c41, 1);
        g.written_register(0x10, 8, &w1a);
        g.insert_end(&w1a, &b1);
        let c42 = g.constant(4, 9);
        let w1b = g.make_op("w1b", OpCode::CPUI_INT_MULT, 2);
        g.set_input(&w1b, &f1b, 0);
        g.set_input(&w1b, &c42, 1);
        g.written_register(0x20, 4, &w1b);
        g.insert_end(&w1b, &b1);
        // Unused as an input (COPY reads only the free) but still created:
        // the constant varnode is part of the compared bank projection.
        let _c43 = g.constant(4, 11);
        let w1c = g.make_op("w1c", OpCode::CPUI_COPY, 1);
        g.set_input(&w1c, &f1c, 0);
        g.written_register(0x30, 1, &w1c);
        g.insert_end(&w1c, &b1);
        // Arm 2: same ranges, different opcodes (slot identity witness).
        let f2a = g.free_register(0x10, 8);
        let f2b = g.free_register(0x20, 4);
        let f2c = g.free_register(0x30, 1);
        let c44 = g.constant(4, 13);
        let w2a = g.make_op("w2a", OpCode::CPUI_INT_OR, 2);
        g.set_input(&w2a, &f2a, 0);
        g.set_input(&w2a, &c44, 1);
        g.written_register(0x10, 8, &w2a);
        g.insert_end(&w2a, &b2);
        let c45 = g.constant(4, 15);
        let w2b = g.make_op("w2b", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&w2b, &f2b, 0);
        g.set_input(&w2b, &c45, 1);
        g.written_register(0x20, 4, &w2b);
        g.insert_end(&w2b, &b2);
        // Unused as an input (COPY reads only the free) but still created:
        // the constant varnode is part of the compared bank projection.
        let _c46 = g.constant(4, 17);
        let w2c = g.make_op("w2c", OpCode::CPUI_COPY, 1);
        g.set_input(&w2c, &f2c, 0);
        g.written_register(0x30, 1, &w2c);
        g.insert_end(&w2c, &b2);
        // Join: one free read per range.
        let f3a = g.free_register(0x10, 8);
        let f3b = g.free_register(0x20, 4);
        let f3c = g.free_register(0x30, 1);
        let c47 = g.constant(4, 19);
        let r1 = g.make_op("r1", OpCode::CPUI_INT_OR, 2);
        g.set_input(&r1, &f3a, 0);
        g.set_input(&r1, &c47, 1);
        g.unique_out(8, &r1);
        g.insert_end(&r1, &b3);
        let c48 = g.constant(4, 21);
        let r2 = g.make_op("r2", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&r2, &f3b, 0);
        g.set_input(&r2, &c48, 1);
        g.unique_out(8, &r2);
        g.insert_end(&r2, &b3);
        let c49 = g.constant(4, 23);
        let r3 = g.make_op("r3", OpCode::CPUI_INT_MULT, 2);
        g.set_input(&r3, &f3c, 0);
        g.set_input(&r3, &c49, 1);
        g.unique_out(8, &r3);
        g.insert_end(&r3, &b3);
        // Four-block diamond: depths b0=1, b1/b2/b3=2 -> maxdepth 2; the
        // persistent cover holds the three register ranges plus the four
        // unique ranges.
        let seq = g.run_three_passes(2, [7, 7, 7]);
        println!(
            "case=adt_diamond_phi|pass={}|ops={}|phis={}|phi={}|oplist={}|vns={}|vnlist={}",
            pass_text(&seq),
            g.op_count(),
            g.phi_count(),
            g.phi_projection(),
            g.op_list(),
            g.vn_count(),
            g.vn_list()
        );
    }

    // case=phi_cycle_oldmark: loop-carried MULTIEQUAL whose slot-1 input
    // is an already-written value (old marker skip) and slot-0 input is a
    // free (promoted to input). Full projection.
    {
        let mut g = Graph::new("phi_cycle_oldmark", 0x5400);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        let b3 = g.make_block(3);
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        g.edge(&b2, &b3);
        let c8 = g.constant(8, 5);
        let c4 = g.constant(4, 7);
        let d0 = g.make_op("d0", OpCode::CPUI_COPY, 1);
        g.set_input(&d0, &c8, 0);
        g.unique_out(8, &d0);
        g.insert_end(&d0, &b0);
        let f = g.free_register(0x28, 8);
        let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 2);
        let m_out = g.written_register(0x28, 8, &m);
        g.set_input(&m, &f, 0);
        let r = g.make_op("r", OpCode::CPUI_INT_ADD, 2);
        let t3 = g.written_register(0x28, 8, &r);
        g.set_input(&r, &m_out, 0);
        g.set_input(&r, &c4, 1);
        g.set_input(&m, &t3, 1);
        g.insert_end(&m, &b1);
        g.insert_end(&r, &b2);
        let o = g.make_op("o", OpCode::CPUI_INT_OR, 2);
        g.set_input(&o, &m_out, 0);
        g.set_input(&o, &c4, 1);
        g.unique_out(8, &o);
        g.insert_end(&o, &b3);
        // Four-block dominator chain b0 > b1 > b2 > b3: depths 1..4; the
        // persistent cover holds the merged register 0x28 entry plus the
        // two unique ranges.
        let seq = g.run_three_passes(4, [3, 3, 3]);
        println!(
            "case=phi_cycle_oldmark|pass={}|ops={}|phis={}|phi={}|oplist={}|vns={}|vnlist={}",
            pass_text(&seq),
            g.op_count(),
            g.phi_count(),
            g.phi_projection(),
            g.op_list(),
            g.vn_count(),
            g.vn_list()
        );
    }

    // case=adt_two_join_order: two nested joins at different dominator
    // depths; the merge vector order from the depth-ordered
    // PriorityQueue/augment walk is [deeper join first], while a
    // block-index ordering would give the opposite. The seq field
    // distinguishes the two implementations.
    {
        let mut g = Graph::new("adt_two_join_order", 0x5500);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        let b3 = g.make_block(3);
        let b4 = g.make_block(4);
        let b5 = g.make_block(5);
        let b6 = g.make_block(6);
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b3, &b4);
        g.edge(&b3, &b5);
        g.edge(&b4, &b6);
        g.edge(&b5, &b6);
        let c8 = g.constant(8, 5);
        let d0 = g.make_op("d0", OpCode::CPUI_COPY, 1);
        g.set_input(&d0, &c8, 0);
        g.unique_out(8, &d0);
        g.insert_end(&d0, &b0);
        let f1 = g.free_register(0x60, 8);
        let c41 = g.constant(4, 7);
        let w1 = g.make_op("w1", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&w1, &f1, 0);
        g.set_input(&w1, &c41, 1);
        g.written_register(0x60, 8, &w1);
        g.insert_end(&w1, &b1);
        let f5 = g.free_register(0x60, 8);
        let c42 = g.constant(4, 9);
        let w5 = g.make_op("w5", OpCode::CPUI_INT_OR, 2);
        g.set_input(&w5, &f5, 0);
        g.set_input(&w5, &c42, 1);
        g.written_register(0x60, 8, &w5);
        g.insert_end(&w5, &b5);
        let f6 = g.free_register(0x60, 8);
        let c43 = g.constant(4, 11);
        let r6 = g.make_op("r6", OpCode::CPUI_INT_MULT, 2);
        g.set_input(&r6, &f6, 0);
        g.set_input(&r6, &c43, 1);
        g.unique_out(8, &r6);
        g.insert_end(&r6, &b6);
        // RPO depths: b6 sits three levels under b0 -> maxdepth 3; the
        // persistent cover holds the register 0x60 entry plus the two
        // unique ranges.
        let seq = g.run_three_passes(3, [3, 3, 3]);
        println!(
            "case=adt_two_join_order|pass={}|ops={}|phis={}|seq={}|phi={}|oplist={}|vns={}|vnlist={}",
            pass_text(&seq),
            g.op_count(),
            g.phi_count(),
            g.phi_seq_order(),
            g.phi_projection(),
            g.op_list(),
            g.vn_count(),
            g.vn_list()
        );
    }

    // case=adt_refine_order: 8-byte range, max write 4 -> refinement into
    // four 2-byte pieces; refineRead's 3-PIECE concat chain before the
    // reader and refineWrite's 2-SUBPIECE groups after each write are
    // pinned by the block-order projection (element-anchor semantics).
    {
        let mut g = Graph::new("adt_refine_order", 0x5600);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        let c8 = g.constant(8, 5);
        let d0 = g.make_op("d0", OpCode::CPUI_COPY, 1);
        g.set_input(&d0, &c8, 0);
        g.unique_out(8, &d0);
        g.insert_end(&d0, &b0);
        let fa = g.free_register(0x70, 4);
        let c41 = g.constant(4, 7);
        let wa = g.make_op("wa", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&wa, &fa, 0);
        g.set_input(&wa, &c41, 1);
        g.written_register(0x70, 4, &wa);
        g.insert_end(&wa, &b0);
        let fb = g.free_register(0x72, 4);
        let c42 = g.constant(4, 9);
        let wb = g.make_op("wb", OpCode::CPUI_INT_OR, 2);
        g.set_input(&wb, &fb, 0);
        g.set_input(&wb, &c42, 1);
        g.written_register(0x72, 4, &wb);
        g.insert_end(&wb, &b0);
        let fr = g.free_register(0x70, 8);
        let c43 = g.constant(4, 11);
        let r = g.make_op("r", OpCode::CPUI_INT_MULT, 2);
        g.set_input(&r, &fr, 0);
        g.set_input(&r, &c43, 1);
        g.unique_out(8, &r);
        g.insert_end(&r, &b1);
        // Two-block chain: depths 1,2 -> maxdepth 2. Per-pass persistent
        // globaldisjoint: pass 1 = the four 2-byte register pieces
        // (refinement splits the merged 0x70 entry, cc:1922-1938) + d0/r
        // unique ranges = 6; pass 2 adds the seven refinement-created
        // unique ranges = 13; pass 3 stable.
        let seq = g.run_three_passes(2, [6, 13, 13]);
        println!(
            "case=adt_refine_order|pass={}|ops={}|order={}|oplist={}|vns={}|vnlist={}",
            pass_text(&seq),
            g.op_count(),
            g.block_order(),
            g.op_list(),
            g.vn_count(),
            g.vn_list()
        );
    }

    // case=adt_revisit_positions: pass 1 heritages range 0x90:4; the
    // injection adds previous-heritage markers + fresh free reads; pass 2
    // converts each marker to SUBPIECE at the element-anchored position
    // (dead-target mid-block [.., a2, S, f2], dead-target tail [a3, S],
    // MULTIEQUAL group [m2, S, x]) — pinned by the block-order projection.
    {
        let mut g = Graph::new("adt_revisit_positions", 0x5700);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        let b3 = g.make_block(3);
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b3);
        let c4 = g.constant(4, 7);
        let fw = g.free_register(0x90, 4);
        let w = g.make_op("w", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&w, &fw, 0);
        g.set_input(&w, &c4, 1);
        g.written_register(0x90, 4, &w);
        g.insert_end(&w, &b0);
        let fr = g.free_register(0x90, 4);
        let r = g.make_op("r", OpCode::CPUI_INT_OR, 2);
        g.set_input(&r, &fr, 0);
        g.set_input(&r, &c4, 1);
        g.unique_out(8, &r);
        g.insert_end(&r, &b1);
        // Blocks b0>b1>{b2,b3}: depths 1,2,3,3 -> maxdepth 3; per-pass cover:
        // pass 1 = range 0x90 + r's unique = 2; pass 2 adds ranges
        // 0x98/0xa0 and the six new unique outputs = 8; pass 3 stable.
        let seq = g.run_three_passes_with(3, [2, 8, 8], Some(inject_revisit_markers));
        println!(
            "case=adt_revisit_positions|pass={}|ops={}|order={}|oplist={}|vns={}|vnlist={}",
            pass_text(&seq),
            g.op_count(),
            g.block_order(),
            g.op_list(),
            g.vn_count(),
            g.vn_list()
        );
    }
}
