// HERITAGE-DRIVER-SWITCH-0001: Rugra comparand for the locked Ghidra 12.0.4
// ActionHeritage -> Funcdata::opHeritage -> Heritage::heritage production
// driver oracle. Mirrors tests/oracle/heritage_driver_switch_1204.cc case
// for case: the same synthetic CFG/def-use graphs are built through the
// production Funcdata APIs, the production boundary `op_heritage` runs once
// or several times per case (the repeatapply mainloop re-entry shape of
// coreaction.cc:5489-5492), and the post-pass projection (pass counter,
// per-space heritagePass lookups at colliding register/stack offsets, read
// input descriptors, whole-bank free-with-reader census, op list, phi
// projection, Varnode multiset) is printed in the shared observation
// format.
//
// The Rust comparand additionally ASSERTS, without printing (so stdout
// stays byte-comparable), the driver-switch production invariants: the
// canonical `Heritage::heritage` re-entry is idempotent (stable op count
// across passes) and the LocationMap keeps register/stack entries at the
// same offset disjoint (the space-identity fix this TODO landed; Ghidra
// gets it from `map<Address,SizePass>` whose Address carries the space).

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
        OpCode::CPUI_INT_SUB => "INT_SUB",
        OpCode::CPUI_INT_OR => "INT_OR",
        OpCode::CPUI_BOOL_NEGATE => "BOOL_NEGATE",
        OpCode::CPUI_BOOL_AND => "BOOL_AND",
        OpCode::CPUI_BOOL_OR => "BOOL_OR",
        OpCode::CPUI_CBRANCH => "CBRANCH",
        OpCode::CPUI_RETURN => "RETURN",
        OpCode::CPUI_MULTIEQUAL => "MULTIEQUAL",
        OpCode::CPUI_PIECE => "PIECE",
        OpCode::CPUI_SUBPIECE => "SUBPIECE",
        _ => "OTHER",
    }
}

// Varnode descriptor shared with the C++ oracle fixture:
//   constant -> C<size>:<hex-value>; register -> R<hex-offset>:<size>:<I|W|F>[+<def-op>];
//   stack -> S<hex-offset>:<size>:<I|W|F>[+<def-op>]; unique -> U<size>:<I|W|F>[+<def-op>].
fn vn_descriptor(vn: &VnRef) -> String {
    let value = vn.read().unwrap();
    if value.is_constant() {
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

    // PcodeEmitFd::dump read form: a FRESH free Varnode per reference.
    fn free_register(&mut self, offset: u64, size: usize) -> VnRef {
        self.fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset)
    }

    fn free_stack(&mut self, offset: u64, size: usize) -> VnRef {
        self.fd
            .vbank
            .create_with_space(size, AddressSpace::Stack, offset)
    }

    fn written_register(&mut self, offset: u64, size: usize, op: &OpRef) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.fd
            .op_set_output(&rudra::op::PcodeOpRef(op.clone()), vn.clone());
        op.read()
            .unwrap()
            .output
            .clone()
            .expect("written register output")
    }

    fn written_stack(&mut self, offset: u64, size: usize, op: &OpRef) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Stack, offset);
        self.fd
            .op_set_output(&rudra::op::PcodeOpRef(op.clone()), vn.clone());
        op.read()
            .unwrap()
            .output
            .clone()
            .expect("written stack output")
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd
            .op_set_input(&rudra::op::PcodeOpRef(op.clone()), vn.clone(), slot);
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd
            .op_insert_end(&rudra::op::PcodeOpRef(op.clone()), block);
    }

    /// Production pre-state (as in the FLAGFREE/ADT-RENAME fixtures):
    /// findSpanningTree reverse-post-order indices + dominator tree +
    /// heritage.buildInfoList (funcdata.cc:166).
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

    /// Heritage::heritagePass (heritage.hh:325): pass when the (space,offset)
    /// was entered into the disjoint cover, or -1. Rugra's LocationMap keys
    /// by (space, offset) — the space identity this TODO landed.
    fn heritage_pass_of(&self, space: AddressSpace, offset: u64) -> i32 {
        self.fd
            .heritage
            .globaldisjoint
            .find_pass(space, Address::new(offset))
    }

    fn label_of(&self, op: &OpRef) -> &'static str {
        for (candidate, name) in &self.ops {
            if Arc::ptr_eq(candidate, op) {
                return name;
            }
        }
        "phi"
    }

    fn op_list(&self) -> String {
        let mut parts = Vec::new();
        for op_ref in &self.fd.obank.optree {
            let op = op_ref.0.read().unwrap();
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

    fn op_count_all(&self) -> usize {
        self.fd
            .obank
            .optree
            .iter()
            .filter(|o| (o.0.read().unwrap().flags & rudra::op::pcodeop_flags::DEAD) == 0)
            .count()
    }

    /// Whole-bank free-with-descendant census (annotation/constant excepted)
    /// — the varnode.cc:334-336 throw precondition.
    fn free_with_reader(&self) -> usize {
        self.fd
            .vbank
            .loc_tree
            .iter()
            .filter(|vn| {
                let v = vn.0.read().unwrap();
                if v.is_constant() || v.is_annotation() {
                    return false;
                }
                v.is_free() && !v.has_no_descend()
            })
            .count()
    }

    fn vn_multiset(&self) -> String {
        let mut parts: Vec<String> = self
            .fd
            .vbank
            .loc_tree
            .iter()
            .filter(|vn| !vn.0.read().unwrap().is_annotation())
            .map(|vn| vn_descriptor(&vn.0))
            .collect();
        parts.sort();
        parts.join(",")
    }

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
                if let Some(out) = &op.output {
                    part.push_str(&vn_descriptor(out));
                }
                part.push_str(")[");
                for (j, input) in op.inrefs.iter().enumerate() {
                    if j != 0 {
                        part.push(',');
                    }
                    let pred_idx = bl
                        .read()
                        .unwrap()
                        .get_in(j)
                        .map(|e| e.point.read().unwrap().get_index())
                        .unwrap_or(-1);
                    part.push_str(&format!(
                        "s{j}<{}>#p{pred_idx}",
                        vn_descriptor(input)
                    ));
                }
                part.push(']');
                parts.push(part);
            }
        }
        parts.join(";")
    }
}

fn main() {
    println!(
        "schema=1|fixture=HERITAGE-DRIVER-SWITCH-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case A: single pass, write then read ----
    {
        let mut g = Graph::new("switch_written_read", 0x1000);
        let b0 = g.make_block(0);

        let w = g.make_op("w", OpCode::CPUI_INT_SUB, 2);
        let c0 = g.constant(1, 0x0);
        let c1 = g.constant(1, 0x1);
        g.set_input(&w, &c0, 0);
        g.set_input(&w, &c1, 1);
        g.written_register(0x30, 8, &w);
        g.insert_end(&w, &b0);

        let r = g.make_op("r", OpCode::CPUI_INT_OR, 2);
        let free = g.free_register(0x30, 8);
        let c11 = g.constant(8, 0x11);
        g.set_input(&r, &free, 0);
        g.set_input(&r, &c11, 1);
        g.unique_out(8, &r);
        g.insert_end(&r, &b0);

        let c = g.make_op("c", OpCode::CPUI_CBRANCH, 2);
        let tgt = g.constant(8, 0x2000);
        let r_out = r.read().unwrap().output.clone().expect("r out");
        g.set_input(&c, &tgt, 0);
        g.set_input(&c, &r_out, 1);
        g.insert_end(&c, &b0);

        g.prepare_structure();
        g.fd.op_heritage();

        let read_in = {
            let op = r.read().unwrap();
            vn_descriptor(&op.inrefs[0].clone())
        };
        println!(
            "case=switch_written_read|pass={}|hp_reg={}|hp_stack={}|read_in={read_in}|ops={}|free_with_reader={}|phis={}|ops_proj={}|vn={}",
            g.fd.num_heritage_passes(),
            g.heritage_pass_of(AddressSpace::Register, 0x30),
            g.heritage_pass_of(AddressSpace::Stack, 0x30),
            g.op_count_all(),
            g.free_with_reader(),
            g.phi_projection(),
            g.op_list(),
            g.vn_multiset(),
        );
    }

    // ---- case B: diamond, three re-entry passes ----
    {
        let mut g = Graph::new("switch_diamond_reherit", 0x2000);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        let b3 = g.make_block(3);
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);

        let w1 = g.make_op("w1", OpCode::CPUI_INT_SUB, 2);
        let c2 = g.constant(8, 0x2);
        let c3 = g.constant(8, 0x3);
        g.set_input(&w1, &c2, 0);
        g.set_input(&w1, &c3, 1);
        g.written_register(0x38, 8, &w1);
        g.insert_end(&w1, &b1);

        let w2 = g.make_op("w2", OpCode::CPUI_INT_OR, 2);
        let c4 = g.constant(8, 0x4);
        let c5 = g.constant(8, 0x5);
        g.set_input(&w2, &c4, 0);
        g.set_input(&w2, &c5, 1);
        g.written_register(0x38, 8, &w2);
        g.insert_end(&w2, &b2);

        let r = g.make_op("r", OpCode::CPUI_INT_ADD, 2);
        let free = g.free_register(0x38, 8);
        let c6 = g.constant(8, 0x6);
        g.set_input(&r, &free, 0);
        g.set_input(&r, &c6, 1);
        g.unique_out(8, &r);
        g.insert_end(&r, &b3);

        let c = g.make_op("c", OpCode::CPUI_CBRANCH, 2);
        let tgt = g.constant(8, 0x3000);
        let r_out = r.read().unwrap().output.clone().expect("r out");
        g.set_input(&c, &tgt, 0);
        g.set_input(&c, &r_out, 1);
        g.insert_end(&c, &b3);

        g.prepare_structure();
        let ops_after_first;
        {
            g.fd.op_heritage();
            ops_after_first = g.op_count_all();
            g.fd.op_heritage();
            let ops_after_second = g.op_count_all();
            assert_eq!(
                ops_after_first, ops_after_second,
                "re-entry pass 2 must be idempotent (no new ops)"
            );
            g.fd.op_heritage();
            let ops_after_third = g.op_count_all();
            assert_eq!(
                ops_after_first, ops_after_third,
                "re-entry pass 3 must be idempotent (no new ops)"
            );
        }

        let read_in = {
            let op = r.read().unwrap();
            vn_descriptor(&op.inrefs[0].clone())
        };
        println!(
            "case=switch_diamond_reherit|pass={}|hp_reg={}|hp_stack={}|read_in={read_in}|ops={}|free_with_reader={}|phis={}|ops_proj={}|vn={}",
            g.fd.num_heritage_passes(),
            g.heritage_pass_of(AddressSpace::Register, 0x38),
            g.heritage_pass_of(AddressSpace::Stack, 0x38),
            g.op_count_all(),
            g.free_with_reader(),
            g.phi_projection(),
            g.op_list(),
            g.vn_multiset(),
        );
    }

    // ---- case C: same offset in register and stack spaces ----
    {
        let mut g = Graph::new("switch_cross_space", 0x3000);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);

        let wr = g.make_op("wr", OpCode::CPUI_INT_SUB, 2);
        let c7 = g.constant(8, 0x7);
        let c8 = g.constant(8, 0x8);
        g.set_input(&wr, &c7, 0);
        g.set_input(&wr, &c8, 1);
        g.written_register(0x30, 8, &wr);
        g.insert_end(&wr, &b0);

        let ws = g.make_op("ws", OpCode::CPUI_INT_OR, 2);
        let c9 = g.constant(8, 0x9);
        let ca = g.constant(8, 0xa);
        g.set_input(&ws, &c9, 0);
        g.set_input(&ws, &ca, 1);
        g.written_stack(0x30, 8, &ws);
        g.insert_end(&ws, &b0);

        let rr = g.make_op("rr", OpCode::CPUI_INT_ADD, 2);
        let free_r = g.free_register(0x30, 8);
        let cb = g.constant(8, 0xb);
        g.set_input(&rr, &free_r, 0);
        g.set_input(&rr, &cb, 1);
        g.unique_out(8, &rr);
        g.insert_end(&rr, &b1);

        let rs = g.make_op("rs", OpCode::CPUI_INT_ADD, 2);
        let free_s = g.free_stack(0x30, 8);
        let cc = g.constant(8, 0xc);
        g.set_input(&rs, &free_s, 0);
        g.set_input(&rs, &cc, 1);
        g.unique_out(8, &rs);
        g.insert_end(&rs, &b1);

        let cret = g.make_op("cret", OpCode::CPUI_RETURN, 1);
        let tgt = g.constant(8, 0x4000);
        g.set_input(&cret, &tgt, 0);
        g.insert_end(&cret, &b1);

        g.prepare_structure();
        // Pass 0 heritages register (delay 0); stack is delayed to pass 1.
        g.fd.op_heritage();
        g.fd.op_heritage();

        // Rust-only invariant (no stdout): the colliding offsets hold TWO
        // disjoint LocationMap entries (register pass 0, stack pass 1) —
        // the space-identity of the cover Ghidra gets from
        // `map<Address,SizePass>`.
        let hp_reg = g.heritage_pass_of(AddressSpace::Register, 0x30);
        let hp_stack = g.heritage_pass_of(AddressSpace::Stack, 0x30);
        assert_eq!(hp_reg, 0, "register 0x30 must be heritaged at pass 0");
        assert_eq!(hp_stack, 1, "stack 0x30 must get its OWN pass-1 entry");

        let (read_in, read_in2) = {
            let rr_in = {
                let op = rr.read().unwrap();
                vn_descriptor(&op.inrefs[0].clone())
            };
            let rs_in = {
                let op = rs.read().unwrap();
                vn_descriptor(&op.inrefs[0].clone())
            };
            (rr_in, rs_in)
        };
        println!(
            "case=switch_cross_space|pass={}|hp_reg={hp_reg}|hp_stack={hp_stack}|read_in={read_in}|read_in2={read_in2}|ops={}|free_with_reader={}|phis={}|ops_proj={}|vn={}",
            g.fd.num_heritage_passes(),
            g.op_count_all(),
            g.free_with_reader(),
            g.phi_projection(),
            g.op_list(),
            g.vn_multiset(),
        );
    }

    // ---- case D: late free read absorbed by re-entry (prev==2 OLD range) ----
    {
        let mut g = Graph::new("switch_late_free_reentry", 0x4000);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);

        let w = g.make_op("w", OpCode::CPUI_INT_SUB, 2);
        let cd = g.constant(8, 0xd);
        let ce = g.constant(8, 0xe);
        g.set_input(&w, &cd, 0);
        g.set_input(&w, &ce, 1);
        g.written_register(0x40, 8, &w);
        g.insert_end(&w, &b0);

        let r1 = g.make_op("r1", OpCode::CPUI_INT_OR, 2);
        let free1 = g.free_register(0x40, 8);
        let cf = g.constant(8, 0xf);
        g.set_input(&r1, &free1, 0);
        g.set_input(&r1, &cf, 1);
        g.unique_out(8, &r1);
        g.insert_end(&r1, &b1);

        let cret = g.make_op("cret", OpCode::CPUI_RETURN, 1);
        let tgt = g.constant(8, 0x5000);
        g.set_input(&cret, &tgt, 0);
        g.insert_end(&cret, &b1);

        g.prepare_structure();
        g.fd.op_heritage();

        // Post-heritage churn: a brand-new free read of the now-OLD range.
        let r2 = g.make_op("r2", OpCode::CPUI_INT_ADD, 2);
        let free2 = g.free_register(0x40, 8);
        let c10 = g.constant(8, 0x10);
        g.set_input(&r2, &free2, 0);
        g.set_input(&r2, &c10, 1);
        g.unique_out(8, &r2);
        g.insert_end(&r2, &b1);

        let ops_after_pass0 = g.op_count_all();
        g.fd.op_heritage();
        let ops_after_pass1 = g.op_count_all();
        // The OLD range re-entry must ABSORB the fresh read by relinking it
        // to the existing write — no new phi, no net op growth beyond r2.
        assert_eq!(
            ops_after_pass1,
            ops_after_pass0,
            "late-free re-entry must not create additional ops"
        );

        let read_in = {
            let op = r2.read().unwrap();
            vn_descriptor(&op.inrefs[0].clone())
        };
        let late_free = {
            let v = r2.read().unwrap().inrefs[0].clone();
            let guard = v.read().unwrap();
            !guard.is_free()
        };
        assert!(late_free, "late free read must be linked by re-entry");

        println!(
            "case=switch_late_free_reentry|pass={}|hp_reg={}|hp_stack={}|read_in={read_in}|ops={ops_after_pass1}|ops_after_pass0={ops_after_pass0}|free_with_reader={}|phis={}|ops_proj={}|vn={}",
            g.fd.num_heritage_passes(),
            g.heritage_pass_of(AddressSpace::Register, 0x40),
            g.heritage_pass_of(AddressSpace::Stack, 0x40),
            g.free_with_reader(),
            g.phi_projection(),
            g.op_list(),
            g.vn_multiset(),
        );
    }

    // ---- case E: partial-width write forces refinement; pieces must be
    //      visible to the re-collect (live beginLoc/endLoc windows) ----
    {
        let mut g = Graph::new("switch_refinement_recollect", 0x5000);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);

        let w = g.make_op("w", OpCode::CPUI_INT_SUB, 2);
        let c0 = g.constant(8, 0xd0);
        let c1 = g.constant(8, 0xd1);
        g.set_input(&w, &c0, 0);
        g.set_input(&w, &c1, 1);
        g.written_register(0x50, 4, &w);
        g.insert_end(&w, &b0);

        let r = g.make_op("r", OpCode::CPUI_INT_ADD, 2);
        let free = g.free_register(0x50, 8);
        let c2 = g.constant(8, 0xd2);
        g.set_input(&r, &free, 0);
        g.set_input(&r, &c2, 1);
        g.unique_out(8, &r);
        g.insert_end(&r, &b1);

        let cret = g.make_op("cret", OpCode::CPUI_RETURN, 1);
        let tgt = g.constant(8, 0x6000);
        g.set_input(&cret, &tgt, 0);
        g.insert_end(&cret, &b1);

        g.prepare_structure();
        g.fd.op_heritage();

        // Rust-only invariant (no stdout): the refinement pieces created
        // during this placeMultiequals walk must be SSA-consumed by the
        // live re-collect — the 8-byte read is rewritten onto the refined
        // structure and no free-with-reader varnode survives (a frozen
        // snapshot implementation leaves the second piece unheritaged).
        assert_eq!(
            g.free_with_reader(),
            0,
            "refinement pieces must be consumed by the live re-collect"
        );

        let read_in = {
            let op = r.read().unwrap();
            vn_descriptor(&op.inrefs[0].clone())
        };
        println!(
            "case=switch_refinement_recollect|pass={}|hp_reg={}|hp_stack={}|read_in={read_in}|ops={}|free_with_reader={}|phis={}|ops_proj={}|vn={}",
            g.fd.num_heritage_passes(),
            g.heritage_pass_of(AddressSpace::Register, 0x50),
            g.heritage_pass_of(AddressSpace::Stack, 0x50),
            g.op_count_all(),
            g.free_with_reader(),
            g.phi_projection(),
            g.op_list(),
            g.vn_multiset(),
        );
    }
}
