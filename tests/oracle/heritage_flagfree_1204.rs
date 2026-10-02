// HERITAGE-FLAGFREE-SSA-0001: Rugra comparand for the locked Ghidra 12.0.4
// SLEIGH BOOL flag/byte free-read SSA-ification oracle. Mirrors
// tests/oracle/heritage_flagfree_1204.cc case for case: the same synthetic
// CFG/def-use graphs are built through the production Funcdata APIs, one
// `op_heritage` boundary call runs per case, and the post-pass projection
// (BOOL input descriptor, whole-bank free-with-reader census, op list with
// per-slot input classes, phi projection, Varnode multiset) is printed in
// the shared observation format.
//
// The Rust fixture additionally ASSERTS, without printing (so stdout stays
// byte-comparable), the same invariants over the DIRECT production route
// (`Funcdata::run_heritage_direct`: place_multiequals_direct +
// rename_direct, the route ActionHeritage drives): the 1-byte free flag
// reads are replaced there too and no free-with-descendant Varnode survives
// in the register/unique spaces. This locks the production-path half of the
// varnode.cc:330-338 unreachability premise whose downstream loss is the
// 351-WARN E2E signal (see TODO HERITAGE-FLAGFREE-SSA-0001).

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
        OpCode::CPUI_MULTIEQUAL => "MULTIEQUAL",
        _ => "OTHER",
    }
}

// Varnode descriptor shared with the C++ oracle fixture:
//   constant -> C<size>:<hex-value>; register -> R<hex-offset>:<size>:<I|W|F>[+<def-op>];
//   unique -> U<size>:<I|W|F>[+<def-op>].
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

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd
            .op_set_input(&rudra::op::PcodeOpRef(op.clone()), vn.clone(), slot);
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd
            .op_insert_end(&rudra::op::PcodeOpRef(op.clone()), block);
    }

    /// Production pre-state (as in the ADT-RENAME fixture):
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

    /// Whole-bank free-with-descendant census over the register and unique
    /// spaces (annotation/constant excepted) — the varnode.cc:334-336 throw
    /// precondition. Ghidra's whole-bank beginLoc() walk spans every space;
    /// Rugra's Address carries no space identity, so the census enumerates
    /// the two spaces this fixture populates (register + unique; const/ram
    /// reads here are constants and branch-target constants, which are
    /// heritage-known).
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

enum Shape {
    Written,
    Unwritten,
    Diamond,
}

fn build(shape: Shape) -> (Graph, OpRef) {
    let mut g = Graph::new(
        match shape {
            Shape::Written => "flagfree_written",
            Shape::Unwritten => "flagfree_unwritten",
            Shape::Diamond => "flagfree_diamond",
        },
        match shape {
            Shape::Written => 0x1000,
            Shape::Unwritten => 0x2000,
            Shape::Diamond => 0x3000,
        },
    );
    match shape {
        Shape::Written => {
            let b0 = g.make_block(0);
            let w = g.make_op("w", OpCode::CPUI_INT_SUB, 2);
            let c0 = g.constant(1, 0x0);
            let c1 = g.constant(1, 0x1);
            g.set_input(&w, &c0, 0);
            g.set_input(&w, &c1, 1);
            g.written_register(0x206, 1, &w);
            g.insert_end(&w, &b0);

            let n = g.make_op("n", OpCode::CPUI_BOOL_NEGATE, 1);
            let flag = g.free_register(0x206, 1);
            g.set_input(&n, &flag, 0);
            g.unique_out(1, &n);
            g.insert_end(&n, &b0);

            let c = g.make_op("c", OpCode::CPUI_CBRANCH, 2);
            let tgt = g.constant(8, 0x2000);
            let n_out = n.read().unwrap().output.clone().expect("n out");
            g.set_input(&c, &tgt, 0);
            g.set_input(&c, &n_out, 1);
            g.insert_end(&c, &b0);
            (g, n)
        }
        Shape::Unwritten => {
            let b0 = g.make_block(0);
            let n = g.make_op("n", OpCode::CPUI_BOOL_NEGATE, 1);
            let flag = g.free_register(0x207, 1);
            g.set_input(&n, &flag, 0);
            g.unique_out(1, &n);
            g.insert_end(&n, &b0);

            let c = g.make_op("c", OpCode::CPUI_CBRANCH, 2);
            let tgt = g.constant(8, 0x3000);
            let n_out = n.read().unwrap().output.clone().expect("n out");
            g.set_input(&c, &tgt, 0);
            g.set_input(&c, &n_out, 1);
            g.insert_end(&c, &b0);
            (g, n)
        }
        Shape::Diamond => {
            let b0 = g.make_block(0);
            let b1 = g.make_block(1);
            let b2 = g.make_block(2);
            let b3 = g.make_block(3);
            g.edge(&b0, &b1);
            g.edge(&b0, &b2);
            g.edge(&b1, &b3);
            g.edge(&b2, &b3);

            let w1 = g.make_op("w1", OpCode::CPUI_INT_SUB, 2);
            let c2 = g.constant(1, 0x2);
            let c3 = g.constant(1, 0x3);
            g.set_input(&w1, &c2, 0);
            g.set_input(&w1, &c3, 1);
            g.written_register(0x206, 1, &w1);
            g.insert_end(&w1, &b1);

            let w2 = g.make_op("w2", OpCode::CPUI_INT_OR, 2);
            let c4 = g.constant(1, 0x4);
            let c5 = g.constant(1, 0x5);
            g.set_input(&w2, &c4, 0);
            g.set_input(&w2, &c5, 1);
            g.written_register(0x206, 1, &w2);
            g.insert_end(&w2, &b2);

            let n = g.make_op("n", OpCode::CPUI_BOOL_NEGATE, 1);
            let flag = g.free_register(0x206, 1);
            g.set_input(&n, &flag, 0);
            g.unique_out(1, &n);
            g.insert_end(&n, &b3);

            let c = g.make_op("c", OpCode::CPUI_CBRANCH, 2);
            let tgt = g.constant(8, 0x4000);
            let n_out = n.read().unwrap().output.clone().expect("n out");
            g.set_input(&c, &tgt, 0);
            g.set_input(&c, &n_out, 1);
            g.insert_end(&c, &b3);
            (g, n)
        }
    }
}

fn emit_case(label: &str, g: &Graph, n: &OpRef) {
    let bool_in = {
        let op = n.read().unwrap();
        vn_descriptor(&op.inrefs[0].clone())
    };
    println!(
        "case={label}|pass={}|ops={}|bool_in={bool_in}|free_with_reader={}|phis={}|ops_proj={}|vn={}",
        g.fd.num_heritage_passes(),
        g.op_count_all(),
        g.free_with_reader(),
        g.phi_projection(),
        g.op_list(),
        g.vn_multiset(),
    );
}

/// Rust-only production-route assertion (no stdout): after
/// `run_heritage_direct` (place_multiequals_direct + rename_direct — the
/// route ActionHeritage drives) the BOOL flag input must not remain a free
/// read and the bank must hold no free-with-descendant Varnode.
#[allow(dead_code)]
fn assert_direct_route(shape: Shape) {
    let label = label_shape(&shape).to_string();
    let (mut g, n) = build(shape);
    g.prepare_structure();
    g.fd.run_heritage_direct();
    let flag_in = n.read().unwrap().inrefs[0].clone();
    {
        let v = flag_in.read().unwrap();
        assert!(
            !v.is_free(),
            "direct route: BOOL flag input still free ({label} {:?}:{:#x})",
            v.address_space,
            v.loc.as_u64()
        );
    }
    let leftover = g.free_with_reader();
    assert_eq!(
        leftover, 0,
        "direct route: free varnodes with readers survive ({label})"
    );
}

fn label_shape(shape: &Shape) -> &'static str {
    match shape {
        Shape::Written => "flagfree_bool_read_written",
        Shape::Unwritten => "flagfree_bool_read_unwritten",
        Shape::Diamond => "flagfree_bool_diamond",
    }
}

fn main() {
    println!(
        "schema=1|fixture=HERITAGE-FLAGFREE-SSA-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    for label in [
        "flagfree_bool_read_written",
        "flagfree_bool_read_unwritten",
        "flagfree_bool_diamond",
    ] {
        let shape = match label {
            "flagfree_bool_read_written" => Shape::Written,
            "flagfree_bool_read_unwritten" => Shape::Unwritten,
            _ => Shape::Diamond,
        };
        // Canonical route (Funcdata::opHeritage): the byte-compared
        // projection.
        let (mut g, n) = build(shape);
        g.prepare_structure();
        g.fd.op_heritage();
        emit_case(label, &g, &n);
    }

    // Production direct route (ActionHeritage's place_multiequals_direct +
    // rename_direct): Rust-side invariant assertions only, so stdout stays
    // byte-comparable with the oracle (which has no direct route).
    assert_direct_route(Shape::Written);
    assert_direct_route(Shape::Unwritten);
    assert_direct_route(Shape::Diamond);
}
