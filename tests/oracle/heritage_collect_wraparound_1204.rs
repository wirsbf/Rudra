// HERITAGE-COLLECT-WRAPAROUND-0001: Rudra comparand for the locked Ghidra
// 12.0.4 Heritage::collect end-address wraparound clamp oracle
// (heritage.cc:317-320). Mirrors tests/oracle/heritage_collect_wraparound_
// 1204.cc case for case: the same synthetic single-block graphs (a 2-byte
// register write straddling the space top with a 1-byte BOOL_NEGATE read,
// the byte-identical control shape at a normal offset, and a 1-byte write
// exactly at the top byte) are built through the production Funcdata APIs,
// the production boundary `op_heritage` runs once per case, and the
// post-pass projection (pass counter, live op count, BOOL input descriptor
// after rename, whole-bank free-with-reader census, globaldisjoint cover
// dump, phi projection, PcodeOpTree-ordered op list, Varnode multiset) is
// printed in the shared observation format.
//
// The wraparound clamp in collect (src/heritage.rs) mirrors the oracle:
// endaddr = memrange.addr + memrange.size through wrapOffset (identity for
// the 64-bit spaces of this architecture); when the wrapped end offset
// falls below start, the window end is endLoc(space, getHighest()) — the
// scan runs from start to the END of the range's space (break on the first
// foreign-space member, no offset bound), not beginLoc(wrapped-end) which
// would terminate the window immediately.
//
// The Rust comparand additionally ASSERTS, without printing (so stdout
// stays byte-comparable), the clamp witnesses: the census is zero after
// each pass and the globaldisjoint cover holds the wrapping register range
// at pass 0.

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

const TOP: u64 = 0xffffffffffffffff;

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
    // Created AFTER the write so the same-location write/read pair stays
    // two objects (create only reuses free varnodes, varnode.cc:1250-1258).
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

    /// Persistent globaldisjoint cover after the pass:
    /// name:hexoffset:size:p<pass> for the processor/stack spaces only
    /// (unique-space entries are allocation-dependent and not comparable),
    /// sorted by the synthetic architecture's space index then offset —
    /// the same order as the oracle's map<Address,SizePass>.
    fn global_cover(&self) -> String {
        let mut entries: Vec<(u32, u64, String)> = Vec::new();
        for ((space, addr), sp) in &self.fd.heritage.globaldisjoint.themap {
            let (rank, name) = match space {
                AddressSpace::Ram => (3u32, "ram"),
                AddressSpace::Register => (4u32, "register"),
                AddressSpace::Stack => (5u32, "stack"),
                AddressSpace::Other(_) => (1u32, "other"),
                _ => continue,
            };
            entries.push((
                rank,
                addr.as_u64(),
                format!("{name}:{:x}:{}:p{}", addr.as_u64(), sp.size, sp.pass),
            ));
        }
        entries.sort();
        entries.into_iter().map(|e| e.2).collect::<Vec<_>>().join(",")
    }

    /// Silent clamp witness: the cover holds the given range (heritaged at
    /// pass 0) and no free varnode with a descendant survives the pass.
    fn assert_clamp_witness(&self, space: AddressSpace, offset: u64, size: i32) {
        assert!(
            self.fd
                .heritage
                .globaldisjoint
                .themap
                .contains_key(&(space, Address::new(offset))),
            "globaldisjoint cover lost the heritaged range"
        );
        let sp = &self.fd.heritage.globaldisjoint.themap
            [&(space, Address::new(offset))];
        assert_eq!(sp.size, size, "globaldisjoint cover range size");
        assert_eq!(sp.pass, 0, "globaldisjoint cover range pass");
        assert_eq!(self.free_with_reader(), 0, "free-with-reader census");
    }
}

fn main() {
    println!(
        "schema=1|fixture=HERITAGE-COLLECT-WRAPAROUND-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case A: 2-byte write straddling the space top + 1-byte read ----
    {
        let mut g = Graph::new("wrap_straddle", 0x1000);
        let b0 = g.make_block(0);

        let w = g.make_op("w", OpCode::CPUI_INT_SUB, 2);
        let c0 = g.constant(2, 0x0);
        let c1 = g.constant(2, 0x1);
        g.set_input(&w, &c0, 0);
        g.set_input(&w, &c1, 1);
        g.written_register(TOP, 2, &w);
        g.insert_end(&w, &b0);

        let n = g.make_op("n", OpCode::CPUI_BOOL_NEGATE, 1);
        let r = g.free_register(TOP, 1);
        g.set_input(&n, &r, 0);
        g.unique_out(1, &n);
        g.insert_end(&n, &b0);

        let c = g.make_op("c", OpCode::CPUI_CBRANCH, 2);
        let t = g.constant(8, 0x2000);
        g.set_input(&c, &t, 0);
        let n_out = n.read().unwrap().output.clone().expect("bool output");
        g.set_input(&c, &n_out, 1);
        g.insert_end(&c, &b0);

        g.prepare_structure();
        g.fd.op_heritage();

        g.assert_clamp_witness(AddressSpace::Register, TOP, 2);
        let bool_in = n.read().unwrap().inrefs[0].clone();
        println!(
            "case=wraparound_straddling_write|pass={}|ops={}|bool_in={}|free_with_reader={}|gd={}|phis={}|ops_proj={}|vn={}",
            g.fd.num_heritage_passes(),
            g.op_count_all(),
            vn_descriptor(&bool_in),
            g.free_with_reader(),
            g.global_cover(),
            g.phi_projection(),
            g.op_list(),
            g.vn_multiset(),
        );
    }

    // ---- case B: byte-identical control shape at a normal offset ----
    {
        let mut g = Graph::new("nonwrap_control", 0x2000);
        let b0 = g.make_block(0);

        let w = g.make_op("w", OpCode::CPUI_INT_SUB, 2);
        let c0 = g.constant(2, 0x0);
        let c1 = g.constant(2, 0x1);
        g.set_input(&w, &c0, 0);
        g.set_input(&w, &c1, 1);
        g.written_register(0x206, 2, &w);
        g.insert_end(&w, &b0);

        let n = g.make_op("n", OpCode::CPUI_BOOL_NEGATE, 1);
        let r = g.free_register(0x206, 1);
        g.set_input(&n, &r, 0);
        g.unique_out(1, &n);
        g.insert_end(&n, &b0);

        let c = g.make_op("c", OpCode::CPUI_CBRANCH, 2);
        let t = g.constant(8, 0x3000);
        g.set_input(&c, &t, 0);
        let n_out = n.read().unwrap().output.clone().expect("bool output");
        g.set_input(&c, &n_out, 1);
        g.insert_end(&c, &b0);

        g.prepare_structure();
        g.fd.op_heritage();

        g.assert_clamp_witness(AddressSpace::Register, 0x206, 2);
        let bool_in = n.read().unwrap().inrefs[0].clone();
        println!(
            "case=nonwrap_control_same_shape|pass={}|ops={}|bool_in={}|free_with_reader={}|gd={}|phis={}|ops_proj={}|vn={}",
            g.fd.num_heritage_passes(),
            g.op_count_all(),
            vn_descriptor(&bool_in),
            g.free_with_reader(),
            g.global_cover(),
            g.phi_projection(),
            g.op_list(),
            g.vn_multiset(),
        );
    }

    // ---- case C: 1-byte write exactly at the top byte + 1-byte read ----
    {
        let mut g = Graph::new("wrap_exact_top", 0x3000);
        let b0 = g.make_block(0);

        let w = g.make_op("w", OpCode::CPUI_INT_SUB, 2);
        let c0 = g.constant(1, 0x0);
        let c1 = g.constant(1, 0x1);
        g.set_input(&w, &c0, 0);
        g.set_input(&w, &c1, 1);
        g.written_register(TOP, 1, &w);
        g.insert_end(&w, &b0);

        let n = g.make_op("n", OpCode::CPUI_BOOL_NEGATE, 1);
        let r = g.free_register(TOP, 1);
        g.set_input(&n, &r, 0);
        g.unique_out(1, &n);
        g.insert_end(&n, &b0);

        let c = g.make_op("c", OpCode::CPUI_CBRANCH, 2);
        let t = g.constant(8, 0x4000);
        g.set_input(&c, &t, 0);
        let n_out = n.read().unwrap().output.clone().expect("bool output");
        g.set_input(&c, &n_out, 1);
        g.insert_end(&c, &b0);

        g.prepare_structure();
        g.fd.op_heritage();

        g.assert_clamp_witness(AddressSpace::Register, TOP, 1);
        let bool_in = n.read().unwrap().inrefs[0].clone();
        println!(
            "case=wraparound_exact_top|pass={}|ops={}|bool_in={}|free_with_reader={}|gd={}|phis={}|ops_proj={}|vn={}",
            g.fd.num_heritage_passes(),
            g.op_count_all(),
            vn_descriptor(&bool_in),
            g.free_with_reader(),
            g.global_cover(),
            g.phi_projection(),
            g.op_list(),
            g.vn_multiset(),
        );
    }
}
