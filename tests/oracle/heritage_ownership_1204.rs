// HERITAGE-OWNERSHIP-0001: Rugra comparand for the locked Ghidra 12.0.4
// Funcdata::opHeritage / Heritage::heritage ownership-boundary oracle.
// Mirrors tests/oracle/heritage_ownership_1204.cc case for case: the same
// synthetic CFG/def-use graphs are built through the production Funcdata
// APIs, three consecutive `op_heritage` boundary calls (pass 0 -> 1 -> 2
// -> 3) run on the same `&mut Funcdata`, and the complete state
// projection (pass counter, op list with per-slot input classes,
// Varnode-bank multiset) is printed in the shared observation format.
//
// The Rust fixture additionally ASSERTS (before printing) the
// ownership-boundary internals the C++ side cannot print because Ghidra
// declares them in an unlabeled default-private region:
//   - maxdepth == -1 at construction and exactly one ADT rebuild across
//     the three passes (heritage.cc:218-224 / 2676-2677),
//   - the persistent globaldisjoint cover survives every mem::take
//     round-trip of the Heritage object.

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
        _ => "OTHER",
    }
}

// Varnode descriptor shared with the C++ oracle fixture:
//   constant -> C<size>; register -> R<hex-offset>:<I|W|F>;
//   unique -> U<size>:<I|W|F>; stack -> S<off>:<..>; ram -> M<off>:<..>
fn vn_descriptor(vn: &VnRef) -> String {
    let value = vn.read().unwrap();
    if value.is_constant() {
        return format!("C{}", value.size);
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
        format!("{code}{}", format!("{:x}", value.loc.as_u64()))
    } else {
        format!("{code}{}", value.size)
    };
    let state = if value.is_input() {
        'I'
    } else if value.is_written() {
        'W'
    } else {
        'F'
    };
    format!("{head}:{state}")
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
            Address::new(self.base),
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
        self.fd.op_set_output(&rudra::op::PcodeOpRef(op.clone()), vn.clone());
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

    fn label_of(&self, op: &OpRef) -> &'static str {
        for (candidate, name) in &self.ops {
            if Arc::ptr_eq(candidate, op) {
                return name;
            }
        }
        "phi"
    }

    /// Production pre-state: `Funcdata::startProcessing`
    /// (funcdata.cc:150-167) runs structureReset (loop structure + forward
    /// dominators) and builds the Heritage info list (funcdata.cc:166)
    /// before the first ActionHeritage pass. The synthetic-graph fixture
    /// applies the same two steps: Rugra's dominator producer is
    /// `BlockGraph::build_dom_tree`, and `build_info_list` is the direct
    /// buildInfoList port.
    fn prepare_structure(&mut self) {
        self.fd.bblocks.build_dom_tree();
        self.fd.heritage.build_info_list();
    }

    /// Three consecutive op_heritage boundary calls on the same `&mut
    /// Funcdata`, recording the public pass counter after each pass and
    /// asserting the Rust-side ownership internals.
    fn run_three_passes(&mut self, expect_maxdepth: i32, expect_gd: usize) -> Vec<i32> {
        self.prepare_structure();
        assert_eq!(self.fd.heritage.maxdepth, -1, "ctor sentinel maxdepth=-1");
        let mut seq = Vec::new();
        for _ in 0..3 {
            self.fd.op_heritage();
            seq.push(self.fd.num_heritage_passes());
            // The ADT rebuild sentinel fires on pass 1 only; maxdepth is
            // then constant across the remaining passes.
            assert_eq!(self.fd.heritage.maxdepth, expect_maxdepth);
            assert_eq!(
                self.fd.heritage.globaldisjoint.themap.len(),
                expect_gd,
                "persistent globaldisjoint must survive every mem::take round-trip"
            );
        }
        seq
    }

    fn op_list(&self) -> String {
        let mut parts = Vec::new();
        for op_ref in &self.fd.obank.optree {
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
            parts.push(part);
        }
        parts.join(";")
    }

    fn op_count(&self) -> usize {
        self.fd.obank.optree.len()
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
}

fn pass_text(seq: &[i32]) -> String {
    format!("{},{},{}", seq[0], seq[1], seq[2])
}

fn main() {
    println!("schema=1|fixture=HERITAGE-OWNERSHIP-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // case=empty_entry: one entry block, no IR.
    {
        let mut g = Graph::new("empty_entry", 0x5000);
        g.make_block(0);
        let seq = g.run_three_passes(1, 0);
        println!(
            "case=empty_entry|pass={}|ops={}|vns={}",
            pass_text(&seq),
            g.op_count(),
            g.vn_count()
        );
    }

    // case=register_free_promote: canonical rename promotes the free reads
    // to one input, rewires the second reader onto the write, and deletes
    // the consumed frees.
    {
        let mut g = Graph::new("register_free_promote", 0x5100);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        let c4a = g.constant(4, 7);
        let c4b = g.constant(4, 7);
        let c8 = g.constant(8, 5);
        let f1 = g.free_register(0x30, 8);
        let f2 = g.free_register(0x30, 8);
        let d1 = g.make_op("d1", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&d1, &f1, 0);
        g.set_input(&d1, &c4a, 1);
        g.written_register(0x30, 8, &d1);
        g.insert_end(&d1, &b0);
        let w2 = g.make_op("w2", OpCode::CPUI_COPY, 1);
        g.set_input(&w2, &c8, 0);
        g.unique_out(8, &w2);
        g.insert_end(&w2, &b0);
        let r1 = g.make_op("r1", OpCode::CPUI_INT_OR, 2);
        g.set_input(&r1, &f2, 0);
        g.set_input(&r1, &c4b, 1);
        g.unique_out(8, &r1);
        g.insert_end(&r1, &b1);
        // Two-block chain: dominator depths 1,2 (block.cc:2056 root=1) ->
        // maxdepth 2; three disjoint covers (register 0x30, t2, t3).
        let seq = g.run_three_passes(2, 3);
        println!(
            "case=register_free_promote|pass={}|ops={}|oplist={}|vns={}|vnlist={}",
            pass_text(&seq),
            g.op_count(),
            g.op_list(),
            g.vn_count(),
            g.vn_list()
        );
    }

    // case=phi_cycle_selfref: MULTIEQUAL self-reference cycle (cover
    // fixture slot2 topology with the loop-carried def-use cycle
    // m_out -> r -> t3 -> m). Restricted projection: the no-hang witness.
    {
        let mut g = Graph::new("phi_cycle_selfref", 0x5200);
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
        let seq = g.run_three_passes(4, 3);
        println!(
            "case=phi_cycle_selfref|pass={}|completed=1",
            pass_text(&seq)
        );
    }
}
