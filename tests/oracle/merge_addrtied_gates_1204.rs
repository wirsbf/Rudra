//! MERGE-ADDRTIED-GATES-0001 Rugra comparand.
//!
//! Every case builds live P-code through `Funcdata`/`VarnodeBank`, invokes
//! `Funcdata::set_high_level`, then runs the production `Merge::merge_addr_tied`
//! entry point. No fixture-local merge algorithm is used.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::merge::Merge;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::{AddressSpace, SpaceType, SPACEID_OTHER};
use rudra::variable::HighVariable;
use rudra::varnode::{varnode_flags, Varnode};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<RwLock<Varnode>>;

#[derive(Clone)]
struct NamedVarnode {
    name: &'static str,
    vn: VnRef,
    cluster: &'static str,
}

struct Graph {
    fd: Funcdata,
    block: Arc<RwLock<BlockBasic>>,
    next_pc: u64,
    nodes: Vec<NamedVarnode>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        let mut fd = Funcdata::new(name, Address::new(base), 0x100);
        let block = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(base))));
        let block_ref: BlockRef = block.clone();
        fd.bblocks.add_block(block_ref);
        Self { fd, block, next_pc: base, nodes: Vec::new() }
    }

    fn output(&mut self, name: &'static str, space: AddressSpace, offset: u64,
              size: usize, cluster: &'static str, flags: u32) -> VnRef {
        let op: PcodeOpRef = self.fd.new_op(1, Address::new(self.next_pc));
        self.next_pc += 1;
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let vn = self.fd.vbank.create_def_with_space(size, space, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        self.fd.set_varnode_properties(&vn);
        let input = self.fd.new_constant(size, self.next_pc & 0xff);
        self.fd.op_insert_input(&op, input, 0);
        vn.write().unwrap().set_flags(flags);
        let block_ref: BlockRef = self.block.clone();
        self.fd.op_insert_end(&op, &block_ref);
        self.nodes.push(NamedVarnode { name, vn: vn.clone(), cluster });
        vn
    }

    fn input(&mut self, name: &'static str, space: AddressSpace, offset: u64,
             size: usize, cluster: &'static str, flags: u32) -> VnRef {
        let vn = self.fd.vbank.create_with_space(size, space, offset);
        let vn = self.fd.set_input_varnode(vn);
        self.fd.set_varnode_properties(&vn);
        vn.write().unwrap().set_flags(flags);
        self.nodes.push(NamedVarnode { name, vn: vn.clone(), cluster });
        vn
    }

    fn prepare(&mut self) {
        self.fd.set_high_level();
    }

    fn run(&mut self) -> String {
        let mut merge = Merge::new();
        let old_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = catch_unwind(AssertUnwindSafe(|| {
            merge.merge_addr_tied(&mut self.fd)
        }));
        std::panic::set_hook(old_hook);
        match result {
            Ok(()) => "none".to_string(),
            Err(payload) => panic_message(payload),
        }
    }

    fn observe(&self, case_name: &str, stage: &str, error: &str) {
        let label_by_vn: BTreeMap<usize, &'static str> = self.nodes.iter()
            .map(|node| (Arc::as_ptr(&node.vn) as usize, node.name))
            .collect();
        let nodes = self.nodes.iter().map(|node| {
            let vn = node.vn.read().unwrap();
            format!("{}@{}:{}:0x{:x}:{}:f0x{:x}:a{}i{}w{}m{}:{}", node.name,
                vn.address_space.space_id(), space_type_name(vn.address_space),
                vn.loc.as_u64(), vn.size, vn.flags,
                u8::from(vn.flags & varnode_flags::ADDRTIED != 0),
                u8::from(vn.is_input()), u8::from(vn.is_written()),
                u8::from(vn.is_implied()), node.cluster)
        }).collect::<Vec<_>>().join(",");
        let same = self.nodes.iter().enumerate().flat_map(|(i, left)| {
            self.nodes.iter().skip(i + 1).map(move |right| {
                let left_high = left.vn.read().unwrap().high.clone();
                let right_high = right.vn.read().unwrap().high.clone();
                let equal = matches!((left_high, right_high), (Some(left), Some(right))
                    if Arc::ptr_eq(&left, &right));
                format!("{}~{}={}", left.name, right.name, u8::from(equal))
            })
        }).collect::<Vec<_>>().join(";");
        let highs = self.nodes.iter().map(|node| {
            let high = node.vn.read().unwrap().high.clone();
            format!("{}{}", node.name, high_shape(high.as_ref(), &label_by_vn))
        }).collect::<Vec<_>>().join(";");
        let pieces = self.nodes.iter().map(|node| {
            let high = node.vn.read().unwrap().high.clone();
            format!("{}:{}", node.name, piece_shape(high.as_ref(), &label_by_vn))
        }).collect::<Vec<_>>().join(";");
        let topology = format!("vn{}:alive{}:dead{}", self.fd.vbank.loc_tree.len(),
            self.fd.obank.alivelist.len(), self.fd.obank.deadlist.len());
        println!("case={case_name}|stage={stage}|error={error}|topology={topology}|nodes={nodes}|same={same}|highs={highs}|pieces={pieces}");
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    "non-string panic".to_string()
}

fn space_type_name(space: AddressSpace) -> &'static str {
    let space_type = match space {
        AddressSpace::Ram | AddressSpace::Register | AddressSpace::Overlay => {
            Some(SpaceType::Processor)
        }
        AddressSpace::Stack => Some(SpaceType::SpaceBase),
        AddressSpace::Const => Some(SpaceType::Constant),
        AddressSpace::Unique => Some(SpaceType::Internal),
        AddressSpace::Iop => Some(SpaceType::Iop),
        AddressSpace::Join => Some(SpaceType::Join),
        AddressSpace::Other(SPACEID_OTHER) => Some(SpaceType::Processor),
        AddressSpace::Other(_) => None,
    };
    match space_type {
        Some(SpaceType::Constant) => "constant",
        Some(SpaceType::Processor) => "processor",
        Some(SpaceType::SpaceBase) => "spacebase",
        Some(SpaceType::Internal) => "internal",
        Some(SpaceType::Fspec) => "fspec",
        Some(SpaceType::Iop) => "iop",
        Some(SpaceType::Join) => "join",
        None => "unclassified",
    }
}

fn high_shape(high: Option<&Arc<RwLock<HighVariable>>>,
              label_by_vn: &BTreeMap<usize, &'static str>) -> String {
    let Some(high) = high else { return "[]".to_string() };
    let high = high.read().unwrap();
    let labels = high.instances.iter().map(|vn| {
        label_by_vn.get(&(Arc::as_ptr(vn) as usize)).copied().unwrap_or("?")
    }).collect::<Vec<_>>().join(",");
    format!("[{labels}]:hf0x{:x}:mc{}:s{}", high.highflags,
        high.num_merge_classes, u8::from(high.symbol.is_some()))
}

fn representative_name(high: &Arc<RwLock<HighVariable>>,
                       label_by_vn: &BTreeMap<usize, &'static str>) -> &'static str {
    high.read().unwrap().instances.iter().filter_map(|vn| {
        label_by_vn.get(&(Arc::as_ptr(vn) as usize)).copied()
    }).min().unwrap_or("?")
}

fn piece_shape(high: Option<&Arc<RwLock<HighVariable>>>,
               label_by_vn: &BTreeMap<usize, &'static str>) -> String {
    let Some(high) = high else { return "-:0:-:-:-".to_string() };
    let instance_size = high.read().unwrap().instances.first()
        .map(|vn| vn.read().unwrap().size).unwrap_or(0);
    let piece = high.read().unwrap().piece.clone();
    let Some(piece) = piece else { return format!("-:{instance_size}:-:-:-") };
    let piece_read = piece.read().unwrap();
    let Some(group) = piece_read.group.clone() else { return "nogroup".to_string() };
    let offset = piece_read.group_offset;
    let size = piece_read.size;
    drop(piece_read);
    let group_read = group.read().unwrap();
    let canonical = group_read.pieces.iter().filter_map(|member| {
        let owner = member.read().unwrap().high.as_ref().and_then(|high| high.upgrade());
        owner.as_ref().map(|high| representative_name(high, label_by_vn))
    }).min().unwrap_or("anon");
    let ordered = group_read.pieces.iter().map(|member| {
        let member = member.read().unwrap();
        let owner = member.high.as_ref().and_then(|high| high.upgrade());
        let owner = owner.as_ref()
            .map(|high| representative_name(high, label_by_vn)).unwrap_or("anon");
        format!("{}:{}:{owner}", member.group_offset, member.size)
    }).collect::<Vec<_>>().join(",");
    format!("{offset}:{size}:{}:{canonical}:[{ordered}]", group_read.size)
}

fn case_space_gate() {
    let mut graph = Graph::new("merge_addrtied_space_type_gate", 0x8100);
    graph.output("R0", AddressSpace::Register, 0x20, 4, "s0", varnode_flags::ADDRTIED);
    graph.output("R1", AddressSpace::Register, 0x20, 4, "s0", 0);
    graph.output("M0", AddressSpace::Ram, 0x120, 4, "s1", varnode_flags::ADDRTIED);
    graph.output("M1", AddressSpace::Ram, 0x120, 4, "s1", 0);
    graph.output("O0", AddressSpace::Other(SPACEID_OTHER), 0x220, 4, "s2",
                 varnode_flags::ADDRTIED);
    graph.output("O1", AddressSpace::Other(SPACEID_OTHER), 0x220, 4, "s2", 0);
    graph.output("S0", AddressSpace::Stack, 0x320, 4, "s3", varnode_flags::ADDRTIED);
    graph.output("S1", AddressSpace::Stack, 0x320, 4, "s3", 0);
    graph.output("U0", AddressSpace::Unique, 0x420, 4, "s4", varnode_flags::ADDRTIED);
    graph.output("U1", AddressSpace::Unique, 0x420, 4, "s4", 0);
    graph.output("J0", AddressSpace::Join, 0x520, 4, "s5", varnode_flags::ADDRTIED);
    graph.output("J1", AddressSpace::Join, 0x520, 4, "s5", 0);
    graph.prepare();
    graph.observe("space_type_gate", "before", "none");
    let error = graph.run();
    graph.observe("space_type_gate", "after", &error);
}

fn case_addrtied_gate() {
    let mut graph = Graph::new("merge_addrtied_first_member_gate", 0x8200);
    graph.output("N0", AddressSpace::Register, 0x40, 4, "f0", 0);
    graph.output("N1", AddressSpace::Register, 0x40, 4, "f0", 0);
    graph.output("L0", AddressSpace::Register, 0x50, 4, "f1", 0);
    graph.output("L1", AddressSpace::Register, 0x50, 4, "f1", varnode_flags::ADDRTIED);
    graph.prepare();
    graph.observe("addrtied_first_member_gate", "before", "none");
    let error = graph.run();
    graph.observe("addrtied_first_member_gate", "after", &error);
}

fn case_transitive_overlap() {
    let mut graph = Graph::new("merge_addrtied_transitive_overlap", 0x8300);
    graph.input("AI", AddressSpace::Register, 0x100, 8, "c0", varnode_flags::ADDRTIED);
    graph.output("A0", AddressSpace::Register, 0x100, 8, "c0", 0);
    graph.output("A1", AddressSpace::Register, 0x100, 8, "c0", 0);
    graph.output("B0", AddressSpace::Register, 0x104, 8, "c0", 0);
    graph.output("B1", AddressSpace::Register, 0x104, 8, "c0", 0);
    graph.output("C0", AddressSpace::Register, 0x10a, 2, "c0", 0);
    graph.output("C1", AddressSpace::Register, 0x10a, 2, "c0", 0);
    graph.output("D0", AddressSpace::Register, 0x10c, 2, "c1", 0);
    graph.output("D1", AddressSpace::Register, 0x10c, 2, "c1", 0);
    graph.prepare();
    graph.observe("transitive_overlap_group", "before", "none");
    let error = graph.run();
    graph.observe("transitive_overlap_group", "after", &error);
}

fn case_forced_error() {
    let mut graph = Graph::new("merge_addrtied_forced_implied", 0x8400);
    graph.output("I0", AddressSpace::Register, 0x180, 4, "e0", varnode_flags::ADDRTIED);
    graph.output("I1", AddressSpace::Register, 0x180, 4, "e0", varnode_flags::IMPLIED);
    graph.prepare();
    graph.observe("forced_implied_error", "before", "none");
    let error = graph.run();
    graph.observe("forced_implied_error", "after", &error);
}

fn main() {
    case_space_gate();
    case_addrtied_gate();
    case_transitive_overlap();
    case_forced_error();
}
