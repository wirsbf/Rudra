// HERITAGE-STORELOAD-FWD-FIXTURE-0001 (KUNABUGS-STORELOAD-FWD-0001)
//
// Rust comparand for tests/oracle/heritage_storeload_fwd_1204.cc.  The
// three cases drive the pre-heritage stack store->load forwarding chain
// (discoverIndexedStackPointers -> generateLoadGuard -> guardStores
// INDIRECT + guardLoads COPY-guard -> rename -> analyzeNewLoadGuards ->
// handleNewLoadCopies/propagateCopyAway) through the canonical
// `Funcdata::opHeritage` boundary, twice per case (stack delay=1: pass 0
// heritages the register space, pass 1 the stack space).
//
// Normalization mirrors the C++ fixture: first-seen alias ids, decoded
// space names for LOAD/STORE space constants, omitted unique/iop offsets.
// All op order, slot order, flags, descendant counts, guard records and
// alias relations are preserved.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::heritage::Heritage;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::{AddressSpace, SPACEID_STACK};
use rudra::varmap::ScopeLocal;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type OpRef = Arc<RwLock<PcodeOp>>;
type VnRef = Arc<RwLock<Varnode>>;

fn read_op(op: &OpRef) -> RwLockReadGuard<'_, PcodeOp> {
    op.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read_vn(vn: &VnRef) -> RwLockReadGuard<'_, Varnode> {
    vn.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn opcode_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_COPY => "COPY",
        OpCode::CPUI_INT_ADD => "INT_ADD",
        OpCode::CPUI_LOAD => "LOAD",
        OpCode::CPUI_STORE => "STORE",
        OpCode::CPUI_INDIRECT => "INDIRECT",
        OpCode::CPUI_MULTIEQUAL => "MULTIEQUAL",
        _ => "OTHER",
    }
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_pc: u64,
    ops: Vec<(OpRef, &'static str)>,
    blocks: Vec<(BlockRef, &'static str)>,
    aliases: HashMap<usize, usize>,
    next_alias: usize,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        let mut fd = Funcdata::new(name, Address::new(base), 0x40);
        // The oracle's Funcdata constructor (funcdata.cc:66-70) builds the
        // real ScopeLocal and calls resetLocalWindow; the model's default
        // localrange [highest-999999,highest] union paramrange [0,511] is
        // what the comparand's model-less fallback produces, so installing
        // the windowed ScopeLocal before any Varnode is created mirrors
        // the oracle construction order.
        let mut scope = ScopeLocal::new();
        scope.reset_local_window(&fd);
        fd.scope = Some(scope);
        Self {
            fd,
            base,
            next_pc: 0,
            ops: Vec::new(),
            blocks: Vec::new(),
            aliases: HashMap::new(),
            next_alias: 0,
        }
    }

    fn block(&mut self, name: &'static str) -> BlockRef {
        // C++ BlockGraph::newBlockBasic creates blocks with index 0; the
        // real indexes are only assigned by the structure/dominator pass
        // (observed in the oracle pre-structure dump: every block is #0).
        let block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            0,
            Address::new(0),
        )));
        self.fd.bblocks.add_block(block.clone());
        self.blocks.push((block.clone(), name));
        block
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn op(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> OpRef {
        let op = self
            .fd
            .new_op(inputs, Address::new(self.base + self.next_pc));
        self.next_pc += 1;
        self.fd.op_set_opcode(&op, opcode);
        self.ops.push((op.0.clone(), name));
        op.0
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

    fn space_const(&mut self) -> VnRef {
        // STORE/LOAD input(0) space constant: the numeric space id
        // (varnode.hh:426 getSpaceFromConst decodes it back).
        self.fd.new_constant(8, SPACEID_STACK as u64)
    }

    fn free_reg(&mut self, offset: u64, size: usize) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        Heritage::apply_new_varnode_flags(&self.fd, &vn);
        vn
    }

    fn spacebase_input(&mut self) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(8, AddressSpace::Register, 0x20);
        Heritage::apply_new_varnode_flags(&self.fd, &vn);
        self.fd.set_input_varnode(vn.clone());
        vn
    }

    fn stack_out(&mut self, op: &OpRef, offset: u64, size: usize) -> VnRef {
        self.fd
            .new_varnode_out_full(size, AddressSpace::Stack, Address::new(offset), &PcodeOpRef(op.clone()))
    }

    fn unique_out(&mut self, op: &OpRef, size: usize) -> VnRef {
        self.fd.new_unique_out(size, &PcodeOpRef(op.clone()))
    }

    fn input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd
            .op_set_input(&PcodeOpRef(op.clone()), vn.clone(), slot);
    }

    fn append(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd.op_insert_end(&PcodeOpRef(op.clone()), block);
    }

    fn prepare(&mut self) {
        let mut preorder = Vec::new();
        let mut roots = Vec::new();
        self.fd
            .bblocks
            .find_spanning_tree(&mut preorder, &mut roots)
            .expect("find_spanning_tree");
        self.fd.bblocks.build_dom_tree();
        self.fd.heritage.build_info_list();
    }

    fn op_name(&self, op: &OpRef) -> &'static str {
        for (candidate, name) in &self.ops {
            if Arc::ptr_eq(candidate, op) {
                return name;
            }
        }
        if read_op(op).opcode == OpCode::CPUI_MULTIEQUAL {
            "phi"
        } else if read_op(op).opcode == OpCode::CPUI_INDIRECT {
            "indirect"
        } else {
            "unknown"
        }
    }

    fn block_name(&self, block: &BlockRef) -> &'static str {
        self.blocks
            .iter()
            .find(|(candidate, _)| Arc::ptr_eq(candidate, block))
            .map(|(_, name)| *name)
            .unwrap_or("unknown")
    }

    fn alias(&mut self, vn: &VnRef) -> usize {
        let key = Arc::as_ptr(vn) as usize;
        if let Some(alias) = self.aliases.get(&key) {
            return *alias;
        }
        let alias = self.next_alias;
        self.next_alias += 1;
        self.aliases.insert(key, alias);
        alias
    }

    fn vn_state(&mut self, vn: Option<&VnRef>) -> String {
        let Some(vn) = vn else {
            return "null".to_string();
        };
        let alias = self.alias(vn);
        let value = read_vn(vn);
        let storage = if value.is_constant() {
            format!("C{}:{:x}", value.get_size(), value.get_offset())
        } else {
            match value.get_space() {
                AddressSpace::Register => {
                    format!("R{:x}:{}", value.get_offset(), value.get_size())
                }
                AddressSpace::Unique => format!("U{}", value.get_size()),
                AddressSpace::Iop => format!("IOP{}", value.get_size()),
                space => format!(
                    "{}:{:x}:{}",
                    space.name(),
                    value.get_offset(),
                    value.get_size()
                ),
            }
        };
        let class = if value.is_constant() {
            'C'
        } else if value.is_annotation() {
            'A'
        } else if value.is_input() {
            'I'
        } else if value.is_written() {
            'W'
        } else {
            'F'
        };
        let desc = value.count_descends();
        let flags = value.flags;
        let active = value.is_active_heritage();
        let known = value.is_heritage_known();
        let def = value.get_def();
        drop(value);
        let def_name = def.map(|op| self.op_name(&op)).unwrap_or("-");
        format!(
            "a{alias}:{storage}:{class}:d{desc}:f{flags:x}:act{}:known{}:def{def_name}",
            u8::from(active),
            u8::from(known),
        )
    }

    fn space_const_state(&self, vn: &VnRef) -> String {
        let value = read_vn(vn);
        format!("SPC:{}", AddressSpace::from_id(value.get_offset() as u8).name())
    }

    fn order(&mut self) -> String {
        let mut block_parts = Vec::new();
        for index in 0..self.fd.bblocks.get_size() {
            let Some(block) = self.fd.bblocks.get_block(index) else {
                continue;
            };
            let block_name = self.block_name(&block);
            let block_index = block.read().unwrap().get_index();
            let ops = block.read().unwrap().get_ops();
            let mut op_parts = Vec::new();
            for op_ref in ops {
                let op = op_ref.0;
                let name = self.op_name(&op);
                let (opcode, output, inputs) = {
                    let value = read_op(&op);
                    (value.opcode, value.output.clone(), value.inrefs.clone())
                };
                let mut part = format!(
                    "{name}.{}{{out={}",
                    opcode_name(opcode),
                    self.vn_state(output.as_ref()),
                );
                for (slot, vn) in inputs.iter().enumerate() {
                    if slot == 0 && (opcode == OpCode::CPUI_LOAD || opcode == OpCode::CPUI_STORE) {
                        part.push_str(&format!(",s{slot}={}", self.space_const_state(vn)));
                        continue;
                    }
                    part.push_str(&format!(",s{slot}={}", self.vn_state(Some(vn))));
                }
                part.push('}');
                op_parts.push(part);
            }
            block_parts.push(format!(
                "{block_name}#{block_index}=[{}]",
                op_parts.join(",")
            ));
        }
        block_parts.join(";")
    }

    fn census(&self) -> String {
        const NAMES: [&str; 6] = ["ram", "register", "stack", "unique", "iop", "const"];
        let mut parts = Vec::new();
        for name in NAMES {
            let (mut w, mut f, mut inp, mut c) = (0, 0, 0, 0);
            for entry in &self.fd.vbank.loc_tree {
                let value = read_vn(&entry.0);
                if value.get_space().name() != name {
                    continue;
                }
                if value.is_written() {
                    w += 1;
                } else if value.is_constant() {
                    c += 1;
                } else if value.is_input() {
                    inp += 1;
                } else if !value.is_annotation() {
                    f += 1;
                }
            }
            parts.push(format!("{name}:W{w}/F{f}/I{inp}/C{c}"));
        }
        parts.join(",")
    }

    fn guards(&self) -> String {
        let mut parts = Vec::new();
        for guard in &self.fd.heritage.load_guard {
            let op_name = guard
                .op
                .upgrade()
                .map(|op| self.op_name(&op).to_string())
                .unwrap_or_else(|| "dead".to_string());
            parts.push(format!(
                "pb={:x},min={:x},max={:x},step={},st={},op={}",
                guard.pointer_base, guard.minimum_offset, guard.maximum_offset, guard.step,
                guard.analysis_state, op_name
            ));
        }
        parts.join(";")
    }

    fn dump_line(&mut self, casename: &str, phase: &str) -> String {
        format!(
            "case={casename}|phase={phase}|pass={}|restart={}|guards={}|sguards={}|copyops={}|census={}|order={}",
            self.fd.num_heritage_passes(),
            u8::from(self.fd.restart_pending),
            self.guards(),
            self.fd.heritage.store_guard.len(),
            self.fd.heritage.load_copy_ops.len(),
            self.census(),
            self.order(),
        )
    }
}

fn case_fwd_indexed_load() {
    let mut g = Graph::new("fwd_indexed_load", 0x7100);
    let entry = g.block("entry");
    let sp = g.spacebase_input();
    let add0 = g.op("add0", OpCode::CPUI_INT_ADD, 2);
    g.input(&add0, &sp, 0);
    let c30 = g.constant(8, 0x30);
    g.input(&add0, &c30, 1);
    let t0 = g.unique_out(&add0, 8);
    let addst = g.op("addst", OpCode::CPUI_INT_ADD, 2);
    g.input(&addst, &sp, 0);
    let c40 = g.constant(8, 0x40);
    g.input(&addst, &c40, 1);
    let t1 = g.unique_out(&addst, 8);
    let addidx = g.op("addidx", OpCode::CPUI_INT_ADD, 2);
    g.input(&addidx, &t0, 0);
    let idx = g.free_reg(0x100, 8);
    g.input(&addidx, &idx, 1);
    let t2 = g.unique_out(&addidx, 8);
    let wa = g.op("wA", OpCode::CPUI_COPY, 1);
    let c21 = g.constant(8, 0x21);
    g.input(&wa, &c21, 0);
    let wa_out = g.stack_out(&wa, 0x40, 8);
    let wb = g.op("wB", OpCode::CPUI_COPY, 1);
    let c22 = g.constant(8, 0x22);
    g.input(&wb, &c22, 0);
    let wb_out = g.stack_out(&wb, 0x40, 8);
    let st = g.op("st", OpCode::CPUI_STORE, 3);
    let st_spc = g.space_const();
    g.input(&st, &st_spc, 0);
    g.input(&st, &t1, 1);
    let c31 = g.constant(8, 0x31);
    g.input(&st, &c31, 2);
    let ld = g.op("ld", OpCode::CPUI_LOAD, 2);
    let ld_spc = g.space_const();
    g.input(&ld, &ld_spc, 0);
    g.input(&ld, &t2, 1);
    g.unique_out(&ld, 8);
    g.append(&add0, &entry);
    g.append(&addst, &entry);
    g.append(&addidx, &entry);
    g.append(&wa, &entry);
    g.append(&wb, &entry);
    g.append(&st, &entry);
    g.append(&ld, &entry);
    println!("case=fwd_indexed_load|phase=pre|order={}", g.order());
    g.prepare();
    g.fd.op_heritage();
    println!("{}", g.dump_line("fwd_indexed_load", "p0"));
    g.fd.op_heritage();
    println!("{}", g.dump_line("fwd_indexed_load", "p1"));
    let mut indirect_op: Option<OpRef> = None;
    let mut load_op: Option<OpRef> = None;
    {
        let ops = entry.read().unwrap().get_ops();
        for op_ref in ops {
            let opcode = read_op(&op_ref.0).opcode;
            if opcode == OpCode::CPUI_INDIRECT {
                indirect_op = Some(op_ref.0.clone());
            }
            if opcode == OpCode::CPUI_LOAD {
                load_op = Some(op_ref.0.clone());
            }
        }
    }
    let indirect_reads_last_write = indirect_op.as_ref().is_some_and(|op| {
        read_op(op).inrefs.first().is_some_and(|vn| Arc::ptr_eq(vn, &wb_out))
    });
    let copy_adjacent_before_load = load_op.as_ref().is_some_and(|load| {
        let ops = entry.read().unwrap().get_ops();
        let mut prev: Option<OpRef> = None;
        for op_ref in ops {
            if Arc::ptr_eq(&op_ref.0, load) {
                break;
            }
            prev = Some(op_ref.0.clone());
        }
        prev.is_some_and(|p| read_op(&p).opcode == OpCode::CPUI_COPY)
    });
    println!(
        "case=fwd_indexed_load|phase=check|indirect_in_is_last_write={}|copy_adjacent_before_load={}|last_write_addrforced={}|first_write_addrforced={}",
        u8::from(indirect_reads_last_write),
        u8::from(copy_adjacent_before_load),
        u8::from(read_vn(&wb_out).is_addr_force()),
        u8::from(read_vn(&wa_out).is_addr_force()),
    );
}

fn case_const_load_no_fwd() {
    let mut g = Graph::new("const_load_no_fwd", 0x7200);
    let entry = g.block("entry");
    let sp = g.spacebase_input();
    let addst = g.op("addst", OpCode::CPUI_INT_ADD, 2);
    g.input(&addst, &sp, 0);
    let c40 = g.constant(8, 0x40);
    g.input(&addst, &c40, 1);
    let t1 = g.unique_out(&addst, 8);
    let addc = g.op("addc", OpCode::CPUI_INT_ADD, 2);
    g.input(&addc, &sp, 0);
    let c40b = g.constant(8, 0x40);
    g.input(&addc, &c40b, 1);
    let t3 = g.unique_out(&addc, 8);
    let wa = g.op("wA", OpCode::CPUI_COPY, 1);
    let c21 = g.constant(8, 0x21);
    g.input(&wa, &c21, 0);
    let wa_out = g.stack_out(&wa, 0x40, 8);
    let wb = g.op("wB", OpCode::CPUI_COPY, 1);
    let c22 = g.constant(8, 0x22);
    g.input(&wb, &c22, 0);
    let wb_out = g.stack_out(&wb, 0x40, 8);
    let st = g.op("st", OpCode::CPUI_STORE, 3);
    let st_spc = g.space_const();
    g.input(&st, &st_spc, 0);
    g.input(&st, &t1, 1);
    let c31 = g.constant(8, 0x31);
    g.input(&st, &c31, 2);
    let ld = g.op("ld", OpCode::CPUI_LOAD, 2);
    let ld_spc = g.space_const();
    g.input(&ld, &ld_spc, 0);
    g.input(&ld, &t3, 1);
    g.unique_out(&ld, 8);
    g.append(&addst, &entry);
    g.append(&addc, &entry);
    g.append(&wa, &entry);
    g.append(&wb, &entry);
    g.append(&st, &entry);
    g.append(&ld, &entry);
    println!("case=const_load_no_fwd|phase=pre|order={}", g.order());
    g.prepare();
    g.fd.op_heritage();
    println!("{}", g.dump_line("const_load_no_fwd", "p0"));
    g.fd.op_heritage();
    println!("{}", g.dump_line("const_load_no_fwd", "p1"));
    let mut indirect_op: Option<OpRef> = None;
    {
        let ops = entry.read().unwrap().get_ops();
        for op_ref in ops {
            if read_op(&op_ref.0).opcode == OpCode::CPUI_INDIRECT {
                indirect_op = Some(op_ref.0.clone());
            }
        }
    }
    let indirect_reads_last_write = indirect_op.as_ref().is_some_and(|op| {
        read_op(op).inrefs.first().is_some_and(|vn| Arc::ptr_eq(vn, &wb_out))
    });
    println!(
        "case=const_load_no_fwd|phase=check|indirect_in_is_last_write={}|last_write_addrforced={}|first_write_addrforced={}",
        u8::from(indirect_reads_last_write),
        u8::from(read_vn(&wb_out).is_addr_force()),
        u8::from(read_vn(&wa_out).is_addr_force()),
    );
}

fn case_phi_fwd() {
    let mut g = Graph::new("phi_fwd", 0x7300);
    let entry = g.block("entry");
    let then_b = g.block("thenB");
    let else_b = g.block("elseB");
    let join_b = g.block("joinB");
    g.edge(&entry, &then_b);
    g.edge(&entry, &else_b);
    g.edge(&then_b, &join_b);
    g.edge(&else_b, &join_b);
    let sp = g.spacebase_input();
    let add0 = g.op("add0", OpCode::CPUI_INT_ADD, 2);
    g.input(&add0, &sp, 0);
    let c30 = g.constant(8, 0x30);
    g.input(&add0, &c30, 1);
    let t0 = g.unique_out(&add0, 8);
    let addidx = g.op("addidx", OpCode::CPUI_INT_ADD, 2);
    g.input(&addidx, &t0, 0);
    let idx = g.free_reg(0x100, 8);
    g.input(&addidx, &idx, 1);
    let t2 = g.unique_out(&addidx, 8);
    let wt = g.op("wT", OpCode::CPUI_COPY, 1);
    let c21 = g.constant(8, 0x21);
    g.input(&wt, &c21, 0);
    let wt_out = g.stack_out(&wt, 0x40, 8);
    let we = g.op("wE", OpCode::CPUI_COPY, 1);
    let c22 = g.constant(8, 0x22);
    g.input(&we, &c22, 0);
    let we_out = g.stack_out(&we, 0x40, 8);
    let ld = g.op("ld", OpCode::CPUI_LOAD, 2);
    let ld_spc = g.space_const();
    g.input(&ld, &ld_spc, 0);
    g.input(&ld, &t2, 1);
    g.unique_out(&ld, 8);
    g.append(&add0, &entry);
    g.append(&addidx, &entry);
    g.append(&wt, &then_b);
    g.append(&we, &else_b);
    g.append(&ld, &join_b);
    println!("case=phi_fwd|phase=pre|order={}", g.order());
    g.prepare();
    g.fd.op_heritage();
    println!("{}", g.dump_line("phi_fwd", "p0"));
    g.fd.op_heritage();
    println!("{}", g.dump_line("phi_fwd", "p1"));
    let mut phi: Option<OpRef> = None;
    {
        let ops = join_b.read().unwrap().get_ops();
        for op_ref in ops {
            if read_op(&op_ref.0).opcode == OpCode::CPUI_MULTIEQUAL {
                phi = Some(op_ref.0.clone());
                break;
            }
        }
    }
    let phi_reads_both_writes = phi.as_ref().is_some_and(|op| {
        let o = read_op(op);
        if o.inrefs.len() != 2 {
            return false;
        }
        let (a, b) = (o.inrefs[0].clone(), o.inrefs[1].clone());
        (Arc::ptr_eq(&a, &wt_out) && Arc::ptr_eq(&b, &we_out))
            || (Arc::ptr_eq(&a, &we_out) && Arc::ptr_eq(&b, &wt_out))
    });
    println!(
        "case=phi_fwd|phase=check|phi_exists={}|phi_reads_both_writes={}|then_write_addrforced={}|else_write_addrforced={}",
        u8::from(phi.is_some()),
        u8::from(phi_reads_both_writes),
        u8::from(read_vn(&wt_out).is_addr_force()),
        u8::from(read_vn(&we_out).is_addr_force()),
    );
}

fn main() {
    println!(
        "schema=1|fixture=HERITAGE-STORELOAD-FWD-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    case_fwd_indexed_load();
    case_const_load_no_fwd();
    case_phi_fwd();
}
