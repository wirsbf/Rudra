// HERITAGE-GUARD-NORMALIZE-0001
//
// Rust comparand for tests/oracle/heritage_guard_normalize_1204.cc.  The six
// cases drive the same public Funcdata construction APIs and the canonical
// `Funcdata::op_heritage` boundary.  Objects are projected only through
// storage, size, class, defining opcode, per-flag booleans and first-seen
// alias ids; block order, op order, input slot order and alias relations
// remain observable.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard};

use rudra::address::Range;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::database::Database;
use rudra::funcdata::Funcdata;
use rudra::fspec::{FuncCallSpecs, ParamEntry, ProtoModelFull};
use rudra::op::{pcodeop_flags, PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varmap::ScopeLocal;
use rudra::varnode::{varnode_flags, Varnode};

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
        OpCode::CPUI_INT_SUB => "INT_SUB",
        OpCode::CPUI_INT_OR => "INT_OR",
        OpCode::CPUI_CALL => "CALL",
        OpCode::CPUI_CALLIND => "CALLIND",
        OpCode::CPUI_RETURN => "RETURN",
        OpCode::CPUI_INDIRECT => "INDIRECT",
        OpCode::CPUI_MULTIEQUAL => "MULTIEQUAL",
        OpCode::CPUI_PIECE => "PIECE",
        OpCode::CPUI_SUBPIECE => "SUBPIECE",
        _ => "OTHER",
    }
}

fn make_ret8_model() -> Arc<ProtoModelFull> {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = "guardnorm_ret8".to_string();
    model.extrapop = 0;
    let output_base = match &mut model.output {
        rudra::fspec::ParamListOutput::Standard(list) => &mut list.base,
        rudra::fspec::ParamListOutput::Register(list) => &mut list.base.base,
    };
    output_base.entry_mut().push(ParamEntry::from_storage(
        AddressSpace::Register,
        0x0,
        8,
        1,
        0,
    ));
    Arc::new(model)
}

fn make_ret4hi_model() -> Arc<ProtoModelFull> {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = "guardnorm_ret4hi".to_string();
    model.extrapop = 0;
    let output_base = match &mut model.output {
        rudra::fspec::ParamListOutput::Standard(list) => &mut list.base,
        rudra::fspec::ParamListOutput::Register(list) => &mut list.base.base,
    };
    output_base.entry_mut().push(ParamEntry::from_storage(
        AddressSpace::Register,
        0x4,
        4,
        1,
        0,
    ));
    Arc::new(model)
}

fn make_call_model() -> Arc<ProtoModelFull> {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = "guardnorm_call".to_string();
    model.extrapop = 0;
    Arc::new(model)
}

// The C++ comparand's Funcdata ctor creates a real ScopeLocal
// (funcdata.cc:67-73) whose resetLocalWindow range comes from the default
// model's defaultLocalRange/defaultParamRange (fspec.cc:2700-2733):
// stack [0,511] for parameters plus [highest-999999, highest] for locals on
// a negative-growth 8-byte stack.  Install the same window on the Rust
// Funcdata so guard's queryProperties sees the same input state.
fn install_default_local_scope(fd: &mut Funcdata) {
    let mut scope = ScopeLocal::new();
    scope.space = AddressSpace::Stack;
    scope.local_range = vec![
        (0, 511),
        (0xFFFFFFFFFFFFFFFF - 999999, 0xFFFFFFFFFFFFFFFF),
    ];
    fd.scope = Some(scope);
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    blocks: Vec<BlockRef>,
    ops: Vec<(OpRef, &'static str)>,
    aliases: HashMap<usize, usize>,
    next_alias: usize,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        let mut fd = Funcdata::new(name, rudra::address::Address::new(base), 0x20);
        install_default_local_scope(&mut fd);
        Graph {
            fd,
            base,
            next_offset: 0,
            blocks: Vec::new(),
            ops: Vec::new(),
            aliases: HashMap::new(),
            next_alias: 0,
        }
    }

    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            index,
            rudra::address::Address::new(self.base),
        )));
        self.fd.bblocks.add_block(block.clone());
        self.blocks.push(block.clone());
        block
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn make_op(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> OpRef {
        let pc = rudra::address::Address::new(self.base + self.next_offset);
        self.next_offset += 1;
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        self.ops.push((op.0.clone(), name));
        op.0
    }

    // Production FuncProtos always carry a backing ProtoStore by the time
    // guardCalls runs; the C++ comparand installs a ProtoStoreInternal with
    // a void output.  Rugra's FuncProto has no store, and its
    // characterization goes straight to the model branch — the same
    // effective state.
    fn add_spec(&mut self, call_op: &OpRef, model: Arc<ProtoModelFull>) -> usize {
        let proto = self.fd.funcp.clone();
        let mut fc = FuncCallSpecs::new_for_op(&PcodeOpRef(call_op.clone()), proto);
        fc.prototype.set_model(Some(model));
        self.fd.add_call_specs(fc)
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

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

    fn free_ram(&mut self, offset: u64, size: usize) -> VnRef {
        self.fd
            .vbank
            .create_with_space(size, AddressSpace::Ram, offset)
    }

    fn written_register(&mut self, offset: u64, size: usize, op: &OpRef) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.fd.op_set_output(&PcodeOpRef(op.clone()), vn);
        read_op(op).output.clone().expect("written register output")
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd
            .op_set_input(&PcodeOpRef(op.clone()), vn.clone(), slot);
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd.op_insert_end(&PcodeOpRef(op.clone()), block);
    }

    fn prepare_structure(&mut self) {
        let mut preorder = Vec::new();
        let mut roots = Vec::new();
        self.fd
            .bblocks
            .find_spanning_tree(&mut preorder, &mut roots)
            .expect("find_spanning_tree");
        self.fd.bblocks.build_dom_tree();
        self.fd.heritage.build_info_list();
    }

    fn op_alias_name(&self, op: &OpRef) -> &str {
        for (candidate, name) in &self.ops {
            if Arc::ptr_eq(candidate, op) {
                return name;
            }
        }
        "none"
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
                AddressSpace::Stack => {
                    format!("S{:x}:{}", value.get_offset(), value.get_size())
                }
                AddressSpace::Unique => format!("U{}", value.get_size()),
                AddressSpace::Iop => format!("IOP{}", value.get_size()),
                AddressSpace::Ram => {
                    format!("M{:x}:{}", value.get_offset(), value.get_size())
                }
                _ => format!("OTH:{:x}:{}", value.get_offset(), value.get_size()),
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
        let def = value.get_def();
        let (act, force, wmask, persist) = (
            value.is_active_heritage(),
            value.is_addr_force(),
            value.is_write_mask(),
            value.is_persist(),
        );
        drop(value);
        let def_name = def
            .map(|op| opcode_name(read_op(&op).opcode))
            .unwrap_or("-");
        format!(
            "a{alias}:{storage}:{class}:def{def_name}:act{}:force{}:wmask{}:persist{}",
            u8::from(act),
            u8::from(force),
            u8::from(wmask),
            u8::from(persist),
        )
    }

    fn op_state(&mut self, op: &OpRef) -> String {
        let (opcode, flags, output, inputs) = {
            let value = read_op(op);
            (value.opcode, value.flags, value.output.clone(), value.inrefs.clone())
        };
        let halt = flags
            & (pcodeop_flags::HALT
                | pcodeop_flags::BADINSTRUCTION
                | pcodeop_flags::UNIMPLEMENTED
                | pcodeop_flags::NORETURN
                | pcodeop_flags::MISSING);
        let name = self.op_alias_name(op).to_string();
        let out_state = self.vn_state(output.as_ref());
        let mut out = format!(
            "{name}.{}{{rc={},halt={halt:x},ic={},is={},out={out_state}",
            opcode_name(opcode),
            u8::from((flags & pcodeop_flags::RETURN_COPY) != 0),
            u8::from((flags & pcodeop_flags::INDIRECT_CREATION) != 0),
            u8::from((flags & pcodeop_flags::INDIRECT_STORE) != 0),
        );
        for (slot, input) in inputs.iter().enumerate() {
            let state = self.vn_state(Some(input));
            out.push_str(&format!(",s{slot}={state}"));
        }
        out.push('}');
        out
    }

    fn order(&mut self) -> String {
        let mut block_ops: Vec<Vec<OpRef>> = Vec::new();
        for block in &self.blocks {
            block_ops.push(
                block
                    .read()
                    .unwrap()
                    .get_ops()
                    .into_iter()
                    .map(|op| op.0)
                    .collect(),
            );
        }
        let mut block_parts = Vec::new();
        for (bi, ops) in block_ops.into_iter().enumerate() {
            let mut op_parts = Vec::new();
            for op in ops {
                op_parts.push(self.op_state(&op));
            }
            block_parts.push(format!("b{bi}[{}]", op_parts.join(",")));
        }
        block_parts.join(";")
    }

    fn indirect_count(&mut self) -> usize {
        let mut count = 0;
        let mut all_ops: Vec<OpRef> = Vec::new();
        for block in &self.blocks {
            all_ops.extend(block.read().unwrap().get_ops().into_iter().map(|op| op.0));
        }
        for op in &all_ops {
            if read_op(op).opcode == OpCode::CPUI_INDIRECT {
                count += 1;
            }
        }
        count
    }

    fn trial_projection(&mut self) -> String {
        let Some(active) = self.fd.active_output.as_ref() else {
            return "none".to_string();
        };
        let mut parts = Vec::new();
        for i in 0..active.get_num_trials() {
            let trial = active.get_trial(i);
            parts.push(format!(
                "t{i}={:x}:{}:slot{}:kb{}",
                trial.get_address().as_u64(),
                trial.get_size(),
                trial.get_slot(),
                u8::from(trial.is_killed_by_call()),
            ));
        }
        parts.join(";")
    }

    fn heritage_pass_of(&self, space: AddressSpace, offset: u64) -> i32 {
        self.fd
            .heritage
            .globaldisjoint
            .find_pass(space, rudra::address::Address::new(offset))
    }

    // The op immediately preceding `op` inside its block (PcodeOp::previousOp).
    fn previous_op(&self, op: &OpRef) -> Option<OpRef> {
        let parent = read_op(op).parent.as_ref().and_then(|p| p.upgrade())?;
        let ops = parent.read().unwrap().get_ops();
        let mut prev: Option<OpRef> = None;
        for entry in ops {
            if Arc::ptr_eq(&entry.0, op) {
                return prev;
            }
            prev = Some(entry.0);
        }
        None
    }
}

fn main() {
    let ret8 = make_ret8_model();
    let ret4hi = make_ret4hi_model();
    let call_model = make_call_model();
    println!(
        "schema=1|fixture=HERITAGE-GUARD-NORMALIZE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case 1: whole-range return storage -> RETURN input trial ----
    {
        let mut g = Graph::new("guard_returns_trial_register", 0x6100);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.fd.get_func_proto_mut().set_model(Some(ret8.clone()));
        g.fd.init_active_output();
        let read = g.make_op("read", OpCode::CPUI_INT_OR, 2);
        let fr = g.free_register(0x0, 8);
        g.set_input(&read, &fr, 0);
        let c21 = g.constant(8, 0x21);
        g.set_input(&read, &c21, 1);
        g.fd.new_unique_out(8, &PcodeOpRef(read.clone()));
        g.insert_end(&read, &b0);
        let ret0 = g.make_op("ret0", OpCode::CPUI_RETURN, 1);
        let cret0 = g.constant(8, 0x6100);
        g.set_input(&ret0, &cret0, 0);
        g.insert_end(&ret0, &b0);
        let rhalt = g.make_op("rhalt", OpCode::CPUI_RETURN, 1);
        let creth = g.constant(8, 0x6101);
        g.set_input(&rhalt, &creth, 0);
        g.insert_end(&rhalt, &b1);
        g.fd.op_mark_halt(&PcodeOpRef(rhalt.clone()), pcodeop_flags::MISSING);
        let ret2 = g.make_op("ret2", OpCode::CPUI_RETURN, 1);
        let cret2 = g.constant(8, 0x6102);
        g.set_input(&ret2, &cret2, 0);
        g.insert_end(&ret2, &b2);
        g.prepare_structure();
        g.fd.op_heritage();
        let (ret0_last, ret2_last) = {
            let r0 = read_op(&ret0);
            let r2 = read_op(&ret2);
            (
                g.vn_state(r0.inrefs.last()),
                g.vn_state(r2.inrefs.last()),
            )
        };
        println!(
            "case=guard_returns_trial_register|pass={}|hp_reg={}|trials={}|ret0_in={}|ret0_last={ret0_last}|rhalt_in={}|ret2_in={}|ret2_last={ret2_last}|order={}",
            g.fd.num_heritage_passes(),
            g.heritage_pass_of(AddressSpace::Register, 0x0),
            g.trial_projection(),
            read_op(&ret0).inrefs.len(),
            read_op(&rhalt).inrefs.len(),
            read_op(&ret2).inrefs.len(),
            g.order(),
        );
    }

    // ---- case 2: range contains return storage -> SUBPIECE truncation ----
    {
        let mut g = Graph::new("guard_returns_overlapping_subpiece", 0x6200);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        g.fd.get_func_proto_mut().set_model(Some(ret4hi.clone()));
        g.fd.init_active_output();
        let read = g.make_op("read", OpCode::CPUI_INT_ADD, 2);
        let fr = g.free_register(0x0, 8);
        g.set_input(&read, &fr, 0);
        let c22 = g.constant(8, 0x22);
        g.set_input(&read, &c22, 1);
        g.fd.new_unique_out(8, &PcodeOpRef(read.clone()));
        g.insert_end(&read, &b0);
        let ret0 = g.make_op("ret0", OpCode::CPUI_RETURN, 1);
        let cret0 = g.constant(8, 0x6200);
        g.set_input(&ret0, &cret0, 0);
        g.insert_end(&ret0, &b0);
        let rhalt = g.make_op("rhalt", OpCode::CPUI_RETURN, 1);
        let creth = g.constant(8, 0x6201);
        g.set_input(&rhalt, &creth, 0);
        g.insert_end(&rhalt, &b1);
        g.fd
            .op_mark_halt(&PcodeOpRef(rhalt.clone()), pcodeop_flags::BADINSTRUCTION);
        g.prepare_structure();
        g.fd.op_heritage();
        let ret0_last = g.vn_state(read_op(&ret0).inrefs.last());
        println!(
            "case=guard_returns_overlapping_subpiece|pass={}|trials={}|ret0_in={}|ret0_last={ret0_last}|rhalt_in={}|order={}",
            g.fd.num_heritage_passes(),
            g.trial_projection(),
            read_op(&ret0).inrefs.len(),
            read_op(&rhalt).inrefs.len(),
            g.order(),
        );
    }

    // ---- case 3: persist property -> return-copy COPY suffix (no active
    //      output; halt RETURN included) ----
    {
        let mut db = Database::new(false);
        db.set_property_range(
            varnode_flags::PERSIST,
            Range::new(
                rudra::address::Address::new(0x1000),
                rudra::address::Address::new(0x2000),
            )
            .expect("persist range"),
        );
        let mut arch = Architecture::new();
        arch.set_symboltab(Arc::new(RwLock::new(db)));
        let mut g = Graph::new("persist_return_copy_suffix", 0x6300);
        g.fd.set_arch(Arc::new(arch));
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        let read = g.make_op("read", OpCode::CPUI_INT_OR, 2);
        let fm = g.free_ram(0x1000, 8);
        g.set_input(&read, &fm, 0);
        let c23 = g.constant(8, 0x23);
        g.set_input(&read, &c23, 1);
        g.fd.new_unique_out(8, &PcodeOpRef(read.clone()));
        g.insert_end(&read, &b0);
        let ret0 = g.make_op("ret0", OpCode::CPUI_RETURN, 1);
        let cret0 = g.constant(8, 0x6300);
        g.set_input(&ret0, &cret0, 0);
        g.insert_end(&ret0, &b0);
        let rhalt = g.make_op("rhalt", OpCode::CPUI_RETURN, 1);
        let creth = g.constant(8, 0x6301);
        g.set_input(&rhalt, &creth, 0);
        g.insert_end(&rhalt, &b1);
        g.fd.op_mark_halt(&PcodeOpRef(rhalt.clone()), pcodeop_flags::MISSING);
        g.prepare_structure();
        g.fd.op_heritage();
        let before_ret0_state = g
            .previous_op(&ret0)
            .map(|op| g.op_state(&op))
            .unwrap_or_else(|| "none".to_string());
        let before_rhalt_state = g
            .previous_op(&rhalt)
            .map(|op| g.op_state(&op))
            .unwrap_or_else(|| "none".to_string());
        println!(
            "case=persist_return_copy_suffix|pass={}|trials={}|before_ret0={before_ret0_state}|before_rhalt={before_rhalt_state}|ret0_in={}|order={}",
            g.fd.num_heritage_passes(),
            g.trial_projection(),
            read_op(&ret0).inrefs.len(),
            g.order(),
        );
    }

    // ---- case 4: normalizeWriteSize on a CALL-defined partial write ----
    {
        let mut g = Graph::new("normalize_write_call_piece", 0x6400);
        let b0 = g.make_block(0);
        let call = g.make_op("call", OpCode::CPUI_CALL, 1);
        let ctarget = g.constant(8, 0x4000);
        g.set_input(&call, &ctarget, 0);
        g.written_register(0x12, 2, &call);
        g.insert_end(&call, &b0);
        g.add_spec(&call, call_model.clone());
        let read = g.make_op("read", OpCode::CPUI_INT_OR, 2);
        let fr = g.free_register(0x10, 4);
        g.set_input(&read, &fr, 0);
        let c24 = g.constant(8, 0x24);
        g.set_input(&read, &c24, 1);
        g.fd.new_unique_out(8, &PcodeOpRef(read.clone()));
        g.insert_end(&read, &b0);
        let ret0 = g.make_op("ret0", OpCode::CPUI_RETURN, 1);
        let cret0 = g.constant(8, 0x6400);
        g.set_input(&ret0, &cret0, 0);
        g.insert_end(&ret0, &b0);
        g.prepare_structure();
        g.fd.op_heritage();
        let call_out = g.vn_state(read_op(&call).output.as_ref());
        println!(
            "case=normalize_write_call_piece|pass={}|hp_reg={}|call_out={call_out}|order={}",
            g.fd.num_heritage_passes(),
            g.heritage_pass_of(AddressSpace::Register, 0x10),
            g.order(),
        );
    }

    // ---- case 5: normalizeWriteSize on a plain partial write ----
    {
        let mut g = Graph::new("normalize_write_subpiece_piece", 0x6500);
        let b0 = g.make_block(0);
        let w = g.make_op("w", OpCode::CPUI_INT_SUB, 2);
        let c31 = g.constant(8, 0x31);
        g.set_input(&w, &c31, 0);
        let c32 = g.constant(8, 0x32);
        g.set_input(&w, &c32, 1);
        g.written_register(0x22, 2, &w);
        g.insert_end(&w, &b0);
        let read = g.make_op("read", OpCode::CPUI_INT_OR, 2);
        let fr = g.free_register(0x20, 4);
        g.set_input(&read, &fr, 0);
        let c25 = g.constant(8, 0x25);
        g.set_input(&read, &c25, 1);
        g.fd.new_unique_out(8, &PcodeOpRef(read.clone()));
        g.insert_end(&read, &b0);
        let ret0 = g.make_op("ret0", OpCode::CPUI_RETURN, 1);
        let cret0 = g.constant(8, 0x6500);
        g.set_input(&ret0, &cret0, 0);
        g.insert_end(&ret0, &b0);
        g.prepare_structure();
        g.fd.op_heritage();
        let w_out = g.vn_state(read_op(&w).output.as_ref());
        let read_in = g.vn_state(read_op(&read).inrefs.first());
        println!(
            "case=normalize_write_subpiece_piece|pass={}|w_out={w_out}|read_in={read_in}|order={}",
            g.fd.num_heritage_passes(),
            g.order(),
        );
    }

    // ---- case 6: guard timing across passes (stack delay 1, CALL guard) ----
    {
        let mut g = Graph::new("guard_retry_pass_boundary", 0x6600);
        let b0 = g.make_block(0);
        let call = g.make_op("call", OpCode::CPUI_CALL, 1);
        let ctarget = g.constant(8, 0x4000);
        g.set_input(&call, &ctarget, 0);
        g.insert_end(&call, &b0);
        g.add_spec(&call, call_model.clone());
        let read = g.make_op("read", OpCode::CPUI_INT_OR, 2);
        let fs = g.free_stack(0x20, 8);
        g.set_input(&read, &fs, 0);
        let c26 = g.constant(8, 0x26);
        g.set_input(&read, &c26, 1);
        g.fd.new_unique_out(8, &PcodeOpRef(read.clone()));
        g.insert_end(&read, &b0);
        let ret0 = g.make_op("ret0", OpCode::CPUI_RETURN, 1);
        let cret0 = g.constant(8, 0x6600);
        g.set_input(&ret0, &cret0, 0);
        g.insert_end(&ret0, &b0);
        g.prepare_structure();
        g.fd.op_heritage(); // pass 0: register spaces only; stack delayed
        let ind0 = g.indirect_count();
        g.fd.op_heritage(); // pass 1: new stack range -> guard fires
        let ind1 = g.indirect_count();
        g.fd.op_heritage(); // pass 2: old range -> no new guard
        let ind2 = g.indirect_count();
        let read_in = g.vn_state(read_op(&read).inrefs.first());
        println!(
            "case=guard_retry_pass_boundary|pass={}|hp_stack={}|ind0={ind0}|ind1={ind1}|ind2={ind2}|read_in={read_in}|order={}",
            g.fd.num_heritage_passes(),
            g.heritage_pass_of(AddressSpace::Stack, 0x20),
            g.order(),
        );
    }
}
