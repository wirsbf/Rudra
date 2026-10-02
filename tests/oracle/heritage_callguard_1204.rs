// HERITAGE-CALLGUARD-0001: Rudra comparand for the locked Ghidra 12.0.4
// ActionHeritage -> Funcdata::opHeritage -> Heritage::heritage call-guard
// oracle (guardCalls / newIndirectOp / newIndirectCreation). Mirrors
// tests/oracle/heritage_callguard_1204.cc case for case: the same synthetic
// call graphs and prototype models are built through the production
// Funcdata / fspec APIs, the canonical `op_heritage` boundary drives the
// guard pipeline, and the complete per-object INDIRECT projection (parent
// block + position, Iop alias, input form, output storage + flags, guard
// order, trials, pass gating) is printed in the shared observation format.
//
// Projected-away divergence (registered): Ghidra's guard() derives `fl`
// from ScopeLocal::queryProperties — stack-local ranges get Varnode::
// addrtied, which sets ADDRFORCE on unknown-effect guard outputs. Rudra's
// canonical path has no ScopeLocal yet (varmap family), so the `af` flag
// is omitted from BOTH comparands' projections; see metadata coverage
// `scope_fl_properties: UNTESTED`.

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::fspec::{
    EffectRecord, EffectType, FuncCallSpecs, ParamEntry, ParamListOutput, ProtoModelFull,
};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;
type OpRef = PcodeOpRef;

fn effect_name(effect: EffectType) -> &'static str {
    match effect {
        EffectType::Unaffected => "unaffected",
        EffectType::KilledByCall => "killedbycall",
        EffectType::ReturnAddress => "return_address",
        EffectType::UnknownEffect => "unknown_effect",
    }
}

// Varnode descriptor shared with the C++ oracle fixture:
//   constant -> C<size>; register -> R<hex-offset>:<I|W|F>;
//   unique -> U<size>:<I|W|F>; stack -> S<off>:<..>; iop -> IOP
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
        AddressSpace::Iop => {
            return "IOP".to_string();
        }
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

// Flag suffix shared with the C++ oracle: {ic,ra,ah}. The ADDRFORCE flag
// is deliberately not printed (scope_fl_properties residual).
fn vn_flag_suffix(vn: &VnRef) -> String {
    let value = vn.read().unwrap();
    let mut parts: Vec<&str> = Vec::new();
    if value.is_indirect_creation() {
        parts.push("ic");
    }
    if value.is_return_address() {
        parts.push("ra");
    }
    if value.is_active_heritage() {
        parts.push("ah");
    }
    format!("{{{}}}", parts.join(","))
}

// The HERITAGE-CALLGUARD model: SYSV-shaped inputs RSI(0x30)/RDI(0x38),
// output RAX(0x0), explicit killedbycall on RAX and stack(0x8,8),
// return_address storage at 0x288 — the same record set the C++ fixture
// decodes from its prototype XML.
fn make_callguard_model() -> Arc<ProtoModelFull> {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = "callguard".to_string();
    model.extrapop = 0;
    model.input.entry_mut().push(ParamEntry::from_storage(
        AddressSpace::Register,
        0x30,
        8,
        1,
        0,
    ));
    model.input.entry_mut().push(ParamEntry::from_storage(
        AddressSpace::Register,
        0x38,
        8,
        1,
        1,
    ));
    let output_base = match &mut model.output {
        ParamListOutput::Standard(list) => &mut list.base,
        ParamListOutput::Register(list) => &mut list.base.base,
    };
    output_base.entry_mut().push(ParamEntry::from_storage(
        AddressSpace::Register,
        0x0,
        8,
        1,
        0,
    ));
    model.effectlist = vec![
        EffectRecord::new(AddressSpace::Register, 0x0, 8, EffectType::KilledByCall),
        EffectRecord::new(AddressSpace::Register, 0x288, 8, EffectType::ReturnAddress),
        EffectRecord::new(AddressSpace::Stack, 0x8, 8, EffectType::KilledByCall),
    ];
    Arc::new(model)
}

// Whole-register-space unaffected model: a size-0 record marks the entire
// space (fspec.cc lookupEffect).
fn make_unaffected_model() -> Arc<ProtoModelFull> {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = "callguard_unaffected".to_string();
    model.extrapop = 0;
    model.input.entry_mut().push(ParamEntry::from_storage(
        AddressSpace::Register,
        0x30,
        8,
        1,
        0,
    ));
    let output_base = match &mut model.output {
        ParamListOutput::Standard(list) => &mut list.base,
        ParamListOutput::Register(list) => &mut list.base.base,
    };
    output_base.entry_mut().push(ParamEntry::from_storage(
        AddressSpace::Register,
        0x0,
        8,
        1,
        0,
    ));
    model.effectlist = vec![EffectRecord::new(
        AddressSpace::Register,
        0x0,
        0,
        EffectType::Unaffected,
    )];
    Arc::new(model)
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    blocks: Vec<BlockRef>,
    ops: Vec<(OpRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            next_offset: 0,
            blocks: Vec::new(),
            ops: Vec::new(),
        }
    }

    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
            index,
            Address::new(self.base),
        )));
        self.fd.bblocks.add_block(block.clone());
        self.blocks.push(block.clone());
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
        self.ops.push((op.clone(), name));
        op
    }

    fn make_call(&mut self, name: &'static str, block: &BlockRef) -> OpRef {
        let op = self.make_op(name, OpCode::CPUI_CALL, 1);
        let target = self.fd.new_constant(8, 0x4000);
        self.fd.op_set_input(&op, target, 0);
        self.fd.op_insert_end(&op, block);
        op
    }

    // Production FuncProtos always carry a backing store by the time
    // guardCalls runs; the C++ comparand installs a ProtoStoreInternal
    // with a void output, which leaves the prototype unlocked. Rudra's
    // FuncProto has no store, and its characterization goes straight to
    // the model branch — the same effective state.
    fn add_spec(&mut self, call_op: &OpRef, model: Arc<ProtoModelFull>) -> usize {
        // flow.cc:1202 mirrors: the Funcdata's own prototype is the base and
        // the callspec is bound to this exact CALL operation.
        let proto = self.fd.funcp.clone();
        let mut fc = FuncCallSpecs::new_for_op(call_op, proto);
        fc.prototype.set_model(Some(model));
        self.fd.add_call_specs(fc)
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd.op_set_input(op, vn.clone(), slot);
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd.op_insert_end(op, block);
    }

    fn seed_register_range(&mut self, offset: u64, size: i32, block: &BlockRef) {
        if size >= 8 {
            let def = self.make_op("def", OpCode::CPUI_COPY, 1);
            let c = self.fd.new_constant(8, 0x11);
            self.set_input(&def, &c, 0);
            let vn = self
                .fd
                .vbank
                .create_with_space(size as usize, AddressSpace::Register, offset);
            self.fd.op_set_output(&def, vn);
            self.insert_end(&def, block);
        } else {
            let freevn =
                self.fd
                    .vbank
                    .create_with_space(size as usize, AddressSpace::Register, offset);
            let reader = self.make_op("reader", OpCode::CPUI_INT_OR, 2);
            self.set_input(&reader, &freevn, 0);
            let c = self.fd.new_constant(1, 1);
            self.set_input(&reader, &c, 1);
            self.insert_end(&reader, block);
        }
    }

    fn seed_stack_range(&mut self, offset: u64, size: i32, block: &BlockRef) {
        if size >= 8 {
            let def = self.make_op("def", OpCode::CPUI_COPY, 1);
            let c = self.fd.new_constant(8, 0x22);
            self.set_input(&def, &c, 0);
            let vn = self
                .fd
                .vbank
                .create_with_space(size as usize, AddressSpace::Stack, offset);
            self.fd.op_set_output(&def, vn);
            self.insert_end(&def, block);
        } else {
            let freevn =
                self.fd
                    .vbank
                    .create_with_space(size as usize, AddressSpace::Stack, offset);
            let reader = self.make_op("reader", OpCode::CPUI_INT_OR, 2);
            self.set_input(&reader, &freevn, 0);
            let c = self.fd.new_constant(1, 1);
            self.set_input(&reader, &c, 1);
            self.insert_end(&reader, block);
        }
    }

    // Production pre-state: Rudra's dominator producer plus the Heritage
    // info list (buildInfoList, funcdata.cc:166).
    fn prepare_structure(&mut self) {
        self.fd.bblocks.build_dom_tree();
        self.fd.heritage.build_info_list();
    }

    fn op_alias_name(&self, op: &Option<PcodeOpRef>) -> &str {
        match op {
            None => "none",
            Some(target) => {
                for (candidate, name) in &self.ops {
                    if Arc::ptr_eq(&candidate.0, &target.0) {
                        return name;
                    }
                }
                "none"
            }
        }
    }

    // Project every alive INDIRECT op in block/position order.
    fn project_indirects(&self, out: &mut String) -> usize {
        let mut count = 0usize;
        for (bi, block) in self.blocks.iter().enumerate() {
            let ops = block.read().unwrap().get_ops();
            for (pos, op) in ops.iter().enumerate() {
                let op_ref = op.0.read().unwrap();
                if op_ref.opcode != OpCode::CPUI_INDIRECT {
                    continue;
                }
                if count != 0 {
                    out.push(',');
                }
                out.push_str(&format!("{bi}.{pos}/"));
                if op_ref.is_indirect_store() {
                    out.push_str("ics");
                } else if op_ref.is_indirect_creation() {
                    out.push_str("ic");
                } else {
                    out.push_str("ind");
                }
                out.push_str("/iop=");
                let in1 = op_ref.get_in(1).cloned();
                let alias = match &in1 {
                    Some(vn) if vn.read().unwrap().get_space() == AddressSpace::Iop => {
                        self.fd.get_op_from_const(vn)
                    }
                    _ => None,
                };
                out.push_str(self.op_alias_name(&alias));
                if let Some(in0) = op_ref.get_in(0) {
                    out.push_str(&format!(
                        "/in0={}{}",
                        vn_descriptor(in0),
                        vn_flag_suffix(in0)
                    ));
                }
                if let Some(outvn) = &op_ref.output {
                    out.push_str(&format!(
                        "/out={}{}",
                        vn_descriptor(outvn),
                        vn_flag_suffix(outvn)
                    ));
                }
                count += 1;
            }
        }
        count
    }

    // Project registered trials for every callspec plus the call op input
    // count. The C++ comparand prints the trial space name; Rudra's
    // ParamTrial stores the offset-only Address, so the space comes from
    // the trial's guarded range space in this fixture (register trials in
    // output_input_trials, none elsewhere).
    fn project_trials(&self, out: &mut String, trial_space: AddressSpace) {
        let space_name = match trial_space {
            AddressSpace::Register => "register",
            AddressSpace::Stack => "stack",
            _ => "other",
        };
        for (i, fc) in self.fd.callspecs.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            out.push_str(&format!("fc{i}"));
            out.push_str(":tin=[");
            let (input_projection, output_projection, call_op) = {
                let fc = fc.read().unwrap();
                let input_projection = fc
                    .active_input
                    .as_ref()
                    .map(|active| {
                        (0..active.get_num_trials())
                            .map(|j| {
                                let trial = active.get_trial(j);
                                format!(
                                    "{}{}/{}",
                                    space_name,
                                    format!("{:x}", trial.get_address().as_u64()),
                                    trial.get_size()
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let output_projection = fc
                    .active_output
                    .as_ref()
                    .map(|active| {
                        (0..active.get_num_trials())
                            .map(|j| {
                                let trial = active.get_trial(j);
                                format!(
                                    "{}{}/{}",
                                    space_name,
                                    format!("{:x}", trial.get_address().as_u64()),
                                    trial.get_size()
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                (
                    input_projection,
                    output_projection,
                    fc.find_call_op(&self.fd),
                )
            };
            out.push_str(&input_projection);
            out.push_str("]:tout=[");
            out.push_str(&output_projection);
            out.push(']');
            let callin = call_op
                .map(|op| op.0.read().unwrap().num_input())
                .unwrap_or(0);
            out.push_str(&format!(":callin={callin}"));
        }
    }
}

// The ten ABI-shaped ranges (GetStr decimal 0/48/56/512/514/518/519/522/523/648).
const RANGES_OFFSET: [u64; 10] = [
    0x0, 0x30, 0x38, 0x200, 0x202, 0x206, 0x207, 0x20a, 0x20b, 0x288,
];
const RANGES_SIZE: [i32; 10] = [8, 8, 8, 1, 1, 1, 1, 1, 1, 8];

fn main() {
    let envelope =
        "schema=1|fixture=HERITAGE-CALLGUARD-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b";
    println!("{envelope}");

    // case=model_state
    {
        let model = make_callguard_model();
        let mut out = String::new();
        out.push_str(&format!("case=model_state|name={}", model.name));
        out.push_str("|effects=[");
        for (i, eff) in model.effectlist.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{}{:x}:{}={}",
                match eff.space {
                    AddressSpace::Register => "register",
                    AddressSpace::Stack => "stack",
                    _ => "other",
                },
                eff.offset,
                eff.size,
                effect_name(eff.effect_type)
            ));
        }
        out.push_str("]");
        out.push_str("|probe=[");
        for i in 0..RANGES_OFFSET.len() {
            if i != 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{:x}/{}",
                RANGES_OFFSET[i],
                effect_name(model.has_effect(
                    AddressSpace::Register,
                    RANGES_OFFSET[i],
                    RANGES_SIZE[i]
                ))
            ));
        }
        out.push_str(&format!(
            ",S18/{}",
            effect_name(model.has_effect(AddressSpace::Stack, 0x18, 8))
        ));
        out.push_str(&format!(
            ",S8/{}",
            effect_name(model.has_effect(AddressSpace::Stack, 0x8, 8))
        ));
        out.push_str("]");
        println!("{out}");
    }

    // case=single_call_ten_ranges
    {
        let model = make_callguard_model();
        let mut g = Graph::new("single", 0x5100);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        for i in 0..RANGES_OFFSET.len() {
            g.seed_register_range(RANGES_OFFSET[i], RANGES_SIZE[i], &b0);
        }
        let call1 = g.make_call("call1", &b1);
        g.add_spec(&call1, model);
        g.prepare_structure();
        g.fd.op_heritage();
        let mut out = String::new();
        out.push_str("case=single_call_ten_ranges|guards=");
        let count = g.project_indirects(&mut out);
        out.push_str(&format!("|count={count}"));
        println!("{out}");
    }

    // case=two_calls_ten_ranges
    {
        let model = make_callguard_model();
        let mut g = Graph::new("twocall", 0x5200);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        for i in 0..RANGES_OFFSET.len() {
            g.seed_register_range(RANGES_OFFSET[i], RANGES_SIZE[i], &b0);
        }
        let call1 = g.make_call("call1", &b1);
        let call2 = g.make_call("call2", &b2);
        g.add_spec(&call1, model.clone());
        g.add_spec(&call2, model);
        g.prepare_structure();
        g.fd.op_heritage();
        let mut out = String::new();
        out.push_str("case=two_calls_ten_ranges|guards=");
        let count = g.project_indirects(&mut out);
        out.push_str(&format!("|count={count}"));
        println!("{out}");
    }

    // case=unaffected_all
    {
        let model = make_unaffected_model();
        let mut g = Graph::new("unaff", 0x5300);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        for i in 0..RANGES_OFFSET.len() {
            g.seed_register_range(RANGES_OFFSET[i], RANGES_SIZE[i], &b0);
        }
        let call1 = g.make_call("call1", &b1);
        g.add_spec(&call1, model);
        g.prepare_structure();
        g.fd.op_heritage();
        let mut out = String::new();
        out.push_str("case=unaffected_all|guards=");
        let count = g.project_indirects(&mut out);
        out.push_str(&format!("|count={count}"));
        println!("{out}");
    }

    // case=output_input_trials
    {
        let model = make_callguard_model();
        let mut g = Graph::new("trials", 0x5400);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        g.seed_register_range(0x30, 8, &b0);
        g.seed_register_range(0x0, 8, &b0);
        g.seed_register_range(0x200, 1, &b0);
        let call1 = g.make_call("call1", &b1);
        g.add_spec(&call1, model);
        {
            let mut fc = g.fd.callspecs[0].write().unwrap();
            fc.init_active_input();
            fc.init_active_output();
        }
        g.prepare_structure();
        g.fd.op_heritage();
        let mut out = String::new();
        out.push_str("case=output_input_trials|guards=");
        let count = g.project_indirects(&mut out);
        out.push_str(&format!("|count={count}|trials="));
        g.project_trials(&mut out, AddressSpace::Register);
        println!("{out}");
    }

    // case=stack_translation
    {
        let model = make_callguard_model();
        let mut g = Graph::new("stack", 0x5500);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        g.seed_stack_range(0x18, 8, &b0);
        let call1 = g.make_call("call1", &b1);
        let call2 = g.make_call("call2", &b1);
        g.add_spec(&call1, model.clone());
        g.add_spec(&call2, model);
        // cc:1461-1462: fc0 has the resolved stack offset; fc1 keeps
        // offset_unknown (tryregister == false).
        g.fd.callspecs[0].write().unwrap().stackoffset = 0x10;
        g.prepare_structure();
        g.fd.op_heritage();
        let mut out1 = String::new();
        let pass1 = g.project_indirects(&mut out1);
        out1.insert_str(0, &format!("case=stack_translation|pass1count={pass1}"));
        g.fd.op_heritage();
        let mut out = String::new();
        out.push_str("|guards=");
        let count = g.project_indirects(&mut out);
        out.push_str(&format!("|count={count}|trials="));
        g.project_trials(&mut out, AddressSpace::Stack);
        println!("{out1}{out}");
    }

    // case=driver_pass_gating
    {
        let model = make_callguard_model();
        let mut g = Graph::new("driver", 0x5600);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        for i in 0..RANGES_OFFSET.len() {
            g.seed_register_range(RANGES_OFFSET[i], RANGES_SIZE[i], &b0);
        }
        let call1 = g.make_call("call1", &b1);
        let call2 = g.make_call("call2", &b2);
        g.add_spec(&call1, model.clone());
        g.add_spec(&call2, model);
        g.prepare_structure();
        g.fd.op_heritage();
        let mut out = String::new();
        out.push_str("case=driver_pass_gating|pass1guards=");
        let pass1 = g.project_indirects(&mut out);
        g.fd.op_heritage();
        let mut out2 = String::new();
        let pass2 = g.project_indirects(&mut out2);
        out.push_str(&format!(
            "|pass1count={pass1}|pass2count={pass2}|pass2new={}",
            pass2 as i64 - pass1 as i64
        ));
        println!("{out}");
    }
}
