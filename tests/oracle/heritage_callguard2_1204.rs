// HERITAGE-CALLGUARD-0001 (follow-up, base=current HEAD): Rugra comparand
// for the locked Ghidra 12.0.4 production-entry call-guard oracle. Mirrors
// tests/oracle/heritage_callguard2_1204.cc case for case: the same
// synthetic call graphs and prototype model are built through the
// production Funcdata / fspec APIs, the GetStr form (2 calls x 10 ABI
// ranges = 20 INDIRECTs) is driven through BOTH the production
// ActionHeritage::apply entry (coreaction.hh:284-290) and the canonical
// `op_heritage` boundary, and the complete per-object guard projection —
// parent block + position, creation form, Iop alias, input[0] source,
// output storage + flags, output use set — is printed in the shared
// observation format.
//
// Projected-away divergence (registered, inherited from the first fixture):
// Ghidra's guard() derives `fl` from ScopeLocal::queryProperties — stack
// locals get Varnode::addrtied, which sets ADDRFORCE on unknown-effect
// guard outputs. Rugra's canonical path has no ScopeLocal yet (varmap
// family), so the af flag is omitted from BOTH comparands' projections.

use std::sync::Arc;

use rudra::action::Action;
use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::coreaction::ActionHeritage;
use rudra::fspec::{
    EffectRecord, EffectType, FuncCallSpecs, ParamEntry, ParamListOutput, ProtoModelFull,
};
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;
type OpRef = Arc<std::sync::RwLock<PcodeOp>>;

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

// input[0] source form: the defining op's opcode number, or input, or
// const (funcdata_op.cc:683 newIndirectOp in[0] = prior storage value;
// :710 newIndirectCreation in[0] = constant zero).
fn vn_source(vn: &VnRef) -> String {
    let value = vn.read().unwrap();
    if value.is_input() {
        return "input".to_string();
    }
    if value.is_constant() {
        return "const".to_string();
    }
    match value.def.as_ref().and_then(std::sync::Weak::upgrade) {
        None => "none".to_string(),
        Some(def) => format!("op{}", def.read().unwrap().opcode as i32),
    }
}

// Output use set: descendant count and the sorted unique opcode numbers.
fn vn_uses(vn: &VnRef) -> String {
    let value = vn.read().unwrap();
    let mut opcodes: Vec<i32> = Vec::new();
    for weak in &value.descend {
        if let Some(op) = weak.upgrade() {
            let code = op.read().unwrap().opcode as i32;
            if !opcodes.contains(&code) {
                opcodes.push(code);
            }
        }
    }
    let count = value
        .descend
        .iter()
        .filter(|weak| weak.upgrade().is_some())
        .count();
    opcodes.sort_unstable();
    let list = opcodes
        .iter()
        .map(|code| format!("op{code}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("uses={count}[{list}]")
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
        ParamListOutput::Standard(output) => &mut output.base,
        ParamListOutput::Register(output) => &mut output.base.base,
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
        let op_ref: OpRef = op.0.clone();
        self.ops.push((op_ref.clone(), name));
        op_ref
    }

    fn make_call(&mut self, name: &'static str, block: &BlockRef) -> OpRef {
        let op = self.make_op(name, OpCode::CPUI_CALL, 1);
        let target = self.fd.new_constant(8, 0x4000);
        self.fd
            .op_set_input(&rudra::op::PcodeOpRef(op.clone()), target, 0);
        self.fd
            .op_insert_end(&rudra::op::PcodeOpRef(op.clone()), block);
        op
    }

    // Production FuncProtos always carry a backing store by the time
    // guardCalls runs; the C++ comparand installs a ProtoStoreInternal
    // with a void output, which leaves the prototype unlocked. Rugra's
    // FuncProto has no store, and its characterization goes straight to
    // the model branch — the same effective state.
    fn add_spec(&mut self, call_op: &OpRef, model: Arc<ProtoModelFull>) {
        let proto = self.fd.funcp.clone();
        let call_op = PcodeOpRef(call_op.clone());
        let mut fc = FuncCallSpecs::new_for_op(&call_op, proto);
        fc.prototype.set_model(Some(model));
        self.fd.add_call_specs(fc);
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd
            .op_set_input(&rudra::op::PcodeOpRef(op.clone()), vn.clone(), slot);
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd
            .op_insert_end(&rudra::op::PcodeOpRef(op.clone()), block);
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
            self.fd
                .op_set_output(&rudra::op::PcodeOpRef(def.clone()), vn);
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
            self.fd
                .op_set_output(&rudra::op::PcodeOpRef(def.clone()), vn);
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

    // Production pre-state: dominator producer + the Heritage info list
    // (buildInfoList, funcdata.cc:166).
    fn prepare_structure(&mut self) {
        self.fd.bblocks.build_dom_tree();
        self.fd.heritage.build_info_list();
    }

    fn op_alias_name(&self, op: &Option<rudra::op::PcodeOpRef>) -> &str {
        match op {
            None => "none",
            Some(target) => {
                for (candidate, name) in &self.ops {
                    if Arc::ptr_eq(candidate, &target.0) {
                        return name;
                    }
                }
                "none"
            }
        }
    }

    // Extended per-object guard projection: every alive INDIRECT op in
    // block/position order with the def-use legs (input[0] source, output
    // use set). Returns the count.
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
                    out.push_str(&format!("/src={}", vn_source(in0)));
                }
                if let Some(outvn) = &op_ref.output {
                    out.push_str(&format!(
                        "/out={}{}",
                        vn_descriptor(outvn),
                        vn_flag_suffix(outvn)
                    ));
                    out.push_str(&format!("/{}", vn_uses(outvn)));
                }
                count += 1;
            }
        }
        count
    }
}

// The ten ABI-shaped ranges (GetStr decimal 0/48/56/512/514/518/519/522/523/648).
const RANGES_OFFSET: [u64; 10] = [
    0x0, 0x30, 0x38, 0x200, 0x202, 0x206, 0x207, 0x20a, 0x20b, 0x288,
];
const RANGES_SIZE: [i32; 10] = [8, 8, 8, 1, 1, 1, 1, 1, 1, 8];

// Build the canonical GetStr form: b0 holds the ten seeded ranges, call1
// lives in b1, call2 in b2 (b0 -> b1 -> b2).
fn build_two_call_graph(g: &mut Graph, model: Arc<ProtoModelFull>) {
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
}

fn main() {
    let envelope =
        "schema=1|fixture=HERITAGE-CALLGUARD2-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b";
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

    // case=production_two_calls_ten_ranges: the GetStr form through the
    // production ActionHeritage::apply entry (coreaction.hh:284-290).
    let production_guards: String;
    {
        let model = make_callguard_model();
        let mut g = Graph::new("prod2call", 0x5100);
        build_two_call_graph(&mut g, model);
        g.prepare_structure();
        if let Err(err) = ActionHeritage::new().apply(&mut g.fd) {
            eprintln!("production ActionHeritage failed: {err:?}");
            std::process::exit(1);
        }
        let mut guards = String::new();
        let count = g.project_indirects(&mut guards);
        production_guards = guards;
        let mut out = String::new();
        out.push_str(&format!(
            "case=production_two_calls_ten_ranges|guards={production_guards}|count={count}"
        ));
        println!("{out}");
    }

    // case=canonical_two_calls_ten_ranges: the same graph through the
    // canonical op_heritage boundary; identical=1 proves the production
    // entry is byte-equivalent to the canonical single pass.
    {
        let model = make_callguard_model();
        let mut g = Graph::new("canon2call", 0x5200);
        build_two_call_graph(&mut g, model);
        g.prepare_structure();
        g.fd.op_heritage();
        let mut guards = String::new();
        let count = g.project_indirects(&mut guards);
        let identical = if guards == production_guards { 1 } else { 0 };
        let mut out = String::new();
        out.push_str(&format!(
            "case=canonical_two_calls_ten_ranges|guards={guards}|count={count}|identical={identical}"
        ));
        println!("{out}");
    }

    // case=guard_def_use: one call, ten ranges — the rename wiring per
    // guard object (constant-zero creation at killedbycall RAX; renamed
    // prior value for the nine unknown-effect ranges).
    {
        let model = make_callguard_model();
        let mut g = Graph::new("defuse", 0x5300);
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
        out.push_str("case=guard_def_use|guards=");
        let count = g.project_indirects(&mut out);
        out.push_str(&format!("|count={count}"));
        println!("{out}");
    }

    // case=production_second_pass_inert: a second production apply adds no
    // new guards — the canonical pass gating through the production entry.
    {
        let model = make_callguard_model();
        let mut g = Graph::new("prodgate", 0x5400);
        build_two_call_graph(&mut g, model);
        g.prepare_structure();
        let mut heritage_action = ActionHeritage::new();
        if let Err(err) = heritage_action.apply(&mut g.fd) {
            eprintln!("production ActionHeritage pass 1 failed: {err:?}");
            std::process::exit(1);
        }
        let mut pass1 = String::new();
        let pass1count = g.project_indirects(&mut pass1);
        if let Err(err) = heritage_action.apply(&mut g.fd) {
            eprintln!("production ActionHeritage pass 2 failed: {err:?}");
            std::process::exit(1);
        }
        let mut pass2 = String::new();
        let pass2count = g.project_indirects(&mut pass2);
        let stable = if pass1 == pass2 { 1 } else { 0 };
        let mut out = String::new();
        out.push_str(&format!(
            "case=production_second_pass_inert|pass1count={pass1count}|pass2count={pass2count}|pass2new={}{}",
            pass2count as i64 - pass1count as i64,
            format!("|stable={stable}")
        ));
        println!("{out}");
    }

    // case=stack_translation: the spacebase half. Stack ranges are delayed
    // one pass (SpacebaseSpace delay=1), so pass 1 guards nothing; pass 2
    // queries caller stack(0x18,8) as callee stack(0x8,8):
    //   fc0 (stack offset 0x10) -> killedbycall -> creation at S0x18
    //   fc1 (offset unknown)    -> unknown_effect -> plain INDIRECT at
    //     S0x18 and no trial registration (tryregister == false)
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
        {
            let mut fc = g.fd.callspecs[0].write().unwrap();
            fc.stackoffset = 0x10;
        }
        g.prepare_structure();
        g.fd.op_heritage();
        let mut pass1 = String::new();
        let pass1count = g.project_indirects(&mut pass1);
        g.fd.op_heritage();
        let mut guards = String::new();
        let count = g.project_indirects(&mut guards);
        let mut out = String::new();
        out.push_str(&format!(
            "case=stack_translation|pass1count={pass1count}|guards={guards}|count={count}"
        ));
        println!("{out}");
    }
}
