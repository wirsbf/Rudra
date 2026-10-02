//! Locked Ghidra 12.0.4 ActionDirectWrite collection oracle companion
//! (ACTIONDW-COPYDEF-MARKING-0001).
//!
//! Mirrors tests/oracle/actiondw_copydef_1204.cc case-for-case and emits the
//! same `case=|reg=|stage=|result=|pip=[...]|varnodes=[...]` records.  The
//! FuncProto model comes from the production cspec parse (the
//! worker_architecture path of examples/curl_decompile.rs) so the
//! cc:1368 possibleInputParam branch runs against the real
//! locked x86-64-gcc prototype model, exactly like the Ghidra side.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::FlowBlock;
use rudra::coreaction::ActionDirectWrite;
use rudra::funcdata::Funcdata;
use rudra::fspec::VarnodeData;
use rudra::op::{pcodeop_flags, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::{varnode_flags, Varnode};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

// FUNCPROTO-MODEL-BIND-0001: worker-local Architecture built from the locked
// production compiler spec (copied from examples/curl_decompile.rs).
const SPEC_UNIQUE_INJECT_BASE: u64 = 0x364_400;
const SPEC_SPACES: [(&str, u64); 9] = [
    ("const", u64::MAX),
    ("OTHER", u64::MAX),
    ("unique", 0xffff_ffff),
    ("ram", u64::MAX),
    ("register", 0xffff_ffff),
    ("fspec", u64::MAX),
    ("iop", u64::MAX),
    ("join", 0xffff_ffff),
    ("stack", u64::MAX),
];

fn spec_space_by_name(name: &str) -> Option<AddressSpace> {
    match name {
        "ram" => Some(AddressSpace::Ram),
        "stack" => Some(AddressSpace::Stack),
        "register" => Some(AddressSpace::Register),
        "OTHER" | "other" => Some(AddressSpace::Other(1)),
        "unique" => Some(AddressSpace::Unique),
        "const" => Some(AddressSpace::Const),
        _ => None,
    }
}

struct WorkerSpecHost {
    registers: HashMap<String, VarnodeData>,
}

impl rudra::arch::SpecQuery for WorkerSpecHost {
    fn get_register(&self, name: &str) -> Option<VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<AddressSpace> {
        spec_space_by_name(name)
    }
    fn space_highest(&self, spc: AddressSpace) -> u64 {
        let name = match spc {
            AddressSpace::Const => "const",
            AddressSpace::Other(_) => "OTHER",
            AddressSpace::Unique => "unique",
            AddressSpace::Ram => "ram",
            AddressSpace::Register => "register",
            AddressSpace::Stack => "stack",
            AddressSpace::Iop => "iop",
            AddressSpace::Join => "join",
            AddressSpace::Overlay => "OTHER",
        };
        SPEC_SPACES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        SPEC_UNIQUE_INJECT_BASE
    }
}

impl rudra::pcodeparse::SleighSymbolLookup for WorkerSpecHost {
    fn find_symbol(&self, name: &str) -> Option<rudra::pcodeparse::SleighSymbol> {
        self.registers.get(name).map(|vd| rudra::pcodeparse::SleighSymbol {
            name: name.to_string(),
            kind: rudra::pcodeparse::SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                space: vd.space,
                offset: vd.offset,
                size: vd.size.max(0) as usize,
            }),
        })
    }
}

fn fixture_architecture() -> Result<Arc<Architecture>, String> {
    let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
        .map_err(|error| format!("unable to read compiler spec: {error}"))?;
    let sleigh = rudra::sleigh_ffi::SleighCtx::new()
        .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
    let mut registers = HashMap::new();
    for index in 0..sleigh.num_registers() {
        let Some((name, space, offset, size)) = sleigh.register_info(index) else {
            continue;
        };
        let Ok(space_id) = u8::try_from(space) else {
            continue;
        };
        registers.insert(
            name.to_string(),
            VarnodeData {
                space: AddressSpace::from_id(space_id),
                offset,
                size,
            },
        );
    }
    let host = Arc::new(WorkerSpecHost { registers });
    let mut store = rudra::marshal::DocumentStorage::new();
    let doc = store
        .parse_document(&cspec_bytes)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    let root = doc
        .root
        .clone()
        .ok_or_else(|| "compiler spec has no root element".to_string())?;
    if root
        .read()
        .map_err(|_| "compiler spec element lock poisoned".to_string())?
        .name
        != "compiler_spec"
    {
        return Err("compiler spec root is not compiler_spec".to_string());
    }
    store.register_tag(&root);
    let mut arch = Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    arch.set_commentdb(Arc::new(RwLock::new(rudra::comment::CommentDatabaseInternal::new())));
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(SPEC_UNIQUE_INJECT_BASE);
    inject_lib.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(Arc::new(RwLock::new(inject_lib)));
    arch.userops = Some(Arc::new(RwLock::new(rudra::userop::UserOpManage::new())));
    let pspec_bytes = fs::read("sleigh_specs/x86-64.pspec")
        .map_err(|error| format!("unable to read processor spec: {error}"))?;
    let pspec_doc = store
        .parse_document(&pspec_bytes)
        .map_err(|error| format!("processor spec parse failed: {error}"))?;
    let pspec_root = pspec_doc
        .root
        .clone()
        .ok_or_else(|| "processor spec has no root element".to_string())?;
    if pspec_root
        .read()
        .map_err(|_| "processor spec element lock poisoned".to_string())?
        .name
        != "processor_spec"
    {
        return Err("processor spec root is not processor_spec".to_string());
    }
    let pspec_children: Vec<_> = pspec_root
        .read()
        .map_err(|_| "processor spec element lock poisoned".to_string())?
        .children
        .clone();
    let pspec_registry = Arc::new(RwLock::new(rudra::marshal::IdRegistry::new()));
    for child in pspec_children {
        let child_name = child
            .read()
            .map_err(|_| "processor spec element lock poisoned".to_string())?
            .name
            .clone();
        if child_name != "context_data" {
            continue;
        }
        let mut decoder = rudra::marshal::TreeDecoder::new(child, pspec_registry.clone());
        arch.decode_context_data(&mut decoder, host.as_ref())
            .map_err(|error| format!("processor spec context_data decode failed: {error}"))?;
    }
    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    if arch.defaultfp.is_none() {
        return Err("No default prototype specified".to_string());
    }
    Ok(Arc::new(arch))
}

struct Fixture {
    fd: Funcdata,
    blocks: Vec<BlockRef>,
    block_names: HashMap<usize, String>,
    ops: Vec<PcodeOpRef>,
    op_names: HashMap<usize, String>,
    varnodes: Vec<VarnodeRef>,
    varnode_names: HashMap<usize, String>,
}

impl Fixture {
    fn new(fd: Funcdata) -> Self {
        Self {
            fd,
            blocks: Vec::new(),
            block_names: HashMap::new(),
            ops: Vec::new(),
            op_names: HashMap::new(),
            varnodes: Vec::new(),
            varnode_names: HashMap::new(),
        }
    }

    fn block_key(block: &BlockRef) -> usize {
        Arc::as_ptr(block) as *const () as usize
    }

    fn op_arc_key(op: &Arc<RwLock<rudra::op::PcodeOp>>) -> usize {
        Arc::as_ptr(op) as usize
    }

    fn op_key(op: &PcodeOpRef) -> usize {
        Arc::as_ptr(&op.0) as usize
    }

    fn varnode_key(vn: &VarnodeRef) -> usize {
        Arc::as_ptr(vn) as usize
    }

    fn op_arc_name(&self, op: &Arc<RwLock<rudra::op::PcodeOp>>) -> &str {
        self.op_names
            .get(&Self::op_arc_key(op))
            .expect("registered operation")
    }

    fn varnode_name(&self, vn: &VarnodeRef) -> &str {
        self.varnode_names
            .get(&Self::varnode_key(vn))
            .expect("registered varnode")
    }

    fn remember_op(&mut self, op: PcodeOpRef, name: &str) {
        let key = Self::op_key(&op);
        if self.op_names.insert(key, name.to_string()).is_none() {
            self.ops.push(op);
        }
    }

    fn remember_varnode(&mut self, vn: VarnodeRef, name: &str) {
        let key = Self::varnode_key(&vn);
        if self.varnode_names.insert(key, name.to_string()).is_none() {
            self.varnodes.push(vn);
        }
    }

    fn make_block(&mut self, name: &str) -> BlockRef {
        let block = self.fd.create_new_block();
        self.block_names
            .insert(Self::block_key(&block), name.to_string());
        self.blocks.push(block.clone());
        block
    }

    fn make_input(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        let vn = self.fd.set_input_varnode(vn);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_free(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_constant(&mut self, name: &str, size: usize, value: u64) -> VarnodeRef {
        let vn = self.fd.new_constant(size, value);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_op(&mut self, name: &str, opcode: OpCode, inputs: usize, output_size: usize) -> PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(0x4c20));
        self.fd.op_set_opcode(&op, opcode);
        self.remember_op(op.clone(), name);
        if output_size != 0 {
            let output = self.fd.new_unique_out(output_size, &op);
            self.remember_varnode(output, &format!("{name}_out"));
        }
        op
    }

    // Construct an op whose output lives at an explicit register address, so
    // INDIRECT in/out address-change cases (cc:1403) are observable.
    fn make_op_at(&mut self, name: &str, opcode: OpCode, inputs: usize, out_offset: u64) -> PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(0x4c20));
        self.fd.op_set_opcode(&op, opcode);
        self.remember_op(op.clone(), name);
        let out = self
            .fd
            .vbank
            .create_with_space(8, AddressSpace::Register, out_offset);
        self.fd.op_set_output(&op, out.clone());
        self.remember_varnode(out, &format!("{name}_out"));
        op
    }

    fn make_iop(&mut self, name: &str, op: &PcodeOpRef) -> VarnodeRef {
        let vn = self.fd.new_varnode_iop(op);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn output(op: &PcodeOpRef) -> VarnodeRef {
        op.0
            .read()
            .unwrap()
            .output
            .clone()
            .expect("fixture output")
    }

    fn set_input(&mut self, op: &PcodeOpRef, vn: VarnodeRef, slot: usize) {
        self.fd.op_set_input(op, vn, slot);
    }

    fn insert_end(&mut self, op: &PcodeOpRef, block: &BlockRef) {
        self.fd.op_insert_end(op, block);
    }

    fn set_persist(&self, vn: &VarnodeRef) {
        vn.write().unwrap().flags |= varnode_flags::PERSIST;
    }

    fn set_spacebase(&self, vn: &VarnodeRef) {
        vn.write().unwrap().flags |= varnode_flags::SPACEBASE;
    }

    fn set_indirect_creation(&self, vn: &VarnodeRef) {
        vn.write().unwrap().flags |= varnode_flags::INDIRECT_CREATION;
    }

    fn set_stack_store(&self, vn: &VarnodeRef) {
        vn.write().unwrap().set_stack_store();
    }

    fn set_indirect_store(&self, op: &PcodeOpRef) {
        op.0.write().unwrap().flags |= pcodeop_flags::INDIRECT_STORE;
    }

    fn space_name(space: AddressSpace) -> &'static str {
        match space {
            AddressSpace::Const => "const",
            AddressSpace::Register => "register",
            AddressSpace::Stack => "stack",
            AddressSpace::Unique => "unique",
            AddressSpace::Iop => "iop",
            AddressSpace::Join => "join",
            AddressSpace::Ram => "ram",
            _ => "other",
        }
    }

    fn live_varnodes(&self) -> HashSet<usize> {
        self.fd
            .vbank
            .loc_tree
            .iter()
            .map(|vn| Self::varnode_key(&vn.0))
            .collect()
    }

    fn varnode_state(&self, vn: &VarnodeRef, live: &HashSet<usize>) -> String {
        if !live.contains(&Self::varnode_key(vn)) {
            return format!("{}{{present=0}}", self.varnode_name(vn));
        }
        let guard = vn.read().unwrap();
        let def = guard
            .get_def()
            .map(|op| self.op_arc_name(&op).to_string())
            .unwrap_or_else(|| "-".to_string());
        let mut occurrences: HashMap<usize, usize> = HashMap::new();
        let descendants = guard
            .descend
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(|op| {
                let key = Self::op_arc_key(&op);
                let occurrence = occurrences.entry(key).or_insert(0);
                let slot = {
                    let op_guard = op.read().unwrap();
                    op_guard
                        .inrefs
                        .iter()
                        .enumerate()
                        .filter(|(_, input)| Arc::ptr_eq(input, vn))
                        .nth(*occurrence)
                        .map(|(slot, _)| slot)
                        .expect("descendant input occurrence")
                };
                *occurrence += 1;
                format!("{}.{}", self.op_arc_name(&op), slot)
            })
            .collect::<Vec<_>>()
            .join(",");
        // The iop-space offset encodes the referenced PcodeOp's process
        // pointer (new_varnode_iop).  Render it as the referenced op's
        // fixture name on both sides — a stable semantic identity with zero
        // information loss for this action (ActionDirectWrite never reads
        // iop offsets).
        let offset_display = if guard.address_space == AddressSpace::Iop {
            self.op_names
                .get(&(guard.get_offset() as usize))
                .cloned()
                .unwrap_or_else(|| "-".to_string())
        } else {
            format!("{:x}", guard.get_offset())
        };
        format!(
            "{}{{present=1,space={},size={},offset={},flags={:x},input={},written={},persist={},dw={},ss={},def={},desc=[{}]}}",
            self.varnode_name(vn),
            Self::space_name(guard.address_space),
            guard.get_size(),
            offset_display,
            guard.flags,
            u8::from(guard.is_input()),
            u8::from(guard.is_written()),
            u8::from(guard.is_persist()),
            u8::from(guard.is_direct_write()),
            u8::from(guard.is_stack_store()),
            def,
            descendants,
        )
    }

    fn pip_state(&self, probe: &[VarnodeRef]) -> String {
        probe
            .iter()
            .map(|vn| {
                let guard = vn.read().unwrap();
                format!(
                    "{}:{}",
                    self.varnode_name(vn),
                    u8::from(self.fd.funcp.possible_input_param(
                        guard.get_offset(),
                        guard.get_size() as i32,
                        guard.get_space()
                    ))
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn op_state(&self, op: &PcodeOpRef) -> String {
        let guard = op.0.read().unwrap();
        let inputs = guard
            .inrefs
            .iter()
            .map(|vn| self.varnode_name(vn).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let output = guard
            .output
            .as_ref()
            .map(|vn| self.varnode_name(vn).to_string())
            .unwrap_or_else(|| "-".to_string());
        format!(
            "{}{{opc={},marker={},istore={},nin={},inputs=[{}],output={}}}",
            self.op_names
                .get(&Self::op_key(op))
                .expect("registered operation"),
            guard.opcode as i32,
            u8::from(guard.is_marker()),
            u8::from(guard.is_indirect_store()),
            guard.inrefs.len(),
            inputs,
            output,
        )
    }

    fn dump(&self, case_name: &str, reg: &str, stage: &str, result: i32, probe: &[VarnodeRef]) {
        let live_varnodes = self.live_varnodes();
        let varnode_states = self
            .varnodes
            .iter()
            .map(|vn| self.varnode_state(vn, &live_varnodes))
            .collect::<Vec<_>>()
            .join(";");
        let op_states = self
            .ops
            .iter()
            .map(|op| self.op_state(op))
            .collect::<Vec<_>>()
            .join(";");
        println!(
            "case={case_name}|reg={reg}|stage={stage}|result={result}|pip=[{}]|ops=[{}]|varnodes=[{}]",
            self.pip_state(probe),
            op_states,
            varnode_states,
        );
    }
}

fn prepare(fd: &mut Funcdata) {
    fd.clear();
    if !fd.funcp.parameters.is_empty() {
        panic!("fixture requires an unlocked zero-param FuncProto");
    }
}

fn apply_and_dump(fixture: &mut Fixture, name: &str, propagate: bool, probe: &[VarnodeRef]) {
    let reg = if propagate { "a" } else { "b" };
    fixture.dump(name, reg, "before", -1, probe);
    let mut action = ActionDirectWrite::new(propagate);
    let result = action.apply(&mut fixture.fd).expect("apply");
    fixture.dump(name, reg, "after", result, probe);
}

// cc:1368 possibleInputParam input branch + cc:1381 plain COPY defs.
fn run_param_inputs(fd: Funcdata) -> Funcdata {
    let mut fd = fd;
    prepare(&mut fd);
    let mut f = Fixture::new(fd);
    let block = f.make_block("b0");
    let rdi = f.make_input("rdi", 8, 0x38); // x86-64 gcc param register
    let r10 = f.make_input("r10", 8, 0x50); // not a param register
    // NOTE: the spacebase flag is planted on r11 rather than the real RSP
    // (register 0x20) because Ghidra's Funcdata::setInputVarnode tail
    // (funcdata_varnode.cc:365-367) derives `unaffected` from the model
    // effectlist for RSP — a bank-level input-state derivation Rugra has
    // not ported.  ActionDirectWrite reads only the flag (cc:1364), so
    // planting it on a register whose input state is otherwise identical on
    // both sides keeps the fixture a strict same-input comparison.
    let r11 = f.make_input("r11", 8, 0x58);
    f.set_spacebase(&r11);
    let t = f.make_op("t", OpCode::CPUI_COPY, 1, 8); // COPY of unmarked input
    f.set_input(&t, r10.clone(), 0);
    let t2 = f.make_op("t2", OpCode::CPUI_COPY, 1, 8); // COPY of a marked param
    f.set_input(&t2, rdi.clone(), 0);
    f.insert_end(&t, &block);
    f.insert_end(&t2, &block);
    let probe = vec![rdi.clone(), r10.clone(), r11.clone()];
    apply_and_dump(&mut f, "param_inputs", true, &probe);
    apply_and_dump(&mut f, "param_inputs", false, &probe);
    f.fd
}

// cc:1382-1393 isStackStore COPY-source trace (single-level unroll).
fn run_stackstore_trace(fd: Funcdata) -> Funcdata {
    let mut fd = fd;
    prepare(&mut fd);
    let mut f = Fixture::new(fd);
    let block = f.make_block("b0");
    let srcfree = f.make_free("srcfree", 8, 0x60);
    let five = f.make_constant("five", 8, 5);
    let ind = f.make_op("ind", OpCode::CPUI_INDIRECT, 2, 8);
    let iop = f.make_iop("ind_iop", &ind);
    f.set_input(&ind, srcfree, 0);
    f.set_input(&ind, iop, 1);
    let ind_out = Fixture::output(&ind);
    let c1 = f.make_op("c1", OpCode::CPUI_COPY, 1, 8); // one COPY hop to the marker
    f.set_input(&c1, ind_out.clone(), 0);
    let ss = f.make_op("ss", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&ss, Fixture::output(&c1), 0);
    f.set_stack_store(&Fixture::output(&ss));
    let use_op = f.make_op("use", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&use_op, Fixture::output(&ss), 0);
    let c2 = f.make_op("c2", OpCode::CPUI_COPY, 1, 8); // two COPY hops: too deep
    f.set_input(&c2, ind_out, 0);
    let c3 = f.make_op("c3", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&c3, Fixture::output(&c2), 0);
    let ss2 = f.make_op("ss2", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&ss2, Fixture::output(&c3), 0);
    f.set_stack_store(&Fixture::output(&ss2));
    let srcfree2 = f.make_free("srcfree2", 8, 0x68);
    let ssn = f.make_op("ssn", OpCode::CPUI_COPY, 1, 8); // stack store of unwritten src
    f.set_input(&ssn, srcfree2, 0);
    f.set_stack_store(&Fixture::output(&ssn));
    let d1 = f.make_op("d1", OpCode::CPUI_COPY, 1, 8); // plain COPY of a marker out
    f.set_input(&d1, Fixture::output(&ind), 0);
    let k = f.make_op("k", OpCode::CPUI_COPY, 1, 8); // stack store of a constant
    f.set_input(&k, five, 0);
    f.set_stack_store(&Fixture::output(&k));
    f.insert_end(&ind, &block);
    f.insert_end(&c1, &block);
    f.insert_end(&ss, &block);
    f.insert_end(&use_op, &block);
    f.insert_end(&c2, &block);
    f.insert_end(&c3, &block);
    f.insert_end(&ss2, &block);
    f.insert_end(&ssn, &block);
    f.insert_end(&d1, &block);
    f.insert_end(&k, &block);
    let probe = Vec::new();
    apply_and_dump(&mut f, "stackstore_trace", true, &probe);
    apply_and_dump(&mut f, "stackstore_trace", false, &probe);
    f.fd
}

// cc:1401-1408 marker(INDIRECT) collection branch (a/b discriminating).
fn run_indirect_marker(fd: Funcdata) -> Funcdata {
    let mut fd = fd;
    prepare(&mut fd);
    let mut f = Fixture::new(fd);
    let block = f.make_block("b0");
    let ia_in = f.make_free("ia_in", 8, 0x70);
    let mma = f.make_free("mma", 8, 0xa0);
    let mmb = f.make_free("mmb", 8, 0xa4);
    let pwin = f.make_free("pwin", 8, 0xa8);
    let pw2n = f.make_free("pw2n", 8, 0xac);
    let iaddr = f.make_op_at("iaddr", OpCode::CPUI_INDIRECT, 2, 0x78); // addr changes
    let iop1 = f.make_iop("iaddr_iop", &iaddr);
    f.set_input(&iaddr, ia_in, 0);
    f.set_input(&iaddr, iop1, 1);
    let use_i = f.make_op("use_i", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&use_i, Fixture::output(&iaddr), 0);
    let is_in = f.make_free("is_in", 8, 0x80);
    let isame = f.make_op_at("isame", OpCode::CPUI_INDIRECT, 2, 0x80); // addr stable
    let iop2 = f.make_iop("isame_iop", &isame);
    f.set_input(&isame, is_in, 0);
    f.set_input(&isame, iop2, 1);
    let ip_in = f.make_free("ip_in", 8, 0x84);
    let ipersist = f.make_op_at("ipersist", OpCode::CPUI_INDIRECT, 2, 0x84); // persist out
    let iop3 = f.make_iop("ipersist_iop", &ipersist);
    f.set_input(&ipersist, ip_in, 0);
    f.set_input(&ipersist, iop3, 1);
    f.set_persist(&Fixture::output(&ipersist));
    let mm = f.make_op("mm", OpCode::CPUI_MULTIEQUAL, 2, 8); // marker, not INDIRECT
    f.set_input(&mm, mma, 0);
    f.set_input(&mm, mmb, 1);
    let pw = f.make_op("pw", OpCode::CPUI_INT_ADD, 2, 8); // persist + non-marker def
    f.set_input(&pw, pwin, 0);
    f.set_input(&pw, pw2n, 1);
    f.set_persist(&Fixture::output(&pw));
    f.insert_end(&iaddr, &block);
    f.insert_end(&use_i, &block);
    f.insert_end(&isame, &block);
    f.insert_end(&ipersist, &block);
    f.insert_end(&mm, &block);
    f.insert_end(&pw, &block);
    let probe = Vec::new();
    apply_and_dump(&mut f, "indirect_marker", true, &probe);
    apply_and_dump(&mut f, "indirect_marker", false, &probe);
    f.fd
}

// cc:1427-1429 phase-2 push gate through call-based INDIRECTs.
fn run_phase2_push(fd: Funcdata) -> Funcdata {
    let mut fd = fd;
    prepare(&mut fd);
    let mut f = Fixture::new(fd);
    let block = f.make_block("b0");
    let seven = f.make_constant("seven", 8, 7);
    let seven2 = f.make_constant("seven2", 8, 7);
    let eight = f.make_constant("eight", 8, 8);
    let x = f.make_op("x", OpCode::CPUI_INDIRECT, 2, 8); // call-based, no store flag
    let iopx = f.make_iop("x_iop", &x);
    f.set_input(&x, seven, 0);
    f.set_input(&x, iopx, 1);
    let y = f.make_op("y", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&y, Fixture::output(&x), 0);
    let z = f.make_op("z", OpCode::CPUI_INDIRECT, 2, 8); // indirect STORE variant
    let iopz = f.make_iop("z_iop", &z);
    f.set_input(&z, eight, 0);
    f.set_input(&z, iopz, 1);
    f.set_indirect_store(&z);
    let w = f.make_op("w", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&w, Fixture::output(&z), 0);
    let n = f.make_op("n", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&n, seven2, 0);
    f.insert_end(&x, &block);
    f.insert_end(&y, &block);
    f.insert_end(&z, &block);
    f.insert_end(&w, &block);
    f.insert_end(&n, &block);
    let probe = Vec::new();
    apply_and_dump(&mut f, "phase2_push", true, &probe);
    apply_and_dump(&mut f, "phase2_push", false, &probe);
    f.fd
}

// cc:1395-1399 non-COPY exclusions + cc:1410-1414 constant branches.
fn run_noncopy_defs(fd: Funcdata) -> Funcdata {
    let mut fd = fd;
    prepare(&mut fd);
    let mut f = Fixture::new(fd);
    let block = f.make_block("b0");
    let hi = f.make_free("hi", 4, 0x90);
    let lo = f.make_free("lo", 4, 0x94);
    let f1 = f.make_free("f1", 8, 0x98);
    let f2 = f.make_free("f2", 8, 0x9c);
    let subin = f.make_free("subin", 8, 0xb0);
    let one = f.make_constant("one", 8, 1);
    let piece = f.make_op("piece", OpCode::CPUI_PIECE, 2, 8);
    f.set_input(&piece, hi.clone(), 0);
    f.set_input(&piece, lo.clone(), 1);
    let sub = f.make_op("sub", OpCode::CPUI_SUBPIECE, 2, 4);
    f.set_input(&sub, subin, 0);
    f.set_input(&sub, one, 1);
    let ad = f.make_op("ad", OpCode::CPUI_INT_ADD, 2, 8);
    f.set_input(&ad, f1, 0);
    f.set_input(&ad, f2, 1);
    let mul = f.make_op("mul", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&mul, Fixture::output(&ad), 0);
    let iz = f.make_constant("iz", 8, 0);
    f.set_indirect_creation(&iz);
    f.insert_end(&piece, &block);
    f.insert_end(&sub, &block);
    f.insert_end(&ad, &block);
    f.insert_end(&mul, &block);
    let probe = vec![hi.clone(), lo.clone()];
    apply_and_dump(&mut f, "noncopy_defs", true, &probe);
    apply_and_dump(&mut f, "noncopy_defs", false, &probe);
    f.fd
}

// cc:1428 isIndirectStore push leg: an INDIRECT with equal in/out addresses
// (no ④ mark under b) whose output is tainted from a persist input — the
// w2 COPY can only be marked under the b registration via the store leg.
fn run_indirect_store_push(fd: Funcdata) -> Funcdata {
    let mut fd = fd;
    prepare(&mut fd);
    let mut f = Fixture::new(fd);
    let block = f.make_block("b0");
    // 0xe0 is outside both the model's unaffected set (callee-saved regs)
    // and its input-param entries, so the bank-level input state is
    // identical on both sides (see the r11 note in run_param_inputs).
    let at: u64 = 0xe0;
    let iszin = f.make_input("iszin", 8, at);
    f.set_persist(&iszin);
    let isz = f.make_op_at("isz", OpCode::CPUI_INDIRECT, 2, at); // equal addresses
    let iop4 = f.make_iop("isz_iop", &isz);
    f.set_input(&isz, iszin, 0);
    f.set_input(&isz, iop4, 1);
    f.set_indirect_store(&isz);
    let w2 = f.make_op("w2", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&w2, Fixture::output(&isz), 0);
    f.insert_end(&isz, &block);
    f.insert_end(&w2, &block);
    let probe = Vec::new();
    apply_and_dump(&mut f, "indirect_store_push", true, &probe);
    apply_and_dump(&mut f, "indirect_store_push", false, &probe);
    f.fd
}

// fspec.cc:4369 voidinputlock gate.  Runs last: setInputLock(true) also
// latches modellock (fspec.cc:3925), which possibleInputParam ignores.
fn run_void_input_lock(fd: Funcdata) -> Funcdata {
    let mut fd = fd;
    prepare(&mut fd);
    fd.funcp.void_input_locked = true;
    fd.funcp.set_model_lock(true);
    let mut f = Fixture::new(fd);
    let block = f.make_block("b0");
    let rdi = f.make_input("rdi", 8, 0x38);
    let v = f.make_op("v", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&v, rdi.clone(), 0);
    f.insert_end(&v, &block);
    let probe = vec![rdi.clone()];
    apply_and_dump(&mut f, "void_input_lock", true, &probe);
    apply_and_dump(&mut f, "void_input_lock", false, &probe);
    f.fd.funcp.void_input_locked = false;
    f.fd
}

fn main() {
    let arch = fixture_architecture().expect("fixture architecture");
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    fd.heritage.build_info_list();
    fd.set_arch(arch);

    let fd = run_param_inputs(fd);
    let fd = run_stackstore_trace(fd);
    let fd = run_indirect_marker(fd);
    let fd = run_phase2_push(fd);
    let fd = run_indirect_store_push(fd);
    let fd = run_noncopy_defs(fd);
    let _fd = run_void_input_lock(fd);
}
