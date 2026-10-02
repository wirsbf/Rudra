//! JT-THUNK-CLASSIFY-1204 (JUMPTABLE-THUNK-CLASSIFY-0001) Rugra comparand.
//!
//! Mirrors `tests/oracle/jt_thunk_classify_1204.cc` case for case against the
//! locked Ghidra 12.0.4 oracle.  The fixture observes the strict single-target
//! thunk boundary, override/reachability ordering, exact typed error text, and
//! all address/load/partial mutations visible at the error boundary.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::FlowBlock;
use rudra::comment::CommentDatabaseInternal;
use rudra::funcdata::Funcdata;
use rudra::jumptable::{JumpModel, JumpTable, JumpTableRecoveryError, LoadTable, RecoveryMode};
use rudra::marshal::{xml_tree, IdRegistry, TreeDecoder};
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::space::{AddrSpace, AddressSpace, SpaceType};
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

struct ModelState {
    recover_calls: AtomicI32,
    build_calls: AtomicI32,
    sanity_calls: AtomicI32,
    build_loads_present: AtomicI32,
    build_counts_present: AtomicI32,
    observed_loadcounts: Mutex<Vec<i32>>,
    events: Mutex<Vec<&'static str>>,
}

impl Default for ModelState {
    fn default() -> Self {
        Self {
            recover_calls: AtomicI32::new(0),
            build_calls: AtomicI32::new(0),
            sanity_calls: AtomicI32::new(0),
            build_loads_present: AtomicI32::new(-1),
            build_counts_present: AtomicI32::new(-1),
            observed_loadcounts: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
        }
    }
}

struct FixtureModel {
    override_mode: bool,
    transient_override: bool,
    sanity_result: bool,
    mutate_during_sanity: bool,
    reject_load_address: Address,
    build_targets: Vec<Address>,
    build_loads: Vec<LoadTable>,
    state: Arc<ModelState>,
}

impl JumpModel for FixtureModel {
    fn is_override(&self) -> bool {
        self.override_mode
            || (self.transient_override && self.state.recover_calls.load(Ordering::Relaxed) == 0)
    }

    fn get_table_size(&self) -> usize {
        self.build_targets.len()
    }

    fn recover_model(
        &mut self,
        _fd: &Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        _matchsize: u32,
        _maxtablesize: u32,
    ) -> Result<bool, JumpTableRecoveryError> {
        // C++ double cannot throw from recoverModel; the Result channel is
        // JUMPTABLE-PIPELINE-0001's typed LowlevelError carrier and stays
        // silent here, matching the oracle double's plain `return true`.
        self.state.recover_calls.fetch_add(1, Ordering::Relaxed);
        self.state.events.lock().unwrap().push("recover");
        Ok(true)
    }

    fn build_addresses(
        &self,
        _fd: &Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: Option<&mut Vec<LoadTable>>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> Result<(), JumpTableRecoveryError> {
        self.state.build_calls.fetch_add(1, Ordering::Relaxed);
        self.state.events.lock().unwrap().push("build");
        *addresstable = self.build_targets.clone();

        self.state
            .build_loads_present
            .store(i32::from(loadpoints.is_some()), Ordering::Relaxed);
        self.state
            .build_counts_present
            .store(i32::from(loadcounts.is_some()), Ordering::Relaxed);
        let count = if let Some(loadpoints) = loadpoints {
            loadpoints.extend(self.build_loads.iter().cloned());
            loadpoints.len() as i32
        } else {
            0
        };
        if let Some(loadcounts) = loadcounts {
            loadcounts.extend(std::iter::repeat_n(count, self.build_targets.len()));
            *self.state.observed_loadcounts.lock().unwrap() = loadcounts.clone();
        }
        Ok(())
    }

    fn find_unnormalized(&mut self, _maxaddsub: u32, _maxleftright: u32, _maxext: u32) {}

    fn build_labels(
        &self,
        _fd: &Funcdata,
        _addresstable: &[Address],
        _label: &mut Vec<u64>,
        _orig: &dyn JumpModel,
    ) {
    }

    fn fold_in_normalization(
        &mut self,
        _fd: &mut Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
    ) -> Option<Arc<RwLock<Varnode>>> {
        None
    }

    fn fold_in_guards(&mut self, _fd: &mut Funcdata, _jump: &mut JumpTable) -> bool {
        false
    }

    fn sanity_check(
        &mut self,
        _fd: &Funcdata,
        _indop: &Arc<RwLock<PcodeOp>>,
        addresstable: &mut Vec<Address>,
        loadpoints: &mut Vec<LoadTable>,
        loadcounts: Option<&mut Vec<i32>>,
    ) -> bool {
        self.state.sanity_calls.fetch_add(1, Ordering::Relaxed);
        self.state.events.lock().unwrap().push("sanity");
        if self.mutate_during_sanity {
            if addresstable.len() > 1 {
                addresstable.truncate(1);
            }
            loadpoints.push(LoadTable::single(self.reject_load_address, 4));
            if let Some(loadcounts) = loadcounts {
                loadcounts.push(7);
                *self.state.observed_loadcounts.lock().unwrap() = loadcounts.clone();
            }
        } else if let Some(loadcounts) = loadcounts {
            *self.state.observed_loadcounts.lock().unwrap() = loadcounts.clone();
        }
        self.sanity_result
    }

    fn clone_model(&self, _jt: Arc<RwLock<JumpTable>>) -> Box<dyn JumpModel> {
        Box::new(Self {
            override_mode: self.override_mode,
            transient_override: self.transient_override,
            sanity_result: self.sanity_result,
            mutate_during_sanity: self.mutate_during_sanity,
            reject_load_address: self.reject_load_address,
            build_targets: self.build_targets.clone(),
            build_loads: self.build_loads.clone(),
            state: self.state.clone(),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReachVariant {
    None,
    False,
    TwoLevel,
    Flip,
    Nonzero,
    SizeOut,
    NonCbranch,
    Nonconstant,
}

#[derive(Clone, Copy)]
enum LoadVariant {
    Default,
    EqualThree,
    EqualSixteen,
    EqualSeventeen,
    EqualThirtyTwo,
    Wrap,
    MultiSpace,
}

struct CaseConfig {
    id: &'static str,
    target_offsets: Vec<u64>,
    reach: ReachVariant,
    override_mode: bool,
    sanity_result: bool,
    mutate_during_sanity: bool,
    drive_recover: bool,
    collect_loads: bool,
    real_model: bool,
    loads: LoadVariant,
}

fn address_text(address: &Address) -> String {
    let index = address.get_space().map_or(-1, |space| space.get_index());
    format!("{}@{}", index, address)
}

fn addresses_text(addresses: &[Address]) -> String {
    addresses
        .iter()
        .map(address_text)
        .collect::<Vec<_>>()
        .join(",")
}

fn loads_text(loads: &[LoadTable]) -> String {
    loads
        .iter()
        .map(|load| format!("{}/{}/{}", address_text(&load.addr), load.size, load.num))
        .collect::<Vec<_>>()
        .join(",")
}

fn counts_text(counts: &[i32]) -> String {
    counts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn events_text(events: &[&str]) -> String {
    events.join(">")
}

fn add_guard(
    fd: &mut Funcdata,
    code: &AddrSpace,
    parent: &BlockRef,
    op_offset: u64,
    condition: u64,
    flip: bool,
    two_edges: bool,
    cbranch: bool,
    constant: bool,
) -> BlockRef {
    let guard: BlockRef = fd.create_new_block();
    let other: BlockRef = fd.create_new_block();
    if cbranch {
        let op = fd.new_op(2, Address::with_space(code, op_offset));
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, op_offset + 0x40);
        let condition = if constant {
            fd.new_constant(1, condition)
        } else {
            fd.new_unique(1)
        };
        fd.op_set_input(&op, target, 0);
        fd.op_set_input(&op, condition, 1);
        if flip {
            op.0.write().unwrap().flags |= rudra::op::pcodeop_flags::BOOLEAN_FLIP;
        }
        fd.op_insert_end(&op, &guard);
    } else {
        let op = fd.new_op(1, Address::with_space(code, op_offset));
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let input = fd.new_constant(1, condition);
        fd.op_set_input(&op, input, 0);
        fd.op_insert_end(&op, &guard);
    }
    if two_edges {
        fd.bblocks.add_edge(guard.clone(), other);
    }
    fd.bblocks.add_edge(guard.clone(), parent.clone());
    guard
}

fn build_indirect(
    fd: &mut Funcdata,
    code: &AddrSpace,
    reach: ReachVariant,
    op_offset: u64,
) -> rudra::op::PcodeOpRef {
    let switch_block: BlockRef = fd.create_new_block();
    match reach {
        ReachVariant::None => {}
        ReachVariant::False => {
            add_guard(
                fd,
                code,
                &switch_block,
                op_offset - 8,
                0,
                false,
                true,
                true,
                true,
            );
        }
        ReachVariant::TwoLevel => {
            let inner = add_guard(
                fd,
                code,
                &switch_block,
                op_offset - 8,
                1,
                false,
                true,
                true,
                true,
            );
            add_guard(fd, code, &inner, op_offset - 16, 0, false, true, true, true);
        }
        ReachVariant::Flip => {
            add_guard(
                fd,
                code,
                &switch_block,
                op_offset - 8,
                1,
                true,
                true,
                true,
                true,
            );
        }
        ReachVariant::Nonzero => {
            add_guard(
                fd,
                code,
                &switch_block,
                op_offset - 8,
                1,
                false,
                true,
                true,
                true,
            );
        }
        ReachVariant::SizeOut => {
            add_guard(
                fd,
                code,
                &switch_block,
                op_offset - 8,
                0,
                false,
                false,
                true,
                true,
            );
        }
        ReachVariant::NonCbranch => {
            add_guard(
                fd,
                code,
                &switch_block,
                op_offset - 8,
                0,
                false,
                true,
                false,
                true,
            );
        }
        ReachVariant::Nonconstant => {
            add_guard(
                fd,
                code,
                &switch_block,
                op_offset - 8,
                0,
                false,
                true,
                true,
                false,
            );
        }
    }

    let indirect = fd.new_op(1, Address::with_space(code, op_offset));
    fd.op_set_opcode(&indirect, OpCode::CPUI_BRANCHIND);
    let destination = if reach == ReachVariant::None {
        fd.new_unique(4)
    } else {
        fd.new_constant(8, op_offset + 0x20)
    };
    fd.op_set_input(&indirect, destination, 0);
    fd.op_insert_end(&indirect, &switch_block);
    indirect
}

fn build_loads(code: &AddrSpace, tiny: &AddrSpace, variant: LoadVariant) -> Vec<LoadTable> {
    match variant {
        LoadVariant::Default => vec![
            LoadTable::single(Address::with_space(code, 0x3004), 4),
            LoadTable::single(Address::with_space(code, 0x3000), 4),
        ],
        LoadVariant::EqualThree => vec![
            LoadTable::new(Address::with_space(code, 0x4000), 8, 2),
            LoadTable::new(Address::with_space(code, 0x4000), 4, 3),
            LoadTable::new(Address::with_space(code, 0x4010), 8, 1),
        ],
        LoadVariant::EqualSixteen | LoadVariant::EqualSeventeen | LoadVariant::EqualThirtyTwo => {
            let count = match variant {
                LoadVariant::EqualSixteen => 16,
                LoadVariant::EqualSeventeen => 17,
                LoadVariant::EqualThirtyTwo => 32,
                _ => unreachable!(),
            };
            (0..count)
                .map(|index| {
                    LoadTable::single(
                        Address::with_space(code, 0x4000),
                        if index & 1 == 0 { 4 } else { 8 },
                    )
                })
                .collect()
        }
        LoadVariant::Wrap => vec![
            LoadTable::single(Address::with_space(tiny, 0xfc), 4),
            LoadTable::single(Address::with_space(tiny, 0), 4),
        ],
        LoadVariant::MultiSpace => vec![
            LoadTable::single(Address::with_space(tiny, 0), 4),
            LoadTable::single(Address::with_space(code, 0x4000), 4),
            LoadTable::single(Address::with_space(tiny, 4), 4),
            LoadTable::single(Address::with_space(code, 0x4004), 4),
        ],
    }
}

fn run_case(
    code: &AddrSpace,
    tiny: &AddrSpace,
    architecture: &Arc<Architecture>,
    commentdb: &Arc<RwLock<CommentDatabaseInternal>>,
    config: CaseConfig,
) {
    const OP_OFFSET: u64 = 0x100000;
    commentdb.write().unwrap().clear();
    let mut fd = Funcdata::new(config.id, Address::with_space(code, 0x90000), 0x20000);
    fd.set_arch(architecture.clone());
    let indirect = build_indirect(&mut fd, code, config.reach, OP_OFFSET);

    let targets = config
        .target_offsets
        .iter()
        .map(|offset| Address::with_space(code, *offset))
        .collect::<Vec<_>>();
    let initial_loads = build_loads(code, tiny, config.loads);
    let mut loadcounts = vec![1, 2];

    let mut table = JumpTable::new(Address::with_space(code, OP_OFFSET));
    table.set_indirect_op(indirect.0.clone());
    let state = Arc::new(ModelState::default());
    if !config.real_model {
        table.jmodel = Some(Box::new(FixtureModel {
            override_mode: config.override_mode,
            transient_override: config.drive_recover && !config.override_mode,
            sanity_result: config.sanity_result,
            mutate_during_sanity: config.mutate_during_sanity,
            reject_load_address: Address::with_space(code, 0x3008),
            build_targets: targets.clone(),
            build_loads: initial_loads.clone(),
            state: state.clone(),
        }));
    }
    table.addresstable = if config.drive_recover {
        Vec::new()
    } else {
        targets
    };
    table.loadpoints = if config.drive_recover {
        Vec::new()
    } else {
        initial_loads
    };
    table.collect_loads = config.collect_loads;

    let result = if config.drive_recover {
        table.recover_addresses_classified(&fd)
    } else {
        table.sanity_check(&fd, Some(&mut loadcounts))
    };
    if config.drive_recover && config.collect_loads && result.is_ok() {
        state.events.lock().unwrap().push("collapse");
    }
    let (kind, mode, message) = match result {
        Ok(()) => ("success", RecoveryMode::Success, "none".to_string()),
        Err(error @ JumpTableRecoveryError::Thunk { .. }) => {
            ("thunk", error.recovery_mode(), error.message().to_string())
        }
        Err(error @ JumpTableRecoveryError::Lowlevel { .. }) => (
            "lowlevel",
            error.recovery_mode(),
            error.message().to_string(),
        ),
    };

    let observed_counts = if config.drive_recover {
        state.observed_loadcounts.lock().unwrap().clone()
    } else {
        loadcounts
    };
    let events = state.events.lock().unwrap().clone();
    let warning = {
        let database = commentdb.read().unwrap();
        let records = database
            .comments_for_function(*fd.get_address())
            .map(|comment| {
                format!(
                    "{}@{}:{}",
                    comment.get_type(),
                    comment.get_addr(),
                    comment.get_text()
                )
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            "none".to_string()
        } else {
            records.join(",")
        }
    };

    println!(
        "case|id={}|path={}|kind={}|mode={}|msg={}|partial={}|override={}|collect={}|recover_calls={}|build_calls={}|sanity_calls={}|build_loads={}|build_counts={}|events={}|addresses={}|loads={}|loadcounts={}|warning={}",
        config.id,
        if config.drive_recover { "recover" } else { "sanity" },
        kind,
        mode as i32,
        message,
        i32::from(table.partial_table),
        i32::from(table.is_override()),
        i32::from(table.collect_loads),
        state.recover_calls.load(Ordering::Relaxed),
        state.build_calls.load(Ordering::Relaxed),
        state.sanity_calls.load(Ordering::Relaxed),
        state.build_loads_present.load(Ordering::Relaxed),
        state.build_counts_present.load(Ordering::Relaxed),
        events_text(&events),
        addresses_text(&table.addresstable),
        loads_text(&table.loadpoints),
        counts_text(&observed_counts),
        warning,
    );
}

#[allow(clippy::too_many_arguments)]
fn case(
    id: &'static str,
    target_offsets: Vec<u64>,
    reach: ReachVariant,
    override_mode: bool,
    sanity_result: bool,
    mutate_during_sanity: bool,
    drive_recover: bool,
    collect_loads: bool,
    real_model: bool,
    loads: LoadVariant,
) -> CaseConfig {
    CaseConfig {
        id,
        target_offsets,
        reach,
        override_mode,
        sanity_result,
        mutate_during_sanity,
        drive_recover,
        collect_loads,
        real_model,
        loads,
    }
}

fn main() {
    let code = AddrSpace::new_space(SpaceType::Processor, "ram", false, 8, 1, 3, 0, 0, 0);
    let tiny = AddrSpace::new_space(SpaceType::Processor, "tiny", false, 1, 1, 8, 0, 0, 0);
    let commentdb = Arc::new(RwLock::new(CommentDatabaseInternal::new()));
    let mut architecture = Architecture::new();
    architecture.commentdb = Some(commentdb.clone());
    architecture.max_basetype_size = 16;
    architecture.stack_pointer_space = AddressSpace::Register;
    architecture.stack_pointer_offset = 0;
    architecture.stack_pointer_size = 8;
    let prototype_document =
        xml_tree(b"<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>")
            .expect("decode fixture prototype XML");
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut decoder = TreeDecoder::from_document(&prototype_document, registry);
    architecture
        .decode_proto(&mut decoder, 8, &|_| None)
        .expect("decode fixture prototype model");
    architecture.set_default_model("fixture");
    let architecture = Arc::new(architecture);
    const OP: u64 = 0x100000;
    let cases = vec![
        case(
            "zero",
            vec![0],
            ReachVariant::None,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "near",
            vec![OP + 0x20],
            ReachVariant::None,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "cutoff",
            vec![OP + 0xffff],
            ReachVariant::None,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "over",
            vec![OP + 0x10000],
            ReachVariant::None,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "multi",
            vec![0, OP + 0x20000],
            ReachVariant::None,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "partial",
            vec![0],
            ReachVariant::False,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "reach_two",
            vec![0],
            ReachVariant::TwoLevel,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "reach_flip",
            vec![0],
            ReachVariant::Flip,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "reach_nonzero",
            vec![0],
            ReachVariant::Nonzero,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "reach_size_out",
            vec![0],
            ReachVariant::SizeOut,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "reach_non_cbranch",
            vec![0],
            ReachVariant::NonCbranch,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "reach_nonconstant",
            vec![0],
            ReachVariant::Nonconstant,
            false,
            true,
            false,
            false,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "override",
            vec![0],
            ReachVariant::False,
            true,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::Default,
        ),
        case(
            "recover_model_fail",
            vec![],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            true,
            LoadVariant::Default,
        ),
        case(
            "recover_table_zero",
            vec![],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::Default,
        ),
        case(
            "recover_no_collect",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            false,
            false,
            LoadVariant::Default,
        ),
        case(
            "recover_thunk",
            vec![0],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::Default,
        ),
        case(
            "success_truncate",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            true,
            true,
            true,
            true,
            false,
            LoadVariant::Default,
        ),
        case(
            "model_reject",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            false,
            true,
            true,
            true,
            false,
            LoadVariant::Default,
        ),
        case(
            "sort_equal_three",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::EqualThree,
        ),
        case(
            "sort_equal_sixteen",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::EqualSixteen,
        ),
        case(
            "sort_equal_seventeen",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::EqualSeventeen,
        ),
        case(
            "sort_equal_thirtytwo",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::EqualThirtyTwo,
        ),
        case(
            "wrap_one_byte",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::Wrap,
        ),
        case(
            "multi_space",
            vec![OP + 0x10, OP + 0x20],
            ReachVariant::None,
            false,
            true,
            false,
            true,
            true,
            false,
            LoadVariant::MultiSpace,
        ),
    ];

    for config in cases {
        run_case(&code, &tiny, &architecture, &commentdb, config);
    }
}
