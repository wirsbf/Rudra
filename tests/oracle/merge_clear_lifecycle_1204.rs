// MERGE-CLEAR-LIFECYCLE-0001: Rugra comparand for the locked Ghidra 12.0.4
// Funcdata::clear lifecycle oracle.  Mirrors
// tests/oracle/merge_clear_lifecycle_1204.cc domain for domain: one Funcdata
// carrying every persistent-state domain Funcdata::clear (funcdata.cc:84-112)
// touches, observed before and after `fd.clear()`.
//
// Projection status (pinned in metadata.json): every projected line is
// byte-identical to the locked oracle except the two registered MISMATCH
// domains (overall_status=MISMATCH):
//   - localmap after-clear line: Ghidra keeps the typelock+namelock symbol
//     (database.cc:2042-2064 clearUnlocked); Rugra's wholesale
//     `scope.symbols.clear()` model drops it (varmap nametree is
//     index-addressed; a faithful retain needs a varmap.rs-side
//     clearUnlocked) — MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001.
//   - funcproto after-clear line: Ghidra zeroes returnBytesConsumed
//     (fspec.cc:4012); Rugra's fspec.rs clear_unlocked_output is a
//     simplification that leaves it — MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001.
//
// clean_up_index / cast_phase_index are not projected: Rugra has no fields
// (coreaction.rs startCleanUp/ActionSetCasts markers are faithful no-ops) —
// coverage entry UNTESTED under the same residual.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::fspec::{FuncCallSpecs, FuncProto, ParamActive};
use rudra::funcdata::{funcdata_flags, Funcdata, LanedStorage};
use rudra::jumptable::{JumpBasicOverride, JumpTable};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase};
use rudra::type_system::TypeMetatype;
use rudra::unionresolve::{ResolveEdge, ResolvedUnion};
use rudra::varmap::{LocalSymbol, ScopeLocal};

fn int4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "int".to_string(),
        4,
        TypeMetatype::Int,
    )))
}

fn bit_str(name: &str, value: bool) -> String {
    format!("{}:{}", name, if value { 1 } else { 0 })
}

fn make_block(
    fd: &mut Funcdata,
    index: i32,
    base: u64,
) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(index, Address::new(base))));
    fd.bblocks.add_block(block.clone());
    block
}

fn main() {
    let ct4 = int4();

    let mut fd = Funcdata::new("lifecycle", Address::new(0x7000), 0x100);
    // FixtureArchitecture counterpart: one 4-byte laned record so
    // getMinimumLanedRegisterSize (architecture.cc:312) is 4. set_arch also
    // mirrors the Ghidra ctor's minLanedSize assignment (funcdata.cc:49), so
    // the 4-byte register varnodes auto-enter lanedMap exactly like the C++
    // side (checkForLanedRegister, funcdata_varnode.cc:298).
    let mut arch = rudra::arch::Architecture::new();
    let lane_record = Arc::new(rudra::transform::LanedRegister::with_sizes(4, 0xa));
    arch.lane_records.push(lane_record.clone());
    fd.set_arch(Arc::new(arch));

    // --- graph: two COPYs in two blocks
    let b0 = make_block(&mut fd, 0, 0x7000);
    let b1 = make_block(&mut fd, 1, 0x7000);
    fd.bblocks.add_edge(b0.clone(), b1.clone());

    let op1 = fd.new_op(1, Address::new(0x7000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let _vn_p = fd.new_varnode_out(4, Address::new(0x10), &op1);
    let c11 = fd.new_constant(4, 0x11);
    fd.op_insert_input(&op1, c11, 0);
    fd.op_insert_end(&op1, &b0);

    let op2 = fd.new_op(1, Address::new(0x7001));
    fd.op_set_opcode(&op2, OpCode::CPUI_COPY);
    let _vn_q = fd.new_varnode_out(4, Address::new(0x20), &op2);
    let c22 = fd.new_constant(4, 0x22);
    fd.op_insert_input(&op2, c22, 0);
    fd.op_insert_end(&op2, &b1);

    // --- CALL op + callspec
    let callop = fd.new_op(1, Address::new(0x7002));
    fd.op_set_opcode(&callop, OpCode::CPUI_CALL);
    let cdead = fd.new_constant(8, 0xdeadbeef);
    fd.op_insert_input(&callop, cdead, 0);
    fd.op_insert_end(&callop, &b1);
    let spec = FuncCallSpecs::new_for_op(&callop, FuncProto::new(String::new(), ct4.clone()));
    fd.add_call_specs(spec);

    fd.set_high_level();

    // --- merge channels deposited the way earlier merge Actions would
    // (testcache: the C++ side populates via production
    // HighIntersectTest::intersection which caches BOTH HighEdge directions)
    fd.merge_state.fixture_deposit_test_cache(2);
    fd.merge_state.fixture_deposit_channels(
        vec![op1.clone()],
        vec![op2.clone()],
        vec![callop.clone()],
    );

    // --- jump tables: one override (kept) + one plain (dropped)
    let jt1 = Arc::new(RwLock::new(JumpTable::new(Address::new(0x7100))));
    jt1.write().unwrap().jmodel = Some(Box::new(JumpBasicOverride::new(jt1.clone())));
    jt1.write().unwrap().norm_max.addsub = 7;
    jt1.write().unwrap().collect_loads = true;
    fd.jump_tables.push(jt1.clone());
    let jt2 = Arc::new(RwLock::new(JumpTable::new(Address::new(0x7200))));
    fd.jump_tables.push(jt2);

    // --- localmap: unlocked symbol (model drops) + typelock/namelock symbol
    let mut s1 = LocalSymbol::new("unlocked_a", 0x100, 4, Some(ct4.clone()), -1);
    s1.typelock = false;
    let mut s2 = LocalSymbol::new("locked_b", 0x104, 4, Some(ct4.clone()), -1);
    s2.typelock = true;
    s2.namelock = true;
    fd.scope = Some(ScopeLocal::new());
    if let Some(scope) = fd.scope.as_mut() {
        scope.symbols.push(s1);
        scope.symbols.push(s2);
        scope.min_param_offset = 0x40;
        scope.max_param_offset = 0x80;
    }

    // --- scalar/flag domains
    fd.flags |= funcdata_flags::HIGHLEVEL_ON
        | funcdata_flags::BLOCKS_GENERATED
        | funcdata_flags::PROCESSING_STARTED
        | funcdata_flags::TYPE_RECOVERY_START
        | funcdata_flags::TYPE_RECOVERY_ON
        | funcdata_flags::DOUBLE_PRECIS_ON
        | funcdata_flags::RESTART_PENDING;
    fd.flags |= funcdata_flags::BLOCKS_UNREACHABLE
        | funcdata_flags::PROCESSING_COMPLETE
        | funcdata_flags::JUMPTABLERECOVERY_DONT;
    fd.restart_pending = true;
    fd.high_level_index = 7;
    fd.set_laned_reg_generated();
    fd.laned_map.insert(
        LanedStorage {
            space: AddressSpace::Register,
            offset: 0x30,
            size: 4,
        },
        lane_record,
    );
    fd.active_output = Some(ParamActive::new(false));
    fd.funcp.return_bytes_consumed = 7;
    let edge = ResolveEdge::new(&ct4, &op1.0.read().unwrap(), 0);
    fd.union_map.insert(edge, ResolvedUnion::new(ct4.clone()));
    fd.heritage.pass = 3;
    fd.heritage.maxdepth = 5;

    // --- observation -------------------------------------------------------
    let observe_core = |fd: &Funcdata, stage: &str| {
        let (tests, trims, _live) = fd.merge_state.channel_sizes();
        let (protos, stack_ops, stack_pop) = fd.merge_state.channel_sizes_extended();
        let register_vns = fd
            .vbank
            .loc_tree
            .iter()
            .filter(|r| r.0.read().unwrap().get_space() == AddressSpace::Register)
            .count();
        let jt1_guard = jt1.read().unwrap();
        println!(
            "case=lifecycle|stage={}|flags={}|highlevelidx={}|minlaned={}|lanedmap={}|activeout={}|unionmap={}|ops={}|varnodes={}|opuniqid={}|createidx={}|calls={}|jts={}|jt1_override={}|jt1_maxaddsub={}|jt1_collectloads={}|heritage_pass={}|heritage_maxdepth={}|testcache={}|copytrims={}|protopartial={}|stackops={}|stackpop={}|procstart_gate={}|restartpend={}",
            stage,
            [
                bit_str("f_highlevel", fd.flags & funcdata_flags::HIGHLEVEL_ON != 0),
                bit_str("f_blocks", fd.flags & funcdata_flags::BLOCKS_GENERATED != 0),
                bit_str("f_procstart", fd.flags & funcdata_flags::PROCESSING_STARTED != 0),
                bit_str("f_typerec_start", fd.flags & funcdata_flags::TYPE_RECOVERY_START != 0),
                bit_str("f_typerec", fd.flags & funcdata_flags::TYPE_RECOVERY_ON != 0),
                bit_str("f_dblprecis", fd.flags & funcdata_flags::DOUBLE_PRECIS_ON != 0),
                bit_str("f_restart", fd.flags & funcdata_flags::RESTART_PENDING != 0),
                bit_str("f_unreach", fd.flags & funcdata_flags::BLOCKS_UNREACHABLE != 0),
                bit_str("f_proccomplete", fd.flags & funcdata_flags::PROCESSING_COMPLETE != 0),
                bit_str("f_jtdont", fd.flags & funcdata_flags::JUMPTABLERECOVERY_DONT != 0),
            ]
            .join(","),
            fd.high_level_index,
            fd.min_laned_size as i32,
            fd.laned_map.len(),
            if fd.active_output.is_some() { 1 } else { 0 },
            fd.union_map.len(),
            fd.obank.alivelist.len() + fd.obank.deadlist.len(),
            register_vns,
            fd.obank.get_uniqid(),
            fd.vbank.get_create_index(),
            fd.num_calls(),
            fd.jump_tables.len(),
            if jt1_guard.is_override() { 1 } else { 0 },
            jt1_guard.norm_max.addsub,
            if jt1_guard.collect_loads { 1 } else { 0 },
            fd.heritage.pass,
            fd.heritage.maxdepth,
            tests,
            trims,
            protos,
            stack_ops,
            if stack_pop { 1 } else { 0 },
            if fd.is_proc_started() { 1 } else { 0 },
            if fd.has_restart_pending() { 1 } else { 0 },
        );
    };
    let observe_localmap = |fd: &Funcdata, stage: &str| {
        let (count, min, max, found) = match fd.scope.as_ref() {
            Some(scope) => (
                scope.symbols.len(),
                scope.min_param_offset,
                scope.max_param_offset,
                if scope
                    .symbols
                    .iter()
                    .any(|s| s.name == "locked_b" && s.typelock)
                {
                    1
                } else {
                    0
                },
            ),
            None => (0usize, 0, 0, 0),
        };
        println!(
            "case=lifecycle|stage={}|domain=localmap|localsyms={}|paramwin=0x{:x}-0x{:x}|locked_found={}",
            stage, count, min, max, found
        );
    };
    let observe_funcproto = |fd: &Funcdata, stage: &str| {
        println!(
            "case=lifecycle|stage={}|domain=funcproto|returnbytes={}",
            stage, fd.funcp.return_bytes_consumed
        );
    };

    observe_core(&fd, "before");
    observe_localmap(&fd, "before");
    observe_funcproto(&fd, "before");

    // --- the lifecycle event under test (funcdata.cc:84-112)
    fd.clear();

    observe_core(&fd, "after");
    observe_localmap(&fd, "after");
    observe_funcproto(&fd, "after");
}
