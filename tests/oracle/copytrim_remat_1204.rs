// COPYTRIM-REMAT-0001: Rugra comparand for the locked Ghidra 12.0.4
// copy-trim re-materialization oracle (tests/oracle/copytrim_remat_1204.cc).
//
// KUNABUGS-COPYTRIM-REMAT-0001 (CASTFUSE-A root-cause candidate ③):
// does Merge::allocateCopyTrim re-materialize an explicit COPY at the
// firstuse of a dynamic-hash temp?  The C++ twin locks the oracle answer
// per case; this fixture mirrors case for case:
//
//   fold_relocate_fn   (C1)  use-anchored dynamic entry + COPY fold —
//                             attempt_dynamic_mapping must fail to
//                             relocate (position hash broken), nothing
//                             mapped, ZERO new ops.
//   refind_attach_fn   (C1b) def-anchored uniqueHash re-find: the baseline
//                             attach succeeds (mapped=1), the second call
//                             is rejected by the already-mapped guard.
//   late_cast_retarget (C2)  attempt_dynamic_mapping_late on an implied
//                             CAST-adjacent temp: both runtimes re-target
//                             the attach to the explicit varnode across
//                             the CAST (funcdata_varnode.cc:1373-1386,
//                             DYNMAP-LATE-CAST-RETARGET-0001 landed) —
//                             the censuses pin the bilateral agreement.
//   trim_dynamic_high  (C3)  CMOV diamond with a dynamic entry on X:
//                             mergeAddrTied + mergeMarker trims are
//                             cover-driven only; merge never consults the
//                             dynamic entry; the late action creates no
//                             ops.
//   action_walk_level  (C4)  ActionDynamicMapping at the ACTION level:
//                             both runtimes walk beginDynamic()/endDynamic()
//                             from Action::perform (action.cc:298) and
//                             attach from the action level; count stays 0
//                             on both sides because attemptDynamicMapping
//                             surfaces Varnode::setSymbolProperties' false
//                             (DYNMAP-SETPROPS-RET-0001 landed).
//   action_late_walk   (C5)  ActionDynamicSymbols at the ACTION level on
//                             the clean C1b shape: both runtimes perform
//                             the late attach from the action level and
//                             report count=1/status=1 (the Action base
//                             bookkeeping returns the accumulated count).
//
// Projections use stable fixture identities (varnode names, hex addresses,
// opcode names) — never Arc pointers or SeqNums.

use std::sync::{Arc, RwLock};

use rugra::action::{action_status, Action, ActionState};
use rugra::address::Address;
use rugra::block::{BlockBasic, FlowBlock};
use rugra::coreaction::{ActionDynamicMapping, ActionDynamicSymbols};
use rugra::dynamic::DynamicHash;
use rugra::funcdata::Funcdata;
use rugra::merge::Merge;
use rugra::opcodes::OpCode;
use rugra::space::AddressSpace;
use rugra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rugra::varmap::ScopeLocal;
use rugra::varnode::{varnode_flags, Varnode};

type VarnodeRef = Arc<RwLock<Varnode>>;
type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn base_type(name: &str, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, metatype)))
}

/// The gcc cspec localrange window (x86-64-gcc.cspec) — installed the way
/// the varmap_dynamicsym twin does so dynamic symbols can be minted into
/// the production-shaped ScopeLocal.
fn install_scope(fd: &mut Funcdata) {
    let mut scope = ScopeLocal::new();
    scope.stack_grows_negative = true;
    scope.stack_direction = 1;
    scope.local_range = vec![
        (0xfffffffffff0bdc1u64, 0xffffffffffffffffu64),
        (8u64, 39u64),
    ];
    fd.scope = Some(scope);
}

fn opcode_name(op: &OpCode) -> String {
    // Ghidra's get_opname (opcodes.cc) names; MULTIEQUAL prints as "BUILD".
    match op {
        OpCode::CPUI_MULTIEQUAL => "BUILD".to_string(),
        other => format!("{:?}", other).trim_start_matches("CPUI_").to_string(),
    }
}

struct Fixture {
    blocks: Vec<BlockRef>,
    varnodes: Vec<VarnodeRef>,
    names: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        Fixture { blocks: Vec::new(), varnodes: Vec::new(), names: Vec::new() }
    }

    fn make_block(&mut self, fd: &mut Funcdata) -> BlockRef {
        let b = fd.create_new_block();
        self.blocks.push(b.clone());
        b
    }

    fn remember(&mut self, vn: VarnodeRef, name: &str) {
        self.varnodes.push(vn);
        self.names.push(name.to_string());
    }

    fn name_of(&self, vn: &VarnodeRef) -> String {
        for (i, candidate) in self.varnodes.iter().enumerate() {
            if Arc::ptr_eq(candidate, vn) {
                return self.names[i].clone();
            }
        }
        "?".to_string()
    }

    fn reg_out(
        &mut self,
        fd: &mut Funcdata,
        name: &str,
        size: usize,
        offset: u64,
        op: &rugra::op::PcodeOpRef,
    ) -> VarnodeRef {
        let vn = fd.new_varnode_out_full(
            size,
            AddressSpace::Register,
            Address::new(offset),
            op,
        );
        self.remember(vn.clone(), name);
        vn
    }

    fn vncensus(&self, case_id: &str, stage: &str) {
        for vn in &self.varnodes {
            let v = vn.read().unwrap();
            println!(
                "vnc|case={case_id}|stage={stage}|vn={}|mapped={}|implied={}|explicit={}|desc={}",
                self.name_of(vn),
                if v.is_mapped() { 1 } else { 0 },
                if v.is_implied() { 1 } else { 0 },
                if v.is_explicit() { 1 } else { 0 },
                v.descend.len(),
            );
        }
    }

    /// Alive-op census sorted by (name, address): any op creation or
    /// removal by a mapping call is visible here.
    fn opcensus(&self, _fd: &Funcdata, case_id: &str, stage: &str) {
        let mut items: Vec<String> = Vec::new();
        for blk in &self.blocks {
            let blk_guard = blk.read().unwrap();
            let Some(bb) = blk_guard.as_any().downcast_ref::<BlockBasic>() else {
                continue;
            };
            for op in bb.get_ops() {
                let o = op.0.read().unwrap();
                items.push(format!("{}@0x{:x}", opcode_name(&o.opcode), o.get_addr().as_u64()));
            }
        }
        items.sort();
        println!(
            "ops|case={case_id}|stage={stage}|count={}|list={}",
            items.len(),
            items.join(";")
        );
    }

    /// Opcode-only alive-op census (sorted, with counts): used where op
    /// addresses are not fixture-controlled (merge trims take the incoming
    /// block's stop address, which the fixture never initializes).
    fn opcensus_names(&self, case_id: &str, stage: &str) {
        let mut items: Vec<String> = Vec::new();
        for blk in &self.blocks {
            let blk_guard = blk.read().unwrap();
            let Some(bb) = blk_guard.as_any().downcast_ref::<BlockBasic>() else {
                continue;
            };
            for op in bb.get_ops() {
                let o = op.0.read().unwrap();
                items.push(opcode_name(&o.opcode));
            }
        }
        items.sort();
        println!(
            "opsn|case={case_id}|stage={stage}|count={}|list={}",
            items.len(),
            items.join(";")
        );
    }

    fn dyncensus(fd: &Funcdata, case_id: &str, stage: &str) {
        let count = fd
            .scope
            .as_ref()
            .map(|s| s.symbols.iter().filter(|sym| sym.is_dynamic).count())
            .unwrap_or(0);
        println!("dync|case={case_id}|stage={stage}|count={count}");
    }

    fn call(case_id: &str, fn_name: &str, res: bool) {
        println!("call|case={case_id}|fn={fn_name}|res={}", if res { 1 } else { 0 });
    }
}

// ---------------------------------------------------------------------------
// C1 fold_relocate_fn
fn run_fold_relocate(fd: &mut Funcdata) {
    install_scope(fd);
    let mut f = Fixture::new();

    let block = f.make_block(fd);

    let op1 = fd.new_op(1, Address::new(0x1000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k2a = fd.new_constant(8, 0x2a);
    fd.op_set_input(&op1, k2a, 0);
    let c = f.reg_out(fd, "c", 8, 0x80, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x1010));
    fd.op_set_opcode(&op2, OpCode::CPUI_COPY);
    fd.op_set_input(&op2, c.clone(), 0);
    let t = f.reg_out(fd, "t", 8, 0x90, &op2);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0x1020));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, t.clone(), 0);
    let k1 = fd.new_constant(8, 1);
    fd.op_set_input(&op3, k1, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();

    // Mint USE-anchored: calc_hash_op(op3, slot 0, method 0) — t as input
    // of op3 (the twin's dhash.calcHash(op3, 0, 0)).
    let mut dhash = DynamicHash::new();
    dhash.calc_hash_op(&op3.0, 0, 0);
    let h = dhash.get_hash();
    let u = dhash.get_address();
    if h == 0 {
        panic!("calc_hash_op failed for the use anchor");
    }
    if let Some(scope) = fd.scope.as_mut() {
        scope.add_dynamic_symbol(
            "dsym_c1",
            Some(base_type("int8", 8, TypeMetatype::Int)),
            h,
            Some(u.as_u64()),
        );
    }
    println!("mint|case=fold_relocate_fn|vn=t|H=0x{:x}|U=0x{:x}", h, u.as_u64());

    f.vncensus("fold_relocate_fn", "pre");
    f.opcensus(fd, "fold_relocate_fn", "pre");
    Fixture::dyncensus(fd, "fold_relocate_fn", "pre");

    // The fold: op3 re-reads c (RulePropagateCopy's IR effect).
    fd.op_set_input(&op3, c.clone(), 0);

    f.vncensus("fold_relocate_fn", "folded");
    f.opcensus(fd, "fold_relocate_fn", "folded");

    let res = fd.attempt_dynamic_mapping(
        u,
        h,
        8,
        false,
        false,
        "dsym_c1",
    );
    Fixture::call("fold_relocate_fn", "attemptDynamicMapping", res);
    f.vncensus("fold_relocate_fn", "after");
    f.opcensus(fd, "fold_relocate_fn", "after");
    Fixture::dyncensus(fd, "fold_relocate_fn", "after");
}

// ---------------------------------------------------------------------------
// C1b refind_attach_fn
fn run_refind_attach(fd: &mut Funcdata) {
    install_scope(fd);
    let mut f = Fixture::new();

    let block = f.make_block(fd);

    let op1 = fd.new_op(1, Address::new(0x1100));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k33 = fd.new_constant(8, 0x33);
    fd.op_set_input(&op1, k33, 0);
    let c = f.reg_out(fd, "c", 8, 0x81, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x1110));
    fd.op_set_opcode(&op2, OpCode::CPUI_COPY);
    fd.op_set_input(&op2, c.clone(), 0);
    let t = f.reg_out(fd, "t", 8, 0x91, &op2);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0x1120));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, t.clone(), 0);
    let k2 = fd.new_constant(8, 2);
    fd.op_set_input(&op3, k2, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();
    let (h, u) = {
        let mut dhash = DynamicHash::new();
        dhash.unique_hash_vn(&t, fd);
        (dhash.get_hash(), dhash.get_address())
    };
    if let Some(scope) = fd.scope.as_mut() {
        scope.add_dynamic_symbol(
            "dsym_c1b",
            Some(base_type("int8", 8, TypeMetatype::Int)),
            h,
            Some(u.as_u64()),
        );
    }
    println!("mint|case=refind_attach_fn|vn=t|H=0x{:x}|U=0x{:x}", h, u.as_u64());

    f.vncensus("refind_attach_fn", "pre");
    f.opcensus(fd, "refind_attach_fn", "pre");

    let res = fd.attempt_dynamic_mapping(u, h, 8, false, false, "dsym_c1b");
    Fixture::call("refind_attach_fn", "attemptDynamicMapping", res);
    f.vncensus("refind_attach_fn", "after1");
    f.opcensus(fd, "refind_attach_fn", "after1");

    let res2 = fd.attempt_dynamic_mapping(u, h, 8, false, false, "dsym_c1b");
    Fixture::call("refind_attach_fn", "attemptDynamicMapping_second", res2);
    f.vncensus("refind_attach_fn", "after2");
    Fixture::dyncensus(fd, "refind_attach_fn", "after2");
}

// ---------------------------------------------------------------------------
// C2 late_cast_retarget
fn run_late_cast_retarget(fd: &mut Funcdata) {
    install_scope(fd);
    let mut f = Fixture::new();

    let block = f.make_block(fd);

    let op1 = fd.new_op(1, Address::new(0x2000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k5a = fd.new_constant(8, 0x5a);
    fd.op_set_input(&op1, k5a, 0);
    let c0 = f.reg_out(fd, "c0", 8, 0xa0, &op1);
    c0.write().unwrap().set_flags(varnode_flags::EXPLICIT);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x2010));
    fd.op_set_opcode(&op2, OpCode::CPUI_CAST);
    fd.op_set_input(&op2, c0.clone(), 0);
    let tmp = f.reg_out(fd, "tmp", 8, 0xa8, &op2);
    tmp.write().unwrap().set_flags(varnode_flags::IMPLIED);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0x2020));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, tmp.clone(), 0);
    let k2 = fd.new_constant(8, 2);
    fd.op_set_input(&op3, k2, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();
    let (h, u) = {
        let mut dhash = DynamicHash::new();
        dhash.unique_hash_vn(&tmp, fd);
        (dhash.get_hash(), dhash.get_address())
    };
    if let Some(scope) = fd.scope.as_mut() {
        scope.add_dynamic_symbol(
            "late_sym",
            Some(base_type("uint8", 8, TypeMetatype::Uint)),
            h,
            Some(u.as_u64()),
        );
    }
    println!("mint|case=late_cast_retarget|vn=tmp|H=0x{:x}|U=0x{:x}", h, u.as_u64());

    f.vncensus("late_cast_retarget", "pre");
    f.opcensus(fd, "late_cast_retarget", "pre");

    let res = fd.attempt_dynamic_mapping_late(u, h, 8, false, false, "late_sym");
    Fixture::call("late_cast_retarget", "attemptDynamicMappingLate", res);
    f.vncensus("late_cast_retarget", "after");
    f.opcensus(fd, "late_cast_retarget", "after");
    Fixture::dyncensus(fd, "late_cast_retarget", "after");
}

// ---------------------------------------------------------------------------
// C3 trim_dynamic_high (the merge_trim_lane T1 CMOV diamond + dynamic
// entry on X).
fn run_trim_dynamic_high(fd: &mut Funcdata) {
    install_scope(fd);
    let mut f = Fixture::new();

    let b0 = f.make_block(fd);
    let b1 = f.make_block(fd);
    let b2 = f.make_block(fd);
    let b3 = f.make_block(fd);
    let b4 = f.make_block(fd);
    fd.bblocks.add_edge(b0.clone(), b1.clone());
    fd.bblocks.add_edge(b1.clone(), b2.clone());
    fd.bblocks.add_edge(b1.clone(), b3.clone());
    fd.bblocks.add_edge(b2.clone(), b3.clone());
    fd.bblocks.add_edge(b3.clone(), b4.clone());

    let def_x = fd.new_op(1, Address::new(0x3000));
    fd.op_set_opcode(&def_x, OpCode::CPUI_COPY);
    let x = f.reg_out(fd, "X", 4, 0x20, &def_x);
    let k1234 = fd.new_constant(4, 0x1234);
    fd.op_set_input(&def_x, k1234, 0);
    fd.op_insert_end(&def_x, &b0);

    let boolvn = fd.vbank.create_with_space(1, AddressSpace::Unique, 0x900);
    let fx_op = fd.new_op(2, Address::new(0x3010));
    fd.op_set_opcode(&fx_op, OpCode::CPUI_INT_RIGHT);
    let fx = fd.vbank.create_def_with_space(4, AddressSpace::Unique, 0x910, &fx_op.0);
    fx_op.0.write().unwrap().output = Some(fx.clone());
    let _ = fd.assign_high(&fx);
    fd.op_set_input(&fx_op, x.clone(), 0);
    let k16 = fd.new_constant(4, 16);
    fd.op_set_input(&fx_op, k16, 1);
    fd.op_insert_end(&fx_op, &b1);

    let cbranch = fd.new_op(2, Address::new(0x3018));
    fd.op_set_opcode(&cbranch, OpCode::CPUI_CBRANCH);
    let k4000 = fd.new_constant(8, 0x4000);
    fd.op_set_input(&cbranch, k4000, 0);
    fd.op_set_input(&cbranch, boolvn, 1);
    fd.op_insert_end(&cbranch, &b1);

    let phi = fd.new_op(2, Address::new(0x3030));
    fd.op_set_opcode(&phi, OpCode::CPUI_MULTIEQUAL);
    let phiout = f.reg_out(fd, "phiout", 4, 0x20, &phi);
    fd.op_set_input(&phi, x.clone(), 0);
    fd.op_set_input(&phi, fx.clone(), 1);
    fd.op_insert_begin(&phi, &b3);

    let reader = fd.new_op(2, Address::new(0x3040));
    fd.op_set_opcode(&reader, OpCode::CPUI_INT_AND);
    fd.op_set_input(&reader, phiout.clone(), 0);
    let kff = fd.new_constant(4, 0xff);
    fd.op_set_input(&reader, kff, 1);
    let _ = fd.new_unique_out(4, &reader);
    fd.op_insert_end(&reader, &b4);

    fd.set_high_level();
    let (h, u) = {
        let mut dhash = DynamicHash::new();
        dhash.unique_hash_vn(&x, fd);
        (dhash.get_hash(), dhash.get_address())
    };
    if let Some(scope) = fd.scope.as_mut() {
        scope.add_dynamic_symbol(
            "x_dyn",
            Some(base_type("int4", 4, TypeMetatype::Int)),
            h,
            Some(u.as_u64()),
        );
    }
    println!("mint|case=trim_dynamic_high|vn=X|H=0x{:x}|U=0x{:x}", h, u.as_u64());

    f.vncensus("trim_dynamic_high", "pre");
    f.opcensus_names("trim_dynamic_high", "pre");
    Fixture::dyncensus(fd, "trim_dynamic_high", "pre");

    {
        let mut merge = Merge::new();
        let _ = merge.try_merge_addr_tied(fd);
        merge.merge_marker(fd);
    }

    f.vncensus("trim_dynamic_high", "postmerge");
    f.opcensus_names("trim_dynamic_high", "postmerge");
    Fixture::dyncensus(fd, "trim_dynamic_high", "postmerge");

    // Which varnode each phi lane reads now (identity via the registered
    // fixture varnodes X/fX; blocks named by creation position b0..b4).
    for slot in 0..2usize {
        let lane = phi.0.read().unwrap().get_in(slot).cloned();
        let desc = match lane {
            Some(lane) if Arc::ptr_eq(&lane, &x) => "X".to_string(),
            Some(lane) if Arc::ptr_eq(&lane, &fx) => "fX".to_string(),
            Some(lane) => {
                let def = lane.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                match def {
                    Some(def)
                        if def.read().unwrap().opcode == OpCode::CPUI_COPY =>
                    {
                        let d = def.read().unwrap();
                        let blk_name = d
                            .parent
                            .as_ref()
                            .and_then(|w| w.upgrade())
                            .and_then(|p| {
                                f.blocks
                                    .iter()
                                    .position(|b| Arc::ptr_eq(b, &p))
                                    .map(|i| format!("b{i}"))
                            })
                            .unwrap_or_else(|| "?".to_string());
                        let reads = d
                            .get_in(0)
                            .cloned()
                            .map(|r| {
                                if Arc::ptr_eq(&r, &x) {
                                    "X".to_string()
                                } else if Arc::ptr_eq(&r, &fx) {
                                    "fX".to_string()
                                } else {
                                    "?".to_string()
                                }
                            })
                            .unwrap_or_else(|| "?".to_string());
                        format!("copy@{blk_name}({reads})")
                    }
                    _ => "?".to_string(),
                }
            }
            None => "?".to_string(),
        };
        println!("phi|case=trim_dynamic_high|lane{slot}={desc}");
    }

    // NOTE: ActionDynamicSymbols is deliberately NOT run on this post-merge
    // state: mergeMarker's LowlevelError aborts the whole decompile in
    // production, so the late action never observes it (the fixture's
    // catch exists only to inspect the trims).  The late action's walk
    // behaviour is pinned instead by action_late_walk on a clean state.
}

// ---------------------------------------------------------------------------
// C4 action_walk_level
fn run_action_walk_level(fd: &mut Funcdata) {
    install_scope(fd);
    let mut f = Fixture::new();

    let block = f.make_block(fd);

    let op1 = fd.new_op(1, Address::new(0x4000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k77 = fd.new_constant(8, 0x77);
    fd.op_set_input(&op1, k77, 0);
    let c = f.reg_out(fd, "c", 8, 0x82, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x4010));
    fd.op_set_opcode(&op2, OpCode::CPUI_COPY);
    fd.op_set_input(&op2, c.clone(), 0);
    let t = f.reg_out(fd, "t", 8, 0x92, &op2);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0x4020));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, t.clone(), 0);
    let k3 = fd.new_constant(8, 3);
    fd.op_set_input(&op3, k3, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();
    let (h, u) = {
        let mut dhash = DynamicHash::new();
        dhash.unique_hash_vn(&t, fd);
        (dhash.get_hash(), dhash.get_address())
    };
    if let Some(scope) = fd.scope.as_mut() {
        scope.add_dynamic_symbol(
            "dsym_c4",
            Some(base_type("int8", 8, TypeMetatype::Int)),
            h,
            Some(u.as_u64()),
        );
    }
    println!("mint|case=action_walk_level|vn=t|H=0x{:x}|U=0x{:x}", h, u.as_u64());

    f.vncensus("action_walk_level", "pre");
    f.opcensus(fd, "action_walk_level", "pre");

    // Action level, mirroring the oracle driver (Action::perform,
    // action.cc:298): count reset → apply walk → count harvested from the
    // action's accumulator (take_count_delta) → perform returns the
    // accumulated count.  attemptDynamicMapping returns
    // Varnode::setSymbolProperties' false on this shape, so count stays 0
    // on both runtimes (the attach itself shows in the vncensus below).
    let mut action = ActionDynamicMapping::new();
    let flags = action.get_flags();
    let mut state = ActionState::new(flags);
    let status = action
        .perform(fd, &mut state)
        .unwrap_or(action_status::NO_CHANGE);
    println!("act|case=action_walk_level|fn=ActionDynamicMapping|count={}|status={status}", state.count);

    f.vncensus("action_walk_level", "after");
    f.opcensus(fd, "action_walk_level", "after");
    Fixture::dyncensus(fd, "action_walk_level", "after");
}

// ---------------------------------------------------------------------------
// C5 action_late_walk: ActionDynamicSymbols at the ACTION level on the clean
// C1b shape (the production state the late action actually observes).
fn run_action_late_walk(fd: &mut Funcdata) {
    install_scope(fd);
    let mut f = Fixture::new();

    let block = f.make_block(fd);

    let op1 = fd.new_op(1, Address::new(0x5000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k88 = fd.new_constant(8, 0x88);
    fd.op_set_input(&op1, k88, 0);
    let c = f.reg_out(fd, "c", 8, 0x83, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x5010));
    fd.op_set_opcode(&op2, OpCode::CPUI_COPY);
    fd.op_set_input(&op2, c.clone(), 0);
    let t = f.reg_out(fd, "t", 8, 0x93, &op2);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0x5020));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, t.clone(), 0);
    let k4 = fd.new_constant(8, 4);
    fd.op_set_input(&op3, k4, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();
    let (h, u) = {
        let mut dhash = DynamicHash::new();
        dhash.unique_hash_vn(&t, fd);
        (dhash.get_hash(), dhash.get_address())
    };
    if let Some(scope) = fd.scope.as_mut() {
        scope.add_dynamic_symbol(
            "dsym_c5",
            Some(base_type("int8", 8, TypeMetatype::Int)),
            h,
            Some(u.as_u64()),
        );
    }
    println!("mint|case=action_late_walk|vn=t|H=0x{:x}|U=0x{:x}", h, u.as_u64());

    f.vncensus("action_late_walk", "pre");
    f.opcensus(fd, "action_late_walk", "pre");

    // Action level, mirroring the oracle driver (Action::perform,
    // action.cc:298): the walk is the production ActionDynamicSymbols::apply
    // (coreaction.cc:4869) and the count/status pair is the Action base
    // bookkeeping — attemptDynamicMappingLate returns true here, so
    // count=1 and perform returns 1 on both runtimes.
    let mut action = ActionDynamicSymbols::new();
    let flags = action.get_flags();
    let mut state = ActionState::new(flags);
    let status = action
        .perform(fd, &mut state)
        .unwrap_or(action_status::NO_CHANGE);
    println!("act|case=action_late_walk|fn=ActionDynamicSymbols|count={}|status={status}", state.count);

    f.vncensus("action_late_walk", "after");
    f.opcensus(fd, "action_late_walk", "after");
    Fixture::dyncensus(fd, "action_late_walk", "after");
}

fn main() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_fold_relocate(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_refind_attach(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_late_cast_retarget(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_trim_dynamic_high(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_action_walk_level(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_action_late_walk(&mut fd);
}
