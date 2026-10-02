// PTRSUB-SWITCH-CAST-RESIDUAL-0001 Rust comparand for the locked Ghidra
// 12.0.4 fixture.  Mirrors ptrsub_switch_cast_1204.cc case for case: the
// same IR/CFG/type seeds, the real ActionSetCasts::apply, and identical
// pre/post/swexpr dumps.  The "atok=" field mirrors the apply-side output
// token dispatch that lives in src/coreaction.rs cast_output (PTRSUB arm =
// TypeOpPtrsub::get_output_token, PTRADD arm = skipped, LOAD arm = inline
// pointee/out-high logic, INT_* arm = base_type_for(size, Int)); on the
// Ghidra side atok is the same virtual TypeOp::getOutputToken call that
// coreaction.cc:2541 consumes.
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::coreaction::ActionSetCasts;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::{space_flags, AddrSpace, AddressSpace, SpaceType};
use rudra::type_system::cast::base_type_for;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::typeop::{TypeOp, TypeOpIntAdd, TypeOpIntMult, TypeOpLoad, TypeOpPtradd, TypeOpPtrsub};
use rudra::variable::high_internal_flags;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<RwLock<Varnode>>;

fn meta_token(meta: TypeMetatype) -> &'static str {
    match meta {
        TypeMetatype::Void => "void",
        TypeMetatype::Pointer => "ptr",
        TypeMetatype::Array => "array",
        TypeMetatype::Struct => "struct",
        TypeMetatype::Spacebase => "spacebase",
        TypeMetatype::Bool => "bool",
        TypeMetatype::Int => "int",
        TypeMetatype::Uint => "uint",
        TypeMetatype::Unknown => "unknown",
        _ => "other",
    }
}

fn type_proj(ct: Option<&Arc<Datatype>>) -> String {
    let Some(ct) = ct else {
        return "null".to_string();
    };
    if let Datatype::Pointer(pointer) = ct.as_ref() {
        return format!(
            "ptr{}w{}->{}",
            pointer.base.size,
            pointer.wordsize,
            type_proj(Some(&pointer.ptr_to))
        );
    }
    format!("{}{}", meta_token(ct.get_metatype()), ct.get_size())
}

fn op_token(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_PTRSUB => "ptrsub",
        OpCode::CPUI_PTRADD => "ptradd",
        OpCode::CPUI_LOAD => "load",
        OpCode::CPUI_INT_ADD => "int_add",
        OpCode::CPUI_INT_MULT => "int_mult",
        OpCode::CPUI_INT_SEXT => "int_sext",
        OpCode::CPUI_CAST => "cast",
        OpCode::CPUI_BRANCHIND => "branchind",
        _ => "other",
    }
}

struct FixtureTypes {
    int4_t: Arc<Datatype>,
    int8_t: Arc<Datatype>,
    p_int4: Arc<Datatype>,
    p_int8: Arc<Datatype>,
    p_table: Arc<Datatype>,
}

fn fixture_struct(
    name: &str,
    size: usize,
    alignment: usize,
    fields: Vec<TypeField>,
) -> Arc<Datatype> {
    let mut base = TypeBase::new(name.to_string(), size, TypeMetatype::Struct);
    base.alignment = alignment as i32;
    base.align_size = size;
    Arc::new(Datatype::Struct(TypeStruct { base, fields }))
}

fn ram_space() -> AddrSpace {
    AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        3,
        space_flags::HASPHYSICAL,
        0,
        0,
    )
}

fn make_fd(
    name: &str,
    base: u64,
    ram: &AddrSpace,
    factory: &Arc<RwLock<TypeFactory>>,
    architecture: &Arc<Architecture>,
) -> Funcdata {
    let mut fd = Funcdata::new(name, Address::with_space(ram, base), 0x40);
    fd.vbank.set_type_factory(factory.clone());
    fd.set_arch(architecture.clone());
    fd
}

struct CaseTracker {
    op_names: HashMap<usize, String>,
    vn_names: HashMap<usize, String>,
    next_found: usize,
}

impl CaseTracker {
    fn new() -> Self {
        Self {
            op_names: HashMap::new(),
            vn_names: HashMap::new(),
            next_found: 0,
        }
    }

    fn op(&mut self, op: &PcodeOpRef, name: &str) {
        self.op_names.insert(Arc::as_ptr(&op.0) as usize, name.to_string());
    }

    fn vn(&mut self, vn: &VnRef, name: &str) {
        self.vn_names.insert(Arc::as_ptr(vn) as usize, name.to_string());
    }

    fn op_name(&mut self, op: &PcodeOpRef) -> String {
        let key = Arc::as_ptr(&op.0) as usize;
        if let Some(name) = self.op_names.get(&key) {
            return name.clone();
        }
        let name = format!("n{}", self.next_found);
        self.next_found += 1;
        self.op_names.insert(key, name.clone());
        name
    }

    fn vn_name(&mut self, vn: &VnRef) -> String {
        let key = Arc::as_ptr(vn) as usize;
        if let Some(name) = self.vn_names.get(&key) {
            return name.clone();
        }
        let name = format!("v{}", self.next_found);
        self.next_found += 1;
        self.vn_names.insert(key, name.clone());
        name
    }
}

fn varnode_high(vn: &VnRef) -> Option<Arc<Datatype>> {
    vn.read().unwrap().high.as_ref().map(|h| h.read().unwrap().get_type())
}

fn input_cell(vn: &VnRef) -> String {
    let rg = vn.read().unwrap();
    format!(
        "t={},h={}",
        type_proj(rg.get_type().as_ref()),
        match varnode_high(vn) {
            Some(ct) => type_proj(Some(&ct)),
            None => "nohigh".to_string(),
        }
    )
}

/// The apply-side output token dispatch, mirroring src/coreaction.rs
/// ActionSetCasts::cast_output: PTRSUB/PTRADD consult the real TypeOp
/// impls, the arithmetic family (INT_ADD/INT_MULT/...) routes through
/// cast::arithmetic_output_standard (cast.cc:394), LOAD uses the inline
/// pointee/out-high arm, and INT_SEXT falls to base_type_for(size, Int).
/// CAST ops never reach cast_output (apply skips them), which maps to the
/// same base-unknown token the virtual call yields.
fn apply_side_token(
    op: &rudra::op::PcodeOp,
    factory: &Arc<RwLock<TypeFactory>>,
) -> Option<Arc<Datatype>> {
    match op.opcode {
        OpCode::CPUI_PTRSUB => {
            TypeOpPtrsub::new(factory.clone()).get_output_token(op)
        }
        OpCode::CPUI_PTRADD => {
            TypeOpPtradd::new(factory.clone()).get_output_token(op)
        }
        OpCode::CPUI_LOAD => {
            let out_size = op.get_out()?.read().unwrap().get_size();
            let in1_high = op.get_in(1).and_then(|a| {
                let vn = a.read().unwrap();
                vn.high
                    .as_ref()
                    .map(|h| h.read().unwrap().get_type())
                    .or_else(|| vn.v_type.clone())
            });
            let out_high = || {
                op.get_out().and_then(|o| {
                    let vn = o.read().unwrap();
                    vn.high
                        .as_ref()
                        .map(|h| h.read().unwrap().get_type())
                        .or_else(|| vn.v_type.clone())
                })
            };
            match in1_high {
                Some(ct) if matches!(ct.as_ref(), Datatype::Pointer(_)) => {
                    if let Datatype::Pointer(pt) = ct.as_ref() {
                        if pt.ptr_to.get_size() == out_size {
                            Some(pt.ptr_to.clone())
                        } else {
                            out_high().or(Some(ct.clone()))
                        }
                    } else {
                        unreachable!()
                    }
                }
                _ => out_high(),
            }
        }
        OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_MULT => {
            rudra::type_system::cast::arithmetic_output_standard(op, factory)
        }
        OpCode::CPUI_INT_SEXT => {
            let size = op.get_out()?.read().unwrap().get_size();
            Some(base_type_for(size, TypeMetatype::Int))
        }
        _ => None,
    }
}

fn pre_op_dump(
    op: &PcodeOpRef,
    tracker: &mut CaseTracker,
    factory: &Arc<RwLock<TypeFactory>>,
) -> String {
    let rg = op.0.read().unwrap();
    let mut out = format!("{}:{}", tracker.op_name(op), op_token(rg.opcode));
    for slot in 0..rg.num_input() {
        let vn = rg.get_in(slot).expect("input slot");
        let cell = if vn.read().unwrap().is_constant() {
            format!("c#{}", vn.read().unwrap().get_offset())
        } else {
            input_cell(&vn)
        };
        out.push_str(&format!(":i{slot}[{cell}]"));
    }
    let outvn = rg.get_out();
    match &outvn {
        Some(outvn) => {
            let t = type_proj(outvn.read().unwrap().get_type().as_ref());
            let h = varnode_high(outvn);
            let h = match h {
                Some(ct) => type_proj(Some(&ct)),
                None => "nohigh".to_string(),
            };
            out.push_str(&format!(":out[t={t},h={h}]"));
        }
        None => out.push_str(":out[none]"),
    }
    if outvn.is_none() || rg.opcode == OpCode::CPUI_BRANCHIND {
        out.push_str(":token=na:atok=na");
    } else if rg.opcode == OpCode::CPUI_CAST {
        // TypeOpCast has no token override: base getOutputLocal is the
        // unknown base (typeop.cc:261-265 via TypeOp::getOutputToken). The
        // .cc dumps token==atok for CAST (same virtual call).
        let size = outvn.as_ref().unwrap().read().unwrap().get_size();
        let token = base_type_for(size, TypeMetatype::Unknown);
        out.push_str(&format!(
            ":token={}:atok={}",
            type_proj(Some(&token)),
            type_proj(Some(&token))
        ));
    } else {
        let token = match rg.opcode {
            OpCode::CPUI_PTRSUB => {
                TypeOpPtrsub::new(factory.clone()).get_output_token(&rg)
            }
            OpCode::CPUI_PTRADD => {
                TypeOpPtradd::new(factory.clone()).get_output_token(&rg)
            }
            OpCode::CPUI_LOAD => TypeOpLoad.get_output_token(&rg),
            OpCode::CPUI_INT_ADD => {
                TypeOpIntAdd::new(factory.clone()).get_output_token(&rg)
            }
            OpCode::CPUI_INT_MULT => {
                // Real Rust TypeOp impl since the arithmetic-token port
                // (typeop.cc:1625 via cast.cc:394).
                TypeOpIntMult::new(factory.clone()).get_output_token(&rg)
            }
            OpCode::CPUI_INT_SEXT => {
                // No token override: base getOutputLocal is the base int
                // (TypeOpFunc metaout TYPE_INT).
                let size = outvn.as_ref().unwrap().read().unwrap().get_size();
                Some(base_type_for(size, TypeMetatype::Int))
            }
            _ => None,
        };
        let atok = apply_side_token(&rg, factory);
        out.push_str(&format!(
            ":token={}:atok={}",
            type_proj(token.as_ref()),
            type_proj(atok.as_ref())
        ));
    }
    if matches!(rg.opcode, OpCode::CPUI_PTRSUB | OpCode::CPUI_PTRADD) {
        let ic = match rg.opcode {
            OpCode::CPUI_PTRSUB => {
                TypeOpPtrsub::new(factory.clone()).get_input_cast(&rg, 0)
            }
            _ => TypeOpPtradd::new(factory.clone()).get_input_cast(&rg, 0),
        };
        match ic {
            Some(ct) => out.push_str(&format!(":ic0={}", type_proj(Some(&ct)))),
            None => out.push_str(":ic0=none"),
        }
    } else {
        out.push_str(":ic0=na");
    }
    out
}

fn post_op_dump(op: &PcodeOpRef, tracker: &mut CaseTracker) -> String {
    let rg = op.0.read().unwrap();
    let mut out = format!("{}:{}", tracker.op_name(op), op_token(rg.opcode));
    let impl_flag = rg
        .get_out()
        .map(|o| u8::from(o.read().unwrap().is_implied()))
        .unwrap_or(0);
    out.push_str(&format!(":impl={impl_flag}"));
    match rg.get_out() {
        Some(outvn) => out.push_str(&format!(
            ":out={}",
            type_proj(outvn.read().unwrap().get_type().as_ref())
        )),
        None => out.push_str(":out=none"),
    }
    out.push_str(":in=");
    for slot in 0..rg.num_input() {
        if slot != 0 {
            out.push(',');
        }
        let vn = rg.get_in(slot).expect("input slot");
        if vn.read().unwrap().is_constant() {
            out.push_str(&format!("c#{}", vn.read().unwrap().get_offset()));
        } else {
            let name = tracker.vn_name(&vn);
            out.push_str(&name);
        }
    }
    out
}

fn block_ops(block: &BlockRef) -> Vec<PcodeOpRef> {
    block.read().unwrap().get_ops()
}

fn typed_input(
    fd: &mut Funcdata,
    space: AddressSpace,
    offset: u64,
    size: usize,
    ct: Arc<Datatype>,
) -> VnRef {
    let vn = fd.vbank.create_with_space(size, space, offset);
    let vn = fd.set_input_varnode(vn);
    vn.write().unwrap().update_type_lock(ct, true, false);
    vn
}

fn make_op(
    fd: &mut Funcdata,
    block: &BlockRef,
    opcode: OpCode,
    inputs: usize,
    pc: u64,
    out_size: usize,
) -> PcodeOpRef {
    let ram = fd
        .baseaddr
        .get_space()
        .expect("fixture function address must carry ram space");
    let op = fd.new_op(inputs, Address::with_space(&ram, pc));
    fd.op_set_opcode(&op, opcode);
    if out_size > 0 {
        fd.new_unique_out(out_size, &op);
    }
    fd.op_insert_end(&op, block);
    op
}

fn seed_high(vn: &VnRef, ct: Arc<Datatype>) {
    let rg = vn.read().unwrap();
    let high = rg.high.as_ref().expect("seeded input must have a high");
    let mut high = high.write().unwrap();
    high.v_type.set(ct);
    high.highflags |= high_internal_flags::TYPE_FINALIZED;
}

struct GlobFormOps {
    gs: Option<VnRef>,
    g_a: VnRef,
    g_b: Option<VnRef>,
    idx: VnRef,
    ps: Option<PcodeOpRef>,
    sext: PcodeOpRef,
    mult: PcodeOpRef,
    pa: PcodeOpRef,
    load: Option<PcodeOpRef>,
    ia: Option<PcodeOpRef>,
    bi: Option<PcodeOpRef>,
}

#[allow(clippy::too_many_arguments)]
fn build_tree(
    fd: &mut Funcdata,
    block: &BlockRef,
    t: &FixtureTypes,
    tracker: &mut CaseTracker,
    pc_base: u64,
    with_ps: bool,
    with_load: bool,
    with_ia: bool,
    with_bi: bool,
    ps_out_type: Option<Arc<Datatype>>,
    pa_out_type: Option<Arc<Datatype>>,
    scale: u64,
) -> GlobFormOps {
    let g_a = typed_input(fd, AddressSpace::Ram, 0x10000119, 8, t.p_int4.clone());
    let idx = typed_input(fd, AddressSpace::Register, 0x10, 4, t.int4_t.clone());
    tracker.vn(&g_a, "gA");
    tracker.vn(&idx, "idx");

    let mut gs = None;
    let mut g_b = None;
    let mut ps = None;
    let pa_in0: VnRef;
    if with_ps {
        let gs_vn = typed_input(fd, AddressSpace::Ram, 0x10000111, 8, t.p_table.clone());
        tracker.vn(&gs_vn, "gs");
        let ps_op = make_op(fd, block, OpCode::CPUI_PTRSUB, 2, pc_base, 8);
        fd.op_set_input(&ps_op, gs_vn.clone(), 0);
        let offset = fd.new_constant(8, 0);
        fd.op_set_input(&ps_op, offset, 1);
        if let Some(ct) = ps_out_type {
            let out = ps_op.0.read().unwrap().get_out().expect("ps out").clone();
            out.write().unwrap().update_type(ct);
        }
        tracker.op(&ps_op, "ps");
        let ps_out = ps_op.0.read().unwrap().get_out().expect("ps out").clone();
        tracker.vn(&ps_out, "ps_o");
        pa_in0 = ps_out;
        gs = Some(gs_vn);
        ps = Some(ps_op);
    } else {
        let gb_vn = typed_input(fd, AddressSpace::Ram, 0x10000111, 8, t.p_int4.clone());
        tracker.vn(&gb_vn, "gB");
        pa_in0 = gb_vn.clone();
        g_b = Some(gb_vn);
    }

    let sext = make_op(fd, block, OpCode::CPUI_INT_SEXT, 1, pc_base + 1, 8);
    fd.op_set_input(&sext, idx.clone(), 0);
    let mult = make_op(fd, block, OpCode::CPUI_INT_MULT, 2, pc_base + 2, 8);
    let sext_out = sext.0.read().unwrap().get_out().expect("sext out").clone();
    fd.op_set_input(&mult, sext_out.clone(), 0);
    let mult_c = fd.new_constant(8, 4);
    fd.op_set_input(&mult, mult_c, 1);
    let pa = make_op(fd, block, OpCode::CPUI_PTRADD, 3, pc_base + 3, 8);
    fd.op_set_input(&pa, pa_in0.clone(), 0);
    let mult_out = mult.0.read().unwrap().get_out().expect("mult out").clone();
    fd.op_set_input(&pa, mult_out.clone(), 1);
    let scale_c = fd.new_constant(4, scale);
    fd.op_set_input(&pa, scale_c, 2);
    if let Some(ct) = pa_out_type {
        let out = pa.0.read().unwrap().get_out().expect("pa out").clone();
        out.write().unwrap().update_type(ct);
    }
    tracker.op(&sext, "sext");
    tracker.op(&mult, "mult");
    tracker.op(&pa, "pa");
    tracker.vn(&sext_out, "sext_o");
    tracker.vn(&mult_out, "mult_o");
    let pa_out = pa.0.read().unwrap().get_out().expect("pa out").clone();
    tracker.vn(&pa_out, "pa_o");

    let mut tree_top = pa_out.clone();
    let mut load = None;
    if with_load {
        let load_op = make_op(fd, block, OpCode::CPUI_LOAD, 2, pc_base + 4, 8);
        let spc = fd.new_constant(8, 1);
        fd.op_set_input(&load_op, spc, 0);
        fd.op_set_input(&load_op, pa_out.clone(), 1);
        let out = load_op.0.read().unwrap().get_out().expect("load out").clone();
        out.write().unwrap().update_type(t.p_int4.clone());
        tracker.op(&load_op, "load");
        let load_out = load_op.0.read().unwrap().get_out().expect("load out").clone();
        tracker.vn(&load_out, "load_o");
        tree_top = load_out;
        load = Some(load_op);
    }
    let mut ia = None;
    if with_ia {
        let ia_op = make_op(fd, block, OpCode::CPUI_INT_ADD, 2, pc_base + 5, 8);
        fd.op_set_input(&ia_op, tree_top.clone(), 0);
        fd.op_set_input(&ia_op, g_a.clone(), 1);
        tracker.op(&ia_op, "ia");
        let ia_out = ia_op.0.read().unwrap().get_out().expect("ia out").clone();
        tracker.vn(&ia_out, "ia_o");
        tree_top = ia_out;
        ia = Some(ia_op);
    }
    let mut bi = None;
    if with_bi {
        let bi_op = make_op(fd, block, OpCode::CPUI_BRANCHIND, 1, pc_base + 6, 0);
        fd.op_set_input(&bi_op, tree_top, 0);
        tracker.op(&bi_op, "bi");
        bi = Some(bi_op);
    }

    fd.set_high_level();
    if let Some(gb_vn) = &g_b {
        seed_high(gb_vn, t.p_int8.clone());
    }
    GlobFormOps {
        gs,
        g_a,
        g_b,
        idx,
        ps,
        sext,
        mult,
        pa,
        load,
        ia,
        bi,
    }
}

fn run_pre(fd: &Funcdata, name: &str, block: &BlockRef, tracker: &mut CaseTracker,
           factory: &Arc<RwLock<TypeFactory>>) {
    let ops: Vec<String> = block_ops(block)
        .iter()
        .map(|op| pre_op_dump(op, tracker, factory))
        .collect();
    println!("case={name}|stage=pre|ops={}", ops.join(";"));
}

fn run_post(name: &str, action: &mut ActionSetCasts, block: &BlockRef,
            tracker: &mut CaseTracker) {
    let delta = action.take_count_delta();
    let ops: Vec<String> = block_ops(block)
        .iter()
        .map(|op| post_op_dump(op, tracker))
        .collect();
    println!("case={name}|stage=post|count={delta}|ops={}", ops.join(";"));
}

fn render_op(op: &PcodeOpRef, tracker: &mut CaseTracker, depth: usize) -> String {
    if depth > 32 {
        return "DEPTH".to_string();
    }
    let rg = op.0.read().unwrap();
    match rg.opcode {
        OpCode::CPUI_CAST => {
            let out_t = rg
                .get_out()
                .and_then(|o| o.read().unwrap().get_type());
            format!(
                "({}){}",
                type_proj(out_t.as_ref()),
                render_expr(&rg.get_in(0).expect("cast in"), tracker, depth)
            )
        }
        OpCode::CPUI_PTRADD | OpCode::CPUI_INT_ADD => format!(
            "({} + {})",
            render_expr(&rg.get_in(0).expect("in0"), tracker, depth),
            render_expr(&rg.get_in(1).expect("in1"), tracker, depth)
        ),
        OpCode::CPUI_INT_MULT => format!(
            "({} * {})",
            render_expr(&rg.get_in(0).expect("in0"), tracker, depth),
            render_expr(&rg.get_in(1).expect("in1"), tracker, depth)
        ),
        OpCode::CPUI_INT_SEXT => format!(
            "SEXT({})",
            render_expr(&rg.get_in(0).expect("in0"), tracker, depth)
        ),
        OpCode::CPUI_LOAD => format!(
            "*({})",
            render_expr(&rg.get_in(1).expect("in1"), tracker, depth)
        ),
        OpCode::CPUI_PTRSUB => format!(
            "PTRSUB({},#{})",
            render_expr(&rg.get_in(0).expect("in0"), tracker, depth),
            rg.get_in(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(0)
        ),
        OpCode::CPUI_BRANCHIND => format!(
            "switch({})",
            render_expr(&rg.get_in(0).expect("in0"), tracker, depth)
        ),
        _ => format!("{}@{}", op_token(rg.opcode), tracker.op_name(op)),
    }
}

fn render_expr(vn: &VnRef, tracker: &mut CaseTracker, depth: usize) -> String {
    if depth > 32 {
        return "DEPTH".to_string();
    }
    let rg = vn.read().unwrap();
    if rg.is_constant() {
        return format!("#{}", rg.get_offset());
    }
    // The renderer inlines every written varnode (implied or not): the
    // fixture-side analogue of PrintLanguage inlining a non-exp expression.
    if let Some(def) = rg.def.as_ref().and_then(|d| d.upgrade()) {
        return render_op(&PcodeOpRef(def), tracker, depth + 1);
    }
    tracker.vn_name(vn)
}

fn run_swexpr(name: &str, stage: &str, bi: &PcodeOpRef, tracker: &mut CaseTracker) {
    println!(
        "case={name}|stage={stage}|text={}",
        render_op(bi, tracker, 0)
    );
}

struct CaseCtx<'a> {
    arch: &'a Arc<Architecture>,
    factory: &'a Arc<RwLock<TypeFactory>>,
    ram: &'a AddrSpace,
    t: &'a FixtureTypes,
}

fn new_case(ctx: &CaseCtx, name: &str, pc: u64) -> (Funcdata, BlockRef) {
    let mut fd = make_fd(name, pc, ctx.ram, ctx.factory, ctx.arch);
    let block = fd.create_new_block();
    block
        .write()
        .unwrap()
        .as_any_mut()
        .downcast_mut::<BlockBasic>()
        .expect("fixture basic block")
        .set_initial_range(
            Address::with_space(ctx.ram, 0),
            Address::with_space(ctx.ram, 0x100),
        );
    (fd, block)
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    ctx: &CaseCtx,
    name: &str,
    pc: u64,
    with_ps: bool,
    with_load: bool,
    with_ia: bool,
    with_bi: bool,
    ps_out_type: Option<Arc<Datatype>>,
    pa_out_type: Option<Arc<Datatype>>,
    scale: u64,
    swexpr: bool,
) {
    let (mut fd, block) = new_case(ctx, name, pc);
    let mut tracker = CaseTracker::new();
    let ops = build_tree(
        &mut fd,
        &block,
        ctx.t,
        &mut tracker,
        pc,
        with_ps,
        with_load,
        with_ia,
        with_bi,
        ps_out_type,
        pa_out_type,
        scale,
    );
    run_pre(&fd, name, &block, &mut tracker, ctx.factory);
    if swexpr {
        run_swexpr(name, "swexpr_pre", ops.bi.as_ref().expect("bi op"), &mut tracker);
    }
    let mut action = ActionSetCasts::new();
    let _ = action.apply(&mut fd).expect("ActionSetCasts::apply");
    run_post(name, &mut action, &block, &mut tracker);
    if swexpr {
        run_swexpr(name, "swexpr_post", ops.bi.as_ref().expect("bi op"), &mut tracker);
    }
}

fn run_ia_token(ctx: &CaseCtx) {
    let (mut fd, block) = new_case(ctx, "sw_ia", 0x5400);
    let mut tracker = CaseTracker::new();
    let g_a = typed_input(&mut fd, AddressSpace::Ram, 0x10000119, 8, ctx.t.int8_t.clone());
    tracker.vn(&g_a, "gA8");
    let ia = make_op(&mut fd, &block, OpCode::CPUI_INT_ADD, 2, 0x5400, 8);
    fd.op_set_input(&ia, g_a.clone(), 0);
    let zero = fd.new_constant(8, 0);
    fd.op_set_input(&ia, zero, 1);
    let out = ia.0.read().unwrap().get_out().expect("ia out").clone();
    out.write().unwrap().update_type(ctx.t.p_int4.clone());
    tracker.op(&ia, "ia");
    let ia_out = ia.0.read().unwrap().get_out().expect("ia out").clone();
    tracker.vn(&ia_out, "ia_o");
    fd.set_high_level();
    run_pre(&fd, "ia_token", &block, &mut tracker, ctx.factory);
    let mut action = ActionSetCasts::new();
    let _ = action.apply(&mut fd).expect("ActionSetCasts::apply");
    run_post("ia_token", &mut action, &block, &mut tracker);
}

fn run_cast_chain(ctx: &CaseCtx) {
    let (mut fd, block) = new_case(ctx, "sw_chain", 0x5500);
    let mut tracker = CaseTracker::new();
    let src = typed_input(&mut fd, AddressSpace::Register, 0x20, 8, ctx.t.int8_t.clone());
    tracker.vn(&src, "src");
    let cast_op = make_op(&mut fd, &block, OpCode::CPUI_CAST, 1, 0x5500, 8);
    fd.op_set_input(&cast_op, src.clone(), 0);
    {
        let out = cast_op.0.read().unwrap().get_out().expect("cast out").clone();
        out.write().unwrap().update_type(ctx.t.p_int4.clone());
        out.write().unwrap().set_implied();
    }
    let mult = make_op(&mut fd, &block, OpCode::CPUI_INT_MULT, 2, 0x5501, 8);
    let cast_out = cast_op
        .0
        .read()
        .unwrap()
        .get_out()
        .expect("cast out")
        .clone();
    fd.op_set_input(&mult, cast_out.clone(), 0);
    let four = fd.new_constant(8, 4);
    fd.op_set_input(&mult, four, 1);
    tracker.op(&cast_op, "cast0");
    tracker.op(&mult, "mult");
    tracker.vn(&cast_out, "cast0_o");
    let mult_out = mult.0.read().unwrap().get_out().expect("mult out").clone();
    tracker.vn(&mult_out, "mult_o");
    fd.set_high_level();
    run_pre(&fd, "cast_chain", &block, &mut tracker, ctx.factory);
    let mut action = ActionSetCasts::new();
    let _ = action.apply(&mut fd).expect("ActionSetCasts::apply");
    run_post("cast_chain", &mut action, &block, &mut tracker);
}

fn run_typedef_typelock(ctx: &CaseCtx, td_int8: Arc<Datatype>) {
    let (mut fd, block) = new_case(ctx, "sw_td_lock", 0x5700);
    let mut tracker = CaseTracker::new();
    let g_a = typed_input(&mut fd, AddressSpace::Ram, 0x10000119, 8, ctx.t.int8_t.clone());
    tracker.vn(&g_a, "gA8");
    let ia = make_op(&mut fd, &block, OpCode::CPUI_INT_ADD, 2, 0x5700, 8);
    fd.op_set_input(&ia, g_a.clone(), 0);
    let zero = fd.new_constant(8, 0);
    fd.op_set_input(&ia, zero, 1);
    {
        let out = ia.0.read().unwrap().get_out().expect("ia out").clone();
        out.write().unwrap().update_type_lock(td_int8.clone(), true, false);
        out.write().unwrap().set_implied();
    }
    tracker.op(&ia, "ia");
    let ia_out = ia.0.read().unwrap().get_out().expect("ia out").clone();
    tracker.vn(&ia_out, "ia_o");
    fd.set_high_level();
    run_pre(&fd, "typedef_typelock", &block, &mut tracker, ctx.factory);
    let mut action = ActionSetCasts::new();
    let _ = action.apply(&mut fd).expect("ActionSetCasts::apply");
    run_post("typedef_typelock", &mut action, &block, &mut tracker);
}

fn run_cast_arm_fork(ctx: &CaseCtx) {
    let (mut fd, block) = new_case(ctx, "sw_arm_fork", 0x5800);
    let mut tracker = CaseTracker::new();
    let src = typed_input(&mut fd, AddressSpace::Register, 0x40, 8, ctx.t.int8_t.clone());
    tracker.vn(&src, "src");
    let cast_op = make_op(&mut fd, &block, OpCode::CPUI_CAST, 1, 0x5800, 0);
    fd.op_set_input(&cast_op, src.clone(), 0);
    let const_c = fd.new_constant(8, 0x30);
    const_c.write().unwrap().update_type(ctx.t.p_int4.clone());
    // Hand-built wiring bypassing VarnodeBank::set_def's constant-space
    // rejection, mirroring the .cc fixture's PcodeOp::setOutput +
    // Varnode::setDef (setDef sets the written flag the same way).
    const_c.write().unwrap().def = Some(Arc::downgrade(&cast_op.0));
    const_c.write().unwrap().flags |= rudra::varnode::varnode_flags::WRITTEN;
    cast_op.0.write().unwrap().output = Some(const_c.clone());
    let mult = make_op(&mut fd, &block, OpCode::CPUI_INT_MULT, 2, 0x5801, 8);
    fd.op_set_input(&mult, const_c.clone(), 0);
    let four = fd.new_constant(8, 4);
    fd.op_set_input(&mult, four, 1);
    tracker.op(&cast_op, "cast0");
    tracker.op(&mult, "mult");
    tracker.vn(&const_c, "constC");
    let mult_out = mult.0.read().unwrap().get_out().expect("mult out").clone();
    tracker.vn(&mult_out, "mult_o");
    fd.set_high_level();
    run_pre(&fd, "cast_arm_fork", &block, &mut tracker, ctx.factory);
    let mut action = ActionSetCasts::new();
    let _ = action.apply(&mut fd).expect("ActionSetCasts::apply");
    run_post("cast_arm_fork", &mut action, &block, &mut tracker);
}

fn main() {
    println!(
        "schema=1|fixture=PTRSUB-SWITCH-CAST-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // Mirror the .cc FixtureArchitecture bootstrap: raw TypeFactory ->
    // setupSizes -> ordered setCoreType -> cacheCoreTypes.
    let mut raw_factory = TypeFactory::raw();
    raw_factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });
    for (name, size, metatype) in [
        ("xunknown1", 1, TypeMetatype::Unknown),
        ("xunknown2", 2, TypeMetatype::Unknown),
        ("xunknown4", 4, TypeMetatype::Unknown),
        ("xunknown8", 8, TypeMetatype::Unknown),
        ("int4", 4, TypeMetatype::Int),
        ("int8", 8, TypeMetatype::Int),
    ] {
        raw_factory
            .set_core_type_result(name, size, metatype, false)
            .expect("locked core type bootstrap");
    }
    raw_factory.cache_core_types();
    let factory = Arc::new(RwLock::new(raw_factory));

    let table = fixture_struct(
        "TableStruct",
        8,
        4,
        vec![
            TypeField {
                name: "sel".into(),
                offset: 0,
                type_ptr: {
                    let f = factory.read().unwrap();
                    f.get_base(4, TypeMetatype::Int).expect("int4")
                },
            },
            TypeField {
                name: "pad".into(),
                offset: 4,
                type_ptr: {
                    let f = factory.read().unwrap();
                    f.get_base(4, TypeMetatype::Int).expect("int4")
                },
            },
        ],
    );
    let t = {
        let mut f = factory.write().unwrap();
        let int4_t = f.get_base(4, TypeMetatype::Int).expect("int4");
        let int8_t = f.get_base(8, TypeMetatype::Int).expect("int8");
        // Preserve the .cc factory request order (int4, int8, u8, then the
        // three pointers).
        let p_int4 = f.get_type_pointer(8, int4_t.clone(), 1);
        let p_int8 = f.get_type_pointer(8, int8_t.clone(), 1);
        let p_table = f.get_type_pointer(8, table, 1);
        FixtureTypes {
            int4_t,
            int8_t,
            p_int4,
            p_int8,
            p_table,
        }
    };
    let td_int8 = factory
        .write()
        .unwrap()
        .get_typedef("td_int8", t.int8_t.clone());

    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.max_basetype_size = 10;
    architecture.set_types(factory.clone());
    let architecture = Arc::new(architecture);
    let ram = ram_space();
    let ctx = CaseCtx {
        arch: &architecture,
        factory: &factory,
        ram: &ram,
        t: &t,
    };

    run_case(&ctx, "aligned", 0x5000, true, false, false, true,
             Some(t.p_int4.clone()), Some(t.p_int4.clone()), 4, false);
    run_case(&ctx, "pa_out_int8", 0x5100, true, false, false, true,
             Some(t.p_int4.clone()), Some(t.int8_t.clone()), 4, false);
    run_case(&ctx, "pa_in_churn", 0x5200, false, false, false, true,
             None, Some(t.p_int4.clone()), 8, false);
    run_case(&ctx, "pa_both_churn", 0x5300, false, false, false, true,
             None, Some(t.int8_t.clone()), 8, false);
    run_ia_token(&ctx);
    run_cast_chain(&ctx);
    run_case(&ctx, "globform", 0x5600, true, true, true, true,
             Some(t.p_int8.clone()), Some(t.p_int8.clone()), 4, true);
    run_typedef_typelock(&ctx, td_int8);
    run_cast_arm_fork(&ctx);
}
