//! DEINDIRECT-ARMS-1204: Rust comparand for the locked Ghidra 12.0.4
//! oracle `deindirect_arms_1204.cc` (FSPEC-DEINDIRECT-TRIGGER-0001).
//!
//! Mirrors each case through the crate's public API: the real
//! `ActionDeindirect::apply` (coreaction.rs, coreaction.cc:1219-1280) over
//! a Funcdata whose Architecture carries the query-channel Database
//! (FunctionSymbols installed with `Scope::add_function`), so the constant
//! arm resolves through the same global-scope queryFunction production
//! uses. The two known production-channel residuals print in the same
//! observation format so the bilateral diff pinpoints them:
//!   - extref: Scope-side refaddr storage (CALLSPEC-0001 seam) — the
//!     detection runs but the referral cannot resolve, exactly like
//!     oracle's `newfd == 0` (no conversion);
//!   - norestart_gate: per-callee noreturn lives in the flow-time
//!     callee-proto channel only; the db-function observable slice Rugra
//!     mints at deindirect time cannot carry it yet.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::action::Action;
use rudra::coreaction::ActionDeindirect;
use rudra::database::Database;
use rudra::funcdata::Funcdata;
use rudra::fspec::{FuncCallSpecs, FuncProto};
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeCode, TypeMetatype, TypePointer};
use rudra::varnode::varnode_flags;

fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

/// One CALLIND call site: fresh op + callspec + typed annotation input,
/// the flow.cc:684-686 construction pattern.
struct Site {
    op: PcodeOpRef,
    owner: Arc<RwLock<FuncCallSpecs>>,
}

fn make_site(fd: &mut Funcdata, call_pc: u64) -> Site {
    let op = fd.new_op(1, Address::new(call_pc));
    fd.op_set_opcode(&op, OpCode::CPUI_CALLIND);
    // FuncCallSpecs::new_for_op's second parameter is the default proto
    // base; the fixture constructs the same default-constructed shape the
    // flow path uses (fspec.cc:4924 FuncProto() base).
    let proto = FuncProto::new(String::new(), void_type());
    let fc = FuncCallSpecs::new_for_op(&op, proto);
    let owner = Arc::new(RwLock::new(fc));
    fd.add_call_specs_owner(owner.clone());
    let annotation = fd.new_varnode_call_specs(&owner);
    fd.op_set_input(&op, annotation, 0);
    Site { op, owner }
}

/// The deindirect observable slice after apply, byte-mirroring the C++
/// Site::dump: opcode number (enum value contract), entry validity/offset,
/// adopted name, action count, restart flag, input lock, override flag,
/// CALL arity.
fn dump_site(fd: &Funcdata, case_name: &str, site: &Site, count: i32, restart_before: bool) {
    let (opcode, arity) = {
        let guard = site.op.0.read().unwrap();
        (guard.opcode as i32, guard.inrefs.len())
    };
    let fc = site.owner.read().unwrap();
    let entry = fc
        .entry_addr
        .map(|a| format!("0x{:x}", a.as_u64()))
        .unwrap_or_else(|| "inv".to_string());
    println!(
        "case={}|op={}|entry={}|name={}|count={}|restart={}|inlock={}|override={}|arity={}",
        case_name,
        opcode,
        entry,
        fc.prototype.name,
        count,
        (fd.restart_pending && !restart_before) as i32,
        fc.prototype.is_input_locked() as i32,
        fc.prototype.is_override() as i32,
        arity,
    );
}

fn site_arch(db_arc: &Arc<RwLock<Database>>, funcptr_align: i32) -> Arc<Architecture> {
    let mut arch = Architecture::new();
    arch.symboltab = Some(db_arc.clone());
    arch.funcptr_align = funcptr_align;
    Arc::new(arch)
}

fn main() {
    let db_arc = Arc::new(RwLock::new(Database::new(false)));
    {
        let mut db = db_arc.write().unwrap();
        let s = db.get_global_scope_mut().expect("global scope");
        s.add_function(Address::new(0x60000000), "target_const", 1);
        s.add_function(Address::new(0x60002000), "target_aligned", 1);
        s.add_function(Address::new(0x60003000), "t_noreturn", 1);
        s.add_function(Address::new(0x60004000), "t_override", 1);
        s.add_function(Address::new(0x60006000), "ext_target", 1);
    }

    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    fd.set_arch(site_arch(&db_arc, 0));

    // ---- case const_hit: constant arm resolves through queryFunction ----
    {
        let mut action = ActionDeindirect::new();
        let site = make_site(&mut fd, 0x500010);
        let cnst = fd.new_constant(8, 0x60000000);
        fd.op_set_input(&site.op, cnst, 0);
        let restart_before = fd.restart_pending;
        action.apply(&mut fd).expect("apply const_hit");
        dump_site(&fd, "const_hit", &site, action.count, restart_before);
    }

    // ---- case const_miss: no function at the constant address ----
    {
        let mut action = ActionDeindirect::new();
        let site = make_site(&mut fd, 0x500020);
        let cnst = fd.new_constant(8, 0x60001000);
        fd.op_set_input(&site.op, cnst, 0);
        let restart_before = fd.restart_pending;
        action.apply(&mut fd).expect("apply const_miss");
        dump_site(&fd, "const_miss", &site, action.count, restart_before);
    }

    // ---- case align_strip: funcptr_align strips the encoding bits ----
    {
        let mut action = ActionDeindirect::new();
        fd.set_arch(site_arch(&db_arc, 2));
        let site = make_site(&mut fd, 0x500030);
        let cnst = fd.new_constant(8, 0x60002003);
        fd.op_set_input(&site.op, cnst, 0);
        let restart_before = fd.restart_pending;
        action.apply(&mut fd).expect("apply align_strip");
        dump_site(&fd, "align_strip", &site, action.count, restart_before);
        fd.set_arch(site_arch(&db_arc, 0));
    }

    // ---- case copy_chain: input(0) resolves through a COPY chain ----
    {
        let mut action = ActionDeindirect::new();
        let site = make_site(&mut fd, 0x500040);
        let cnst = fd.new_constant(8, 0x60000000);
        let copyop = fd.new_op(1, Address::new(0x500041));
        fd.op_set_opcode(&copyop, OpCode::CPUI_COPY);
        let copyout = fd.new_unique_out(8, &copyop);
        fd.op_set_input(&copyop, cnst, 0);
        fd.op_insert_before(&copyop, &site.op);
        fd.op_set_input(&site.op, copyout, 0);
        let restart_before = fd.restart_pending;
        action.apply(&mut fd).expect("apply copy_chain");
        dump_site(&fd, "copy_chain", &site, action.count, restart_before);
    }

    // ---- case norestart_gate: fspec.cc:5461 noreturn callee -> restart.
    //      Production residual: the per-callee noreturn bit rides the
    //      flow-time callee-proto channel; the db observable slice Rugra
    //      mints here cannot carry it (registered on the ticket).
    {
        let mut action = ActionDeindirect::new();
        let site = make_site(&mut fd, 0x500050);
        let cnst = fd.new_constant(8, 0x60003000);
        fd.op_set_input(&site.op, cnst, 0);
        let restart_before = fd.restart_pending;
        action.apply(&mut fd).expect("apply norestart_gate");
        dump_site(&fd, "norestart_gate", &site, action.count, restart_before);
    }

    // ---- case override_site: fspec.cc:5462 early return ----
    {
        let mut action = ActionDeindirect::new();
        let site = make_site(&mut fd, 0x500060);
        let cnst = fd.new_constant(8, 0x60004000);
        fd.op_set_input(&site.op, cnst, 0);
        site.owner.write().unwrap().prototype.set_override(true);
        let restart_before = fd.restart_pending;
        action.apply(&mut fd).expect("apply override_site");
        dump_site(&fd, "override_site", &site, action.count, restart_before);
    }

    // ---- case extref: external-reference arm. Production residual:
    //      Scope-side refaddr storage (CALLSPEC-0001 seam) — detection
    //      runs, referral cannot resolve (= oracle newfd==0, no
    //      conversion; the C++ fixture resolves through its real scope).
    {
        let mut action = ActionDeindirect::new();
        let site = make_site(&mut fd, 0x500070);
        let exvn = fd
            .vbank
            .create_with_space(8, rudra::space::AddressSpace::Ram, 0x60005000);
        exvn.write().unwrap().flags |= varnode_flags::PERSIST | varnode_flags::EXTERNREF;
        fd.op_set_input(&site.op, exvn, 0);
        let restart_before = fd.restart_pending;
        action.apply(&mut fd).expect("apply extref");
        dump_site(&fd, "extref", &site, action.count, restart_before);
    }

    // ---- case funcptr_force: typed-funcptr forceSet arm (cc:1258-1277) ----
    fd.set_type_recovery_started();
    {
        let mut action = ActionDeindirect::new();
        let site = make_site(&mut fd, 0x500080);
        let fpvn = fd
            .vbank
            .create_with_space(8, rudra::space::AddressSpace::Ram, 0x60007000);
        let mut fp = FuncProto::new(String::new(), void_type());
        fp.set_internal(None, void_type());
        let mut tc = TypeCode::new();
        tc.proto = Some(Arc::new(fp));
        let code = Arc::new(Datatype::Code(tc));
        let ptr = Arc::new(Datatype::Pointer(TypePointer::new(8, code, 1)));
        fpvn.write().unwrap().v_type = Some(ptr);
        fd.op_set_input(&site.op, fpvn, 0);
        let restart_before = fd.restart_pending;
        action.apply(&mut fd).expect("apply funcptr_force");
        dump_site(&fd, "funcptr_force", &site, action.count, restart_before);
    }
}
