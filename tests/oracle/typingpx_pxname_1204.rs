//! TYPINGPX-PXNAME-0001 Rugra comparand: `Funcdata::map_globals`
//! discovery-arm naming with POINTER-typed highs (funcdata_varnode.cc:
//! 1653-1719 + database.cc:2434-2518 persist arm + type.hh:424/457/273
//! printNameBase recursion) against the locked Ghidra 12.0.4 oracle.
//! Mirrors tests/oracle/typingpx_pxname_1204.cc case by case; every
//! printed value must byte-match the oracle.
//!
//! The pinned semantics: the discovery arm's `ct` reaches
//! `build_variable_name(addr, usepoint, ct, index, addrtied|persist)`
//! (cc:1706-1710), whose persist arm prepends `ct->print_name_base()` to
//! the capitalized space name — `TypePointer` contributes 'p' +
//! pointee recursively (px / pax / pi / pc / ppx), bases contribute
//! name[0] ('x' for the sleigh_arch xunknownN cores, 'i', 'c').
//!
//! Structural mapping notes (mirrors funcdata_mapglobals_maxvn_1204.rs):
//!   * persist|addrtied and the forced `v_type` are pinned directly on
//!     written varnodes (production derives them from the localmap
//!     queryProperties channel, a registered Rugda gap); identical flag
//!     state both sides.
//!   * Pointer types are constructed via `TypePointer::new` (Rugra's
//!     mirror of `getTypePointer`'s `TypePointer(s,pt,ws)` constructor
//!     form, type.hh:412) and the array via the factory's
//!     `get_type_array` (Rugra's getTypeArray interned form).
//!   * The unknown cores are the shared factory's xunknownN entries, so
//!     the name base is the golden's 'x' character.
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::database::Database;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeMetatype, TypePointer};
use rudra::type_system::typefactory::TypeFactory;
use rudra::varmap::ScopeLocal;
use rudra::varnode::varnode_flags;

fn metaname(meta: TypeMetatype) -> &'static str {
    use TypeMetatype::*;
    match meta {
        Unknown => "unknown",
        Void => "void",
        Bool => "bool",
        Int => "int",
        Uint => "uint",
        Float => "float",
        Pointer => "ptr",
        Array => "array",
        Struct => "struct",
        Union => "union",
        Enum => "other",
        Code => "code",
        Spacebase => "other",
        PartialStruct | PartialEnum | PartialUnion => "other",
    }
}

fn ptr_to(pointee: Arc<Datatype>) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer::new(8, pointee, 1)))
}

fn main() {
    // The channel: Database with a global scope (fresh — no symbols yet,
    // ranges seeded after varnode creation exactly like the C++ twin) and
    // a comment db so warningHeader is observable instead of stderr noise.
    let mut arch = rudra::arch::Architecture::new();
    let db_arc = Arc::new(RwLock::new(Database::new(false)));
    arch.set_symboltab(db_arc.clone());
    arch.commentdb = Some(Arc::new(RwLock::new(
        rudra::comment::CommentDatabaseInternal::new(),
    )));

    let mut fd = Funcdata::new("pxname", Address::new(0x5000), 0x100);
    fd.set_arch(Arc::new(arch));
    fd.scope = Some(ScopeLocal::new());
    let block = fd.create_new_block();

    // The forced ct per case — base pointees from the shared factory
    // (xunknownN cores), the array interned through get_type_array.
    let xu1 = TypeFactory::shared_default()
        .read()
        .unwrap()
        .get_base(1, TypeMetatype::Unknown)
        .expect("xunknown1 core");
    let xu8 = TypeFactory::shared_default()
        .read()
        .unwrap()
        .get_base(8, TypeMetatype::Unknown)
        .expect("xunknown8 core");
    let i8 = TypeFactory::shared_default()
        .read()
        .unwrap()
        .get_base(8, TypeMetatype::Int)
        .expect("int8 core");
    let code = TypeFactory::shared_default()
        .read()
        .unwrap()
        .get_base(1, TypeMetatype::Code)
        .expect("code core");
    let arr16 = TypeFactory::shared_default()
        .write()
        .unwrap()
        .get_type_array(16, xu1.clone());

    let mut pc = 0x5010u64;
    let mut make_persist_out = |fd: &mut Funcdata,
                                block: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
                                addr: u64,
                                ct: Arc<Datatype>| {
        let op = fd.new_op(1, Address::new(pc));
        pc += 1;
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let vn = fd.vbank.create_def_with_space(8, AddressSpace::Ram, addr, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        let c = fd.new_constant(8, 0x11);
        fd.op_set_input(&op, c, 0);
        fd.op_insert_end(&op, block);
        let mut vn_w = vn.write().unwrap();
        vn_w.v_type = Some(ct);
        vn_w.set_flags(varnode_flags::PERSIST | varnode_flags::ADDRTIED);
        drop(vn_w);
        vn
    };

    let _a = make_persist_out(&mut fd, &block, 0x7000, ptr_to(xu8.clone()));
    let _b = make_persist_out(&mut fd, &block, 0x7100, ptr_to(arr16.clone()));
    let _c = make_persist_out(&mut fd, &block, 0x7200, ptr_to(i8.clone()));
    let _d = make_persist_out(&mut fd, &block, 0x7300, ptr_to(code.clone()));
    let _e = make_persist_out(&mut fd, &block, 0x7400, ptr_to(ptr_to(xu1.clone())));
    let _f = make_persist_out(&mut fd, &block, 0x7500, xu8.clone());

    // Channel state AFTER varnode creation: global ownership range for
    // discover_scope (database.cc:1353-1366).
    {
        let mut db = db_arc.write().unwrap();
        let global = db.global_scope_id;
        if let Some(rng) = rudra::address::Range::new(Address::new(0), Address::new(u64::MAX)) {
            db.add_range(global, rng);
        }
    }

    fd.set_high_level();
    fd.map_globals().expect("map_globals succeeds");

    // Observation helper: the same query channel map_globals used
    // (cc:1701 queryProperties(addr, 1, empty usepoint)).
    let describe = |fd: &Funcdata, addr: u64| -> String {
        match fd.query_properties_parent_scope(Address::new(addr), 1, Address::new(0)) {
            Some((Some(hit), _)) => format!(
                "name={}|size={}|mt={}|tsize={}",
                hit.symbol_name,
                hit.entry_size,
                metaname(hit.type_metatype),
                hit.symbol_type
                    .as_ref()
                    .map(|t| t.get_size())
                    .unwrap_or(0),
            ),
            _ => "none".to_string(),
        }
    };

    println!("case=a_px|{}", describe(&fd, 0x7000));
    println!("case=b_pax|{}", describe(&fd, 0x7100));
    println!("case=c_pi|{}", describe(&fd, 0x7200));
    println!("case=d_pc|{}", describe(&fd, 0x7300));
    println!("case=e_ppx|{}", describe(&fd, 0x7400));
    println!("case=f_x|{}", describe(&fd, 0x7500));
}
