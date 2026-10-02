//! FUNCDATA-MAPGLOBALS-MAXVN-0001 Rudra comparand: `Funcdata::map_globals`
//! group maxvn carrying (funcdata_varnode.cc:1653-1719) against the locked
//! Ghidra 12.0.4 oracle. Mirrors tests/oracle/funcdata_mapglobals_maxvn_1204.cc
//! case by case; every printed value must byte-match the oracle.
//!
//! The pinned semantics are the inner group loop's maxvn reassignment
//! (cc:1685-1686, strictly-greater size carries the varnode Arc) and the
//! ct read (cc:1692-1693, the biggest varnode's high type when it spans
//! exactly [addr,endaddr)) — the R-MAPGLOBALS REJECT fix-forward
//! discrimination on the same-address dual-width persist shape.
//!
//! Structural mapping notes (registered in the metadata):
//!   * The fixture pins `persist|addrtied` and the forced `v_type` directly
//!     on written varnodes (production derives them from the localmap
//!     queryProperties channel in `Funcdata::newVarnodeOut`, a registered
//!     Rudra gap); the C++ twin does the same through test-only access.
//!   * The global-scope query channel is the Database (Rudra models the
//!     global scope as the query point; the C++ twin queries through the
//!     ScopeLocal whose parent walk reaches the same entries).
//!   * Core unknowns are named `undefinedN` on this side (data-organization
//!     flavor) — the C++ twin registers the same spelling so the span
//!     fallback's printNameBase contribution matches.
//!   * The 4-byte unsigned base is named `uint` here and `uint4` in the
//!     C++ twin; only the first character (`u`) is observable through
//!     buildVariableName's printNameBase, so created-symbol names match.
//!   * Case b forces an 8-byte type on the 1-byte group start: the
//!     maxvn-source fix reads the MAX member's 2-byte type (no overflow,
//!     no warning), while the pre-fix group-start source would read the
//!     8-byte start type and flip inconsistentuse/warningHeader.
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::comment::comment_type;
use rudra::database::Database;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::TypeMetatype;
use rudra::type_system::typefactory::TypeFactory;
use rudra::varmap::ScopeLocal;
use rudra::varnode::varnode_flags;

fn forced_type(size: usize, meta: TypeMetatype) -> Arc<rudra::type_system::datatype::Datatype> {
    TypeFactory::shared_default()
        .read()
        .unwrap()
        .get_base(size, meta)
        .expect("shared factory produces every base type")
}

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

    let mut fd = Funcdata::new("mapglobals", Address::new(0x5000), 0x100);
    fd.set_arch(Arc::new(arch));
    fd.scope = Some(ScopeLocal::new());
    let block = fd.create_new_block();

    // Written persist varnode at (addr,size) with a forced Datatype — the
    // same construction as the C++ twin's make_persist_out. The varnode is
    // created directly in the ram space (Rudra's new_varnode_out maps a
    // spaceless Address into the register space, which would take the
    // legacy proxy arm instead of the RAM query channel mapGlobals uses);
    // the HighVariable attaches during the set_high_level sweep below,
    // exactly like the C++ twin (highlevel_on is clear at creation).
    let mut pc = 0x5010u64;
    let mut make_persist_out = |fd: &mut Funcdata,
                                block: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
                                size: usize,
                                addr: u64,
                                tsize: usize,
                                meta: TypeMetatype| {
        let op = fd.new_op(1, Address::new(pc));
        pc += 1;
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let vn = fd.vbank.create_def_with_space(size, AddressSpace::Ram, addr, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        let c = fd.new_constant(size, 0x11);
        fd.op_set_input(&op, c, 0);
        fd.op_insert_end(&op, block);
        let ct = forced_type(tsize, meta);
        let mut vn_w = vn.write().unwrap();
        vn_w.v_type = Some(ct);
        vn_w.set_flags(varnode_flags::PERSIST | varnode_flags::ADDRTIED);
        drop(vn_w);
        vn
    };

    let _a1 = make_persist_out(&mut fd, &block, 1, 0x6000, 1, TypeMetatype::Int);
    let _a8 = make_persist_out(&mut fd, &block, 8, 0x6000, 4, TypeMetatype::Uint);

    let _b1 = make_persist_out(&mut fd, &block, 1, 0x6100, 8, TypeMetatype::Int);
    let _b8 = make_persist_out(&mut fd, &block, 8, 0x6100, 2, TypeMetatype::Int);

    let _c8 = make_persist_out(&mut fd, &block, 8, 0x6200, 8, TypeMetatype::Uint);
    let _c1 = make_persist_out(&mut fd, &block, 1, 0x6201, 1, TypeMetatype::Int);

    let _d8a = make_persist_out(&mut fd, &block, 8, 0x6300, 8, TypeMetatype::Uint);
    let _d8b = make_persist_out(&mut fd, &block, 8, 0x6300, 8, TypeMetatype::Int);

    let _e1 = make_persist_out(&mut fd, &block, 1, 0x6400, 1, TypeMetatype::Int);
    let _e8 = make_persist_out(&mut fd, &block, 8, 0x6400, 4, TypeMetatype::Uint);
    let _e4 = make_persist_out(&mut fd, &block, 4, 0x6404, 4, TypeMetatype::Int);

    // Channel state AFTER varnode creation: global ownership range for
    // discover_scope (database.cc:1353-1366) + the case-b seeded entry.
    {
        let mut db = db_arc.write().unwrap();
        let global = db.global_scope_id;
        if let Some(rng) = rudra::address::Range::new(Address::new(0), Address::new(u64::MAX)) {
            db.add_range(global, rng);
        }
        let seed_type = forced_type(4, TypeMetatype::Uint);
        db.add_symbol_mapped(global, "seed_b", Some(seed_type), Address::new(0x6100), 4);
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

    println!("case=a_maxvn_type|{}", describe(&fd, 0x6000));
    println!("case=b_entryflip|{}", describe(&fd, 0x6100));
    println!("case=c_fallback|{}", describe(&fd, 0x6200));
    println!("case=d_nomaxswap|{}", describe(&fd, 0x6300));
    println!("case=e_multigroup|{}", describe(&fd, 0x6400));

    let warnings = fd
        .arch
        .as_ref()
        .and_then(|a| a.commentdb.clone())
        .map(|cdb| {
            cdb.read()
                .unwrap()
                .comments_for_function(fd.baseaddr)
                .filter(|c| (c.get_type() & comment_type::WARNINGHEADER) != 0)
                .count()
        })
        .unwrap_or(0);
    println!("case=warn|count={warnings}");
}
