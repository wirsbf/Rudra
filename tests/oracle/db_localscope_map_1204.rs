// Locked Ghidra 12.0.4 fixture for DB-LOCALSCOPE-MAP-0001 (Rust side).
//
// Mirrors tests/oracle/db_localscope_map_1204.cc record-for-record: the
// Database flagbase partmap (setPropertyRange / clearPropertyRange /
// getProperty / encode-decode changepoints), the <hole> document-order
// wiring (decodeHole -> setPropertyRange feeding the addMap fold at
// database.cc:1153), and the addMap property fold itself (persist /
// global-discovery uselimit clear / addrtied + flagbase fold) projected
// through queryProperties' getAllFlags branch. Record formats are
// byte-identical to the C++ fixture.
//
// Case semantics (see the .cc header for the full rationale):
//   setup / fb_accumulate / fb_clear_subrange / fb_roundtrip
//   fb_hole_interleave(_flipped)   hole-vs-mapsym document order.
//   fold_ro_after / fold_vol_after / fold_overlap_* / fold_tail_overlap
//   fold_usepoint_guard_hit/miss   the empty-uselimit guard.
//   fold_victim_before(+scope_only)  property installed AFTER the map.
//   fold_global_persist            persist + fold on the global scope.
//   fold_discovery_clear(+uselimit) global-discovery persist + uselimit
//                                  clear feeding the fold.

use rudra::address::{Address, Range};
use rudra::rangemap::RangeRecord;
use rudra::database::{symbol_flags, Database, Scope};
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::space::AddressSpace;
use rudra::varmap::{ghidra_space_index, LocalSymbol, ScopeLocal, symbol_category};
use rudra::varnode::varnode_flags;
use std::sync::{Arc, RwLock};

fn ram_range(first: u64, last: u64) -> Range {
    Range::new(Address::new(first), Address::new(last)).unwrap()
}

fn sym(name: &str, space: AddressSpace, start: u64, size: i32, usepoint: Option<u64>) -> LocalSymbol {
    let mut s = LocalSymbol::new(name, start, size, None, symbol_category::NO_CATEGORY);
    s.space = space;
    s.usepoint = usepoint;
    s
}

fn scope_tag(final_scope: rudra::varmap::QueryFinalScope) -> &'static str {
    match final_scope {
        rudra::varmap::QueryFinalScope::None => "none",
        rudra::varmap::QueryFinalScope::This => "this",
        rudra::varmap::QueryFinalScope::Parent => "parent",
    }
}

/// queryProperties observation via the ScopeLocal projection, formatted
/// like the .cc dumpQp.
fn dump_qp(
    case: &str,
    scope: &ScopeLocal,
    parent: Option<&ScopeLocal>,
    property: &dyn Fn(AddressSpace, u64) -> u32,
    space: AddressSpace,
    offset: u64,
    size: i64,
    usepoint: Option<u64>,
) {
    let out = scope.query_properties_ex(space, offset, size, usepoint, parent, property);
    let up = match usepoint {
        None => "inv".to_string(),
        Some(up) => format!("{up:#x}"),
    };
    let line = match &out.entry {
        None => format!(
            "case={case}|kind=qp|query={offset:#x}:{size:x}|up={up}|result=null|flags={:#x}|scope={}",
            out.flags,
            scope_tag(out.final_scope)
        ),
        Some(e) => {
            let name = match out.final_scope {
                rudra::varmap::QueryFinalScope::Parent => &parent.unwrap().symbols[e.sym].name,
                _ => &scope.symbols[e.sym].name,
            };
            format!(
                "case={case}|kind=qp|query={offset:#x}:{size:x}|up={up}|result={name}|first={:#x}|last={:#x}|off={}|flags={:#x}|scope={}",
                e.start, e.last(), e.offset, out.flags, scope_tag(out.final_scope)
            )
        }
    };
    println!("{line}");
}

/// Database flagbase property samples, formatted like dumpProp.
fn dump_prop(case: &str, db: &Database, offsets: &[u64]) {
    let mut line = format!("case={case}");
    for (i, off) in offsets.iter().enumerate() {
        line.push_str(&format!("|p{}={:#x}", i, db.get_property(Address::new(*off))));
    }
    println!("{line}");
}

/// The flagbase changepoint sequence (split points + cumulative values),
/// formatted like dumpChangepoints.
fn dump_changepoints(case: &str, db: &Database) {
    let mut line = format!("case={case}|changepoints={}", db.flagbase.database.len());
    for (addr, val) in &db.flagbase.database {
        line.push_str(&format!("|cp={:#x}:{:#x}", addr.as_u64(), val));
    }
    println!("{line}");
}

/// Build one <mapsym> element: <mapsym><symbol name=..><type ../></symbol>
/// <addr offset=../><rangelist/></mapsym> — the marshal mirror of the .cc
/// XML form.
fn mapsym_element(name: &str, offset: u64) -> Element {
    let mut mapsym = Element::new();
    mapsym.set_name("mapsym");
    let mut symbol = Element::new();
    symbol.set_name("symbol");
    symbol.add_attribute("name", name);
    let mut ty = Element::new();
    ty.set_name("type");
    ty.add_attribute("name", "int");
    ty.add_attribute("size", "4");
    ty.add_attribute("metatype", "int");
    symbol.add_child(Arc::new(RwLock::new(ty)));
    let mut addr = Element::new();
    addr.set_name("addr");
    addr.add_attribute("space", "ram");
    addr.add_attribute("offset", &format!("{offset:#x}"));
    let mut rangelist = Element::new();
    rangelist.set_name("rangelist");
    mapsym.add_child(Arc::new(RwLock::new(symbol)));
    mapsym.add_child(Arc::new(RwLock::new(addr)));
    mapsym.add_child(Arc::new(RwLock::new(rangelist)));
    mapsym
}

fn hole_element(first: u64, last: u64) -> Element {
    let mut hole = Element::new();
    hole.set_name("hole");
    hole.add_attribute("space", "ram");
    hole.add_attribute("first", &format!("{first:#x}"));
    hole.add_attribute("last", &format!("{last:#x}"));
    hole.add_attribute("readonly", "true");
    hole
}

/// Build the <db><scope name="" id="0"><symbollist>... document with the
/// given children (document order preserved) and decode it into a fresh
/// Database — the mirror of decodeInterleave. Returns the Database.
fn decode_interleave(registry: &Arc<RwLock<IdRegistry>>, children: Vec<Element>) -> Database {
    let mut db_elem = Element::new();
    db_elem.set_name("db");
    let mut scope = Element::new();
    scope.set_name("scope");
    scope.add_attribute("name", "");
    scope.add_attribute("id", "0");
    let mut symbollist = Element::new();
    symbollist.set_name("symbollist");
    for child in children {
        symbollist.add_child(Arc::new(RwLock::new(child)));
    }
    scope.add_child(Arc::new(RwLock::new(symbollist)));
    db_elem.add_child(Arc::new(RwLock::new(scope)));
    let mut db = Database::new(false);
    let mut dec = TreeDecoder::new(Arc::new(RwLock::new(db_elem)), registry.clone());
    db.decode(&mut dec);
    db
}

/// The interleave observation: queryByAddr each mapsym (exact address,
/// invalid usepoint) and print name + getAllFlags, then the property
/// samples from the seam flagbase the <hole> wrote into (this Database's
/// own — production decodes glb->symboltab into itself, database.cc:2684).
fn run_interleave(
    case: &str,
    registry: &Arc<RwLock<IdRegistry>>,
    children: Vec<Element>,
    names: &[&str],
    addrs: &[u64],
) {
    let db = decode_interleave(registry, children);
    let global = db.get_global_scope().unwrap();
    for (name, addr) in names.iter().zip(addrs.iter()) {
        let res = Scope::query_by_addr(&[global], Address::new(*addr), Address::new(0));
        match res {
            None => println!("case={case}|sym={name}|result=null"),
            Some((_s, e)) => {
                let entry = &global.entries[e];
                let sym_name = entry.symbol.read().unwrap().name.clone();
                println!(
                    "case={case}|sym={name}|result={sym_name}|flags={:#x}",
                    entry.get_all_flags()
                );
            }
        }
    }
    println!(
        "case={case}-prop|p0={:#x}|p1={:#x}",
        db.get_property(Address::new(addrs[0])),
        db.get_property(Address::new(addrs[1])),
    );
}

fn make_registry() -> Arc<RwLock<IdRegistry>> {
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    {
        let mut r = registry.write().unwrap();
        for nm in &[
            "name", "id", "label", "first", "last", "readonly", "volatile",
            "space", "offset", "val", "size", "metatype",
        ] {
            r.register_attribute(nm);
        }
        for nm in &[
            "db", "scope", "parent", "symbollist", "mapsym", "symbol",
            "type", "addr", "rangelist", "range", "hole", "property_changepoint",
        ] {
            r.register_element(nm);
        }
    }
    registry
}

fn main() {
    let registry = make_registry();

    // setup: space indices of Rugra's canonical model (the locked
    // BfdArchitecture prints const=0, unique=2, ram=3, stack=8).
    println!(
        "case=setup|const_index={}|ram_index={}|stack_index={}|unique_index={}",
        ghidra_space_index(&AddressSpace::Const),
        ghidra_space_index(&AddressSpace::Ram),
        ghidra_space_index(&AddressSpace::Stack),
        ghidra_space_index(&AddressSpace::Unique),
    );

    // fb_accumulate: readonly [0x7e100000,0x7e1000ff] + volatile
    // [0x7e100080,0x7e10017f] — shared partitions accumulate.
    let mut fdb = Database::new(false);
    fdb.set_property_range(symbol_flags::READONLY, ram_range(0x7e100000, 0x7e1000ff));
    fdb.set_property_range(symbol_flags::VOLATIL, ram_range(0x7e100080, 0x7e10017f));
    dump_prop(
        "fb_accumulate",
        &fdb,
        &[0x7e0fffff, 0x7e100040, 0x7e1000a0, 0x7e100120, 0x7e100180],
    );

    // fb_clear_subrange: clear readonly over [0x7e100040,0x7e10005f].
    fdb.clear_property_range(symbol_flags::READONLY, ram_range(0x7e100040, 0x7e10005f));
    dump_prop(
        "fb_clear_subrange",
        &fdb,
        &[0x7e100030, 0x7e100050, 0x7e100060, 0x7e1000a0],
    );

    // fb_roundtrip: a manually populated Database encodes its flagbase as
    // <property_changepoint> split points; decoding assigns each split
    // point its exact value (database.cc:3334), preserving boundaries.
    {
        use rudra::marshal::TreeEncoder;
        let mut db1 = Database::new(false);
        db1.set_property_range(symbol_flags::READONLY, ram_range(0x7e110000, 0x7e1100ff));
        db1.set_property_range(symbol_flags::VOLATIL, ram_range(0x7e110080, 0x7e11017f));
        db1.clear_property_range(symbol_flags::READONLY, ram_range(0x7e1100c0, 0x7e1100df));
        let mut enc = TreeEncoder::new(registry.clone());
        db1.encode(&mut enc);
        let doc = enc.into_document();
        let root = doc.get_root().unwrap().clone();
        let mut db2 = Database::new(false);
        let mut dec = TreeDecoder::new(root, registry.clone());
        db2.decode(&mut dec);
        dump_changepoints("fb_roundtrip", &db2);
        dump_prop(
            "fb_roundtrip_prop",
            &db2,
            &[0x7e110040, 0x7e1100a0, 0x7e1100d0, 0x7e110120],
        );
    }

    // fb_hole_interleave: mapsym BEFORE the hole installs without the
    // fold; mapsym AFTER folds (document order, database.cc:2768-2784).
    run_interleave(
        "fb_hole_interleave",
        &registry,
        vec![
            mapsym_element("pre_victim", 0x7e120000),
            hole_element(0x7e120000, 0x7e1200ff),
            mapsym_element("post_folded", 0x7e120010),
        ],
        &["pre_victim", "post_folded"],
        &[0x7e120000, 0x7e120010],
    );
    // Same content, hole FIRST: both mapsyms fold.
    run_interleave(
        "fb_hole_interleave_flipped",
        &registry,
        vec![
            hole_element(0x7e130000, 0x7e1300ff),
            mapsym_element("hole_first_a", 0x7e130000),
            mapsym_element("hole_first_b", 0x7e130010),
        ],
        &["hole_first_a", "hole_first_b"],
        &[0x7e130000, 0x7e130010],
    );

    // The ScopeLocal fold block. The property closures model the Database
    // flagbase exactly as the .cc installed it (per-range, cumulative).
    let mut scope = ScopeLocal::new();
    scope.space = AddressSpace::Stack;
    // symboltab->addRange(lm, stack, 0x900, 0xfff): the scope-only branch
    // owns the window.
    scope.local_range = vec![(0x900, 0xfff)];

    // fold_ro_after: property FIRST, then the symbol.
    let ro_stack = |space: AddressSpace, off: u64| -> u32 {
        if space == AddressSpace::Stack && (0x900..=0x97f).contains(&off) {
            varnode_flags::READONLY
        } else if space == AddressSpace::Stack && (0xb00..=0xb5f).contains(&off) {
            varnode_flags::READONLY
        } else if space == AddressSpace::Stack && (0xc04..=0xc0f).contains(&off) {
            varnode_flags::READONLY
        } else if space == AddressSpace::Stack && (0xd00..=0xd7f).contains(&off) {
            varnode_flags::READONLY
        } else {
            0
        }
    };
    let vol_stack = |space: AddressSpace, off: u64| -> u32 {
        if space == AddressSpace::Stack && (0xa00..=0xa7f).contains(&off) {
            varnode_flags::VOLATIL
        } else if space == AddressSpace::Stack && (0xb20..=0xb7f).contains(&off) {
            varnode_flags::VOLATIL
        } else {
            0
        }
    };
    let full_property = move |space: AddressSpace, off: u64| -> u32 {
        ro_stack(space, off) | vol_stack(space, off)
    };
    // The full flagbase as of each case's install time (construction
    // order): ranges accumulate onto the closure exactly when the .cc
    // setPropertyRange ran.
    let prop_ro_after = |space: AddressSpace, off: u64| -> u32 { ro_stack(space, off) };
    let prop_vol_after = |space: AddressSpace, off: u64| -> u32 {
        prop_ro_after(space, off) | vol_stack(space, off)
    };

    scope.install_symbol_with_property(sym("foldro", AddressSpace::Stack, 0x900, 4, None), &prop_ro_after);
    dump_qp("fold_ro_after", &scope, None, &prop_ro_after, AddressSpace::Stack, 0x902, 2, None);

    scope.install_symbol_with_property(sym("foldvol", AddressSpace::Stack, 0xa00, 4, None), &prop_vol_after);
    dump_qp("fold_vol_after", &scope, None, &prop_vol_after, AddressSpace::Stack, 0xa02, 2, None);

    // fold_overlap: the fold reads the property at each mapping START.
    scope.install_symbol_with_property(sym("foldboth", AddressSpace::Stack, 0xb20, 4, None), &prop_vol_after);
    scope.install_symbol_with_property(sym("foldroonly", AddressSpace::Stack, 0xb10, 4, None), &prop_vol_after);
    scope.install_symbol_with_property(sym("foldvolonly", AddressSpace::Stack, 0xb60, 4, None), &prop_vol_after);
    dump_qp("fold_overlap_both", &scope, None, &prop_vol_after, AddressSpace::Stack, 0xb22, 2, None);
    dump_qp("fold_overlap_ro_only", &scope, None, &prop_vol_after, AddressSpace::Stack, 0xb12, 2, None);
    dump_qp("fold_overlap_vol_only", &scope, None, &prop_vol_after, AddressSpace::Stack, 0xb62, 2, None);

    // fold_tail_overlap: the range starts INSIDE the symbol extent —
    // nothing folds (the fold reads entry.addr only).
    scope.install_symbol_with_property(sym("tailover", AddressSpace::Stack, 0xc00, 8, None), &prop_vol_after);
    dump_qp("fold_tail_overlap", &scope, None, &prop_vol_after, AddressSpace::Stack, 0xc00, 4, None);

    // fold_usepoint_guard: a usepoint-restricted map inside a readonly
    // range takes neither addrtied nor the fold.
    scope.install_symbol_with_property(sym("guarded", AddressSpace::Stack, 0xd00, 4, Some(0x1000)), &prop_vol_after);
    dump_qp("fold_usepoint_guard_hit", &scope, None, &prop_vol_after, AddressSpace::Stack, 0xd00, 4, Some(0x1000));
    dump_qp("fold_usepoint_guard_miss", &scope, None, &prop_vol_after, AddressSpace::Stack, 0xd00, 4, None);

    // fold_victim_before: symbol FIRST, property AFTER — no fold into its
    // flags; the property shows only through the query-time getProperty.
    scope.install_symbol_with_property(sym("victim2", AddressSpace::Stack, 0xe00, 4, None), &prop_vol_after);
    let prop_victim = |space: AddressSpace, off: u64| -> u32 {
        if space == AddressSpace::Stack && (0xe00..=0xe7f).contains(&off) {
            prop_vol_after(space, off) | varnode_flags::READONLY
        } else {
            prop_vol_after(space, off)
        }
    };
    dump_qp("fold_victim_before", &scope, None, &prop_victim, AddressSpace::Stack, 0xe02, 2, None);
    dump_qp("fold_victim_scope_only", &scope, None, &prop_victim, AddressSpace::Stack, 0xe40, 1, None);

    // fold_global_persist: a global-scope symbol in a readonly ram range —
    // persist AND the fold both land (persist derives from
    // is_global_scope, the entry projection of database.cc:1131-1132).
    let mut parent = ScopeLocal::new();
    parent.is_global_scope = true;
    parent.space = AddressSpace::Ram;
    let ram_property = |space: AddressSpace, off: u64| -> u32 {
        if space == AddressSpace::Ram && (0x7e140000..=0x7e1400ff).contains(&off) {
            varnode_flags::READONLY
        } else if space == AddressSpace::Ram && (0x7e150000..=0x7e1500ff).contains(&off) {
            varnode_flags::READONLY
        } else {
            0
        }
    };
    parent.install_symbol_with_property(sym("gfold", AddressSpace::Ram, 0x7e140000, 8, None), &ram_property);
    dump_qp("fold_global_persist", &parent, None, &ram_property, AddressSpace::Ram, 0x7e140002, 2, None);

    // fold_discovery_clear: database.cc:1133-1142 — a LOCAL symbol mapped
    // at an address in the GLOBAL scope's discovery range with a usepoint:
    // persist + uselimit CLEAR, which feeds addrtied + the readonly fold,
    // so the entry answers at an INVALID usepoint. The global window is
    // [0x7e150000,0x7e1500ff] (the .cc addRange); a ScopeLocal entry in
    // ram models the cross-space local mapping.
    let mut gscope = ScopeLocal::new();
    gscope.is_global_scope = true;
    gscope.space = AddressSpace::Ram;
    gscope.local_range = vec![(0x7e150000, 0x7e1500ff)];
    let in_global_discovery =
        |space: AddressSpace, off: u64| -> bool { space == AddressSpace::Ram && (0x7e150000..=0x7e1500ff).contains(&off) };
    scope.install_symbol_addmap(
        sym("discovery", AddressSpace::Ram, 0x7e150010, 4, Some(0x1000)),
        &ram_property,
        Some(&in_global_discovery),
    );
    dump_qp("fold_discovery_clear", &scope, Some(&gscope), &ram_property, AddressSpace::Ram, 0x7e150010, 4, None);
    // The cleared uselimit: the entry answers without one.
    {
        let entry = scope.find_addr_entry(AddressSpace::Ram, 0x7e150010, None);
        let name = entry
            .as_ref()
            .map(|e| scope.symbols[e.sym].name.clone())
            .unwrap_or_else(|| "null".to_string());
        let empty = entry
            .as_ref()
            .map(|e| e.uselimit.is_empty())
            .unwrap_or(false);
        println!("case=fold_discovery_uselimit|result={name}|uselimit_empty={}", empty as i32);
    }
    let _ = full_property;
}
