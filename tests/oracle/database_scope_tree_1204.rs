/*
 * Rugra comparand for DATABASE-SCOPE-TREE-FIXTURE-0001
 * (MIGW1-DATABASE-0005 phase 2), the bilateral twin of
 * tests/oracle/database_scope_tree_1204.cc.
 *
 * Exercises the same Scope name/tree query surface under the same
 * anchors:
 *
 *   Scope::hashScopeName           database.cc:880-895
 *   Scope::resolveScope            database.cc:1315-1345
 *   Scope::isSubScope              database.cc:1432-1441
 *   Scope::getFullName             database.cc:1443-1454
 *   Scope::getScopePath            database.cc:1458-1474
 *   Scope::findDistinguishingScope database.cc:1481-1504
 *   Symbol::getResolutionDepth     database.cc:323-360
 *   ScopeInternal::isNameUsed      database.cc:2417-2432
 *   Scope::overrideSizeLockType    database.cc:1387-1397
 *   Scope::resetSizeLockType       database.cc:1402-1408
 *   Scope::attachScope             database.cc:857-862
 *   Scope::detachScope             database.cc:866-872
 *   Database::clearReferences      database.cc:2893-2904
 *   Database::adjustCaches         database.cc:2975-2982
 *
 * All projections are id/name/size/message-level: pointer values are
 * never printed.  Tree ids are chosen explicitly so both comparands see
 * identical uniqueIds (the C++ Database ctor creates no global scope,
 * database.cc:2924-2931 — the eager id-0 placeholder of Rust's
 * Database::new is replaced by the explicit-id global exactly as the
 * C++ fixture attaches its own global via attachScope(global, null)).
 * Data-type identity prints as name+size (never the raw metatype enum).
 *
 * The TypeFactory uses the standalone SLEIGH core-type table
 * (CoreTypeFlavor::Standalone = sleigh_arch.cc:229-232), mirroring the
 * oracle's BfdArchitecture environment, so getBase(size, TYPE_UNKNOWN)
 * resolves the same xunknownN core types on both sides.
 */

use rudra::address::{Address, Range, RangeList};
use rudra::database::{symbol_flags, Database, Scope, Symbol};
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};

fn hex64(v: u64) -> String {
    format!("{:016x}", v)
}

/// The C++ Database ctor (database.cc:2924-2931) leaves globalscope null;
/// the fixture's attachScope(global, nullptr) then registers the
/// explicit-id global.  The Rust mirror: replace Database::new's eager
/// id-0 placeholder with the same explicit-id global.
fn new_database_with_global(id_by_name: bool, global_id: u64) -> Database {
    let mut db = Database::new(id_by_name);
    db.scopes.remove(&0);
    db.scopes.insert(global_id, Scope::new(global_id, "", 0));
    db.global_scope_id = global_id;
    db
}

/// Mirror of the C++ hashViaProduction: the raw hashScopeName value is
/// observed through its production caller findCreateScopeFromSymbolName
/// (database.cc:3165) — the id of the scope that call CREATES under a
/// pinned parent id IS the hash.
fn hash_via_production(
    db: &mut Database,
    parent_id: u64,
    nm: &str,
) -> Result<u64, &'static str> {
    let (scope_id, _base) =
        db.find_create_scope_from_symbol_name(&format!("{}::tail", nm), "::", Some(parent_id))?;
    Ok(scope_id)
}

struct Tree {
    db: Database,
    global: u64,
    a: u64,
    b: u64,
    c: u64,
}

fn make_tree(id_by_name: bool) -> Tree {
    let mut db = new_database_with_global(id_by_name, 100);
    let a = db.find_create_scope(101, "a", 100);
    let b = db.find_create_scope(102, "b", a);
    let c = db.find_create_scope(103, "c", a);
    Tree { db, global: 100, a, b, c }
}

fn emit_hash_cases() {
    // The crc cascade, including the signed-char feed for name bytes
    // >= 0x80 (cc:887-890: `uint4 val = nm[i]` reads a signed char, so
    // high bytes sign-extend into the uint4).  The signed-byte case uses
    // "\u{ff}" = UTF-8 bytes [0xC3, 0xBF] — both high bytes sign-extend —
    // because the Rust name channel is a UTF-8 &str and the bilateral
    // pair must feed the same byte sequence on both sides (the C++ twin
    // passes the raw "\xc3\xbf").
    let mut db = new_database_with_global(true, 100);
    let big = db.find_create_scope(0x1122_3344_5566_7788, "p", 100);
    let feed = db.find_create_scope(0xfedc_ba98_7654_3210, "q", big);

    let alpha = hash_via_production(&mut db, 100, "alpha").unwrap();
    println!("case=hash_name_zero_alpha|{}", hex64(alpha));
    let mixed = hash_via_production(&mut db, big, "a").unwrap();
    println!("case=hash_name_mixed|{}", hex64(mixed));
    // NOTE (mirroring the C++ comment): the empty-name hash input has no
    // production observable — findCreateScopeFromSymbolName routes ""
    // through attachScope, which rejects empty non-global scope names
    // (database.cc:2958-2959), and no other production caller exposes the
    // raw hash.  The Rust unit test pins value determinism for that input
    // only.
    let signed_byte = hash_via_production(&mut db, 100, "\u{ff}").unwrap();
    println!("case=hash_name_signed_byte|{}", hex64(signed_byte));
    let signed_bytes = hash_via_production(&mut db, feed, "a\u{80}z").unwrap();
    println!("case=hash_name_signed_bytes|{}", hex64(signed_bytes));
}

fn emit_resolve_cases() {
    let mut t = make_tree(true); // idByName: the hash-strategy cases need it
    let db = &mut t.db;
    let (global, a, b) = (t.global, t.a, t.b);

    // database.cc:1336-1343 — linear scan branch.
    println!(
        "case=resolve_linear_hit|{}",
        match db.resolve_scope_by_name(global, "a", false) {
            Some(id) if id == a => "101",
            _ => "other",
        }
    );
    println!(
        "case=resolve_linear_miss|{}",
        match db.resolve_scope_by_name(global, "zzz", false) {
            None => "null",
            Some(_) => "nonnull",
        }
    );
    println!(
        "case=resolve_linear_nested|{}",
        match db.resolve_scope_by_name(a, "b", false) {
            Some(id) if id == b => "102",
            _ => "other",
        }
    );

    // database.cc:1326-1334 — decimal direct id branch.  Child 101 is
    // addressable by the string "101"; trailing junk parses the prefix
    // (istringstream >> semantics).
    println!(
        "case=resolve_decimal_hit|{}",
        match db.resolve_scope_by_name(global, "101", false) {
            Some(id) if id == a => "101",
            _ => "other",
        }
    );
    println!(
        "case=resolve_decimal_prefix|{}",
        match db.resolve_scope_by_name(global, "101x", false) {
            Some(id) if id == a => "101",
            _ => "other",
        }
    );
    println!(
        "case=resolve_decimal_miss|{}",
        match db.resolve_scope_by_name(global, "999", false) {
            None => "null",
            Some(_) => "nonnull",
        }
    );

    // database.cc:1318-1325 — hash strategy branch: child keyed by the
    // hash of its name under the parent id, returned only on name match.
    let hashed = hash_via_production(db, global, "hashed").unwrap();
    println!(
        "case=resolve_hash_hit|{}",
        match db.resolve_scope_by_name(global, "hashed", true) {
            Some(id) if id == hashed => hex64(hashed),
            _ => "other".to_string(),
        }
    );
    println!(
        "case=resolve_hash_name_mismatch|{}",
        match db.resolve_scope_by_name(global, "other", true) {
            None => "null",
            Some(_) => "nonnull",
        }
    );
    println!(
        "case=resolve_hash_absent|{}",
        match db.resolve_scope_by_name(global, "nokey", true) {
            None => "null",
            Some(_) => "nonnull",
        }
    );
}

fn emit_tree_cases() {
    let mut t = make_tree(false);
    let db = &mut t.db;
    let (global, a, b, c) = (t.global, t.a, t.b, t.c);

    // database.cc:1443-1454.
    println!("case=fullname_b|{}", db.get_full_name(b));
    println!("case=fullname_a|{}", db.get_full_name(a));
    println!("case=fullname_global_len|{}", db.get_full_name(global).len());

    // database.cc:1458-1474 — path includes global and self.
    let path = db.get_scope_path(b);
    let ids: Vec<String> = path.iter().map(|id| id.to_string()).collect();
    println!("case=scopespath_b|{}", ids.join(","));

    // database.cc:1432-1441.
    println!("case=issub_self|{}", db.is_sub_scope(b, b) as u8);
    println!("case=issub_parent|{}", db.is_sub_scope(b, a) as u8);
    println!("case=issub_global|{}", db.is_sub_scope(b, global) as u8);
    println!("case=issub_reverse|{}", db.is_sub_scope(a, b) as u8);
    println!("case=issub_global_of_child|{}", db.is_sub_scope(global, b) as u8);

    // database.cc:1481-1504.
    println!(
        "case=distinguish_same|{}",
        match db.find_distinguishing_scope(b, b) {
            None => "null",
            Some(_) => "nonnull",
        }
    );
    println!(
        "case=distinguish_parent|{}",
        match db.find_distinguishing_scope(b, a) {
            Some(id) if id == b => "102",
            _ => "other",
        }
    );
    println!(
        "case=distinguish_child|{}",
        match db.find_distinguishing_scope(a, b) {
            None => "null",
            Some(_) => "nonnull",
        }
    );
    println!(
        "case=distinguish_sibling|{}",
        match db.find_distinguishing_scope(b, c) {
            Some(id) if id == b => "102",
            _ => "other",
        }
    );
    println!(
        "case=distinguish_sibling_rev|{}",
        match db.find_distinguishing_scope(c, b) {
            Some(id) if id == c => "103",
            _ => "other",
        }
    );
    println!(
        "case=distinguish_from_global|{}",
        match db.find_distinguishing_scope(b, global) {
            Some(id) if id == a => "101",
            _ => "other",
        }
    );
    println!(
        "case=distinguish_global_from|{}",
        match db.find_distinguishing_scope(global, b) {
            None => "null",
            Some(_) => "nonnull",
        }
    );

    // database.cc:857-862 / 866-872 — attach/detach observables via the
    // production registration path (Database::attachScope →
    // Scope::attachScope; Database::deleteScope → clearReferences +
    // Scope::detachScope).
    let extra = db.attach_scope("extra", a);
    let a_children = db.resolve_scope(a).map(|s| s.children.len()).unwrap_or(0);
    println!("case=attach_child_count|{}", a_children);
    let parent_alias = db
        .resolve_scope(extra)
        .map(|s| s.parent_id == a)
        .unwrap_or(false);
    println!("case=attach_child_parent_alias|{}", parent_alias as u8);
    db.delete_scope(extra);
    let a_children = db.resolve_scope(a).map(|s| s.children.len()).unwrap_or(0);
    println!("case=detach_child_count|{}", a_children);
}

fn emit_resolution_depth_cases() {
    // global :: ns(110) :: inner(111); symbol "x" in ns.
    let mut db = new_database_with_global(false, 100);
    let ns = db.find_create_scope(110, "ns", 100);
    let inner = db.find_create_scope(111, "inner", ns);
    let x = {
        let scope = db.resolve_scope_mut(ns).unwrap();
        let id = scope.add_symbol("x", "fixture_i32");
        scope.symbols[&id].clone()
    };

    // database.cc:326 — same scope.
    println!("case=resdepth_same|{}", db.get_resolution_depth(&x, Some(ns)));
    // database.cc:327-335 — null use scope: full path minus global.
    println!("case=resdepth_null|{}", db.get_resolution_depth(&x, None));
    // database.cc:343-358 — ancestor use, no collision: ns is an
    // ancestor of inner (findDistinguishingScope → null) and "x" is not
    // used in inner.
    println!("case=resdepth_ancestor|{}", db.get_resolution_depth(&x, Some(inner)));
    // Memo repeat (database.hh:190-191): the second query with the same
    // use scope short-circuits and must return the same value.
    println!("case=resdepth_memo_repeat|{}", db.get_resolution_depth(&x, Some(inner)));

    // Collision (database.cc:357-358): a same-named symbol in the use
    // scope forces one more distinguishing name.  Fresh symbol, because
    // the memo would otherwise answer stale.
    let x2 = {
        let scope = db.resolve_scope_mut(ns).unwrap();
        let id = scope.add_symbol("x2", "fixture_i32");
        scope.symbols[&id].clone()
    };
    db.resolve_scope_mut(inner)
        .unwrap()
        .add_symbol("x2", "fixture_i32");
    println!("case=resdepth_collision|{}", db.get_resolution_depth(&x2, Some(inner)));

    // Sibling use scope: quick check 4 (same parents) → distinguish ns.
    let sib = db.find_create_scope(112, "sib", 100);
    println!("case=resdepth_sibling|{}", db.get_resolution_depth(&x, Some(sib)));
}

fn emit_size_lock_cases() {
    let types = TypeFactory::new_flavor(8, CoreTypeFlavor::Standalone);
    let unknown4 = types.get_base(4, rudra::type_system::datatype::TypeMetatype::Unknown).unwrap();
    let int4 = types.get_base(4, rudra::type_system::datatype::TypeMetatype::Int).unwrap();
    let int8 = types.get_base(8, rudra::type_system::datatype::TypeMetatype::Int).unwrap();
    let mut db = new_database_with_global(false, 100);
    let global = db.global_scope_id;

    // A size-locked symbol: typelock + unknown type (size_typelock on).
    let locked = {
        let scope = db.resolve_scope_mut(global).unwrap();
        let id = scope.add_symbol("locked", "");
        let sym = scope.symbols[&id].clone();
        {
            let mut w = sym.write().unwrap();
            w.flags |= symbol_flags::TYPELOCK;
            w.dtype = Some(unknown4.clone());
            w.check_size_type_lock();
        }
        (id, sym)
    };
    let is_locked = locked.1.read().unwrap().is_size_type_locked();
    println!("case=sizelock_flag|{}", is_locked as u8);

    // database.cc:1387-1397 — same-size override succeeds.
    match db
        .resolve_scope_mut(global)
        .unwrap()
        .override_size_lock_type(locked.0, int4.clone())
    {
        Ok(()) => {
            let w = locked.1.read().unwrap();
            let dt = w.dtype.as_ref().unwrap();
            println!("case=override_ok|ok|name={}|size={}", dt.get_name(), dt.get_size());
        }
        Err(message) => println!("case=override_ok|error:{}", message),
    }
    // Different size throws with the exact message.
    match db
        .resolve_scope_mut(global)
        .unwrap()
        .override_size_lock_type(locked.0, int8.clone())
    {
        Ok(()) => println!("case=override_size_mismatch|no-throw"),
        Err(message) => println!("case=override_size_mismatch|{}", message),
    }
    // database.cc:1402-1408 — reset restores the unknown base of the
    // same size.
    db.resolve_scope_mut(global)
        .unwrap()
        .reset_size_lock_type(locked.0, &types);
    {
        let w = locked.1.read().unwrap();
        let dt = w.dtype.as_ref().unwrap();
        println!("case=reset_sizelock|name={}|size={}", dt.get_name(), dt.get_size());
    }
    // Reset of an already-unknown type is a no-op (cc:1405).
    db.resolve_scope_mut(global)
        .unwrap()
        .reset_size_lock_type(locked.0, &types);
    {
        let w = locked.1.read().unwrap();
        let dt = w.dtype.as_ref().unwrap();
        println!("case=reset_sizelock_idempotent|name={}", dt.get_name());
    }

    // Not size-locked symbol → the other exact message.
    let plain = {
        let scope = db.resolve_scope_mut(global).unwrap();
        let id = scope.add_symbol("plain", "");
        let sym = scope.symbols[&id].clone();
        {
            let mut w = sym.write().unwrap();
            w.dtype = Some(int4.clone());
        }
        (id, sym)
    };
    match db
        .resolve_scope_mut(global)
        .unwrap()
        .override_size_lock_type(plain.0, int4.clone())
    {
        Ok(()) => println!("case=override_not_locked|no-throw"),
        Err(message) => println!("case=override_not_locked|{}", message),
    }
}

fn emit_clear_reference_cases() {
    let mut t = make_tree(false);
    let db = &mut t.db;
    let (global, a, b) = (t.global, t.a, t.b);

    // Ownership ranges so the resolvemap has entries: a owns
    // [0x1000,0x1fff] (Database::setRange → fillResolve).
    let rlist = {
        let mut rl = RangeList::new();
        rl.insert_range(Range::new(Address::new(0x1000), Address::new(0x1fff)).unwrap());
        rl
    };
    db.set_range(a, &rlist);
    let probe = Address::new(0x1800);
    println!(
        "case=mapscope_owner|{}",
        match db.map_scope(global, probe) {
            id if id == a => "101",
            _ => "other",
        }
    );

    // database.cc:2893-2904 — clearReferences is a Database private whose
    // recursion (children first, then idmap.erase, then clearResolve for
    // non-global scopes) is observable through its production caller
    // Database::deleteScope (database.cc:2988).  b first: b owns no
    // ranges, so only the idmap entry goes; then a: the recursion covers
    // c and removes a's resolvemap ranges.
    db.delete_scope(b);
    println!(
        "case=clearref_resolve_b|{}",
        match db.resolve_scope(102) {
            None => "null",
            Some(_) => "nonnull",
        }
    );
    db.delete_scope(a);
    println!(
        "case=clearref_resolve_a|{}",
        match db.resolve_scope(101) {
            None => "null",
            Some(_) => "nonnull",
        }
    );
    println!(
        "case=clearref_resolve_c|{}",
        match db.resolve_scope(103) {
            None => "null",
            Some(_) => "nonnull",
        }
    );
    println!(
        "case=clearref_mapscope_default|{}",
        match db.map_scope(global, probe) {
            id if id == global => "global",
            _ => "other",
        }
    );
}

fn emit_adjust_caches_case() {
    // database.cc:2975-2982 — every scope in the idmap adjusts; this is
    // observable as a no-throw sweep whose scope membership is unchanged.
    let mut t = make_tree(false);
    t.db.adjust_caches();
    let present: String = [100u64, 101, 102, 103]
        .iter()
        .map(|id| if t.db.resolve_scope(*id).is_some() { '1' } else { '0' })
        .collect();
    println!("case=adjust_caches|ok|scopes={}", present);
}

fn main() {
    emit_hash_cases();
    emit_resolve_cases();
    emit_tree_cases();
    emit_resolution_depth_cases();
    emit_size_lock_cases();
    emit_clear_reference_cases();
    emit_adjust_caches_case();
    // Silence the unused-import lint for the Symbol type re-exported as
    // part of the fixture's compile-time API surface.
    let _ = std::any::type_name::<Symbol>();
}
