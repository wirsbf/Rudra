/*
 * Rudra comparand for DATABASE-RESID7-FIXTURE-0001
 * (MIGW1-DATABASE-0005 residual-seven closure lane, wt/database7).
 *
 * Mirrors tests/oracle/database_resid7_1204.cc case for case through the
 * production src/database.rs value model:
 *
 *   Scope::add_dynamic_map_internal   (database.cc:1874 whole-count)
 *   Scope::category_sanity            (database.cc:1992)
 *   Scope::multi_entry_symbols        (database.hh:813/865 — SymbolNameTree
 *                                      (name, nameDedup) order)
 *   Scope::resolve_external_ref_function (database.cc:2362)
 *   Scope::attach_child/children_begin (database.hh:765 — ScopeMap
 *                                      unique-id ascending order)
 *   Scope::print_entries              (database.cc:2791 — maptable
 *                                      ascending space-index grouping)
 *
 * decodeWrappingAttributes (database.hh:719) has no case: the
 * database-layer base body is `{}` on both sides (no reads, no state);
 * the only override is ScopeLocal (varmap.cc:479), a varmap.rs lease.
 */

use rudra::address::{Address, RangeList};
use rudra::database::Scope;
use rudra::space::{space_flags, AddrSpace, SpaceType};
use rudra::type_system::datatype::TypeMetatype;
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};

fn hexoff(v: u64) -> String {
    format!("{:x}", v)
}

fn main() {
    let mut types = TypeFactory::new_flavor(8, CoreTypeFlavor::Standalone);
    let int4 = types.get_base(4, TypeMetatype::Int).unwrap();
    let ram = AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        4,
        1,
        3,
        space_flags::HASPHYSICAL,
        -1,
        -1,
    );
    let rom = AddrSpace::new_space(
        SpaceType::Processor,
        "rom",
        false,
        4,
        1,
        4,
        space_flags::HASPHYSICAL,
        -1,
        -1,
    );
    let empty = RangeList::new();

    // ---- addDynamicMapInternal whole-count (database.cc:1874-1887) ----
    {
        let mut scope = Scope::new(130, "dyn", 0);
        let a = scope.add_symbol("a", "int");
        scope.symbols[&a].write().unwrap().dtype = Some(int4.clone());
        let is_multi = |s: &Scope, id: u64| {
            (s.symbols[&id].read().unwrap().whole_count > 1) as u8
        };
        scope.add_dynamic_map_internal(a, 0, 0x1234, 0, 4, empty.clone());
        println!("case=dyn_whole_1|multi={}", is_multi(&scope, a));
        let e0 = scope.dynamic_entries[0].print_entry();
        print!("case=dyn_print|{}", e0);
        scope.add_dynamic_map_internal(a, 0, 0x1235, 0, 4, empty.clone());
        println!("case=dyn_whole_2|multi={}", is_multi(&scope, a));
        scope.add_dynamic_map_internal(a, 0, 0x1236, 0, 4, empty.clone());
        println!("case=dyn_whole_3|multi={}", is_multi(&scope, a));
        scope.add_dynamic_map_internal(a, 0, 0x1237, 0, 2, empty.clone());
        println!("case=dyn_partial_add|multi={}", is_multi(&scope, a));
        let e3 = scope.dynamic_entries[3].print_entry();
        print!("case=dyn_print_partial|{}", e3);
        scope.remove_symbol_mappings(a);
        println!("case=dyn_removed|multi={}", is_multi(&scope, a));
        scope.add_dynamic_map_internal(a, 0, 0x1238, 0, 4, empty.clone());
        println!("case=dyn_readd|multi={}", is_multi(&scope, a));
    }

    // ---- multiEntrySet iteration order (database.hh:813/865-866) ----
    {
        let mut scope = Scope::new(131, "order", 0);
        let names = ["zeta", "alpha", "mid", "alpha", "solo"];
        let mut ids = Vec::new();
        for nm in names {
            let id = scope.add_symbol(nm, "int");
            scope.symbols[&id].write().unwrap().dtype = Some(int4.clone());
            ids.push(id);
        }
        // insertNameTree (database.cc:2712-2727) dedups the duplicate
        // "alpha" to nameDedup 1 in the oracle; the value model mirrors
        // the resulting state directly.
        scope.symbols[&ids[3]].write().unwrap().name_dedup = 1;
        let mut base: u64 = 0x1000;
        for (i, &id) in ids.iter().enumerate() {
            let whole = if i < 4 { 2 } else { 1 };
            for j in 0..whole {
                scope.add_map_point(
                    id,
                    Address::with_space(&ram, base + 0x10 * j),
                    Address::new(0),
                    4,
                    None,
                );
            }
            base += 0x100;
        }
        let ordered: Vec<String> = scope
            .multi_entry_symbols()
            .into_iter()
            .map(|id| {
                let sym = scope.symbols[&id].read().unwrap();
                format!("{}#{}", sym.name, sym.name_dedup)
            })
            .collect();
        let count = ordered.len();
        println!("case=multientry_order|{}", ordered.join(","));
        println!("case=multientry_count|{}", count);
    }

    // ---- categorySanity (database.cc:1992-2018) ----
    {
        let mut scope = Scope::new(132, "cats", 0);
        let mut cat_ids = Vec::new();
        for nm in ["s1", "s2", "s3", "s4", "s5"] {
            let id = scope.add_symbol(nm, "int");
            scope.symbols[&id].write().unwrap().dtype = Some(int4.clone());
            cat_ids.push(id);
        }
        scope.set_category(cat_ids[0], 1, 0);
        scope.set_category(cat_ids[1], 1, 0);
        scope.set_category(cat_ids[2], 1, 0);
        scope.set_category(cat_ids[3], 2, 0);
        scope.set_category(cat_ids[4], 2, 0);
        println!(
            "case=cat_pre|c1={}|c2={}",
            scope.get_category_size(1),
            scope.get_category_size(2)
        );
        scope.remove_symbol(cat_ids[1]);
        println!("case=cat_null_hole|c1={}", scope.get_category_size(1));
        scope.category_sanity();
        let cat_of = |s: &Scope, id: u64| s.symbols[&id].read().unwrap().category as i32;
        println!(
            "case=cat_post|c1={}|c2={}|s1={}|s3={}|s4={}|s5={}",
            scope.get_category_size(1),
            scope.get_category_size(2),
            cat_of(&scope, cat_ids[0]),
            cat_of(&scope, cat_ids[2]),
            cat_of(&scope, cat_ids[3]),
            cat_of(&scope, cat_ids[4]),
        );
    }

    // ---- resolveExternalRefFunction (database.cc:2362-2366) ----
    {
        let mut scope = Scope::new(133, "refs", 0);
        let f = scope.add_symbol("fn", "func");
        scope.add_map_point(
            f,
            Address::with_space(&ram, 0x1000),
            Address::new(0),
            4,
            None,
        );
        // The oracle's mapScope returns the query scope itself (empty
        // resolvemap), so queryFunction == findFunction on this scope.
        match scope.resolve_external_ref_function(Address::with_space(&ram, 0x1000)) {
            Some(addr) => {
                let name = scope
                    .symbols
                    .get(&f)
                    .map(|s| s.read().unwrap().name.clone())
                    .unwrap_or_default();
                println!("case=resolve_hit|name={}|addr={}", name, hexoff(addr.as_u64()));
            }
            None => println!("case=resolve_hit|unreachable"),
        }
        let miss =
            scope.resolve_external_ref_function(Address::with_space(&ram, 0x9000));
        println!("case=resolve_miss|{}", miss.is_some() as u8);
    }

    // ---- childrenBegin/childrenEnd order (database.hh:765-766) ----
    {
        // Production registration path mirror: Database::attachScope →
        // parent attach_child upsert on the id-keyed child list.
        let mut db = rudra::database::Database::new(false);
        db.scopes.remove(&0);
        db.scopes.insert(200, Scope::new(200, "", 0));
        db.global_scope_id = 200;
        db.find_create_scope(105, "c105", 200);
        db.find_create_scope(101, "c101", 200);
        db.find_create_scope(103, "c103", 200);
        let ids: Vec<u64> = db
            .resolve_scope(200)
            .map(|s| s.children_begin().cloned().collect::<Vec<u64>>())
            .unwrap_or_default();
        let count = ids.len();
        let rendered: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
        println!("case=children_ids|{}", rendered.join(","));
        println!("case=children_count|{}", count);
    }

    // ---- printEntries multi-space order (database.cc:2791-2804) ----
    {
        let mut scope = Scope::new(134, "multi", 0);
        let mut mids = Vec::new();
        for nm in ["m1", "m2", "m3", "m4"] {
            let id = scope.add_symbol(nm, "int");
            scope.symbols[&id].write().unwrap().dtype = Some(int4.clone());
            mids.push(id);
        }
        scope.add_map_point(
            mids[0],
            Address::with_space(&ram, 0x1000),
            Address::new(0),
            4,
            None,
        );
        scope.add_map_point(
            mids[1],
            Address::with_space(&rom, 0x2000),
            Address::new(0),
            4,
            None,
        );
        scope.add_map_point(
            mids[2],
            Address::with_space(&ram, 0x3000),
            Address::new(0),
            4,
            None,
        );
        scope.add_map_point(
            mids[3],
            Address::with_space(&rom, 0x1000),
            Address::new(0),
            4,
            None,
        );
        print!("case=printentries_multi|{}", scope.print_entries());

        let mut single = Scope::new(135, "onlyrom", 0);
        let r1 = single.add_symbol("r1", "int");
        single.symbols[&r1].write().unwrap().dtype = Some(int4.clone());
        let r2 = single.add_symbol("r2", "int");
        single.symbols[&r2].write().unwrap().dtype = Some(int4.clone());
        single.add_map_point(
            r1,
            Address::with_space(&rom, 0x6000),
            Address::new(0),
            4,
            None,
        );
        single.add_map_point(
            r2,
            Address::with_space(&rom, 0x7000),
            Address::new(0),
            4,
            None,
        );
        print!("case=printentries_single|{}", single.print_entries());
    }
}
