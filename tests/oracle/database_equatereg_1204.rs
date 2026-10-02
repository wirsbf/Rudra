//! DATABASE-EQUATE-VALUE-REGISTRY-0001: Rudra side of the locked 12.0.4
//! oracle fixture for `Scope::addEquateSymbol` (database.cc:1712-1724) +
//! the EquateSymbol constructor state (database.cc:624-631) through the
//! addSymbolInternal category registration (database.cc:1827-1836).
//!
//! Mirrors `database_equatereg_1204.cc` case-for-case (same names, same
//! observation format) against the pinned rudra source:
//!   er_single/er_dup: case|cat|catindex|cat_size|is_equate|value|
//!                     id_nonzero|dyn_delta
//!   er_dup_ids:       case|ids_differ
//!   er_scope_local:   case|cat|catindex|local_cat_size|global_cat_size|
//!                     is_equate|value|global_unchanged
//!   er_scope_local_table: case|same_object|value
//!   er_pipe_*:        case|src_symbol|dst_symbol
//!
//! The C++ subtype identity (`dynamic_cast<EquateSymbol*>`, varnode.cc:516)
//! is read through `equate_symbol_registry::query_value` on the registered
//! symbol Arc — the identity `Scope::add_equate_symbol` itself registers.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::database::{display_flags, Scope};
use rudra::varnode::{equate_symbol_registry, Varnode};

// Mirror of the C++ observeAdded (database_equatereg_1204.cc): the
// category/value state of one addEquateSymbol result plus the scope's
// category[equate] size and the dynamic-entry delta of that add.
fn observe_added(scope: &Scope, id: u64, cat_size: usize, dyn_delta: usize, name: &str) {
    let sym_arc = scope.symbols.get(&id).cloned().unwrap();
    let (cat, catindex, id_nonzero) = {
        let s = sym_arc.read().unwrap();
        (
            s.get_category() as i64,
            s.get_category_index() as u64,
            if s.get_id() != 0 { 1 } else { 0 },
        )
    };
    // dynamic_cast<EquateSymbol*> stand-in: query_value returns the subtype
    // payload the cast would expose.
    let (is_equate, value) = match equate_symbol_registry::query_value(&sym_arc) {
        Some(v) => (1, v),
        None => (0, 0u64),
    };
    println!(
        "case={name}|cat={cat}|catindex={catindex}|cat_size={cat_size}|is_equate={is_equate}|value={value}|id_nonzero={id_nonzero}|dyn_delta={dyn_delta}"
    );
}

// Sections 1 + 2: single add and same-value duplicate on the global scope.
fn run_global_scope(scope: &mut Scope) {
    let before1 = scope.dynamic_entries.len();
    let (_, id1) = scope.add_equate_symbol(
        "REG_EQ", display_flags::FORCE_HEX, 66, Address::new(0), 0x1111,
    );
    let cat_size1 = scope.get_category_size(1);
    let dyn_delta1 = scope.dynamic_entries.len() - before1;
    observe_added(scope, id1, cat_size1, dyn_delta1, "er_single");

    let before2 = scope.dynamic_entries.len();
    let (_, id2) = scope.add_equate_symbol(
        "REG_EQ", display_flags::FORCE_HEX, 66, Address::new(0), 0x2222,
    );
    let cat_size2 = scope.get_category_size(1);
    let dyn_delta2 = scope.dynamic_entries.len() - before2;
    observe_added(scope, id2, cat_size2, dyn_delta2, "er_dup");
    let ids_differ = if id1 != id2 { 1 } else { 0 };
    println!("case=er_dup_ids|ids_differ={ids_differ}");
}

// Section 3: an equate in a separate (function-local) scope — the local
// category table sees exactly its own symbol, the global table is unaffected.
fn run_local_scope(global: &Scope, local: &mut Scope) {
    let global_before = global.get_category_size(1);
    let (_, id) = local.add_equate_symbol(
        "REG_EQ", display_flags::FORCE_HEX, 66, Address::new(0), 0x3333,
    );
    let sym_arc = local.symbols.get(&id).cloned().unwrap();
    let (cat, catindex) = {
        let s = sym_arc.read().unwrap();
        (s.get_category() as i64, s.get_category_index() as u64)
    };
    let (is_equate, value) = match equate_symbol_registry::query_value(&sym_arc) {
        Some(v) => (1, v),
        None => (0, 0u64),
    };
    let global_unchanged = if global.get_category_size(1) == global_before { 1 } else { 0 };
    println!(
        "case=er_scope_local|cat={cat}|catindex={catindex}|local_cat_size={}|global_cat_size={}|is_equate={is_equate}|value={value}|global_unchanged={global_unchanged}",
        local.get_category_size(1),
        global.get_category_size(1)
    );
    // The category table round-trips the same identity (getCategorySymbol,
    // database.hh:733).
    let from_table = local.get_category_symbol(1, 0);
    let same_object = match &from_table {
        Some(t) if Arc::ptr_eq(t, &sym_arc) => 1,
        _ => 0,
    };
    let table_value = from_table
        .as_ref()
        .and_then(equate_symbol_registry::query_value)
        .unwrap_or(0);
    println!("case=er_scope_local_table|same_object={same_object}|value={table_value}");
}

// Section 4: a pipeline-created equate reaching copy_symbol_if_valid.  The
// C++ fixture attaches through the public Funcdata::remapDynamicVarnode
// (funcdata_varnode.cc:1120-1126) which stores the symbol's dynamic whole
// map on the varnode; Rudra's database-side route is the same whole map
// (dynamic_entries) via Varnode::set_symbol_entry.
fn run_pipe(local: &mut Scope) {
    for (name, value, src_const, dst_const) in [
        ("er_pipe_close", 0x33333333u64, 0x33333333u64, 0x33333333u64),
        ("er_pipe_not_close", 0x12345678u64, 0x12345678u64, 0x33333333u64),
    ] {
        let mut src = Varnode::new_constant(src_const, 4);
        let mut dst = Varnode::new_constant(dst_const, 4);
        // Scope::addEquateSymbol (database.cc:1712) + the dynamic whole map
        // attached to the constant (the cc:1301 route stores the equate in
        // the local scope; remapDynamicVarnode stores getFirstWholeMap()).
        let _ = local.add_equate_symbol(
            "", display_flags::FORCE_HEX, value, Address::new(0), 0x4444,
        );
        let entry = local.dynamic_entries.last().cloned().unwrap();
        src.set_symbol_entry(Arc::new(RwLock::new(entry)));
        dst.copy_symbol_if_valid(&src);
        println!(
            "case={name}|src_symbol={}|dst_symbol={}",
            if src.get_symbol_entry().is_some() { 1 } else { 0 },
            if dst.get_symbol_entry().is_some() { 1 } else { 0 }
        );
    }
}

fn main() {
    let mut global = Scope::new(1, "global", 0);
    let mut local = Scope::new(2, "GetStr", 1);
    run_global_scope(&mut global);
    run_local_scope(&global, &mut local);
    run_pipe(&mut local);
}
