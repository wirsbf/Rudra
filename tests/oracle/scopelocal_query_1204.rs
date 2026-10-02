// Locked Ghidra 12.0.4 ScopeLocal query-layer oracle for
// SCOPELOCAL-QUERY-0001 r2 (Rust side).
//
// Mirrors tests/oracle/scopelocal_query_1204.cc record-for-record: each case
// installs the same symbol/entry table on a hand-built ScopeLocal — the
// entry log (LocalMapEntry) stands in for ScopeInternal::maptable — and
// issues the same findOverlap / findAddr / queryProperties queries through
// rudra::varmap::ScopeLocal. Record formats are byte-identical to the C++
// fixture (std::hex sticky fields mirrored with explicit hex formatting).
//
// Case semantics (see the .cc header for the full rationale):
//   setup                space indices of both models.
//   equal_subsort_*     the second insert's rangemap parts bracket the
//                       first (hinted-before + tail-after), so BOTH walks
//                       answer the second inserted.
//   wide_narrow_*       (last, subsort) cell owner vs the exact-start
//                       descending walk; inUse is uselimit range containment.
//   multi_uselimit_*    two disjoint uselimit ranges; subsort from the first.
//   cross_space_*       per-space maptable dimension.
//   multi_mapping/      one symbol, two entries; removeSymbol drops both.
//   remove_requery_*
//   find_container_*    smallest container, exact-size break, equal tie.
//   partial_offset_*    piece entries carry offset != 0 + precislo/precishi.
//   qp_*                the three queryProperties flag branches + the parent
//                       (global scope) walk + constant short-circuit.
//   marknotmapped_window  symbol removal + ownership-window split.

use rudra::rangemap::{RangeRecord, RangeSubsort};
use rudra::space::AddressSpace;
use rudra::varmap::{
    ghidra_space_index, symbol_category, EntrySubsort, LocalMapEntry,
    LocalSymbol, QueryFinalScope, ScopeLocal,
};
use rudra::varnode::varnode_flags;

fn sym(name: &str, space: AddressSpace, start: u64, size: i32, usepoint: Option<u64>) -> LocalSymbol {
    let mut s = LocalSymbol::new(name, start, size, None, symbol_category::NO_CATEGORY);
    s.space = space;
    s.usepoint = usepoint;
    s
}

/// SymbolEntry::getSubsort equivalent for the fixture's uselimit edits
/// (database.cc:97-107; ScopeLocal::entry_subsort is crate-private).
fn subsort_of(addrtied: bool, uselimit: &[(i32, u64, u64)]) -> EntrySubsort {
    if addrtied {
        return EntrySubsort::minimum();
    }
    match uselimit.first() {
        None => EntrySubsort::minimum(),
        Some(&(useindex, useoffset, _)) => EntrySubsort { useindex, useoffset },
    }
}

/// Replace the last entry's uselimit and re-freeze its subsort — the
/// fixture mirror of `sym->getMapEntry(0)->setUseLimit(rnglist)`.
fn set_last_uselimit(scope: &mut ScopeLocal, uselimit: Vec<(i32, u64, u64)>) {
    let entry = scope.mapentry_log.last_mut().unwrap();
    entry.subsort = subsort_of(false, &uselimit);
    entry.uselimit = uselimit;
}

/// findOverlap / findAddr observation, formatted like dumpEntryQuery.
fn dump_entry_query(
    case: &str,
    kind: &str,
    scope: &ScopeLocal,
    space: AddressSpace,
    offset: u64,
    size: i32,
    usepoint: Option<u64>,
) {
    let entry: Option<LocalMapEntry> = if kind == "overlap" {
        scope.find_overlap_entry(space, offset, size)
    } else {
        scope.find_addr_entry(space, offset, usepoint)
    };
    let up = match usepoint {
        None => "inv".to_string(),
        Some(up) => format!("{up:#x}"),
    };
    let line = match entry {
        None => format!("case={case}|kind={kind}|query={offset:#x}:{size:x}|up={up}|result=null"),
        Some(e) => {
            let name = &scope.symbols[e.sym].name;
            format!(
                "case={case}|kind={kind}|query={offset:#x}:{size:x}|up={up}|result={name}|first={:#x}|last={:#x}|off={}|sz={}",
                e.start, e.last(), e.offset, e.size
            )
        }
    };
    println!("{line}");
}

fn scope_tag(final_scope: QueryFinalScope) -> &'static str {
    match final_scope {
        QueryFinalScope::None => "none",
        QueryFinalScope::This => "this",
        QueryFinalScope::Parent => "parent",
    }
}

/// queryProperties observation, formatted like dumpQueryProperties.
fn dump_qp(
    case: &str,
    scope: &ScopeLocal,
    parent: Option<&ScopeLocal>,
    property: &dyn Fn(AddressSpace, u64) -> u32,
    space: AddressSpace,
    offset: u64,
    size: i64,
) {
    let out = scope.query_properties_ex(space, offset, size, None, parent, property);
    let up = "inv".to_string();
    let line = match &out.entry {
        None => format!(
            "case={case}|kind=qp|query={offset:#x}:{size:x}|up={up}|result=null|flags={:#x}|scope={}",
            out.flags,
            scope_tag(out.final_scope)
        ),
        Some(e) => {
            let name = match out.final_scope {
                QueryFinalScope::Parent => &parent.unwrap().symbols[e.sym].name,
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

fn main() {
    let mut scope = ScopeLocal::new();
    scope.space = AddressSpace::Stack;
    let ram = ghidra_space_index(&AddressSpace::Ram);

    // setup: space indices of Rugra's canonical model.
    println!(
        "case=setup|const_index={}|ram_index={}|stack_index={}|unique_index={}",
        ghidra_space_index(&AddressSpace::Const),
        ram,
        ghidra_space_index(&AddressSpace::Stack),
        ghidra_space_index(&AddressSpace::Unique),
    );

    // equal_subsort: two entries with identical range AND identical subsort.
    scope.install_symbol(sym("first_es", AddressSpace::Stack, 0x300, 8, Some(0x1000)));
    scope.install_symbol(sym("second_es", AddressSpace::Stack, 0x300, 8, Some(0x1000)));
    dump_entry_query("equal_subsort_overlap", "overlap", &scope, AddressSpace::Stack, 0x302, 2, None);
    dump_entry_query("equal_subsort_findaddr", "findaddr", &scope, AddressSpace::Stack, 0x300, 8, Some(0x1000));

    // wide/narrow double order: wide [0x320,0x32f] uselimit [0x1100,0x11ff]
    // (subsort (3,0x1100)), narrow [0x328,0x32b] uselimit [0x1000,0x10ff]
    // (subsort (3,0x1000)). The shared cell answers NARROW — the subsort
    // minimum — even though wide was inserted first.
    scope.install_symbol(sym("wide", AddressSpace::Stack, 0x320, 16, Some(0x1100)));
    set_last_uselimit(&mut scope, vec![(ram, 0x1100, 0x11ff)]);
    scope.install_symbol(sym("narrow", AddressSpace::Stack, 0x328, 4, Some(0x1000)));
    set_last_uselimit(&mut scope, vec![(ram, 0x1000, 0x10ff)]);
    dump_entry_query("wide_narrow_overlap", "overlap", &scope, AddressSpace::Stack, 0x329, 2, None);
    dump_entry_query("wide_narrow_overlap_wide_cell", "overlap", &scope, AddressSpace::Stack, 0x322, 2, None);
    dump_entry_query("wide_narrow_findaddr_midrange", "findaddr", &scope, AddressSpace::Stack, 0x328, 4, Some(0x1050));
    dump_entry_query("wide_narrow_findaddr_wide_use", "findaddr", &scope, AddressSpace::Stack, 0x320, 4, Some(0x1150));
    dump_entry_query("wide_narrow_findaddr_nouse", "findaddr", &scope, AddressSpace::Stack, 0x320, 4, Some(0x1050));

    // multi_uselimit: "spread" [0x340,0x347] with two disjoint code ranges.
    scope.install_symbol(sym("spread", AddressSpace::Stack, 0x340, 8, Some(0x1000)));
    set_last_uselimit(&mut scope, vec![(ram, 0x1000, 0x100f), (ram, 0x2000, 0x200f)]);
    dump_entry_query("multi_uselimit_second_range", "findaddr", &scope, AddressSpace::Stack, 0x340, 8, Some(0x2005));
    dump_entry_query("multi_uselimit_gap", "findaddr", &scope, AddressSpace::Stack, 0x340, 8, Some(0x1500));

    // cross_space_storage: an entry in ram never answers a stack query.
    scope.install_symbol(sym("ramsym", AddressSpace::Ram, 0x4000, 8, None));
    dump_entry_query("cross_space_stack_query", "overlap", &scope, AddressSpace::Stack, 0x4000, 8, None);
    dump_entry_query("cross_space_ram_query", "overlap", &scope, AddressSpace::Ram, 0x4002, 4, None);

    // multi_mapping: one symbol, two mappings; then removal of both.
    let two = scope.install_symbol(sym("two", AddressSpace::Stack, 0x500, 4, None));
    scope.add_map_entry(
        two,
        AddressSpace::Stack,
        0x510,
        4,
        0,
        varnode_flags::MAPPED,
        Vec::new(),
    );
    scope.install_symbol(sym("third", AddressSpace::Stack, 0x520, 4, None));
    dump_entry_query("multi_mapping_first", "overlap", &scope, AddressSpace::Stack, 0x501, 2, None);
    dump_entry_query("multi_mapping_second", "overlap", &scope, AddressSpace::Stack, 0x513, 2, None);
    scope.remove_symbol(two);
    dump_entry_query("remove_requery_first", "overlap", &scope, AddressSpace::Stack, 0x501, 2, None);
    dump_entry_query("remove_requery_second", "overlap", &scope, AddressSpace::Stack, 0x513, 2, None);
    dump_entry_query("remove_requery_survivor", "overlap", &scope, AddressSpace::Stack, 0x522, 2, None);

    // find_container: smallest container, exact-size break, equal tie.
    scope.install_symbol(sym("bigc", AddressSpace::Stack, 0x600, 16, None));
    scope.install_symbol(sym("smallc", AddressSpace::Stack, 0x604, 4, None));
    let no_parent: Option<&ScopeLocal> = None;
    let no_property: &dyn Fn(AddressSpace, u64) -> u32 = &|_, _| 0;
    dump_qp("find_container_smallest", &scope, no_parent, no_property, AddressSpace::Stack, 0x605, 2);
    scope.install_symbol(sym("tieA", AddressSpace::Stack, 0x620, 8, None));
    scope.install_symbol(sym("tieB", AddressSpace::Stack, 0x620, 8, None));
    dump_qp("find_container_equal_tie", &scope, no_parent, no_property, AddressSpace::Stack, 0x622, 4);

    // partial_offset_piece: a join symbol's stack pieces carry offset != 0
    // and precislo/precishi extraflags (database.cc:1156-1177). The unified
    // join-space entry never answers a stack query and is not modeled; the
    // piece entries are installed in the oracle's addMap loop order
    // (j=0 -> pieces[1] offset 0 precislo, j=1 -> pieces[0] offset 4
    // precishi).
    {
        let mut piecesym = sym("piecesym", AddressSpace::Stack, 0x640, 8, None);
        piecesym.addrtied = true; // the unified entry's empty uselimit
        // SymbolStore::push returns the stable slot id — the Symbol* the
        // oracle's addSymbol hands back (database.cc:1810). The old
        // len()-before-push dense-index idiom died with the Vec storage:
        // a tombstoned store makes live-len != next-slot.
        let idx = scope.symbols.push(piecesym);
        scope.add_map_entry(
            idx,
            AddressSpace::Stack,
            0x640,
            4,
            0,
            varnode_flags::PRECISLO,
            Vec::new(),
        );
        scope.add_map_entry(
            idx,
            AddressSpace::Stack,
            0x644,
            4,
            4,
            varnode_flags::PRECISHI,
            Vec::new(),
        );
    }
    dump_qp("partial_offset_piece_hi", &scope, no_parent, no_property, AddressSpace::Stack, 0x645, 2);

    // qp_local_symbol: the answering entry's getAllFlags (typelock folded in).
    let locked = scope.install_symbol(sym("locked", AddressSpace::Stack, 0x100, 4, None));
    scope.symbols[locked].typelock = true;
    dump_qp("qp_local_symbol", &scope, no_parent, no_property, AddressSpace::Stack, 0x102, 2);

    // qp_scope_only / marknotmapped_window: the local scope owns
    // [0x900,0x9ff]; victim installed before the readonly property range so
    // no addMap property fold contaminates its flags.
    scope.local_range = vec![(0x900, 0x9ff)];
    scope.install_symbol(sym("victim", AddressSpace::Stack, 0x900, 4, None));
    let property: &dyn Fn(AddressSpace, u64) -> u32 = &|space, off| {
        if space == AddressSpace::Stack && (0x900..=0x9ff).contains(&off) {
            varnode_flags::READONLY
        } else {
            0
        }
    };
    dump_qp("qp_scope_symbol_victim", &scope, no_parent, property, AddressSpace::Stack, 0x902, 1);
    scope.mark_not_mapped(0x900, 4, false);
    dump_qp("marknotmapped_window", &scope, no_parent, property, AddressSpace::Stack, 0x902, 1);
    dump_qp("qp_scope_only_property", &scope, no_parent, property, AddressSpace::Stack, 0x910, 1);

    // qp_parent_symbol: the global scope's symbol answers through the local
    // scope's query (persist set by addMap, database.cc:1131-1132).
    let mut parent = ScopeLocal::new();
    parent.is_global_scope = true;
    parent.space = AddressSpace::Ram;
    parent.install_symbol(sym("gpar", AddressSpace::Ram, 0x7f001000, 8, None));
    dump_qp("qp_parent_symbol", &scope, Some(&parent), property, AddressSpace::Ram, 0x7f001002, 2);
    // qp_none: unique space — no symbol, no scope ownership anywhere.
    dump_qp("qp_none", &scope, Some(&parent), property, AddressSpace::Unique, 0x9000, 1);
    // qp_constant: constant addresses never enter a scope (database.cc:950).
    dump_qp("qp_constant", &scope, Some(&parent), property, AddressSpace::Const, 0x10, 1);
}
