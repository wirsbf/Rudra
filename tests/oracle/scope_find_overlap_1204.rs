// Locked Ghidra 12.0.4 ScopeInternal::findOverlap oracle for
// SCOPE-FINDOVERLAP-KEY-0001 / SCOPE-FINDOVERLAP-DYNAMIC-0001 (Rust side).
//
// Mirrors tests/oracle/scope_find_overlap_1204.cc record-for-record: each
// case installs the same static/dynamic symbols on a hand-built ScopeLocal
// (Rugra's LocalSymbol models one SymbolEntry per Symbol) and issues the
// same findOverlap queries through
// rudra::funcdata::scope_local_find_overlap — the ScopeInternal::findOverlap
// analogue consumed by Funcdata::sync_varnodes_with_symbols.
//
// Case semantics (see the .cc header for the full rationale):
//   partition_usepoint      EntrySubsort(usepoint)-minimum record covering
//                           the partition unit containing the query start.
//   partition_usepoint_far  query start inside the "wide"-only unit.
//   addrtied_wins           address-tied (usepoint == None) minimal subsort.
//   gap_query / _short      uncovered query start: leftmost intersecting
//                           unit answers; none -> null.
//   dynamic_null            dynamic symbols are invisible to findOverlap.
//   dynamic_no_shadow       static symbol answers with "dyn" present.

use rudra::funcdata::scope_local_find_overlap;
use rudra::space::AddressSpace;
use rudra::varmap::{symbol_category, LocalSymbol, ScopeLocal};

fn static_symbol(name: &str, start: u64, size: i32, usepoint: Option<u64>) -> LocalSymbol {
    let mut sym = LocalSymbol::new(name, start, size, None, symbol_category::NO_CATEGORY);
    sym.usepoint = usepoint;
    sym
}

fn dynamic_symbol(name: &str, size: i32, caddr: Option<u64>) -> LocalSymbol {
    let mut sym = LocalSymbol::new(name, 0, size, None, symbol_category::NO_CATEGORY);
    sym.is_dynamic = true;
    sym.hash = 0x1234;
    sym.usepoint = caddr;
    sym
}

fn dump_query(case: &str, scope: &ScopeLocal, offset: u64, size: i32) {
    let entry = scope_local_find_overlap(scope, AddressSpace::Stack, offset, size);
    let line = match entry {
        None => format!("case={case}|query={offset:#x}:{size:x}|result=null"),
        Some(sym) => format!(
            "case={case}|query={offset:#x}:{size:x}|result={}|first={:#x}|last={:#x}|dyn={}",
            sym.name,
            sym.start,
            sym.start + sym.size as u64 - 1,
            if sym.is_dynamic { 1 } else { 0 }
        ),
    };
    println!("{line}");
}

fn main() {
    let mut scope = ScopeLocal::new();
    scope.space = AddressSpace::Stack;

    // partition_usepoint: "wide" [0x300,0x30f] usepoint 0x1010,
    // "narrow" [0x308,0x30b] usepoint 0x1000.
    scope.symbols.push(static_symbol("wide", 0x300, 16, Some(0x1010)));
    scope.symbols.push(static_symbol("narrow", 0x308, 4, Some(0x1000)));
    dump_query("partition_usepoint", &scope, 0x309, 2);
    dump_query("partition_usepoint_far", &scope, 0x300, 2);

    // addrtied_wins: "used" (usepoint, inserted first) vs "tied"
    // (no usepoint -> address-tied, minimal subsort).
    scope.symbols.push(static_symbol("used", 0x320, 8, Some(0x1000)));
    scope.symbols.push(static_symbol("tied", 0x320, 8, None));
    dump_query("addrtied_wins", &scope, 0x322, 4);

    // gap_query: query start 0x338 uncovered; leftmost intersecting unit
    // [0x340,0x343] is "gapend"; a short query reaching no unit is null.
    scope.symbols.push(static_symbol("gapend", 0x340, 4, Some(0x1000)));
    scope.symbols.push(static_symbol("gapfar", 0x344, 4, Some(0x1001)));
    dump_query("gap_query", &scope, 0x338, 0x10);
    dump_query("gap_query_short", &scope, 0x338, 0x6);

    // dynamic_null / dynamic_no_shadow: "dyn" must never answer or shadow.
    scope.symbols.push(dynamic_symbol("dyn", 4, Some(0x1000)));
    dump_query("dynamic_null", &scope, 0x0, 8);
    scope.symbols.push(static_symbol("staticfar", 0x360, 4, Some(0x1000)));
    dump_query("dynamic_no_shadow", &scope, 0x360, 4);
}
