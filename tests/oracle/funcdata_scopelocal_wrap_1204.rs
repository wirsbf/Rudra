// Locked Ghidra 12.0.4 ScopeInternal::findOverlap wrap-domain oracle for
// FUNCDATA-SCOPELOCALOVERFLOW-0001 / FUNCDATA-SCOPELOCAL-WRAP-0001
// (Rust side).
//
// Mirrors tests/oracle/funcdata_scopelocal_wrap_1204.cc record-for-record:
// the same address-tied symbol table (top8 = [0xfffffffffffffff8,
// 0xffffffffffffffff], low8 = [0x100, 0x107]) queried through
// rudra::funcdata::scope_local_find_overlap — the LocalSymbol-granular
// projection ScopeInternal::findOverlap (database.cc:2392) that
// Funcdata::syncVarnodesWithSymbols (funcdata_varnode.cc:951) drives.
// The point of the fixture is the uint8 modular domain of
// `addr.getOffset()+size-1` (database.cc:2397): the pre-fix Rust trapped
// with `attempt to add with overflow` on the debug profile at these exact
// queries and missed the top-of-space record with its `p < first+size`
// containment form when first+size wrapped to 0.

use rudra::funcdata::scope_local_find_overlap;
use rudra::space::AddressSpace;
use rudra::varmap::{symbol_category, LocalSymbol, ScopeLocal};

fn add_addrtied_symbol(scope: &mut ScopeLocal, name: &str, start: u64, size: i32) {
    // Scope::addSymbol with an invalid usepoint: address-tied storage,
    // empty uselimit, subsort (0,0) (database.cc:1149-1150) — modeled by
    // usepoint == None on the LocalSymbol projection.
    let mut sym = LocalSymbol::new(name, start, size, None, symbol_category::NO_CATEGORY);
    sym.space = AddressSpace::Stack;
    sym.usepoint = None;
    scope.symbols.push(sym);
}

fn dump_overlap(case: &str, scope: &ScopeLocal, offset: u64, size: i32) {
    let entry = scope_local_find_overlap(scope, AddressSpace::Stack, offset, size);
    let line = match entry {
        None => format!("case={case}|kind=overlap|query={offset:#x}:{size}|up=inv|result=null"),
        Some(sym) => {
            let last = sym.start.wrapping_add(sym.size as u64).wrapping_sub(1);
            format!(
                "case={case}|kind=overlap|query={offset:#x}:{size}|up=inv|result={}|first={:#x}|last={:#x}|off=0|sz={}",
                sym.name, sym.start, last, sym.size
            )
        }
    };
    println!("{line}");
}

fn main() {
    let mut scope = ScopeLocal::new();
    scope.space = AddressSpace::Stack;
    add_addrtied_symbol(&mut scope, "top8", 0xffff_ffff_ffff_fff8, 8);
    add_addrtied_symbol(&mut scope, "low8", 0x100, 8);

    dump_overlap("wrap_top_full", &scope, 0xffff_ffff_ffff_fff8, 8);
    dump_overlap("wrap_top_last_byte", &scope, 0xffff_ffff_ffff_ffff, 1);
    dump_overlap("wrap_top_from_below", &scope, 0xffff_ffff_ffff_fff6, 4);
    dump_overlap("neg_size_below", &scope, 0x1000, -8);
    dump_overlap("zero_size_top", &scope, 0xffff_ffff_ffff_fff8, 0);
    dump_overlap("low_hit", &scope, 0x104, 4);
    dump_overlap("nonoverlap_above", &scope, 0x10, 8);
}
