// FSPEC-ENDIAN-RESOLVER-1204: Rugra comparand for the locked Ghidra
// 12.0.4 oracle (FSPEC-JUSTIFIED-ENDIAN-0002 +
// FSPEC-CHARACTERIZE-RESOLVER-GATE-0003). Mirrors
// tests/oracle/fspec_endian_resolver_1204.cc case for case:
//  - le_forceleft_routing: the spaceless helper
//    rudra::fspec::justified_contain_range over the full LE/BE x
//    forceleft matrix; the branch key is
//    `space_is_big_endian && !force_left` (address.cc:138), so LE rows
//    print the start distance for BOTH forceleft values and only the
//    (BE,false) rows print the end distance.
//  - param_entry_le_unflagged: the ParamEntry::justifiedContain
//    alignment==0 wrapper over an unflagged little-endian exclusion
//    entry — the `==0` determination route fixed by ENDIAN-0002 (the
//    transitional enum AddressSpace reports little-endian).
//  - truncate_subpiece: the heritage.cc:1221 SUBPIECE-constant call
//    shape (forceleft=false + space endianness) exactly as
//    src/heritage.rs guard_call_overlapping_input evaluates it.
//  - characterize_resolver_gate: ParamListStandard::characterize_as_param
//    over two unflagged LE exclusion entries; extent-out queries pin the
//    resolver gating (phase-1 extent window, phase-2 start window, gate
//    closed when no registered extent starts above the query start).

use rudra::address::Address;
use rudra::fspec::{justified_contain_range, ParamEntry, ParamListStandard, TypeClass};
use rudra::space::AddressSpace;

// staged-loader entry builder (the pub equivalent of the C++ fixture's
// direct field writes; same pattern as the justified_contain_1204
// fixture).
fn make_entry(
    grp: i32,
    spc: AddressSpace,
    base: u64,
    size: i32,
    min_size: i32,
    alignment: i32,
    flags: u32,
) -> ParamEntry {
    let mut e = ParamEntry::new(grp);
    *e.flags_mut() = flags;
    e.set_type_class(TypeClass::General);
    e.set_space(spc);
    e.set_base(base);
    e.set_sizes(size, min_size);
    e.set_alignment(alignment); // normalizes alignment == size to 0
    e
}

#[derive(Clone, Copy)]
struct JcGeom { base: u64, esz: i32, qoff: u64, qsz: i32 }

// The same geometries as the C++ oracle, in the same order.
const GEOMS: [JcGeom; 7] = [
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1000, qsz: 8 },   // exact
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1000, qsz: 4 },   // low sub-range
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1003, qsz: 1 },   // size-1 high byte
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1002, qsz: 4 },   // mid sub-range
    JcGeom { base: 0x2000, esz: 4, qoff: 0x2000, qsz: 1 },   // size-1 low byte (4B entry)
    JcGeom { base: 0x2000, esz: 4, qoff: 0x2003, qsz: 1 },   // size-1 high byte (4B entry)
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1000, qsz: 12 },  // equal start pokes out
];

#[derive(Clone, Copy)]
struct TrGeom { addr: u64, size: i32, toff: u64, tsz: i32 }

// The same heritage.cc:1221 geometries as the C++ oracle.
const TRGEOMS: [TrGeom; 5] = [
    TrGeom { addr: 0x1000, size: 16, toff: 0x1004, tsz: 4 },
    TrGeom { addr: 0x1000, size: 16, toff: 0x1000, tsz: 8 },
    TrGeom { addr: 0x2000, size: 8, toff: 0x2006, tsz: 2 },
    TrGeom { addr: 0x2000, size: 8, toff: 0x2002, tsz: 4 },
    TrGeom { addr: 0x2000, size: 4, toff: 0x2000, tsz: 8 },
];

fn main() {
    println!("schema=1|fixture=FSPEC-ENDIAN-RESOLVER-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // ---- case 1: LE/BE x forceleft branch matrix ----------------------
    println!("case=le_forceleft_routing");
    for g in GEOMS.iter() {
        for be in [false, true] {
            for fl in [false, true] {
                let off = justified_contain_range(g.base, g.esz, g.qoff, g.qsz, fl, be);
                let fl_i = if fl { 1 } else { 0 };
                let be_i = if be { 1 } else { 0 };
                println!("  jc base=0x{:x} esz={} qoff=0x{:x} qsz={} fl={} be={} off={}",
                         g.base, g.esz, g.qoff, g.qsz, fl_i, be_i, off);
            }
        }
    }

    // ---- case 2: unflagged LE exclusion entry through the wrapper -----
    println!("case=param_entry_le_unflagged");
    {
        // Unflagged Ram entry: the transitional enum space reports
        // little-endian, so the wrapper forwards force_left=false +
        // space_is_big_endian=false — the ENDIAN-0002 route.
        let le = make_entry(0, AddressSpace::Ram, 0x100, 8, 1, 0, 0);
        let lec: [(u64, i32); 8] = [
            (0x100, 8),   // exact -> 0
            (0x100, 4),   // low sub-range -> start distance 0
            (0x102, 4),   // unjustified sub-range -> 2
            (0x106, 2),   // flush with the high end -> 6 (NOT 0 on LE)
            (0x103, 1),   // size-1 sub-range -> 3
            (0x100, 12),  // equal start, pokes out high -> -1
            (0x0FE, 4),   // low overlap ending inside -> -1
            (0x104, 8),   // high poke -> -1
        ];
        for &(qoff, qsz) in lec.iter() {
            let off = le.justified_contain(Address::new(qoff), qsz);
            println!("  pe qoff=0x{:x} qsz={} off={}", qoff, qsz, off);
        }
    }

    // ---- case 3: heritage truncate_amount SUBPIECE constant -----------
    println!("case=truncate_subpiece");
    for g in TRGEOMS.iter() {
        // The exact src/heritage.rs guard_call_overlapping_input shape:
        // forceleft=false + the heritage space's endianness.
        let amt_le = justified_contain_range(g.addr, g.size, g.toff, g.tsz, false, false);
        println!("  tr spc=le addr=0x{:x} size={} toff=0x{:x} tsz={} amt={}",
                 g.addr, g.size, g.toff, g.tsz, amt_le);
        let amt_be = justified_contain_range(g.addr, g.size, g.toff, g.tsz, false, true);
        println!("  tr spc=be addr=0x{:x} size={} toff=0x{:x} tsz={} amt={}",
                 g.addr, g.size, g.toff, g.tsz, amt_be);
    }

    // ---- case 4: characterize_as_param resolver gating ----------------
    println!("case=characterize_resolver_gate");
    {
        let mut model = ParamListStandard::new();
        let mut effects = Vec::new();
        model.parse_pentry(0, true, false, false, &mut effects, make_entry(
            0, AddressSpace::Ram, 0x100, 4, 1, 0, 0,
        )).unwrap();
        model.parse_pentry(1, true, false, false, &mut effects, make_entry(
            1, AddressSpace::Ram, 0x200, 8, 1, 0, 0,
        )).unwrap();
        model.finalize_after_decode(0);
        let chc: [(u64, i32); 12] = [
            (0x150, 0x20),  // start between extents, overlaps nothing -> 0
            (0x150, 0x100), // start between, range covers E2 -> 3
            (0x300, 8),     // start above every extent -> gate closed -> 0
            (0x080, 0x90),  // start below E1, range covers E1 -> 3
            (0x200, 8),     // exact E2 -> 2
            (0x202, 4),     // unjustified inside E2 -> 1
            (0x200, 16),    // equal-start pokes out of E2 -> 3
            (0x1F0, 0x18),  // start below E2, covers it exactly -> 3
            (0x104, 8),     // start between extents -> 0
            (0x0F0, 4),     // start below every extent -> 0
            (0x080, 0x200), // start below, covers both -> 3
            (0x204, 8),     // start inside E2, pokes high -> 0
        ];
        for &(qoff, qsz) in chc.iter() {
            let cls = model.characterize_as_param(AddressSpace::Ram, qoff, qsz);
            println!("  ch qoff=0x{:x} qsz={} cls={}", qoff, qsz, cls);
        }
    }
}
