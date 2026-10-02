// JUSTIFIED-CONTAIN-1204: Rugra comparand for the locked Ghidra 12.0.4
// justified-containment oracle (FSPEC-JUSTIFIED-CONTAIN-0001). Mirrors
// tests/oracle/justified_contain_1204.cc case for case:
//  - Address::justifiedContain (address.cc:131-141) polarity: EITHER side
//    poking out independently returns -1 (equal-start-bigger, low overlap
//    flush at entry end, superset, high poke). The spaceless helper
//    rudra::fspec::justified_contain_range selects the branch by the
//    space endianness and force_left exactly like Ghidra's
//    `base->isBigEndian() && !forceleft` (address.cc:138; re-pinned by
//    FSPEC-JUSTIFIED-ENDIAN-0002): view=start rows call
//    force_left=false on a little-endian space (the `op2.offset -
//    offset` arithmetic, = Ghidra LE forceleft=false / forceleft=true /
//    BE forceleft=true), view=end rows call force_left=false on a
//    big-endian space (the `off1 - off2` arithmetic, = Ghidra BE
//    forceleft=false). The C++ side additionally pins LE(false) ==
//    LE(true) == BE(true) internally.
//  - ParamEntry::justifiedContain (fspec.cc:248-283) alignment==0 path
//    through a force-left exclusion entry (start-distance). The be=1
//    rows (Ghidra's BE-unflagged entry, end-distance) call the helper
//    with an explicit big-endian space: the transitional enum
//    AddressSpace cannot stage a BE ParamEntry (ADDRESS-0001), and an
//    unflagged Ram entry now correctly returns the LE start distance.
//  - ParamListStandard::characterizeAsParam (fspec.cc:682-719) over a
//    single 4-byte exclusion force-left entry: contains_justified(2),
//    contains_unjustified(1), contained_by(3), no_containment(0), with
//    query starts kept inside the entry extent (resolver gating).

use rudra::address::Address;
use rudra::fspec::param_entry_flags;
use rudra::fspec::{justified_contain_range, ParamEntry, ParamListStandard, TypeClass};
use rudra::space::AddressSpace;

// staged-loader entry builder (the pub equivalent of the C++ fixture's
// direct field writes; same pattern as the fspec_phase0 fixture).
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

// The same 17 geometries as the C++ oracle, in the same order.
const GEOMS: [JcGeom; 17] = [
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1000, qsz: 8 },   // exact
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1000, qsz: 4 },   // low sub-range
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1002, qsz: 4 },   // mid sub-range
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1004, qsz: 4 },   // high sub-range flush
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1003, qsz: 1 },   // size-1 sub-range
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1000, qsz: 1 },   // size-1 justified
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1000, qsz: 12 },  // equal start, pokes out
    JcGeom { base: 0x1000, esz: 8, qoff: 0x0FFE, qsz: 10 },  // low overlap flush end
    JcGeom { base: 0x1000, esz: 8, qoff: 0x0FFC, qsz: 16 },  // strict superset
    JcGeom { base: 0x1000, esz: 8, qoff: 0x1004, qsz: 8 },   // high poke
    JcGeom { base: 0x1000, esz: 8, qoff: 0x0FFE, qsz: 6 },   // low overlap inside
    JcGeom { base: 0x2000, esz: 4, qoff: 0x1FFE, qsz: 8 },   // cross-4 superset
    JcGeom { base: 0x2000, esz: 4, qoff: 0x2002, qsz: 4 },   // cross-4 high poke
    JcGeom { base: 0x2000, esz: 4, qoff: 0x2000, qsz: 4 },   // exact 4-byte
    JcGeom { base: 0x3000, esz: 1, qoff: 0x3000, qsz: 1 },   // exact 1-byte
    JcGeom { base: 0x3000, esz: 1, qoff: 0x3000, qsz: 2 },   // size-1 bigger
    JcGeom { base: 0x3000, esz: 1, qoff: 0x2FFF, qsz: 3 },   // size-1 superset
];

fn main() {
    println!("schema=1|fixture=JUSTIFIED-CONTAIN-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // ---- case 1: justified_contain_range polarity + branch arithmetic --
    println!("case=address_justified_contain");
    for g in GEOMS.iter() {
        // view=start: op2.offset - offset arithmetic (Ghidra LE any
        // forceleft, BE forceleft=true). Re-pinned by
        // FSPEC-JUSTIFIED-ENDIAN-0002: force_left=false on a
        // little-endian space — the real defect route.
        let start = justified_contain_range(g.base, g.esz, g.qoff, g.qsz, false, false);
        println!("  jc base=0x{:x} esz={} qoff=0x{:x} qsz={} view=start off={}",
                 g.base, g.esz, g.qoff, g.qsz, start);
        // view=end: off1 - off2 arithmetic (Ghidra BE forceleft=false):
        // force_left=false on a big-endian space.
        let end = justified_contain_range(g.base, g.esz, g.qoff, g.qsz, false, true);
        println!("  jc base=0x{:x} esz={} qoff=0x{:x} qsz={} view=end off={}",
                 g.base, g.esz, g.qoff, g.qsz, end);
    }

    // ---- case 2: ParamEntry::justified_contain alignment==0 path -------
    println!("case=param_entry_justified_contain");
    {
        // Force-left exclusion entry: start-distance branch.
        let le = make_entry(
            0, AddressSpace::Ram, 0x100, 8, 1, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        );
        let lec: [(u64, i32); 11] = [
            (0x100, 8),   // exact
            (0x100, 4),   // justified sub-range (forceleft)
            (0x102, 4),   // unjustified sub-range
            (0x106, 2),   // sub-range flush with the high end
            (0x103, 1),   // size-1 sub-range
            (0x100, 12),  // equal start, pokes out high -> -1
            (0x0FE, 4),   // low overlap ending inside -> -1
            (0x100, 16),  // strict superset -> -1
            (0x104, 8),   // high poke -> -1
            (0x10C, 2),   // fully above -> -1
            (0x0FC, 4),   // fully below -> -1
        ];
        for &(qoff, qsz) in lec.iter() {
            let off = le.justified_contain(Address::new(qoff), qsz);
            println!("  pe be=0 qoff=0x{:x} qsz={} off={}", qoff, qsz, off);
        }
        // BE-unflagged rows (end-distance branch): the transitional enum
        // AddressSpace cannot stage a big-endian ParamEntry, so these
        // rows pin the wrapper's forwarded arithmetic (fspec.cc:267 ->
        // Address::justifiedContain BE forceleft=false) through the
        // spaceless helper with an explicit BE space (ADDRESS-0001).
        let bec: [(u64, i32); 6] = [
            (0x100, 8),   // exact
            (0x100, 4),   // sub-range at the low end -> off1 - off2 = 4
            (0x106, 2),   // sub-range flush with the high end -> 0
            (0x103, 1),   // size-1 sub-range -> 4
            (0x100, 12),  // equal start, pokes out high -> -1
            (0x0FE, 8),   // low overlap ending flush at entry end -> -1
        ];
        for &(qoff, qsz) in bec.iter() {
            let off = justified_contain_range(0x100, 8, qoff, qsz, false, true);
            println!("  pe be=1 qoff=0x{:x} qsz={} off={}", qoff, qsz, off);
        }
    }

    // ---- case 3: characterize_as_param three-way classification -------
    println!("case=characterize_projection");
    {
        let mut model = ParamListStandard::new();
        let mut effects = Vec::new();
        model.parse_pentry(0, true, false, false, &mut effects, make_entry(
            0, AddressSpace::Ram, 0x100, 4, 1, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        )).unwrap();
        model.finalize_after_decode(0);
        let chc: [(u64, i32); 8] = [
            (0x100, 4),  // exact -> contains_justified
            (0x100, 1),  // size-1 justified sub-range -> contains_justified
            (0x102, 2),  // unjustified sub-range -> contains_unjustified
            (0x103, 1),  // size-1 sub-range at the high end -> contains_unjustified
            (0x100, 6),  // equal start, pokes out -> contained_by
            (0x100, 8),  // size-8 over a 4-byte entry -> contained_by
            (0x102, 4),  // high poke, entry not inside query -> no_containment
            (0x101, 4),  // staggered poke -> no_containment
        ];
        for &(qoff, qsz) in chc.iter() {
            let cls = model.characterize_as_param(AddressSpace::Ram, qoff, qsz);
            println!("  ch qoff=0x{:x} qsz={} cls={}", qoff, qsz, cls);
        }
    }
}
