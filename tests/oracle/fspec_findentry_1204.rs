// FSPEC-FINDENTRY-1204: Rugra comparand for the locked Ghidra 12.0.4
// oracle (FSPEC-FINDENTRY-GATE-0005 + the join coverage of
// FSPEC-RESOLVER-JOIN-WINDOW-0004). Mirrors
// tests/oracle/fspec_findentry_1204.cc case for case:
//  - find_window_gate: ParamListStandard::find_entry window gating —
//    only entries with a registered extent containing the query start
//    (in the query's space) are visited, so extent-out queries return
//    None even with just=false, and the minSize gate runs inside the
//    window (fspec.cc:661-680 resolver->find window).
//  - join_piece_access: join entries are reachable through their
//    per-piece registration (populateResolver fspec.cc:1191-1216);
//    the just=true justification runs the join walk
//    (ParamEntry::justifiedContain fspec.cc:248-283, least significant
//    piece first).
//  - cross_space_join: pieces in different spaces with equal offsets;
//    the per-piece space guard (address.cc:133 base != op2.base) makes
//    the ram query return offset 4 != 0 -> None with just=true.
//  - find_vs_characterize: the shared phase-1 resolver window ties a
//    justified find hit to cls=contains_justified and out-of-window
//    starts to None / no_containment.

use rudra::address::Address;
use rudra::fspec::{param_entry_flags, ParamEntry, ParamListStandard, TypeClass,
                   VarnodeData};
use rudra::space::AddressSpace;

// staged-loader entry builder (the pub equivalent of the C++ fixture's
// direct field writes; same pattern as the fspec_endian_resolver_1204
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

// Stage a join ParamEntry (space = join space + pieces, most
// significant first) — the state resolveJoin caches after decoding a
// join <pentry>.
fn make_join_entry(
    grp: i32,
    size: i32,
    min_size: i32,
    pieces: &[VarnodeData],
) -> ParamEntry {
    let mut e = ParamEntry::new(grp);
    e.set_type_class(TypeClass::General);
    e.set_space(AddressSpace::Join);
    e.set_base(0);
    e.set_sizes(size, min_size);
    e.set_alignment(0);
    e.set_join_pieces(pieces.to_vec());
    e
}

fn print_fe(model: &ParamListStandard, spcname: &str, space: AddressSpace,
            off: u64, sz: i32, just: bool) {
    let hit = model.find_entry(space, Address::new(off), sz, just);
    let fe = match hit { Some(i) => format!("e{}", i), None => "null".to_string() };
    println!("  fe spc={} off=0x{:x} sz={} just={} -> {}",
             spcname, off, sz, if just { 1 } else { 0 }, fe);
}

fn main() {
    println!("schema=1|fixture=FSPEC-FINDENTRY-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // ---- case 1: find window gating over plain entries ----------------
    println!("case=find_window_gate");
    {
        let mut model = ParamListStandard::new();
        let fl = param_entry_flags::FORCE_LEFT_JUSTIFY;
        // e0: register [0x100,0x107] min 1
        model.entry_mut().push(make_entry(0, AddressSpace::Register, 0x100, 8, 1, 0, fl));
        // e1: register [0x200,0x207] min 4
        model.entry_mut().push(make_entry(1, AddressSpace::Register, 0x200, 8, 4, 0, fl));
        // e2: ram [0x2000,0x200F] min 8
        model.entry_mut().push(make_entry(2, AddressSpace::Ram, 0x2000, 16, 8, 0, fl));
        // e3: register [0x108,0x10F] min 1
        model.entry_mut().push(make_entry(3, AddressSpace::Register, 0x108, 8, 1, 0, fl));
        // e4: register [0x104,0x10F] min 1 (overlaps e0's high half)
        model.entry_mut().push(make_entry(4, AddressSpace::Register, 0x104, 8, 1, 0, fl));
        model.set_num_group(5);
        model.populate_resolver();
        let fe: [(&str, AddressSpace, u64, i32, bool); 14] = [
            ("reg", AddressSpace::Register, 0x100, 8, true),   // in window, justified -> e0
            ("reg", AddressSpace::Register, 0x100, 4, true),   // force-left sub-range -> e0
            ("reg", AddressSpace::Register, 0x102, 4, true),   // unjustified in window -> null
            ("reg", AddressSpace::Register, 0x102, 4, false),  // just=false in window -> e0
            ("reg", AddressSpace::Register, 0x110, 4, false),  // above every reg extent -> null
            ("reg", AddressSpace::Register, 0x1F0, 8, false),  // between extents -> null
            ("reg", AddressSpace::Register, 0x300, 8, false),  // above all -> null
            ("reg", AddressSpace::Register, 0xFF, 4, false),   // below all -> null
            ("reg", AddressSpace::Register, 0x200, 2, false),  // in e1 window, minSize 4 > 2 -> null
            ("reg", AddressSpace::Register, 0x104, 4, false),  // window {e0,e4}, position order -> e0
            ("reg", AddressSpace::Register, 0x104, 4, true),   // e0 unjustified, e4 justified -> e4
            ("ram", AddressSpace::Ram, 0x2000, 16, true),      // ram entry hit -> e2
            ("ram", AddressSpace::Ram, 0x100, 8, false),       // register offset in ram -> null
            ("unique", AddressSpace::Unique, 0x100, 8, false), // no resolver for unique -> null
        ];
        for &(name, space, off, sz, just) in fe.iter() {
            print_fe(&model, name, space, off, sz, just);
        }
    }

    // ---- case 2: join entries reached through piece windows -----------
    println!("case=join_piece_access");
    {
        // pieces are MOST significant first: reg:0x104 high, reg:0x100 low.
        let pieces = [
            VarnodeData { space: AddressSpace::Register, offset: 0x104, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
        ];
        let mut model = ParamListStandard::new();
        // e0: the join entry (registered per piece at reg:0x104/0x100)
        model.entry_mut().push(make_join_entry(0, 8, 4, &pieces));
        // e1: plain register [0x100,0x107] min 8 overlapping both pieces
        model.entry_mut().push(make_entry(
            1, AddressSpace::Register, 0x100, 8, 8, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        model.set_num_group(2);
        model.populate_resolver();
        let fe: [(&str, AddressSpace, u64, i32, bool); 6] = [
            ("reg", AddressSpace::Register, 0x100, 8, true),  // join walk -1, plain justified -> e1
            ("reg", AddressSpace::Register, 0x100, 8, false), // join piece window first -> e0 (join!)
            ("reg", AddressSpace::Register, 0x100, 4, true),  // low piece justified -> e0 (join!)
            ("reg", AddressSpace::Register, 0x104, 4, true),  // high piece gives offset 4 -> null
            ("reg", AddressSpace::Register, 0x104, 4, false), // high piece window, just=false -> e0
            ("reg", AddressSpace::Register, 0x102, 4, true),  // pokes out of the low piece -> null
        ];
        for &(name, space, off, sz, just) in fe.iter() {
            print_fe(&model, name, space, off, sz, just);
        }
    }

    // ---- case 3: cross-space join pieces ------------------------------
    println!("case=cross_space_join");
    {
        // High piece in ram, low piece in reg, both at offset 0x200: the
        // numeric coincidence that requires the per-piece space guard
        // (address.cc:133 base != op2.base) inside the join walk.
        let pieces = [
            VarnodeData { space: AddressSpace::Ram, offset: 0x200, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x200, size: 4 },
        ];
        let mut model = ParamListStandard::new();
        model.entry_mut().push(make_join_entry(0, 8, 4, &pieces));
        model.set_num_group(1);
        model.populate_resolver();
        let fe: [(&str, AddressSpace, u64, i32, bool); 4] = [
            ("reg", AddressSpace::Register, 0x200, 4, true),  // low piece justified -> e0
            ("ram", AddressSpace::Ram, 0x200, 4, true),       // low piece foreign space: offset 4 -> null
            ("ram", AddressSpace::Ram, 0x200, 4, false),      // high piece window, just=false -> e0
            ("reg", AddressSpace::Register, 0x204, 4, false), // outside both piece extents -> null
        ];
        for &(name, space, off, sz, just) in fe.iter() {
            print_fe(&model, name, space, off, sz, just);
        }
    }

    // ---- case 4: find_entry vs characterize_as_param on one model -----
    println!("case=find_vs_characterize");
    {
        let pieces = [
            VarnodeData { space: AddressSpace::Register, offset: 0x104, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
        ];
        let mut model = ParamListStandard::new();
        model.entry_mut().push(make_join_entry(0, 8, 4, &pieces));
        model.entry_mut().push(make_entry(
            1, AddressSpace::Register, 0x100, 8, 8, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        model.set_num_group(2);
        model.populate_resolver();
        let fc: [(u64, i32); 5] = [
            (0x100, 4),  // find -> e0 (join, justified); characterize -> 2
            (0x100, 8),  // find -> e1 (plain justified); characterize -> 2
            (0x104, 4),  // find -> null; characterize -> 1 (unjustified)
            (0x110, 8),  // find -> null; characterize -> 0 (gate closed)
            (0xFC, 8),   // find -> null; characterize -> 0 (containedBy false)
        ];
        for &(off, sz) in fc.iter() {
            let hit = model.find_entry(AddressSpace::Register, Address::new(off), sz, true);
            let fe = match hit { Some(i) => format!("e{}", i), None => "null".to_string() };
            let cls = model.characterize_as_param(AddressSpace::Register, off, sz);
            println!("  fc spc=reg off=0x{:x} sz={} fe={} ch={}", off, sz, fe, cls);
        }
    }
}
