// FSPEC-POSSIBLEPARAM-1204: Rugra comparand for the locked Ghidra
// 12.0.4 oracle (FSPEC-POSSIBLEPARAM-JOIN-0006, A46 residual 3).
// Mirrors tests/oracle/fspec_possibleparam_1204.cc case for case:
//  - plain_out_entries: ParamListStandardOut::possible_param iterates
//    the raw entry list (no resolver window, no caller-level space
//    filter, no minSize gate) and accepts any justifiedContain >= 0
//    (fspec.cc:1765-1774); space rejection happens only inside
//    justifiedContain (fspec.cc:269 / address.cc:133).
//  - join_out_entries: join entries are reachable through the
//    per-piece join walk (fspec.cc:251-262): 0x104/4 gives offset 4
//    >= 0 -> true, unlike find_entry(just=true)'s == 0 gate.
//  - cross_space_join: the foreign low piece contributes
//    address.cc:133 -1 (+4 skip), the containing high piece cur=0,
//    so a ram query returns offset 4 >= 0 -> true.
//  - assumed_extension: ParamListStandard::assumed_extension
//    (fspec.cc:1426) -> ParamEntry::assumed_extension (fspec.cc:366)
//    with the space-aware cc:377 gate, the cc:376 join guard, the sz
//    gates, the list minSize skip, and both container shapes.

use rudra::address::Address;
use rudra::fspec::{param_entry_flags, ParamEntry, ParamListStandard,
                   ParamListStandardOut, TypeClass, VarnodeData};
use rudra::space::AddressSpace;

// staged-loader entry builder (the pub equivalent of the C++ fixture's
// direct field writes; same pattern as the fspec_findentry_1204
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

fn print_pp(out: &ParamListStandardOut, spcname: &str, space: AddressSpace,
            off: u64, sz: i32) {
    let hit = out.possible_param(space, Address::new(off), sz);
    println!("  pp spc={} off=0x{:x} sz={} -> {}", spcname, off, sz,
             if hit { "true" } else { "false" });
}

fn print_ae(model: &ParamListStandard, spcname: &str, space: AddressSpace,
            off: u64, sz: i32) {
    let mut res = VarnodeData { space: AddressSpace::Ram, offset: 0, size: 0 };
    let ext = model.assumed_extension(space, Address::new(off), sz, &mut res);
    let mut line = format!("  ae spc={} off=0x{:x} sz={} -> {}", spcname, off,
                           sz, ext.name());
    if ext != rudra::opcodes::OpCode::CPUI_COPY {
        line.push_str(&format!(" res={}:0x{:x}/{}", res.space.name(),
                               res.offset, res.size));
    }
    println!("{}", line);
}

fn main() {
    println!("schema=1|fixture=FSPEC-POSSIBLEPARAM-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // ---- case 1: plain output entries --------------------------------
    println!("case=plain_out_entries");
    {
        let mut out = ParamListStandardOut::new();
        // e0: register [0x200,0x207] min 4, exclusion, force-left
        out.base.entry_mut().push(make_entry(
            0, AddressSpace::Register, 0x200, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        // e1: register [0x1000,0x100F] min 4, alignment 8 (aligned route)
        out.base.entry_mut().push(make_entry(
            1, AddressSpace::Register, 0x1000, 16, 4, 8, 0,
        ));
        // e2: ram [0x2000,0x200F] min 2, exclusion, force-left
        out.base.entry_mut().push(make_entry(
            2, AddressSpace::Ram, 0x2000, 16, 2, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        out.base.set_num_group(3);
        let pp: [(&str, AddressSpace, u64, i32); 10] = [
            ("reg", AddressSpace::Register, 0x200, 4),    // justified hit -> true
            ("reg", AddressSpace::Register, 0x202, 2),    // unjustified offset 2: >= 0 -> true
            ("reg", AddressSpace::Register, 0x208, 4),    // above e0, below e1 -> false
            ("reg", AddressSpace::Register, 0x1000, 8),   // aligned justified hit -> true
            ("reg", AddressSpace::Register, 0x1002, 4),   // aligned unjustified (2) -> true
            ("stack", AddressSpace::Stack, 0x1000, 8),    // cc:269 foreign-space guard -> false
            ("stack", AddressSpace::Stack, 0x200, 4),     // address.cc:133 route -> false
            ("ram", AddressSpace::Ram, 0x2000, 1),        // NO minSize gate (min 2 > 1) -> true
            ("reg", AddressSpace::Register, 0x200, 1),    // NO minSize gate (min 4 > 1) -> true
            ("unique", AddressSpace::Unique, 0x200, 4),   // foreign space -> false
        ];
        for &(name, space, off, sz) in pp.iter() {
            print_pp(&out, name, space, off, sz);
        }
    }

    // ---- case 2: join entries ARE reachable --------------------------
    println!("case=join_out_entries");
    {
        let pieces = [
            VarnodeData { space: AddressSpace::Register, offset: 0x104, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
        ];
        let mut out = ParamListStandardOut::new();
        // e0: join reg:0x104 (high) + reg:0x100 (low)
        out.base.entry_mut().push(make_join_entry(0, 8, 4, &pieces));
        // e1: plain register [0x200,0x207] min 4
        out.base.entry_mut().push(make_entry(
            1, AddressSpace::Register, 0x200, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        out.base.set_num_group(2);
        let pp: [(&str, AddressSpace, u64, i32); 6] = [
            ("reg", AddressSpace::Register, 0x100, 4),    // low piece offset 0 -> true (join!)
            ("reg", AddressSpace::Register, 0x104, 4),    // walk offset 4 >= 0 -> true (join!)
            ("reg", AddressSpace::Register, 0x100, 8),    // join walk -1, e1 no -> false
            ("reg", AddressSpace::Register, 0x102, 4),    // pokes out of both pieces -> false
            ("reg", AddressSpace::Register, 0x200, 4),    // plain entry hit -> true
            ("stack", AddressSpace::Stack, 0x100, 4),     // per-piece address.cc:133 -> false
        ];
        for &(name, space, off, sz) in pp.iter() {
            print_pp(&out, name, space, off, sz);
        }
    }

    // ---- case 3: cross-space join pieces ------------------------------
    println!("case=cross_space_join");
    {
        let pieces = [
            VarnodeData { space: AddressSpace::Ram, offset: 0x200, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x200, size: 4 },
        ];
        let mut out = ParamListStandardOut::new();
        out.base.entry_mut().push(make_join_entry(0, 8, 4, &pieces));
        out.base.set_num_group(1);
        let pp: [(&str, AddressSpace, u64, i32); 5] = [
            ("reg", AddressSpace::Register, 0x200, 4),    // low piece offset 0 -> true
            ("ram", AddressSpace::Ram, 0x200, 4),         // foreign low -1 (+4), high cur=0 -> 4 >= 0 -> true
            ("reg", AddressSpace::Register, 0x204, 4),    // outside both pieces -> false
            ("reg", AddressSpace::Register, 0x200, 8),    // low pokes out, high foreign -> -1 -> false
            ("stack", AddressSpace::Stack, 0x200, 4),     // both pieces foreign -> false
        ];
        for &(name, space, off, sz) in pp.iter() {
            print_pp(&out, name, space, off, sz);
        }
    }

    // ---- case 4: assumed_extension gates and containers ----------------
    println!("case=assumed_extension");
    {
        let pieces = [
            VarnodeData { space: AddressSpace::Register, offset: 0x204, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x200, size: 4 },
        ];
        let mut model = ParamListStandard::new();
        // e0: register [0x100,0x11F] min 2 alignment 8, smallsize zext
        model.entry_mut().push(make_entry(
            0, AddressSpace::Register, 0x100, 32, 2, 8,
            param_entry_flags::SMALLSIZE_ZEXT,
        ));
        // e1: join reg:0x204 + reg:0x200 min 2, smallsize sext (never
        // extends: cc:376 join guard)
        model.entry_mut().push(make_join_entry(1, 8, 2, &pieces));
        *model.entry_mut().last_mut().unwrap().flags_mut() =
            param_entry_flags::SMALLSIZE_SEXT;
        // e2: ram [0x2000,0x200F] min 2, exclusion, smallsize inttype
        model.entry_mut().push(make_entry(
            2, AddressSpace::Ram, 0x2000, 16, 2, 0,
            param_entry_flags::SMALLSIZE_INTTYPE,
        ));
        // e3: register [0x3000,0x3007] min 2, exclusion, smallsize sext
        model.entry_mut().push(make_entry(
            3, AddressSpace::Register, 0x3000, 8, 2, 0,
            param_entry_flags::SMALLSIZE_SEXT,
        ));
        // e4: register [0x4000,0x4007] min 2, exclusion, zext|inttype —
        // cc:389 zext wins over cc:391 inttype
        model.entry_mut().push(make_entry(
            4, AddressSpace::Register, 0x4000, 8, 2, 0,
            param_entry_flags::SMALLSIZE_ZEXT
                | param_entry_flags::SMALLSIZE_INTTYPE,
        ));
        // e5: register [0x5000,0x5007] min 2, exclusion, inttype|sext —
        // cc:391 inttype wins over cc:393 sext
        model.entry_mut().push(make_entry(
            5, AddressSpace::Register, 0x5000, 8, 2, 0,
            param_entry_flags::SMALLSIZE_INTTYPE
                | param_entry_flags::SMALLSIZE_SEXT,
        ));
        model.set_num_group(6);
        let ae: [(&str, AddressSpace, u64, i32); 13] = [
            ("reg", AddressSpace::Register, 0x100, 2),    // justified -> ZEXT, container 0x100/8
            ("reg", AddressSpace::Register, 0x108, 2),    // second slot -> ZEXT, container 0x108/8
            ("reg", AddressSpace::Register, 0x102, 2),    // unjustified (2 % 8) -> COPY
            ("stack", AddressSpace::Stack, 0x100, 2),     // foreign space at numeric hit -> COPY
            ("reg", AddressSpace::Register, 0x100, 8),    // sz >= alignment (and all later gates)
            ("reg", AddressSpace::Register, 0x100, 1),    // list minSize skip (e0/e1/e2 min 2)
            ("reg", AddressSpace::Register, 0x200, 2),    // join guard cc:376 (low piece justifies)
            ("ram", AddressSpace::Ram, 0x2000, 4),        // exclusion container 0x2000/16 -> PIECE
            ("ram", AddressSpace::Ram, 0x2002, 4),        // unjustified (offset 2) -> COPY
            ("stack", AddressSpace::Stack, 0x2000, 4),    // address.cc:133 route -> COPY
            ("reg", AddressSpace::Register, 0x3000, 2),   // sext only -> INT_SEXT, container 0x3000/8
            ("reg", AddressSpace::Register, 0x4000, 2),   // zext|inttype -> INT_ZEXT (cc:389 first)
            ("reg", AddressSpace::Register, 0x5000, 2),   // inttype|sext -> PIECE (cc:391 before 393)
        ];
        for &(name, space, off, sz) in ae.iter() {
            print_ae(&model, name, space, off, sz);
        }
    }
}
