// FSPEC-SPACELESS-REM-1204: Rugra comparand for the locked Ghidra
// 12.0.4 oracle (FSPEC-SPACELESS-REMAINDER). Mirrors
// tests/oracle/fspec_spaceless_rem_1204.cc case for case:
//  - uc_plain_cross_space / uc_join_reachable:
//    ParamListStandard::unjustified_container (fspec.cc:1411-1424)
//    threads the query space into justified_contain_in_space — no
//    caller-level filter, space rejection only inside the walk
//    (fspec.cc:269 / address.cc:133 plain; per-piece address.cc:133
//    joins, which ARE reachable; getContainer passes back the
//    containing PIECE, fspec.cc:295).
//  - fb_*: ParamListStandardOut::fillin_map_fallback (fspec.cc:1638-
//    1719) — both trial queries (cc:1656 and the cc:1702 best-entry
//    re-evaluation) go through justified_contain_in_space with the
//    trial's own space; the caller-level getSpace() equality guard is
//    gone, join entries match register/ram trials per piece, the best
//    loop overwrites per-entry evaluation state, the offmatch
//    contiguity walk, minSize coverage gate, type/cover preference,
//    and the firstOnly skip (cc:1649-1652) are exercised.

use rudra::address::Address;
use rudra::fspec::param_entry_flags;
use rudra::fspec::{ParamActive, ParamEntry, ParamListStandard,
                   ParamListStandardOut, TypeClass, VarnodeData};
use rudra::space::AddressSpace;

// staged-loader entry builder (the pub equivalent of the C++ fixture's
// direct field writes; same pattern as the fspec_possibleparam_1204
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

fn print_uc(model: &ParamListStandard, spcname: &str, space: AddressSpace,
            off: u64, sz: i32) {
    let mut res = VarnodeData { space: AddressSpace::Ram, offset: 0, size: 0 };
    let hit = model.unjustified_container(space, Address::new(off), sz, &mut res);
    let mut line = format!("  uc spc={} off=0x{:x} sz={} hit={}", spcname, off, sz,
                           if hit { 1 } else { 0 });
    if hit {
        line.push_str(&format!(" res={}:0x{:x}/{}", res.space.name(),
                               res.offset, res.size));
    }
    println!("{}", line);
}

// Register active trials then run fillin_map_fallback and dump the
// final trial order (post sort_trials) with used/entry/offset state.
fn run_fb(out: &ParamListStandardOut, active: &mut ParamActive, first_only: bool) {
    out.fillin_map_fallback(active, first_only);
    for i in 0..active.get_num_trials() {
        let t = active.get_trial(i);
        let entry = t.get_entry_index().map(|ix| ix as i32).unwrap_or(-1);
        println!("  fb spc={} off=0x{:x} sz={} used={} entry={} joff={}",
                 t.get_space().name(), t.get_address().as_u64(), t.get_size(),
                 t.is_used() as i32, entry, t.get_offset());
    }
}

fn main() {
    println!("schema=1|fixture=FSPEC-SPACELESS-REM-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // ---- case 1: plain entries, cross-space rejection ----------------
    println!("case=uc_plain_cross_space");
    {
        let mut model = ParamListStandard::new();
        // e0: register [0x100,0x107] min 2, exclusion, force-left
        model.entry_mut().push(make_entry(
            0, AddressSpace::Register, 0x100, 8, 2, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        // e1: ram [0x100,0x10F] min 4, alignment 8 (non-exclusion)
        model.entry_mut().push(make_entry(
            1, AddressSpace::Ram, 0x100, 16, 4, 8, 0,
        ));
        // e2: register [0x200,0x207] min 4, exclusion, force-left
        model.entry_mut().push(make_entry(
            2, AddressSpace::Register, 0x200, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        model.set_num_group(3);
        let uc: [(&str, AddressSpace, u64, i32); 7] = [
            ("reg", AddressSpace::Register, 0x104, 4),   // unjustified in e0 -> 0x100/8
            ("reg", AddressSpace::Register, 0x100, 4),   // just==0 -> early false
            ("stack", AddressSpace::Stack, 0x104, 4),    // address.cc:133 -> hit=0
            ("ram", AddressSpace::Ram, 0x104, 8),        // e1 aligned route, just=4 -> 0x100/16
            ("reg", AddressSpace::Register, 0x100, 1),   // minSize gate
            ("ram", AddressSpace::Ram, 0x108, 8),        // aligned justified -> false
            ("reg", AddressSpace::Register, 0x202, 2),   // e2 container 0x200/8
        ];
        for &(name, space, off, sz) in uc.iter() {
            print_uc(&model, name, space, off, sz);
        }
    }

    // ---- case 2: join entries ARE reachable --------------------------
    println!("case=uc_join_reachable");
    {
        let pieces = [
            VarnodeData { space: AddressSpace::Ram, offset: 0x204, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
        ];
        let mut model = ParamListStandard::new();
        // e0: join ram:0x204 (high) + reg:0x100 (low)
        model.entry_mut().push(make_join_entry(0, 8, 4, &pieces));
        // e1: register [0x100,0x107] min 4, exclusion, force-left
        model.entry_mut().push(make_entry(
            1, AddressSpace::Register, 0x100, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        model.set_num_group(2);
        let uc: [(&str, AddressSpace, u64, i32); 6] = [
            ("reg", AddressSpace::Register, 0x102, 2),   // low piece just=2 -> PIECE reg:0x100/4
            ("reg", AddressSpace::Register, 0x104, 4),   // join walk -1 -> e1 just=4
            ("reg", AddressSpace::Register, 0x204, 4),   // both pieces foreign -> -1
            ("ram", AddressSpace::Ram, 0x204, 4),        // skip low (+4), high cur=0 -> PIECE ram:0x204/4
            ("reg", AddressSpace::Register, 0x100, 4),   // low piece just=0 -> early false
            ("stack", AddressSpace::Stack, 0x102, 2),    // per-piece address.cc:133 -> hit=0
        ];
        for &(name, space, off, sz) in uc.iter() {
            print_uc(&model, name, space, off, sz);
        }
    }

    // ---- case 3: fallback, plain entries, best cover ------------------
    println!("case=fb_plain_best_cover");
    {
        let mut out = ParamListStandardOut::new();
        out.base.entry_mut().push(make_entry(
            0, AddressSpace::Register, 0x100, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY
                | param_entry_flags::FIRST_STORAGE,
        ));
        out.base.entry_mut().push(make_entry(
            1, AddressSpace::Ram, 0x100, 16, 4, 8,
            param_entry_flags::FIRST_STORAGE,
        ));
        // e2: same range as e0 but min 8 — coverage tie rejected
        out.base.entry_mut().push(make_entry(
            2, AddressSpace::Register, 0x100, 8, 8, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY
                | param_entry_flags::FIRST_STORAGE,
        ));
        out.base.set_num_group(3);
        let mut active = ParamActive::new(false);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x104), 4);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x100), 4);
        active.register_trial_in_space(AddressSpace::Stack, Address::new(0x104), 4);
        for i in 0..active.get_num_trials() {
            active.get_trial_mut(i).mark_active();
        }
        run_fb(&out, &mut active, false);
    }

    // ---- case 4: fallback, join entry reachable (core divergence) -----
    println!("case=fb_join_reachable");
    {
        let pieces = [
            VarnodeData { space: AddressSpace::Register, offset: 0x104, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
        ];
        let mut out = ParamListStandardOut::new();
        out.base.entry_mut().push(make_join_entry(0, 8, 4, &pieces));
        *out.base.entry_mut().last_mut().unwrap().flags_mut() |=
            param_entry_flags::FIRST_STORAGE;
        out.base.entry_mut().push(make_entry(
            1, AddressSpace::Register, 0x200, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY
                | param_entry_flags::FIRST_STORAGE,
        ));
        out.base.set_num_group(2);
        let mut active = ParamActive::new(false);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x100), 4);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x104), 4);
        for i in 0..active.get_num_trials() {
            active.get_trial_mut(i).mark_active();
        }
        run_fb(&out, &mut active, false);
    }

    // ---- case 5: fallback, cross-space join pieces ---------------------
    println!("case=fb_cross_space_join");
    {
        let pieces = [
            VarnodeData { space: AddressSpace::Ram, offset: 0x204, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
        ];
        let mut out = ParamListStandardOut::new();
        out.base.entry_mut().push(make_join_entry(0, 8, 4, &pieces));
        *out.base.entry_mut().last_mut().unwrap().flags_mut() |=
            param_entry_flags::FIRST_STORAGE;
        out.base.set_num_group(1);
        let mut active = ParamActive::new(false);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x100), 4);
        active.register_trial_in_space(AddressSpace::Ram, Address::new(0x204), 4);
        active.register_trial_in_space(AddressSpace::Stack, Address::new(0x204), 4);
        for i in 0..active.get_num_trials() {
            active.get_trial_mut(i).mark_active();
        }
        run_fb(&out, &mut active, false);
    }

    // ---- case 6: firstOnly skips non-first single-group exclusions -----
    println!("case=fb_first_only_skip");
    {
        let mut out = ParamListStandardOut::new();
        out.base.entry_mut().push(make_entry(
            0, AddressSpace::Register, 0x100, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY
                | param_entry_flags::FIRST_STORAGE,
        ));
        // e1: NOT first_storage, exclusion (alignment 0), one group
        out.base.entry_mut().push(make_entry(
            1, AddressSpace::Register, 0x108, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        out.base.set_num_group(2);
        let mut active = ParamActive::new(false);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x108), 4);
        active.get_trial_mut(0).mark_active();
        run_fb(&out, &mut active, true);
    }

    // ---- case 7: same layout, firstOnly=false reaches e1 ----------------
    println!("case=fb_first_only_allowed");
    {
        let mut out = ParamListStandardOut::new();
        out.base.entry_mut().push(make_entry(
            0, AddressSpace::Register, 0x100, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY
                | param_entry_flags::FIRST_STORAGE,
        ));
        out.base.entry_mut().push(make_entry(
            1, AddressSpace::Register, 0x108, 8, 4, 0,
            param_entry_flags::FORCE_LEFT_JUSTIFY,
        ));
        out.base.set_num_group(2);
        let mut active = ParamActive::new(false);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x108), 4);
        active.get_trial_mut(0).mark_active();
        run_fb(&out, &mut active, false);
    }
}
