// FSPEC-PHASE0-1204: Rugra comparand for the locked Ghidra 12.0.4 fspec
// Phase-0 oracle (FSPEC-SPACEFILTER-0002 + FSPEC-TRIALCMP-0003). Mirrors
// tests/oracle/fspec_phase0_1204.cc case for case:
//  - find_entry resolves only entries whose space equals the query space
//    (register/stack entries hit; const/unique/ram cross-offset queries
//    miss),
//  - unjustified_container/assumed_extension iterate every entry with no
//    space filter,
//  - sort_trials orders by ParamTrial::op_less (group, entry order,
//    exclusion offset / reverseStack-aware address, size; entry-less
//    trials last),
//  - split_hi/split_lo produce (addr, size, slot, flags) per fspec.cc:1845/
//    1856 and split_trial renumbers survivor slots and bumps slotbase
//    (fspec.cc:2033).
// Trial addresses are minted through the SpaceRegistry (register/stack) so
// the comparator orders real spaces exactly like Ghidra's tagged Addresses.
// Slot observations are deltas (Ghidra slots are 1-based, fspec.cc:4062;
// Rugra's coupled consumers are 0-based — outside the covered projection).

use rudra::address::Address;
use rudra::fspec::param_entry_flags;
use rudra::fspec::{ParamActive, ParamEntry, ParamListStandard, TypeClass};
use rudra::fspec::VarnodeData;
use rudra::space::{AddrSpace, AddressSpace, SpaceRegistry, SpaceType};

fn proc_space(name: &str, big_end: bool, size: u32, ws: u32, ind: i32, fl: u32) -> AddrSpace {
    AddrSpace::new_space(SpaceType::Processor, name, big_end, size, ws, ind, fl, 0, 0)
}

// canonical synthetic spaces: constant=0, other=1, unique=2, ram=3,
// register=4, stack=5 (same index plan as the C++ oracle fixture).
fn build_spaces(m: &mut SpaceRegistry) {
    m.insert_space(AddrSpace::new_constant_space(false)).unwrap();
    m.insert_space(AddrSpace::new_other_space()).unwrap();
    m.insert_space(AddrSpace::new_unique_space(2, 0, false)).unwrap();
    let ram_handle = proc_space("ram", false, 8, 1, 3, 1);
    m.insert_space(ram_handle.clone()).unwrap();
    m.insert_space(proc_space("register", false, 8, 1, 4, 1)).unwrap();
    m.insert_space(AddrSpace::new_spacebase_space(
        "stack", 5, 8, &ram_handle, 0, true, false,
    )).unwrap();
}

fn vd(v: &VarnodeData) -> String {
    format!("{}:0x{:x}/{}", v.space.name(), v.offset, v.size)
}

// staged-loader entry builder (the pub equivalent of the C++ fixture's
// direct field writes).
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

fn main() {
    println!("schema=1|fixture=FSPEC-PHASE0-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    let mut registry = SpaceRegistry::new();
    build_spaces(&mut registry);
    let reg_handle = registry.get_space_by_name("register").unwrap();
    let stack_handle = registry.get_space_by_name("stack").unwrap();

    let coarse_reg = AddressSpace::Register;
    let coarse_stack = AddressSpace::Stack;
    let coarse_ram = AddressSpace::Ram;
    let coarse_unique = AddressSpace::Unique;
    let coarse_const = AddressSpace::Const;

    let mut model = ParamListStandard::new();
    let mut effects = Vec::new();
    model.parse_pentry(0, true, false, false, &mut effects, make_entry(
        0, coarse_reg, 0x30, 8, 4, 8, // alignment == size -> exclusion
        param_entry_flags::FORCE_LEFT_JUSTIFY,
    )).unwrap();
    model.parse_pentry(1, true, false, false, &mut effects, make_entry(
        1, coarse_reg, 0x38, 8, 4, 8,
        param_entry_flags::FORCE_LEFT_JUSTIFY | param_entry_flags::SMALLSIZE_ZEXT,
    )).unwrap();
    model.parse_pentry(2, true, false, false, &mut effects, make_entry(
        2, coarse_stack, 0, 64, 4, 8, // aligned, non-exclusion
        param_entry_flags::REVERSE_STACK,
    )).unwrap();
    model.parse_pentry(3, true, false, false, &mut effects, make_entry(
        3, coarse_ram, 0x2000, 16, 8, 16,
        param_entry_flags::FORCE_LEFT_JUSTIFY | param_entry_flags::SMALLSIZE_INTTYPE,
    )).unwrap();
    model.finalize_after_decode(0);
    let entries = model.get_entry().to_vec();

    // ---- case 1: find_entry per-space resolution ----
    println!("case=cross_space_find_entry");
    let pp: [(AddressSpace, u64, i32); 12] = [
        (coarse_reg, 0x30, 8),
        (coarse_reg, 0x30, 4),
        (coarse_reg, 0x34, 4),
        (coarse_reg, 0x30, 2),
        (coarse_reg, 0x48, 8),
        (coarse_stack, 0x8, 8),
        (coarse_stack, 0x10, 4),
        (coarse_stack, 0x100, 8),
        (coarse_ram, 0x2000, 16),
        (coarse_ram, 0x30, 8),
        (coarse_unique, 0x30, 8),
        (coarse_const, 0x2000, 8),
    ];
    for &(spc, off, sz) in pp.iter() {
        let mut slot: i32 = -1;
        let mut slot_size: i32 = -1;
        let ok = model.possible_param_with_slot(
            spc, Address::new(off), sz, &mut slot, &mut slot_size,
        );
        println!("  pp {}:{}/{} ok={} slot={} slotsize={}", spc.name(), hex(off), sz,
                 if ok { 1 } else { 0 }, slot, slot_size);
    }

    // ---- case 2: unjustified_container has no space filter ----
    println!("case=unjustified_container");
    let uc: [(AddressSpace, u64, i32); 5] = [
        (coarse_reg, 0x34, 4),
        (coarse_reg, 0x32, 4),
        (coarse_reg, 0x30, 4),
        (coarse_ram, 0x2008, 8),
        (coarse_stack, 0x2, 8),
    ];
    for &(spc, off, sz) in uc.iter() {
        let mut res = VarnodeData { space: AddressSpace::Ram, offset: 0, size: 0 };
        let hit = model.unjustified_container(spc, Address::new(off), sz, &mut res);
        if hit {
            println!("  uc {}:{}/{} hit=1 res={}", spc.name(), hex(off), sz, vd(&res));
        } else {
            println!("  uc {}:{}/{} hit=0", spc.name(), hex(off), sz);
        }
    }

    // ---- case 3: assumed_extension has no space filter ----
    println!("case=assumed_extension");
    let ae: [(AddressSpace, u64, i32); 5] = [
        (coarse_reg, 0x38, 4),
        (coarse_ram, 0x2000, 8),
        (coarse_reg, 0x30, 4),
        (coarse_ram, 0x2004, 8),
        (coarse_reg, 0x38, 8),
    ];
    for &(spc, off, sz) in ae.iter() {
        let mut res = VarnodeData { space: AddressSpace::Ram, offset: 0, size: 0 };
        let op = model.assumed_extension(spc, Address::new(off), sz, &mut res);
        if op != rudra::opcodes::OpCode::CPUI_COPY {
            println!("  ae {}:{}/{} op={} res={}", spc.name(), hex(off), sz, op.name(), vd(&res));
        } else {
            println!("  ae {}:{}/{} op=COPY", spc.name(), hex(off), sz);
        }
    }

    // ---- case 4: sort_trials uses the operator< ladder ----
    println!("case=sort_trials");
    {
        let mut active = ParamActive::new(false);
        assert!(active.register_trial(Address::with_space(&stack_handle, 0x10), 8));
        assert!(active.register_trial(Address::with_space(&reg_handle, 0x38), 4));
        assert!(active.register_trial(Address::with_space(&stack_handle, 0x0), 8));
        assert!(active.register_trial(Address::with_space(&reg_handle, 0x30), 8));
        assert!(active.register_trial(Address::with_space(&reg_handle, 0x34), 4));
        assert!(active.register_trial(Address::with_space(&reg_handle, 0x50), 8));
        active.get_trial_mut(0).set_entry(2, 0);
        active.get_trial_mut(1).set_entry(1, 0);
        active.get_trial_mut(2).set_entry(2, 0);
        active.get_trial_mut(3).set_entry(0, 0);
        active.get_trial_mut(4).set_entry(0, 4);
        active.sort_trials(&entries);
        for i in 0..active.get_num_trials() {
            let t = active.get_trial(i);
            let entry = t.get_entry_index();
            let grp = entry.map(|ix| entries[ix].get_group()).unwrap_or(-1);
            let off = entry.map(|_| t.get_offset()).unwrap_or(-1);
            let spc = t.get_address().get_space().map(|s| s.get_name()).unwrap_or_default();
            println!("  sorted[{}] addr={}:0x{:x} size={} grp={} off={}",
                     i, spc, t.get_address().as_u64(), t.get_size(), grp, off);
        }
    }

    // ---- case 5: split_hi/split_lo address, flags, slot ----
    println!("case=split_hi_lo");
    {
        let mut active = ParamActive::new(false);
        assert!(active.register_trial(Address::with_space(&reg_handle, 0x100), 12));
        {
            let t = active.get_trial_mut(0);
            t.mark_used();
            t.mark_active();
        }
        let (base_slot, base_addr) = {
            let t = active.get_trial(0);
            (t.get_slot(), t.get_address())
        };
        let hi = active.get_trial(0).split_hi(4);
        let lo = active.get_trial(0).split_lo(4);
        let name = |a: Address| a.get_space().map(|s| s.get_name()).unwrap_or_default();
        println!("  hi addr={}:0x{:x} size={} slot_delta={} used={} active={} checked={}",
                 name(hi.get_address()), hi.get_address().as_u64(), hi.get_size(),
                 hi.get_slot() - base_slot, hi.is_used() as i32, hi.is_active() as i32,
                 hi.is_checked() as i32);
        println!("  lo addr={}:0x{:x} size={} slot_delta={} used={} active={} checked={}",
                 name(lo.get_address()), lo.get_address().as_u64(), lo.get_size(),
                 lo.get_slot() - base_slot, lo.is_used() as i32, lo.is_active() as i32,
                 lo.is_checked() as i32);
        let lo8 = active.get_trial(0).split_lo(8);
        println!("  lo8 addr={}:0x{:x} size={} slot_delta={}",
                 name(lo8.get_address()), lo8.get_address().as_u64(), lo8.get_size(),
                 lo8.get_slot() - base_slot);
        let _ = base_addr;
    }

    // ---- case 6: split_trial rebuilds slots and keeps flags ----
    println!("case=split_trial");
    {
        let mut active = ParamActive::new(false);
        assert!(active.register_trial(Address::with_space(&reg_handle, 0x100), 12));
        assert!(active.register_trial(Address::with_space(&reg_handle, 0x200), 8));
        {
            let t = active.get_trial_mut(0);
            t.mark_used();
            t.mark_active();
        }
        let survivor_slot_before = active.get_trial(1).get_slot();
        let slotbase_before = active.get_slot_base();
        active.split_trial(0, 4);
        let name = |ix: usize| {
            active.get_trial(ix).get_address().get_space()
                .map(|s| s.get_name()).unwrap_or_default()
        };
        for i in 0..active.get_num_trials() {
            let t = active.get_trial(i);
            println!("  st[{}] addr={}:0x{:x} size={} used={} active={}",
                     i, name(i), t.get_address().as_u64(), t.get_size(),
                     t.is_used() as i32, t.is_active() as i32);
        }
        println!("  survivor_slot_delta={} slotbase_delta={} numtrials={}",
                 active.get_trial(2).get_slot() - survivor_slot_before,
                 active.get_slot_base() - slotbase_before,
                 active.get_num_trials());
    }
}

fn hex(v: u64) -> String {
    format!("0x{:x}", v)
}
