// ADDRESS-SPACE-HANDLE-1204: Rudra comparand for the locked Ghidra 12.0.4
// space-aware Address/Range/RangeList oracle (address.hh/address.cc).
// Mirrors tests/oracle/address_space_handle_1204.cc case for case through
// the ADDRESS-0001 handle types (SpaceAddress/SpaceRange/SpaceRangeList)
// over the architecture-owned SpaceRegistry; every observation is printed
// in the shared line format and must match the C++ output byte for byte.

use rudra::address::{RangeProperties, SpaceAddress, SpaceRange, SpaceRangeList};
use rudra::space::{space_flags, AddrSpace, SpaceRegistry, SpaceType};

fn hex_u64(v: u64) -> String {
    format!("0x{:x}", v)
}

fn walk_label(a: &SpaceAddress) -> String {
    if a.is_invalid() {
        return format!("invalid:{}", hex_u64(a.get_offset()));
    }
    match a.get_space() {
        None => format!("maximal:{}", hex_u64(a.get_offset())),
        Some(spc) => format!("{}:{}", spc.get_name(), hex_u64(a.get_offset())),
    }
}

fn try_range_props(props: &RangeProperties, manage: &SpaceRegistry) -> String {
    match SpaceRange::from_properties(props, manage) {
        Ok(range) => range.print_bounds(),
        Err(msg) => format!("err {}", msg),
    }
}

fn proc_space(name: &str, big_end: bool, size: u32, ws: u32, ind: i32, fl: u32) -> AddrSpace {
    AddrSpace::new_space(SpaceType::Processor, name, big_end, size, ws, ind, fl, 0, 0)
}

// Build the canonical synthetic architecture plus the extra spaces the
// wrap/justified cases need: flash4 = 4-byte space, ws2spc = 4-byte space
// with wordsize 2, beram = big-endian 8-byte space (same layout as the C++
// oracle fixture).
fn build_spaces(m: &mut SpaceRegistry) {
    m.insert_space(AddrSpace::new_constant_space(false)).unwrap();
    m.insert_space(AddrSpace::new_other_space()).unwrap();
    m.insert_space(AddrSpace::new_unique_space(2, 0, false)).unwrap();
    m.insert_space(proc_space("ram", false, 8, 1, 3, space_flags::HASPHYSICAL))
        .unwrap();
    m.insert_space(proc_space("register", false, 8, 1, 4, space_flags::HASPHYSICAL))
        .unwrap();
    let ram = m.get_space_by_name("ram").unwrap();
    m.insert_space(AddrSpace::new_spacebase_space(
        "stack", 5, 8, &ram, 1, true, false,
    ))
    .unwrap();
    m.insert_space(AddrSpace::new_join_space(6, false)).unwrap();
    m.insert_space(AddrSpace::new_iop_space(7, false)).unwrap();
    m.insert_space(proc_space("flash4", false, 4, 1, 8, 0)).unwrap();
    m.insert_space(proc_space("ws2spc", false, 4, 2, 9, 0)).unwrap();
    m.insert_space(proc_space("beram", true, 8, 1, 10, 0)).unwrap();
}

fn b(cond: bool) -> i32 {
    if cond {
        1
    } else {
        0
    }
}

fn main() {
    println!(
        "schema=1|fixture=ADDRESS-SPACE-HANDLE-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case 1: invalid vs ram:0, extremal sentinels ----------------------
    println!("case=invalid_vs_ram0");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let constant = m.get_constant_space().unwrap();
        let join = m.get_join_space().unwrap();
        let invalid = SpaceAddress::minimal();
        let invalid2 = SpaceAddress::minimal();
        let ram0 = SpaceAddress::new(ram.clone(), 0);
        let ram1000 = SpaceAddress::new(ram.clone(), 0x1000);
        let maximal = SpaceAddress::maximal();
        let const10 = SpaceAddress::new(constant.clone(), 0x10);
        let join30 = SpaceAddress::new(join.clone(), 0x30);
        println!(
            "  invalidIsInvalid={} ram0IsInvalid={}",
            b(invalid.is_invalid()),
            b(ram0.is_invalid())
        );
        println!(
            "  print invalid={} ram0={} ram1000={}",
            invalid.print_raw(),
            ram0.print_raw(),
            ram1000.print_raw()
        );
        println!(
            "  eq_invalid_ram0={} eq_invalid_minimal={} ne_invalid_ram0={}",
            b(invalid == ram0),
            b(invalid == invalid2),
            b(invalid != ram0)
        );
        println!(
            "  lt_invalid_ram0={} lt_ram0_invalid={} le_invalid_ram0={}",
            b(invalid < ram0),
            b(ram0 < invalid),
            b(invalid <= ram0)
        );
        println!(
            "  lt_min_ram1000={} lt_max_ram1000={} lt_ram1000_max={} eq_max_max={}",
            b(invalid < ram1000),
            b(maximal < ram1000),
            b(ram1000 < maximal),
            b(maximal == SpaceAddress::maximal())
        );
        println!("  addrSize ram={}", ram0.get_addr_size());
        println!(
            "  const10 isConst={} isJoin={} join30 isJoin={} constPrint={}",
            b(const10.is_constant()),
            b(const10.is_join()),
            b(join30.is_join()),
            const10.print_raw()
        );
        println!(
            "  shortcut ram={} const={}",
            ram0.get_shortcut(),
            const10.get_shortcut()
        );
    }

    // ---- case 2: cross-space ordering in a sorted container ----------------
    println!("case=cross_space_ordering");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let constant = m.get_constant_space().unwrap();
        let other = m.get_space_by_name("OTHER").unwrap();
        let unique = m.get_unique_space().unwrap();
        let ram = m.get_space_by_name("ram").unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        let stack = m.get_stack_space().unwrap();
        let join = m.get_join_space().unwrap();
        let iop = m.get_iop_space().unwrap();
        let mut ordered: std::collections::BTreeSet<SpaceAddress> = std::collections::BTreeSet::new();
        ordered.insert(SpaceAddress::new(register_.clone(), 0x5000));
        ordered.insert(SpaceAddress::new(unique.clone(), 0x99));
        ordered.insert(SpaceAddress::new(ram.clone(), 0x1000));
        ordered.insert(SpaceAddress::new(constant.clone(), 0x7f));
        ordered.insert(SpaceAddress::new(other.clone(), 0x1));
        ordered.insert(SpaceAddress::new(stack.clone(), 0x20));
        ordered.insert(SpaceAddress::new(join.clone(), 0x30));
        ordered.insert(SpaceAddress::new(iop.clone(), 0x40));
        ordered.insert(SpaceAddress::new(ram.clone(), 0x2000));
        ordered.insert(SpaceAddress::new(register_.clone(), 0x3000));
        ordered.insert(SpaceAddress::new(unique.clone(), 0x11));
        ordered.insert(SpaceAddress::new(ram.clone(), 0x800));
        ordered.insert(SpaceAddress::minimal());
        ordered.insert(SpaceAddress::maximal());
        println!("  size={}", ordered.len());
        for a in &ordered {
            println!("  walk {}", walk_label(a));
        }
        println!(
            "  lt(const7f,other1)={} lt(register3000,ram2000)={} lt(ram800,ram1000)={} lt(unique99,ram1)={}",
            b(SpaceAddress::new(constant.clone(), 0x7f) < SpaceAddress::new(other.clone(), 0x1)),
            b(SpaceAddress::new(register_.clone(), 0x3000) < SpaceAddress::new(ram.clone(), 0x2000)),
            b(SpaceAddress::new(ram.clone(), 0x800) < SpaceAddress::new(ram.clone(), 0x1000)),
            b(SpaceAddress::new(unique.clone(), 0x99) < SpaceAddress::new(ram.clone(), 0x1))
        );
    }

    // ---- case 3: wrap boundaries through the real space --------------------
    println!("case=wrap_boundaries");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let flash4 = m.get_space_by_name("flash4").unwrap();
        let ws2spc = m.get_space_by_name("ws2spc").unwrap();
        let constant = m.get_constant_space().unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        println!(
            "  flash4 highest={} ws2 highest={} addrSize flash4={} ws2={}",
            hex_u64(flash4.get_highest()),
            hex_u64(ws2spc.get_highest()),
            SpaceAddress::new(flash4.clone(), 0).get_addr_size(),
            SpaceAddress::new(ws2spc.clone(), 0).get_addr_size()
        );
        println!(
            "  flash4 fffffffe+2={} ffffffff+1={} fffffffe+3={} 10-11={}",
            hex_u64(SpaceAddress::new(flash4.clone(), 0xfffffffe).add(2).get_offset()),
            hex_u64(SpaceAddress::new(flash4.clone(), 0xffffffff).add(1).get_offset()),
            hex_u64(SpaceAddress::new(flash4.clone(), 0xfffffffe).add(3).get_offset()),
            hex_u64(SpaceAddress::new(flash4.clone(), 0x10).sub(0x11).get_offset())
        );
        println!(
            "  ws2 1ffffffff+1={} 1ffffffff+3={} raw wrap 200000003={}",
            hex_u64(SpaceAddress::new(ws2spc.clone(), 0x1ffffffff).add(1).get_offset()),
            hex_u64(SpaceAddress::new(ws2spc.clone(), 0x1ffffffff).add(3).get_offset()),
            hex_u64(ws2spc.wrap_offset(0x200000003))
        );
        println!(
            "  ram maxff+1={} ram 100+ff={}",
            hex_u64(SpaceAddress::new(ram.clone(), 0xffffffffffffffff).add(1).get_offset()),
            hex_u64(SpaceAddress::new(ram.clone(), 0x100).add(0xff).get_offset())
        );
        println!(
            "  overlap wrap={} negskip={} const={} crossspace={} far={}",
            SpaceAddress::new(flash4.clone(), 0xfffffffe)
                .overlap(4, &SpaceAddress::new(flash4.clone(), 0x1), 8),
            SpaceAddress::new(flash4.clone(), 0x10)
                .overlap(-8, &SpaceAddress::new(flash4.clone(), 0x5), 16),
            SpaceAddress::new(constant.clone(), 0x10)
                .overlap(0, &SpaceAddress::new(constant.clone(), 0x8), 16),
            SpaceAddress::new(ram.clone(), 0x10)
                .overlap(0, &SpaceAddress::new(register_.clone(), 0x8), 16),
            SpaceAddress::new(flash4.clone(), 0x0)
                .overlap(0, &SpaceAddress::new(flash4.clone(), 0x8), 4)
        );
    }

    // ---- case 4: big-endian justified containment ---------------------------
    println!("case=justified_big_endian");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let beram = m.get_space_by_name("beram").unwrap();
        let leram = m.get_space_by_name("ram").unwrap();
        let constant = m.get_constant_space().unwrap();
        let be_container = SpaceAddress::new(beram.clone(), 0x100);
        let le_container = SpaceAddress::new(leram.clone(), 0x100);
        println!(
            "  beram endian big={} leram={}",
            b(be_container.is_big_endian()),
            b(le_container.is_big_endian())
        );
        println!(
            "  jc be full={} be low2={} be forceleft={} be high2={} be out={}",
            be_container.justified_contain(8, &SpaceAddress::new(beram.clone(), 0x100), 8, false),
            be_container.justified_contain(8, &SpaceAddress::new(beram.clone(), 0x100), 2, false),
            be_container.justified_contain(8, &SpaceAddress::new(beram.clone(), 0x100), 2, true),
            be_container.justified_contain(8, &SpaceAddress::new(beram.clone(), 0x106), 2, false),
            be_container.justified_contain(8, &SpaceAddress::new(beram.clone(), 0x108), 2, false)
        );
        println!(
            "  jc le low2={} cross={}",
            le_container.justified_contain(8, &SpaceAddress::new(leram.clone(), 0x100), 2, false),
            be_container.justified_contain(8, &SpaceAddress::new(leram.clone(), 0x100), 2, false)
        );
        println!(
            "  containedBy 100/4in100/8={} 102/4in100/4={} cross={}",
            b(SpaceAddress::new(beram.clone(), 0x100)
                .contained_by(4, &SpaceAddress::new(beram.clone(), 0x100), 8)),
            b(SpaceAddress::new(beram.clone(), 0x102)
                .contained_by(4, &SpaceAddress::new(beram.clone(), 0x100), 4)),
            b(SpaceAddress::new(beram.clone(), 0x100)
                .contained_by(4, &SpaceAddress::new(leram.clone(), 0x100), 8))
        );
        println!(
            "  contiguous be hit={} be miss={} le hit={} cross={}",
            b(SpaceAddress::new(beram.clone(), 0x104)
                .is_contiguous(4, &SpaceAddress::new(beram.clone(), 0x108), 4)),
            b(SpaceAddress::new(beram.clone(), 0x104)
                .is_contiguous(4, &SpaceAddress::new(beram.clone(), 0x100), 4)),
            b(SpaceAddress::new(leram.clone(), 0x104)
                .is_contiguous(4, &SpaceAddress::new(leram.clone(), 0x100), 4)),
            b(SpaceAddress::new(beram.clone(), 0x104)
                .is_contiguous(4, &SpaceAddress::new(leram.clone(), 0x100), 4))
        );
        println!(
            "  overlapJoin same={} pointcross={} opconst={} far={}",
            SpaceAddress::new(leram.clone(), 0x12)
                .overlap_join(0, &SpaceAddress::new(leram.clone(), 0x10), 8),
            SpaceAddress::new(constant.clone(), 0x12)
                .overlap_join(0, &SpaceAddress::new(leram.clone(), 0x10), 8),
            SpaceAddress::new(leram.clone(), 0x12)
                .overlap_join(0, &SpaceAddress::new(constant.clone(), 0x10), 8),
            SpaceAddress::new(leram.clone(), 0x1a)
                .overlap_join(0, &SpaceAddress::new(leram.clone(), 0x10), 8)
        );
    }

    // ---- case 5: RangeList space isolation, merge, split -------------------
    println!("case=range_space_isolation");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        let unique = m.get_unique_space().unwrap();
        let mut rl = SpaceRangeList::new();
        rl.insert_range(&ram, 0x1000, 0x1fff);
        rl.insert_range(&register_, 0x1000, 0x1fff);
        rl.insert_range(&ram, 0x2000, 0x2fff);
        println!("  numRanges={} (adjacent kept)", rl.num_ranges());
        print!("{}", rl.print_bounds());
        println!(
            "  inRange ram1ffc/4={} ram1ffd/4={} reg1000/4={} uniq1000/4={} invalid/4={}",
            b(rl.in_range(&SpaceAddress::new(ram.clone(), 0x1ffc), 4)),
            b(rl.in_range(&SpaceAddress::new(ram.clone(), 0x1ffd), 4)),
            b(rl.in_range(&SpaceAddress::new(register_.clone(), 0x1000), 4)),
            b(rl.in_range(&SpaceAddress::new(unique.clone(), 0x1000), 4)),
            b(rl.in_range(&SpaceAddress::minimal(), 4))
        );
        println!(
            "  getRange ram1500={} uniq1500={} ram3000={}",
            if rl.get_range(&ram, 0x1500).is_some() { "found" } else { "null" },
            if rl.get_range(&unique, 0x1500).is_some() { "found" } else { "null" },
            if rl.get_range(&ram, 0x3000).is_some() { "found" } else { "null" }
        );
        let ram_range = rl.get_range(&ram, 0x1500).unwrap();
        println!(
            "  contains ram1500={} reg1500={} invalid={}",
            b(ram_range.contains(&SpaceAddress::new(ram.clone(), 0x1500))),
            b(ram_range.contains(&SpaceAddress::new(register_.clone(), 0x1500))),
            b(ram_range.contains(&SpaceAddress::minimal()))
        );
        rl.insert_range(&ram, 0x1800, 0x2200);
        println!("  numRanges={} (overlap merged)", rl.num_ranges());
        rl.remove_range(&ram, 0x1400, 0x17ff);
        println!("  numRanges={} (split)", rl.num_ranges());
        print!("{}", rl.print_bounds());
    }

    // ---- case 6: RangeList queries, signed view, open end, merge -----------
    println!("case=rangelist_queries");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        let unique = m.get_unique_space().unwrap();
        let beram = m.get_space_by_name("beram").unwrap();
        let mut rl2 = SpaceRangeList::new();
        rl2.insert_range(&ram, 0x100, 0x1ff);
        rl2.insert_range(&ram, 0x200, 0x2ff);
        println!("  adjacent numRanges={}", rl2.num_ranges());
        println!(
            "  longestFit 150/1000={} 150/100={} 50/1000={} uniq150/1000={} invalid/1000={}",
            rl2.longest_fit(&SpaceAddress::new(ram.clone(), 0x150), 1000),
            rl2.longest_fit(&SpaceAddress::new(ram.clone(), 0x150), 100),
            rl2.longest_fit(&SpaceAddress::new(ram.clone(), 0x50), 1000),
            rl2.longest_fit(&SpaceAddress::new(unique.clone(), 0x150), 1000),
            rl2.longest_fit(&SpaceAddress::minimal(), 1000)
        );
        println!("  first={}", rl2.get_first_range().unwrap().print_bounds());
        println!("  last={}", rl2.get_last_range().unwrap().print_bounds());
        rl2.insert_range(&ram, 0xffffffff80000000, 0xffffffffffffffff);
        println!(
            "  signed ram={}",
            rl2.get_last_signed_range(&ram).unwrap().print_bounds()
        );
        let mut rl4 = SpaceRangeList::new();
        rl4.insert_range(&register_, 0xfffffff000000000, 0xfffffff0ffffffff);
        println!(
            "  signed negonly={}",
            rl4.get_last_signed_range(&register_).unwrap().print_bounds()
        );
        let mut rl5 = SpaceRangeList::new();
        rl5.insert_range(&ram, 0, 0xffffffffffffffff);
        let open5 = rl5.get_first_range().unwrap().get_last_addr_open(&m);
        println!("  lastAddrOpen fullram={} print={}", walk_label(&open5), open5.print_raw());
        let mut rl6 = SpaceRangeList::new();
        rl6.insert_range(&beram, 0, 0xffffffffffffffff);
        let open6 = rl6.get_first_range().unwrap().get_last_addr_open(&m);
        println!(
            "  lastAddrOpen fullberam isMax={} lt_before_max={}",
            b(open6 == SpaceAddress::maximal()),
            b(SpaceAddress::new(ram.clone(), 0x10) < open6)
        );
        let mut rl3 = SpaceRangeList::new();
        rl3.insert_range(&unique, 0x10, 0x1f);
        rl3.insert_range(&ram, 0x300, 0x3ff);
        rl2.merge(&rl3);
        println!("  merged numRanges={}", rl2.num_ranges());
        print!("{}", rl2.print_bounds());
    }

    // ---- case 7: Range construction from properties ------------------------
    println!("case=range_properties");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let mut p1 = RangeProperties::new();
        p1.space_name = "ram".to_string();
        p1.first = 0x100;
        p1.last = 0x1ff;
        p1.seen_last = true;
        println!("  p1 {}", try_range_props(&p1, &m));
        let mut p2 = RangeProperties::new();
        p2.space_name = "ram".to_string();
        p2.first = 0x100;
        println!("  p2 {}", try_range_props(&p2, &m));
        let mut p3 = RangeProperties::new();
        p3.space_name = "nosuch".to_string();
        p3.first = 0;
        p3.seen_last = true;
        println!("  p3 {}", try_range_props(&p3, &m));
        let mut p4 = RangeProperties::new();
        p4.space_name = "ram".to_string();
        p4.first = 2;
        p4.last = 1;
        p4.seen_last = true;
        println!("  p4 {}", try_range_props(&p4, &m));
        let mut p5 = RangeProperties::new();
        p5.space_name = "flash4".to_string();
        p5.first = 0x100000000;
        p5.last = 0x100000001;
        p5.seen_last = true;
        println!("  p5 {}", try_range_props(&p5, &m));
        let mut p6 = RangeProperties::new();
        p6.space_name = "flash4".to_string();
        p6.first = 0x10;
        println!("  p6 {}", try_range_props(&p6, &m));
    }
}
