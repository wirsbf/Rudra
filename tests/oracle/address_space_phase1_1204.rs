// ADDRESS-SPACE-PHASE1-1204: Rudra comparand for the locked Ghidra 12.0.4
// ADDRESS-0001 phase-1 legacy-Address space bridge oracle
// (address.hh/address.cc). Mirrors tests/oracle/address_space_phase1_1204.cc
// case for case: the None fallback (Rudra's legacy spaceless `Address::new`,
// modelled by the C++ null base with an explicit offset) keeps offset-only
// ordering/equality; the None-to-tagged meeting rules follow Ghidra's
// null-base rules; tagged addresses order by space index then offset, carry
// intern-table tag identity (pointer identity), wrap through the real space
// and gate overlap by space/constant/wrap. Every observation is printed in
// the shared line format and must match the C++ output byte for byte.

use rudra::address::Address;
use rudra::space::{space_flags, AddrSpace, SpaceRegistry, SpaceType};

fn hex_u64(v: u64) -> String {
    format!("0x{:x}", v)
}

fn walk_label(a: &Address) -> String {
    if a.is_invalid() {
        return format!("invalid:{}", hex_u64(a.as_u64()));
    }
    format!("{}:{}", a.get_space().unwrap().get_name(), hex_u64(a.as_u64()))
}

fn proc_space(name: &str, big_end: bool, size: u32, ws: u32, ind: i32, fl: u32) -> AddrSpace {
    AddrSpace::new_space(SpaceType::Processor, name, big_end, size, ws, ind, fl, 0, 0)
}

// Build the canonical synthetic architecture subset (same indices as the C++
// oracle fixture): constant=0, OTHER=1, unique=2, ram=3, register=4, flash4=8.
fn build_spaces(m: &mut SpaceRegistry) {
    m.insert_space(AddrSpace::new_constant_space(false)).unwrap();
    m.insert_space(AddrSpace::new_other_space()).unwrap();
    m.insert_space(AddrSpace::new_unique_space(2, 0, false)).unwrap();
    m.insert_space(proc_space("ram", false, 8, 1, 3, space_flags::HASPHYSICAL))
        .unwrap();
    m.insert_space(proc_space("register", false, 8, 1, 4, space_flags::HASPHYSICAL))
        .unwrap();
    m.insert_space(proc_space("flash4", false, 4, 1, 8, 0)).unwrap();
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
        "schema=1|fixture=ADDRESS-SPACE-PHASE1-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case 1: the None fallback = null-base to null-base ---------------
    println!("case=none_compat_fallback");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let n1000 = Address::new(0x1000);
        let n800 = Address::new(0x800);
        let n800b = Address::new(0x800);
        let n0 = Address::new(0);
        println!(
            "  eq_n800_n800b={} eq_n800_n1000={} ne_n800_n1000={}",
            b(n800 == n800b),
            b(n800 == n1000),
            b(n800 != n1000)
        );
        println!(
            "  lt_n800_n1000={} lt_n1000_n800={} le_n800_n800b={}",
            b(n800 < n1000),
            b(n1000 < n800),
            b(n800 <= n800b)
        );
        println!(
            "  isInvalid_n1000={} isInvalid_minimal={} eq_minimal_n0={}",
            b(n1000.is_invalid()),
            b(Address::new(0).is_invalid()),
            b(Address::new(0) == n0)
        );
        let mut ordered = std::collections::BTreeSet::new();
        ordered.insert(n1000);
        ordered.insert(n800);
        ordered.insert(n0);
        ordered.insert(Address::new(0xffffffffffffffff));
        println!("  size={}", ordered.len());
        for a in &ordered {
            println!("  walk {}", walk_label(a));
        }
        // The meeting rules where the two models touch (address.hh:356/377/383).
        let ram1000 = Address::with_space(&ram, 0x1000);
        let ram800 = Address::with_space(&ram, 0x800);
        let ram0 = Address::with_space(&ram, 0);
        println!(
            "  eq_n1000_ram1000={} lt_n1000_ram800={} lt_ram800_n1000={} le_n1000_ram0={} isInvalid_ram1000={}",
            b(n1000 == ram1000),
            b(n1000 < ram800),
            b(ram800 < n1000),
            b(n1000 <= ram0),
            b(ram1000.is_invalid())
        );
    }

    // ---- case 2: cross-space ordering with the null base mixed in ---------
    println!("case=space_ordering");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let constant = m.get_constant_space().unwrap();
        let other = m.get_space_by_name("OTHER").unwrap();
        let unique = m.get_unique_space().unwrap();
        let ram = m.get_space_by_name("ram").unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        let mut ordered: std::collections::BTreeSet<Address> = std::collections::BTreeSet::new();
        ordered.insert(Address::with_space(&register_, 0x5000));
        ordered.insert(Address::with_space(&unique, 0x99));
        ordered.insert(Address::with_space(&ram, 0x1000));
        ordered.insert(Address::with_space(&constant, 0x7f));
        ordered.insert(Address::with_space(&other, 0x1));
        ordered.insert(Address::with_space(&ram, 0x2000));
        ordered.insert(Address::with_space(&register_, 0x3000));
        ordered.insert(Address::with_space(&unique, 0x11));
        ordered.insert(Address::with_space(&ram, 0x800));
        ordered.insert(Address::new(0x1000));
        println!("  size={}", ordered.len());
        for a in &ordered {
            println!("  walk {}", walk_label(a));
        }
        println!(
            "  lt(const7f,other1)={} lt(register3000,ram2000)={} lt(ram800,ram1000)={} lt(unique99,ram1)={}",
            b(Address::with_space(&constant, 0x7f) < Address::with_space(&other, 0x1)),
            b(Address::with_space(&register_, 0x3000) < Address::with_space(&ram, 0x2000)),
            b(Address::with_space(&ram, 0x800) < Address::with_space(&ram, 0x1000)),
            b(Address::with_space(&unique, 0x99) < Address::with_space(&ram, 0x1))
        );
        println!(
            "  eq_ram1000_again={} eq_ram1000_reg1000={}",
            b(Address::with_space(&ram, 0x1000) == Address::with_space(&ram, 0x1000)),
            b(Address::with_space(&ram, 0x1000) == Address::with_space(&register_, 0x1000))
        );
    }

    // ---- case 3: tag identity = intern-table pointer identity -------------
    println!("case=tag_identity");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        let a1 = Address::with_space(&ram, 0x1000);
        let a2 = Address::with_space(&ram, 0x1000);
        let a3 = Address::with_space(&register_, 0x1000);
        println!(
            "  eq_same_space_twice={} ne_distinct_space={}",
            b(a1 == a2),
            b(a1 != a3)
        );
        println!(
            "  resolve_a1={} resolve_a3={}",
            a1.get_space().unwrap().get_name(),
            a3.get_space().unwrap().get_name()
        );
        let mut dedup = std::collections::BTreeSet::new();
        dedup.insert(a1);
        dedup.insert(Address::with_space(&ram, 0x1000));
        println!("  set_dedup_size={}", dedup.len());
        // Display for a tagged address is the space's printRaw (the C++
        // Address::printRaw); both 8-byte spaces print the same padded form
        // for the same offset while staying unequal.
        println!("  print_a1={} print_a3={}", a1, a3);
        // A re-fetched handle from the registry is the same allocation: the
        // intern table must return the same tag for the cloned handle.
        let ram_again = m.get_space_by_name("ram").unwrap();
        println!(
            "  eq_handle_clone={}",
            b(a1 == Address::with_space(&ram_again, 0x1000))
        );
    }

    // ---- case 4: wrap arithmetic and overlap gates through real spaces ---
    println!("case=wrap_overlap_tagged");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let flash4 = m.get_space_by_name("flash4").unwrap();
        let constant = m.get_constant_space().unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        println!(
            "  flash4 fffffffe+2={} ffffffff+1={} fffffffe+3={} 10-11={}",
            hex_u64(Address::with_space(&flash4, 0xfffffffe).offset(2).as_u64()),
            hex_u64(Address::with_space(&flash4, 0xffffffff).offset(1).as_u64()),
            hex_u64(Address::with_space(&flash4, 0xfffffffe).offset(3).as_u64()),
            hex_u64(Address::with_space(&flash4, 0x10).offset(-0x11).as_u64())
        );
        println!(
            "  ram maxff+1={}",
            hex_u64(Address::with_space(&ram, 0xffffffffffffffff).offset(1).as_u64())
        );
        println!(
            "  overlap wrap={} negskip={} const={} crossspace={}",
            Address::with_space(&flash4, 0xfffffffe)
                .overlap(4, Address::with_space(&flash4, 0x1), 8),
            Address::with_space(&flash4, 0x10)
                .overlap(-8, Address::with_space(&flash4, 0x5), 16),
            Address::with_space(&constant, 0x10)
                .overlap(0, Address::with_space(&constant, 0x8), 16),
            Address::with_space(&ram, 0x10)
                .overlap(0, Address::with_space(&register_, 0x8), 16)
        );
    }
}
