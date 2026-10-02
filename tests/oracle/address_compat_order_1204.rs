// ADDRESS-COMPAT-ORDER-1204: Rudra comparand for the locked Ghidra 12.0.4
// ordering oracle of the ADDRESS-0001 phase-1 legacy-Address space bridge
// (address.hh/address.cc). Mirrors tests/oracle/address_compat_order_1204.cc
// case for case: the oracle's null-`base` `m_minimal` address is minted as
// the legacy spaceless `Address::new(0)` (tag `None`), every real
// `Address(space, off)` as `Address::with_space(&space, off)`, and the
// sorted-container walks through BTreeSet<Address> whose Ord is the phase-1
// chain (None first -> space index -> offset -> tag tiebreak). Every
// observation is printed in the shared line format and must match the C++
// output byte for byte.

use rudra::address::{Address, SeqNum};
use rudra::space::{space_flags, AddrSpace, SpaceRegistry, SpaceType};

fn hex_u64(v: u64) -> String {
    format!("0x{:x}", v)
}

// The legacy address carries no space, so the walk label crosses the bridge
// to the null-base SpaceAddress form — exactly the oracle's invalid label.
fn walk_label(a: &Address) -> String {
    let sa = a.to_space_address();
    match sa.get_space() {
        None => format!("invalid:{}", hex_u64(sa.get_offset())),
        Some(spc) => format!("{}:{}", spc.get_name(), hex_u64(sa.get_offset())),
    }
}

fn b(cond: bool) -> i32 {
    if cond {
        1
    } else {
        0
    }
}

fn proc_space(name: &str, big_end: bool, size: u32, ws: u32, ind: i32, fl: u32) -> AddrSpace {
    AddrSpace::new_space(SpaceType::Processor, name, big_end, size, ws, ind, fl, 0, 0)
}

// Build the canonical synthetic architecture (same layout as the C++ oracle
// fixture): constant=0, other=1, unique=2, ram=3, register=4, stack=5,
// join=6, iop=7, flash4=8 (4-byte wrap space).
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
}

fn main() {
    println!(
        "schema=1|fixture=ADDRESS-COMPAT-ORDER-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case 1: null base (the oracle model of the None tag) vs real ------
    println!("case=null_base_vs_real");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let constant = m.get_constant_space().unwrap();
        let nullbase = Address::new(0);
        let nullbase2 = Address::new(0);
        let ram0 = Address::with_space(&ram, 0);
        let ram1000 = Address::with_space(&ram, 0x1000);
        let const10 = Address::with_space(&constant, 0x10);
        println!(
            "  eq_null_null={} eq_null_ram0={} ne_null_ram0={}",
            b(nullbase == nullbase2),
            b(nullbase == ram0),
            b(nullbase != ram0)
        );
        println!(
            "  lt_null_ram0={} lt_ram0_null={} le_null_ram0={} lt_null_const10={} lt_const10_null={}",
            b(nullbase < ram0),
            b(ram0 < nullbase),
            b(nullbase <= ram0),
            b(nullbase < const10),
            b(const10 < nullbase)
        );
        println!(
            "  lt_null_ram1000={} eq_null_nulloffset={}",
            b(nullbase < ram1000),
            b(nullbase == Address::new(0))
        );
        println!(
            "  print_null={}",
            nullbase.to_space_address().print_raw()
        );
    }

    // ---- case 2: cross-space sorted walk with the null base first ----------
    println!("case=cross_space_walk");
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
        let mut ordered = std::collections::BTreeSet::new();
        ordered.insert(Address::with_space(&register_, 0x5000));
        ordered.insert(Address::with_space(&unique, 0x99));
        ordered.insert(Address::with_space(&ram, 0x1000));
        ordered.insert(Address::with_space(&constant, 0x7f));
        ordered.insert(Address::with_space(&other, 0x1));
        ordered.insert(Address::with_space(&stack, 0x20));
        ordered.insert(Address::with_space(&join, 0x30));
        ordered.insert(Address::with_space(&iop, 0x40));
        ordered.insert(Address::with_space(&ram, 0x2000));
        ordered.insert(Address::with_space(&register_, 0x3000));
        ordered.insert(Address::with_space(&unique, 0x11));
        ordered.insert(Address::with_space(&ram, 0x800));
        ordered.insert(Address::with_space(&iop, 0x50));
        ordered.insert(Address::new(0));
        println!("  size={}", ordered.len());
        for a in &ordered {
            println!("  walk {}", walk_label(a));
        }
        println!(
            "  lt(const7f,other1)={} lt(register3000,ram2000)={} lt(iop40,join30)={} lt(unique99,ram1)={} lt(null,all)={}",
            b(Address::with_space(&constant, 0x7f) < Address::with_space(&other, 0x1)),
            b(Address::with_space(&register_, 0x3000) < Address::with_space(&ram, 0x2000)),
            b(Address::with_space(&iop, 0x40) < Address::with_space(&join, 0x30)),
            b(Address::with_space(&unique, 0x99) < Address::with_space(&ram, 0x1)),
            b(Address::new(0) < Address::with_space(&constant, 0x0))
        );
    }

    // ---- case 3: same-space offset ordering ---------------------------------
    println!("case=same_space_offset_order");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        println!(
            "  lt(ram0,ram800)={} le(ram800,ram800)={} lt(ram2000,ram1000)={} eq(ram1000,ram1000)={}",
            b(Address::with_space(&ram, 0) < Address::with_space(&ram, 0x800)),
            b(Address::with_space(&ram, 0x800) <= Address::with_space(&ram, 0x800)),
            b(Address::with_space(&ram, 0x2000) < Address::with_space(&ram, 0x1000)),
            b(Address::with_space(&ram, 0x1000) == Address::with_space(&ram, 0x1000))
        );
        println!(
            "  lt(reg0,reg8)={} eq(reg8,ram8)={} lt(reg_maxm1,reg_max)={}",
            b(Address::with_space(&register_, 0) < Address::with_space(&register_, 8)),
            b(Address::with_space(&register_, 8) == Address::with_space(&ram, 8)),
            b(Address::with_space(&register_, 0xfffffffffffffffe)
                < Address::with_space(&register_, 0xffffffffffffffff))
        );
    }

    // ---- case 4: wrapOffset arithmetic through real spaces ------------------
    println!("case=wrap_arithmetic");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let flash4 = m.get_space_by_name("flash4").unwrap();
        println!(
            "  flash4 fffffffe+2={} ffffffff+1={} fffffffe+3={} 10-11={}",
            hex_u64(Address::with_space(&flash4, 0xfffffffe).offset(2).as_u64()),
            hex_u64(Address::with_space(&flash4, 0xffffffff).offset(1).as_u64()),
            hex_u64(Address::with_space(&flash4, 0xfffffffe).offset(3).as_u64()),
            hex_u64(Address::with_space(&flash4, 0x10).offset(-0x11).as_u64())
        );
        println!(
            "  ram maxff+1={} ram 100+ff={} ram 0-1={}",
            hex_u64(Address::with_space(&ram, 0xffffffffffffffff).offset(1).as_u64()),
            hex_u64(Address::with_space(&ram, 0x100).offset(0xff).as_u64()),
            hex_u64(Address::with_space(&ram, 0).offset(-1).as_u64())
        );
        let wrapped = Address::with_space(&flash4, 0xfffffffe).offset(2);
        println!(
            "  spacekept fffffffe+2={} spaceis={}",
            hex_u64(wrapped.as_u64()),
            b(wrapped.get_space().map(|s| s.identity_ptr()) == Some(flash4.identity_ptr()))
        );
    }

    // ---- case 5: overlap gates ----------------------------------------------
    println!("case=overlap_gates");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let flash4 = m.get_space_by_name("flash4").unwrap();
        let constant = m.get_constant_space().unwrap();
        let register_ = m.get_space_by_name("register").unwrap();
        println!(
            "  overlap wrap={} negskip={} far={}",
            Address::with_space(&flash4, 0xfffffffe)
                .overlap(4, Address::with_space(&flash4, 0x1), 8),
            Address::with_space(&flash4, 0x10)
                .overlap(-8, Address::with_space(&flash4, 0x5), 16),
            Address::with_space(&flash4, 0x0)
                .overlap(0, Address::with_space(&flash4, 0x8), 4)
        );
        println!(
            "  const={} crossspace={} plain={}",
            Address::with_space(&constant, 0x10)
                .overlap(0, Address::with_space(&constant, 0x8), 16),
            Address::with_space(&ram, 0x10)
                .overlap(0, Address::with_space(&register_, 0x8), 16),
            Address::with_space(&ram, 0x12)
                .overlap(0, Address::with_space(&ram, 0x10), 8)
        );
    }

    // ---- case 6: SeqNum ordering ladder --------------------------------------
    println!("case=seqnum_order");
    {
        let mut m = SpaceRegistry::new();
        build_spaces(&mut m);
        let ram = m.get_space_by_name("ram").unwrap();
        let constant = m.get_constant_space().unwrap();
        let a = SeqNum::new(Address::with_space(&ram, 0x1000), 5);
        let bb = SeqNum::new(Address::with_space(&ram, 0x1000), 6);
        let c = SeqNum::new(Address::with_space(&ram, 0x80), 9);
        let d = SeqNum::new(Address::with_space(&constant, 0x10), 0);
        let e = SeqNum::new(Address::with_space(&ram, 0x1000), 5);
        println!(
            "  lt(a,b)={} lt(b,a)={} lt(c,a)={} lt(d,a)={} eq(a,e)={}",
            b(a < bb),
            b(bb < a),
            b(c < a),
            b(d < a),
            b(a == e)
        );
        // address.cc:32 operator<<: pc.printRaw + ':' + decimal uniq.
        println!(
            "  print_a={}:{}",
            a.get_addr().to_space_address().print_raw(),
            a.get_time()
        );
    }
}
