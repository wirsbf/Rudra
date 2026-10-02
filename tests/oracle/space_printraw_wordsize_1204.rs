// Locked Ghidra 12.0.4 AddrSpace::printRaw oracle for
// SPACE-PRINTRAW-WORDSIZE-0001 (Rust side).
//
// Mirrors tests/oracle/space_printraw_wordsize_1204.cc record-for-record:
// the registry handle's `AddrSpace::print_raw` (space.cc:206-222 analogue)
// must reproduce the oracle byte for byte across wordsize 1/2/4 spaces,
// the addrsize>4 leading-zero shrink rule, the byteToAddress scaling, the
// "+cut" suffix, the setw minimum-width semantics, and the
// ConstantSpace/OtherSpace overrides. The addrsize_projection case locks
// `AddrSpace::get_addr_size` (registry) and `AddressSpace::addr_size` /
// `AddressSpace::word_size` (flat enum, SPACE-0001 bridge) against the
// Ghidra constructor truth: const/OTHER/iop = 8, unique = UniqueSpace::SIZE
// = 4, join = sizeof(uintm) = 4, x86-64-shaped ram/register/stack = 8,
// overlay copies its base.

use rudra::space::{space_flags, AddrSpace, AddressSpace, SpaceType};

fn print_raw_line(spc: &AddrSpace, off: u64) {
    println!("  {} off=0x{:x} -> {}", spc.get_name(), off, spc.print_raw(off));
}

fn main() {
    println!(
        "schema=1|fixture=SPACE-PRINTRAW-WORDSIZE-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case 1: canonical per-space address sizes -------------------------
    println!("case=addrsize_projection");
    {
        let constspc = AddrSpace::new_constant_space(false);
        let otherspc = AddrSpace::new_other_space();
        let uniqspc = AddrSpace::new_unique_space(2, 0, false);
        let ram = AddrSpace::new_space(
            SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            space_flags::HASPHYSICAL,
            0,
            0,
        );
        let reg = AddrSpace::new_space(
            SpaceType::Processor,
            "register",
            false,
            8,
            1,
            4,
            space_flags::HASPHYSICAL,
            0,
            0,
        );
        let stack = AddrSpace::new_spacebase_space("stack", 5, 8, &ram, 1, true, false);
        let joinspc = AddrSpace::new_join_space(6, false);
        let iopspc = AddrSpace::new_iop_space(7, false);
        let ovram = AddrSpace::new_overlay_space("ovram", 9, &ram);
        for spc in [
            &constspc, &otherspc, &uniqspc, &ram, &reg, &stack, &joinspc, &iopspc, &ovram,
        ] {
            println!(
                "  space {} addrsize={} wordsize={}",
                spc.get_name(),
                spc.get_addr_size(),
                spc.get_word_size()
            );
        }
        // Flat-enum projection must carry the same constructor truth.
        for (name, spc) in [
            ("ram", AddressSpace::Ram),
            ("register", AddressSpace::Register),
            ("unique", AddressSpace::Unique),
            ("const", AddressSpace::Const),
            ("stack", AddressSpace::Stack),
            ("join", AddressSpace::Join),
            ("iop", AddressSpace::Iop),
            ("overlay", AddressSpace::Overlay),
            ("other", AddressSpace::Other(1)),
        ] {
            println!(
                "  legacy {} addrsize={} wordsize={}",
                name,
                spc.addr_size(),
                spc.word_size()
            );
        }
    }

    // ---- case 2: wordsize 1 printing ---------------------------------------
    println!("case=printraw_wordsize1");
    {
        let ram8 = AddrSpace::new_space(SpaceType::Processor, "ram8", false, 8, 1, 3, 0, 0, 0);
        let ram4 = AddrSpace::new_space(SpaceType::Processor, "ram4", false, 4, 1, 4, 0, 0, 0);
        let ram2 = AddrSpace::new_space(SpaceType::Processor, "ram2", false, 2, 1, 5, 0, 0, 0);
        print_raw_line(&ram8, 0x0);
        print_raw_line(&ram8, 0x1234);
        print_raw_line(&ram8, 0x123456789ab);
        print_raw_line(&ram8, 0x123456789abcdef0);
        print_raw_line(&ram4, 0x0);
        print_raw_line(&ram4, 0x1234);
        print_raw_line(&ram4, 0xffffffff);
        print_raw_line(&ram2, 0x0);
        print_raw_line(&ram2, 0x123);
        print_raw_line(&ram2, 0x12345);
    }

    // ---- case 3: wordsize 2 printing ---------------------------------------
    println!("case=printraw_wordsize2");
    {
        let ws2x4 = AddrSpace::new_space(SpaceType::Processor, "ws2x4", false, 4, 2, 3, 0, 0, 0);
        let ws2x8 = AddrSpace::new_space(SpaceType::Processor, "ws2x8", false, 8, 2, 4, 0, 0, 0);
        let ws2x2 = AddrSpace::new_space(SpaceType::Processor, "ws2x2", false, 2, 2, 5, 0, 0, 0);
        print_raw_line(&ws2x4, 0x0);
        print_raw_line(&ws2x4, 0x100);
        print_raw_line(&ws2x4, 0x101);
        print_raw_line(&ws2x4, 0x102);
        print_raw_line(&ws2x4, 0x103);
        print_raw_line(&ws2x4, 0xfffffffe);
        print_raw_line(&ws2x4, 0xffffffff);
        print_raw_line(&ws2x8, 0x10);
        print_raw_line(&ws2x8, 0x11);
        print_raw_line(&ws2x8, 0x10000000000);
        print_raw_line(&ws2x8, 0xffffffffffffffff);
        print_raw_line(&ws2x2, 0x100);
        print_raw_line(&ws2x2, 0x1ff);
        print_raw_line(&ws2x2, 0x201);
    }

    // ---- case 4: wordsize 4 printing ---------------------------------------
    println!("case=printraw_wordsize4");
    {
        let ws4x8 = AddrSpace::new_space(SpaceType::Processor, "ws4x8", false, 8, 4, 3, 0, 0, 0);
        let ws4x4 = AddrSpace::new_space(SpaceType::Processor, "ws4x4", false, 4, 4, 4, 0, 0, 0);
        print_raw_line(&ws4x8, 0x10);
        print_raw_line(&ws4x8, 0x13);
        print_raw_line(&ws4x8, 0x10000000000);
        print_raw_line(&ws4x8, 0x10000000003);
        print_raw_line(&ws4x8, 0xffffffffffffffff);
        print_raw_line(&ws4x4, 0x1000);
        print_raw_line(&ws4x4, 0x1003);
        print_raw_line(&ws4x4, 0xffffffff);
    }

    // ---- case 5: ConstantSpace/OtherSpace overrides ------------------------
    println!("case=printraw_overrides");
    {
        let constspc = AddrSpace::new_constant_space(false);
        let otherspc = AddrSpace::new_other_space();
        print_raw_line(&constspc, 0x0);
        print_raw_line(&constspc, 0xabc);
        print_raw_line(&constspc, 0xdeadbeefcafe);
        print_raw_line(&otherspc, 0x0);
        print_raw_line(&otherspc, 0xabc);
    }
}
