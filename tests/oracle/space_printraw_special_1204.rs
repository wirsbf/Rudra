// Locked Ghidra 12.0.4 JoinSpace::printRaw oracle for
// SPACE-PRINTRAW-SPECIAL-0001 (Rust side).
//
// Mirrors tests/oracle/space_printraw_special_1204.cc record-for-record:
// the registry join tables (AddrSpaceManager::findAddJoin/findJoin,
// translate.cc:671-715/746-762) plus the join-space printRaw dispatch
// (space.cc:590-609) must reproduce the oracle byte for byte: the
// `{piece1,piece2,...}` pieces form printed through each piece space's own
// printRaw, the 1-piece float-extension `{piece:logicalsize}` form (the
// loop szsum discarded in favor of the unified size), the wordsize-2 piece
// recursion (byteToAddress scaling + "+cut"), findAddJoin dedup, the
// 16-byte-rounded allocation sequence, and the
// "Unlinked join address" panic on an offset with no record.
//
// The IopSpace::printRaw form is not exercised (SPACE-IOP-PRINTRAW-0001
// residual: Rugra's legacy SeqNum.addr and BlockBasic::start_addr carry no
// space handle, so the pc/block-start printRaw cannot be derived; blocked
// by ADDRESS-0001).

use rudra::space::{space_flags, AddrSpace, SpaceRegistry, SpaceType};

fn print_join_raw(join: &AddrSpace, off: u64) {
    println!("  join off=0x{:x} -> {}", off, join.print_raw(off));
}

// RUGRA-GLUE: panic payload extraction (panic!("literal") payloads are
// &str; panic!("{}", x) payloads are String).
fn panic_message(e: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        unreachable!("panic payload was not a string")
    }
}

fn main() {
    println!(
        "schema=1|fixture=SPACE-PRINTRAW-SPECIAL-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // Fixture-shaped registry: const=0, unique=2, ram=3, register=4, ws2=5
    // (addrsize 4, wordsize 2), join=6, iop=7 — the same shape as the C++
    // comparand.
    let mut mgr = SpaceRegistry::new();
    mgr.insert_space(AddrSpace::new_constant_space(false)).unwrap();
    mgr.insert_space(AddrSpace::new_unique_space(2, 0, false)).unwrap();
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
    mgr.insert_space(ram.clone()).unwrap();
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
    mgr.insert_space(reg.clone()).unwrap();
    let ws2 = AddrSpace::new_space(SpaceType::Processor, "ws2", false, 4, 2, 5, 0, 0, 0);
    mgr.insert_space(ws2.clone()).unwrap();
    let join = AddrSpace::new_join_space(6, false);
    mgr.insert_space(join.clone()).unwrap();
    mgr.insert_space(AddrSpace::new_iop_space(7, false)).unwrap();

    // ---- case 1: JoinSpace::printRaw pieces forms --------------------------
    println!("case=join_printraw");
    {
        use rudra::space::SpaceVarnodeData as Vd;
        // A: 2-piece register pair (MS to LS).
        let pieces_a = [
            Vd { space: reg.clone(), offset: 0x18, size: 4 },
            Vd { space: reg.clone(), offset: 0x10, size: 4 },
        ];
        let off_a = mgr.find_add_join(&pieces_a, 0);
        print_join_raw(&join, off_a);
        // Dedup: identical pieces return the same record and offset.
        let off_a2 = mgr.find_add_join(&pieces_a, 0);
        let same_record = off_a == off_a2;
        println!("  dedup same_record={} off=0x{:x}", same_record as u8, off_a2);

        // B: 3-piece ram + register + register.
        let pieces_b = [
            Vd { space: ram.clone(), offset: 0x1000, size: 4 },
            Vd { space: reg.clone(), offset: 0x20, size: 2 },
            Vd { space: reg.clone(), offset: 0x22, size: 2 },
        ];
        let off_b = mgr.find_add_join(&pieces_b, 0);
        print_join_raw(&join, off_b);

        // C: 1-piece float extension (real size 8, logical size 4).
        let pieces_c = [Vd { space: reg.clone(), offset: 0x100, size: 8 }];
        let off_c = mgr.find_add_join(&pieces_c, 4);
        print_join_raw(&join, off_c);

        // D: piece recursion through the wordsize-2 space (0x101 -> 0x80+1).
        let pieces_d = [
            Vd { space: ws2.clone(), offset: 0x101, size: 2 },
            Vd { space: reg.clone(), offset: 0x30, size: 2 },
        ];
        let off_d = mgr.find_add_join(&pieces_d, 0);
        print_join_raw(&join, off_d);
    }

    // ---- case 2: join-space allocation sequence -----------------------------
    println!("case=join_allocation");
    {
        // The allocation counter is private on both sides (Ghidra: field;
        // Rugra: inside the shared tables), so the sequence is locked
        // through the observable offsets: records A-D printed 0x0, 0x10,
        // 0x20, 0x30 in case 1; a fresh 5th record allocates 0x40 (each
        // allocation rounds the counter up to a multiple of 16,
        // translate.cc:706-710).
        use rudra::space::SpaceVarnodeData as Vd;
        let pieces_e = [
            Vd { space: ram.clone(), offset: 0x2000, size: 1 },
            Vd { space: reg.clone(), offset: 0x40, size: 1 },
        ];
        let off_e = mgr.find_add_join(&pieces_e, 0);
        println!("  next_alloc off=0x{:x}", off_e);
    }

    // ---- case 3: unlinked join address throws -------------------------------
    println!("case=join_printraw_unlinked");
    {
        // Suppress the default panic hook's stderr message: the runner
        // requires byte-identical, empty stderr on both sides (the C++ side
        // catches LowlevelError before it reaches stderr).
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            print_join_raw(&join, 0xdeadb0)
        }));
        std::panic::set_hook(default_hook);
        match result {
            Ok(()) => println!("  printRaw(0xdeadb0) returned without throwing"),
            Err(e) => println!("  printRaw(0xdeadb0) threw: {}", panic_message(e)),
        }
    }
}
