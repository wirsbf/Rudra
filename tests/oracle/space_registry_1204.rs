// SPACE-REGISTRY-1204: Rugra comparand for the locked Ghidra 12.0.4
// architecture-owned AddrSpace registry oracle (AddrSpaceManager core).
// Mirrors tests/oracle/space_registry_1204.cc case for case: the same space
// lifecycle is driven through the translate bridge (AddrSpaceManager::
// insert_dyn_space / add_dyn_spacebase_pointer into the architecture-owned
// SpaceRegistry) and every observation is printed in the shared line format.

use rudra::space::{
    space_flags, AddrSpace, SpaceRegistry, SpaceType, SpaceVarnodeData,
};
use rudra::translate::AddrSpaceManager;

fn hex_u64(v: u64) -> String {
    format!("0x{:x}", v)
}

fn print_space_line(spc: &AddrSpace) {
    println!(
        "  space idx={} name={} type={} addrsize={} wordsize={} endian={} shortcut={} delay={} dead={} highest={} plb={} pub={} minptr={} ref={} be={} h={} dc={} rj={} fs={} ov={} ob={} tr={} hp={} oo={} np={}",
        spc.get_index(),
        spc.get_name(),
        spc.get_type() as u32,
        spc.get_addr_size(),
        spc.get_word_size(),
        if spc.is_big_endian() { "big" } else { "l" },
        spc.get_shortcut(),
        spc.get_delay(),
        spc.get_deadcode_delay(),
        hex_u64(spc.get_highest()),
        hex_u64(spc.get_pointer_lower_bound()),
        hex_u64(spc.get_pointer_upper_bound()),
        spc.get_minimum_ptr_size(),
        spc.refcount(),
        if spc.is_big_endian() { 1 } else { 0 },
        if spc.is_heritaged() { 1 } else { 0 },
        if spc.does_deadcode() { 1 } else { 0 },
        if spc.is_reverse_justified() { 1 } else { 0 },
        if spc.is_formal_stackspace() { 1 } else { 0 },
        if spc.is_overlay() { 1 } else { 0 },
        if spc.is_overlay_base() { 1 } else { 0 },
        if spc.is_truncated() { 1 } else { 0 },
        if spc.has_physical() { 1 } else { 0 },
        if spc.is_other_space() { 1 } else { 0 },
        if spc.has_near_pointers() { 1 } else { 0 },
    );
}

fn print_walk(reg: &SpaceRegistry) {
    let mut out = String::from("  walk");
    let mut cur = reg.get_next_space_in_order(None);
    while let Some(spc) = cur {
        out.push(' ');
        out.push_str(&spc.get_name());
        cur = reg.get_next_space_in_order(Some(spc));
    }
    println!("{}", out);
}

fn try_insert(m: &mut AddrSpaceManager, spc: AddrSpace) -> String {
    match m.insert_dyn_space(spc) {
        Ok(()) => "ok".to_string(),
        Err(msg) => format!("err {}", msg),
    }
}

fn try_add_spacebase_pointer(
    m: &mut AddrSpaceManager,
    basespace: &AddrSpace,
    ptr: &SpaceVarnodeData,
    trunc_size: i32,
    stack_growth: bool,
) -> String {
    match m.add_dyn_spacebase_pointer(basespace, ptr, trunc_size, stack_growth) {
        Ok(()) => "ok".to_string(),
        Err(msg) => format!("err {}", msg),
    }
}

fn try_set_default_code_space(m: &mut AddrSpaceManager, index: usize) -> String {
    match m.space_registry.set_default_code_space(index) {
        Ok(()) => "ok".to_string(),
        Err(msg) => format!("err {}", msg),
    }
}

fn try_get_spacebase(spc: &AddrSpace, i: i32) -> (String, Option<SpaceVarnodeData>) {
    match spc.get_spacebase(i) {
        Ok(data) => ("ok".to_string(), Some(data)),
        Err(msg) => (format!("err {}", msg), None),
    }
}

fn try_truncate_space(m: &mut AddrSpaceManager, name: &str, size: u32) -> String {
    match m.space_registry.truncate_space(name, size) {
        Ok(()) => "ok".to_string(),
        Err(msg) => format!("err {}", msg),
    }
}

fn proc_space(
    name: &str,
    big_end: bool,
    size: u32,
    ws: u32,
    ind: i32,
    fl: u32,
) -> AddrSpace {
    AddrSpace::new_space(SpaceType::Processor, name, big_end, size, ws, ind, fl, 0, 0)
}

// Build the canonical synthetic architecture: const=0, OTHER=1, unique=2,
// ram=3, register=4, stack=5, join=6, iop=7 (same layout as the C++ oracle).
fn build_canonical(m: &mut AddrSpaceManager) {
    try_insert(m, AddrSpace::new_constant_space(false));
    try_insert(m, AddrSpace::new_other_space());
    try_insert(m, AddrSpace::new_unique_space(2, 0, false));
    try_insert(
        m,
        proc_space("ram", false, 8, 1, 3, space_flags::HASPHYSICAL),
    );
    try_insert(
        m,
        proc_space("register", false, 8, 1, 4, space_flags::HASPHYSICAL),
    );
    let ram = m.space_registry.get_space_by_name("ram").unwrap();
    try_insert(
        m,
        AddrSpace::new_spacebase_space("stack", 5, 8, &ram, 1, true, false),
    );
    try_insert(m, AddrSpace::new_join_space(6, false));
    try_insert(m, AddrSpace::new_iop_space(7, false));
    try_set_default_code_space(m, 3);
}

fn main() {
    println!(
        "schema=1|fixture=SPACE-REGISTRY-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case 1: canonical insert order + index allocation ----------------
    println!("case=canonical_insert_order");
    {
        let mut m = AddrSpaceManager::new();
        build_canonical(&mut m);
        let reg = &m.space_registry;
        println!("  numSpaces={}", reg.num_spaces());
        for i in 0..reg.num_spaces() {
            print_space_line(&reg.get_space(i).unwrap());
        }
        println!("  defaultSize={}", reg.get_default_size());
        println!(
            "  const={} iop={} join={} stack={} uniq={} code={} data={}",
            reg.get_constant_space().unwrap().get_name(),
            reg.get_iop_space().unwrap().get_name(),
            reg.get_join_space().unwrap().get_name(),
            reg.get_stack_space().unwrap().get_name(),
            reg.get_unique_space().unwrap().get_name(),
            reg.get_default_code_space().unwrap().get_name(),
            reg.get_default_data_space().unwrap().get_name()
        );
        print_walk(reg);
    }

    // ---- case 2: rejection paths (name/id/type/index) ----------------------
    println!("case=rejection_paths");
    {
        let mut m = AddrSpaceManager::new();
        try_insert(&mut m, AddrSpace::new_constant_space(false));
        try_insert(&mut m, proc_space("ram", false, 8, 1, 3, space_flags::HASPHYSICAL));
        try_insert(
            &mut m,
            proc_space("register", false, 8, 1, 4, space_flags::HASPHYSICAL),
        );
        println!("  {}", try_insert(&mut m, proc_space("extra", false, 8, 1, 3, 0)));
        println!("  {}", try_insert(&mut m, proc_space("ram", false, 8, 1, 9, 0)));
        println!(
            "  {}",
            try_insert(
                &mut m,
                AddrSpace::new_space(SpaceType::Internal, "tmpx", false, 8, 1, 9, 0, 0, 0)
            )
        );
        println!(
            "  {}",
            try_insert(
                &mut m,
                AddrSpace::new_space(SpaceType::Constant, "const", false, 8, 1, 5, 0, 0, 0)
            )
        );
        let fake_other = AddrSpace::new_space(
            SpaceType::Processor, "OTHER", false, 8, 1, 5, 0, 0, 0,
        );
        fake_other.set_flags(space_flags::IS_OTHERSPACE);
        println!("  {}", try_insert(&mut m, fake_other));
        println!("  {}", try_insert(&mut m, AddrSpace::new_constant_space(false)));
        let reg = &m.space_registry;
        println!("  numSpaces={}", reg.num_spaces());
        println!(
            "  extraLookup={}",
            if reg.get_space_by_name("extra").is_some() {
                "found"
            } else {
                "null"
            }
        );
        println!(
            "  slot9={}",
            if reg.get_space(9).is_some() { "found" } else { "null" }
        );
        print_walk(reg);
    }

    // ---- case 3: dead-hole skipping and late re-fill -----------------------
    println!("case=hole_fill_iteration");
    {
        let mut m = AddrSpaceManager::new();
        try_insert(&mut m, AddrSpace::new_constant_space(false));
        try_insert(&mut m, proc_space("ram", false, 8, 1, 3, space_flags::HASPHYSICAL));
        println!("  numSpaces={}", m.space_registry.num_spaces());
        print_walk(&m.space_registry);
        println!(
            "  slot1={}",
            if m.space_registry.get_space(1).is_some() {
                "found"
            } else {
                "null"
            }
        );
        try_insert(&mut m, proc_space("extra", false, 8, 1, 2, 0));
        println!("  numSpaces={}", m.space_registry.num_spaces());
        print_walk(&m.space_registry);
        try_insert(&mut m, proc_space("far", false, 8, 1, 9, 0));
        println!("  numSpaces={}", m.space_registry.num_spaces());
        print_walk(&m.space_registry);
        println!(
            "  slot8={}",
            if m.space_registry.get_space(8).is_some() {
                "found"
            } else {
                "null"
            }
        );
    }

    // ---- case 4: shortcut assignment + collisions --------------------------
    println!("case=shortcut_collision");
    {
        let mut m = AddrSpaceManager::new();
        try_insert(&mut m, AddrSpace::new_constant_space(false));
        try_insert(&mut m, AddrSpace::new_other_space());
        try_insert(
            &mut m,
            proc_space("register", false, 8, 1, 4, space_flags::HASPHYSICAL),
        );
        try_insert(&mut m, proc_space("ram", false, 8, 1, 3, space_flags::HASPHYSICAL));
        try_insert(&mut m, AddrSpace::new_unique_space(2, 0, false));
        let ram = m.space_registry.get_space_by_name("ram").unwrap();
        try_insert(
            &mut m,
            AddrSpace::new_spacebase_space("stack", 5, 8, &ram, 1, true, false),
        );
        try_insert(&mut m, AddrSpace::new_join_space(6, false));
        try_insert(&mut m, AddrSpace::new_iop_space(7, false));
        try_insert(&mut m, AddrSpace::new_fspec_space(8, false));
        let sram = proc_space("sram", false, 8, 1, 9, 0);
        try_insert(&mut m, sram.clone());
        let trampoline = proc_space("trampoline", false, 8, 1, 10, 0);
        try_insert(&mut m, trampoline.clone());
        let zulu = proc_space("Zulu", false, 8, 1, 11, 0);
        try_insert(&mut m, zulu.clone());
        println!(
            "  sram={} trampoline={} zulu={}",
            sram.get_shortcut(),
            trampoline.get_shortcut(),
            zulu.get_shortcut()
        );
        let keys = ['#', '%', 's', 'u', 'j', 'i', 'f', 'r', 'o', 't', 'v', 'z'];
        for key in keys {
            let name = m
                .space_registry
                .get_space_by_shortcut(key)
                .map(|s| s.get_name())
                .unwrap_or_else(|| "null".to_string());
            println!("  lookup {} -> {}", key, name);
        }
    }

    // ---- case 5: shortcut 'z' reuse after 26 collisions --------------------
    println!("case=shortcut_z_reuse");
    {
        let mut m = AddrSpaceManager::new();
        try_insert(&mut m, AddrSpace::new_constant_space(false));
        for i in 0..26u8 {
            let name: String =
                std::iter::repeat((b'a' + i) as char).take(2).collect();
            try_insert(&mut m, proc_space(&name, false, 8, 1, i as i32 + 1, 0));
        }
        let apple = proc_space("apple", false, 8, 1, 27, 0);
        try_insert(&mut m, apple.clone());
        println!("  appleShortcut={}", apple.get_shortcut());
        println!(
            "  zOwner={}",
            m.space_registry
                .get_space_by_shortcut('z')
                .unwrap()
                .get_name()
        );
    }

    // ---- case 6: wordsize/addrsize/endian/flag projection ------------------
    println!("case=projection_wordsize_endian_flags");
    {
        let mut m = AddrSpaceManager::new();
        let ws2 = proc_space("ws2", false, 4, 2, 3, 0);
        try_insert(&mut m, ws2.clone());
        let ws3 = proc_space("ws3", false, 2, 3, 4, 0);
        try_insert(&mut m, ws3.clone());
        let big = proc_space("big", true, 8, 1, 5, 0);
        try_insert(&mut m, big.clone());
        print_space_line(&ws2);
        print_space_line(&ws3);
        print_space_line(&big);
        println!(
            "  a2b(5,2)={} b2a(10,2)={} a2bi(7,2)={} b2ai(14,2)={}",
            AddrSpace::address_to_byte(5, 2),
            AddrSpace::byte_to_address(10, 2),
            AddrSpace::address_to_byte_int(7, 2),
            AddrSpace::byte_to_address_int(14, 2)
        );
        println!(
            "  wrap {} {} {} {}",
            hex_u64(ws2.wrap_offset(0x1ffffffff)),
            hex_u64(ws2.wrap_offset(0x200000000)),
            hex_u64(ws2.wrap_offset(0x200000001)),
            hex_u64(ws2.wrap_offset(0x300000002))
        );
        m.space_registry.mark_near_pointers(&ws2, 2);
        m.space_registry.set_reverse_justified(&ws2);
        m.space_registry.set_deadcode_delay(&ws2, 7);
        println!(
            "  afterMarks np={} minptr={} rj={} dead={}",
            if ws2.has_near_pointers() { 1 } else { 0 },
            ws2.get_minimum_ptr_size(),
            if ws2.is_reverse_justified() { 1 } else { 0 },
            ws2.get_deadcode_delay()
        );
        m.space_registry.set_infer_ptr_bounds(&ws2, 0x10, 0x20);
        println!(
            "  inferBounds plb={} pub={}",
            hex_u64(ws2.get_pointer_lower_bound()),
            hex_u64(ws2.get_pointer_upper_bound())
        );
        big.truncate_space(4);
        println!(
            "  truncated tr={} minptr={} addrsize={} highest={}",
            if big.is_truncated() { 1 } else { 0 },
            big.get_minimum_ptr_size(),
            big.get_addr_size(),
            hex_u64(big.get_highest())
        );
        let ram = proc_space("ram", false, 8, 1, 6, space_flags::HASPHYSICAL);
        try_insert(&mut m, ram.clone());
        let ov = AddrSpace::new_overlay_space("ov", 7, &ram);
        try_insert(&mut m, ov.clone());
        println!(
            "  overlay ram_ob={} ov_ov={} contain={} ov_hp={}",
            if ram.is_overlay_base() { 1 } else { 0 },
            if ov.is_overlay() { 1 } else { 0 },
            ov.get_contain().unwrap().get_name(),
            if ov.has_physical() { 1 } else { 0 }
        );
        println!("  {}", try_truncate_space(&mut m, "nosuch", 4));
        println!("  {}", try_truncate_space(&mut m, "ov", 2));
        println!(
            "  ovAfter tr={} addrsize={} highest={}",
            if ov.is_truncated() { 1 } else { 0 },
            ov.get_addr_size(),
            hex_u64(ov.get_highest())
        );
    }

    // ---- case 7: spacebase pointer bridge ----------------------------------
    println!("case=spacebase_pointer_bridge");
    {
        let mut m = AddrSpaceManager::new();
        try_insert(&mut m, AddrSpace::new_constant_space(false));
        let ram = proc_space("ram", false, 8, 1, 3, space_flags::HASPHYSICAL);
        try_insert(&mut m, ram.clone());
        let reg = proc_space("register", false, 8, 1, 4, space_flags::HASPHYSICAL);
        try_insert(&mut m, reg.clone());
        let stack = AddrSpace::new_spacebase_space("stack", 5, 8, &ram, 1, true, false);
        try_insert(&mut m, stack.clone());
        println!("  numBaseBefore={}", stack.num_spacebase());
        let ptr = SpaceVarnodeData {
            space: reg.clone(),
            offset: 0,
            size: 8,
        };
        println!("  {}", try_add_spacebase_pointer(&mut m, &stack, &ptr, 8, true));
        println!("  numBaseAfter={}", stack.num_spacebase());
        let (status, base) = try_get_spacebase(&stack, 0);
        let base = base.unwrap();
        println!(
            "  get0 {} space={} off={} size={}",
            status,
            base.space.get_name(),
            base.offset,
            base.size
        );
        let full = stack.get_spacebase_full(0).unwrap();
        println!(
            "  full0 space={} off={} size={}",
            full.space.get_name(),
            full.offset,
            full.size
        );
        println!(
            "  growsNeg={} contain={}",
            if stack.stack_grows_negative() { 1 } else { 0 },
            stack.get_contain().unwrap().get_name()
        );
        println!(
            "  readdSame {}",
            try_add_spacebase_pointer(&mut m, &stack, &ptr, 8, true)
        );
        let other = SpaceVarnodeData {
            space: reg.clone(),
            offset: 8,
            size: 8,
        };
        println!("  {}", try_add_spacebase_pointer(&mut m, &stack, &other, 8, true));
        let (status, _) = try_get_spacebase(&stack, 1);
        println!("  get1 {}", status);
        let heap = AddrSpace::new_spacebase_space("heapbase", 6, 8, &ram, 0, false, false);
        try_insert(&mut m, heap.clone());
        println!(
            "  heapNum={} growsNeg={} formal={}",
            heap.num_spacebase(),
            if heap.stack_grows_negative() { 1 } else { 0 },
            if heap.is_formal_stackspace() { 1 } else { 0 }
        );
        let (status, _) = try_get_spacebase(&heap, 0);
        println!("  heapGet0 {}", status);
        // Big-endian register truncation shifts the offset up by the lost bytes.
        let bereg = proc_space("beregi", true, 8, 1, 7, 0);
        let bestack = AddrSpace::new_spacebase_space("bestack", 8, 8, &ram, 0, false, false);
        let beptr = SpaceVarnodeData {
            space: bereg,
            offset: 0x100,
            size: 8,
        };
        println!(
            "  beTrunc {}",
            try_add_spacebase_pointer(&mut m, &bestack, &beptr, 4, false)
        );
        let bebase = bestack.get_spacebase(0).unwrap();
        println!(
            "  beBase off={} size={} growsNeg={}",
            hex_u64(bebase.offset),
            bebase.size,
            if bestack.stack_grows_negative() { 1 } else { 0 }
        );
        let befull = bestack.get_spacebase_full(0).unwrap();
        println!("  beFull off={} size={}", hex_u64(befull.offset), befull.size);
        // Little-endian truncation keeps the low offset.
        let lestack = AddrSpace::new_spacebase_space("lestack", 9, 8, &ram, 0, false, false);
        let leptr = SpaceVarnodeData {
            space: reg,
            offset: 0x100,
            size: 8,
        };
        try_add_spacebase_pointer(&mut m, &lestack, &leptr, 4, true);
        let lebase = lestack.get_spacebase(0).unwrap();
        println!("  leBase off={} size={}", hex_u64(lebase.offset), lebase.size);
    }

    // ---- case 8: copySpaces shared-handle refcounting ----------------------
    println!("case=copy_spaces_refcount");
    {
        let mut ma = AddrSpaceManager::new();
        build_canonical(&mut ma);
        let mut mb = AddrSpaceManager::new();
        let status = match mb.space_registry.copy_spaces(&ma.space_registry) {
            Ok(()) => "ok".to_string(),
            Err(msg) => format!("err {}", msg),
        };
        println!("  {}", status);
        println!("  numSpaces={}", mb.space_registry.num_spaces());
        let ram_a = ma.space_registry.get_space_by_name("ram").unwrap();
        let ram_b = mb.space_registry.get_space_by_name("ram").unwrap();
        println!("  sameHandle={}", if ram_a == ram_b { 1 } else { 0 });
        println!("  refA={} refB={}", ram_a.refcount(), ram_b.refcount());
        println!(
            "  defaultSize={} code={} data={}",
            mb.space_registry.get_default_size(),
            mb.space_registry.get_default_code_space().unwrap().get_name(),
            mb.space_registry.get_default_data_space().unwrap().get_name()
        );
        println!(
            "  slots iop={} join={} stack={} uniq={} const={}",
            mb.space_registry.get_iop_space().unwrap().get_name(),
            mb.space_registry.get_join_space().unwrap().get_name(),
            mb.space_registry.get_stack_space().unwrap().get_name(),
            mb.space_registry.get_unique_space().unwrap().get_name(),
            mb.space_registry.get_constant_space().unwrap().get_name()
        );
        print_walk(&mb.space_registry);
        println!("  {}", try_insert(&mut mb, proc_space("ram", false, 8, 1, 9, 0)));
    }
}
