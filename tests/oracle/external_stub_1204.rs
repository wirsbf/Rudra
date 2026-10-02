//! EXTERNAL-STUB-1204 Rust comparand: construction-period space
//! registration through `SpaceRegistry::decode_spaces`/`decode_space`
//! (the ports of translate.cc:281/254), the EXTERNAL-named space
//! registration, and the decode-path error surfaces. Output must match the
//! locked Ghidra 12.0.4 fixture byte for byte
//! (`tests/oracle/external_stub_1204.cc`).

use std::sync::{Arc, RwLock};

use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::space::{AddrSpace, SpaceType, SpaceRegistry};

fn hex_u64(v: u64) -> String {
    format!("{:#x}", v)
}

fn print_space_line(spc: &AddrSpace) {
    println!(
        "  space idx={} name={} type={} addrsize={} wordsize={} endian={} shortcut={} delay={} dead={} highest={} plb={} pub={} ref={} h={} dc={} fs={} ov={} ob={} hp={} oo={}",
        spc.get_index(),
        spc.get_name(),
        spc.get_type() as i32,
        spc.get_addr_size(),
        spc.get_word_size(),
        if spc.is_big_endian() { "big" } else { "l" },
        spc.get_shortcut(),
        spc.get_delay(),
        spc.get_deadcode_delay(),
        hex_u64(spc.get_highest()),
        hex_u64(spc.get_pointer_lower_bound()),
        hex_u64(spc.get_pointer_upper_bound()),
        spc.refcount(),
        i32::from(spc.is_heritaged()),
        i32::from(spc.does_deadcode()),
        i32::from(spc.is_formal_stackspace()),
        i32::from(spc.is_overlay()),
        i32::from(spc.is_overlay_base()),
        i32::from(spc.has_physical()),
        i32::from(spc.is_other_space()),
    );
}

fn print_walk(registry: &SpaceRegistry) {
    print!("  walk");
    let mut cursor = registry.get_next_space_in_order(None);
    while let Some(spc) = cursor {
        print!(" {}", spc.get_name());
        cursor = registry.get_next_space_in_order(Some(spc));
    }
    println!();
}

fn make_space_element(
    parent: &mut Element,
    tag: &str,
    attributes: &[(&str, &str)],
) -> Arc<RwLock<Element>> {
    let mut child = Element::new();
    child.set_name(tag);
    for (name, value) in attributes {
        child.add_attribute(name, value);
    }
    let child = Arc::new(RwLock::new(child));
    parent.add_child(Arc::clone(&child));
    child
}

fn make_spaces_document(defaultspace: &str) -> Element {
    let mut spaces = Element::new();
    spaces.set_name("spaces");
    spaces.add_attribute("defaultspace", defaultspace);
    spaces
}

fn canonical_spaces() -> Element {
    let mut spaces = make_spaces_document("ram");
    make_space_element(
        &mut spaces,
        "space_unique",
        &[("name", "unique"), ("index", "2"), ("size", "4"), ("delay", "0")],
    );
    make_space_element(
        &mut spaces,
        "space",
        &[
            ("name", "ram"),
            ("index", "3"),
            ("size", "8"),
            ("delay", "0"),
            ("physical", "true"),
        ],
    );
    make_space_element(
        &mut spaces,
        "space",
        &[
            ("name", "register"),
            ("index", "4"),
            ("size", "8"),
            ("delay", "0"),
            ("physical", "true"),
        ],
    );
    spaces
}

fn decode_spaces(registry: &mut SpaceRegistry, doc: Element) -> String {
    let root = Arc::new(RwLock::new(doc));
    let id_registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut decoder = TreeDecoder::new(root, id_registry);
    match registry.decode_spaces(&mut decoder) {
        Ok(()) => "ok".to_string(),
        Err(message) => format!("err {}", message),
    }
}

fn main() {
    println!(
        "schema=1|fixture=EXTERNAL-STUB-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case 1: decodeSpaces canonical registration + DEFAULT ----------
    println!("case=decode_spaces_default_registration");
    {
        let mut registry = SpaceRegistry::new();
        let doc = canonical_spaces();
        println!("  {}", decode_spaces(&mut registry, doc));
        println!("  numSpaces={}", registry.num_spaces());
        for index in 0..registry.num_spaces() {
            if let Some(spc) = registry.get_space(index) {
                print_space_line(&spc);
            }
        }
        println!(
            "  defaultSize={} code={} data={}",
            registry.get_default_size(),
            registry
                .get_default_code_space()
                .map(|s| s.get_name())
                .unwrap_or_default(),
            registry
                .get_default_data_space()
                .map(|s| s.get_name())
                .unwrap_or_default(),
        );
        print_walk(&registry);
    }

    // ---- case 2: <space_overlay> decode marks the base -------------------
    println!("case=decode_space_overlay_marks_base");
    {
        let mut registry = SpaceRegistry::new();
        let mut doc = canonical_spaces();
        make_space_element(
            &mut doc,
            "space_overlay",
            &[("name", "ov"), ("index", "5"), ("base", "ram")],
        );
        println!("  {}", decode_spaces(&mut registry, doc));
        let ov = registry.get_space_by_name("ov").expect("ov registered");
        let ram = registry.get_space_by_name("ram").expect("ram registered");
        println!(
            "  ram_ob={} ov_ov={} contain={}",
            i32::from(ram.is_overlay_base()),
            i32::from(ov.is_overlay()),
            ov.get_contain().map(|s| s.get_name()).unwrap_or_default(),
        );
        print_space_line(&ov);
    }

    // ---- case 3: <space_base> decode resolves contain --------------------
    println!("case=decode_space_base_stack_contain");
    {
        let mut registry = SpaceRegistry::new();
        let mut doc = canonical_spaces();
        make_space_element(
            &mut doc,
            "space_base",
            &[
                ("name", "stack"),
                ("index", "5"),
                ("size", "8"),
                ("delay", "1"),
                ("contain", "ram"),
            ],
        );
        println!("  {}", decode_spaces(&mut registry, doc));
        let stack = registry.get_space_by_name("stack").expect("stack registered");
        println!(
            "  stackSlot={} type={} contain={} numBase={} growsNeg={} formal={}",
            registry
                .get_stack_space()
                .map(|s| s.get_name())
                .unwrap_or_default(),
            stack.get_type() as i32,
            stack
                .get_contain()
                .map(|s| s.get_name())
                .unwrap_or_default(),
            stack.num_spacebase(),
            i32::from(stack.stack_grows_negative()),
            i32::from(stack.is_formal_stackspace()),
        );
        print_space_line(&stack);
    }

    // ---- case 4: readSpace resolution failure ----------------------------
    println!("case=decode_space_unknown_base");
    {
        let mut registry = SpaceRegistry::new();
        let mut doc = canonical_spaces();
        make_space_element(
            &mut doc,
            "space_overlay",
            &[("name", "bad"), ("index", "6"), ("base", "nope")],
        );
        println!("  {}", decode_spaces(&mut registry, doc));
        println!(
            "  ovLookup={}",
            registry
                .get_space_by_name("bad")
                .map(|s| s.get_name())
                .unwrap_or_else(|| "null".to_string()),
        );
    }

    // ---- case 5: bad defaultspace attribute ------------------------------
    println!("case=decode_spaces_bad_default");
    {
        let mut registry = SpaceRegistry::new();
        let mut doc = make_spaces_document("missing");
        make_space_element(
            &mut doc,
            "space",
            &[("name", "ram"), ("index", "3"), ("size", "8"), ("delay", "0")],
        );
        println!("  {}", decode_spaces(&mut registry, doc));
        println!(
            "  default={}",
            registry
                .get_default_code_space()
                .map(|s| s.get_name())
                .unwrap_or_else(|| "null".to_string()),
        );
    }

    // ---- case 6: EXTERNAL-named processor space registration -------------
    println!("case=external_named_space_registration");
    {
        let mut registry = SpaceRegistry::new();
        let doc = canonical_spaces();
        println!("  {}", decode_spaces(&mut registry, doc));
        // The Ghidra-platform external space (AddressSpace.java:80): flat
        // 32-bit space named EXTERNAL, registered like any processor space.
        let external = AddrSpace::new_external_space(9, false);
        match registry.insert_space(external.clone()) {
            Ok(()) => println!("  ok"),
            Err(message) => println!("  err {}", message),
        }
        let ram = registry.get_space_by_name("ram").expect("ram registered");
        println!(
            "  lookup={} shortcut={} ram_ob={}",
            registry
                .get_space_by_name("EXTERNAL")
                .map(|s| s.get_name())
                .unwrap_or_else(|| "null".to_string()),
            external.get_shortcut(),
            i32::from(ram.is_overlay_base()),
        );
        print_space_line(&external);
        let duplicate = AddrSpace::new_external_space(10, false);
        match registry.insert_space(duplicate) {
            Ok(()) => println!("  ok"),
            Err(message) => println!("  err {}", message),
        }
        print_walk(&registry);
    }

    // ---- case 7: deadcodedelay default from delay ------------------------
    println!("case=deadcodedelay_default_from_delay");
    {
        let mut registry = SpaceRegistry::new();
        let mut doc = make_spaces_document("ws");
        make_space_element(
            &mut doc,
            "space",
            &[
                ("name", "ws"),
                ("index", "3"),
                ("size", "4"),
                ("wordsize", "2"),
                ("delay", "3"),
            ],
        );
        println!("  {}", decode_spaces(&mut registry, doc));
        let ws = registry.get_space_by_name("ws").expect("ws registered");
        print_space_line(&ws);

        let mut registry2 = SpaceRegistry::new();
        let mut doc2 = make_spaces_document("ws2");
        make_space_element(
            &mut doc2,
            "space",
            &[
                ("name", "ws2"),
                ("index", "3"),
                ("size", "4"),
                ("delay", "2"),
                ("deadcodedelay", "5"),
            ],
        );
        println!("  {}", decode_spaces(&mut registry2, doc2));
        let ws2 = registry2.get_space_by_name("ws2").expect("ws2 registered");
        print_space_line(&ws2);
    }
    let _ = SpaceType::Processor;
}
