//! FSPEC-SPACE-IDENTITY-1204: Rust comparand for the locked Ghidra 12.0.4
//! oracle `fspec_space_identity_1204.cc` (TYPEOP-FSPEC-SPACE-0001 slice 1).
//!
//! Byte-mirrors the C++ projection: FspecSpace registration/lookup/
//! rejection, same-offset CONST/FSPEC/IOP discrimination (equality, order,
//! map order, overlap, wraparound), the four FspecSpace::printRaw forms,
//! the encodeAttributes invalid/valid-entry projection with the decode
//! round-trip and its rejection paths, and the never-decoded guards.
//!
//! The C++ side drives real FuncCallSpecs-shaped storage whose address is
//! the fspec offset; the Rust side registers the same name/entry views at
//! fixed offsets through the registry's fspec-entry table — nothing offset
//! raw is printed, so both projections are byte-identical.

use rudra::address::SpaceAddress;
use rudra::marshal::{xml_tree, IdRegistry, TreeDecoder, TreeEncoder};
use rudra::space::{
    attrib_offset, AddrSpace, FspecEntryTable, FSPEC_SPACE_NAME, SpaceRegistry, SpaceType,
    space_flags,
};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

fn build_registry() -> SpaceRegistry {
    let mut m = SpaceRegistry::new();
    m.insert_space(AddrSpace::new_constant_space(false)).unwrap();
    m.insert_space(AddrSpace::new_unique_space(2, 0, false)).unwrap();
    m.insert_space(AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        3,
        space_flags::HASPHYSICAL,
        0,
        0,
    ))
    .unwrap();
    m.insert_space(AddrSpace::new_space(
        SpaceType::Processor,
        "register",
        false,
        8,
        1,
        4,
        space_flags::HASPHYSICAL,
        0,
        0,
    ))
    .unwrap();
    let ram = m.get_space_by_name("ram").unwrap();
    m.insert_space(AddrSpace::new_spacebase_space(
        "stack", 5, 8, &ram, 1, true, false,
    ))
    .unwrap();
    // architecture.cc:631-634 order: fspec at numSpaces(), then iop, then
    // join.
    m.insert_space(AddrSpace::new_fspec_space(m.num_spaces() as i32, false))
        .unwrap();
    m.insert_space(AddrSpace::new_iop_space(m.num_spaces() as i32, false))
        .unwrap();
    m.insert_space(AddrSpace::new_join_space(m.num_spaces() as i32, false))
        .unwrap();
    m
}

// RUDRA-GLUE: panic payload extraction (the space module signals its
// LowlevelError equivalents as string panics).
fn panic_message(e: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        unreachable!("panic payload was not a string")
    }
}

fn catch_quiet<F: FnOnce()>(f: F) -> Box<dyn std::any::Any + Send> {
    // The C++ side catches its LowlevelError with no diagnostic output;
    // silence the default Rust panic hook for the duration of the catch so
    // stderr stays byte-empty like the oracle binary.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    result.unwrap_err()
}

fn encode_document(addr: &SpaceAddress) -> rudra::marshal::Document {
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut enc = TreeEncoder::new(registry);
    addr.encode(&mut enc);
    enc.into_document()
}

fn attr_names(doc: &rudra::marshal::Document) -> String {
    let root = doc.root.as_ref().unwrap();
    let root = root.read().unwrap();
    root.attr_names.join(",")
}

fn decode_document(
    doc: &rudra::marshal::Document,
    registry: &SpaceRegistry,
) -> Result<SpaceAddress, String> {
    let ids = Arc::new(RwLock::new(IdRegistry::new()));
    let mut dec = TreeDecoder::from_document(doc, ids);
    SpaceAddress::decode(&mut dec, registry)
}

fn decode_xml(
    xml: &str,
    registry: &SpaceRegistry,
) -> Result<SpaceAddress, String> {
    let doc = xml_tree(xml.as_bytes()).expect("fixture xml parses");
    decode_document(&doc, registry)
}

fn main() {
    println!(
        "schema=1|fixture=FSPEC-SPACE-IDENTITY-1204|\
         oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    let mut m = build_registry();

    // ---- case=registration_lookup --------------------------------------
    let fspec = m.get_space_by_name(FSPEC_SPACE_NAME).unwrap();
    let iop = m.get_space_by_name("iop").unwrap();
    {
        let mut out = String::from("case=registration_lookup");
        out.push_str(&format!(
            "|byname_eq_cached={}",
            (m.get_space_by_name("fspec") == m.get_fspec_space()) as u8
        ));
        out.push_str(&format!(
            "|byname_miss={}",
            m.get_space_by_name("fspec2").is_none() as u8
        ));
        out.push_str(&format!("|shortcut={}", fspec.get_shortcut()));
        out.push_str(&format!(
            "|shortcut_lookup_eq={}",
            (m.get_space_by_shortcut('f').as_ref() == Some(&fspec)) as u8
        ));
        out.push_str(&format!(
            "|type={}",
            fspec.get_type() as u32
        ));
        out.push_str(&format!("|name={}", fspec.get_name()));
        out.push_str(&format!("|addrsize={}", fspec.get_addr_size()));
        out.push_str(&format!("|wordsize={}", fspec.get_word_size()));
        out.push_str(&format!("|delay={}", fspec.get_delay()));
        out.push_str(&format!("|deadcodedelay={}", fspec.get_deadcode_delay()));
        out.push_str(&format!(
            "|heritaged={}",
            fspec.is_heritaged() as u8
        ));
        out.push_str(&format!(
            "|does_deadcode={}",
            fspec.does_deadcode() as u8
        ));
        out.push_str(&format!(
            "|bigendian={}",
            fspec.is_big_endian() as u8
        ));
        out.push_str(&format!("|highest=0x{:x}", fspec.get_highest()));
        out.push_str(&format!("|plb=0x{:x}", fspec.get_pointer_lower_bound()));
        out.push_str(&format!("|pub=0x{:x}", fspec.get_pointer_upper_bound()));
        out.push_str(&format!("|index={}", fspec.get_index()));
        let dup_msg = m
            .insert_space(AddrSpace::new_fspec_space(20, false))
            .unwrap_err();
        out.push_str(&format!("|dup_msg={}", dup_msg));
        // Fresh registry so only the type-name mismatch fires.
        let mut m2 = SpaceRegistry::new();
        m2.insert_space(AddrSpace::new_constant_space(false)).unwrap();
        m2.insert_space(AddrSpace::new_space(
            SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            space_flags::HASPHYSICAL,
            0,
            0,
        ))
        .unwrap();
        let wrongtype_msg = m2
            .insert_space(AddrSpace::new_space(
                SpaceType::Fspec, "wrongfs", false, 8, 1, 9, 0, 1, 1,
            ))
            .unwrap_err();
        out.push_str(&format!("|wrongtype_msg={}", wrongtype_msg));
        out.push_str(&format!("|iop_shortcut={}", iop.get_shortcut()));
        out.push_str(&format!("|iop_index={}", iop.get_index()));
        out.push_str("|walk=");
        let mut first = true;
        let mut cur = m.get_next_space_in_order(None);
        while let Some(spc) = cur {
            if !first {
                out.push(',');
            }
            out.push_str(&spc.get_name());
            first = false;
            cur = m.get_next_space_in_order(Some(spc));
        }
        println!("{}", out);
    }

    // ---- fspec entry views (the Rust stand-in for the C++ storage) ------
    let ram = m.get_space_by_name("ram").unwrap();
    const OFF_INVALID: u64 = 1000;
    const OFF_VALID: u64 = 2000;
    const OFF_NAMED: u64 = 3000;
    const OFF_NAMED2: u64 = 4000;
    m.register_fspec_entry(OFF_INVALID, "", None);
    m.register_fspec_entry(OFF_VALID, "", Some((&ram, 0x1234)));
    m.register_fspec_entry(OFF_NAMED, "target_func", Some((&ram, 0x1234)));
    m.register_fspec_entry(OFF_NAMED2, "named_indirect", None);

    // ---- case=same_offset_discrimination --------------------------------
    {
        const X: u64 = 0x5555aaaa;
        let constspc = m.get_space_by_name("const").unwrap();
        let stack = m.get_space_by_name("stack").unwrap();
        let join = m.get_space_by_name("join").unwrap();
        let c = SpaceAddress::new(constspc.clone(), X);
        let s = SpaceAddress::new(stack.clone(), X);
        let f = SpaceAddress::new(fspec.clone(), X);
        let i = SpaceAddress::new(iop.clone(), X);
        let j = SpaceAddress::new(join.clone(), X);
        let f2 = SpaceAddress::new(fspec.clone(), X);
        // Ghidra has no Address hash; the Rust Hash key must at least agree
        // with PartialEq (equal addresses hash equal) — asserted silently.
        {
            use std::hash::{Hash, Hasher};
            fn hash_of(a: &SpaceAddress) -> u64 {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                a.hash(&mut h);
                h.finish()
            }
            assert_eq!(hash_of(&f), hash_of(&f2));
            assert_ne!(hash_of(&f), hash_of(&i));
        }
        let mut vec = vec![i.clone(), f.clone(), j.clone(), c.clone(), s.clone()];
        vec.sort();
        let mut ordered = BTreeMap::new();
        ordered.insert(i.clone(), 4);
        ordered.insert(f.clone(), 3);
        ordered.insert(j.clone(), 5);
        ordered.insert(c.clone(), 1);
        ordered.insert(s.clone(), 2);
        let mut out = String::from("case=same_offset_discrimination");
        out.push_str(&format!("|eq_cross={}", (c == f) as u8));
        out.push_str(&format!("|eq_self={}", (f == f2) as u8));
        out.push_str(&format!("|lt_const_fspec={}", (c < f) as u8));
        out.push_str(&format!("|lt_fspec_iop={}", (f < i) as u8));
        out.push_str(&format!("|lt_const_iop={}", (c < i) as u8));
        out.push_str(&format!("|lt_fspec_join={}", (f < j) as u8));
        out.push_str(&format!("|lt_stack_fspec={}", (s < f) as u8));
        out.push_str("|order=");
        let mut first = true;
        for addr in &vec {
            if !first {
                out.push(',');
            }
            out.push_str(&addr.get_space().unwrap().get_name());
            first = false;
        }
        out.push_str("|map_order=");
        let mut first = true;
        for (addr, _) in &ordered {
            if !first {
                out.push(',');
            }
            out.push_str(&addr.get_space().unwrap().get_name());
            first = false;
        }
        out.push_str(&format!("|ovl_fspec_iop={}", f.overlap(0, &i, 8)));
        out.push_str(&format!("|ovl_self={}", f.overlap(0, &f2, 8)));
        out.push_str(&format!(
            "|ovl_shift={}",
            SpaceAddress::new(fspec.clone(), X + 4).overlap(0, &f, 8)
        ));
        out.push_str(&format!("|ovl_const={}", c.overlap(0, &c, 8)));
        out.push_str(&format!(
            "|ovl_iop_shift={}",
            SpaceAddress::new(iop.clone(), X + 3).overlap(0, &i, 5)
        ));
        out.push_str(&format!(
            "|contained_cross={}",
            f.contained_by(4, &i, 8) as u8
        ));
        out.push_str(&format!(
            "|justified_cross={}",
            f.justified_contain(8, &i, 4, false)
        ));
        out.push_str(&format!(
            "|wrap_max_eq0={}",
            (SpaceAddress::new(fspec.clone(), u64::MAX)
                .add(1)
                .get_offset()
                == 0) as u8
        ));
        println!("{}", out);
    }

    // ---- case=print_raw_forms -------------------------------------------
    {
        let mut out = String::from("case=print_raw_forms");
        out.push_str(&format!(
            "|invalid_entry={}",
            fspec.print_raw(OFF_INVALID)
        ));
        out.push_str(&format!("|valid_entry={}", fspec.print_raw(OFF_VALID)));
        out.push_str(&format!("|named={}", fspec.print_raw(OFF_NAMED)));
        out.push_str(&format!(
            "|named_indirect={}",
            fspec.print_raw(OFF_NAMED2)
        ));
        let constspc = m.get_space_by_name("const").unwrap();
        out.push_str(&format!("|const_form={}", constspc.print_raw(0x1234)));
        println!("{}", out);
    }

    // ---- case=encode_decode_roundtrip -----------------------------------
    {
        let mut out = String::from("case=encode_decode_roundtrip");
        // (a) invalid entry: only the space attribute; decoding throws.
        {
            let orig = SpaceAddress::new(fspec.clone(), OFF_INVALID);
            let doc = encode_document(&orig);
            let names = attr_names(&doc);
            let err = decode_document(&doc, &m).unwrap_err();
            out.push_str(&format!("|invalid_entry_attrs={}", names));
            out.push_str(&format!("|invalid_entry_decode_err={}", err));
        }
        // (b) valid entry: encodes the ENTRY space+offset; decoding yields
        // the entry address, NOT the original fspec address.
        {
            let orig = SpaceAddress::new(fspec.clone(), OFF_VALID);
            let doc = encode_document(&orig);
            let names = attr_names(&doc);
            let res = decode_document(&doc, &m).unwrap();
            let dec_space = res.get_space().unwrap().get_name();
            let dec_off = res.get_offset();
            out.push_str(&format!("|valid_entry_attrs={}", names));
            out.push_str(&format!("|valid_entry_dec_space={}", dec_space));
            out.push_str(&format!("|valid_entry_dec_off={}", dec_off));
            out.push_str(&format!(
                "|valid_entry_dec_is_fspec={}",
                (dec_space == FSPEC_SPACE_NAME) as u8
            ));
            out.push_str(&format!(
                "|valid_entry_same_as_orig={}",
                (res == orig) as u8
            ));
        }
        // (c) plain ram address round-trips through itself.
        {
            let orig = SpaceAddress::new(ram.clone(), 0x1234);
            let doc = encode_document(&orig);
            let res = decode_document(&doc, &m).unwrap();
            out.push_str(&format!("|ram_rt_eq={}", (res == orig) as u8));
        }
        // (d) crafted <addr space="fspec" offset="0x77"/> resolves by name;
        // compared against the original handle (the duplicate-insert test
        // poisoned the cached slot exactly like translate.cc:373-379).
        {
            let res = decode_xml(
                "<addr space=\"fspec\" offset=\"0x77\"/>",
                &m,
            )
            .unwrap();
            out.push_str(&format!(
                "|crafted_fspec_space={}",
                (res.get_space().unwrap() == &fspec) as u8
            ));
            out.push_str(&format!(
                "|crafted_off_eq={}",
                (res.get_offset() == 0x77) as u8
            ));
            out.push_str(&format!("|crafted_wrap={}", res.add(1).get_offset()));
        }
        // (e) unknown space name rejection.
        {
            let err = decode_xml("<addr space=\"nosuch\" offset=\"0x1\"/>", &m).unwrap_err();
            out.push_str(&format!("|unknown_space_err={}", err));
        }
        // (f) attribute-less <addr/> decodes invalid.
        {
            let res = decode_xml("<addr/>", &m).unwrap();
            out.push_str(&format!(
                "|empty_addr_invalid={}",
                res.is_invalid() as u8
            ));
        }
        // (g) the never-decoded guard.
        {
            let doc = xml_tree(b"<addr/>").unwrap();
            let ids = Arc::new(RwLock::new(IdRegistry::new()));
            let mut dec = TreeDecoder::from_document(&doc, ids);
            let payload = catch_quiet(|| fspec.decode(&mut dec));
            out.push_str(&format!("|fspec_decode_err={}", panic_message(payload)));
        }
        println!("{}", out);
    }

    // ---- case=cross_space_exceptions -------------------------------------
    {
        let f = SpaceAddress::new(fspec.clone(), 0x1000);
        let ram_point = SpaceAddress::new(ram.clone(), 0x1000);
        let ram_range = rudra::address::SpaceRange::new(ram.clone(), 0x1000, 0x2000);
        let mut out = String::from("case=cross_space_exceptions");
        out.push_str(&format!(
            "|range_contains_fspec={}",
            ram_range.contains(&f) as u8
        ));
        out.push_str(&format!(
            "|overlap_join_cross={}",
            f.overlap_join(0, &ram_point, 8)
        ));
        let doc = xml_tree(b"<addr/>").unwrap();
        let ids = Arc::new(RwLock::new(IdRegistry::new()));
        let mut dec = TreeDecoder::from_document(&doc, ids);
        let payload = catch_quiet(|| iop.decode(&mut dec));
        out.push_str(&format!("|iop_decode_err={}", panic_message(payload)));
        println!("{}", out);
    }

    // RUDRA-GLUE: keep the fspec entry table reachable for the Debug
    // formatting of the registry in future slices; a no-op read today.
    let _ = FspecEntryTable::default();
    let _ = attrib_offset();
}
