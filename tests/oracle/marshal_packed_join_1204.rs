//! MARSHAL-PACKED-JOIN-1204: Rust comparand for the locked Ghidra 12.0.4
//! oracle `marshal_packed_join_1204.cc` (MARSHAL-XML-TEXT-0001).
//!
//! Byte-mirrors the C++ projection: the PackedEncode special-space type
//! byte per space type (fspec/iop/join/stack/regbase + the index arm),
//! PackedDecode::readSpace round-trips and every rejection path (the
//! encode-writes/decode-rejects asymmetry for fspec/iop/spacebase special
//! codes, unknown index, non-space attribute), the JoinSpace piece codec
//! through both the packed and XML/tree encodings (including the
//! single-piece float-extension logicalsize form and the findAddJoin dedup
//! on re-decode), and the edge rejections (unlinked offset, malformed
//! piece, piece position beyond MAX_PIECES, encoding more than MAX_PIECES
//! pieces).
//!
//! The register-name piece form (no ':') and unknown piece space names are
//! deliberately NOT exercised — see the C++ header comment: the former
//! needs the Translate register table (SPACE-0001), the latter is
//! UB-adjacent C++ that Rust's non-optional space handle rejects.

use rudra::address::elem_addr;
use rudra::marshal::{
    xml_tree, Decoder, Encoder, IdRegistry, PackedDecode, PackedEncode,
    TreeDecoder, TreeEncoder,
};
use rudra::space::{
    attrib_space, AddrSpace, SpaceRegistry, SpaceVarnodeData, SpaceType,
    space_flags,
};
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
    m.insert_space(AddrSpace::new_fspec_space(m.num_spaces() as i32, false))
        .unwrap();
    m.insert_space(AddrSpace::new_iop_space(m.num_spaces() as i32, false))
        .unwrap();
    m.insert_space(AddrSpace::new_join_space(m.num_spaces() as i32, false))
        .unwrap();
    // Secondary (non-formal) spacebase for the SPECIALSPACE_SPACEBASE byte.
    m.insert_space(AddrSpace::new_spacebase_space(
        "regbase",
        9,
        8,
        &ram,
        1,
        false,
        false,
    ))
    .unwrap();
    m
}

// RUGRA-GLUE: panic payload extraction (the space module signals its
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

fn hex_bytes(raw: &[u8]) -> String {
    let mut out = String::new();
    for b in raw {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// The PackedEncode byte image of <addr space="..."/> for one space.
fn packed_space_image(spc: &AddrSpace) -> Vec<u8> {
    let mut enc = PackedEncode::new();
    enc.open_element(&elem_addr());
    enc.write_space(&attrib_space(), spc);
    enc.close_element(&elem_addr());
    enc.into_bytes()
}

// readSpace(ATTRIB_SPACE) mirror: the findMatchingAttribute walk
// (rewind, scan ids, skip non-matching values) + read_space.
fn packed_read_space_probe(
    image: &[u8],
    m: &SpaceRegistry,
) -> Result<String, String> {
    let ids = Arc::new(RwLock::new(IdRegistry::new()));
    let mut dec = PackedDecode::new(image.to_vec(), ids);
    let elem = dec.open_element();
    dec.rewind_attributes();
    let name;
    loop {
        let aid = dec.next_attribute_id();
        if aid == 0 {
            return Err("Attribute space is not present".to_string());
        }
        if aid == attrib_space().id {
            name = dec.read_space(m)?.get_name();
            break;
        }
        let _ = dec.read_string(); // skipAttribute
    }
    dec.close_element(elem);
    Ok(name)
}

// The VarnodeData::decodeFromAttributes walk (pcoderaw.cc:33-56) over an
// open packed element: ATTRIB_SPACE -> read_space -> rewind ->
// decode_attributes.
fn packed_decode_addr(
    image: &[u8],
    m: &SpaceRegistry,
) -> Result<(u64, u32), String> {
    let ids = Arc::new(RwLock::new(IdRegistry::new()));
    let mut dec = PackedDecode::new(image.to_vec(), ids);
    let elem = dec.open_element();
    let aid = dec.next_attribute_id();
    if aid != attrib_space().id {
        return Err("no space attribute".to_string());
    }
    let spc = dec.read_space(m)?;
    dec.rewind_attributes();
    let mut size: u32 = 0;
    let off = spc.decode_attributes(&mut dec, m, &mut size)?;
    dec.close_element(elem);
    Ok((off, size))
}

// Same walk over an XML document (TreeDecoder standing in for XmlDecode).
fn xml_decode_addr(xml: &str, m: &SpaceRegistry) -> Result<(u64, u32), String> {
    let doc = xml_tree(xml.as_bytes()).map_err(|e| e.explain)?;
    let ids = Arc::new(RwLock::new(IdRegistry::new()));
    let mut dec = TreeDecoder::from_document(&doc, ids);
    let elem = dec.open_element();
    let aid = dec.next_attribute_id();
    if aid != attrib_space().id {
        return Err("no space attribute".to_string());
    }
    let spc = dec.read_space(m)?;
    dec.rewind_attributes();
    let mut size: u32 = 0;
    let off = spc.decode_attributes(&mut dec, m, &mut size)?;
    dec.close_element(elem);
    Ok((off, size))
}

fn main() {
    println!(
        "schema=1|fixture=MARSHAL-PACKED-JOIN-1204|\
         oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    let mut m = build_registry();
    let ram = m.get_space_by_name("ram").unwrap();
    let reg = m.get_space_by_name("register").unwrap();
    let stack = m.get_space_by_name("stack").unwrap();
    let regbase = m.get_space_by_name("regbase").unwrap();
    let fspec = m.get_space_by_name("fspec").unwrap();
    let iop = m.get_space_by_name("iop").unwrap();
    let join = m.get_join_space().unwrap();
    let constspc = m.get_space_by_name("const").unwrap();
    let uniqspc = m.get_space_by_name("unique").unwrap();

    // ---- case=packed_special_space_bytes ---------------------------------
    {
        let mut out = String::from("case=packed_special_space_bytes");
        out.push_str(&format!(
            "|const={}",
            hex_bytes(&packed_space_image(&constspc))
        ));
        out.push_str(&format!(
            "|unique={}",
            hex_bytes(&packed_space_image(&uniqspc))
        ));
        out.push_str(&format!("|ram={}", hex_bytes(&packed_space_image(&ram))));
        out.push_str(&format!(
            "|register={}",
            hex_bytes(&packed_space_image(&reg))
        ));
        out.push_str(&format!(
            "|stack={}",
            hex_bytes(&packed_space_image(&stack))
        ));
        out.push_str(&format!(
            "|regbase={}",
            hex_bytes(&packed_space_image(&regbase))
        ));
        out.push_str(&format!(
            "|fspec={}",
            hex_bytes(&packed_space_image(&fspec))
        ));
        out.push_str(&format!("|iop={}", hex_bytes(&packed_space_image(&iop))));
        out.push_str(&format!(
            "|join={}",
            hex_bytes(&packed_space_image(&join))
        ));
        println!("{}", out);
    }

    // ---- case=packed_read_space -------------------------------------------
    {
        let mut out = String::from("case=packed_read_space");
        let err = packed_read_space_probe(&packed_space_image(&ram), &m)
            .err()
            .unwrap_or_default();
        out.push_str(&format!(
            "|ram_rt={}",
            (err.is_empty()
                && packed_read_space_probe(&packed_space_image(&ram), &m)
                    == Ok("ram".to_string())) as u8
        ));
        out.push_str(&format!("|ram_err={}", err));
        let err = packed_read_space_probe(&packed_space_image(&join), &m)
            .err()
            .unwrap_or_default();
        out.push_str(&format!(
            "|join_rt={}",
            (err.is_empty()
                && packed_read_space_probe(&packed_space_image(&join), &m)
                    == Ok("join".to_string())) as u8
        ));
        out.push_str(&format!("|join_err={}", err));
        let err = packed_read_space_probe(&packed_space_image(&stack), &m)
            .err()
            .unwrap_or_default();
        out.push_str(&format!(
            "|stack_rt={}",
            (err.is_empty()
                && packed_read_space_probe(&packed_space_image(&stack), &m)
                    == Ok("stack".to_string())) as u8
        ));
        out.push_str(&format!("|stack_err={}", err));
        // Crafted rejections (byte images identical to the C++ literals).
        let err = packed_read_space_probe(&[0x4b, 0xd4, 0x62, 0x8b], &m)
            .err()
            .unwrap_or_default();
        out.push_str(&format!("|fspec_rej={}", err));
        let err = packed_read_space_probe(&[0x4b, 0xd4, 0x63, 0x8b], &m)
            .err()
            .unwrap_or_default();
        out.push_str(&format!("|iop_rej={}", err));
        let err = packed_read_space_probe(&[0x4b, 0xd4, 0x64, 0x8b], &m)
            .err()
            .unwrap_or_default();
        out.push_str(&format!("|spacebase_rej={}", err));
        let err = packed_read_space_probe(
            &[0x4b, 0xd4, 0x52, 0x81, 0xc8, 0x8b],
            &m,
        )
        .err()
        .unwrap_or_default();
        out.push_str(&format!("|bad_index_rej={}", err));
        let err = packed_read_space_probe(&[0x4b, 0xd4, 0x41, 0x85, 0x8b], &m)
            .err()
            .unwrap_or_default();
        out.push_str(&format!("|not_space_rej={}", err));
        println!("{}", out);
    }

    // ---- case=packed_join_roundtrip ---------------------------------------
    {
        // Two-piece join: ram:0x1000:8 + register:0x8:8 (most significant
        // first); findAddJoin allocates 16-byte aligned unified offsets.
        let pieces = [
            SpaceVarnodeData { space: ram.clone(), offset: 0x1000, size: 8 },
            SpaceVarnodeData { space: reg.clone(), offset: 0x8, size: 8 },
        ];
        let off2 = m.find_add_join(&pieces, 0);

        let mut enc = PackedEncode::new();
        enc.open_element(&elem_addr());
        join.encode_attributes(&mut enc, off2);
        enc.close_element(&elem_addr());
        let image = enc.into_bytes();

        let mut out = String::from("case=packed_join_roundtrip");
        out.push_str(&format!("|bytes={}", hex_bytes(&image)));
        out.push_str(&format!("|off={:x}", off2));
        match packed_decode_addr(&image, &m) {
            Ok((rt_off, rt_size)) => {
                out.push_str("|rt_ok=1");
                out.push_str("|rt_err=");
                out.push_str(&format!("|rt_off={:x}", rt_off));
                out.push_str(&format!("|rt_size={}", rt_size));
            }
            Err(e) => {
                out.push_str("|rt_ok=0");
                out.push_str(&format!("|rt_err={}", e));
                out.push_str("|rt_off=0");
                out.push_str("|rt_size=0");
            }
        }

        // Single-piece float extension: register:0x0:10 with logical 16.
        let fpiece = [SpaceVarnodeData {
            space: reg.clone(),
            offset: 0,
            size: 10,
        }];
        let offf = m.find_add_join(&fpiece, 16);

        let mut fenc = PackedEncode::new();
        fenc.open_element(&elem_addr());
        join.encode_attributes(&mut fenc, offf);
        fenc.close_element(&elem_addr());
        let fimage = fenc.into_bytes();

        out.push_str(&format!("|float_bytes={}", hex_bytes(&fimage)));
        out.push_str(&format!("|float_off={:x}", offf));
        match packed_decode_addr(&fimage, &m) {
            Ok((rt_off, rt_size)) => {
                out.push_str("|float_rt_ok=1");
                out.push_str("|float_rt_err=");
                out.push_str(&format!("|float_rt_off={:x}", rt_off));
                out.push_str(&format!("|float_rt_size={}", rt_size));
            }
            Err(e) => {
                out.push_str("|float_rt_ok=0");
                out.push_str(&format!("|float_rt_err={}", e));
                out.push_str("|float_rt_off=0");
                out.push_str("|float_rt_size=0");
            }
        }
        println!("{}", out);
    }

    // ---- case=xml_join_roundtrip ------------------------------------------
    {
        let pieces = [
            SpaceVarnodeData { space: ram.clone(), offset: 0x1000, size: 8 },
            SpaceVarnodeData { space: reg.clone(), offset: 0x8, size: 8 },
        ];
        let off2 = m.find_add_join(&pieces, 0); // dedup hit

        let ids = Arc::new(RwLock::new(IdRegistry::new()));
        let mut enc = TreeEncoder::new(ids);
        enc.open_element(&elem_addr());
        join.encode_attributes(&mut enc, off2);
        enc.close_element(&elem_addr());
        let doc = enc.into_document();

        // Attribute-pair walk (name=value, source order) — the projection
        // of the C++ parseDocument walk over the XmlEncode text.
        let root = doc.root.as_ref().unwrap();
        let root = root.read().unwrap();
        let attrs = root
            .attr_names
            .iter()
            .zip(root.attr_values.iter())
            .map(|(n, v)| format!("{}={}", n, v))
            .collect::<Vec<_>>()
            .join(",");

        // Decode from the encoded XML form.
        let xml = "<addr space=\"join\" piece1=\"ram:0x1000:8\" \
                   piece2=\"register:0x8:8\"/>";
        let mut out = String::from("case=xml_join_roundtrip");
        out.push_str(&format!("|attrs={}", attrs));
        out.push_str(&format!("|off={:x}", off2));
        match xml_decode_addr(xml, &m) {
            Ok((rt_off, rt_size)) => {
                out.push_str("|rt1_ok=1");
                out.push_str("|rt1_err=");
                out.push_str(&format!("|rt1_off={:x}", rt_off));
                out.push_str(&format!("|rt1_size={}", rt_size));
                let dedup_eq = match xml_decode_addr(xml, &m) {
                    Ok((off_again, _)) => off_again == rt_off,
                    Err(_) => false,
                };
                out.push_str(&format!("|dedup_eq={}", dedup_eq as u8));
            }
            Err(e) => {
                out.push_str("|rt1_ok=0");
                out.push_str(&format!("|rt1_err={}", e));
                out.push_str("|rt1_off=0");
                out.push_str("|rt1_size=0");
                out.push_str("|dedup_eq=0");
            }
        }
        println!("{}", out);
    }

    // ---- case=join_codec_edges --------------------------------------------
    {
        let mut out = String::from("case=join_codec_edges");
        // (a) Encoding an offset with no JoinRecord: find_join panics with
        // the C++ LowlevelError text.
        {
            let payload = catch_quiet(|| {
                let mut enc = PackedEncode::new();
                enc.open_element(&elem_addr());
                join.encode_attributes(&mut enc, 0xdead);
            });
            out.push_str(&format!(
                "|unlinked_err={}",
                panic_message(payload)
            ));
        }
        // (b) Single-colon piece string: malformed.
        {
            let err = match xml_decode_addr(
                "<addr space=\"join\" piece1=\"ram:0x1000\"/>",
                &m,
            ) {
                Ok(_) => String::new(),
                Err(e) => e,
            };
            out.push_str(&format!("|malformed_err={}", err));
        }
        // (c) piece66: pos 65 > MAX_PIECES, skipped -> no pieces ->
        // find_add_join's "Cannot create a join without pieces" panic.
        {
            let payload = catch_quiet(|| {
                let _ = xml_decode_addr(
                    "<addr space=\"join\" piece66=\"ram:0x0:4\"/>",
                    &m,
                );
            });
            out.push_str(&format!(
                "|overflow_piece_err={}",
                panic_message(payload)
            ));
        }
        // (d) Encoding a record holding more than MAX_PIECES pieces.
        {
            let many: Vec<SpaceVarnodeData> = (0..65u64)
                .map(|i| SpaceVarnodeData {
                    space: ram.clone(),
                    offset: i * 0x10,
                    size: 1,
                })
                .collect();
            let off65 = m.find_add_join(&many, 0);
            let payload = catch_quiet(|| {
                let mut enc = PackedEncode::new();
                enc.open_element(&elem_addr());
                join.encode_attributes(&mut enc, off65);
            });
            out.push_str(&format!(
                "|encode_overflow_err={}",
                panic_message(payload)
            ));
        }
        println!("{}", out);
    }
}
