// TYPEFACTORY-LOCALTYPE-CACHE-0001: Rust comparand for the locked Ghidra
// TypeFactory core-cache fixture. Record order and values mirror the C++
// fixture byte-for-byte; Arc pointer identity is the Rust observation of the
// factory-owned canonical Datatype pointer identity used by Ghidra.
//
// REWORK: the factory mirrors the production BfdArchitecture state by
// decoding the same <size_alignment_map> the compiler spec installs (the C++
// side inherits it from architecture.init), and the additional waves cover
// wide/float slots, the raw constructor, promotion, conflict partial state,
// decodeCoreTypes, and the large-base array conversion.

use std::sync::{Arc, RwLock};

use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::TypeFactory;

fn metatype_number(metatype: TypeMetatype) -> i32 {
    match metatype {
        TypeMetatype::Int => 14,
        TypeMetatype::Uint => 13,
        TypeMetatype::Float => 10,
        TypeMetatype::Void => 17,
        TypeMetatype::Unknown => 15,
        TypeMetatype::Array => 7,
        other => panic!("fixture received unsupported metatype: {other:?}"),
    }
}

fn emit_identity(key: &str, left: &Arc<Datatype>, right: &Arc<Datatype>) {
    println!("{key}={}", if Arc::ptr_eq(left, right) { 1 } else { 0 });
}

fn emit_type(key: &str, datatype: &Arc<Datatype>) {
    println!("{key}.name={}", datatype.get_name());
    println!("{key}.id={}", datatype.get_id());
    println!("{key}.size={}", datatype.get_size());
    println!("{key}.meta={}", metatype_number(datatype.get_metatype()));
    println!("{key}.core={}", if datatype.is_coretype() { 1 } else { 0 });
    println!(
        "{key}.char={}",
        if datatype.get_flags() & rudra::type_system::datatype::type_flags::CHARTYPE != 0 {
            1
        } else {
            0
        }
    );
}

fn base(factory: &mut TypeFactory, metatype: TypeMetatype) -> Arc<Datatype> {
    factory
        .get_base_result(1, metatype)
        .expect("fixture base type must exist")
}

fn base_sized(factory: &mut TypeFactory, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    factory
        .get_base_result(size, metatype)
        .expect("fixture base type must exist")
}

fn nochar(factory: &mut TypeFactory) -> Arc<Datatype> {
    factory
        .get_base_no_char_result(1, TypeMetatype::Int)
        .expect("fixture nochar base type must exist")
}

fn named(factory: &TypeFactory, name: &str) -> Arc<Datatype> {
    factory
        .find_by_name(name)
        .unwrap_or_else(|| panic!("missing fixture type: {name}"))
}

/// Build an XML element tree mirroring the C++ fixture's decode strings.
fn elem(name: &str, attrs: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut el = Element::new();
    el.set_name(name);
    for (k, v) in attrs {
        el.add_attribute(k, v);
    }
    Arc::new(RwLock::new(el))
}

fn coretypes_doc(children: Vec<Arc<RwLock<Element>>>) -> Arc<RwLock<Element>> {
    let root = elem("coretypes", &[]);
    {
        let mut rg = root.write().unwrap();
        for child in children {
            rg.add_child(child);
        }
    }
    root
}

fn decode_core_types(factory: &mut TypeFactory, doc: Arc<RwLock<Element>>) -> Result<(), String> {
    let mut decoder = TreeDecoder::new(doc, Arc::new(RwLock::new(IdRegistry)));
    factory.decode_core_types(&mut decoder)
}

fn main() {
    let mut factory = TypeFactory::new(8);
    // Mirror BfdArchitecture's decodeDataOrganization: the production
    // factory carries the compiler spec's size alignment map through every
    // clear() (type.cc:3251 does not wipe alignMap).
    {
        let map = elem("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            for (size, alignment) in [(1, 1), (2, 2), (4, 4), (8, 8), (16, 16)] {
                rg.add_child(elem(
                    "entry",
                    &[
                        ("size", &size.to_string()),
                        ("alignment", &alignment.to_string()),
                    ],
                ));
            }
        }
        let root = elem("data_organization", &[]);
        root.write().unwrap().add_child(map);
        let mut decoder = TreeDecoder::new(root, Arc::new(RwLock::new(IdRegistry)));
        let _ = factory.decode_data_organization(&mut decoder);
    }
    factory.clear();
    factory.set_core_type_result("plain_high", 1, TypeMetatype::Int, false).expect("core registration");
    factory.set_core_type_result("aaaaaaaa", 1, TypeMetatype::Int, false).expect("core registration");
    factory.set_core_type_result("unsigned_custom_a", 1, TypeMetatype::Uint, false).expect("core registration");
    factory.set_core_type_result("unsigned_custom_b", 1, TypeMetatype::Uint, false).expect("core registration");
    factory.set_core_type_result("custom_ascii_glyph", 1, TypeMetatype::Int, true).expect("core registration");
    factory.cache_core_types();

    let plain_high = named(&factory, "plain_high");
    let plain_a = named(&factory, "aaaaaaaa");
    let uint_a = named(&factory, "unsigned_custom_a");
    let uint_b = named(&factory, "unsigned_custom_b");
    let ascii = named(&factory, "custom_ascii_glyph");
    let preferred = base(&mut factory, TypeMetatype::Int);
    let initial_nochar = nochar(&mut factory);
    let preferred_uint = base(&mut factory, TypeMetatype::Uint);
    emit_type("initial.plain_high", &plain_high);
    emit_type("initial.aaaaaaaa", &plain_a);
    emit_type("initial.ascii", &ascii);
    emit_type("initial.uint_a", &uint_a);
    emit_type("initial.uint_b", &uint_b);
    emit_type("initial.preferred", &preferred);
    emit_type("initial.nochar", &initial_nochar);
    emit_type("initial.preferred_uint", &preferred_uint);
    emit_identity("initial.preferred_is_ascii", &preferred, &ascii);
    let expected_nochar = if plain_high.get_id() > plain_a.get_id() {
        &plain_high
    } else {
        &plain_a
    };
    emit_identity(
        "initial.nochar_is_tree_last",
        &initial_nochar,
        expected_nochar,
    );
    let expected_uint = if uint_a.get_id() < uint_b.get_id() {
        &uint_a
    } else {
        &uint_b
    };
    emit_identity("initial.uint_is_tree_first", &preferred_uint, expected_uint);
    let initial_char = factory.get_type_char(1).expect("cached char");
    emit_identity("initial.charcache_is_ascii", &initial_char, &ascii);
    emit_identity(
        "initial.getbase_repeat",
        &preferred,
        &base(&mut factory, TypeMetatype::Int),
    );
    emit_identity("initial.nochar_repeat", &initial_nochar, &nochar(&mut factory));

    factory.cache_core_types();
    emit_identity(
        "repeat_cache.preferred",
        &preferred,
        &base(&mut factory, TypeMetatype::Int),
    );
    emit_identity("repeat_cache.nochar", &initial_nochar, &nochar(&mut factory));
    emit_identity(
        "repeat_cache.uint",
        &preferred_uint,
        &base(&mut factory, TypeMetatype::Uint),
    );

    factory.set_core_type_result("zzzzzzzz", 1, TypeMetatype::Int, false).expect("core registration");
    let late_plain = named(&factory, "zzzzzzzz");
    factory.cache_core_types();
    let late_nochar = nochar(&mut factory);
    emit_type("late.plain", &late_plain);
    emit_type("late.nochar", &late_nochar);
    emit_identity("late.old_nochar_same", &initial_nochar, &late_nochar);
    emit_identity("late.new_nochar_is_late", &late_nochar, &late_plain);
    emit_identity(
        "late.preferred_still_ascii",
        &base(&mut factory, TypeMetatype::Int),
        &ascii,
    );

    factory.clear();
    factory.clear();
    println!(
        "clear.old_name_absent={}",
        if factory.find_by_name("custom_ascii_glyph").is_none() {
            1
        } else {
            0
        }
    );
    let empty_base = base(&mut factory, TypeMetatype::Int);
    emit_type("clear.empty_base", &empty_base);
    emit_identity(
        "clear.empty_nochar_falls_through",
        &empty_base,
        &nochar(&mut factory),
    );

    factory.clear();
    factory.set_core_type_result("post_clear_plain", 1, TypeMetatype::Int, false).expect("core registration");
    factory.cache_core_types();
    let post_plain = named(&factory, "post_clear_plain");
    let post_preferred = base(&mut factory, TypeMetatype::Int);
    let post_nochar = nochar(&mut factory);
    emit_type("post.plain", &post_plain);
    emit_identity("post.preferred_is_plain", &post_preferred, &post_plain);
    emit_identity("post.nochar_is_plain", &post_nochar, &post_plain);
    factory.cache_core_types();
    emit_identity(
        "post.repeat_cache_preferred",
        &post_preferred,
        &base(&mut factory, TypeMetatype::Int),
    );
    emit_identity("post.repeat_cache_nochar", &post_nochar, &nochar(&mut factory));

    factory.set_core_type_result("post_clear_ascii", 1, TypeMetatype::Int, true).expect("core registration");
    let post_ascii = named(&factory, "post_clear_ascii");
    factory.cache_core_types();
    emit_type("post.ascii", &post_ascii);
    emit_identity(
        "post.preferred_is_ascii",
        &base(&mut factory, TypeMetatype::Int),
        &post_ascii,
    );
    emit_identity("post.nochar_stays_plain", &nochar(&mut factory), &post_plain);
    let post_char = factory.get_type_char(1).expect("cached char");
    emit_identity("post.charcache_is_ascii", &post_char, &post_ascii);

    // ---- REWORK waves: wide characters, float10/16, raw constructor,
    // ---- promotion, conflicts, decodeCoreTypes, and large-base conversion.

    // Wave A: wide characters and dedicated float slots.
    factory.clear();
    factory
        .set_core_type_result("wide2", 2, TypeMetatype::Int, true)
        .expect("core registration");
    factory
        .set_core_type_result("wide4", 4, TypeMetatype::Int, true)
        .expect("core registration");
    factory
        .set_core_type_result("plain2", 2, TypeMetatype::Int, false)
        .expect("core registration");
    factory
        .set_core_type_result("f10", 10, TypeMetatype::Float, false)
        .expect("core registration");
    factory
        .set_core_type_result("f16", 16, TypeMetatype::Float, false)
        .expect("core registration");
    factory.cache_core_types();
    emit_type("wide.w2", &named(&factory, "wide2"));
    emit_type("wide.f10", &named(&factory, "f10"));
    emit_type("wide.f16", &named(&factory, "f16"));
    let wide_char2 = factory.get_type_char(2).expect("cached wchar");
    emit_identity(
        "wide.charcache2_is_wide2",
        &wide_char2,
        &named(&factory, "wide2"),
    );
    emit_identity(
        "wide.preferred2_is_plain2",
        &base_sized(&mut factory, 2, TypeMetatype::Int),
        &named(&factory, "plain2"),
    );
    emit_identity(
        "wide.f10_slot",
        &base_sized(&mut factory, 10, TypeMetatype::Float),
        &named(&factory, "f10"),
    );
    emit_identity(
        "wide.f16_slot",
        &base_sized(&mut factory, 16, TypeMetatype::Float),
        &named(&factory, "f16"),
    );
    match factory.get_type_char(5) {
        Ok(_) => println!("wide.char5_threw=0"),
        Err(message) => {
            println!("wide.char5_threw=1");
            println!("wide.char5_msg={message}");
        }
    }

    // Wave B: the raw TypeFactory constructor state (type.cc:3106-3119).
    {
        let mut raw_factory = TypeFactory::raw();
        match raw_factory.get_base_result(1, TypeMetatype::Int) {
            Ok(_) => println!("raw.align_threw=0"),
            Err(message) => {
                println!("raw.align_threw=1");
                println!("raw.align_msg={message}");
            }
        }
        let raw_void = raw_factory.get_type_void_result();
        emit_type("raw.void", &raw_void);
        match raw_factory.get_type_char(1) {
            Ok(_) => println!("raw.char_threw=0"),
            Err(message) => {
                println!("raw.char_threw=1");
                println!("raw.char_msg={message}");
            }
        }
    }

    // Wave C: promoting an existing non-core named type (type.cc:3178-3195).
    factory.clear();
    let promo_pre = factory
        .get_base_named(1, TypeMetatype::Int, "promo_plain")
        .expect("named non-core base");
    emit_type("promo.pre", &promo_pre);
    factory
        .set_core_type_result("promo_plain", 1, TypeMetatype::Int, false)
        .expect("promotion");
    let promo_post = named(&factory, "promo_plain");
    emit_type("promo.post", &promo_post);
    factory.cache_core_types();
    emit_identity(
        "promo.preferred_is_promo",
        &base(&mut factory, TypeMetatype::Int),
        &promo_post,
    );
    emit_identity("promo.nochar_is_promo", &nochar(&mut factory), &promo_post);
    factory.clear_non_core();
    println!(
        "promo.noncore_survives={}",
        if factory.find_by_name("promo_plain").is_some() { 1 } else { 0 }
    );

    // Wave D: same-name conflicts leave the factory untouched (type.cc:3423).
    match factory.set_core_type_result("promo_plain", 2, TypeMetatype::Int, false) {
        Ok(_) => println!("conflict.size_threw=0"),
        Err(message) => {
            println!("conflict.size_threw=1");
            println!("conflict.size_msg={message}");
        }
    }
    match factory.set_core_type_result("promo_plain", 1, TypeMetatype::Int, true) {
        Ok(_) => println!("conflict.char_threw=0"),
        Err(message) => {
            println!("conflict.char_threw=1");
            println!("conflict.char_msg={message}");
        }
    }
    let conflict_survivor = named(&factory, "promo_plain");
    emit_type("conflict.survivor", &conflict_survivor);
    emit_identity(
        "conflict.preferred_unaffected",
        &base(&mut factory, TypeMetatype::Int),
        &conflict_survivor,
    );

    // Wave E1: full decodeCoreTypes rebuild (type.cc:4567-4577).
    let enum_child = elem(
        "type",
        &[
            ("metatype", "enum_int"),
            ("name", "dk_enum1"),
            ("size", "1"),
            ("id", "0x5500000000000004"),
        ],
    );
    enum_child.write().unwrap().add_child(elem(
        "val",
        &[("name", "A"), ("value", "0")],
    ));
    decode_core_types(
        &mut factory,
        coretypes_doc(vec![
            elem(
                "type",
                &[
                    ("name", "dk_int1"),
                    ("size", "1"),
                    ("metatype", "int"),
                    ("id", "0x5500000000000001"),
                ],
            ),
            elem(
                "type",
                &[
                    ("name", "dk_char"),
                    ("size", "1"),
                    ("metatype", "int"),
                    ("char", "true"),
                    ("id", "0x5500000000000002"),
                ],
            ),
            elem(
                "type",
                &[
                    ("name", "dk_utf2"),
                    ("size", "2"),
                    ("metatype", "int"),
                    ("utf", "true"),
                    ("id", "0x5500000000000003"),
                ],
            ),
            enum_child,
            elem("type", &[("metatype", "void"), ("id", "0x5500000000000005")]),
            elem(
                "type",
                &[
                    ("name", "dk_plain2"),
                    ("size", "2"),
                    ("metatype", "int"),
                    ("id", "0x5500000000000006"),
                ],
            ),
        ]),
    )
    .expect("decode wave E1");
    println!(
        "dk.old_promo_gone={}",
        if factory.find_by_name("promo_plain").is_none() { 1 } else { 0 }
    );
    emit_type("dk.int1", &named(&factory, "dk_int1"));
    emit_type("dk.char", &named(&factory, "dk_char"));
    emit_type("dk.enum1", &named(&factory, "dk_enum1"));
    emit_type("dk.void", &named(&factory, "void"));
    emit_identity(
        "dk.nochar_is_int1",
        &nochar(&mut factory),
        &named(&factory, "dk_int1"),
    );
    emit_identity(
        "dk.preferred_is_char",
        &base(&mut factory, TypeMetatype::Int),
        &named(&factory, "dk_char"),
    );
    let dk_char2 = factory.get_type_char(2).expect("cached wchar");
    emit_identity(
        "dk.charcache2_is_utf2",
        &dk_char2,
        &named(&factory, "dk_utf2"),
    );
    emit_identity(
        "dk.preferred2_is_plain2",
        &base_sized(&mut factory, 2, TypeMetatype::Int),
        &named(&factory, "dk_plain2"),
    );
    emit_identity(
        "dk.void_is_decoded",
        &factory.get_type_void_result(),
        &named(&factory, "void"),
    );

    // Wave E2: a size-1 signed enum with no plain INT competitor wins
    // type_nochar (type.cc:3220-3222 runs before the isEnumType break).
    decode_core_types(
        &mut factory,
        coretypes_doc(vec![elem(
            "type",
            &[
                ("metatype", "enum_int"),
                ("name", "dk_enum_only"),
                ("size", "1"),
                ("id", "0x5500000000000011"),
            ],
        )]),
    )
    .expect("decode wave E2");
    emit_identity(
        "dk2.nochar_is_enum",
        &nochar(&mut factory),
        &named(&factory, "dk_enum_only"),
    );
    let dk2_preferred = base(&mut factory, TypeMetatype::Int);
    emit_identity(
        "dk2.preferred_not_enum",
        &dk2_preferred,
        &named(&factory, "dk_enum_only"),
    );
    emit_type("dk2.preferred", &dk2_preferred);

    // Wave E3: the shared-id insert conflict (type.cc:3393-3403) with partial
    // state — the first child survives, the cache pass never runs.
    match decode_core_types(
        &mut factory,
        coretypes_doc(vec![
            elem(
                "type",
                &[
                    ("name", "dk3_a"),
                    ("size", "1"),
                    ("metatype", "int"),
                    ("id", "0x5500000000000021"),
                ],
            ),
            elem(
                "type",
                &[
                    ("name", "dk3_b"),
                    ("size", "1"),
                    ("metatype", "int"),
                    ("id", "0x5500000000000021"),
                ],
            ),
        ]),
    ) {
        Ok(()) => println!("dk3.shared_threw=0"),
        Err(message) => {
            println!("dk3.shared_threw=1");
            let first_line = message.split('\n').next().unwrap_or("");
            println!("dk3.shared_first_line={first_line}");
        }
    }
    println!(
        "dk3.partial_a_present={}",
        if factory.find_by_name("dk3_a").is_some() { 1 } else { 0 }
    );
    println!(
        "dk3.partial_b_absent={}",
        if factory.find_by_name("dk3_b").is_none() { 1 } else { 0 }
    );
    emit_identity(
        "dk3.preferred_not_a",
        &base(&mut factory, TypeMetatype::Int),
        &named(&factory, "dk3_a"),
    );

    // Wave E4: a named candidate without an id (type.cc:3419).
    match decode_core_types(
        &mut factory,
        coretypes_doc(vec![elem("type", &[("metatype", "void")])]),
    ) {
        Ok(()) => println!("dk4.noid_threw=0"),
        Err(message) => {
            println!("dk4.noid_threw=1");
            println!("dk4.noid_msg={message}");
        }
    }
    println!(
        "dk4.void_absent={}",
        if factory.find_by_name("void").is_none() { 1 } else { 0 }
    );

    // Wave F: the large-base array conversion (type.cc:3652-3657).
    factory.clear();
    factory
        .set_core_type_result("u1", 1, TypeMetatype::Unknown, false)
        .expect("core registration");
    factory.cache_core_types();
    let big = base_sized(&mut factory, 20, TypeMetatype::Int);
    emit_type("big.arr20", &big);
    emit_identity(
        "big.repeat",
        &big,
        &base_sized(&mut factory, 20, TypeMetatype::Int),
    );
    let (element_name, element_core) = match big.as_ref() {
        Datatype::Array(a) => (a.array_of.get_name().to_string(), a.array_of.is_coretype()),
        _ => panic!("expected an array"),
    };
    println!("big.element_name={element_name}");
    println!("big.element_core={}", if element_core { 1 } else { 0 });
    let big_float = base_sized(&mut factory, 12, TypeMetatype::Float);
    emit_type("big.float12", &big_float);
}
