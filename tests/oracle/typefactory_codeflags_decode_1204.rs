// TYPEFACTORY-CODEFLAGS-DECODE-0001: Rust comparand for the locked Ghidra
// 12.0.4 decodeTypeWithCodeFlags / decodeCode oracle fixture. Record order
// and values mirror the C++ fixture byte-for-byte; Arc pointer identity is
// the Rust observation of the factory-owned canonical Datatype pointer
// identity Ghidra compares with ==.
//
// The factory mirrors the production BfdArchitecture state by decoding the
// same <size_alignment_map> the compiler spec installs (the C++ side
// inherits it from architecture.init).

use std::sync::{Arc, RwLock};

use rudra::marshal::{Decoder, Element, IdRegistry, TreeDecoder};
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::TypeFactory;

fn metatype_number(metatype: TypeMetatype) -> i32 {
    match metatype {
        // Locked oracle type.hh:79-99 numbering.
        TypeMetatype::Void => 17,
        TypeMetatype::Unknown => 15,
        TypeMetatype::Int => 14,
        TypeMetatype::Uint => 13,
        TypeMetatype::Bool => 12,
        TypeMetatype::Code => 11,
        TypeMetatype::Float => 10,
        TypeMetatype::Pointer => 9,
        TypeMetatype::Array => 7,
        other => panic!("fixture received unsupported metatype: {other:?}"),
    }
}

/// Build an XML element tree mirroring the C++ fixture's decode strings.
fn elem_new(name: &str, attrs: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut el = Element::new();
    el.set_name(name);
    for (k, v) in attrs {
        el.add_attribute(k, v);
    }
    Arc::new(RwLock::new(el))
}

fn add_child(parent: &Arc<RwLock<Element>>, child: Arc<RwLock<Element>>) {
    parent.write().unwrap().add_child(child);
}

fn elem_owned(name: &str, attrs: Vec<(String, String)>) -> Arc<RwLock<Element>> {
    let mut el = Element::new();
    el.set_name(name);
    for (k, v) in attrs {
        el.add_attribute(&k, &v);
    }
    Arc::new(RwLock::new(el))
}

/// Wrap element trees into a <root> document and hand back a positioned
/// decoder plus the opened root id.
fn root_decoder(children: Vec<Arc<RwLock<Element>>>) -> (TreeDecoder, u32) {
    let root = elem_new("root", &[]);
    for child in children {
        add_child(&root, child);
    }
    let mut decoder = TreeDecoder::new(root, Arc::new(RwLock::new(IdRegistry)));
    let root_id = decoder.open_element();
    (decoder, root_id)
}

/// Wave-1 probe: decodeTypeWithCodeFlags + the cursor partial state.
fn run_code_flags_case(
    factory: &mut TypeFactory,
    key: &str,
    inner: Vec<Arc<RwLock<Element>>>,
    is_constructor: bool,
    is_destructor: bool,
) {
    let void_elem = elem_new("void", &[]);
    let (mut decoder, root_id) = root_decoder({
        let mut all = inner;
        all.push(void_elem);
        all
    });
    let outcome = factory.decode_type_with_code_flags(&mut decoder, is_constructor, is_destructor);
    let (thrown, err_text) = match outcome {
        Ok(_) => (false, String::new()),
        Err(text) => (true, text),
    };
    println!("{key}.thrown={}", thrown as i32);
    println!("{key}.text={err_text}");
    println!("{key}.peek={}", (decoder.peek_element() != 0) as i32);
    decoder.close_element_skipping(0);
    // Open-matching by element name: the C++ side uses the throwing
    // openElement(ELEM_VOID); the Rust decoder registry and the type
    // system's ElementId table assign ids independently, so the element
    // name is the shared observable.
    let sub_id = decoder.open_element();
    let resume = sub_id != 0
        && decoder
            .element_name(sub_id)
            .is_some_and(|name| name == "void");
    if resume {
        decoder.close_element(sub_id);
    }
    println!("{key}.resume_void={}", resume as i32);
    decoder.close_element(root_id);
}

/// Wave-2/3 probe: decode one inner <type> through decodeType.
fn decode_type_str(
    factory: &mut TypeFactory,
    inner: Arc<RwLock<Element>>,
) -> Result<Arc<Datatype>, String> {
    let (mut decoder, root_id) = root_decoder(vec![inner]);
    let outcome = factory.decode_type(&mut decoder);
    decoder.close_element(root_id);
    outcome
}

fn emit_thrown(key: &str, outcome: &Result<Arc<Datatype>, String>) {
    println!("{key}.thrown={}", outcome.is_err() as i32);
    if let Err(text) = outcome {
        println!("{key}.text={text}");
    }
}

fn emit_code_type(key: &str, dt: &Arc<Datatype>) {
    println!("{key}.name={}", dt.get_name());
    println!("{key}.id={}", dt.get_id());
    println!("{key}.size={}", dt.get_size());
    println!("{key}.meta={}", metatype_number(dt.get_metatype()));
    println!(
        "{key}.incomplete={}",
        (dt.get_flags() & rudra::type_system::datatype::type_flags::TYPE_INCOMPLETE != 0) as i32
    );
    println!(
        "{key}.varlength={}",
        (dt.get_flags() & rudra::type_system::datatype::type_flags::VARLENGTH != 0) as i32
    );
    let proto_present = match dt.as_ref() {
        Datatype::Code(c) => c.proto.is_some(),
        _ => false,
    };
    println!("{key}.proto={}", proto_present as i32);
}

/// Inner XML trees for the wave-1 cases, mirroring the C++ strings 1:1.
fn code_type(attrs: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    elem_new("type", attrs)
}

fn code_type_with_proto(
    attrs: &[(&str, &str)],
    proto_attrs: &[(&str, &str)],
    with_returnsym: bool,
) -> Arc<RwLock<Element>> {
    let ty = code_type(attrs);
    let proto = elem_new("prototype", proto_attrs);
    if with_returnsym {
        add_child(&proto, elem_new("returnsym", &[]));
    }
    add_child(&ty, proto);
    ty
}

fn ptr_type(attrs: &[(&str, &str)], child: Arc<RwLock<Element>>) -> Arc<RwLock<Element>> {
    let ty = elem_new("type", attrs);
    add_child(&ty, child);
    ty
}

fn main() {
    let mut factory = TypeFactory::new(8);
    // Mirror BfdArchitecture's decodeDataOrganization: the production
    // factory carries the compiler spec's size alignment map (type.cc:3251
    // does not wipe alignMap).
    {
        let map = elem_new("size_alignment_map", &[]);
        for (size, alignment) in [(1, 1), (2, 2), (4, 4), (8, 8), (16, 16)] {
            add_child(
                &map,
                elem_owned(
                    "entry",
                    vec![
                        ("size".to_string(), size.to_string()),
                        ("alignment".to_string(), alignment.to_string()),
                    ],
                ),
            );
        }
        let root = elem_new("data_organization", &[]);
        add_child(&root, map);
        let mut decoder = TreeDecoder::new(root, Arc::new(RwLock::new(IdRegistry)));
        let _ = factory.decode_data_organization(&mut decoder);
    }

    // ---------------- Wave 1: decodeTypeWithCodeFlags ----------------
    run_code_flags_case(
        &mut factory,
        "w1.a_plain",
        vec![ptr_type(
            &[("metatype", "ptr"), ("size", "8")],
            code_type(&[("metatype", "code"), ("size", "1")]),
        )],
        true,
        false,
    );
    run_code_flags_case(
        &mut factory,
        "w1.a_varargs",
        vec![ptr_type(
            &[("metatype", "ptr"), ("size", "8")],
            code_type_with_proto(
                &[("metatype", "code"), ("size", "1")],
                &[("model", "__stdcall"), ("dotdotdot", "true")],
                true,
            ),
        )],
        false,
        true,
    );
    run_code_flags_case(
        &mut factory,
        "w1.a_model",
        vec![ptr_type(
            &[("metatype", "ptr"), ("size", "8")],
            code_type_with_proto(
                &[("metatype", "code"), ("size", "1")],
                &[
                    ("model", "unknown_cc"),
                    ("constructor", "true"),
                    ("destructor", "true"),
                ],
                false,
            ),
        )],
        true,
        true,
    );
    run_code_flags_case(
        &mut factory,
        "w1.a_thiscall",
        vec![ptr_type(
            &[("metatype", "ptr"), ("size", "8"), ("wordsize", "1")],
            code_type_with_proto(
                &[("metatype", "code"), ("size", "1")],
                &[("model", "__thiscall")],
                true,
            ),
        )],
        false,
        false,
    );
    run_code_flags_case(
        &mut factory,
        "w1.b_code",
        vec![code_type(&[("metatype", "code"), ("size", "1")])],
        true,
        false,
    );
    run_code_flags_case(
        &mut factory,
        "w1.b_unspec",
        vec![code_type(&[("size", "4")])],
        true,
        true,
    );
    run_code_flags_case(
        &mut factory,
        "w1.c_nosize_named",
        vec![code_type(&[("metatype", "ptr"), ("name", "vp")])],
        true,
        false,
    );
    run_code_flags_case(
        &mut factory,
        "w1.c_nosize_anon",
        vec![code_type(&[("metatype", "ptr")])],
        false,
        true,
    );

    // ---------------- Wave 2: decodeCode via decodeType ----------------
    let cf_one = decode_type_str(
        &mut factory,
        code_type(&[("metatype", "code"), ("name", "cf_one"), ("size", "1")]),
    )
    .expect("cf_one decode");
    println!("w2.d_named.thrown=0");
    emit_code_type("w2.d_named", &cf_one);

    let cf_one_again = decode_type_str(
        &mut factory,
        code_type(&[("metatype", "code"), ("name", "cf_one"), ("size", "1")]),
    )
    .expect("cf_one re-decode");
    println!(
        "w2.d_dedup.identity={}",
        Arc::ptr_eq(&cf_one, &cf_one_again) as i32
    );
    emit_code_type("w2.d_dedup", &cf_one_again);

    let redefine = decode_type_str(
        &mut factory,
        code_type(&[("metatype", "code"), ("name", "cf_one"), ("size", "2")]),
    );
    emit_thrown("w2.d_redefine", &redefine);
    let survivor = factory
        .find_by_name("cf_one")
        .expect("cf_one survivor after redefinition");
    emit_code_type("w2.d_redefine_survivor", &survivor);

    let clash_int = decode_type_str(
        &mut factory,
        code_type(&[("metatype", "int"), ("name", "clash_t"), ("size", "4")]),
    )
    .expect("clash_t int decode");
    println!("w2.d_clash_int.thrown=0");
    println!("w2.d_clash_int.meta={}", metatype_number(clash_int.get_metatype()));
    let clash_code = decode_type_str(
        &mut factory,
        code_type(&[("metatype", "code"), ("name", "clash_t"), ("size", "1")]),
    );
    emit_thrown("w2.d_clash", &clash_code);
    let clash_survivor = factory
        .find_by_name("clash_t")
        .expect("clash_t survivor after redefine attempt");
    println!(
        "w2.d_clash_survivor.meta={}",
        metatype_number(clash_survivor.get_metatype())
    );
    println!("w2.d_clash_survivor.size={}", clash_survivor.get_size());

    // d_ctorflags: TypeFactory::decodeCode is private in the oracle
    // (type.hh:791); the constructor/destructor chain has no reachable
    // public success observation in 12.0.4 (see w1 flag-indifference
    // records). Nothing is emitted here, mirroring the C++ fixture.

    let cf_v = decode_type_str(
        &mut factory,
        code_type(&[
            ("metatype", "code"),
            ("name", "cf_v"),
            ("size", "1"),
            ("varlength", "true"),
        ]),
    )
    .expect("cf_v decode");
    println!("w2.d_varlength.thrown=0");
    emit_code_type("w2.d_varlength", &cf_v);
    let cf_v_again = decode_type_str(
        &mut factory,
        code_type(&[
            ("metatype", "code"),
            ("name", "cf_v"),
            ("size", "1"),
            ("varlength", "true"),
        ]),
    )
    .expect("cf_v re-decode");
    println!(
        "w2.d_varlength_dedup.identity={}",
        Arc::ptr_eq(&cf_v, &cf_v_again) as i32
    );

    let anon1 = decode_type_str(&mut factory, code_type(&[("metatype", "code"), ("size", "1")]))
        .expect("anonymous code decode");
    println!("w2.d_unnamed.thrown=0");
    emit_code_type("w2.d_unnamed", &anon1);
    let anon2 = decode_type_str(&mut factory, code_type(&[("metatype", "code"), ("size", "1")]))
        .expect("anonymous code re-decode");
    println!(
        "w2.d_unnamed_dedup.identity={}",
        Arc::ptr_eq(&anon1, &anon2) as i32
    );

    // ---------------- Wave 3: pointer->code chain via decodeType ----------------
    let chain_code = decode_type_str(
        &mut factory,
        code_type(&[("metatype", "code"), ("name", "cf_chain"), ("size", "1")]),
    )
    .expect("cf_chain decode");
    println!("w3.chain.thrown=0");

    let plain_ptr = decode_type_str(
        &mut factory,
        ptr_type(
            &[("metatype", "ptr"), ("size", "8")],
            code_type(&[("metatype", "code"), ("name", "cf_chain"), ("size", "1")]),
        ),
    )
    .expect("pointer->code decode");
    println!("w3.ptr.thrown=0");
    println!("w3.ptr.meta={}", metatype_number(plain_ptr.get_metatype()));
    println!("w3.ptr.size={}", plain_ptr.get_size());
    let (wordsize, ptrto, ptr_meta) = match plain_ptr.as_ref() {
        Datatype::Pointer(p) => (p.wordsize, p.ptr_to.clone(), plain_ptr.get_metatype()),
        _ => panic!("w3.ptr is not a pointer"),
    };
    let _ = ptr_meta;
    println!("w3.ptr.wordsize={wordsize}");
    println!(
        "w3.ptr.ptrto_identity={}",
        Arc::ptr_eq(&ptrto, &chain_code) as i32
    );

    let wide_ptr = decode_type_str(
        &mut factory,
        ptr_type(
            &[("metatype", "ptr"), ("size", "8"), ("wordsize", "4")],
            code_type(&[("metatype", "code"), ("name", "cf_chain"), ("size", "1")]),
        ),
    )
    .expect("wide pointer->code decode");
    println!("w3.ptr_ws.thrown=0");
    let ws = match wide_ptr.as_ref() {
        Datatype::Pointer(p) => p.wordsize,
        _ => panic!("w3.ptr_ws is not a pointer"),
    };
    println!("w3.ptr_ws.wordsize={ws}");
}
