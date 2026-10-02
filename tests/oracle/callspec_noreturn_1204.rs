//! CALLSPEC-NORETURN-1204: Rust comparand for the locked Ghidra 12.0.4
//! oracle `callspec_noreturn_1204.cc` (CALLSPEC-NORETURN-WIRE-0001 slice a).
//!
//! Byte-mirrors the C++ projection of the FuncProto/FuncCallSpecs no-return
//! flag lifecycle: constructor defaults (flags==0), explicit
//! set/clear/idempotence through both the FuncProto and the FuncCallSpecs
//! inherited surface, copyFlowEffects' is_inline|no_return one-way subset
//! overwrite (flow.cc:664 queryCall channel), full copy + callspec clone
//! propagation with op rebind and active-input reset, the absence of any
//! void->noreturn inference, and the decode/encode attribute channel.
//!
//! The C++ side drives the real Ghidra classes against a fixture
//! architecture (spaces + TypeFactory + decoded "fixture" ProtoModel); this
//! side mirrors each observation through the crate's public fspec API plus
//! the marshal TreeDecoder/TreeEncoder, so both stdouts are byte-identical.

use std::sync::{Arc, RwLock};

use rudra::address::{Address, SeqNum};
use rudra::fspec::{FuncCallSpecs, FuncProto};
use rudra::marshal::{xml_tree, AttributeId, Decoder, ElementId, IdRegistry, TreeDecoder, TreeEncoder};
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

// RUDRA-GLUE: fixture-local canonical void type, the same construction the
// funcproto_lock_1204 comparand uses (C++ reads arch.types->getTypeVoid()).
fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

// A bare CALLIND-opcoded op: FuncCallSpecs::new_for_op only reads input(0)
// for CPUI_CALL, so the spec's entry stays None exactly like the C++
// constructor's non-CALL branch (fspec.cc:4942).
fn make_callind_op(ord: u32) -> PcodeOpRef {
    PcodeOpRef(Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0), ord),
        OpCode::CPUI_CALLIND,
    ))))
}

// Mirror of the C++ decode_proto staging: setInternal before decode
// (fspec.cc:4679-4680). The closures hand-roll the minimal <returnsym>
// child reader the flat FuncProto decode needs (C++ resolves storage
// through ProtoStoreInternal inside FuncProto::decode).
fn decode_proto(xml: &str) -> FuncProto {
    let mut proto = FuncProto::new(String::new(), void_type());
    proto.set_internal(None, void_type());
    let doc = xml_tree(xml.as_bytes()).expect("fixture xml parses");
    let ids = Arc::new(RwLock::new(IdRegistry::new()));
    let mut dec = TreeDecoder::from_document(&doc, ids);
    let model_resolver = |name: &str| name == "fixture";
    let decode_output_storage =
        |dec: &mut dyn Decoder| -> (Address, Arc<Datatype>, bool) {
            // <returnsym typelock=".."><addr ../><void/></returnsym>
            let returnsym = dec.open_element();
            let mut output_lock = false;
            loop {
                let aid = dec.next_attribute_id();
                if aid == 0 {
                    break;
                }
                match dec.attribute_name(aid).as_deref() {
                    Some("typelock") => output_lock = dec.read_bool(),
                    _ => {
                        let _ = dec.read_string();
                    }
                }
            }
            let mut addr = Address::new(0);
            if dec.peek_element() != 0 {
                let addr_id = dec.open_element();
                loop {
                    let aid = dec.next_attribute_id();
                    if aid == 0 {
                        break;
                    }
                    match dec.attribute_name(aid).as_deref() {
                        Some("offset") => {
                            addr = Address::new(dec.read_string().parse::<u64>().unwrap_or(0));
                        }
                        _ => {
                            let _ = dec.read_string();
                        }
                    }
                }
                dec.close_element(addr_id);
            }
            let mut ty = void_type();
            if dec.peek_element() != 0 {
                let type_id = dec.open_element();
                // C++ TypeFactory::decodeTypeNoRef (type.cc:4436): the
                // ELEM_VOID child (<void/>) resolves to the void type.
                let type_name = dec
                    .element_name(type_id)
                    .unwrap_or_default()
                    .to_string();
                loop {
                    let aid = dec.next_attribute_id();
                    if aid == 0 {
                        break;
                    }
                    let _ = dec.read_string();
                }
                if type_name != "void" {
                    panic!("fixture only decodes the void type, got {type_name}");
                }
                dec.close_element(type_id);
                ty = void_type();
            }
            dec.close_element(returnsym);
            (addr, ty, output_lock)
        };
    proto
        .decode(&mut dec, &model_resolver, &decode_output_storage)
        .expect("FuncProto::decode succeeds");
    proto
}

// Mirror of FuncProto::encode through the TreeEncoder, checking the
// noreturn attribute presence the way the C++ side greps its XML stream.
fn encode_has_noreturn(proto: &FuncProto) -> bool {
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut enc = TreeEncoder::new(registry);
    let prototype_elem = ElementId::new("prototype", 169);
    let model_attrib = AttributeId::new("model", 13);
    let extrapop_attrib = AttributeId::new("extrapop", 6);
    let dotdotdot_attrib = AttributeId::new("dotdotdot", 115);
    let modellock_attrib = AttributeId::new("modellock", 122);
    let inline_attrib = AttributeId::new("inline", 118);
    let noreturn_attrib = AttributeId::new("noreturn", 123);
    let constructor_attrib = AttributeId::new("constructor", 4);
    let destructor_attrib = AttributeId::new("destructor", 5);
    let returnsym_elem = ElementId::new("returnsym", 172);
    let typelock_attrib = AttributeId::new("typelock", 23);
    let unaffected_elem = ElementId::new("unaffected", 173);
    let killedbycall_elem = ElementId::new("killedbycall", 162);
    let returnaddress_elem = ElementId::new("returnaddress", 5);
    let likelytrash_elem = ElementId::new("likelytrash", 163);
    let addr_elem = ElementId::new("addr", 11);
    let space_attrib = AttributeId::new("space", 20);
    let offset_attrib = AttributeId::new("offset", 16);
    let size_attrib = AttributeId::new("size", 19);
    proto.encode(
        &mut enc,
        &prototype_elem,
        &model_attrib,
        &extrapop_attrib,
        &dotdotdot_attrib,
        &modellock_attrib,
        &inline_attrib,
        &noreturn_attrib,
        &constructor_attrib,
        &destructor_attrib,
        &returnsym_elem,
        &typelock_attrib,
        &unaffected_elem,
        &killedbycall_elem,
        &returnaddress_elem,
        &likelytrash_elem,
        &addr_elem,
        &space_attrib,
        &offset_attrib,
        &size_attrib,
        rudra::space::AddressSpace::Ram,
        0,
        1,
        &[],
        &[],
        &|_, _, _| rudra::fspec::EffectType::UnknownEffect,
        &|_| {},
    );
    let doc = enc.into_document();
    let root = doc.root.as_ref().unwrap();
    let root = root.read().unwrap();
    root.attr_names.iter().any(|name| name == "noreturn")
}

fn main() {
    println!(
        "schema=1|fixture=CALLSPEC-NORETURN-1204|\
         oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case=default_ctor ------------------------------------------
    {
        let mut proto = FuncProto::new(String::new(), void_type());
        proto.set_internal(None, void_type());
        let op = make_callind_op(1);
        let fc = FuncCallSpecs::new_for_op(&op, FuncProto::new(String::new(), void_type()));
        println!(
            "case=default_ctor|proto_noret={}|proto_inline={}|callspec_noret={}|callspec_inline={}|callspec_entry_invalid={}",
            u8::from(proto.is_no_return()),
            u8::from(proto.is_inline()),
            u8::from(fc.is_no_return()),
            u8::from(fc.is_inline()),
            u8::from(fc.entry_addr.is_none()),
        );
    }

    // ---- case=explicit_set_idempotent ------------------------------
    {
        let mut proto = FuncProto::new(String::new(), void_type());
        proto.set_internal(None, void_type());
        proto.set_no_return(true);
        let a = u8::from(proto.is_no_return());
        proto.set_no_return(true);
        let b = u8::from(proto.is_no_return());
        proto.set_no_return(false);
        let c = u8::from(proto.is_no_return());
        proto.set_no_return(false);
        let d = u8::from(proto.is_no_return());
        // Through the FuncCallSpecs inherited surface (flow.cc:747 uses
        // fc->setNoReturn(true) on a callspec).
        let op = make_callind_op(2);
        let mut fc = FuncCallSpecs::new_for_op(&op, FuncProto::new(String::new(), void_type()));
        fc.set_no_return(true);
        let e = u8::from(fc.is_no_return());
        fc.set_no_return(false);
        let f = u8::from(fc.is_no_return());
        println!(
            "case=explicit_set_idempotent|set_true={a}|set_true_again={b}|set_false={c}|set_false_again={d}|callspec_set_true={e}|callspec_clear={f}",
        );
    }

    // ---- case=copy_flow_effects -------------------------------------
    {
        // callee{inline=T,noret=T} -> fc{F,F} becomes {T,T}
        let mut callee1 = FuncProto::new(String::new(), void_type());
        callee1.set_internal(None, void_type());
        callee1.set_inline(true);
        callee1.set_no_return(true);
        let op = make_callind_op(3);
        let mut fc = FuncCallSpecs::new_for_op(&op, FuncProto::new(String::new(), void_type()));
        fc.copy_flow_effects(&callee1);
        let (s1_noret, s1_inline) = (u8::from(fc.is_no_return()), u8::from(fc.is_inline()));

        // callee{F,F} -> fc{previous T,T} clears to {F,F} (one-way overwrite)
        let mut callee2 = FuncProto::new(String::new(), void_type());
        callee2.set_internal(None, void_type());
        fc.copy_flow_effects(&callee2);
        let (s2_noret, s2_inline) = (u8::from(fc.is_no_return()), u8::from(fc.is_inline()));

        // callee{inline=F,noret=T} -> fc {F,T}; modellock (a non-subset flag
        // on the source) must not leak into the callspec.
        let mut callee3 = FuncProto::new(String::new(), void_type());
        callee3.set_internal(None, void_type());
        callee3.set_no_return(true);
        callee3.set_model_lock(true);
        fc.copy_flow_effects(&callee3);
        let (s3_noret, s3_inline) = (u8::from(fc.is_no_return()), u8::from(fc.is_inline()));
        let ml_leak = u8::from(fc.prototype.is_model_locked());
        let ml_src = u8::from(callee3.is_model_locked());
        println!(
            "case=copy_flow_effects|step1_noret={s1_noret}|step1_inline={s1_inline}|step2_noret={s2_noret}|step2_inline={s2_inline}|step3_noret={s3_noret}|step3_inline={s3_inline}|modellock_not_copied={}|src_modellock_stays={ml_src}",
            u8::from(ml_leak == 0),
        );
    }

    // ---- case=full_copy_and_clone -----------------------------------
    {
        let mut a = FuncProto::new(String::new(), void_type());
        a.set_internal(None, void_type());
        a.set_no_return(true);
        a.set_inline(true);
        let mut b = FuncProto::new(String::new(), void_type());
        b.set_internal(None, void_type());
        b.copy_from(&a);
        let copy_noret = u8::from(b.is_no_return());
        let copy_inline = u8::from(b.is_inline());

        let op1 = make_callind_op(4);
        let op2 = make_callind_op(5);
        let mut fc1 = FuncCallSpecs::new_for_op(&op1, FuncProto::new(String::new(), void_type()));
        fc1.set_no_return(true);
        fc1.set_inline(true);
        fc1.init_active_input();
        let clone = fc1.clone_for_op(&op2);
        let clone_noret = u8::from(clone.is_no_return());
        let clone_inline = u8::from(clone.is_inline());
        let clone_rebound = u8::from(
            clone
                .op
                .upgrade()
                .map(|c| Arc::ptr_eq(&c, &op2.0))
                .unwrap_or(false)
                && !Arc::ptr_eq(&op1.0, &op2.0),
        );
        let clone_active_reset =
            u8::from(!clone.is_input_active() && fc1.is_input_active());
        println!(
            "case=full_copy_and_clone|copy_noret={copy_noret}|copy_inline={copy_inline}|clone_noret={clone_noret}|clone_inline={clone_inline}|clone_rebound={clone_rebound}|clone_active_reset={clone_active_reset}",
        );
    }

    // ---- case=void_no_inference -------------------------------------
    {
        // A void-returning prototype never gains noreturn implicitly.
        let mut proto = FuncProto::new(String::new(), void_type());
        proto.set_internal(None, void_type());
        let ctor_void = u8::from(proto.is_no_return());
        let decoded = decode_proto(
            "<prototype model=\"fixture\" extrapop=\"0\">\
             <returnsym typelock=\"true\">\
             <addr space=\"ram\" offset=\"0x0\" size=\"1\"/>\
             <void/>\
             </returnsym></prototype>",
        );
        let decode_void = u8::from(decoded.is_no_return());
        let decode_void_output = u8::from(matches!(
            *decoded.return_type,
            Datatype::Void(_)
        ));
        println!(
            "case=void_no_inference|setinternal_void_noret={ctor_void}|decode_void_noret={decode_void}|decode_output_is_void={decode_void_output}",
        );
    }

    // ---- case=decode_encode_channel ----------------------------------
    {
        let with_true = decode_proto(
            "<prototype model=\"fixture\" extrapop=\"0\" noreturn=\"true\">\
             <returnsym typelock=\"true\">\
             <addr space=\"ram\" offset=\"0x0\" size=\"1\"/>\
             <void/>\
             </returnsym></prototype>",
        );
        let d_true = u8::from(with_true.is_no_return());

        let with_absent = decode_proto(
            "<prototype model=\"fixture\" extrapop=\"0\">\
             <returnsym typelock=\"true\">\
             <addr space=\"ram\" offset=\"0x0\" size=\"1\"/>\
             <void/>\
             </returnsym></prototype>",
        );
        let d_absent = u8::from(with_absent.is_no_return());

        let with_false = decode_proto(
            "<prototype model=\"fixture\" extrapop=\"0\" noreturn=\"false\">\
             <returnsym typelock=\"true\">\
             <addr space=\"ram\" offset=\"0x0\" size=\"1\"/>\
             <void/>\
             </returnsym></prototype>",
        );
        let d_false = u8::from(with_false.is_no_return());

        // encode emits the noreturn attribute only when the bit is set.
        let e_present = u8::from(encode_has_noreturn(&with_true));
        let e_absent = u8::from(encode_has_noreturn(&with_absent));
        println!(
            "case=decode_encode_channel|decode_true={d_true}|decode_absent={d_absent}|decode_false_attr={d_false}|encode_present={e_present}|encode_absent={e_absent}",
        );
    }
}
