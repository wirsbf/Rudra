// CPOOL-TYPED-RECORD-0001: Rust comparand for the locked Ghidra 12.0.4
// CPoolRecord/ConstantPoolInternal fixture. The canonical `Arc<Datatype>`
// identity observations correspond directly to Ghidra Datatype pointer
// identity; packed bytes are emitted without normalization.

use std::sync::{Arc, RwLock};

use rudra::cpool::{cpool_tag, CPoolRecord, ConstantPool, ConstantPoolInternal};
use rudra::marshal::{
    AttributeId, ElementId, Encoder, IdRegistry, PackedEncode, TreeDecoder, TreeEncoder,
};
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::TypeFactory;

fn attrib(name: &str, id: u32) -> AttributeId {
    AttributeId::new(name, id)
}

fn elem(name: &str, id: u32) -> ElementId {
    ElementId::new(name, id)
}

fn open_pool(encoder: &mut dyn Encoder) {
    encoder.open_element(&elem("constantpool", 109));
}

fn close_pool(encoder: &mut dyn Encoder) {
    encoder.close_element(&elem("constantpool", 109));
}

fn encode_ref(encoder: &mut dyn Encoder, a: u64, b: u64) {
    let ref_elem = elem("ref", 111);
    encoder.open_element(&ref_elem);
    encoder.write_unsigned_integer(&attrib("a", 80), a);
    encoder.write_unsigned_integer(&attrib("b", 81), b);
    encoder.close_element(&ref_elem);
}

fn encode_typeref(encoder: &mut dyn Encoder, name: &str) {
    let type_elem = elem("typeref", 63);
    encoder.open_element(&type_elem);
    encoder.write_string(&attrib("name", 14), name);
    encoder.close_element(&type_elem);
}

fn encode_token(encoder: &mut dyn Encoder, token: &str) {
    let token_elem = elem("token", 112);
    encoder.open_element(&token_elem);
    encoder.write_string(&attrib("XMLcontent", 1), token);
    encoder.close_element(&token_elem);
}

fn encode_record(
    encoder: &mut dyn Encoder,
    refs: (u64, u64),
    tag: &str,
    value: Option<u64>,
    token: Option<&str>,
    data: Option<&[u8]>,
    type_name: Option<&str>,
) {
    encode_ref(encoder, refs.0, refs.1);
    let record_elem = elem("cpoolrec", 110);
    encoder.open_element(&record_elem);
    encoder.write_string(&attrib("tag", 83), tag);
    if let Some(value) = value {
        let value_elem = elem("value", 9);
        encoder.open_element(&value_elem);
        encoder.write_unsigned_integer(&attrib("XMLcontent", 1), value);
        encoder.close_element(&value_elem);
    }
    if let Some(data) = data {
        let data_elem = elem("data", 1);
        encoder.open_element(&data_elem);
        encoder.write_signed_integer(&attrib("length", 82), data.len() as i64);
        let content = data
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
            + " ";
        encoder.write_string(&attrib("XMLcontent", 1), &content);
        encoder.close_element(&data_elem);
    } else if let Some(token) = token {
        encode_token(encoder, token);
    }
    if let Some(type_name) = type_name {
        encode_typeref(encoder, type_name);
    }
    encoder.close_element(&record_elem);
}

fn decode_tree(
    pool: &mut ConstantPoolInternal,
    encoder: TreeEncoder,
    registry: Arc<RwLock<IdRegistry>>,
    factory: &mut TypeFactory,
) -> Result<(), String> {
    let document = encoder.into_document();
    let root = document
        .get_root()
        .ok_or_else(|| "fixture tree has no root".to_string())?
        .clone();
    let mut decoder = TreeDecoder::new(root, registry);
    pool.decode(&mut decoder, factory)
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn record_bytes(record: &CPoolRecord) -> String {
    record
        .get_byte_data()
        .map(bytes_hex)
        .unwrap_or_else(|| "-".to_string())
}

fn emit_record(
    key: &str,
    record: &CPoolRecord,
    int_type: &Arc<Datatype>,
    bool_type: &Arc<Datatype>,
) {
    let type_name = record
        .get_type()
        .map(|datatype| datatype.get_name())
        .unwrap_or("<null>");
    let is_i4 = record
        .get_type()
        .is_some_and(|datatype| Arc::ptr_eq(datatype, int_type));
    let is_bool = record
        .get_type()
        .is_some_and(|datatype| Arc::ptr_eq(datatype, bool_type));
    println!(
        "record|key={key}|tag={}|token={}|value={}|bytes={}|type={type_name}|is_i4={}|is_bool={}|ctor={}|dtor={}",
        record.get_tag(),
        record.get_token(),
        record.get_value(),
        record_bytes(record),
        if is_i4 { 1 } else { 0 },
        if is_bool { 1 } else { 0 },
        if record.is_constructor() { 1 } else { 0 },
        if record.is_destructor() { 1 } else { 0 },
    );
}

fn main() -> Result<(), String> {
    let mut factory = TypeFactory::new(8);
    let int_type = factory.get_base_named(4, TypeMetatype::Int, "int4")?;
    let bool_type = factory
        .find_by_name("bool")
        .ok_or_else(|| "production TypeFactory has no canonical bool1".to_string())?;
    if int_type.get_size() != 4 || int_type.get_metatype() != TypeMetatype::Int {
        return Err("production TypeFactory canonical int has wrong shape".to_string());
    }
    if bool_type.get_size() != 1 || bool_type.get_metatype() != TypeMetatype::Bool {
        return Err("production TypeFactory canonical bool has wrong shape".to_string());
    }

    println!("schema=1");
    println!("oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut encoder = TreeEncoder::new(registry.clone());
    open_pool(&mut encoder);
    encode_record(
        &mut encoder,
        (9, 4),
        "primitive",
        Some(287_454_020),
        Some("primitive-token"),
        None,
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (2, 8),
        "string",
        None,
        None,
        Some(&(0u8..17).collect::<Vec<_>>()),
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (7, 1),
        "classref",
        None,
        Some("class-token"),
        None,
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (4, 0),
        "method",
        None,
        Some("method-token"),
        None,
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (6, 2),
        "field",
        None,
        Some("field-token"),
        None,
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (3, 9),
        "arraylength",
        None,
        Some("length-token"),
        None,
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (8, 5),
        "instanceof",
        None,
        Some("instance-token"),
        None,
        Some("bool"),
    );
    encode_record(
        &mut encoder,
        (5, 7),
        "checkcast",
        None,
        Some("cast-token"),
        None,
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (10, 0),
        "unknown-tag",
        Some(7),
        Some("unknown-token"),
        None,
        Some("int4"),
    );
    close_pool(&mut encoder);
    let mut primary = ConstantPoolInternal::new();
    decode_tree(&mut primary, encoder, registry, &mut factory)?;

    for refs in [
        (2, 8),
        (3, 9),
        (4, 0),
        (5, 7),
        (6, 2),
        (7, 1),
        (8, 5),
        (9, 4),
        (10, 0),
    ] {
        let key = format!("{},{}", refs.0, refs.1);
        let record = primary
            .get_record(&[refs.0, refs.1])
            .ok_or_else(|| format!("missing primary record {key}"))?;
        emit_record(&key, record, &int_type, &bool_type);
    }

    let method_one = primary.get_record(&[4]).map(|record| record as *const _);
    let method_two = primary.get_record(&[4, 0]).map(|record| record as *const _);
    let method_three = primary
        .get_record(&[4, 0, 77])
        .map(|record| record as *const _);
    println!(
        "lookup|one_equals_two={}|third_ignored={}|reverse_miss={}|plain_miss={}",
        if method_one == method_two { 1 } else { 0 },
        if method_three == method_two { 1 } else { 0 },
        if primary.get_record(&[0, 4]).is_none() {
            1
        } else {
            0
        },
        if primary.get_record(&[100, 1]).is_none() {
            1
        } else {
            0
        },
    );
    let mut packed = PackedEncode::new();
    primary.encode(&mut packed)?;
    println!("packed={}", bytes_hex(&packed.into_bytes()));

    let mut replacement = ConstantPoolInternal::new();
    replacement.put_record(
        &[42, 7],
        cpool_tag::POINTER_FIELD,
        "original",
        int_type.clone(),
    )?;
    let duplicate_error = replacement
        .put_record(
            &[42, 7],
            cpool_tag::CHECK_CAST,
            "replacement",
            bool_type.clone(),
        )
        .expect_err("duplicate reference must fail");
    let original = replacement
        .get_record(&[42, 7])
        .ok_or_else(|| "duplicate removed original".to_string())?;
    println!(
        "duplicate|error={duplicate_error}|token={}|type_is_i4={}",
        original.get_token(),
        if original
            .get_type()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &int_type))
        {
            1
        } else {
            0
        }
    );
    replacement.clear();
    replacement.put_record(
        &[42, 7],
        cpool_tag::CHECK_CAST,
        "replacement",
        bool_type.clone(),
    )?;
    let replaced = replacement
        .get_record(&[42, 7])
        .ok_or_else(|| "replacement is missing".to_string())?;
    println!(
        "replace_after_clear|empty=0|token={}|type_is_bool={}",
        replaced.get_token(),
        if replaced
            .get_type()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &bool_type))
        {
            1
        } else {
            0
        }
    );

    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut encoder = TreeEncoder::new(registry.clone());
    open_pool(&mut encoder);
    encode_record(
        &mut encoder,
        (1, 1),
        "field",
        None,
        Some("good"),
        None,
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (13, 6),
        "string",
        None,
        Some("not-data"),
        None,
        Some("int4"),
    );
    encode_record(
        &mut encoder,
        (20, 1),
        "field",
        None,
        Some("after"),
        None,
        Some("int4"),
    );
    close_pool(&mut encoder);
    let mut partial = ConstantPoolInternal::new();
    let partial_error = decode_tree(&mut partial, encoder, registry, &mut factory)
        .expect_err("missing string data must fail");
    let bad = partial
        .get_record(&[13, 6])
        .ok_or_else(|| "bad partial record was not retained".to_string())?;
    println!(
        "partial|error={partial_error}|good={}|bad=1|bad_tag={}|bad_token={}|bad_type_null={}|after_miss={}",
        if partial.get_record(&[1, 1]).is_some() { 1 } else { 0 },
        bad.get_tag(),
        bad.get_token(),
        if bad.get_type().is_none() { 1 } else { 0 },
        if partial.get_record(&[20, 1]).is_none() { 1 } else { 0 },
    );

    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut encoder = TreeEncoder::new(registry.clone());
    open_pool(&mut encoder);
    encode_record(
        &mut encoder,
        (14, 6),
        "field",
        None,
        Some("typed-before-error"),
        None,
        Some("missing_cpool_type"),
    );
    close_pool(&mut encoder);
    let mut type_error_pool = ConstantPoolInternal::new();
    let type_error = decode_tree(&mut type_error_pool, encoder, registry, &mut factory)
        .expect_err("unknown type must fail");
    let type_partial = type_error_pool
        .get_record(&[14, 6])
        .ok_or_else(|| "type-error partial record was not retained".to_string())?;
    println!(
        "type_error|error={type_error}|present=1|tag={}|token={}|type_null={}",
        type_partial.get_tag(),
        type_partial.get_token(),
        if type_partial.get_type().is_none() {
            1
        } else {
            0
        },
    );

    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut encoder = TreeEncoder::new(registry.clone());
    open_pool(&mut encoder);
    encode_ref(&mut encoder, 30, 1);
    let record_elem = elem("cpoolrec", 110);
    encoder.open_element(&record_elem);
    encoder.write_string(&attrib("tag", 83), "method");
    encoder.write_bool(&attrib("constructor", 4), true);
    encoder.write_bool(&attrib("destructor", 5), true);
    encode_token(&mut encoder, "flagged");
    let type_elem = elem("type", 60);
    encoder.open_element(&type_elem);
    encoder.write_string(&attrib("metatype", 12), "ptr");
    encoder.write_signed_integer(&attrib("size", 19), 8);
    encoder.open_element(&type_elem);
    encoder.write_string(&attrib("metatype", 12), "code");
    encoder.write_signed_integer(&attrib("size", 19), 1);
    let prototype_elem = elem("prototype", 169);
    encoder.open_element(&prototype_elem);
    encoder.close_element(&prototype_elem);
    encoder.close_element(&type_elem);
    encoder.close_element(&type_elem);
    encoder.close_element(&record_elem);
    close_pool(&mut encoder);
    let mut flags_pool = ConstantPoolInternal::new();
    let flags_result = decode_tree(&mut flags_pool, encoder, registry, &mut factory);
    let (flags_status, flags_error) = match flags_result {
        Ok(()) => ("OK", String::new()),
        Err(error) => ("ERROR", error),
    };
    let flags_record = flags_pool
        .get_record(&[30, 1])
        .ok_or_else(|| "flags record is missing".to_string())?;
    let prototype = flags_record
        .get_type()
        .and_then(|datatype| match datatype.as_ref() {
            Datatype::Pointer(pointer) => match pointer.ptr_to.as_ref() {
                Datatype::Code(code) => code.proto.as_ref(),
                _ => None,
            },
            _ => None,
        });
    println!(
        "codeflags|status={flags_status}|error={flags_error}|record_ctor={}|record_dtor={}|type_null={}|prototype={}|proto_ctor={}|proto_dtor={}",
        if flags_record.is_constructor() { 1 } else { 0 },
        if flags_record.is_destructor() { 1 } else { 0 },
        if flags_record.get_type().is_none() { 1 } else { 0 },
        if prototype.is_some() { 1 } else { 0 },
        if prototype.is_some_and(|proto| proto.is_constructor_flag()) {
            1
        } else {
            0
        },
        if prototype.is_some_and(|proto| proto.is_destructor()) {
            1
        } else {
            0
        },
    );
    Ok(())
}
