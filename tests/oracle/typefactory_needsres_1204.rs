// TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001: Rust comparand for the locked
// Ghidra 12.0.4 needs_resolution setting-matrix oracle. Mirrors
// tests/oracle/typefactory_needsres_1204.cc record-for-record (15 lines,
// "<record>=<0|1>", value = Datatype::needs_resolution()):
//
//   set.*       — TypeFactory::set_fields_sized (explicit newSize twin of
//                 TypeFactory::setFields, type.cc:3479) covering the
//                 TypeStruct::setFields single-field arm (type.cc:1569-1571):
//                 fills / notfills / offset-not-examined / multi-field.
//   grammar.*   — the CParse::newStruct derivation (grammar.cc:2798-2799):
//                 TypeStruct::assign_field_offsets derives the size, then
//                 set_fields applies the arm against the derived size.
//   dec.*       — the XML decode path through TypeFactory::decode_type:
//                 TypeStruct::decodeFields tail (type.cc:1874-1877) via
//                 decode_struct, and TypeArray::decode arraysize==1 arm
//                 (type.cc:1341-1342) via the decode_type_no_ref array
//                 branch.
//   arr.factory — TypeFactory::get_array(1, int): the inline TypeArray
//                 ctor arm (type.hh:937-944) sets the flag, same as the
//                 decode arm.
//   ptr.*       — TypePointer::calcSubmeta inheritance arm (type.cc:1051-
//                 1052) via get_type_pointer: pointer to the single-field
//                 struct inherits the flag; through a second pointer level
//                 and to a plain base type it does not.
//   union.setfields — TypeUnion ctor flag (type.hh:551) survives
//                 set_union_fields (TypeUnion::setFields never touches
//                 flags, type.cc:2002-2009).
//
// The XML strings are byte-identical to the C++ fixture's; the fixture-local
// ingestion (parse_xml -> Element DOM -> TreeDecoder) is the same model as
// cspec_typeorg_state_1204.rs.

use std::sync::{Arc, RwLock};

use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::type_system::datatype::{
    Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct,
};
use rudra::type_system::typefactory::TypeFactory;

type Node = Arc<RwLock<Element>>;

struct ParsedXml {
    root: Node,
    registry: Arc<RwLock<IdRegistry>>,
}

fn int4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "int".to_string(),
        4,
        TypeMetatype::Int,
    )))
}

fn int8() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(),
        8,
        TypeMetatype::Int,
    )))
}

fn field(name: &str, offset: usize, type_ptr: Arc<Datatype>) -> TypeField {
    TypeField {
        name: name.to_string(),
        offset,
        type_ptr,
    }
}

fn flag_of(ct: &Arc<Datatype>) -> u8 {
    if ct.needs_resolution() {
        1
    } else {
        0
    }
}

// Build one struct via the explicit-newSize factory twin and observe its flag.
fn set_path_cell(
    factory: &mut TypeFactory,
    name: &str,
    fields: Vec<TypeField>,
    new_size: usize,
) -> u8 {
    factory.create_struct(name);
    factory
        .set_fields_sized(name, fields, new_size, 4)
        .expect("struct exists");
    let dt = factory.find_by_name(name).expect("struct re-readable");
    flag_of(&dt)
}

// Build one struct the way CParse::newStruct does (grammar.cc:2798-2799):
// assign_field_offsets derives (size, align), then set_fields applies the
// single-field arm against that derived size.
fn grammar_path_cell(factory: &mut TypeFactory, name: &str, mut fields: Vec<TypeField>) -> u8 {
    factory.create_struct(name);
    for f in fields.iter_mut() {
        f.offset = usize::MAX; // Ghidra's offset -1 == "unassigned"
    }
    // grammar.cc:2798-2799 passes the DERIVED (newSize,newAlign) into
    // setFields; the explicit-size twin reproduces that exactly (a naive
    // re-derivation would fire the flag for unrounded field types — see
    // grammar.overfire).
    let (new_size, new_align) =
        TypeStruct::assign_field_offsets(&mut fields).expect("assignable fields");
    factory
        .set_fields_sized(name, fields, new_size, new_align)
        .expect("struct exists");
    let dt = factory.find_by_name(name).expect("struct re-readable");
    flag_of(&dt)
}

// Decode one <type> element (equivalent XML (3 unnamed <type size="1"> carry name="oct1" on the Rust side; names are outside every compared observation) to the C++ fixture) through
// the public TypeFactory::decode_type entry.
fn decode_type_xml(factory: &mut TypeFactory, xml: &str) -> Arc<Datatype> {
    decode_type_xml_result(factory, xml).expect("type decodes")
}

// Fallible twin for the rejection cells: surfaces the Err(String) text the
// C++ side observes as LowlevelError::explain.
fn decode_type_xml_result(factory: &mut TypeFactory, xml: &str) -> Result<Arc<Datatype>, String> {
    let parsed = parse_xml(xml).expect("fixture XML parses");
    let mut decoder = TreeDecoder::new(parsed.root.clone(), parsed.registry.clone());
    factory.decode_type(&mut decoder)
}

// Composite struct-state record (fields/needsres/incomplete) for the decode
// acceptance-tail cells.
fn struct_state(ct: &Arc<Datatype>) -> String {
    let fields = match ct.as_ref() {
        Datatype::Struct(s) => s.fields.len(),
        _ => 0,
    };
    format!(
        "fields:{},needsres:{},incomplete:{}",
        fields,
        flag_of(ct),
        if ct.is_incomplete() { 1 } else { 0 }
    )
}

fn main() {
    let mut factory = TypeFactory::new(8);

    // --- set-path: explicit newSize (TypeFactory::setFields twin) ---
    println!(
        "set.single.fills={}",
        set_path_cell(&mut factory, "fixture_nres_fills", vec![field("x", 0, int8())], 8)
    );
    println!(
        "set.single.notfills={}",
        set_path_cell(&mut factory, "fixture_nres_notfills", vec![field("x", 0, int4())], 8)
    );
    println!(
        "set.single.offset={}",
        set_path_cell(&mut factory, "fixture_nres_offset", vec![field("x", 4, int8())], 8)
    );
    println!(
        "set.multi={}",
        set_path_cell(
            &mut factory,
            "fixture_nres_multi",
            vec![field("lo", 0, int4()), field("hi", 4, int4())],
            8
        )
    );

    // --- grammar-path: derived size (assign_field_offsets + set_fields) ---
    println!(
        "grammar.single={}",
        grammar_path_cell(&mut factory, "fixture_nres_gram1", vec![field("x", usize::MAX, int8())])
    );
    println!(
        "grammar.multi={}",
        grammar_path_cell(
            &mut factory,
            "fixture_nres_gram2",
            vec![field("lo", usize::MAX, int4()), field("hi", usize::MAX, int4())]
        )
    );

    // --- decode-path: decodeFields tail + TypeArray::decode arm ---
    let dec_fills = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_dec_fills\" size=\"8\" metatype=\"struct\">\
         <field name=\"x\" offset=\"0\">\
         <type name=\"long\" size=\"8\" metatype=\"int\"/>\
         </field></type>",
    );
    println!("dec.single.fills={}", flag_of(&dec_fills));
    let dec_notfills = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_dec_notfills\" size=\"12\" metatype=\"struct\">\
         <field name=\"x\" offset=\"0\">\
         <type name=\"int\" size=\"4\" metatype=\"int\"/>\
         </field></type>",
    );
    println!("dec.single.notfills={}", flag_of(&dec_notfills));
    let dec_multi = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_dec_multi\" size=\"8\" metatype=\"struct\">\
         <field name=\"lo\" offset=\"0\">\
         <type name=\"int\" size=\"4\" metatype=\"int\"/>\
         </field>\
         <field name=\"hi\" offset=\"4\">\
         <type name=\"int\" size=\"4\" metatype=\"int\"/>\
         </field></type>",
    );
    println!("dec.multi={}", flag_of(&dec_multi));
    let dec_arr1 = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_dec_arr1\" size=\"4\" metatype=\"array\" arraysize=\"1\">\
         <type name=\"int\" size=\"4\" metatype=\"int\"/>\
         </type>",
    );
    println!("dec.arr.size1={}", flag_of(&dec_arr1));

    // --- factory array ctor: no flag on the non-decode path ---
    let factory_arr1 = factory.get_array(int4(), 1);
    println!("arr.factory={}", flag_of(&factory_arr1));

    // --- pointer inheritance: TypePointer::calcSubmeta arm ---
    let fills_struct = factory
        .find_by_name("fixture_nres_fills")
        .expect("fills struct exists");
    let ptr_inner = factory.get_type_pointer(8, fills_struct, 1);
    println!("ptr.inner={}", flag_of(&ptr_inner));
    let ptr_ptr = factory.get_type_pointer(8, ptr_inner.clone(), 1);
    println!("ptr.ptrptr={}", flag_of(&ptr_ptr));
    let ptr_plain = factory.get_type_pointer(8, int8(), 1);
    println!("ptr.plain={}", flag_of(&ptr_plain));

    // --- grammar over-fire regression cell: an XML-decoded UNROUNDED struct
    // (size 5, alignment 4, alignSize 8) as a single grammar field. Ghidra's
    // assignFieldOffsets newSize is calcAlignSize(8,4)=8 != 5, so the flag
    // must stay CLEAR even though max(offset+getSize)=5 would fire a naive
    // derivation (type.cc:1971-1993 + 1569-1571).
    let pad5 = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_pad5\" size=\"5\" metatype=\"struct\">\
         <field name=\"lo\" offset=\"0\">\
         <type name=\"int\" size=\"4\" metatype=\"int\"/>\
         </field>\
         <field name=\"hi\" offset=\"4\">\
         <type name=\"oct1\" size=\"1\" metatype=\"int\"/>\
         </field></type>",
    );
    println!(
        "grammar.overfire={}",
        grammar_path_cell(
            &mut factory,
            "fixture_nres_over",
            vec![field("p", usize::MAX, pad5.clone())]
        )
    );
    // --- nested single-field propagation: inner flag set by the grammar
    // path; the outer single field of inner (size 4 == newSize 4) flags too.
    grammar_path_cell(
        &mut factory,
        "fixture_nres_nestin",
        vec![field("x", usize::MAX, int4())],
    );
    let nest_inner = factory
        .find_by_name("fixture_nres_nestin")
        .expect("inner struct readable");
    let nest_outer_flag = grammar_path_cell(
        &mut factory,
        "fixture_nres_nestout",
        vec![field("i", usize::MAX, nest_inner.clone())],
    );
    println!(
        "grammar.nested=inner:{},outer:{}",
        flag_of(&nest_inner),
        nest_outer_flag
    );
    // --- pointer ordering: a pointer built while the struct is still an
    // incomplete stub never inherits the flag (calcSubmeta runs at
    // construction only; recalcPointerSubmeta fixes submeta, not flags).
    // After the grammar definition the SAME pointer stays clear, while a
    // differently-sized new pointer inherits the flag.
    factory.create_struct("fixture_nres_pre");
    let pre_stub = factory
        .find_by_name("fixture_nres_pre")
        .expect("pre stub exists");
    let stub_ptr = factory.get_type_pointer(8, pre_stub.clone(), 1);
    let mut pre_fd = vec![field("x", usize::MAX, int8())];
    TypeStruct::assign_field_offsets(&mut pre_fd).expect("assignable fields");
    factory
        .set_fields("fixture_nres_pre", pre_fd)
        .expect("struct exists");
    let pre_done = factory
        .find_by_name("fixture_nres_pre")
        .expect("completed pre readable");
    let cached_ptr = factory.get_type_pointer(8, pre_done.clone(), 1);
    let new_ptr = factory.get_type_pointer(4, pre_done.clone(), 1);
    println!(
        "ptr.ordering=stub:{},struct:{},cached:{},new:{}",
        flag_of(&stub_ptr),
        flag_of(&pre_done),
        flag_of(&cached_ptr),
        flag_of(&new_ptr)
    );

    // --- decode acceptance tail: overlap throw-out + incomplete residue ---
    // Overlapping second field is dropped (type.cc:1849-1860, warning only),
    // leaving a single filling field: flag set, complete.
    let overlap = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_dec_overlap\" size=\"4\" metatype=\"struct\">\
         <field name=\"x\" offset=\"0\">\
         <type name=\"int\" size=\"4\" metatype=\"int\"/>\
         </field>\
         <field name=\"y\" offset=\"0\">\
         <type name=\"oct1\" size=\"1\" metatype=\"int\"/>\
         </field></type>",
    );
    println!("dec.overlap={}", struct_state(&overlap));
    // Equal-offset fields: the FIRST survives, the second is overlap-dropped.
    let keepfirst = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_dec_keepfirst\" size=\"1\" metatype=\"struct\">\
         <field name=\"x\" offset=\"0\">\
         <type name=\"oct1\" size=\"1\" metatype=\"int\"/>\
         </field>\
         <field name=\"y\" offset=\"0\">\
         <type name=\"int\" size=\"4\" metatype=\"int\"/>\
         </field></type>",
    );
    println!("dec.overlap.keepfirst={}", struct_state(&keepfirst));
    // No fields: the factory type stays incomplete (decodeStruct transfers
    // the scratch's incomplete state via setFields, type.cc:4350-4356).
    let empty8 = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_dec_empty8\" size=\"8\" metatype=\"struct\"/>",
    );
    println!("dec.incomplete.empty={}", struct_state(&empty8));
    // size="0" (old-style incomplete marker) with no fields: incomplete.
    let zero = decode_type_xml(
        &mut factory,
        "<type name=\"fixture_nres_dec_zero\" size=\"0\" metatype=\"struct\"/>",
    );
    println!("dec.incomplete.zero={}", struct_state(&zero));
    // --- decode rejection texts (verbatim error strings) ---
    let error_cases: [(&str, &str); 5] = [
        (
            "dec.err.order",
            "<type name=\"fixture_nres_dec_errorder\" size=\"8\" metatype=\"struct\">\
             <field name=\"x\" offset=\"4\">\
             <type name=\"int\" size=\"4\" metatype=\"int\"/>\
             </field>\
             <field name=\"y\" offset=\"0\">\
             <type name=\"int\" size=\"4\" metatype=\"int\"/>\
             </field></type>",
        ),
        (
            "dec.err.fit",
            "<type name=\"fixture_nres_dec_errfit\" size=\"4\" metatype=\"struct\">\
             <field name=\"z\" offset=\"2\">\
             <type name=\"int\" size=\"4\" metatype=\"int\"/>\
             </field></type>",
        ),
        (
            "dec.err.void",
            "<type name=\"fixture_nres_dec_errvoid\" size=\"4\" metatype=\"struct\">\
             <field name=\"x\" offset=\"0\"><void/></field></type>",
        ),
        (
            "dec.err.name",
            "<type name=\"fixture_nres_dec_errname\" size=\"4\" metatype=\"struct\">\
             <field name=\"\" offset=\"0\">\
             <type name=\"int\" size=\"4\" metatype=\"int\"/>\
             </field></type>",
        ),
        (
            "dec.err.namevoid",
            "<type name=\"fixture_nres_dec_errnamevoid\" size=\"4\" metatype=\"struct\">\
             <field name=\"\" offset=\"0\"><void/></field></type>",
        ),
    ];
    for (record, xml) in error_cases {
        match decode_type_xml_result(&mut factory, xml) {
            Ok(_) => println!("{}=<none>", record),
            Err(message) => println!("{}={}", record, message),
        }
    }

    // --- union: ctor flag survives set_union_fields ---
    factory.get_type_union("fixture_nres_union");
    factory
        .set_union_fields("fixture_nres_union", vec![field("a", 0, int4())])
        .expect("union exists");
    let nu = factory
        .find_by_name("fixture_nres_union")
        .expect("union re-readable");
    println!("union.setfields={}", flag_of(&nu));
}

// ---------------------------------------------------------------------------
// Fixture-local XML ingestion (same model as cspec_typeorg_state_1204.rs).
// ---------------------------------------------------------------------------

fn find_bytes(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| start + offset)
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn parse_start_tag(source: &str) -> Result<(String, Vec<(String, String)>), String> {
    let bytes = source.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    let name_start = pos;
    while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'/' {
        pos += 1;
    }
    if pos == name_start {
        return Err("empty start tag".to_string());
    }
    let name = source[name_start..pos].to_string();
    let mut attributes = Vec::new();
    while pos < bytes.len() {
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos == bytes.len() || bytes[pos] == b'/' {
            break;
        }
        let attr_start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'=' {
            pos += 1;
        }
        let attr_name = source[attr_start..pos].to_string();
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos == bytes.len() || bytes[pos] != b'=' {
            return Err(format!("attribute {attr_name} has no '='"));
        }
        pos += 1;
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos == bytes.len() || (bytes[pos] != b'\'' && bytes[pos] != b'\"') {
            return Err(format!("attribute {attr_name} is not quoted"));
        }
        let quote = bytes[pos];
        pos += 1;
        let value_start = pos;
        while pos < bytes.len() && bytes[pos] != quote {
            pos += 1;
        }
        if pos == bytes.len() {
            return Err(format!("attribute {attr_name} has no closing quote"));
        }
        attributes.push((attr_name, xml_unescape(&source[value_start..pos])));
        pos += 1;
    }
    Ok((name, attributes))
}

fn parse_xml(source: &str) -> Result<ParsedXml, String> {
    let bytes = source.as_bytes();
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut pos = 0usize;
    while pos < bytes.len() {
        let Some(open) = bytes[pos..].iter().position(|byte| *byte == b'<') else {
            break;
        };
        pos += open;
        if bytes[pos..].starts_with(b"<!--") {
            let end = find_bytes(bytes, pos + 4, b"-->")
                .ok_or_else(|| "unterminated XML comment".to_string())?;
            pos = end + 3;
            continue;
        }
        if bytes[pos..].starts_with(b"<?") {
            let end = find_bytes(bytes, pos + 2, b"?>")
                .ok_or_else(|| "unterminated XML declaration".to_string())?;
            pos = end + 2;
            continue;
        }
        if bytes[pos..].starts_with(b"<![CDATA[") {
            let end = find_bytes(bytes, pos + 9, b"]]>")
                .ok_or_else(|| "unterminated CDATA".to_string())?;
            if let Some(current) = stack.last() {
                current
                    .write()
                    .map_err(|_| "poisoned XML node".to_string())?
                    .add_content(&source[pos + 9..end]);
            }
            pos = end + 3;
            continue;
        }
        if bytes[pos..].starts_with(b"<!") {
            let end = bytes[pos + 2..]
                .iter()
                .position(|byte| *byte == b'>')
                .map(|offset| pos + 2 + offset)
                .ok_or_else(|| "unterminated XML directive".to_string())?;
            pos = end + 1;
            continue;
        }
        if bytes[pos..].starts_with(b"</") {
            let end = bytes[pos + 2..]
                .iter()
                .position(|byte| *byte == b'>')
                .map(|offset| pos + 2 + offset)
                .ok_or_else(|| "unterminated end tag".to_string())?;
            let name = source[pos + 2..end].trim();
            let node = stack.pop().ok_or_else(|| format!("unexpected </{name}>"))?;
            let actual = node
                .read()
                .map_err(|_| "poisoned XML node".to_string())?
                .name
                .clone();
            if actual != name {
                return Err(format!("mismatched </{name}> for <{actual}>"));
            }
            pos = end + 1;
            continue;
        }

        let mut end = pos + 1;
        let mut quote = None;
        while end < bytes.len() {
            match (quote, bytes[end]) {
                (None, b'\'' | b'\"') => quote = Some(bytes[end]),
                (Some(expected), current) if expected == current => quote = None,
                (None, b'>') => break,
                _ => {}
            }
            end += 1;
        }
        if end == bytes.len() {
            return Err("unterminated start tag".to_string());
        }
        let mut inner = source[pos + 1..end].trim_end();
        let self_closing = inner.ends_with('/');
        if self_closing {
            inner = inner[..inner.len() - 1].trim_end();
        }
        let (name, attributes) = parse_start_tag(inner)?;
        {
            let mut ids = registry
                .write()
                .map_err(|_| "poisoned XML registry".to_string())?;
            ids.register_element(&name);
            for (attr_name, _) in &attributes {
                ids.register_attribute(attr_name);
            }
        }
        let mut element = Element::new();
        element.set_name(&name);
        for (attr_name, value) in attributes {
            element.add_attribute(&attr_name, &value);
        }
        let node = Arc::new(RwLock::new(element));
        if let Some(parent) = stack.last() {
            parent
                .write()
                .map_err(|_| "poisoned XML node".to_string())?
                .add_child(node.clone());
        } else if root.replace(node.clone()).is_some() {
            return Err("multiple XML roots".to_string());
        }
        if !self_closing {
            stack.push(node);
        }
        pos = end + 1;
    }
    if !stack.is_empty() {
        return Err("unclosed XML element".to_string());
    }
    Ok(ParsedXml {
        root: root.ok_or_else(|| "missing XML root".to_string())?,
        registry,
    })
}
