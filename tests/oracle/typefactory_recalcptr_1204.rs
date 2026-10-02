// WORKPKG-UNMAP-TYPEUNION-0003: Rudra comparand for the locked Ghidra
// 12.0.4 TypeFactory recalcPointerSubmeta / setName / warnings /
// getTypePointerWithSpace / destroyType / setFields-flags family plus the
// type.cc free functions string2typeclass / metatype2typeclass
// (tests/oracle/typefactory_recalcptr_1204.cc), record for record.
//
// The warning cells ride the PUBLIC decode channel on both sides: the
// decodeStruct overlap warning reaches insertWarning (type.cc:4357-4358)
// and throws verbatim on anonymous (id-0) types; destroyType drains the
// warning list through removeWarning (type.cc:4126-4127).

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{
    metatype2typeclass, string2typeclass, Datatype, TypeClass, TypeField, TypeMetatype,
};
use rudra::type_system::typefactory::TypeFactory;

fn field(name: &str, offset: usize, dt: Arc<Datatype>) -> TypeField {
    TypeField {
        name: name.to_string(),
        offset,
        type_ptr: dt,
    }
}

fn decode_type_xml(factory: &mut TypeFactory, xml: &str) -> Result<Arc<Datatype>, String> {
    let parsed = parse_xml(xml).expect("fixture XML parses");
    let mut decoder = TreeDecoder::new(parsed.root.clone(), parsed.registry.clone());
    factory.decode_type(&mut decoder)
}

// --- minimal XML parser (the typefactory_needsres_1204.rs helper) ---

use rudra::marshal::IdRegistry as Registry;

struct ParsedXml {
    root: Arc<RwLock<Element>>,
    registry: Arc<RwLock<Registry>>,
}

fn find_bytes(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn parse_start_tag(inner: &str) -> Result<(String, Vec<(String, String)>), String> {
    let bytes = inner.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    let name_start = pos;
    while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    let name = inner[name_start..pos].to_string();
    let mut attributes = Vec::new();
    loop {
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
        let attr_name = inner[attr_start..pos].to_string();
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
        if pos == bytes.len() || (bytes[pos] != b'\'' && bytes[pos] != b'"') {
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
        attributes.push((attr_name, xml_unescape(&inner[value_start..pos])));
        pos += 1;
    }
    Ok((name, attributes))
}

fn parse_xml(source: &str) -> Result<ParsedXml, String> {
    let bytes = source.as_bytes();
    let registry = Arc::new(RwLock::new(Registry::new()));
    let mut stack: Vec<Arc<RwLock<Element>>> = Vec::new();
    let mut root: Option<Arc<RwLock<Element>>> = None;
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
                .get_name()
                .to_string();
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
                (None, b'\'' | b'"') => quote = Some(bytes[end]),
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
            let mut node = Element::new();
            node.set_name(&name);
            for (attr_name, value) in attributes {
                node.add_attribute(&attr_name, &value);
            }
            let node = Arc::new(RwLock::new(node));
            if let Some(current) = stack.last() {
                current
                    .write()
                    .map_err(|_| "poisoned XML node".to_string())?
                    .add_child(node.clone());
            } else {
                root = Some(node.clone());
            }
            if !self_closing {
                stack.push(node);
            }
        }
        pos = end + 1;
    }
    let root = root.ok_or_else(|| "no root element".to_string())?;
    Ok(ParsedXml { root, registry })
}

fn class_num(class: TypeClass) -> i32 {
    class as i32
}

fn main() {
    // The curl cspec <size_alignment_map> (alignMap[0] stays -1), decoded
    // through the production entry — see the C++ fixture header.
    let mut factory = TypeFactory::new(8);
    {
        let data_organization = {
            let mut root = Element::new();
            root.set_name("data_organization");
            let mut map = Element::new();
            map.set_name("size_alignment_map");
            for (size, alignment) in [(1, 1), (2, 2), (4, 4), (8, 8), (16, 16)] {
                let mut entry = Element::new();
                entry.set_name("entry");
                entry.add_attribute("size", &size.to_string());
                entry.add_attribute("alignment", &alignment.to_string());
                map.add_child(Arc::new(RwLock::new(entry)));
            }
            root.add_child(Arc::new(RwLock::new(map)));
            Arc::new(RwLock::new(root))
        };
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        let mut decoder = TreeDecoder::new(data_organization, registry);
        factory.decode_data_organization(&mut decoder);
    }

    let int4 = factory.get_base(4, TypeMetatype::Int).expect("int4");
    let int8 = factory.get_base(8, TypeMetatype::Int).expect("int8");

    // --- s2tc: string2typeclass (type.cc:371-411) ---
    for (label, spelling) in [
        ("class1", "class1"),
        ("class2", "class2"),
        ("class3", "class3"),
        ("class4", "class4"),
        ("general", "general"),
        ("hiddenret", "hiddenret"),
        ("float", "float"),
        ("ptr", "ptr"),
        ("pointer", "pointer"),
        ("vector", "vector"),
        ("unknown", "unknown"),
    ] {
        let class = string2typeclass(spelling).expect("valid spelling");
        println!("s2tc.{label}={}", class_num(class));
    }
    for (label, spelling) in [("err.classes", "classes"), ("err.empty", "")] {
        match string2typeclass(spelling) {
            Ok(_) => println!("s2tc.{label}=NO_THROW"),
            Err(message) => println!("s2tc.{label}={message}"),
        }
    }

    // --- m2tc: metatype2typeclass (type.cc:420-432) ---
    println!("m2tc.float={}", class_num(metatype2typeclass(TypeMetatype::Float)));
    println!("m2tc.ptr={}", class_num(metatype2typeclass(TypeMetatype::Pointer)));
    println!("m2tc.int={}", class_num(metatype2typeclass(TypeMetatype::Int)));

    // --- recalc: setFields completion drives recalcPointerSubmeta ---
    {
        factory.create_struct("fixture_recp_single");
        let st = factory
            .find_by_name("fixture_recp_single")
            .expect("single stub exists");
        let p1 = factory.get_type_pointer(8, st.clone(), 1);
        println!("recalc.single.subbefore={}", p1.get_submeta() as i32);
        factory
            .set_fields_sized("fixture_recp_single", vec![field("x", 0, int8.clone())], 8, 8)
            .expect("single completes");
        let st_done = factory
            .find_by_name("fixture_recp_single")
            .expect("completed single readable");
        let p2 = factory.get_type_pointer(8, st_done.clone(), 1);
        println!("recalc.single.identity={}", Arc::ptr_eq(&p1, &p2) as u8);
        println!("recalc.single.subafter={}", p2.get_submeta() as i32);
    }
    {
        factory.create_struct("fixture_recp_multi");
        let st = factory
            .find_by_name("fixture_recp_multi")
            .expect("multi stub exists");
        let p1 = factory.get_type_pointer(8, st.clone(), 1);
        println!("recalc.multi.subbefore={}", p1.get_submeta() as i32);
        factory
            .set_fields_sized(
                "fixture_recp_multi",
                vec![field("a", 0, int4.clone()), field("b", 4, int4.clone())],
                8,
                4,
            )
            .expect("multi completes");
        let st_done = factory
            .find_by_name("fixture_recp_multi")
            .expect("completed multi readable");
        let p2 = factory.get_type_pointer(8, st_done.clone(), 1);
        println!("recalc.multi.identity={}", Arc::ptr_eq(&p1, &p2) as u8);
        println!("recalc.multi.subafter={}", p2.get_submeta() as i32);
    }

    // --- setname: TypeFactory::setName (type.cc:3445-3459) ---
    {
        factory.create_struct("fixture_recp_name_old");
        let st = factory
            .find_by_name("fixture_recp_name_old")
            .expect("name_old stub exists");
        let renamed = factory
            .set_name(&st, "fixture_recp_name_new")
            .expect("rename succeeds");
        let found = factory
            .find_by_name("fixture_recp_name_new")
            .expect("renamed type findable");
        println!("setname.newfound={}", Arc::ptr_eq(&found, &renamed) as u8);
        println!(
            "setname.oldgone={}",
            factory.find_by_name("fixture_recp_name_old").is_none() as u8
        );
        println!(
            "setname.idkept={}",
            (renamed.get_id() != 0 && found.get_id() == renamed.get_id()) as u8
        );
        // The anonymous zero-id branch (type.cc:3453-3454).
        let arr = factory.get_type_array(2, int4.clone());
        println!("setname.anonzero={}", (arr.get_id() == 0) as u8);
        let named_arr = factory
            .set_name(&arr, "fixture_recp_arr")
            .expect("array rename succeeds");
        let arr_slot = factory
            .find_by_name("fixture_recp_arr")
            .expect("renamed array findable");
        println!("setname.anonhash.nonzero={}", (named_arr.get_id() != 0) as u8);
        println!(
            "setname.anonhash.slotmatch={}",
            (named_arr.get_id() == arr_slot.get_id()) as u8
        );
    }

    // --- warn: the insertWarning channel through PUBLIC decode triggers ---
    {
        // Anonymous (id-0) struct with an overlapping field: decodeStruct
        // reaches insertWarning (type.cc:4357-4358) and throws verbatim.
        match decode_type_xml(
            &mut factory,
            "<type size=\"8\" metatype=\"struct\">\
             <field name=\"x\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>\
             <field name=\"y\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>\
             </type>",
        ) {
            Ok(_) => println!("warn.anon.err=NO_THROW"),
            Err(message) => println!("warn.anon.err={message}"),
        }
        // Named struct: the warning is registered, hasWarning set.
        let warned = decode_type_xml(
            &mut factory,
            "<type name=\"fixture_recp_warn\" size=\"8\" metatype=\"struct\">\
             <field name=\"x\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>\
             <field name=\"y\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>\
             </type>",
        )
        .expect("warned struct decodes");
        println!("warn.named.has={}", warned.has_warning() as u8);
        // destroyType drains the warning list through removeWarning and
        // the type is gone.
        factory.destroy_type(&warned).expect("warned type destroys");
        println!(
            "warn.destroy.gone={}",
            factory.find_by_name("fixture_recp_warn").is_none() as u8
        );
    }

    // --- destroy: destroyType (type.cc:4122-4132) ---
    {
        match factory.destroy_type(&int4) {
            Ok(()) => println!("destroy.core.err=NO_THROW"),
            Err(message) => println!("destroy.core.err={message}"),
        }
        let warned_destroy = decode_type_xml(
            &mut factory,
            "<type name=\"fixture_recp_destroy\" size=\"8\" metatype=\"struct\">\
             <field name=\"x\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>\
             <field name=\"y\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>\
             </type>",
        )
        .expect("warned destroy struct decodes");
        factory
            .destroy_type(&warned_destroy)
            .expect("warned type destroys");
        println!(
            "destroy.named.gone={}",
            factory.find_by_name("fixture_recp_destroy").is_none() as u8
        );
    }

    // --- ptrspace: getTypePointerWithSpace (type.cc:4055-4065) ---
    {
        let ptr = factory
            .get_type_pointer_with_space(int4.clone(), AddressSpace::Ram, "fixture_tp_ptr")
            .expect("space pointer builds");
        println!("ptrspace.name={}", ptr.get_name());
        let slot = factory
            .find_by_name("fixture_tp_ptr")
            .expect("space pointer registered");
        println!(
            "ptrspace.idhash={}",
            (ptr.get_id() != 0 && slot.get_id() == ptr.get_id()) as u8
        );
        let wordsize = match ptr.as_ref() {
            Datatype::Pointer(p) => p.wordsize,
            _ => 0,
        };
        println!("ptrspace.wordsize={wordsize}");
        println!("ptrspace.size={}", ptr.get_size());
        println!(
            "ptrspace.space={}",
            (match ptr.as_ref() {
                Datatype::Pointer(p) => p.base.pointer_space == Some(AddressSpace::Ram),
                _ => false,
            }) as u8
        );
    }

    // --- flags: the setFields flags mask (type.cc:3487-3488/3508-3509) ---
    {
        factory.create_struct("fixture_recp_mask_s");
        let mask = rudra::type_system::datatype::type_flags::OPAQUE_STRUCT
            | rudra::type_system::datatype::type_flags::VARLENGTH;
        let st = factory
            .set_fields_flags("fixture_recp_mask_s", vec![field("x", 0, int8.clone())], 8, 8, mask)
            .expect("masked struct completes");
        println!(
            "flags.struct.opaque={}",
            ((st.get_flags() & rudra::type_system::datatype::type_flags::OPAQUE_STRUCT) != 0)
                as u8
        );
        println!("flags.struct.varlen={}", st.is_variable_length() as u8);
        factory.get_type_union("fixture_recp_mask_u");
        let ut = factory
            .set_union_fields_flags(
                "fixture_recp_mask_u",
                vec![field("x", 0, int8.clone())],
                8,
                8,
                mask,
            )
            .expect("masked union completes");
        println!(
            "flags.union.opaque={}",
            ((ut.get_flags() & rudra::type_system::datatype::type_flags::OPAQUE_STRUCT) != 0)
                as u8
        );
        println!("flags.union.varlen={}", ut.is_variable_length() as u8);
    }
}
