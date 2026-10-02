// CSPEC-TYPEORG-STATE-0001: Rust comparand for the locked Ghidra 12.0.4
// data-organization state oracle (TypeFactory::{decodeDataOrganization,
// decodeAlignmentMap, setupSizes} + getAlignment/getPrimitiveAlignSize).
//
// Parses the locked x86-64-gcc.cspec text into the structured Element DOM
// (fixture-local ingestion, same model as cspec_param_model_1204.rs) and
// drives the production TreeDecoder through the mapped decode functions.
// The `production` group emulates the full chain as
// decode_data_organization(production element) + setup_sizes(locked arch
// inputs); the C++ side observes the real BfdArchitecture::init chain, and
// the byte diff pins both to the same state.

use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::sync::{Arc, RwLock};

type Node = Arc<RwLock<Element>>;

struct ParsedXml {
    root: Node,
    registry: Arc<RwLock<IdRegistry>>,
}

// Locked x86-64 architecture facts TypeFactory::setupSizes reads from glb
// (type.cc:3142-3167). The C++ fixture observes these from the live
// BfdArchitecture; this side pins the same locked-spec facts: RSP stack
// spacebase size 8, ram default data space address size 8, default size 8,
// no far-pointer segment op.
const ARCH_DEFAULT_SIZE: i32 = 8;
const ARCH_STACK_SPACEBASE_SIZE: Option<i32> = Some(8);
const ARCH_DEFAULT_DATA_SPACE_ADDR_SIZE: i32 = 8;
const ARCH_FAR_POINTER: Option<(i32, i32)> = None;

fn arch_inputs() -> SizeArchInputs {
    SizeArchInputs {
        stack_spacebase_size: ARCH_STACK_SPACEBASE_SIZE,
        default_data_space_addr_size: ARCH_DEFAULT_DATA_SPACE_ADDR_SIZE,
        default_size: ARCH_DEFAULT_SIZE,
        far_pointer: ARCH_FAR_POINTER,
    }
}

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

fn child_named(parent: &Node, name: &str) -> Result<Node, String> {
    let guard = parent
        .read()
        .map_err(|_| "poisoned XML node".to_string())?;
    guard
        .children
        .iter()
        .find(|child| {
            child
                .read()
                .map(|node| node.name == name)
                .unwrap_or(false)
        })
        .cloned()
        .ok_or_else(|| format!("missing <{name}> child"))
}

fn json_escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            value if value < ' ' => write!(&mut out, "\\u{:04x}", value as u32).unwrap(),
            value => out.push(value),
        }
    }
    out
}

fn decode_data_organization(factory: &mut TypeFactory, parsed: &ParsedXml) {
    let mut decoder = TreeDecoder::new(parsed.root.clone(), parsed.registry.clone());
    factory.decode_data_organization(&mut decoder);
}

fn write_sizes_fields(out: &mut String, factory: &TypeFactory) {
    write!(
        out,
        "\"int\":{},\"long\":{},\"char\":{},\"wchar\":{},\"pointer\":{},\"alt_pointer\":{}",
        factory.get_size_of_int(),
        factory.get_size_of_long(),
        factory.get_size_of_char(),
        factory.get_size_of_wchar(),
        factory.get_size_of_pointer(),
        factory.get_size_of_alt_pointer()
    )
    .unwrap();
}

fn write_sizes(out: &mut String, factory: &TypeFactory) {
    out.push('{');
    write_sizes_fields(out, factory);
    out.push('}');
}

fn write_align_probes(out: &mut String, factory: &TypeFactory, first: u32, last: u32) {
    out.push('[');
    for size in first..=last {
        if size != first {
            out.push(',');
        }
        write!(out, "{}", factory.get_alignment(size).unwrap()).unwrap();
    }
    out.push(']');
}

fn write_primitive_probes(out: &mut String, factory: &TypeFactory, first: u32, last: u32) {
    out.push('[');
    for size in first..=last {
        if size != first {
            out.push(',');
        }
        write!(out, "{}", factory.get_primitive_align_size(size).unwrap()).unwrap();
    }
    out.push(']');
}

fn observe_align_error(factory: &TypeFactory, size: u32) -> String {
    match factory.get_alignment(size) {
        Ok(_) => "NO_ERROR".to_string(),
        Err(message) => message,
    }
}

// Decode one synthetic <data_organization> document into `factory`.
fn decode_synthetic(factory: &mut TypeFactory, xml: &str) {
    let parsed = parse_xml(xml).expect("synthetic document parses");
    decode_data_organization(factory, &parsed);
}

fn run() -> Result<String, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err("usage: cspec_typeorg_state_1204 <cspec>".to_string());
    }
    let cspec_text = fs::read_to_string(&args[1])
        .map_err(|error| format!("failed to read {}: {error}", args[1]))?;
    let parsed = parse_xml(&cspec_text)?;
    if parsed.root.read().unwrap().name != "compiler_spec" {
        return Err("cspec root is not compiler_spec".to_string());
    }
    let data_organization = child_named(&parsed.root, "data_organization")?;
    let data_org_parsed = ParsedXml {
        root: data_organization,
        registry: parsed.registry.clone(),
    };

    // production: decode of the production element + setup_sizes over the
    // locked arch inputs (the C++ side observes the full init chain; the
    // byte diff pins the resulting TypeFactory state).
    let mut production = TypeFactory::new(8);
    decode_data_organization(&mut production, &data_org_parsed);
    production.setup_sizes(&arch_inputs());

    // raw_decode: pre-setupSizes state of a standalone factory.
    let mut raw = TypeFactory::new(8);
    decode_data_organization(&mut raw, &data_org_parsed);

    // c1: sparse map -> forward fill; index 0 keeps -1.
    let mut c1 = TypeFactory::new(8);
    decode_synthetic(
        &mut c1,
        "<data_organization><size_alignment_map>\
         <entry size=\"3\" alignment=\"4\"/>\
         <entry size=\"7\" alignment=\"8\"/>\
         </size_alignment_map></data_organization>",
    );

    // c2: empty map -> oracle LowlevelError text, then default install.
    let mut c2 = TypeFactory::new(8);
    decode_synthetic(
        &mut c2,
        "<data_organization><size_alignment_map>\
         </size_alignment_map></data_organization>",
    );
    let c2_error = observe_align_error(&c2, 1);
    c2.setup_sizes(&arch_inputs());

    // c3: explicit size-0 entry; primitive size 0 becomes a safe probe.
    let mut c3 = TypeFactory::new(8);
    decode_synthetic(
        &mut c3,
        "<data_organization><size_alignment_map>\
         <entry size=\"0\" alignment=\"1\"/>\
         <entry size=\"2\" alignment=\"2\"/>\
         </size_alignment_map></data_organization>",
    );

    // c4: out-of-order entries, later duplicate wins, explicit zero
    // alignment (no primitive probes: align 0 divides by zero).
    let mut c4 = TypeFactory::new(8);
    decode_synthetic(
        &mut c4,
        "<data_organization><size_alignment_map>\
         <entry size=\"8\" alignment=\"8\"/>\
         <entry size=\"3\" alignment=\"2\"/>\
         <entry size=\"8\" alignment=\"4\"/>\
         <entry size=\"5\" alignment=\"0\"/>\
         </size_alignment_map></data_organization>",
    );

    // c5: only char_size decoded; everything else derives in setup_sizes.
    let mut c5 = TypeFactory::new(8);
    decode_synthetic(
        &mut c5,
        "<data_organization><char_size value=\"3\"/></data_organization>",
    );
    let mut c5_decoded = TypeFactory::new(8);
    decode_synthetic(
        &mut c5_decoded,
        "<data_organization><char_size value=\"3\"/></data_organization>",
    );
    c5.setup_sizes(&arch_inputs());

    // c6: skipped children around one consumed size; int != 4 branch.
    let mut c6 = TypeFactory::new(8);
    decode_synthetic(
        &mut c6,
        "<data_organization><machine_alignment value=\"2\"/>\
         <default_alignment value=\"1\"/>\
         <short_size value=\"2\"/>\
         <integer_size value=\"2\"/>\
         <float_size value=\"4\"/>\
         <double_size value=\"8\"/>\
         </data_organization>",
    );
    c6.setup_sizes(&arch_inputs());

    // c7: negative size survives decode and flows through the long branch.
    let mut c7 = TypeFactory::new(8);
    decode_synthetic(
        &mut c7,
        "<data_organization><integer_size value=\"-2\"/>\
         </data_organization>",
    );
    c7.setup_sizes(&arch_inputs());

    // c8: children AFTER <size_alignment_map> are still consumed — the
    // sam branch must fall through to the unified close_element (the
    // oracle's closeElement at type.cc:4612).
    let mut c8 = TypeFactory::new(8);
    decode_synthetic(
        &mut c8,
        "<data_organization><size_alignment_map>\
         <entry size=\"1\" alignment=\"1\"/>\
         </size_alignment_map>\
         <char_size value=\"3\"/>\
         </data_organization>",
    );

    let mut out = String::new();
    write!(
        &mut out,
        "{{\"schema\":1,\"fixture\":\"CSPEC-TYPEORG-STATE-0001\"\
         ,\"arch_inputs\":{{\"default_size\":{},\"stack_spacebase_size\":{},\
         \"default_data_space_addr_size\":{},\"far_pointer\":{}}}",
        ARCH_DEFAULT_SIZE,
        ARCH_STACK_SPACEBASE_SIZE.unwrap_or(-1),
        ARCH_DEFAULT_DATA_SPACE_ADDR_SIZE,
        i32::from(ARCH_FAR_POINTER.is_some())
    )
    .unwrap();
    out.push_str(",\"production\":{");
    write_sizes_fields(&mut out, &production);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &production, 0, 17);
    out.push_str(",\"primitive\":");
    write_primitive_probes(&mut out, &production, 1, 17);
    out.push_str("},\"raw_decode\":{");
    write_sizes_fields(&mut out, &raw);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &raw, 0, 17);
    out.push_str(",\"primitive\":");
    write_primitive_probes(&mut out, &raw, 1, 17);
    out.push_str("},\"cases\":[");
    out.push_str("{\"name\":\"c1_sparse_map\",\"decoded\":");
    write_sizes(&mut out, &c1);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &c1, 0, 8);
    out.push_str(",\"primitive\":");
    write_primitive_probes(&mut out, &c1, 1, 8);
    out.push_str("},{\"name\":\"c2_empty_map\",\"align_error\":\"");
    out.push_str(&json_escape(&c2_error));
    out.push_str("\",\"setup\":");
    write_sizes(&mut out, &c2);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &c2, 0, 9);
    out.push_str(",\"primitive\":");
    write_primitive_probes(&mut out, &c2, 1, 9);
    out.push_str("},{\"name\":\"c3_zero_entry\",\"decoded\":");
    write_sizes(&mut out, &c3);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &c3, 0, 3);
    out.push_str(",\"primitive\":");
    write_primitive_probes(&mut out, &c3, 0, 3);
    out.push_str("},{\"name\":\"c4_duplicate_zero_align\",\"decoded\":");
    write_sizes(&mut out, &c4);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &c4, 0, 9);
    out.push_str("},{\"name\":\"c5_char_only_setup\",\"decoded\":");
    write_sizes(&mut out, &c5_decoded);
    out.push_str(",\"setup\":");
    write_sizes(&mut out, &c5);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &c5, 0, 9);
    out.push_str(",\"primitive\":");
    write_primitive_probes(&mut out, &c5, 1, 9);
    out.push_str("},{\"name\":\"c6_unknown_children_setup\",\"setup\":");
    write_sizes(&mut out, &c6);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &c6, 0, 9);
    out.push_str(",\"primitive\":");
    write_primitive_probes(&mut out, &c6, 1, 9);
    out.push_str("},{\"name\":\"c7_negative_setup\",\"setup\":");
    write_sizes(&mut out, &c7);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &c7, 0, 9);
    out.push_str(",\"primitive\":");
    write_primitive_probes(&mut out, &c7, 1, 9);
    out.push_str("},{\"name\":\"c8_sam_followed_by_child\",\"decoded\":");
    write_sizes(&mut out, &c8);
    out.push_str(",\"align\":");
    write_align_probes(&mut out, &c8, 0, 1);
    out.push_str("}],\"done\":1}\n");
    Ok(out)
}

fn main() {
    match run() {
        Ok(output) => {
            print!("{output}");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
