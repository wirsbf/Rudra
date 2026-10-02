use rudra::arch::Architecture;
use rudra::fspec::{EffectRecord, ParamListStandard, VarnodeData};
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::sleigh_ffi::{set_sla_path, SleighCtx};
use rudra::space::AddressSpace;

use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::sync::{Arc, RwLock};

type Node = Arc<RwLock<Element>>;

struct ParsedXml {
    root: Node,
    registry: Arc<RwLock<IdRegistry>>,
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
        while pos < bytes.len()
            && !bytes[pos].is_ascii_whitespace()
            && bytes[pos] != b'='
        {
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
            let end = find_bytes(bytes, pos + 9, b"]]>" )
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
                return Err(format!("mismatched </{name}> for <{actual}>") );
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

fn node_name(node: &Node) -> Result<String, String> {
    Ok(node
        .read()
        .map_err(|_| "poisoned XML node".to_string())?
        .name
        .clone())
}

fn child_named(parent: &Node, name: &str) -> Result<Node, String> {
    let guard = parent
        .read()
        .map_err(|_| "poisoned XML node".to_string())?;
    guard
        .children
        .iter()
        .find(|child| child.read().map(|node| node.name == name).unwrap_or(false))
        .cloned()
        .ok_or_else(|| format!("missing <{name}> child"))
}

fn prototype_named(compiler_spec: &Node, name: &str) -> Result<Node, String> {
    let guard = compiler_spec
        .read()
        .map_err(|_| "poisoned XML node".to_string())?;
    guard
        .children
        .iter()
        .find(|child| {
            child
                .read()
                .map(|node| {
                    node.name == "prototype"
                        && node.get_attribute_value("name") == Some(name)
                })
                .unwrap_or(false)
        })
        .cloned()
        .ok_or_else(|| format!("missing prototype {name}"))
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

fn space_name(space: AddressSpace) -> &'static str {
    match space {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Overlay => "overlay",
        AddressSpace::Other(_) => "other",
    }
}

fn write_ranges(output: &mut String, ranges: &rudra::address::RangeList, space: AddressSpace) {
    output.push('[');
    for (index, range) in ranges.ranges().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"space\":\"{}\",\"first\":{},\"last\":{}}}",
            space_name(space),
            range.get_first().as_u64(),
            range.get_last().as_u64()
        )
        .unwrap();
    }
    output.push(']');
}

fn write_entries(output: &mut String, params: &ParamListStandard) {
    output.push('[');
    for (index, entry) in params.get_entry().iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"space\":\"{}\",\"offset\":{},\"size\":{},\"minsize\":{},\"align\":{},\"type\":{},\"groups\":[",
            space_name(entry.get_space()),
            entry.get_base(),
            entry.get_size(),
            entry.get_min_size(),
            entry.get_align(),
            entry.get_type() as i32
        )
        .unwrap();
        for (group_index, group) in entry.get_all_groups().iter().enumerate() {
            if group_index != 0 {
                output.push(',');
            }
            write!(output, "{group}").unwrap();
        }
        write!(
            output,
            "],\"reverse\":{},\"grouped\":{},\"overlap\":{},\"first_in_class\":{}}}",
            i32::from(entry.is_reverse_stack()),
            i32::from(entry.is_grouped()),
            i32::from(entry.is_overlap()),
            i32::from(entry.is_first_in_class())
        )
        .unwrap();
    }
    output.push(']');
}

fn decode_params(
    node: Node,
    registry: Arc<RwLock<IdRegistry>>,
    normal_stack: bool,
    resolver: &dyn Fn(&str) -> Option<VarnodeData>,
) -> Result<ParamListStandard, String> {
    let mut decoder = TreeDecoder::new(node, registry);
    let mut params = ParamListStandard::new();
    let mut effects: Vec<EffectRecord> = Vec::new();
    params.decode(&mut decoder, &mut effects, normal_stack, resolver)?;
    Ok(params)
}

fn observe_error(
    xml: &str,
    normal_stack: bool,
    resolver: &dyn Fn(&str) -> Option<VarnodeData>,
) -> String {
    match parse_xml(xml).and_then(|parsed| {
        decode_params(parsed.root, parsed.registry, normal_stack, resolver).map(|_| ())
    }) {
        Ok(()) => "NO_ERROR".to_string(),
        Err(error) => error,
    }
}

fn write_error(output: &mut String, name: &str, message: &str) {
    write!(
        output,
        "{{\"case\":\"{}\",\"message\":\"{}\"}}",
        name,
        json_escape(message)
    )
    .unwrap();
}

fn run() -> Result<String, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: cspec_param_model_1204 <cspec> <sla>".to_string());
    }
    let cspec_text = fs::read_to_string(&args[1])
        .map_err(|error| format!("failed to read {}: {error}", args[1]))?;
    let parsed = parse_xml(&cspec_text)?;
    if node_name(&parsed.root)? != "compiler_spec" {
        return Err("cspec root is not compiler_spec".to_string());
    }

    set_sla_path(&args[2]);
    let sleigh = SleighCtx::new().ok_or_else(|| "SleighCtx::new failed".to_string())?;
    let mut registers = BTreeMap::new();
    for index in 0..sleigh.num_registers() {
        if let Some((name, space, offset, size)) = sleigh.register_info(index) {
            let space = u8::try_from(space)
                .map(AddressSpace::from_id)
                .map_err(|_| format!("invalid register space for {name}"))?;
            registers.insert(name, VarnodeData { space, offset, size });
        }
    }
    let resolver = |name: &str| registers.get(name).copied();

    let default_wrapper = child_named(&parsed.root, "default_proto")?;
    let default_prototype = child_named(&default_wrapper, "prototype")?;
    let default_input = child_named(&default_prototype, "input")?;
    let msabi_prototype = prototype_named(&parsed.root, "MSABI")?;
    let msabi_input = child_named(&msabi_prototype, "input")?;

    let default_params = decode_params(
        default_input,
        parsed.registry.clone(),
        true,
        &resolver,
    )?;
    let mut default_stack_ranges = rudra::address::RangeList::new();
    default_params.get_range_list(AddressSpace::Stack, &mut default_stack_ranges);

    let msabi_params = decode_params(
        msabi_input,
        parsed.registry.clone(),
        true,
        &resolver,
    )?;
    let mut msabi_stack_ranges = rudra::address::RangeList::new();
    msabi_params.get_range_list(AddressSpace::Stack, &mut msabi_stack_ranges);

    let flipped_xml =
        "<input><pentry minsize=\"1\" maxsize=\"16\" align=\"4\">\
         <addr space=\"stack\" offset=\"100\"/></pentry></input>";
    let flipped_parsed = parse_xml(flipped_xml)?;
    let flipped_params = decode_params(
        flipped_parsed.root,
        flipped_parsed.registry,
        false,
        &resolver,
    )?;
    let mut flipped_ranges = rudra::address::RangeList::new();
    flipped_params.get_range_list(AddressSpace::Stack, &mut flipped_ranges);

    let wrapper_children = default_wrapper
        .read()
        .map_err(|_| "poisoned XML node".to_string())?
        .children
        .len();
    let mut architecture = Architecture::new();
    let mut default_decoder = TreeDecoder::new(default_wrapper, parsed.registry.clone());
    architecture.decode_default_proto(&mut default_decoder, 8, &resolver)?;
    let old_default_handle = architecture
        .get_default_model()
        .cloned()
        .ok_or_else(|| "architecture has no default model".to_string())?;
    let initial_map_identity = Arc::ptr_eq(
        &old_default_handle,
        architecture
            .get_model(old_default_handle.get_name())
            .ok_or_else(|| "default model is absent from map".to_string())?,
    );
    let identity_parsed = parse_xml(
        "<prototype name=\"__fixture_external\" extrapop=\"0\"></prototype>",
    )?;
    let mut identity_decoder =
        TreeDecoder::new(identity_parsed.root, identity_parsed.registry);
    let decoded_handle = architecture.decode_proto(&mut identity_decoder, 8, &resolver)?;
    let decoded_map = architecture
        .get_model(decoded_handle.get_name())
        .ok_or_else(|| "default model is absent from map".to_string())?;
    let decode_return_map_identity = Arc::ptr_eq(&decoded_handle, decoded_map);
    architecture.set_default_model(decoded_handle.get_name());
    let decode_return_default_identity = Arc::ptr_eq(
        &decoded_handle,
        architecture
            .get_default_model()
            .ok_or_else(|| "selected model is absent".to_string())?,
    );
    let old_printed_after_select = old_default_handle.print_in_decl();
    let decoded_printed_when_default = decoded_handle.print_in_decl();
    architecture.set_default_model(old_default_handle.get_name());
    let decoded_printed_after_restore = decoded_handle.print_in_decl();
    let old_printed_after_restore = old_default_handle.print_in_decl();
    let restored_default_identity = Arc::ptr_eq(
        &old_default_handle,
        architecture
            .get_default_model()
            .ok_or_else(|| "restored model is absent".to_string())?,
    );

    let errors = [
        (
            "missing_size",
            "<input><pentry minsize=\"1\"><addr space=\"stack\" offset=\"0\"/>\
             </pentry></input>",
            true,
        ),
        (
            "bad_extension",
            "<input><pentry minsize=\"1\" maxsize=\"8\" extension=\"mystery\">\
             <register name=\"RDI\"/></pentry></input>",
            true,
        ),
        (
            "flipped_misaligned_size",
            "<input><pentry minsize=\"1\" maxsize=\"10\" align=\"4\">\
             <addr space=\"stack\" offset=\"100\"/></pentry></input>",
            false,
        ),
        (
            "entry_after_rule",
            "<input><rule><datatype name=\"any\"/><consume storage=\"general\"/></rule>\
             <pentry minsize=\"1\" maxsize=\"8\"><register name=\"RDI\"/>\
             </pentry></input>",
            true,
        ),
        (
            "ambiguous_group",
            "<input><group><pentry minsize=\"1\" maxsize=\"8\">\
             <register name=\"RDI\"/></pentry><pentry minsize=\"1\" maxsize=\"8\">\
             <register name=\"RSI\"/></pentry></group></input>",
            true,
        ),
    ];

    let mut output = String::new();
    write!(
        &mut output,
        "{{\"schema\":1,\"fixture\":\"CSPEC-PARAMMODEL-0001\",\"source\":{{\"root\":\"compiler_spec\",\"default_wrapper_children\":{wrapper_children}}},\"default_input\":{{\"entry_count\":{},\"entries\":",
        default_params.get_entry().len()
    )
    .unwrap();
    write_entries(&mut output, &default_params);
    output.push_str(",\"stack_ranges\":");
    write_ranges(&mut output, &default_stack_ranges, AddressSpace::Stack);
    write!(
        &mut output,
        "}},\"msabi_input\":{{\"entry_count\":{},\"entries\":",
        msabi_params.get_entry().len()
    )
    .unwrap();
    write_entries(&mut output, &msabi_params);
    output.push_str(",\"stack_ranges\":");
    write_ranges(&mut output, &msabi_stack_ranges, AddressSpace::Stack);
    output.push_str("},\"flipped\":{\"entries\":");
    write_entries(&mut output, &flipped_params);
    output.push_str(",\"stack_ranges\":");
    write_ranges(&mut output, &flipped_ranges, AddressSpace::Stack);
    write!(
        &mut output,
        "}},\"model\":{{\"name\":\"{}\",\"extrapop\":{},\"param_ranges\":",
        json_escape(old_default_handle.get_name()),
        old_default_handle.get_extrapop()
    )
    .unwrap();
    write_ranges(
        &mut output,
        old_default_handle.get_param_range(),
        AddressSpace::Stack,
    );
    write!(
        &mut output,
        ",\"architecture_default_name\":\"{}\",\"default_map_identity\":{},\"default_printed\":{},\"stable_identity\":{{\"decode_return_map\":{},\"decode_return_default\":{},\"old_printed_after_select\":{},\"decoded_printed_when_default\":{},\"decoded_printed_after_restore\":{},\"old_printed_after_restore\":{},\"restored_default_identity\":{}}}}},\"errors\":[",
        json_escape(old_default_handle.get_name()),
        i32::from(initial_map_identity),
        i32::from(old_default_handle.print_in_decl()),
        i32::from(decode_return_map_identity),
        i32::from(decode_return_default_identity),
        i32::from(old_printed_after_select),
        i32::from(decoded_printed_when_default),
        i32::from(decoded_printed_after_restore),
        i32::from(old_printed_after_restore),
        i32::from(restored_default_identity)
    )
    .unwrap();
    for (index, (name, xml, normal_stack)) in errors.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write_error(
            &mut output,
            name,
            &observe_error(xml, *normal_stack, &resolver),
        );
    }
    output.push_str("]}\n");
    Ok(output)
}

fn main() {
    match run() {
        Ok(output) => print!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
