// ARCH-CONTEXT-TRACKED-0001: Rust comparand for the locked Ghidra 12.0.4
// pspec <context_data> tracked-register ingest oracle
// (ContextInternal::decodeFromSpec -> Range::decodeFromAttributes +
// getLastAddrOpen + createSet(partmap clearRange) + decodeTracked +
// TrackedContext::decode + VarnodeData::decodeFromAttributes, reached in
// production through parseProcessorConfig's ELEM_CONTEXT_DATA arm,
// architecture.cc:1190).
//
// The production group reads the locked x86-64.pspec bytes (fixture-local
// Element DOM, same model as cspec_typeorg_state_1204.rs), resolves
// registers through the real .sla via the SLEIGH FFI catalog, and drives
// Architecture::decode_context_data; the C++ side observes the same bytes
// through the live BfdArchitecture::init chain, and the byte diff pins both
// to the same tracked-set state (probes through Architecture::get_tracked_set
// vs ContextDatabase::getTrackedSet).

use rudra::arch::{Architecture, SpecQuery};
use rudra::fspec::VarnodeData as FspecVarnodeData;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::space::AddressSpace;

use std::env;
use std::collections::{HashMap, HashSet};
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
                .ok_or_else(|| "unterminated CDATA section".to_string())?;
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

fn child_named(parent: &Node, name: &str) -> Result<Option<Node>, String> {
    let guard = parent
        .read()
        .map_err(|_| "poisoned XML node".to_string())?;
    Ok(guard
        .children
        .iter()
        .find(|child| {
            child
                .read()
                .map(|node| node.name == name)
                .unwrap_or(false)
        })
        .cloned())
}

// Locked x86-64 space facts (names + highest offsets), pinned to the C++
// oracle's live AddrSpaceManager (the fixture prints ram_highest from this
// table and the byte diff holds it to the oracle's getHighest()).
fn spec_space_by_name(name: &str) -> Option<AddressSpace> {
    match name {
        "ram" => Some(AddressSpace::Ram),
        "stack" => Some(AddressSpace::Stack),
        "register" => Some(AddressSpace::Register),
        "OTHER" | "other" => Some(AddressSpace::Other(1)),
        "unique" => Some(AddressSpace::Unique),
        "const" => Some(AddressSpace::Const),
        _ => None,
    }
}

fn spec_space_highest(spc: AddressSpace) -> u64 {
    match spc {
        AddressSpace::Unique => 0xffff_ffff,
        AddressSpace::Register => 0xffff_ffff,
        _ => u64::MAX,
    }
}

// Language host for the decode: registers resolved through the real .sla
// via the SLEIGH FFI catalog (Translate::getAllRegisters on the C++ side),
// spaces from the locked table.
struct TrackedSpecHost {
    registers: HashMap<String, FspecVarnodeData>,
}

impl TrackedSpecHost {
    fn from_spec_dir(spec_dir: &str) -> Result<Self, String> {
        rudra::sleigh_ffi::set_sla_path(&format!("{spec_dir}/x86-64.sla"));
        let sleigh = rudra::sleigh_ffi::SleighCtx::new()
            .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
        let mut registers = HashMap::new();
        let mut space_ids = HashSet::new();
        for index in 0..sleigh.num_registers() {
            let Some((name, space, offset, size)) = sleigh.register_info(index) else {
                continue;
            };
            space_ids.insert(space);
            registers.insert(
                name,
                FspecVarnodeData {
                    space: AddressSpace::Register,
                    offset,
                    size,
                },
            );
        }
        // getAllRegisters for the locked x86-64 .sla reports exactly one
        // storage space (the register space); refuse anything else instead
        // of silently mislabeling spaces.
        if space_ids.len() != 1 {
            return Err(format!(
                "unexpected register space count {} in SLEIGH catalog",
                space_ids.len()
            ));
        }
        Ok(Self { registers })
    }
}

impl SpecQuery for TrackedSpecHost {
    fn get_register(&self, name: &str) -> Option<FspecVarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<AddressSpace> {
        spec_space_by_name(name)
    }
    fn space_highest(&self, spc: AddressSpace) -> u64 {
        spec_space_highest(spc)
    }
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

// Decode one synthetic <context_data> document into a fresh Architecture.
fn decode_context_xml(arch: &mut Architecture, host: &TrackedSpecHost, xml: &str) -> Result<(), String> {
    let parsed = parse_xml(xml).map_err(|error| format!("synthetic document parse failed: {error}"))?;
    let mut decoder = TreeDecoder::new(parsed.root, parsed.registry);
    arch.decode_context_data(&mut decoder, host)
}

fn write_tracked_entry(out: &mut String, tracked: &rudra::arch::TrackedRegister) {
    write!(
        out,
        "{{\"space\":\"{}\",\"off\":\"{:#x}\",\"size\":{},\"val\":{}}}",
        tracked.loc.space.name(),
        tracked.loc.offset,
        tracked.loc.size,
        tracked.val
    )
    .unwrap();
}

fn write_probe(out: &mut String, arch: &Architecture, space: AddressSpace, space_name: &str, off: u64) {
    let set = arch.get_tracked_set(space, off);
    write!(
        out,
        "{{\"space\":\"{}\",\"off\":\"{:#x}\",\"count\":{},\"entries\":[",
        space_name,
        off,
        set.len()
    )
    .unwrap();
    for (i, tracked) in set.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        write_tracked_entry(out, tracked);
    }
    out.push_str("]}");
}

fn observe_error(host: &TrackedSpecHost, xml: &str) -> String {
    let mut arch = Architecture::new();
    match decode_context_xml(&mut arch, host, xml) {
        Ok(()) => "NO_ERROR".to_string(),
        Err(message) => message,
    }
}

fn run() -> Result<String, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err("usage: arch_context_tracked_1204 <spec-directory>".to_string());
    }
    let spec_dir = args[1].clone();
    let host = TrackedSpecHost::from_spec_dir(&spec_dir)?;

    // production: the locked x86-64.pspec bytes through the mapped decode.
    let pspec_text = fs::read_to_string(format!("{spec_dir}/x86-64.pspec"))
        .map_err(|error| format!("failed to read pspec: {error}"))?;
    let parsed = parse_xml(&pspec_text)?;
    if parsed.root.read().unwrap().name != "processor_spec" {
        return Err("pspec root is not processor_spec".to_string());
    }
    let context_data = child_named(&parsed.root, "context_data")?
        .ok_or_else(|| "missing <context_data> child".to_string())?;
    let mut production = Architecture::new();
    {
        let mut decoder = TreeDecoder::new(context_data, parsed.registry.clone());
        production
            .decode_context_data(&mut decoder, &host)
            .map_err(|error| format!("production decode failed: {error}"))?;
    }

    // cases: fresh decodes of synthetic documents.
    let mut c1 = Architecture::new();
    decode_context_xml(&mut c1, &host,
        "<context_data><tracked_set space=\"ram\">\
         <set name=\"DF\" val=\"0\"/>\
         </tracked_set></context_data>")
        .map_err(|error| format!("c1 failed: {error}"))?;

    let mut c2 = Architecture::new();
    decode_context_xml(&mut c2, &host,
        "<context_data><tracked_set space=\"ram\" first=\"0x100\" last=\"0x1ff\">\
         <set name=\"DF\" val=\"0\"/>\
         <set name=\"EAX\" val=\"1\"/>\
         </tracked_set></context_data>")
        .map_err(|error| format!("c2 failed: {error}"))?;

    let mut c3 = Architecture::new();
    decode_context_xml(&mut c3, &host,
        "<context_data>\
         <tracked_set space=\"ram\" first=\"0x100\" last=\"0x2ff\">\
         <set name=\"DF\" val=\"0\"/>\
         </tracked_set>\
         <tracked_set space=\"ram\" first=\"0x200\" last=\"0x2ff\">\
         <set name=\"DF\" val=\"1\"/>\
         </tracked_set>\
         </context_data>")
        .map_err(|error| format!("c3 failed: {error}"))?;

    let mut c4 = Architecture::new();
    decode_context_xml(&mut c4, &host,
        "<context_data><tracked_set name=\"DF\">\
         <set name=\"DF\" val=\"0\"/>\
         </tracked_set></context_data>")
        .map_err(|error| format!("c4 failed: {error}"))?;

    let mut c5 = Architecture::new();
    decode_context_xml(&mut c5, &host,
        "<context_data><tracked_set space=\"ram\">\
         <set space=\"register\" offset=\"0x20a\" size=\"1\" val=\"0x123\"/>\
         <set name=\"RAX\" val=\"0xffffffffffffffff\"/>\
         </tracked_set></context_data>")
        .map_err(|error| format!("c5 failed: {error}"))?;

    let ram_highest = spec_space_highest(AddressSpace::Ram);
    let mut out = String::new();
    write!(
        &mut out,
        "{{\"schema\":1,\"fixture\":\"ARCH-CONTEXT-TRACKED-0001\"\
         ,\"production\":{{\"ram_highest\":\"{:#x}\",\"context_set_children\":{}\
         ,\"default_count\":{},\"probes\":[",
        ram_highest,
        production.context_set_children_skipped,
        production.get_tracked_default().len()
    )
    .unwrap();
    write_probe(&mut out, &production, AddressSpace::Ram, "ram", 0x0);
    out.push(',');
    write_probe(&mut out, &production, AddressSpace::Ram, "ram", 0x403000);
    out.push(',');
    write_probe(&mut out, &production, AddressSpace::Ram, "ram", ram_highest);
    out.push_str("]},\"cases\":[");
    out.push_str("{\"name\":\"c1_minimal_whole_space\",\"probes\":[");
    write_probe(&mut out, &c1, AddressSpace::Ram, "ram", 0x0);
    out.push(',');
    write_probe(&mut out, &c1, AddressSpace::Ram, "ram", 0x403000);
    out.push(',');
    write_probe(&mut out, &c1, AddressSpace::Ram, "ram", ram_highest);
    out.push_str("]},{\"name\":\"c2_explicit_range_two_sets\",\"probes\":[");
    write_probe(&mut out, &c2, AddressSpace::Ram, "ram", 0xff);
    out.push(',');
    write_probe(&mut out, &c2, AddressSpace::Ram, "ram", 0x100);
    out.push(',');
    write_probe(&mut out, &c2, AddressSpace::Ram, "ram", 0x1ff);
    out.push(',');
    write_probe(&mut out, &c2, AddressSpace::Ram, "ram", 0x200);
    out.push_str("]},{\"name\":\"c3_later_set_overrides\",\"probes\":[");
    write_probe(&mut out, &c3, AddressSpace::Ram, "ram", 0x1ff);
    out.push(',');
    write_probe(&mut out, &c3, AddressSpace::Ram, "ram", 0x200);
    out.push(',');
    write_probe(&mut out, &c3, AddressSpace::Ram, "ram", 0x2ff);
    out.push(',');
    write_probe(&mut out, &c3, AddressSpace::Ram, "ram", 0x300);
    out.push_str("]},{\"name\":\"c4_register_name_range\",\"probes\":[");
    write_probe(&mut out, &c4, AddressSpace::Register, "register", 0x209);
    out.push(',');
    write_probe(&mut out, &c4, AddressSpace::Register, "register", 0x20a);
    out.push(',');
    write_probe(&mut out, &c4, AddressSpace::Register, "register", 0x20b);
    out.push_str("]},{\"name\":\"c5_explicit_varnode_and_max_val\",\"probes\":[");
    write_probe(&mut out, &c5, AddressSpace::Ram, "ram", 0x0);
    out.push_str("]}],\"errors\":[");
    let errors = [
        ("e1_missing_space",
         "<context_data><tracked_set><set name=\"DF\" val=\"0\"/></tracked_set></context_data>"),
        ("e2_bad_child",
         "<context_data><bogus/></context_data>"),
        ("e2b_bad_child_with_range",
         "<context_data><bogus space=\"ram\"/></context_data>"),
        ("e3_reversed_range",
         "<context_data><tracked_set space=\"ram\" first=\"0x10\" last=\"0x8\"><set name=\"DF\" val=\"0\"/></tracked_set></context_data>"),
        ("e4_unknown_register",
         "<context_data><tracked_set space=\"ram\"><set name=\"NOSUCHREG\" val=\"0\"/></tracked_set></context_data>"),
        ("e5_unknown_space",
         "<context_data><tracked_set space=\"nosuchspace\"><set name=\"DF\" val=\"0\"/></tracked_set></context_data>"),
        ("e6_non_set_child",
         "<context_data><tracked_set space=\"ram\"><register val=\"0\"/></tracked_set></context_data>"),
    ];
    for (i, (name, xml)) in errors.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        write!(
            &mut out,
            "{{\"name\":\"{}\",\"error\":\"{}\"}}",
            name,
            json_escape(&observe_error(&host, xml))
        )
        .unwrap();
    }
    out.push_str("],\"done\":1}\n");
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
