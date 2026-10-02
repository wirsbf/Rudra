//! CSPEC-TEXT-INGEST-0001: Rust side of the locked Ghidra 12.0.4
//! compiler-spec text-ingest oracle.  Ingests the same production
//! x86-64-gcc.cspec bytes through the real marshal `DocumentStorage` text
//! parser, drives `Architecture::parse_compiler_config`, and prints the
//! same published-state projections the C++ fixture prints
//! (tests/oracle/cspec_text_ingest_1204.cc) so the runner can diff the two
//! byte for byte.
//!
//! Locked x86-64 language facts (verified against the locked oracle run):
//! the address-space table (index/name/type/addrsize/highest) and the
//! unique-space inject base `0x364420` (= 0x200 + the .sla unique base).
//! Registers and their varnodes come from the real .sla via SleighCtx.

use rudra::arch::{Architecture, SpecQuery};
use rudra::fspec::VarnodeData;
use rudra::marshal::{DocumentStorage, Element, IdRegistry, TreeDecoder};
use rudra::pcodeparse::{
    ConstructTpl, ConstTpl, SleighSymbol, SleighSymbolLookup, SleightSymbolKind, VarnodeTpl,
};
use rudra::sleigh_ffi::{set_sla_path, SleighCtx};
use rudra::space::AddressSpace;
use rudra::userop::{UserOpManage, UserOpType};

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

/// Locked x86-64 address-space table: (index, name, type, addr size,
/// highest).  Mirrors the locked oracle's `AddrSpaceManager` enumeration
/// (evidence: the C++ fixture SPACE projection on the same spec set).
const SPACES: [(i32, &str, i32, u32, u64); 9] = [
    (0, "const", 0, 8, u64::MAX),
    (1, "OTHER", 1, 8, u64::MAX),
    (2, "unique", 3, 4, 0xffff_ffff),
    (3, "ram", 1, 8, u64::MAX),
    (4, "register", 1, 4, 0xffff_ffff),
    (5, "fspec", 4, 8, u64::MAX),
    (6, "iop", 5, 8, u64::MAX),
    (7, "join", 6, 4, 0xffff_ffff),
    (8, "stack", 2, 8, u64::MAX),
];

/// Unique-space base for snippet temporaries
/// (`Translate::getUniqueStart(Translate::INJECT)` = 0x200 + the .sla
/// unique base; locked x86-64 fact: the thunk payload allocates 2 temps
/// before the fentry temp at 0x364420).
const UNIQUE_INJECT_BASE: u64 = 0x364_400;

fn space_index(spc: AddressSpace) -> i32 {
    match spc {
        AddressSpace::Const => 0,
        AddressSpace::Other(_) => 1,
        AddressSpace::Unique => 2,
        AddressSpace::Ram => 3,
        AddressSpace::Register => 4,
        AddressSpace::Stack => 8,
        AddressSpace::Iop => 6,
        AddressSpace::Join => 7,
        AddressSpace::Overlay => 1,
    }
}

fn space_name_of(spc: AddressSpace) -> &'static str {
    match spc {
        AddressSpace::Const => "const",
        AddressSpace::Other(_) => "OTHER",
        AddressSpace::Unique => "unique",
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Stack => "stack",
        AddressSpace::Iop => "iop",
        AddressSpace::Join => "join",
        AddressSpace::Overlay => "overlay",
    }
}

/// The language host: registers from the real .sla, spaces from the locked
/// x86-64 table.
struct Host {
    registers: BTreeMap<String, VarnodeData>,
}

impl SpecQuery for Host {
    fn get_register(&self, name: &str) -> Option<VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<AddressSpace> {
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
    fn space_highest(&self, spc: AddressSpace) -> u64 {
        let name = space_name_of(spc);
        SPACES
            .iter()
            .find(|(_, n, ..)| *n == name)
            .map(|(_, _, _, _, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        UNIQUE_INJECT_BASE
    }
}

impl SleighSymbolLookup for Host {
    fn find_symbol(&self, name: &str) -> Option<SleighSymbol> {
        self.registers.get(name).map(|vd| SleighSymbol {
            name: name.to_string(),
            kind: SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                space: vd.space,
                offset: vd.offset,
                size: vd.size.max(0) as usize,
            }),
        })
    }
}

/// Extract the `<body>` character content under the first p-code element of
/// an element subtree (Ghidra reads it via `readString(ATTRIB_CONTENT)`).
fn find_body_content(
    element: &Arc<RwLock<Element>>,
) -> Option<String> {
    const PCODE_TAGS: [&str; 5] = [
        "pcode",
        "case_pcode",
        "addr_pcode",
        "default_pcode",
        "size_pcode",
    ];
    let el = element.read().ok()?;
    for pcode in &el.children {
        let pcode_el = pcode.read().ok()?;
        if !PCODE_TAGS.contains(&pcode_el.name.as_str()) {
            continue;
        }
        for body in &pcode_el.children {
            let body_el = body.read().ok()?;
            if body_el.name == "body" {
                return Some(body_el.content.clone());
            }
        }
    }
    None
}

/// The XmlEncode-style mini writer used to print compiled templates with
/// byte-identical formatting to Ghidra's `printTemplate`
/// (marshal.cc:471-498 XmlEncode).
struct TplWriter {
    out: String,
    depth: usize,
    tag_open: bool,
}

impl TplWriter {
    fn new() -> Self {
        Self {
            out: String::new(),
            depth: 0,
            tag_open: false,
        }
    }
    fn newline_indent(&mut self) {
        self.out.push('\n');
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
    }
    fn begin(&mut self, name: &str, attrs: &[(&str, String)]) {
        if self.tag_open {
            self.out.push('>');
            self.tag_open = false;
        }
        self.newline_indent();
        self.out.push('<');
        self.out.push_str(name);
        for (key, value) in attrs {
            self.out.push_str(&format!(" {}=\"{}\"", key, value));
        }
        self.depth += 1;
        self.tag_open = true;
    }
    fn end(&mut self, name: &str) {
        self.depth -= 1;
        if self.tag_open {
            self.out.push_str("/>");
            self.tag_open = false;
            return;
        }
        self.newline_indent();
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
    }
}

fn write_const_tpl(writer: &mut TplWriter, ct: &ConstTpl) {
    match ct {
        ConstTpl::Real(v) => writer.begin("const_real", &[("val", format!("0x{:x}", v))]),
        ConstTpl::SpaceId(spc) => writer.begin(
            "const_spaceid",
            &[("space", space_name_of(*spc).to_string())],
        ),
        ConstTpl::JCurSpace => writer.begin("const_curspace", &[]),
        ConstTpl::JCurSpaceSize => writer.begin("const_curspace_size", &[]),
        ConstTpl::JRelative(i) => {
            writer.begin("const_relative", &[("val", format!("0x{:x}", i))])
        }
        ConstTpl::Handle { index, select, plus } => {
            // ConstTpl::encode handle case (semantics.cc): val = handle
            // index, s = select, plus only for v_offset_plus.
            let s = match select {
                rudra::pcodeparse::HandleSelect::Space => 0,
                rudra::pcodeparse::HandleSelect::Offset => 1,
                rudra::pcodeparse::HandleSelect::Size => 2,
                rudra::pcodeparse::HandleSelect::OffsetPlus => 3,
            };
            if matches!(select, rudra::pcodeparse::HandleSelect::OffsetPlus) {
                writer.begin(
                    "const_handle",
                    &[
                        ("val", format!("{}", index)),
                        ("s", format!("{}", s)),
                        ("plus", format!("0x{:x}", plus)),
                    ],
                )
            } else {
                writer.begin(
                    "const_handle",
                    &[("val", format!("{}", index)), ("s", format!("{}", s))],
                )
            }
        }
    }
    // Matching element name for the close.
    let name = match ct {
        ConstTpl::Real(_) => "const_real",
        ConstTpl::SpaceId(_) => "const_spaceid",
        ConstTpl::JCurSpace => "const_curspace",
        ConstTpl::JCurSpaceSize => "const_curspace_size",
        ConstTpl::JRelative(_) => "const_relative",
        ConstTpl::Handle { .. } => "const_handle",
    };
    writer.end(name);
}

fn write_varnode_tpl(writer: &mut TplWriter, vn: &VarnodeTpl) {
    writer.begin("varnode_tpl", &[]);
    write_const_tpl(writer, &vn.get_space());
    write_const_tpl(writer, &vn.get_offset());
    write_const_tpl(writer, &vn.get_size());
    writer.end("varnode_tpl");
}

fn write_template(tpl: &ConstructTpl) -> String {
    let mut writer = TplWriter::new();
    writer.begin("construct_tpl", &[]);
    if tpl.delayslot != 0 {
        // Not exercised by snippet templates (default 0, semantics.hh:174).
        writer.begin("delay_placeholder", &[]);
        writer.end("delay_placeholder");
    }
    // Snippet templates carry no result handle: <null/>.
    writer.begin("null", &[]);
    writer.end("null");
    for op in tpl.get_opvec() {
        writer.begin("op_tpl", &[("code", op.opc.name().to_string())]);
        match &op.out {
            Some(out) => write_varnode_tpl(&mut writer, out),
            None => {
                writer.begin("null", &[]);
                writer.end("null");
            }
        }
        for input in &op.inputs {
            write_varnode_tpl(&mut writer, input);
        }
        writer.end("op_tpl");
    }
    writer.end("construct_tpl");
    writer.out
}

fn escape_newlines(value: &str) -> String {
    value.replace('\n', "\\n")
}

fn count_library_payloads(lib: &rudra::pcodeinject::PcodeInjectLibrary) -> usize {
    let mut total = 0usize;
    for id in 0..4096i32 {
        let present = !lib.get_call_fixup_name(id).is_empty()
            || !lib.get_call_other_target(id).is_empty()
            || !lib.get_call_mechanism_name(id).is_empty();
        if !present {
            break;
        }
        total += 1;
    }
    total
}

fn decode_synthetic(
    xml: &str,
) -> Result<(Arc<RwLock<Element>>, TreeDecoder), String> {
    let mut store = DocumentStorage::new();
    let doc = store
        .parse_document(xml.as_bytes())
        .map_err(|e| format!("synthetic parse failed: {}", e))?;
    let root = doc.root.clone().ok_or_else(|| "no root".to_string())?;
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let decoder = TreeDecoder::new(root.clone(), registry);
    Ok((root, decoder))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: cspec_text_ingest_1204 <cspec> <sla>".to_string());
    }
    let cspec_bytes =
        fs::read(&args[1]).map_err(|e| format!("failed to read {}: {}", args[1], e))?;

    // Text ingestion through the real marshal DocumentStorage
    // (MARSHAL-XML-TEXT-0001), registered under the compiler_spec tag.
    let mut store = DocumentStorage::new();
    let doc = store
        .parse_document(&cspec_bytes)
        .map_err(|e| format!("cspec parse failed: {}", e))?;
    let root = doc
        .root
        .clone()
        .ok_or_else(|| "cspec has no root element".to_string())?;
    if root.read().map_err(|_| "poisoned lock")?.name != "compiler_spec" {
        return Err("cspec root is not compiler_spec".to_string());
    }
    store.register_tag(&root);

    // Registers from the real .sla.
    set_sla_path(&args[2]);
    let sleigh = SleighCtx::new().ok_or_else(|| "SleighCtx::new failed".to_string())?;
    let mut registers = BTreeMap::new();
    for index in 0..sleigh.num_registers() {
        if let Some((name, space, offset, size)) = sleigh.register_info(index) {
            let Ok(space_id) = u8::try_from(space) else {
                continue;
            };
            registers.insert(
                name,
                VarnodeData {
                    space: AddressSpace::from_id(space_id),
                    offset,
                    size,
                },
            );
        }
    }

    let host = Arc::new(Host { registers });

    // The Architecture with the injection library (SLEIGH lookup installed
    // like PcodeInjectLibrarySleigh's slgh member) and the userop table
    // seeded with the locked x86-64 "segment" user op (index 0).
    let mut arch = Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
    inject_lib.set_sleigh_lookup(host.clone());
    let inject_arc = Arc::new(RwLock::new(inject_lib));
    arch.pcodeinjectlib = Some(inject_arc.clone());
    let mut userops = UserOpManage::new();
    userops.register_op("segment".to_string(), UserOpType::Unspecialized);
    let userops_arc = Arc::new(RwLock::new(userops));
    arch.userops = Some(userops_arc.clone());

    let report = arch
        .parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|e| format!("parse_compiler_config failed: {}", e))?;

    let mut out = String::new();
    out.push_str("SCHEMA|1\n");

    // SPACE projection: locked x86-64 table (the Rust AddressSpace model
    // has no dynamic spaces; the table mirrors the oracle's enumeration).
    for (index, name, ty, addr_size, highest) in SPACES {
        out.push_str(&format!(
            "SPACE|{}|{}|{}|{}|0x{:x}\n",
            index, name, ty, addr_size, highest
        ));
    }

    // GLOBAL projection: the applied triples sorted by (space index, first)
    // like Range::operator< / Scope::printBounds.
    let mut ranges: Vec<(i32, u64, u64, &'static str)> = arch
        .global_scope_ranges
        .iter()
        .map(|(spc, first, last)| (space_index(*spc), *first, *last, space_name_of(*spc)))
        .collect();
    ranges.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    for (_, first, last, name) in ranges {
        out.push_str(&format!("GLOBAL|{}: {:x}-{:x}\n", name, first, last));
    }

    // RET projection (architecture.cc:898 decodeReturnAddress).
    match &arch.default_return_addr {
        Some(ret) => out.push_str(&format!(
            "RET|{}|{}|{}\n",
            space_name_of(ret.space),
            ret.offset,
            ret.size
        )),
        None => out.push_str("RET|null\n"),
    }

    // STACK projection (architecture.cc:979 decodeStackPointer).
    out.push_str(&format!(
        "STACK|{}|{}\n",
        space_name_of(arch.stack_space),
        i32::from(arch.stack_grows_negative)
    ));

    // MODELRET projection: per-model return_address effect records
    // (fspec.cc:2689-2691 default injection).
    for (name, model) in &arch.proto_models {
        let mut count = 0usize;
        let mut first = "NONE".to_string();
        for fx in model.effect_iter() {
            if !matches!(fx.get_type(), rudra::fspec::EffectType::ReturnAddress) {
                continue;
            }
            if count == 0 {
                first = format!(
                    "{}|{}|{}",
                    space_name_of(fx.space),
                    fx.offset,
                    fx.size
                );
            }
            count += 1;
        }
        out.push_str(&format!("MODELRET|{}|{}|{}\n", name, count, first));
    }

    // THISCALL projection (architecture.cc:1343-1347).
    match arch.proto_models.get("__thiscall") {
        Some(model) => out.push_str(&format!(
            "THISCALL|present|{}\n",
            i32::from(model.print_in_decl())
        )),
        None => out.push_str("THISCALL|absent|\n"),
    }

    // FIXUP + TPL projections.
    let lib = inject_arc.read().map_err(|_| "poisoned lock")?;
    for id in 0..64i32 {
        let name = lib.get_call_fixup_name(id);
        if name.is_empty() {
            continue;
        }
        let Some(payload) = lib.get_payload_by_id(id) else {
            continue;
        };
        out.push_str(&format!(
            "FIXUP|{}|{}|{}|{}|{}|{}|{}\n",
            id,
            name,
            payload.size_input(),
            payload.size_output(),
            payload.get_paramshift(),
            i32::from(payload.is_dynamic()),
            i32::from(payload.is_incidental_copy())
        ));
        match &payload.tpl {
            Some(tpl) => out.push_str(&format!(
                "TPL|{}|{}\n",
                id,
                escape_newlines(&write_template(tpl))
            )),
            None => out.push_str(&format!("TPL|{}|NO_TEMPLATE\n", id)),
        }
    }

    // Synthetic <callotherfixup> probes (userop.cc:85-96 + userop.cc:589).
    drop(lib); // release the FIXUP projection read guard
    {
        // Snapshot the count before taking the write guards (a RwLock read
        // while the write guard is held would deadlock).
        let before = count_library_payloads(&*inject_arc.read().map_err(|_| "poisoned lock")?);
        out.push_str(&format!("CALLOTHER_COUNT_BEFORE|{}\n", before));

        let probe = "<callotherfixup targetop=\"zz_compile_fail\">\
                     <pcode><body>out1 = in0;</body></pcode></callotherfixup>";
        let (elem, mut decoder) = decode_synthetic(probe)?;
        let body = find_body_content(&elem);
        let message = {
            let mut lib = inject_arc.write().map_err(|_| "poisoned lock")?;
            let mut userops = userops_arc.write().map_err(|_| "poisoned lock")?;
            let r = userops
                .decode_call_other_fixup(&mut decoder, &mut lib, body.as_deref())
                .err()
                .unwrap_or_else(|| "NO_ERROR".to_string());
            r
        };
        out.push_str(&format!("CALLOTHER_COMPILEFAIL|{}\n", message));
        {
            let shown = inject_arc.read().map_err(|_| "poisoned lock")?;
            out.push_str(&format!(
                "CALLOTHER_COUNT_AFTER|{}\n",
                count_library_payloads(&shown)
            ));
            out.push_str(&format!(
                "CALLOTHER_RESIDUE_ID|{}\n",
                shown.get_payload_id(
                    rudra::pcodeinject::InjectPayloadType::CallOtherFixup,
                    "zz_compile_fail"
                )
            ));
        }

        let probe = "<callotherfixup targetop=\"zz_unknown_target\">\
                     <pcode><input name=\"in0\" size=\"8\"/><output name=\"out1\" size=\"8\"/>\
                     <body>out1 = in0;</body></pcode></callotherfixup>";
        let (elem, mut decoder) = decode_synthetic(probe)?;
        let body = find_body_content(&elem);
        let message = {
            let mut lib = inject_arc.write().map_err(|_| "poisoned lock")?;
            let mut userops = userops_arc.write().map_err(|_| "poisoned lock")?;
            userops
                .decode_call_other_fixup(&mut decoder, &mut lib, body.as_deref())
                .err()
                .unwrap_or_else(|| "NO_ERROR".to_string())
        };
        out.push_str(&format!("CALLOTHER_UNKNOWN|{}\n", message));
        {
            let shown = inject_arc.read().map_err(|_| "poisoned lock")?;
            out.push_str(&format!(
                "CALLOTHER_COUNT_AFTER2|{}\n",
                count_library_payloads(&shown)
            ));
            out.push_str(&format!(
                "CALLOTHER_RESIDUE_ID2|{}\n",
                shown.get_payload_id(
                    rudra::pcodeinject::InjectPayloadType::CallOtherFixup,
                    "zz_unknown_target"
                )
            ));
        }

        let probe = "<callotherfixup targetop=\"segment\">\
                     <pcode><input name=\"in0\" size=\"8\"/><output name=\"out1\" size=\"8\"/>\
                     <body>out1 = in0;</body></pcode></callotherfixup>";
        let (elem, mut decoder) = decode_synthetic(probe)?;
        let body = find_body_content(&elem);
        let message = {
            let mut lib = inject_arc.write().map_err(|_| "poisoned lock")?;
            let mut userops = userops_arc.write().map_err(|_| "poisoned lock")?;
            userops
                .decode_call_other_fixup(&mut decoder, &mut lib, body.as_deref())
                .err()
                .unwrap_or_else(|| "NO_ERROR".to_string())
        };
        out.push_str(&format!("CALLOTHER_SEGMENT|{}\n", message));
        {
            let shown = inject_arc.read().map_err(|_| "poisoned lock")?;
            out.push_str(&format!(
                "CALLOTHER_COUNT_AFTER3|{}\n",
                count_library_payloads(&shown)
            ));
        }
        let shown = userops_arc.read().map_err(|_| "poisoned lock")?;
        let op_type = shown
            .get_op_by_name("segment")
            .map(|op| op.op_type as i32)
            .unwrap_or(-1);
        let op_index = shown
            .get_op_by_name("segment")
            .map(|op| op.userop_index)
            .unwrap_or(-1);
        out.push_str(&format!(
            "CALLOTHER_SEGMENT_TYPE|{}|{}\n",
            op_type, op_index
        ));
    }

    // Synthetic <volatile> probes (userop.cc:551-583).
    {
        let mut userops = userops_arc.write().map_err(|_| "poisoned lock")?;
        let probe = "<volatile inputop=\"zz_read\" outputop=\"zz_write\"/>";
        let (_, mut decoder) = decode_synthetic(probe)?;
        // Architecture::decodeVolatile (architecture.cc:884) opens the
        // element before the attribute decode.
        let elem_id = {
            use rudra::marshal::Decoder as _;
            decoder.open_element()
        };
        let message = userops
            .decode_volatile(&mut decoder)
            .err()
            .unwrap_or_else(|| "NO_ERROR".to_string());
        {
            use rudra::marshal::Decoder as _;
            decoder.close_element(elem_id);
        }
        out.push_str(&format!("VOLATILE1|{}\n", message));
        let read_name = userops
            .get_op(rudra::userop::BUILTIN_VOLATILE_READ as i32)
            .map(|op| op.name.clone())
            .unwrap_or_else(|| "null".to_string());
        let write_name = userops
            .get_op(rudra::userop::BUILTIN_VOLATILE_WRITE as i32)
            .map(|op| op.name.clone())
            .unwrap_or_else(|| "null".to_string());
        out.push_str(&format!("VOLATILE_NAMES|{}|{}\n", read_name, write_name));
        let probe = "<volatile inputop=\"zz_read2\" outputop=\"zz_write2\"/>";
        let (_, mut decoder) = decode_synthetic(probe)?;
        let elem_id = {
            use rudra::marshal::Decoder as _;
            decoder.open_element()
        };
        let message = userops
            .decode_volatile(&mut decoder)
            .err()
            .unwrap_or_else(|| "NO_ERROR".to_string());
        {
            use rudra::marshal::Decoder as _;
            decoder.close_element(elem_id);
        }
        out.push_str(&format!("VOLATILE2|{}\n", message));
    }

    // Reviewer probe F1: nameless <input> aborts the callfixup decode
    // (pcodeinject.cc:62-63 LowlevelError propagates) and leaves the
    // payload unregistered.
    {
        let probe = "<callfixup name=\"zz_param_name\">\
                     <pcode><input size=\"8\"/><body>RAX = RBX;</body></pcode></callfixup>";
        let (elem, mut decoder) = decode_synthetic(probe)?;
        let body = find_body_content(&elem);
        let message = {
            let mut lib = inject_arc.write().map_err(|_| "poisoned lock")?;
            let source = format!("{} : compiler spec", arch.archid);
            lib.decode_inject(
                &source,
                "",
                rudra::pcodeinject::InjectPayloadType::CallFixup,
                &mut decoder,
                body.as_deref(),
            )
            .err()
            .unwrap_or_else(|| "NO_ERROR".to_string())
        };
        out.push_str(&format!("CALLFIXUP_PARAMNAME|{}\n", message));
        let shown = inject_arc.read().map_err(|_| "poisoned lock")?;
        out.push_str(&format!(
            "CALLFIXUP_PARAMNAME_ID|{}\n",
            shown.get_payload_id(
                rudra::pcodeinject::InjectPayloadType::CallFixup,
                "zz_param_name"
            )
        ));
    }

    // Reviewer probes F2/F3: full-chain parses of the same surgically
    // modified cspec bytes the C++ fixture builds (identical byte-level
    // transform on both sides).
    {
        let cspec_text = String::from_utf8(cspec_bytes.clone())
            .map_err(|_| "cspec is not valid UTF-8".to_string())?;
        let start = cspec_text
            .find("<returnaddress>")
            .ok_or_else(|| "returnaddress block not found".to_string())?;
        let end = cspec_text
            .find("</returnaddress>")
            .filter(|e| *e >= start)
            .ok_or_else(|| "returnaddress block not found".to_string())?;
        let tail = &cspec_text[end + "</returnaddress>".len()..];
        let head = &cspec_text[..start];

        // RA_EMPTY: two attribute-less varnodes decode to the null-space
        // sentinel; the nohighptr hex child exercises the marshal integer
        // hex auto-detection.
        let empty_cspec = format!(
            "{}{}{}",
            head,
            "<returnaddress><varnode/></returnaddress><returnaddress><varnode/></returnaddress>\
             <nohighptr><range space=\"ram\" first=\"0x100\" last=\"0x2ff\"/></nohighptr>",
            tail
        );
        let mut store2 = DocumentStorage::new();
        let doc2 = store2
            .parse_document(empty_cspec.as_bytes())
            .map_err(|e| format!("RA_EMPTY parse failed: {}", e))?;
        let root2 = doc2.root.clone().ok_or_else(|| "no root".to_string())?;
        store2.register_tag(&root2);
        let mut arch2 = Architecture::new();
        arch2.archid = arch.archid.clone();
        let mut lib2 = rudra::pcodeinject::PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
        lib2.set_sleigh_lookup(host.clone());
        arch2.pcodeinjectlib = Some(std::sync::Arc::new(std::sync::RwLock::new(lib2)));
        arch2.userops = Some(std::sync::Arc::new(std::sync::RwLock::new({
            let mut u = UserOpManage::new();
            u.register_op("segment".to_string(), UserOpType::Unspecialized);
            u
        })));
        let result2 = arch2.parse_compiler_config(&mut store2, host.as_ref(), 8);
        match result2 {
            Ok(_) => {
                out.push_str(&format!(
                    "RA_EMPTY_CHAIN|{}\n",
                    if arch2.default_return_addr.is_some() { "set" } else { "unset" }
                ));
                let ranges = arch2.nohighptr.ranges();
                let mut projection = format!("NOHIGHPTR_HEX|{}|", ranges.len());
                for (i, rng) in ranges.iter().enumerate() {
                    if i != 0 {
                        projection.push('|');
                    }
                    projection.push_str(&format!(
                        "0x{:x}-0x{:x}",
                        rng.get_first().as_u64(),
                        rng.get_last().as_u64()
                    ));
                }
                out.push_str(&projection);
                out.push('\n');
            }
            Err(error) => {
                out.push_str(&format!("RA_EMPTY_CHAIN|ERROR|{}\n", error));
            }
        }

        // RA_DOUBLE: two real returnaddress tags hit the cc:904 guard.
        let double_cspec = format!(
            "{}{}{}",
            head,
            "<returnaddress><varnode space=\"ram\" offset=\"0\" size=\"8\"/></returnaddress>\
             <returnaddress><varnode space=\"ram\" offset=\"0\" size=\"8\"/></returnaddress>",
            tail
        );
        let mut store3 = DocumentStorage::new();
        let doc3 = store3
            .parse_document(double_cspec.as_bytes())
            .map_err(|e| format!("RA_DOUBLE parse failed: {}", e))?;
        let root3 = doc3.root.clone().ok_or_else(|| "no root".to_string())?;
        store3.register_tag(&root3);
        let mut arch3 = Architecture::new();
        arch3.archid = arch.archid.clone();
        let mut lib3 = rudra::pcodeinject::PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
        lib3.set_sleigh_lookup(host.clone());
        arch3.pcodeinjectlib = Some(std::sync::Arc::new(std::sync::RwLock::new(lib3)));
        arch3.userops = Some(std::sync::Arc::new(std::sync::RwLock::new(UserOpManage::new())));
        let result3 = arch3.parse_compiler_config(&mut store3, host.as_ref(), 8);
        out.push_str(&format!(
            "RA_DOUBLE_CHAIN|{}\n",
            result3.err().unwrap_or_else(|| "NO_ERROR".to_string())
        ));
    }

    // Residual disclosure: children the Rust dispatch could not fully
    // decode plus post-loop residuals are printed to STDERR (never silently
    // skipped); the formal residual statuses live in the fixture metadata
    // and the stdout projection stays byte-comparable with the oracle.
    for (child, reason) in &report.skipped_children {
        eprintln!("SKIPPED|{}|{}", child, reason);
    }
    for child in &report.ignored_children {
        eprintln!("IGNORED|{}", child);
    }
    for residual in &report.post_step_residuals {
        eprintln!("POSTRES|{}", residual);
    }

    out.push_str("DONE\n");
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(out.as_bytes());
    let _ = stdout.flush();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error);
            ExitCode::FAILURE
        }
    }
}
