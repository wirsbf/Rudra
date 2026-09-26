//! Marshaling / serialization — faithful port of `marshal.hh` / `marshal.cc`
//! (1273 lines) + `xml.hh` / `xml.cc` (2510 lines, the in-memory DOM tree).
//!
//! Provides the `AttributeId`/`ElementId` registry, the in-memory `Element`/
//! `Document` DOM tree, and the `Encoder`/`Decoder` traits with a concrete
//! XML-based implementation. This is the serialization foundation referenced
//! by database.rs, override.rs, and arch.rs as their XML encode/decode L3 gap.
//!
//! Status: L1→L2. The registry, DOM tree, and Encoder/Decoder traits are
//! complete with a working in-memory `XmlEncode`/`XmlDecode` round-trip.
//! XML text ingestion (`XmlScan` + grammar driver + `DocumentStorage`,
//! MARSHAL-XML-TEXT-0001) parses production XML bytes into the ordered
//! DOM. The Packed binary format (`PackedEncode`/`PackedDecode`) is an
//! L3 gap.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/{marshal,xml}.{hh,cc}.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

/// The locked Ghidra 12.0.4 id for an unrecognized attribute name.
pub const ATTRIB_UNKNOWN: u32 = 159;

/// The locked Ghidra 12.0.4 id for an unrecognized element name.
pub const ELEM_UNKNOWN: u32 = 289;

/// A special attribute id for an element's text content. Faithful to
/// `ATTRIB_CONTENT`.
pub const ATTRIB_CONTENT: u32 = 1;

/// Locked Ghidra 12.0.4 scope-0 attribute name/id table. Missing numeric ids
/// are intentional protocol gaps and must never be compacted or renumbered.
pub const ATTRIBUTE_ID_TABLE: &[(&str, u32)] = &[
    ("XMLcontent", 1),
    ("align", 2),
    ("bigendian", 3),
    ("constructor", 4),
    ("destructor", 5),
    ("extrapop", 6),
    ("format", 7),
    ("hiddenretparm", 8),
    ("id", 9),
    ("index", 10),
    ("indirectstorage", 11),
    ("metatype", 12),
    ("model", 13),
    ("name", 14),
    ("namelock", 15),
    ("offset", 16),
    ("readonly", 17),
    ("ref", 18),
    ("size", 19),
    ("space", 20),
    ("thisptr", 21),
    ("type", 22),
    ("typelock", 23),
    ("val", 24),
    ("value", 25),
    ("wordsize", 26),
    ("first", 27),
    ("last", 28),
    ("uniq", 29),
    ("addrtied", 30),
    ("grp", 31),
    ("input", 32),
    ("persists", 33),
    ("unaff", 34),
    ("blockref", 35),
    ("close", 36),
    ("color", 37),
    ("indent", 38),
    ("off", 39),
    ("open", 40),
    ("opref", 41),
    ("varref", 42),
    ("code", 43),
    ("contain", 44),
    ("defaultspace", 45),
    ("uniqbase", 46),
    ("alignment", 47),
    ("arraysize", 48),
    ("char", 49),
    ("core", 50),
    ("incomplete", 52),
    ("opaquestring", 56),
    ("signed", 57),
    ("structalign", 58),
    ("utf", 59),
    ("varlength", 60),
    ("cat", 61),
    ("field", 62),
    ("merge", 63),
    ("scopeidbyname", 64),
    ("volatile", 65),
    ("class", 66),
    ("repref", 67),
    ("symref", 68),
    ("trunc", 69),
    ("dynamic", 70),
    ("incidentalcopy", 71),
    ("inject", 72),
    ("paramshift", 73),
    ("targetop", 74),
    ("altindex", 75),
    ("depth", 76),
    ("end", 77),
    ("opcode", 78),
    ("rev", 79),
    ("a", 80),
    ("b", 81),
    ("length", 82),
    ("tag", 83),
    ("nocode", 84),
    ("farpointer", 85),
    ("inputop", 86),
    ("outputop", 87),
    ("userop", 88),
    ("base", 89),
    ("deadcodedelay", 90),
    ("delay", 91),
    ("logicalsize", 92),
    ("physical", 93),
    ("piece", 94),
    ("adjustvma", 103),
    ("enable", 104),
    ("group", 105),
    ("growth", 106),
    ("key", 107),
    ("loadersymbols", 108),
    ("parent", 109),
    ("register", 110),
    ("reversejustify", 111),
    ("signext", 112),
    ("style", 113),
    ("custom", 114),
    ("dotdotdot", 115),
    ("extension", 116),
    ("hasthis", 117),
    ("inline", 118),
    ("killedbycall", 119),
    ("maxsize", 120),
    ("minsize", 121),
    ("modellock", 122),
    ("noreturn", 123),
    ("pointermax", 124),
    ("separatefloat", 125),
    ("stackshift", 126),
    ("strategy", 127),
    ("thisbeforeretpointer", 128),
    ("voidlock", 129),
    ("vector_lane_sizes", 130),
    ("label", 131),
    ("num", 132),
    ("lock", 133),
    ("main", 134),
    ("arch", 135),
    ("deprecated", 136),
    ("endian", 137),
    ("processor", 138),
    ("processorspec", 139),
    ("slafile", 140),
    ("spec", 141),
    ("target", 142),
    ("variant", 143),
    ("version", 144),
    ("baddata", 145),
    ("hash", 146),
    ("unimpl", 147),
    ("address", 148),
    ("storage", 149),
    ("stackspill", 150),
    ("sizes", 151),
    ("maxprimitives", 153),
    ("reversesignif", 154),
    ("matchsize", 155),
    ("afterbytes", 156),
    ("afterstorage", 157),
    ("fillalternate", 158),
    ("XMLunknown", 159),
];

/// Locked Ghidra 12.0.4 scope-0 element name/id table. Missing numeric ids
/// are intentional protocol gaps and must never be compacted or renumbered.
pub const ELEMENT_ID_TABLE: &[(&str, u32)] = &[
    ("data", 1),
    ("input", 2),
    ("off", 3),
    ("output", 4),
    ("returnaddress", 5),
    ("symbol", 6),
    ("target", 7),
    ("val", 8),
    ("value", 9),
    ("void", 10),
    ("addr", 11),
    ("range", 12),
    ("rangelist", 13),
    ("register", 14),
    ("seqnum", 15),
    ("varnode", 16),
    ("break", 17),
    ("clang_document", 18),
    ("funcname", 19),
    ("funcproto", 20),
    ("label", 21),
    ("return_type", 22),
    ("statement", 23),
    ("syntax", 24),
    ("vardecl", 25),
    ("variable", 26),
    ("op", 27),
    ("sleigh", 28),
    ("space", 29),
    ("spaceid", 30),
    ("spaces", 31),
    ("space_base", 32),
    ("space_other", 33),
    ("space_overlay", 34),
    ("space_unique", 35),
    ("truncate_space", 36),
    ("char_size", 39),
    ("coretypes", 41),
    ("data_organization", 42),
    ("def", 43),
    ("entry", 47),
    ("enum", 48),
    ("field", 49),
    ("integer_size", 51),
    ("long_size", 54),
    ("pointer_size", 57),
    ("size_alignment_map", 59),
    ("type", 60),
    ("typegrp", 62),
    ("typeref", 63),
    ("wchar_size", 65),
    ("collision", 67),
    ("db", 68),
    ("equatesymbol", 69),
    ("externrefsymbol", 70),
    ("facetsymbol", 71),
    ("functionshell", 72),
    ("hash", 73),
    ("hole", 74),
    ("labelsym", 75),
    ("mapsym", 76),
    ("parent", 77),
    ("property_changepoint", 78),
    ("rangeequalssymbols", 79),
    ("scope", 80),
    ("symbollist", 81),
    ("high", 82),
    ("bytes", 83),
    ("string", 84),
    ("stringmanage", 85),
    ("comment", 86),
    ("commentdb", 87),
    ("text", 88),
    ("addr_pcode", 89),
    ("body", 90),
    ("callfixup", 91),
    ("callotherfixup", 92),
    ("case_pcode", 93),
    ("context", 94),
    ("default_pcode", 95),
    ("inject", 96),
    ("injectdebug", 97),
    ("inst", 98),
    ("payload", 99),
    ("pcode", 100),
    ("size_pcode", 101),
    ("bhead", 102),
    ("block", 103),
    ("blockedge", 104),
    ("edge", 105),
    ("parammeasures", 106),
    ("proto", 107),
    ("rank", 108),
    ("constantpool", 109),
    ("cpoolrec", 110),
    ("ref", 111),
    ("token", 112),
    ("iop", 113),
    ("unimpl", 114),
    ("ast", 115),
    ("function", 116),
    ("highlist", 117),
    ("jumptablelist", 118),
    ("varnodes", 119),
    ("context_data", 120),
    ("context_points", 121),
    ("context_pointset", 122),
    ("context_set", 123),
    ("set", 124),
    ("tracked_pointset", 125),
    ("tracked_set", 126),
    ("constresolve", 127),
    ("jumpassist", 128),
    ("segmentop", 129),
    ("address_shift_amount", 130),
    ("aggressivetrim", 131),
    ("compiler_spec", 132),
    ("data_space", 133),
    ("default_memory_blocks", 134),
    ("default_proto", 135),
    ("default_symbols", 136),
    ("eval_called_prototype", 137),
    ("eval_current_prototype", 138),
    ("experimental_rules", 139),
    ("flowoverridelist", 140),
    ("funcptr", 141),
    ("global", 142),
    ("incidentalcopy", 143),
    ("inferptrbounds", 144),
    ("modelalias", 145),
    ("nohighptr", 146),
    ("processor_spec", 147),
    ("programcounter", 148),
    ("properties", 149),
    ("property", 150),
    ("readonly", 151),
    ("register_data", 152),
    ("rule", 153),
    ("save_state", 154),
    ("segmented_address", 155),
    ("spacebase", 156),
    ("specextensions", 157),
    ("stackpointer", 158),
    ("volatile", 159),
    ("group", 160),
    ("internallist", 161),
    ("killedbycall", 162),
    ("likelytrash", 163),
    ("localrange", 164),
    ("model", 165),
    ("param", 166),
    ("paramrange", 167),
    ("pentry", 168),
    ("prototype", 169),
    ("resolveprototype", 170),
    ("retparam", 171),
    ("returnsym", 172),
    ("unaffected", 173),
    ("aliasblock", 174),
    ("allowcontextset", 175),
    ("analyzeforloops", 176),
    ("commentheader", 177),
    ("commentindent", 178),
    ("commentinstruction", 179),
    ("commentstyle", 180),
    ("conventionprinting", 181),
    ("currentaction", 182),
    ("defaultprototype", 183),
    ("errorreinterpreted", 184),
    ("errortoomanyinstructions", 185),
    ("errorunimplemented", 186),
    ("extrapop", 187),
    ("ignoreunimplemented", 188),
    ("indentincrement", 189),
    ("inferconstptr", 190),
    ("inline", 191),
    ("inplaceops", 192),
    ("integerformat", 193),
    ("jumpload", 194),
    ("maxinstruction", 195),
    ("maxlinewidth", 196),
    ("namespacestrategy", 197),
    ("nocastprinting", 198),
    ("noreturn", 199),
    ("nullprinting", 200),
    ("optionslist", 201),
    ("param1", 202),
    ("param2", 203),
    ("param3", 204),
    ("protoeval", 205),
    ("setaction", 206),
    ("setlanguage", 207),
    ("structalign", 208),
    ("togglerule", 209),
    ("warning", 210),
    ("basicoverride", 211),
    ("dest", 212),
    ("jumptable", 213),
    ("loadtable", 214),
    ("normaddr", 215),
    ("normhash", 216),
    ("startval", 217),
    ("deadcodedelay", 218),
    ("flow", 219),
    ("forcegoto", 220),
    ("indirectoverride", 221),
    ("multistagejump", 222),
    ("override", 223),
    ("protooverride", 224),
    ("prefersplit", 225),
    ("callgraph", 226),
    ("node", 227),
    ("localdb", 228),
    ("doc", 229),
    ("binaryimage", 230),
    ("bytechunk", 231),
    ("compiler", 232),
    ("description", 233),
    ("language", 234),
    ("language_definitions", 235),
    ("xml_savefile", 236),
    ("raw_savefile", 237),
    ("bfd_savefile", 238),
    ("command_isnameused", 239),
    ("command_getbytes", 240),
    ("command_getcallfixup", 241),
    ("command_getcallmech", 242),
    ("command_getcallotherfixup", 243),
    ("command_getcodelabel", 244),
    ("command_getcomments", 245),
    ("command_getcpoolref", 246),
    ("command_getdatatype", 247),
    ("command_getexternalref", 248),
    ("command_getmappedsymbols", 249),
    ("command_getnamespacepath", 250),
    ("command_getpcode", 251),
    ("command_getpcodeexecutable", 252),
    ("command_getregister", 253),
    ("command_getregistername", 254),
    ("command_getstringdata", 255),
    ("command_gettrackedregisters", 256),
    ("command_getuseropname", 257),
    ("blocksig", 258),
    ("call", 259),
    ("gensig", 260),
    ("major", 261),
    ("minor", 262),
    ("copysig", 263),
    ("settings", 264),
    ("sig", 265),
    ("signaturedesc", 266),
    ("signatures", 267),
    ("sigsettings", 268),
    ("varsig", 269),
    ("splitdatatype", 270),
    ("jumptablemax", 271),
    ("nanignore", 272),
    ("datatype", 273),
    ("consume", 274),
    ("consume_extra", 275),
    ("convert_to_ptr", 276),
    ("goto_stack", 277),
    ("join", 278),
    ("datatype_at", 279),
    ("position", 280),
    ("varargs", 281),
    ("hidden_return", 282),
    ("join_per_primitive", 283),
    ("braceformat", 284),
    ("join_dual_class", 285),
    ("internal_storage", 286),
    ("extra_stack", 287),
    ("consume_remaining", 288),
    ("XMLunknown", 289),
];

/// An annotation for a data element being transferred to/from a stream.
/// Faithful to `AttributeId` (marshal.hh:41).
#[derive(Debug, Clone)]
pub struct AttributeId {
    /// The name of the attribute.
    pub name: String,
    /// The internal id of the attribute.
    pub id: u32,
}

impl AttributeId {
    /// Construct a const placeholder with the numeric id.
    /// The name cannot be retained by this const initializer.
    // RUGRA-GLUE: Const placeholder; unlike Ghidra's constructor, it cannot retain the name or register globally.
    pub const fn new_static(nm: &'static str, id: u32) -> Self {
        Self {
            name: String::new(), // Will be set at runtime; const can't allocate.
            id,
        }
    }

    // Ghidra: marshal.cc:45 AttributeId::new
    /// Construct at runtime.
    pub fn new(nm: &str, id: u32) -> Self {
        Self {
            name: nm.to_string(),
            id,
        }
    }

    // Ghidra: marshal.cc:45 AttributeId::getName
    /// Get the attribute's name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: marshal.cc:45 AttributeId::getId
    /// Get the attribute's id.
    pub fn get_id(&self) -> u32 {
        self.id
    }
}

impl PartialEq for AttributeId {
    // Ghidra: marshal.cc:45 AttributeId::eq
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

/// An annotation for a specific collection of hierarchical data. Faithful to
/// `ElementId` (marshal.hh:65).
#[derive(Debug, Clone)]
pub struct ElementId {
    /// The name of the element.
    pub name: String,
    /// The internal id of the element.
    pub id: u32,
}

impl ElementId {
    // Ghidra: marshal.cc:87 ElementId::new
    /// Construct given a name and id.
    pub fn new(nm: &str, id: u32) -> Self {
        Self {
            name: nm.to_string(),
            id,
        }
    }

    // Ghidra: marshal.cc:87 ElementId::getName
    /// Get the element's name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: marshal.cc:87 ElementId::getId
    /// Get the element's id.
    pub fn get_id(&self) -> u32 {
        self.id
    }
}

impl PartialEq for ElementId {
    // Ghidra: marshal.cc:87 ElementId::eq
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

#[derive(Debug, Default)]
struct IdTables {
    attr_by_name: HashMap<&'static str, u32>,
    attr_by_id: HashMap<u32, &'static str>,
    elem_by_name: HashMap<&'static str, u32>,
    elem_by_id: HashMap<u32, &'static str>,
}

static ID_TABLES: OnceLock<IdTables> = OnceLock::new();

// Ghidra: marshal.cc:54 AttributeId::initialize
fn initialize_attribute_ids(tables: &mut IdTables) {
    for &(name, id) in ATTRIBUTE_ID_TABLE {
        tables.attr_by_name.insert(name, id);
        tables.attr_by_id.insert(id, name);
    }
}

// Ghidra: marshal.cc:96 ElementId::initialize
fn initialize_element_ids(tables: &mut IdTables) {
    for &(name, id) in ELEMENT_ID_TABLE {
        tables.elem_by_name.insert(name, id);
        tables.elem_by_id.insert(id, name);
    }
}

// RUGRA-GLUE: Combines the two Ghidra global lookup tables behind Rust's OnceLock.
fn build_id_tables() -> IdTables {
    let mut tables = IdTables::default();
    initialize_attribute_ids(&mut tables);
    initialize_element_ids(&mut tables);
    tables
}

// RUGRA-GLUE: Rust process-wide access to Ghidra's two static lookup tables.
fn id_tables() -> &'static IdTables {
    ID_TABLES.get_or_init(build_id_tables)
}

/// Process-wide fixed registry of locked Ghidra 12.0.4 scope-0 ids.
///
/// The value has no per-instance allocation or numbering state. All instances
/// address the same immutable tables initialized from `ATTRIBUTE_ID_TABLE` and
/// `ELEMENT_ID_TABLE`.
#[derive(Debug, Default)]
pub struct IdRegistry;

impl IdRegistry {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Access the fixed process-wide registry.
    pub fn new() -> Self {
        Self::initialize();
        Self
    }

    // RUGRA-GLUE: One Rust entry point invokes both Ghidra initialize methods.
    /// Initialize the process-wide tables. Repeated calls preserve the exact
    /// same table and have no observable mutation.
    pub fn initialize() {
        let _ = id_tables();
    }

    // RUGRA-GLUE: register_attribute (no Ghidra counterpart found)
    /// Compatibility lookup for callers that formerly registered names.
    /// Unknown input returns `ATTRIB_UNKNOWN`; no id is allocated.
    pub fn register_attribute(&mut self, nm: &str) -> u32 {
        self.find_attribute(nm)
    }

    // RUGRA-GLUE: register_attribute_with_id (no Ghidra counterpart found)
    /// Compatibility validation hook. Returns whether the pair is part of the
    /// locked table; runtime input can never mutate the process table.
    pub fn register_attribute_with_id(&mut self, nm: &str, id: u32) -> bool {
        self.find_attribute(nm) == id && self.attribute_name(id) == Some(nm)
    }

    // Ghidra: marshal.hh:686 AttributeId::find
    /// Look up an attribute id by name. Returns ATTRIB_UNKNOWN if not found.
    pub fn find_attribute(&self, nm: &str) -> u32 {
        self.find_attribute_in_scope(nm, 0)
    }

    // Ghidra: marshal.hh:686 AttributeId::find
    /// Look up an attribute in a Ghidra marshal scope. Locked 12.0.4 only
    /// supports reverse lookup for scope zero.
    pub fn find_attribute_in_scope(&self, nm: &str, scope: i32) -> u32 {
        if scope != 0 {
            return ATTRIB_UNKNOWN;
        }
        id_tables()
            .attr_by_name
            .get(nm)
            .copied()
            .unwrap_or(ATTRIB_UNKNOWN)
    }

    // RUGRA-GLUE: attribute_name (no Ghidra counterpart found)
    /// Look up an attribute name by id.
    pub fn attribute_name(&self, id: u32) -> Option<&str> {
        id_tables().attr_by_id.get(&id).copied()
    }

    // RUGRA-GLUE: register_element (no Ghidra counterpart found)
    /// Compatibility lookup for callers that formerly registered names.
    /// Unknown input returns `ELEM_UNKNOWN`; no id is allocated.
    pub fn register_element(&mut self, nm: &str) -> u32 {
        self.find_element(nm)
    }

    // RUGRA-GLUE: register_element_with_id (no Ghidra counterpart found)
    /// Compatibility validation hook. Returns whether the pair is part of the
    /// locked table; runtime input can never mutate the process table.
    pub fn register_element_with_id(&mut self, nm: &str, id: u32) -> bool {
        self.find_element(nm) == id && self.element_name(id) == Some(nm)
    }

    // Ghidra: marshal.hh:702 ElementId::find
    /// Look up an element id by name. Returns `ELEM_UNKNOWN` if not found.
    pub fn find_element(&self, nm: &str) -> u32 {
        self.find_element_in_scope(nm, 0)
    }

    // Ghidra: marshal.hh:702 ElementId::find
    /// Look up an element in a Ghidra marshal scope. Locked 12.0.4 only
    /// supports reverse lookup for scope zero.
    pub fn find_element_in_scope(&self, nm: &str, scope: i32) -> u32 {
        if scope != 0 {
            return ELEM_UNKNOWN;
        }
        id_tables()
            .elem_by_name
            .get(nm)
            .copied()
            .unwrap_or(ELEM_UNKNOWN)
    }

    // RUGRA-GLUE: element_name (no Ghidra counterpart found)
    /// Look up an element name by id.
    pub fn element_name(&self, id: u32) -> Option<&str> {
        id_tables().elem_by_id.get(&id).copied()
    }
}

/// An XML element — a node in the DOM tree. Faithful to `Element`
/// (xml.hh:159). Owned by its parent; children are stored as `Arc<RwLock<>>`
/// to allow shared reference during decode.
#[derive(Debug, Clone)]
pub struct Element {
    /// The local name of the element.
    pub name: String,
    /// Character content of the element.
    pub content: String,
    /// Attribute names (parallel to `values`).
    pub attr_names: Vec<String>,
    /// Attribute values (parallel to `attr_names`).
    pub attr_values: Vec<String>,
    /// Child elements.
    pub children: Vec<Arc<RwLock<Element>>>,
}

impl Element {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct an empty element.
    pub fn new() -> Self {
        Self {
            name: String::new(),
            content: String::new(),
            attr_names: Vec::new(),
            attr_values: Vec::new(),
            children: Vec::new(),
        }
    }

    // RUGRA-GLUE: set_name (no Ghidra counterpart found)
    /// Set the local name of the element. Faithful to `setName`.
    pub fn set_name(&mut self, nm: &str) {
        self.name = nm.to_string();
    }

    // RUGRA-GLUE: add_content (no Ghidra counterpart found)
    /// Append character content. Faithful to `addContent`.
    pub fn add_content(&mut self, s: &str) {
        self.content.push_str(s);
    }

    // RUGRA-GLUE: add_child (no Ghidra counterpart found)
    /// Add a child element. Faithful to `addChild`.
    pub fn add_child(&mut self, child: Arc<RwLock<Element>>) {
        self.children.push(child);
    }

    // RUGRA-GLUE: add_attribute (no Ghidra counterpart found)
    /// Add a name/value attribute pair. Faithful to `addAttribute`.
    pub fn add_attribute(&mut self, nm: &str, vl: &str) {
        self.attr_names.push(nm.to_string());
        self.attr_values.push(vl.to_string());
    }

    // RUGRA-GLUE: get_name (no Ghidra counterpart found)
    /// Get the local name. Faithful to `getName`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // RUGRA-GLUE: get_content (no Ghidra counterpart found)
    /// Get the character content. Faithful to `getContent`.
    pub fn get_content(&self) -> &str {
        &self.content
    }

    // RUGRA-GLUE: get_children (no Ghidra counterpart found)
    /// Get the child elements. Faithful to `getChildren`.
    pub fn get_children(&self) -> &[Arc<RwLock<Element>>] {
        &self.children
    }

    // RUGRA-GLUE: get_attribute_value (no Ghidra counterpart found)
    /// Get an attribute value by name. Returns None if not found. Faithful to
    /// `getAttributeValue` (which throws; we return Option).
    pub fn get_attribute_value(&self, nm: &str) -> Option<&str> {
        for (i, name) in self.attr_names.iter().enumerate() {
            if name == nm {
                return Some(&self.attr_values[i]);
            }
        }
        None
    }

    // RUGRA-GLUE: get_num_attributes (no Ghidra counterpart found)
    /// Get the number of attributes. Faithful to `getNumAttributes`.
    pub fn get_num_attributes(&self) -> usize {
        self.attr_names.len()
    }

    // RUGRA-GLUE: get_attribute_name (no Ghidra counterpart found)
    /// Get the name of the i-th attribute. Faithful to `getAttributeName`.
    pub fn get_attribute_name(&self, i: usize) -> &str {
        &self.attr_names[i]
    }

    // RUGRA-GLUE: get_attribute_value_at (no Ghidra counterpart found)
    /// Get the value of the i-th attribute. Faithful to `getAttributeValue(i)`.
    pub fn get_attribute_value_at(&self, i: usize) -> &str {
        &self.attr_values[i]
    }
}

impl Default for Element {
    // RUGRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

/// A complete in-memory XML document. Faithful to `Document` (xml.hh:215).
/// This is an `Element` whose single child is the root element.
#[derive(Debug, Clone, Default)]
pub struct Document {
    /// The root element of the document.
    pub root: Option<Arc<RwLock<Element>>>,
}

impl Document {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct an empty document.
    pub fn new() -> Self {
        Self { root: None }
    }

    // RUGRA-GLUE: get_root (no Ghidra counterpart found)
    /// Get the root element. Faithful to `getRoot`.
    pub fn get_root(&self) -> Option<&Arc<RwLock<Element>>> {
        self.root.as_ref()
    }

    // RUGRA-GLUE: set_root (no Ghidra counterpart found)
    /// Set the root element.
    pub fn set_root(&mut self, root: Arc<RwLock<Element>>) {
        self.root = Some(root);
    }
}

// ===========================================================================
// XML text ingestion — the `xml.cc` scanner + grammar (MARSHAL-XML-TEXT-0001).
//
// Ghidra parses XML text with a hand-written byte scanner (`XmlScan`,
// xml.cc:111-177/2080-2375) driven by a bison LALR grammar (xml.y, compiled
// into xml.cc). The Rust port below is a 1:1 port of the scanner plus a
// recursive-descent realization of the same grammar with identical actions
// and identical token-read timing: every mode-switching reduce in the bison
// output is a default reduction (single complete item / only-action state),
// so each action runs before the next token is read. The parser keeps at
// most one lookahead token and defers reading it (`ensure`) exactly like
// bison, so the scanner mode at each read matches Ghidra byte for byte.
// ===========================================================================

/// Scanner token values above the raw byte range. Faithful to the
/// `XmlScan::token` enumeration (xml.cc:118-126).
const CHAR_DATA_TOKEN: i32 = 258;
const CDATA_TOKEN: i32 = 259;
const ATT_VALUE_TOKEN: i32 = 260;
const COMMENT_TOKEN: i32 = 261;
const CHAR_REF_TOKEN: i32 = 262;
const NAME_TOKEN: i32 = 263;
const SNAME_TOKEN: i32 = 264;
const ELEMENT_BRACE_TOKEN: i32 = 265;
const COMMAND_BRACE_TOKEN: i32 = 266;

/// The byte value returned for end-of-file tokens. Bison maps any token
/// value `<= 0` to `$end` (xml.cc:1521-1523); the scanner produces -1 after
/// its single synthetic `'\n'` fill (xml.cc:141-157).
const TOKEN_EOF: i32 = -1;

/// The XML character scanner modes. Faithful to the `XmlScan::mode`
/// enumeration (xml.cc:114-116). Modes are one-shot: `nexttoken` resets to
/// `Single` before dispatching (xml.cc:2285).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    /// Look for `<`, `&`, or `]]>`.
    CharData,
    /// Looking for `]]>`.
    CData,
    /// Attribute value with single quotes.
    AttValueSingle,
    /// Attribute value with double quotes.
    AttValueDouble,
    /// Looking for `--`.
    Comment,
    /// Character references: decimal or hex digits.
    CharRef,
    /// Look for non-name char.
    Name,
    /// Scan a Name, allowing white space before.
    SName,
    /// Single character mode.
    Single,
}

/// An XML character scanner over a byte buffer. Faithful to `XmlScan`
/// (xml.cc:111-177): a 4-byte ring-buffer lookahead so multi-byte XML
/// sequences can be checked without consuming, with a single synthetic
/// `'\n'` entering the stream at end-of-stream (a NUL byte also terminates
/// the stream, xml.cc:146-148).
struct XmlScan<'a> {
    /// The current scanning mode (one-shot per token).
    curmode: ScanMode,
    /// The byte buffer being scanned (the `istream &s`).
    input: &'a [u8],
    /// Read position into `input`.
    inpos: usize,
    /// Raw bytes of the current token string being built (the `string *lvalue`).
    lbytes: Vec<u8>,
    /// The 4-byte lookahead ring buffer.
    lookahead: [i32; 4],
    /// Current position in the lookahead buffer.
    pos: usize,
    /// Has end of stream been reached.
    endofstream: bool,
}

impl<'a> XmlScan<'a> {
    // Ghidra: xml.cc:2080 XmlScan::XmlScan(istream &t)
    /// Construct the scanner and fill the lookahead buffer.
    fn new(input: &'a [u8]) -> Self {
        let mut scan = Self {
            curmode: ScanMode::Single,
            input,
            inpos: 0,
            lbytes: Vec::new(),
            lookahead: [0; 4],
            pos: 0,
            endofstream: false,
        };
        scan.getxmlchar();
        scan.getxmlchar();
        scan.getxmlchar();
        scan.getxmlchar(); // Fill lookahead buffer
        scan
    }

    // Ghidra: xml.cc:2096 void XmlScan::clearlvalue(void)
    /// Clear the current token string.
    fn clearlvalue(&mut self) {
        self.lbytes.clear();
    }

    // Ghidra: xml.cc:141 int4 getxmlchar(void)
    /// Get the next byte in the stream, maintaining the 4-byte lookahead so
    /// special XML character sequences can be checked without consuming.
    fn getxmlchar(&mut self) -> i32 {
        let ret = self.lookahead[self.pos];
        if !self.endofstream {
            let fetched = if self.inpos < self.input.len() {
                let byte = self.input[self.inpos];
                self.inpos += 1;
                Some(byte)
            } else {
                None // istream get() failure sets eofbit
            };
            match fetched {
                Some(0) | None => {
                    // s.eof() || c == '\0': terminate and pad once with '\n'
                    self.endofstream = true;
                    self.lookahead[self.pos] = b'\n' as i32;
                }
                Some(byte) => {
                    self.lookahead[self.pos] = byte as i32;
                }
            }
        } else {
            self.lookahead[self.pos] = TOKEN_EOF;
        }
        self.pos = (self.pos + 1) & 3;
        ret
    }

    // Ghidra: xml.cc:158 int4 next(int4 i)
    /// Peek at the next (i-th) byte without consuming.
    fn next(&self, i: usize) -> i32 {
        self.lookahead[(self.pos + i) & 3]
    }

    // Ghidra: xml.cc:159 bool isLetter(int4 val)
    /// Is the given byte an ASCII letter.
    fn is_letter(val: i32) -> bool {
        (0x41..=0x5a).contains(&val) || (0x61..=0x7a).contains(&val)
    }

    // Ghidra: xml.cc:2256 bool XmlScan::isInitialNameChar(int4 val)
    /// Is the given byte the valid start of an XML name.
    fn is_initial_name_char(val: i32) -> bool {
        if Self::is_letter(val) {
            return true;
        }
        val == '_' as i32 || val == ':' as i32
    }

    // Ghidra: xml.cc:2264 bool XmlScan::isNameChar(int4 val)
    /// Is the given byte valid inside an XML name.
    fn is_name_char(val: i32) -> bool {
        if Self::is_letter(val) {
            return true;
        }
        if ('0' as i32..='9' as i32).contains(&val) {
            return true;
        }
        val == '.' as i32 || val == '-' as i32 || val == '_' as i32 || val == ':' as i32
    }

    // Ghidra: xml.cc:2273 bool XmlScan::isChar(int4 val)
    /// Is the given byte valid as an XML character.
    fn is_char(val: i32) -> bool {
        if val >= 0x20 {
            return true;
        }
        val == 0xd || val == 0xa || val == 0x9
    }

    // Ghidra: xml.cc:2103 int4 XmlScan::scanSingle(void)
    /// Scan for the next token in single character mode.
    fn scan_single(&mut self) -> i32 {
        let res = self.getxmlchar();
        if res == '<' as i32 {
            if Self::is_initial_name_char(self.next(0)) {
                return ELEMENT_BRACE_TOKEN;
            }
            return COMMAND_BRACE_TOKEN;
        }
        res
    }

    // Ghidra: xml.cc:2114 int4 XmlScan::scanCharData(void)
    /// Scan for the next token in character data mode, looking for `<`, `&`,
    /// or `]]>`.
    fn scan_char_data(&mut self) -> i32 {
        self.clearlvalue();
        while self.next(0) != TOKEN_EOF {
            if self.next(0) == '<' as i32 {
                break;
            }
            if self.next(0) == '&' as i32 {
                break;
            }
            if self.next(0) == ']' as i32
                && self.next(1) == ']' as i32
                && self.next(2) == '>' as i32
            {
                break;
            }
            let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
        }
        if self.lbytes.is_empty() {
            return self.scan_single();
        }
        CHAR_DATA_TOKEN
    }

    // Ghidra: xml.cc:2134 int4 XmlScan::scanCData(void)
    /// Scan for the next token in CDATA mode, looking for `]]>` and non-Chars.
    /// CDATA can be empty.
    fn scan_cdata(&mut self) -> i32 {
        self.clearlvalue();
        while self.next(0) != TOKEN_EOF {
            if self.next(0) == ']' as i32
                && self.next(1) == ']' as i32
                && self.next(2) == '>' as i32
            {
                break;
            }
            if !Self::is_char(self.next(0)) {
                break;
            }
            let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
        }
        CDATA_TOKEN
    }

    // Ghidra: xml.cc:2151 int4 XmlScan::scanCharRef(void)
    /// Scan for the next token in character reference mode (decimal or hex
    /// digits; the hex form keeps its `x` prefix in the token string).
    fn scan_char_ref(&mut self) -> i32 {
        self.clearlvalue();
        if self.next(0) == 'x' as i32 {
            let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
            while self.next(0) != TOKEN_EOF {
                let v = self.next(0);
                if v < '0' as i32 {
                    break;
                }
                if v > '9' as i32 && v < 'A' as i32 {
                    break;
                }
                if v > 'F' as i32 && v < 'a' as i32 {
                    break;
                }
                if v > 'f' as i32 {
                    break;
                }
                let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
            }
            if self.lbytes.len() == 1 {
                return 'x' as i32; // Must be at least 1 hex digit
            }
        } else {
            while self.next(0) != TOKEN_EOF {
                let v = self.next(0);
                if v < '0' as i32 {
                    break;
                }
                if v > '9' as i32 {
                    break;
                }
                let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
            }
            if self.lbytes.is_empty() {
                return self.scan_single();
            }
        }
        CHAR_REF_TOKEN
    }

    // Ghidra: xml.cc:2183 int4 XmlScan::scanAttValue(int4 quote)
    /// Scan for the next token in attribute value mode, stopping at the
    /// closing quote, `<`, or `&`.
    fn scan_att_value(&mut self, quote: u8) -> i32 {
        self.clearlvalue();
        while self.next(0) != TOKEN_EOF {
            if self.next(0) == quote as i32 {
                break;
            }
            if self.next(0) == '<' as i32 {
                break;
            }
            if self.next(0) == '&' as i32 {
                break;
            }
            let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
        }
        if self.lbytes.is_empty() {
            return self.scan_single();
        }
        ATT_VALUE_TOKEN
    }

    // Ghidra: xml.cc:2199 int4 XmlScan::scanComment(void)
    /// Scan for the next token in comment mode, looking for `--`.
    fn scan_comment(&mut self) -> i32 {
        self.clearlvalue();
        while self.next(0) != TOKEN_EOF {
            if self.next(0) == '-' as i32 && self.next(1) == '-' as i32 {
                break;
            }
            if !Self::is_char(self.next(0)) {
                break;
            }
            let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
        }
        COMMENT_TOKEN
    }

    // Ghidra: xml.cc:2215 int4 XmlScan::scanName(void)
    /// Scan a Name, or return a single non-name character.
    fn scan_name(&mut self) -> i32 {
        self.clearlvalue();
        if !Self::is_initial_name_char(self.next(0)) {
            return self.scan_single();
        }
        let byte = self.getxmlchar();
        self.lbytes.push(byte as u8);
        while self.next(0) != TOKEN_EOF {
            if !Self::is_name_char(self.next(0)) {
                break;
            }
            let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
        }
        NAME_TOKEN
    }

    // Ghidra: xml.cc:2231 int4 XmlScan::scanSName(void)
    /// Scan a Name, allowing white space before. Consumed white space is
    /// reported as a single literal `' '` token when no Name follows.
    fn scan_sname(&mut self) -> i32 {
        let mut whitecount = 0usize;
        while self.next(0) == ' ' as i32
            || self.next(0) == '\n' as i32
            || self.next(0) == '\r' as i32
            || self.next(0) == '\t' as i32
        {
            whitecount += 1;
            self.getxmlchar();
        }
        self.clearlvalue();
        if !Self::is_initial_name_char(self.next(0)) {
            // First non-whitespace is not a Name char
            if whitecount > 0 {
                return ' ' as i32;
            }
            return self.scan_single();
        }
        let byte = self.getxmlchar();
        self.lbytes.push(byte as u8);
        while self.next(0) != TOKEN_EOF {
            if !Self::is_name_char(self.next(0)) {
                break;
            }
            let byte = self.getxmlchar();
            self.lbytes.push(byte as u8);
        }
        if whitecount > 0 {
            return SNAME_TOKEN;
        }
        NAME_TOKEN
    }

    // Ghidra: xml.cc:2281 int4 XmlScan::nexttoken(void)
    /// Get the next token, dispatching on (and resetting) the current mode.
    fn nexttoken(&mut self) -> i32 {
        let mymode = self.curmode;
        self.curmode = ScanMode::Single;
        match mymode {
            ScanMode::CharData => self.scan_char_data(),
            ScanMode::CData => self.scan_cdata(),
            ScanMode::AttValueSingle => self.scan_att_value(b'\''),
            ScanMode::AttValueDouble => self.scan_att_value(b'"'),
            ScanMode::Comment => self.scan_comment(),
            ScanMode::CharRef => self.scan_char_ref(),
            ScanMode::Name => self.scan_name(),
            ScanMode::SName => self.scan_sname(),
            ScanMode::Single => self.scan_single(),
        }
    }

    // Ghidra: xml.cc:174 void setmode(mode m)
    /// Set the scanning mode.
    fn setmode(&mut self, m: ScanMode) {
        self.curmode = m;
    }

    // Ghidra: xml.cc:176 string *lval(void)
    /// Return the last token string (taking ownership).
    fn lval(&mut self) -> String {
        String::from_utf8_lossy(&self.lbytes).into_owned()
    }
}

// Ghidra: xml.cc:2326 int4 convertEntityRef(const string &ref)
/// Convert an XML entity to its equivalent character, or -1 when unknown.
fn convert_entity_ref(name: &str) -> i32 {
    match name {
        "lt" => '<' as i32,
        "amp" => '&' as i32,
        "gt" => '>' as i32,
        "quot" => '"' as i32,
        "apos" => '\'' as i32,
        _ => -1,
    }
}

// Ghidra: xml.cc:2337 int4 convertCharRef(const string &ref)
/// Convert an XML character reference (`x`-prefixed hex or decimal) to its
/// character value.
fn convert_char_ref(text: &str) -> i32 {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mult: i32;
    if !bytes.is_empty() && bytes[0] == b'x' {
        i = 1;
        mult = 16;
    } else {
        mult = 10;
    }
    let mut val: i32 = 0;
    while i < bytes.len() {
        let cur: i32 = if bytes[i] <= b'9' {
            (bytes[i] - b'0') as i32
        } else if bytes[i] <= b'F' {
            10 + (bytes[i] - b'A') as i32
        } else {
            10 + (bytes[i] - b'a') as i32
        };
        // KUNAUB-CHARREF-0001: the C++ `int4` accumulator overflows silently
        // on hostile long digit runs (xml.cc:2356-2357 has no cap); the de
        // facto oracle behavior on the locked x86-64 build is two's-complement
        // wraparound, which Rust release mirrors but debug panics on. Use
        // explicit wrapping ops so debug == release == de-facto-C++.
        val = val.wrapping_mul(mult);
        val = val.wrapping_add(cur);
        i += 1;
    }
    val
}

// RUGRA-GLUE: push_reference_char（对应 xml.cc:1610/1628/1790 语法动作里的
// `*lvalue += (yyvsp[0].i)` —— C++ 经 string::operator+=(char) 截断为单字节；
// Rust String 侧以 UTF-8 编码同一低字节，ASCII 域 byte-exact，>=0x80 为已登记残余）
/// Append a converted reference character the way `string::operator+=(char)`
/// does in the grammar actions: the codepoint is truncated to a single byte.
fn push_reference_char(buffer: &mut String, val: i32) {
    if let Some(ch) = char::from_u32((val as u8) as u32) {
        buffer.push(ch);
    }
}

/// The attributes collected for a single element during parsing. Faithful
/// to the SAX `Attributes` container (xml.hh:45-78): it holds the element
/// name plus ordered name/value pairs and is not part of the final DOM.
struct XmlAttributes {
    /// The name of the XML element.
    element_name: String,
    /// Ordered attribute names.
    names: Vec<String>,
    /// Ordered attribute values.
    values: Vec<String>,
}

impl XmlAttributes {
    // Ghidra: xml.hh:52 Attributes(string *el)
    /// Construct from the element name string.
    fn new(element_name: String) -> Self {
        Self {
            element_name,
            names: Vec::new(),
            values: Vec::new(),
        }
    }

    // Ghidra: xml.hh:59 void add_attribute(string *nm, string *vl)
    /// Add a formal attribute, preserving source order.
    fn add_attribute(&mut self, nm: String, vl: String) {
        self.names.push(nm);
        self.values.push(vl);
    }
}

/// The error thrown by the XML parser. Faithful to `struct DecoderError`
/// (xml.hh:297-300): it holds the explanatory string passed to the SAX
/// `setError` callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderError {
    /// Explanatory string.
    pub explain: String,
}

impl DecoderError {
    // RUGRA-GLUE: constructor mirroring DecoderError(const string &s)
    /// Construct with the explanatory string.
    pub fn new(s: impl Into<String>) -> Self {
        Self { explain: s.into() }
    }
}

impl std::fmt::Display for DecoderError {
    // RUGRA-GLUE: Display for the error type (C++ has no Display)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.explain)
    }
}

impl std::error::Error for DecoderError {}

// RUGRA-GLUE: is_ws_token（xml.y:143-148 whitespace/S 产生式的 token 分类，
/// scanner 在 SingleMode 逐字符产出空白 token，scanSName 把前导空白物化为 ' '）
/// Is the token a single XML whitespace character token?
fn is_ws_token(tok: i32) -> bool {
    tok == ' ' as i32 || tok == '\n' as i32 || tok == '\r' as i32 || tok == '\t' as i32
}

/// The tree-building parse of one XML document. Combines the bison parser
/// driver (`xmlparse`, xml.cc:269/1362) with the `TreeHandler` DOM builder
/// (xml.cc:2394-2415). A single lookahead token is kept and read lazily so
/// every grammar action (notably the scanner mode switches) runs at exactly
/// the same point between token reads as the bison default reductions do.
struct XmlTreeParser<'a> {
    /// The scanner.
    scan: XmlScan<'a>,
    /// The stack of open elements (`TreeHandler` root/cur pointers).
    stack: Vec<Arc<RwLock<Element>>>,
    /// The last error condition (`TreeHandler::error`).
    error: String,
    /// Current lookahead token (`yychar`); TOKEN_EOF when never read.
    tok: i32,
    /// Whether `tok` holds a valid lookahead (bison's YYEMPTY distinction).
    tok_valid: bool,
    /// The `yylval.str` string for tokens above the byte range.
    lval: Option<String>,
}

/// The error string bison reports for an unexpected token with
/// `YYERROR_VERBOSE` disabled (the locked xml.cc build defines it to 0).
const SYNTAX_ERROR: &str = "syntax error";
/// The error reported for any processing instruction (xml.cc:1664).
const PI_ERROR: &str = "Processing instructions are not supported";
/// The error reported for a DTD declaration (xml.cc:1682).
const DTD_ERROR: &str = "DTD's not supported";

impl<'a> XmlTreeParser<'a> {
    // Ghidra: xml.cc:2378 int4 xml_parse(istream &i, ContentHandler *hand, int4 dbg)
    /// Run the whole parse: start the document, parse, then end the document
    /// only on success (`TreeHandler` callbacks are no-ops for these two).
    fn run(input: &'a [u8]) -> Result<Self, String> {
        let mut parser = Self {
            scan: XmlScan::new(input),
            stack: Vec::new(),
            error: String::new(),
            tok: TOKEN_EOF,
            tok_valid: false,
            lval: None,
        };
        // TreeHandler root is the Document element itself (xml.cc:622-632).
        parser.stack.push(Arc::new(RwLock::new(Element::new())));
        match parser.parse_document() {
            Ok(()) => Ok(parser),
            Err(msg) => Err(msg),
        }
    }

    // Ghidra: xml.cc:2362 int xmllex(void)
    /// Read the next token from the scanner and install it as the
    /// lookahead, capturing the token string for tokens above the byte
    /// range.
    fn advance(&mut self) {
        let res = self.scan.nexttoken();
        if res > 255 {
            self.lval = Some(self.scan.lval());
        } else {
            self.lval = None;
        }
        self.tok = res;
        self.tok_valid = true;
    }

    // RUGRA-GLUE: deferred lookahead read mirroring bison default reductions
    /// Read the lookahead token only if none is pending. Bison performs
    /// default reductions without reading a lookahead; deferring the read
    /// here keeps every scanner mode switch ahead of the next token read.
    fn ensure(&mut self) {
        if !self.tok_valid {
            self.advance();
        }
    }

    // RUGRA-GLUE: shift bookkeeping (bison consumes the lookahead on shift)
    /// Consume the current token; the next read is deferred until `ensure`.
    fn shift(&mut self) {
        self.tok_valid = false;
    }

    // RUGRA-GLUE: yyerror("syntax error") for the locked non-verbose build
    /// Record the bison syntax error message on the handler.
    fn syntax_error(&self) -> String {
        SYNTAX_ERROR.to_string()
    }

    // Ghidra: xml.cc:2394 void TreeHandler::startElement(...)
    /// Open a new element as a child of the current one, in source order.
    fn start_element(&mut self, atts: &XmlAttributes) {
        let mut newel = Element::new();
        newel.set_name(&atts.element_name);
        for i in 0..atts.names.len() {
            newel.add_attribute(&atts.names[i], &atts.values[i]);
        }
        let newel = Arc::new(RwLock::new(newel));
        self.stack
            .last()
            .expect("handler stack empty")
            .write()
            .expect("element lock poisoned")
            .add_child(newel.clone());
        self.stack.push(newel);
    }

    // Ghidra: xml.cc:2405 void TreeHandler::endElement(...)
    /// Close the current element.
    fn end_element(&mut self) {
        self.stack.pop();
    }

    // Ghidra: xml.cc:2411 void TreeHandler::characters(const char *text, ...)
    /// Append character content to the current element.
    fn characters(&mut self, text: &str) {
        self.stack
            .last()
            .expect("handler stack empty")
            .write()
            .expect("element lock poisoned")
            .add_content(text);
    }

    // Ghidra: xml.cc:2309 void print_content(const string &str)
    /// Send character data to the content handler: whitespace-only runs go
    /// to `ignorableWhitespace` (dropped by `TreeHandler`), everything else
    /// to `characters`.
    fn print_content(&mut self, text: &str) {
        let all_ws = text
            .bytes()
            .all(|b| b == b' ' || b == b'\n' || b == b'\r' || b == b'\t');
        if all_ws {
            // handler->ignorableWhitespace: TreeHandler no-op (xml.hh:243)
        } else {
            self.characters(text);
        }
    }

    // Ghidra: xml.cc:141 document production (xml.y:141-142, xml.cc:269)
    /// `document: element Misc | prolog element Misc`, then `$end`.
    fn parse_document(&mut self) -> Result<(), String> {
        self.advance(); // bison reads the first token before its first decision
        if self.tok == COMMAND_BRACE_TOKEN || is_ws_token(self.tok) {
            self.parse_prolog()?;
        }
        self.parse_element()?;
        self.parse_misc()?; // exactly one trailing Misc
        self.ensure();
        if self.tok != TOKEN_EOF {
            return Err(self.syntax_error());
        }
        Ok(())
    }

    // Ghidra: xml.cc:1682 doctypedecl action (xml.y:166-174 prolog)
    /// `prolog: prologpre doctypepro | prologpre` with
    /// `prologpre: XMLDecl | Misc | prologpre Misc`. A `<!DOCTYPE` always
    /// reports the DTD error; any `<?` after the optional leading XMLDecl
    /// reports the processing-instruction error.
    fn parse_prolog(&mut self) -> Result<(), String> {
        // prologpre: at most one leading XMLDecl, then Misc*.
        if is_ws_token(self.tok) {
            // A leading whitespace Misc opens the prolog as well.
            self.parse_s_run();
            self.prolog_misc_loop()?;
            return Ok(());
        }
        self.shift(); // consume COMMBRACE
        self.ensure();
        if self.tok == '?' as i32 {
            self.shift();
            self.ensure();
            if self.tok == 'x' as i32 {
                self.parse_xml_decl()?;
            } else {
                // PI: COMMBRACE '?' (xml.cc:1664)
                return Err(PI_ERROR.to_string());
            }
        } else if self.tok == '!' as i32 {
            // First prologpre position: only a comment can start here.
            // doctypedecl is unreachable until prologpre is non-empty, so
            // `<!D...` reports the plain syntax error (bison state after the
            // initial COMMBRACE has only the commentstart continuation).
            self.shift();
            self.ensure();
            if self.tok == '-' as i32 {
                self.parse_comment_tail()?;
            } else {
                return Err(self.syntax_error());
            }
        } else {
            return Err(self.syntax_error());
        }
        self.prolog_misc_loop()?;
        Ok(())
    }

    // RUGRA-GLUE: shared Misc* tail of the prolog productions (xml.y:166-174)
    /// `prologpre: prologpre Misc` continuation loop: Misc entries followed
    /// by the (always failing) doctypedecl opportunity.
    fn prolog_misc_loop(&mut self) -> Result<(), String> {
        loop {
            self.ensure();
            if self.tok != COMMAND_BRACE_TOKEN && !is_ws_token(self.tok) {
                break;
            }
            self.parse_misc()?;
        }
        Ok(())
    }

    // Ghidra: xml.cc:1688 VersionInfo action (xml.y:182-188)
    /// `xmldeclstart: COMMBRACE '?' 'x' 'm' 'l' VersionInfo` followed by
    /// `XMLDecl: xmldeclstart '?' '>' | xmldeclstart S '?' '>' |
    /// xmldeclstart EncodingDecl '?' '>' | xmldeclstart EncodingDecl S '?' '>'`.
    /// `setVersion`/`setEncoding` are `TreeHandler` no-ops.
    fn parse_xml_decl(&mut self) -> Result<(), String> {
        // Entry: 'x' is the lookahead; shift it, then expect literal "ml".
        self.shift();
        self.ensure();
        for expected in [b'm', b'l'] {
            if self.tok != expected as i32 {
                return Err(self.syntax_error());
            }
            self.shift();
            self.ensure();
        }
        // VersionInfo: S 'v' 'e' 'r' 's' 'i' 'o' 'n' Eq AttValue
        if !is_ws_token(self.tok) {
            return Err(self.syntax_error());
        }
        self.parse_s_run();
        for expected in b"version" {
            if self.tok != *expected as i32 {
                return Err(self.syntax_error());
            }
            self.shift();
            self.ensure();
        }
        self.parse_eq();
        let _version = self.parse_att_value()?; // handler->setVersion: no-op
        self.ensure(); // the token after the closing quote (SingleMode)
        if is_ws_token(self.tok) {
            self.parse_s_run();
            if self.tok == 'e' as i32 {
                // EncodingDecl: S 'e' 'n' 'c' 'o' 'd' 'i' 'n' 'g' Eq AttValue
                for expected in b"encoding" {
                    if self.tok != *expected as i32 {
                        return Err(self.syntax_error());
                    }
                    self.shift();
                    self.ensure();
                }
                self.parse_eq();
                let _encoding = self.parse_att_value()?; // setEncoding: no-op
                self.ensure(); // the token after the closing quote (SingleMode)
                if is_ws_token(self.tok) {
                    self.parse_s_run();
                }
            }
        }
        if self.tok != '?' as i32 {
            return Err(self.syntax_error());
        }
        self.shift();
        self.ensure();
        if self.tok != '>' as i32 {
            return Err(self.syntax_error());
        }
        self.shift();
        Ok(())
    }

    // Ghidra: xml.cc:1658 Comment action (xml.y:178-180 Misc)
    /// `Misc: Comment | PI | S` from the current lookahead token.
    fn parse_misc(&mut self) -> Result<(), String> {
        self.ensure();
        if self.tok == COMMAND_BRACE_TOKEN {
            self.shift();
            self.ensure();
            return self.parse_misc_after_brace();
        }
        if is_ws_token(self.tok) {
            self.parse_s_run(); // Misc: S
            return Ok(());
        }
        Err(self.syntax_error())
    }

    // Ghidra: xml.cc:1664 PI / xml.cc:1682 doctypedecl actions
    /// Dispatch after a shifted COMMBRACE: `!` selects a comment or the
    /// always-failing DTD, `?` selects the always-failing processing
    /// instruction.
    fn parse_misc_after_brace(&mut self) -> Result<(), String> {
        if self.tok == '?' as i32 {
            return Err(PI_ERROR.to_string());
        }
        if self.tok == '!' as i32 {
            self.shift();
            self.ensure();
            if self.tok == '-' as i32 {
                return self.parse_comment_tail();
            }
            if self.tok == 'D' as i32 {
                return Err(DTD_ERROR.to_string());
            }
            return Err(self.syntax_error());
        }
        Err(self.syntax_error())
    }

    // Ghidra: xml.cc:2235 S token materialization (xml.y:143-148 whitespace/S)
    /// `S: whitespace | S whitespace` — consume a run of one-or-more single
    /// whitespace tokens.
    fn parse_s_run(&mut self) {
        while is_ws_token(self.tok) {
            self.shift();
            self.ensure();
        }
    }

    // Ghidra: xml.cc:1748 SAttribute/Eq productions (xml.y:175-177 Eq)
    /// `Eq: '=' | S '=' | Eq S` — an `=` with optional surrounding
    /// whitespace.
    fn parse_eq(&mut self) -> Result<(), String> {
        if is_ws_token(self.tok) {
            self.parse_s_run();
        }
        if self.tok != '=' as i32 {
            return Err(self.syntax_error());
        }
        self.shift();
        self.ensure();
        if is_ws_token(self.tok) {
            self.parse_s_run();
        }
        Ok(())
    }

    // Ghidra: xml.cc:1650 commentstart action (xml.y:159-160)
    /// `commentstart: COMMBRACE '!' '-' '-'` (the caller has shifted
    /// COMMBRACE `'!'` and holds the third `-`), then
    /// `Comment: commentstart COMMENT '-' '-' '>'` with the comment text
    /// discarded. The lookahead is left unset after the closing `>` so the
    /// caller's re-arming action runs before the next token is read.
    fn parse_comment_tail(&mut self) -> Result<(), String> {
        // tok == '-': the third dash.
        self.shift();
        self.ensure();
        if self.tok != '-' as i32 {
            return Err(self.syntax_error());
        }
        self.shift();
        self.scan.setmode(ScanMode::Comment); // case 19 action
        self.ensure();
        if self.tok != COMMENT_TOKEN {
            return Err(self.syntax_error());
        }
        let _text = self.lval.take(); // Comment text is discarded (case 20)
        self.shift();
        self.ensure();
        let tail = [b'-', b'-', b'>'];
        for (i, expected) in tail.iter().enumerate() {
            if self.tok != *expected as i32 {
                return Err(self.syntax_error());
            }
            self.shift();
            if i + 1 < tail.len() {
                self.ensure();
            }
        }
        Ok(())
    }

    // Ghidra: xml.cc:1676 CDStart action (xml.y:162-164)
    /// `CDSect: CDStart CDATA CDEnd` with `CDEnd: ']' ']' '>'`. The caller
    /// has shifted COMMBRACE `'!'` and holds `[`. CDATA content goes through
    /// `print_content` (whitespace-only CDATA is dropped).
    fn parse_cdsect(&mut self) -> Result<(), String> {
        // tok == '[': consume it, then the literal "CDATA[".
        self.shift();
        self.ensure();
        let literals = *b"CDATA[";
        for (i, expected) in literals.iter().enumerate() {
            if self.tok != *expected as i32 {
                return Err(self.syntax_error());
            }
            self.shift();
            if i + 1 < literals.len() {
                self.ensure();
            }
        }
        self.scan.setmode(ScanMode::CData); // case 23 action
        self.ensure();
        if self.tok != CDATA_TOKEN {
            return Err(self.syntax_error());
        }
        let text = self.lval.take().unwrap_or_default();
        self.shift();
        self.ensure();
        let tail = [b']', b']', b'>'];
        for (i, expected) in tail.iter().enumerate() {
            if self.tok != *expected as i32 {
                return Err(self.syntax_error());
            }
            self.shift();
            if i + 1 < tail.len() {
                self.ensure();
            }
        }
        self.print_content(&text); // case 62 action
        Ok(())
    }

    // Ghidra: xml.cc:1814 Reference action (xml.y:213-219)
    /// `Reference: EntityRef | CharRef` from a shifted `&`:
    /// `refstart: '&'` switches to Name mode; `charrefstart: refstart '#'`
    /// switches to CharRef mode; `EntityRef: refstart NAME ';'` and
    /// `CharRef: charrefstart CHARREF ';'` return the converted character.
    fn parse_reference(&mut self) -> Result<i32, String> {
        self.shift(); // shift '&'
        self.scan.setmode(ScanMode::Name); // refstart action (case 67)
        self.ensure();
        if self.tok == '#' as i32 {
            self.shift(); // shift '#'
            self.scan.setmode(ScanMode::CharRef); // case 68 action
            self.ensure();
            if self.tok != CHAR_REF_TOKEN {
                return Err(self.syntax_error());
            }
            let digits = self.lval.take().unwrap_or_default();
            self.shift(); // shift CHARREF — CharRef reduces (case 69: $$=$2)
            self.ensure();
            if self.tok != ';' as i32 {
                return Err(self.syntax_error());
            }
            self.shift(); // ';' — Reference reduces (case 66)
            Ok(convert_char_ref(&digits))
        } else {
            if self.tok != NAME_TOKEN {
                return Err(self.syntax_error());
            }
            let name = self.lval.take().unwrap_or_default();
            self.shift(); // shift NAME
            self.ensure();
            if self.tok != ';' as i32 {
                return Err(self.syntax_error());
            }
            self.shift(); // ';' — EntityRef/Reference reduce (case 70/65)
            Ok(convert_entity_ref(&name))
        }
    }

    // Ghidra: xml.cc:1598 attsinglemid action (xml.y:150-157)
    /// `AttValue: attsinglemid '\'' | attdoublemid '"'` where the mid rules
    /// accumulate ATTVALUE pieces and converted Reference characters,
    /// re-arming the matching AttValue scan mode after each piece.
    fn parse_att_value(&mut self) -> Result<String, String> {
        let quote = match self.tok {
            t if t == '\'' as i32 => b'\'',
            t if t == '"' as i32 => b'"',
            _ => return Err(self.syntax_error()),
        };
        self.shift(); // shift the opening quote — attXmid reduces (cases 10/13)
        let mode = if quote == b'\'' {
            ScanMode::AttValueSingle
        } else {
            ScanMode::AttValueDouble
        };
        self.scan.setmode(mode);
        let mut value = String::new(); // new string
        self.ensure();
        loop {
            if self.tok == ATT_VALUE_TOKEN {
                value.push_str(&self.lval.take().unwrap_or_default()); // cases 11/14
                self.scan.setmode(mode);
                self.shift();
                self.ensure();
            } else if self.tok == '&' as i32 {
                let ch = self.parse_reference()?;
                push_reference_char(&mut value, ch); // cases 12/15
                self.scan.setmode(mode);
                self.ensure();
            } else if self.tok == quote as i32 {
                self.shift(); // AttValue reduces (cases 16/17)
                return Ok(value);
            } else {
                return Err(self.syntax_error());
            }
        }
    }

    // Ghidra: xml.cc:1736 stagstart action (xml.y:198-199)
    /// `stagstart: elemstart NAME | stagstart SAttribute` — collect the
    /// element name and ordered attributes. `elemstart: ELEMBRACE` switches
    /// to Name mode; each completed attribute re-arms SName mode.
    fn parse_stagstart(&mut self) -> Result<XmlAttributes, String> {
        // tok == ELEMENT_BRACE_TOKEN
        self.shift();
        self.scan.setmode(ScanMode::Name); // elemstart action (case 18)
        self.ensure();
        if self.tok != NAME_TOKEN {
            return Err(self.syntax_error());
        }
        let name = self.lval.take().unwrap_or_default();
        self.shift(); // the NAME is shifted; bison reads the next lookahead after
        let mut attrs = XmlAttributes::new(name); // case 52 action
        self.scan.setmode(ScanMode::SName);
        self.ensure();
        while self.tok == SNAME_TOKEN {
            let aname = self.lval.take().unwrap_or_default();
            self.shift(); // shift SNAME
            self.ensure();
            self.parse_eq()?;
            let avalue = self.parse_att_value()?; // SAttribute reduces (case 54)
            attrs.add_attribute(aname, avalue);
            self.scan.setmode(ScanMode::SName); // case 53 action
            self.ensure();
        }
        Ok(attrs)
    }

    // Ghidra: xml.cc:1700 element action (xml.y:190-196)
    /// `element: EmptyElemTag | STag content ETag` — fires `startElement`
    /// when the opening tag completes, then `endElement` when the element
    /// closes. The end tag name is not checked against the start tag.
    fn parse_element(&mut self) -> Result<(), String> {
        if self.tok != ELEMENT_BRACE_TOKEN {
            return Err(self.syntax_error());
        }
        let attrs = self.parse_stagstart()?;
        let is_stag = match self.tok {
            t if t == '>' as i32 => {
                self.shift(); // STag: stagstart '>' (case 48)
                true
            }
            t if t == '/' as i32 => {
                self.shift();
                self.ensure();
                if self.tok != '>' as i32 {
                    return Err(self.syntax_error());
                }
                self.shift(); // EmptyElemTag: stagstart '/' '>' (case 50)
                false
            }
            t if t == ' ' as i32 => {
                // The S produced by scanSName.
                self.shift();
                self.ensure();
                if self.tok == '>' as i32 {
                    self.shift(); // STag: stagstart S '>' (case 49)
                    true
                } else if self.tok == '/' as i32 {
                    self.shift();
                    self.ensure();
                    if self.tok != '>' as i32 {
                        return Err(self.syntax_error());
                    }
                    self.shift(); // EmptyElemTag: stagstart S '/' '>' (case 51)
                    false
                } else {
                    return Err(self.syntax_error());
                }
            }
            _ => return Err(self.syntax_error()),
        };
        self.start_element(&attrs); // handler->startElement (cases 48-51)
        if !is_stag {
            self.end_element(); // element: EmptyElemTag (case 46)
            return Ok(());
        }
        self.scan.setmode(ScanMode::CharData); // content: ε (case 58)
        self.parse_content()?;
        self.parse_etag()?; // element: STag content ETag (case 47)
        self.end_element();
        Ok(())
    }

    // Ghidra: xml.cc:1754 etagbrace action (xml.y:201-203)
    /// `ETag: etagbrace NAME '>' | etagbrace NAME S '>'` where
    /// `etagbrace: COMMBRACE '/'` switches to Name mode. The caller has
    /// shifted COMMBRACE and the `/`.
    fn parse_etag(&mut self) -> Result<String, String> {
        // etagbrace action already applied by the caller.
        self.ensure();
        if self.tok != NAME_TOKEN {
            return Err(self.syntax_error());
        }
        let name = self.lval.take().unwrap_or_default();
        self.shift();
        self.ensure();
        if self.tok == '>' as i32 {
            self.shift(); // ETag: etagbrace NAME '>' (case 56)
        } else if is_ws_token(self.tok) {
            self.parse_s_run();
            if self.tok != '>' as i32 {
                return Err(self.syntax_error());
            }
            self.shift(); // ETag: etagbrace NAME S '>' (case 57)
        } else {
            return Err(self.syntax_error());
        }
        Ok(name)
    }

    // Ghidra: xml.cc:1772 content productions (xml.y:205-211)
    /// `content:` a sequence of CHARDATA (via `print_content`), child
    /// elements, References (printed as characters), CDSects, and Comments,
    /// re-arming CharData mode after each item. A `COMMBRACE '/'` ends the
    /// loop as the enclosing end tag.
    fn parse_content(&mut self) -> Result<(), String> {
        loop {
            self.ensure();
            if self.tok == CHAR_DATA_TOKEN {
                let text = self.lval.take().unwrap_or_default();
                self.shift();
                self.print_content(&text); // case 59 action
                self.scan.setmode(ScanMode::CharData);
            } else if self.tok == ELEMENT_BRACE_TOKEN {
                self.parse_element()?;
                self.scan.setmode(ScanMode::CharData); // case 60 action
            } else if self.tok == '&' as i32 {
                let ch = self.parse_reference()?;
                let mut tmp = String::new();
                push_reference_char(&mut tmp, ch);
                self.print_content(&tmp); // case 61 action
                self.scan.setmode(ScanMode::CharData);
            } else if self.tok == COMMAND_BRACE_TOKEN {
                self.shift();
                self.ensure();
                if self.tok == '!' as i32 {
                    self.shift();
                    self.ensure();
                    if self.tok == '-' as i32 {
                        self.parse_comment_tail()?;
                    } else if self.tok == '[' as i32 {
                        self.parse_cdsect()?;
                    } else {
                        return Err(self.syntax_error());
                    }
                    self.scan.setmode(ScanMode::CharData); // cases 63/64
                } else if self.tok == '?' as i32 {
                    return Err(PI_ERROR.to_string()); // PI (case 21)
                } else if self.tok == '/' as i32 {
                    self.shift();
                    self.scan.setmode(ScanMode::Name); // etagbrace (case 55)
                    return Ok(()); // hand the end tag to the caller
                } else {
                    return Err(self.syntax_error());
                }
            } else {
                return Err(self.syntax_error());
            }
        }
    }

    // RUGRA-GLUE: document assembly from the TreeHandler root element
    /// Extract the built document: the grammar admits exactly one root
    /// element, which becomes the `Document` root (Ghidra's `Document` is
    /// itself the `Element` whose first child is the root, xml.hh:215-219).
    fn into_document(self) -> Document {
        let root_element = self.stack.into_iter().next().expect("root element");
        let children = root_element.read().expect("element lock poisoned");
        let mut doc = Document::new();
        if let Some(first) = children.get_children().first() {
            doc.set_root(first.clone());
        }
        doc
    }
}

// Ghidra: xml.cc:2480 Document *xml_tree(istream &i)
/// Parse the given XML bytes into an in-memory document. On any parse
/// error the partially built document is discarded and the handler's error
/// message is thrown as a `DecoderError`.
pub fn xml_tree(input: &[u8]) -> Result<Document, DecoderError> {
    match XmlTreeParser::run(input) {
        Ok(parser) => Ok(parser.into_document()),
        Err(msg) => Err(DecoderError::new(msg)),
    }
}

/// A container for parsed XML documents. Faithful to `DocumentStorage`
/// (xml.hh:258-291): documents are parsed into an ordered list, and
/// registered elements can be looked up by tag name.
#[derive(Debug, Default)]
pub struct DocumentStorage {
    /// The list of documents held by this container (null slots preserved
    /// for parses that failed after the slot was appended).
    doclist: Vec<Option<Document>>,
    /// The map from name to registered XML elements (same-name
    /// registration overwrites, like `map::operator[]`).
    tagmap: std::collections::BTreeMap<String, Arc<RwLock<Element>>>,
}

impl DocumentStorage {
    // RUGRA-GLUE: Default construction (C++ default-constructs members)
    /// Construct an empty container.
    pub fn new() -> Self {
        Self::default()
    }

    // Ghidra: xml.cc:2444 Document *DocumentStorage::parseDocument(istream &s)
    /// Parse an XML document from the given bytes. The null document slot
    /// is appended before parsing, so a failed parse leaves it behind as
    /// observable partial state; the error is thrown to the caller.
    pub fn parse_document(&mut self, input: &[u8]) -> Result<&Document, DecoderError> {
        self.doclist.push(None);
        match xml_tree(input) {
            Ok(doc) => {
                let slot = self.doclist.last_mut().expect("slot just pushed");
                *slot = Some(doc);
            }
            Err(e) => return Err(e),
        }
        Ok(self
            .doclist
            .last()
            .and_then(|slot| slot.as_ref())
            .expect("slot just filled"))
    }

    // Ghidra: xml.cc:2452 Document *DocumentStorage::openDocument(const string &filename)
    /// Open and parse an XML file from the local filesystem.
    pub fn open_document(&mut self, filename: &str) -> Result<&Document, DecoderError> {
        let bytes = std::fs::read(filename).map_err(|_| {
            DecoderError::new(format!("Unable to open xml document {}", filename))
        })?;
        self.parse_document(&bytes)
    }

    // Ghidra: xml.cc:2463 void DocumentStorage::registerTag(const Element *el)
    /// Register the given XML element under its tag name. Only one element
    /// is stored per tag name; a same-name registration overwrites.
    pub fn register_tag(&mut self, el: &Arc<RwLock<Element>>) {
        let name = el.read().expect("element lock poisoned").name.clone();
        self.tagmap.insert(name, el.clone());
    }

    // Ghidra: xml.cc:2469 const Element *DocumentStorage::getTag(const string &nm) const
    /// Retrieve a registered XML element by name, or `None`.
    pub fn get_tag(&self, nm: &str) -> Option<&Arc<RwLock<Element>>> {
        self.tagmap.get(nm)
    }

    // RUGRA-GLUE: doclist_len (Ghidra keeps doclist private with no accessor;
    // exposed so fixtures can assert the null-slot partial state invariant)
    /// The number of document slots, including null slots left by failed
    /// parses. Ghidra's `doclist` is private and unobservable through its
    /// API; this accessor exists for state-parity assertions only.
    pub fn doclist_len(&self) -> usize {
        self.doclist.len()
    }
}

/// A class for writing structured data to a stream. Faithful to `Encoder`
/// (marshal.hh). This trait mirrors the virtual methods of Ghidra's Encoder.
pub trait Encoder {
    // RUGRA-GLUE: open_element (no Ghidra counterpart found)
    /// Open a new element with the given id.
    fn open_element(&mut self, elem_id: &ElementId);
    // RUGRA-GLUE: close_element (no Ghidra counterpart found)
    /// Close the current element.
    fn close_element(&mut self, elem_id: &ElementId);
    // RUGRA-GLUE: write_bool (no Ghidra counterpart found)
    /// Write a boolean attribute.
    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool);
    // RUGRA-GLUE: write_signed_integer (no Ghidra counterpart found)
    /// Write a signed integer attribute.
    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64);
    // RUGRA-GLUE: write_unsigned_integer (no Ghidra counterpart found)
    /// Write an unsigned integer attribute.
    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64);
    // RUGRA-GLUE: write_string (no Ghidra counterpart found)
    /// Write a string attribute.
    fn write_string(&mut self, attrib_id: &AttributeId, val: &str);
    // RUGRA-GLUE: write_string_indexed (no Ghidra counterpart found)
    /// Write an indexed string attribute.
    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &str);
    // Ghidra: marshal.hh:368 Encoder::writeSpace (pure virtual)
    /// Write an address space reference into the encoding. Each `Encoder`
    /// specialization renders the space its own way: the XML/tree form
    /// writes the space NAME string (`XmlEncode::writeSpace`,
    /// marshal.cc:569-581), while the packed form writes a special-space
    /// type byte or the space index (`PackedEncode::writeSpace`,
    /// marshal.cc:1193-1218). Rust passes the registry handle
    /// `crate::space::AddrSpace` where Ghidra passes `const AddrSpace *`.
    fn write_space(&mut self, attrib_id: &AttributeId, spc: &crate::space::AddrSpace);
}

/// A class for reading structured data from a stream. Faithful to `Decoder`
/// (marshal.hh:99). The document is traversed depth-first via `open_element`/
/// `close_element`, with attributes read via `read_*`.
pub trait Decoder {
    // RUGRA-GLUE: peek_element (no Ghidra counterpart found)
    /// Peek at the next child element id without traversing in. Returns 0 if
    /// none. Faithful to `peekElement`.
    fn peek_element(&self) -> u32;

    // RUGRA-GLUE: open_element (no Ghidra counterpart found)
    /// Open (traverse into) the next child element. Returns the element id.
    /// Faithful to `openElement`.
    fn open_element(&mut self) -> u32;

    // RUGRA-GLUE: open_element_matching (no Ghidra counterpart found)
    /// Open the next child element, which must match the given id.
    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32;

    // RUGRA-GLUE: close_element (no Ghidra counterpart found)
    /// Close the current element. Faithful to `closeElement`.
    fn close_element(&mut self, id: u32);

    // RUGRA-GLUE: close_element_skipping (no Ghidra counterpart found)
    /// Close the current element, skipping unread children. Faithful to
    /// `closeElementSkipping`.
    fn close_element_skipping(&mut self, id: u32);

    // RUGRA-GLUE: next_attribute_id (no Ghidra counterpart found)
    /// Get the next attribute id for the current element. Returns 0 when done.
    fn next_attribute_id(&mut self) -> u32;

    // RUGRA-GLUE: attribute_name (no Ghidra counterpart found)
    /// Look up the name of an attribute id. Returns None if the id is not
    /// registered. This allows decode implementations to dispatch on attribute
    /// names without holding a separate registry reference.
    fn attribute_name(&self, id: u32) -> Option<String>;

    // RUGRA-GLUE: element_name (no Ghidra counterpart found)
    /// Look up the name of an element id. Returns None if not registered.
    fn element_name(&self, id: u32) -> Option<String>;

    // RUGRA-GLUE: rewind_attributes (no Ghidra counterpart found)
    /// Reset attribute traversal. Faithful to `rewindAttributes`.
    fn rewind_attributes(&mut self);

    // Ghidra: marshal.hh:165 Decoder::getIndexedAttributeId (pure virtual)
    /// Assuming the previous `next_attribute_id` returned `ATTRIB_UNKNOWN`,
    /// reinterpret the current attribute as an indexed form of `attrib_id`.
    /// The XML decoder reinterprets the decimal suffix of the attribute name
    /// (`XmlDecode::getIndexedAttributeId`, marshal.cc:243-260); the packed
    /// decoder never needs to reinterpret and returns `ATTRIB_UNKNOWN`
    /// (`PackedDecode::getIndexedAttributeId`, marshal.cc:825-829).
    fn get_indexed_attribute_id(&mut self, attrib_id: &AttributeId) -> u32;

    // Ghidra: marshal.hh:151-156 region Decoder::readSpace (pure virtual)
    /// Read the current attribute as an address space reference. Each
    /// `Decoder` resolves the space its own way: the XML/tree form looks
    /// the space NAME up in the manager (`XmlDecode::readSpace`,
    /// marshal.cc:400-409), while the packed form reads the space index or
    /// special-space code (`PackedDecode::readSpace`, marshal.cc:997-1031).
    /// Ghidra's decoders hold `const AddrSpaceManager *spcManager` from the
    /// constructor (marshal.hh:101-103); Rust decoders stay manager-less, so
    /// the manager is passed per call — the same object Ghidra would hold.
    /// Unknown names/indices and rejected special codes return
    /// `Err` with Ghidra's exact `DecoderError` message.
    fn read_space(
        &mut self,
        spc_manager: &crate::space::SpaceRegistry,
    ) -> Result<crate::space::AddrSpace, String>;

    // Ghidra: marshal.hh:176 Decoder::readBool(void) (pure virtual)
    /// Read the current attribute as a boolean. Each `Decoder` resolves
    /// the value its own way: the XML/tree form parses the attribute
    /// string with `xml_readbool` — first character, case-sensitive
    /// (`XmlDecode::readBool`, marshal.cc:279-284 + xml.hh:391-400) —
    /// while the packed form reads the type byte's length-code bit
    /// (`PackedDecode::readBool`, marshal.cc:831-842).
    fn read_bool(&mut self) -> bool;

    // Ghidra: marshal.hh:186 Decoder::readBool(const AttributeId &) (pure virtual)
    /// Read a specific attribute as a boolean. The VALUE domain is the
    /// oracle's `xml_readbool` — first character, case-sensitive
    /// ('t'/'1'/'y' true; xml.hh:391-400). Divergence note
    /// (MARSHAL-READBOOL-0001 residual, registered in TODO_BOARD): the
    /// oracle's `readBool(attribId)` THROWS
    /// `DecoderError("Attribute missing: <name>")` on a missing
    /// attribute (marshal.cc:276 XmlDecode / marshal.cc:636 PackedDecode
    /// — different messages), while this bool-typed convenience returns
    /// `false`; the exact throw channel is modeled at the production
    /// decode port (`ScopeLocal::decode_wrapping_attributes`, which
    /// scans by name exactly as the C++ does before reading).
    fn read_bool_attr(&mut self, attrib_id: &AttributeId) -> bool;

    // RUGRA-GLUE: read_signed_integer (no Ghidra counterpart found)
    /// Read the current attribute as a signed integer.
    fn read_signed_integer(&mut self) -> i64;

    // RUGRA-GLUE: read_signed_integer_attr (no Ghidra counterpart found)
    /// Read a specific attribute as a signed integer.
    fn read_signed_integer_attr(&mut self, attrib_id: &AttributeId) -> i64;

    // RUGRA-GLUE: read_unsigned_integer (no Ghidra counterpart found)
    /// Read the current attribute as an unsigned integer.
    fn read_unsigned_integer(&mut self) -> u64;

    // RUGRA-GLUE: read_unsigned_integer_attr (no Ghidra counterpart found)
    /// Read a specific attribute as an unsigned integer.
    fn read_unsigned_integer_attr(&mut self, attrib_id: &AttributeId) -> u64;

    // RUGRA-GLUE: read_string (no Ghidra counterpart found)
    /// Read the current attribute as a string.
    fn read_string(&mut self) -> String;

    // RUGRA-GLUE: read_string_attr (no Ghidra counterpart found)
    /// Read a specific attribute as a string.
    fn read_string_attr(&mut self, attrib_id: &AttributeId) -> String;
}

/// An in-memory `Encoder` that builds an `Element` tree. This is the Rust
/// equivalent of Ghidra's `TreeHandler` + `Document` construction. The built
/// tree can be retrieved via `into_document`.
pub struct TreeEncoder {
    /// The stack of open elements; the last is the current.
    stack: Vec<Arc<RwLock<Element>>>,
    /// The root element (set after the first open_element).
    root: Option<Arc<RwLock<Element>>>,
    /// The registry for id→name lookup.
    registry: Arc<RwLock<IdRegistry>>,
}

impl TreeEncoder {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct given a registry.
    pub fn new(registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self {
            stack: Vec::new(),
            root: None,
            registry,
        }
    }

    // RUGRA-GLUE: into_document (no Ghidra counterpart found)
    /// Consume the encoder and return the built document.
    pub fn into_document(self) -> Document {
        Document { root: self.root }
    }

    // RUGRA-GLUE: root (no Ghidra counterpart found)
    /// Get the root element.
    pub fn root(&self) -> Option<Arc<RwLock<Element>>> {
        self.root.clone()
    }
}

impl Encoder for TreeEncoder {
    // RUGRA-GLUE: open_element (no Ghidra counterpart found)
    fn open_element(&mut self, elem_id: &ElementId) {
        let mut elem = Element::new();
        elem.set_name(&elem_id.name);
        let elem_arc = Arc::new(RwLock::new(elem));
        if let Some(parent) = self.stack.last() {
            parent.write().unwrap().add_child(elem_arc.clone());
        } else {
            self.root = Some(elem_arc.clone());
        }
        self.stack.push(elem_arc);
    }

    // RUGRA-GLUE: close_element (no Ghidra counterpart found)
    fn close_element(&mut self, _elem_id: &ElementId) {
        self.stack.pop();
    }

    // RUGRA-GLUE: write_bool (no Ghidra counterpart found)
    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool) {
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(
                &attrib_id.name,
                if val { "1" } else { "0" },
            );
        }
    }

    // RUGRA-GLUE: write_signed_integer (no Ghidra counterpart found)
    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64) {
        if let Some(cur) = self.stack.last() {
            cur.write()
                .unwrap()
                .add_attribute(&attrib_id.name, &val.to_string());
        }
    }

    // RUGRA-GLUE: write_unsigned_integer (no Ghidra counterpart found)
    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64) {
        if let Some(cur) = self.stack.last() {
            cur.write()
                .unwrap()
                .add_attribute(&attrib_id.name, &val.to_string());
        }
    }

    // RUGRA-GLUE: write_string (no Ghidra counterpart found)
    fn write_string(&mut self, attrib_id: &AttributeId, val: &str) {
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(&attrib_id.name, val);
        }
    }

    // Ghidra: marshal.cc:559 XmlEncode::writeStringIndexed
    /// Write an indexed string attribute. Faithful to `XmlEncode::
    /// writeStringIndexed` (marshal.cc:559-567): the attribute NAME carries
    /// the 1-based index directly appended to the base name (e.g. "piece1",
    /// "piece2"), with no separator.
    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &str) {
        let nm = format!("{}{}", attrib_id.name, index + 1);
        if let Some(cur) = self.stack.last() {
            cur.write().unwrap().add_attribute(&nm, val);
        }
    }

    // Ghidra: marshal.cc:569 XmlEncode::writeSpace
    /// Write the space as its NAME attribute value. Faithful to
    /// `XmlEncode::writeSpace` (marshal.cc:569-581): the plain-attribute
    /// path is `a_v(outStream, attribId.getName(), spc->getName())`; the
    /// `ATTRIB_CONTENT` text-value form is unreachable for the tree encoder,
    /// which stores attributes by name (its `write_string` handles content
    /// storage the same way).
    fn write_space(&mut self, attrib_id: &AttributeId, spc: &crate::space::AddrSpace) {
        self.write_string(attrib_id, &spc.get_name());
    }
}

// Ghidra: marshal.cc:296/353 XmlDecode integer attribute extraction
/// Parse an integer attribute string the way Ghidra's `XmlDecode` does:
/// through `istringstream` with `unsetf(ios::dec | ios::hex | ios::oct)`.
/// Leading whitespace is skipped, an optional sign is taken, then the base
/// is auto-detected (`0x`/`0X` prefix → hex, a leading `0` followed by
/// more digits → octal, otherwise decimal) and the longest valid digit
/// prefix is consumed.  No valid digits → 0 (the `res = 0`
/// initialization); overflow saturates (the C++11 stream behavior).
fn cpp_stream_magnitude(value: &str) -> (bool, u64) {
    let text = value.trim_start();
    let (negative, text) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (radix, digits) = if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        (16u32, rest)
    } else if text.len() > 1 && text.starts_with('0') {
        (8u32, &text[1..])
    } else {
        (10u32, text)
    };
    let mut end = 0;
    for (index, ch) in digits.char_indices() {
        if ch.is_digit(radix) {
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        // No valid digits (e.g. a bare "0x"): the stream consumed the "0".
        return (negative, 0);
    }
    let mut magnitude: u64 = 0;
    for ch in digits[..end].chars() {
        let digit = ch.to_digit(radix).unwrap_or(0) as u64;
        magnitude = magnitude
            .checked_mul(radix as u64)
            .and_then(|m| m.checked_add(digit))
            .unwrap_or(u64::MAX);
        if magnitude == u64::MAX {
            break;
        }
    }
    (negative, magnitude)
}

// Ghidra: marshal.cc:353 XmlDecode::readUnsignedInteger (stream extraction)
/// Unsigned variant of the iostream-style integer parse. Also the piece
/// numeric parse of `JoinSpace::decodeAttributes` (space.cc:576-581 uses
/// the same `unsetf(ios::dec|ios::hex|ios::oct)` extraction), so it is
/// shared crate-wide.
pub(crate) fn cpp_stream_unsigned(value: &str) -> u64 {
    let (negative, magnitude) = cpp_stream_magnitude(value);
    if negative {
        magnitude.wrapping_neg()
    } else {
        magnitude
    }
}

// Ghidra: marshal.cc:296 XmlDecode::readSignedInteger (stream extraction)
/// Signed variant of the iostream-style integer parse.
fn cpp_stream_signed(value: &str) -> i64 {
    let (negative, magnitude) = cpp_stream_magnitude(value);
    if negative {
        (magnitude as i64).wrapping_neg()
    } else {
        magnitude as i64
    }
}

// Ghidra: xml.hh:391 xml_readbool
/// Read an XML attribute value as a boolean. Faithful to the inline
/// `xml_readbool` (xml.hh:385-400): the empty string is false; otherwise
/// the FIRST character decides, case-sensitively — `'t'`, `'1'`, or
/// `'y'` (the legacy "yes" spelling kept "For backward compatibility",
/// xml.hh:398) are true, and anything else — including `'T'`, `'Y'`,
/// `'0'`, `'f'` — is false.
pub fn xml_readbool(attr: &str) -> bool {
    match attr.as_bytes().first() {
        Some(b't') | Some(b'1') | Some(b'y') => true,
        _ => false,
    }
}

/// An in-memory `Decoder` that reads from an `Element` tree. This traverses
/// the DOM depth-first, mirroring Ghidra's `XmlDecode`.
pub struct TreeDecoder {
    /// The root of the tree being decoded.
    root: Option<Arc<RwLock<Element>>>,
    /// Stack of (element, current child index, current attribute index).
    stack: Vec<(Arc<RwLock<Element>>, usize, usize)>,
    /// The registry for name→id lookup.
    registry: Arc<RwLock<IdRegistry>>,
}

impl TreeDecoder {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct given a document root and registry.
    pub fn new(root: Arc<RwLock<Element>>, registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self {
            root: Some(root),
            stack: Vec::new(),
            registry,
        }
    }

    // RUGRA-GLUE: from_document (no Ghidra counterpart found)
    /// Construct from a document.
    pub fn from_document(doc: &Document, registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self::new(
            doc.root.clone().unwrap_or_else(|| Arc::new(RwLock::new(Element::new()))),
            registry,
        )
    }
}

impl Decoder for TreeDecoder {
    // RUGRA-GLUE: peek_element (no Ghidra counterpart found)
    fn peek_element(&self) -> u32 {
        let Some((elem, child_idx, _)) = self.stack.last() else {
            // At the document level: peek the root.
            if let Some(root) = &self.root {
                if self.stack.is_empty() {
                    let rg = root.read().unwrap();
                    return self.registry.read().unwrap().find_element(&rg.name);
                }
            }
            return 0;
        };
        let rg = elem.read().unwrap();
        if *child_idx < rg.children.len() {
            let child = &rg.children[*child_idx];
            let child_rg = child.read().unwrap();
            self.registry.read().unwrap().find_element(&child_rg.name)
        } else {
            0
        }
    }

    // RUGRA-GLUE: open_element (no Ghidra counterpart found)
    fn open_element(&mut self) -> u32 {
        // If at document level with no stack, push the root.
        if self.stack.is_empty() {
            if let Some(root) = self.root.take() {
                let id = {
                    let rg = root.read().unwrap();
                    self.registry.read().unwrap().find_element(&rg.name)
                };
                self.stack.push((root, 0, 0));
                return id;
            }
            return 0;
        }
        let (elem, child_idx, _) = self.stack.last().cloned().unwrap();
        let child = {
            let rg = elem.read().unwrap();
            rg.children.get(child_idx).cloned()
        };
        let Some(child) = child else {
            return 0;
        };
        let id = {
            let rg = child.read().unwrap();
            self.registry.read().unwrap().find_element(&rg.name)
        };
        // Advance the parent's child index.
        if let Some(last) = self.stack.last_mut() {
            last.1 += 1;
        }
        self.stack.push((child, 0, 0));
        id
    }

    // RUGRA-GLUE: open_element_matching (no Ghidra counterpart found)
    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32 {
        let id = self.open_element();
        if id != elem_id.id {
            // Ghidra throws; we return 0.
            return 0;
        }
        id
    }

    // RUGRA-GLUE: close_element (no Ghidra counterpart found)
    fn close_element(&mut self, _id: u32) {
        self.stack.pop();
    }

    // RUGRA-GLUE: close_element_skipping (no Ghidra counterpart found)
    fn close_element_skipping(&mut self, _id: u32) {
        self.stack.pop();
    }

    // RUGRA-GLUE: next_attribute_id (no Ghidra counterpart found)
    fn next_attribute_id(&mut self) -> u32 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx < rg.get_num_attributes() {
            // Clone the name to release the borrow before mutating the stack.
            let name = rg.get_attribute_name(attr_idx).to_string();
            drop(rg);
            if let Some(last) = self.stack.last_mut() {
                last.2 += 1;
            }
            self.registry.read().unwrap().find_attribute(&name)
        } else {
            0
        }
    }

    // RUGRA-GLUE: rewind_attributes (no Ghidra counterpart found)
    fn rewind_attributes(&mut self) {
        if let Some(last) = self.stack.last_mut() {
            last.2 = 0;
        }
    }

    // Ghidra: marshal.cc:243 XmlDecode::getIndexedAttributeId
    /// Reinterpret the current attribute as an indexed form of `attrib_id`.
    /// Faithful to `XmlDecode::getIndexedAttributeId` (marshal.cc:243-260):
    /// out-of-range cursor or a name without the base-name prefix yields
    /// `ATTRIB_UNKNOWN`; otherwise the decimal suffix (starting at 1) is
    /// decoded and `attrib_id.id + (val-1)` returned, with Ghidra's
    /// `LowlevelError("Bad indexed attribute: " + nm)` panic when no digits
    /// were consumed.
    fn get_indexed_attribute_id(&mut self, attrib_id: &AttributeId) -> u32 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return ATTRIB_UNKNOWN;
        };
        let rg = elem.read().unwrap();
        if attr_idx == 0 || attr_idx - 1 >= rg.get_num_attributes() {
            return ATTRIB_UNKNOWN;
        }
        // const string &attribName(el->getAttributeName(attributeIndex));
        let attrib_name = rg.get_attribute_name(attr_idx - 1);
        // Does the name start with desired attribute base name?
        let Some(suffix) = attrib_name.strip_prefix(attrib_id.name.as_str()) else {
            return ATTRIB_UNKNOWN;
        };
        // istringstream s(attribName.substr(base)); s >> dec >> val;
        // Decode the longest decimal digit prefix (stream extraction).
        let digits: String = suffix.chars().take_while(|c| c.is_ascii_digit()).collect();
        let val: u32 = if digits.is_empty() {
            0
        } else {
            digits.parse().unwrap_or(0)
        };
        if val == 0 {
            panic!("Bad indexed attribute: {}", attrib_id.name);
        }
        attrib_id.id + (val - 1)
    }

    // Ghidra: marshal.cc:400 XmlDecode::readSpace
    /// Read the current attribute's value as a space NAME and resolve it
    /// through the manager. Faithful to `XmlDecode::readSpace`
    /// (marshal.cc:400-409): the value at the attribute cursor is looked up
    /// with `getSpaceByName`, an unknown name throwing
    /// `DecoderError("Unknown address space name: " + nm)`.
    fn read_space(
        &mut self,
        spc_manager: &crate::space::SpaceRegistry,
    ) -> Result<crate::space::AddrSpace, String> {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return Err("Unknown address space name: ".to_string());
        };
        let rg = elem.read().unwrap();
        if attr_idx == 0 || attr_idx - 1 >= rg.get_num_attributes() {
            // Ghidra reads getAttributeValue(attributeIndex) at cursor -1;
            // an unpositioned cursor is caller error (out-of-range index
            // would be UB in C++); mapped to the unknown-name rejection.
            return Err("Unknown address space name: ".to_string());
        }
        let nm = rg.get_attribute_value_at(attr_idx - 1).to_string();
        match spc_manager.get_space_by_name(&nm) {
            Some(spc) => Ok(spc),
            None => Err(format!("Unknown address space name: {}", nm)),
        }
    }

    // RUGRA-GLUE: attribute_name (no Ghidra counterpart found)
    fn attribute_name(&self, id: u32) -> Option<String> {
        self.registry
            .read()
            .unwrap()
            .attribute_name(id)
            .map(|s| s.to_string())
    }

    // RUGRA-GLUE: element_name (no Ghidra counterpart found)
    fn element_name(&self, id: u32) -> Option<String> {
        self.registry
            .read()
            .unwrap()
            .element_name(id)
            .map(|s| s.to_string())
    }

    // Ghidra: marshal.cc:279 XmlDecode::readBool(void)
    /// Read the current attribute as a boolean. Faithful to
    /// `XmlDecode::readBool()` (marshal.cc:279-284): the value string is
    /// parsed by `xml_readbool` — first character, case-sensitive
    /// (xml.hh:391-400). An unpositioned/out-of-range cursor has no
    /// oracle observation (C++ would read `getAttributeValue` out of
    /// bounds); `false` keeps the historical default.
    fn read_bool(&mut self) -> bool {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return false;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return xml_readbool(rg.get_attribute_value_at(attr_idx - 1));
        }
        false
    }

    // Ghidra: marshal.cc:286 XmlDecode::readBool(const AttributeId &)
    /// Read a specific attribute as a boolean. Faithful to
    /// `XmlDecode::readBool(attribId)` (marshal.cc:286-294) for the
    /// VALUE domain: the content pseudo-attribute (`ATTRIB_CONTENT`)
    /// parses the element's text, any other name resolves by name and
    /// the found value is parsed by `xml_readbool` (first character,
    /// case-sensitive, xml.hh:391-400). Divergence note
    /// (MARSHAL-READBOOL-0001 residual): a MISSING name returns `false`
    /// where the oracle's `findMatchingAttribute` throws
    /// `DecoderError("Attribute missing: <name>")` (marshal.cc:276) —
    /// the throw channel is modeled at the production decode port
    /// (`ScopeLocal::decode_wrapping_attributes`). An empty decode stack
    /// has no oracle observation (`elStack.back()` on an empty stack is
    /// UB in C++); `false` keeps the historical default.
    fn read_bool_attr(&mut self, attrib_id: &AttributeId) -> bool {
        let Some((elem, _, _)) = self.stack.last().cloned() else {
            return false;
        };
        let rg = elem.read().unwrap();
        // if (attribId == ATTRIB_CONTENT) return xml_readbool(el->getContent());
        // (marshal.cc:290-291)
        if attrib_id.id == ATTRIB_CONTENT {
            return xml_readbool(rg.get_content());
        }
        // int4 index = findMatchingAttribute(el, attribId.getName()); (marshal.cc:292)
        rg.get_attribute_value(&attrib_id.name)
            .map(|value| xml_readbool(value))
            .unwrap_or(false)
    }

    // Ghidra: marshal.cc:296 XmlDecode::readSignedInteger(void)
    /// Read the current attribute as a signed integer.  Faithful to
    /// `XmlDecode::readSignedInteger()` (marshal.cc:296-305): the value is
    /// parsed through an `istringstream` with `unsetf(dec|hex|oct)`, so
    /// `0x`-prefixed hex and leading-`0` octal are auto-detected; a failed
    /// parse yields 0 (the `intb res = 0` initialization).
    fn read_signed_integer(&mut self) -> i64 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return cpp_stream_signed(rg.get_attribute_value_at(attr_idx - 1));
        }
        0
    }

    // Ghidra: marshal.cc:307 XmlDecode::readSignedInteger(const AttributeId &)
    /// Read a specific attribute as a signed integer, with the same
    /// hex/octal auto-detection as the stream variant (marshal.cc:309-330).
    fn read_signed_integer_attr(&mut self, attrib_id: &AttributeId) -> i64 {
        let Some((elem, _, _)) = self.stack.last() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .map(|v| cpp_stream_signed(v))
            .unwrap_or(0)
    }

    // Ghidra: marshal.cc:353 XmlDecode::readUnsignedInteger(void)
    /// Read the current attribute as an unsigned integer.  Faithful to
    /// `XmlDecode::readUnsignedInteger()` (marshal.cc:353-361): the value
    /// is parsed through an `istringstream` with `unsetf(dec|hex|oct)`, so
    /// `0x`-prefixed hex and leading-`0` octal are auto-detected (e.g. the
    /// production cspec `<localrange>` hex offsets); a failed parse yields
    /// 0 (the `uintb res = 0` initialization).
    fn read_unsigned_integer(&mut self) -> u64 {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return cpp_stream_unsigned(rg.get_attribute_value_at(attr_idx - 1));
        }
        0
    }

    // Ghidra: marshal.cc:364 XmlDecode::readUnsignedInteger(const AttributeId &)
    /// Read a specific attribute as an unsigned integer, with the same
    /// hex/octal auto-detection as the stream variant (marshal.cc:366-381).
    fn read_unsigned_integer_attr(&mut self, attrib_id: &AttributeId) -> u64 {
        let Some((elem, _, _)) = self.stack.last() else {
            return 0;
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .map(|v| cpp_stream_unsigned(v))
            .unwrap_or(0)
    }

    // RUGRA-GLUE: read_string (no Ghidra counterpart found)
    fn read_string(&mut self) -> String {
        let Some((elem, _, attr_idx)) = self.stack.last().cloned() else {
            return String::new();
        };
        let rg = elem.read().unwrap();
        if attr_idx > 0 && attr_idx - 1 < rg.get_num_attributes() {
            return rg.get_attribute_value_at(attr_idx - 1).to_string();
        }
        String::new()
    }

    // RUGRA-GLUE: read_string_attr (no Ghidra counterpart found)
    fn read_string_attr(&mut self, attrib_id: &AttributeId) -> String {
        let Some((elem, _, _)) = self.stack.last() else {
            return String::new();
        };
        let rg = elem.read().unwrap();
        rg.get_attribute_value(&attrib_id.name)
            .unwrap_or("")
            .to_string()
    }
}

// ---------------------------------------------------------------------------
// PackedEncode — binary marshaling format (marshal.hh:579)
// ---------------------------------------------------------------------------

/// Protocol format constants. Faithful to `PackedFormat` (marshal.hh:480).
pub mod packed_format {
    pub const HEADER_MASK: u8 = 0xc0;
    pub const ELEMENT_START: u8 = 0x40;
    pub const ELEMENT_END: u8 = 0x80;
    pub const ATTRIBUTE: u8 = 0xc0;
    pub const HEADEREXTEND_MASK: u8 = 0x20;
    pub const ELEMENTID_MASK: u8 = 0x1f;
    pub const RAWDATA_MASK: u8 = 0x7f;
    pub const RAWDATA_BITSPERBYTE: u32 = 7;
    pub const RAWDATA_MARKER: u8 = 0x80;
    pub const TYPECODE_SHIFT: u32 = 4;
    pub const LENGTHCODE_MASK: u8 = 0xf;
    pub const TYPECODE_BOOLEAN: u8 = 1;
    pub const TYPECODE_SIGNEDINT_POSITIVE: u8 = 2;
    pub const TYPECODE_SIGNEDINT_NEGATIVE: u8 = 3;
    pub const TYPECODE_UNSIGNEDINT: u8 = 4;
    pub const TYPECODE_ADDRESSSPACE: u8 = 5;
    pub const TYPECODE_SPECIALSPACE: u8 = 6;
    pub const TYPECODE_STRING: u8 = 7;
    // Ghidra: marshal.hh:499-503 PackedFormat special-space codes
    pub const SPECIALSPACE_STACK: u32 = 0;
    pub const SPECIALSPACE_JOIN: u32 = 1;
    pub const SPECIALSPACE_FSPEC: u32 = 2;
    pub const SPECIALSPACE_IOP: u32 = 3;
    pub const SPECIALSPACE_SPACEBASE: u32 = 4;
}

/// A byte-based encoder for the packed binary format. Faithful to
/// `PackedEncode` (marshal.hh:579).
pub struct PackedEncode {
    out: Vec<u8>,
}

impl PackedEncode {
    // Ghidra: marshal.hh:579 PackedEncode::new
    /// Construct an empty encoder.
    pub fn new() -> Self {
        Self { out: Vec::new() }
    }

    // Ghidra: marshal.hh:579 PackedEncode::intoBytes
    /// Consume and return the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    // Ghidra: marshal.hh:661 PackedEncode::writeHeader
    /// Write a header byte (element start/end or attribute) with an id.
    /// Faithful to `writeHeader` (marshal.hh inline).
    fn write_header(&mut self, header: u8, id: u32) {
        use packed_format::*;
        if id > 0x1f {
            let h = header | HEADEREXTEND_MASK | ((id >> RAWDATA_BITSPERBYTE) as u8);
            let extend = ((id & RAWDATA_MASK as u32) as u8) | RAWDATA_MARKER;
            self.out.push(h);
            self.out.push(extend);
        } else {
            self.out.push(header | (id as u8));
        }
    }

    // Ghidra: marshal.cc:1065 PackedEncode::writeInteger
    /// Write an integer value with the given type byte. Faithful to
    /// `writeInteger` (marshal.cc:1065).
    fn write_integer(&mut self, type_byte: u8, val: u64) {
        use packed_format::*;
        let (len_code, sa) = if val == 0 {
            (0u8, -1i32)
        } else if val < 0x800000000 {
            if val < 0x200000 {
                if val < 0x80 {
                    (1, 0)
                } else if val < 0x4000 {
                    (2, RAWDATA_BITSPERBYTE as i32)
                } else {
                    (3, 2 * RAWDATA_BITSPERBYTE as i32)
                }
            } else if val < 0x10000000 {
                (4, 3 * RAWDATA_BITSPERBYTE as i32)
            } else {
                (5, 4 * RAWDATA_BITSPERBYTE as i32)
            }
        } else if val < 0x2000000000000 {
            if val < 0x40000000000 {
                (6, 5 * RAWDATA_BITSPERBYTE as i32)
            } else {
                (7, 6 * RAWDATA_BITSPERBYTE as i32)
            }
        } else if val < 0x100000000000000 {
            (8, 7 * RAWDATA_BITSPERBYTE as i32)
        } else if val < 0x8000000000000000 {
            (9, 8 * RAWDATA_BITSPERBYTE as i32)
        } else {
            (10, 9 * RAWDATA_BITSPERBYTE as i32)
        };
        self.out.push(type_byte | len_code);
        let mut shift = sa;
        while shift >= 0 {
            let piece = ((val >> shift) & RAWDATA_MASK as u64) as u8;
            self.out.push(piece | RAWDATA_MARKER);
            shift -= RAWDATA_BITSPERBYTE as i32;
        }
    }
}

impl Default for PackedEncode {
    // Ghidra: marshal.hh:579 PackedEncode::default
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for PackedEncode {
    // Ghidra: marshal.cc:1131 PackedEncode::openElement
    fn open_element(&mut self, elem_id: &ElementId) {
        self.write_header(packed_format::ELEMENT_START, elem_id.id);
    }

    // Ghidra: marshal.cc:1137 PackedEncode::closeElement
    fn close_element(&mut self, elem_id: &ElementId) {
        self.write_header(packed_format::ELEMENT_END, elem_id.id);
    }

    // Ghidra: marshal.cc:1143 PackedEncode::writeBool
    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        let type_byte = if val {
            (TYPECODE_BOOLEAN << TYPECODE_SHIFT) | 1
        } else {
            TYPECODE_BOOLEAN << TYPECODE_SHIFT
        };
        self.out.push(type_byte);
    }

    // Ghidra: marshal.cc:1151 PackedEncode::writeSignedInteger
    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        if val < 0 {
            let type_byte = TYPECODE_SIGNEDINT_NEGATIVE << TYPECODE_SHIFT;
            self.write_integer(type_byte, (-val) as u64);
        } else {
            let type_byte = TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT;
            self.write_integer(type_byte, val as u64);
        }
    }

    // Ghidra: marshal.cc:1168 PackedEncode::writeUnsignedInteger
    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        self.write_integer(TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT, val);
    }

    // Ghidra: marshal.cc:1175 PackedEncode::writeString
    fn write_string(&mut self, attrib_id: &AttributeId, val: &str) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        self.write_integer(TYPECODE_STRING << TYPECODE_SHIFT, val.len() as u64);
        self.out.extend_from_slice(val.as_bytes());
    }

    // Ghidra: marshal.cc:1184 PackedEncode::writeStringIndexed
    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &str) {
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id + index);
        self.write_integer(TYPECODE_STRING << TYPECODE_SHIFT, val.len() as u64);
        self.out.extend_from_slice(val.as_bytes());
    }

    // Ghidra: marshal.cc:1193 PackedEncode::writeSpace
    /// Write an address space reference. Faithful to `PackedEncode::
    /// writeSpace` (marshal.cc:1193-1218): after the attribute header, the
    /// fspec/iop/join types emit a single TYPECODE_SPECIALSPACE type byte
    /// carrying the special code in the length field (fspec=2, iop=3,
    /// join=1); a spacebase emits the STACK code (0) when it is the formal
    /// stack space, otherwise the SPACEBASE code (4); every other type
    /// falls to the default arm, an ADDRESSSPACE-typed integer holding the
    /// space index.
    fn write_space(&mut self, attrib_id: &AttributeId, spc: &crate::space::AddrSpace) {
        use crate::space::SpaceType;
        use packed_format::*;
        self.write_header(ATTRIBUTE, attrib_id.id);
        let special =
            (TYPECODE_SPECIALSPACE as u32) << TYPECODE_SHIFT;
        match spc.get_type() {
            SpaceType::Fspec => {
                self.out.push((special | SPECIALSPACE_FSPEC) as u8);
            }
            SpaceType::Iop => {
                self.out.push((special | SPECIALSPACE_IOP) as u8);
            }
            SpaceType::Join => {
                self.out.push((special | SPECIALSPACE_JOIN) as u8);
            }
            SpaceType::SpaceBase => {
                if spc.is_formal_stackspace() {
                    self.out.push((special | SPECIALSPACE_STACK) as u8);
                } else {
                    // A secondary register offset space
                    self.out.push((special | SPECIALSPACE_SPACEBASE) as u8);
                }
            }
            _ => {
                let spc_id = spc.get_index() as u64;
                self.write_integer(TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT, spc_id);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PackedDecode — binary marshaling format reader (marshal.hh:512)
// ---------------------------------------------------------------------------

/// A byte-based decoder for the packed binary format. Faithful to
/// `PackedDecode` (marshal.hh:512).
pub struct PackedDecode {
    /// The raw input bytes.
    input: Vec<u8>,
    /// Current position in the input.
    pos: usize,
    /// Stack of open elements: (element_id, attribute_start_pos, attribute_cursor_pos).
    stack: Vec<(u32, usize, usize)>,
    /// The registry for name lookup.
    registry: Arc<RwLock<IdRegistry>>,
    /// Pending type byte from the last attribute header.
    pending_type: Option<u8>,
    /// Pending integer length code.
    pending_int_len: Option<usize>,
    /// Pending string byte length.
    pending_string_len: Option<usize>,
}

impl PackedDecode {
    // Ghidra: marshal.hh:512 PackedDecode::new
    /// Construct from a byte vector and registry.
    pub fn new(input: Vec<u8>, registry: Arc<RwLock<IdRegistry>>) -> Self {
        Self {
            input,
            pos: 0,
            stack: Vec::new(),
            registry,
            pending_type: None,
            pending_int_len: None,
            pending_string_len: None,
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::readByte
    /// Read the next byte.
    fn read_byte(&mut self) -> Option<u8> {
        let b = self.input.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    // Ghidra: marshal.hh:512 PackedDecode::readHeader
    /// Read a header byte and extract the (record_type, id). Returns None at
    /// EOF.
    fn read_header(&mut self) -> Option<(u8, u32)> {
        use packed_format::*;
        let b = self.read_byte()?;
        let header_type = b & HEADER_MASK;
        let mut id = (b & ELEMENTID_MASK) as u32;
        if (b & HEADEREXTEND_MASK) != 0 {
            // Extended id: next byte has 7 more bits.
            let ext = self.read_byte()?;
            id = (id << RAWDATA_BITSPERBYTE) | ((ext & RAWDATA_MASK) as u32);
        }
        Some((header_type, id))
    }

    // Ghidra: marshal.cc:603 PackedDecode::readInteger
    /// Read an encoded integer given its length in bytes.
    fn read_integer(&mut self, len: usize) -> u64 {
        let mut val = 0u64;
        for _ in 0..len {
            if let Some(b) = self.read_byte() {
                val = (val << packed_format::RAWDATA_BITSPERBYTE) | (b & packed_format::RAWDATA_MASK) as u64;
            }
        }
        val
    }

    // Ghidra: marshal.hh:512 PackedDecode::lengthCode
    /// Determine the length code from a type byte.
    fn length_code(type_byte: u8) -> u8 {
        type_byte & packed_format::LENGTHCODE_MASK
    }

    // Ghidra: marshal.hh:512 PackedDecode::typeCode
    /// Determine the type code from a type byte.
    fn type_code(type_byte: u8) -> u8 {
        (type_byte >> packed_format::TYPECODE_SHIFT) & 0xf
    }
}

impl Decoder for PackedDecode {
    // Ghidra: marshal.cc:716 PackedDecode::peekElement
    fn peek_element(&self) -> u32 {
        use packed_format::*;
        // Scan forward from current pos to find the next ELEMENT_START header.
        let mut scan = self.pos;
        // Skip any attributes that belong to the current element.
        let attr_skip = self.stack.last().map(|(_, _, cur)| *cur).unwrap_or(self.pos);
        scan = scan.max(attr_skip);
        while scan < self.input.len() {
            let b = self.input[scan];
            let ht = b & HEADER_MASK;
            if ht == ELEMENT_START {
                // Decode the id.
                let mut id = (b & ELEMENTID_MASK) as u32;
                if (b & HEADEREXTEND_MASK) != 0 && scan + 1 < self.input.len() {
                    let ext = self.input[scan + 1];
                    id = (id << RAWDATA_BITSPERBYTE) | ((ext & RAWDATA_MASK) as u32);
                }
                return id;
            }
            if ht == ATTRIBUTE {
                // Skip this attribute to continue scanning.
                scan += 1;
                if (b & HEADEREXTEND_MASK) != 0 {
                    scan += 1;
                }
                // Read type byte.
                if scan >= self.input.len() {
                    break;
                }
                let tb = self.input[scan];
                scan += 1;
                let tc = Self::type_code(tb);
                let lc = Self::length_code(tb);
                // Skip the data based on type.
                match tc {
                    TYPECODE_BOOLEAN => {} // No data bytes.
                    TYPECODE_SIGNEDINT_POSITIVE | TYPECODE_SIGNEDINT_NEGATIVE | TYPECODE_UNSIGNEDINT | TYPECODE_ADDRESSSPACE => {
                        scan += lc as usize;
                    }
                    TYPECODE_SPECIALSPACE => {} // No data bytes.
                    TYPECODE_STRING => {
                        // lc = length of the length encoding; read the actual string length.
                        let mut str_len = 0u64;
                        for _ in 0..lc {
                            if scan >= self.input.len() { break; }
                            str_len = (str_len << RAWDATA_BITSPERBYTE) | (self.input[scan] & RAWDATA_MASK) as u64;
                            scan += 1;
                        }
                        scan += str_len as usize;
                    }
                    _ => break,
                }
            } else if ht == ELEMENT_END {
                return 0; // No more children.
            } else {
                break;
            }
        }
        0
    }

    // Ghidra: marshal.cc:730 PackedDecode::openElement
    fn open_element(&mut self) -> u32 {
        use packed_format::*;
        loop {
            let (ht, id) = match self.read_header() {
                Some(h) => h,
                None => return 0,
            };
            if ht == ELEMENT_START {
                let attr_start = self.pos;
                self.stack.push((id, attr_start, attr_start));
                return id;
            }
            // Skip non-element-start headers (shouldn't happen at this level).
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::openElementMatching
    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32 {
        let id = self.open_element();
        if id != elem_id.id {
            return 0;
        }
        id
    }

    // Ghidra: marshal.cc:767 PackedDecode::closeElement
    fn close_element(&mut self, _id: u32) {
        // Read until we find the matching ELEMENT_END.
        use packed_format::*;
        loop {
            let (ht, _) = match self.read_header() {
                Some(h) => h,
                None => break,
            };
            if ht == ELEMENT_END {
                break;
            }
            // Skip attributes.
            if ht == ATTRIBUTE {
                if let Some(tb) = self.read_byte() {
                    let tc = Self::type_code(tb);
                    let lc = Self::length_code(tb);
                    match tc {
                        TYPECODE_BOOLEAN | TYPECODE_SPECIALSPACE => {}
                        TYPECODE_STRING => {
                            let str_len = self.read_integer(lc as usize);
                            for _ in 0..str_len {
                                let _ = self.read_byte();
                            }
                        }
                        _ => {
                            for _ in 0..lc {
                                let _ = self.read_byte();
                            }
                        }
                    }
                }
            }
        }
        self.stack.pop();
    }

    // Ghidra: marshal.cc:782 PackedDecode::closeElementSkipping
    fn close_element_skipping(&mut self, id: u32) {
        self.close_element(id);
    }

    // Ghidra: marshal.hh:512 PackedDecode::nextAttributeId
    fn next_attribute_id(&mut self) -> u32 {
        use packed_format::*;
        if self.pos >= self.input.len() {
            return 0;
        }
        let b = self.input[self.pos];
        let ht = b & HEADER_MASK;
        if ht != ATTRIBUTE {
            return 0; // No more attributes.
        }
        // Decode the attribute id.
        let mut id = (b & ELEMENTID_MASK) as u32;
        self.pos += 1;
        if (b & HEADEREXTEND_MASK) != 0 {
            if let Some(ext) = self.read_byte() {
                id = (id << RAWDATA_BITSPERBYTE) | ((ext & RAWDATA_MASK) as u32);
            }
        }
        // Read the type byte to know how to handle the value.
        let type_byte = self.read_byte().unwrap_or(0);
        let tc = Self::type_code(type_byte);
        let lc = Self::length_code(type_byte);
        match tc {
            TYPECODE_BOOLEAN | TYPECODE_SPECIALSPACE => {
                // No data bytes. Store the type_byte for the read_* call.
                self.stack.last_mut().map(|(_, _, cur)| *cur = self.pos);
                // Save type info for subsequent read.
                self.pending_type = Some(type_byte);
            }
            TYPECODE_STRING => {
                let str_len = self.read_integer(lc as usize);
                self.pending_string_len = Some(str_len as usize);
                self.pending_type = Some(type_byte);
                self.stack.last_mut().map(|(_, _, cur)| *cur = self.pos);
            }
            _ => {
                self.pending_int_len = Some(lc as usize);
                self.pending_type = Some(type_byte);
                self.stack.last_mut().map(|(_, _, cur)| *cur = self.pos);
            }
        }
        id
    }

    // Ghidra: marshal.hh:512 PackedDecode::attributeName
    fn attribute_name(&self, id: u32) -> Option<String> {
        self.registry
            .read()
            .unwrap()
            .attribute_name(id)
            .map(|s| s.to_string())
    }

    // Ghidra: marshal.hh:512 PackedDecode::elementName
    fn element_name(&self, id: u32) -> Option<String> {
        self.registry
            .read()
            .unwrap()
            .element_name(id)
            .map(|s| s.to_string())
    }

    // Ghidra: marshal.cc:801 PackedDecode::rewindAttributes
    fn rewind_attributes(&mut self) {
        if let Some((_, start, _)) = self.stack.last_mut() {
            self.pos = *start;
        }
    }

    // Ghidra: marshal.cc:825 PackedDecode::getIndexedAttributeId
    /// The packed format encodes indexed attribute ids directly in the
    /// attribute header, so no reinterpretation is ever needed:
    /// `PackedDecode::getIndexedAttributeId` (marshal.cc:825-829)
    /// unconditionally returns `ATTRIB_UNKNOWN.getId()`.
    fn get_indexed_attribute_id(&mut self, _attrib_id: &AttributeId) -> u32 {
        ATTRIB_UNKNOWN
    }

    // Ghidra: marshal.cc:997 PackedDecode::readSpace
    /// Read the current attribute as an address space reference. Faithful
    /// to `PackedDecode::readSpace` (marshal.cc:997-1031): an
    /// ADDRESSSPACE-typed attribute carries the space index, resolved
    /// through `AddrSpaceManager::getSpace` with
    /// `DecoderError("Unknown address space index")` when the slot is
    /// empty; a SPECIALSPACE-typed attribute carries the special code in
    /// the type byte's length field — only STACK and JOIN are accepted
    /// (resolved via `getStackSpace`/`getJoinSpace`), every other code
    /// throwing `DecoderError("Cannot marshal special address space")`;
    /// any other attribute type throws
    /// `DecoderError("Expecting space attribute")` after skipping its data
    /// (the `skipAttributeRemaining` tail, marshal.cc:1025).
    fn read_space(
        &mut self,
        spc_manager: &crate::space::SpaceRegistry,
    ) -> Result<crate::space::AddrSpace, String> {
        use crate::space::AddrSpace;
        use packed_format::*;
        // uint1 typeByte = getNextByte(curPos); — the type byte was already
        // consumed by next_attribute_id and staged in pending_type.
        let Some(type_byte) = self.pending_type.take() else {
            return Err("Expecting space attribute".to_string());
        };
        let type_code = Self::type_code(type_byte);
        let spc: AddrSpace;
        if type_code == TYPECODE_ADDRESSSPACE {
            // res = readInteger(readLengthCode(typeByte));
            let len = self.pending_int_len.take().unwrap_or(0);
            let res = self.read_integer(len) as usize;
            // spc = spcManager->getSpace(res);
            let Some(found) = spc_manager.get_space(res) else {
                return Err("Unknown address space index".to_string());
            };
            spc = found;
        } else if type_code == TYPECODE_SPECIALSPACE {
            // uint4 specialCode = readLengthCode(typeByte);
            let special_code = Self::length_code(type_byte) as u32;
            if special_code == SPECIALSPACE_STACK {
                spc = spc_manager.get_stack_space().ok_or_else(|| {
                    "Cannot marshal special address space".to_string()
                })?;
            } else if special_code == SPECIALSPACE_JOIN {
                spc = spc_manager.get_join_space().ok_or_else(|| {
                    "Cannot marshal special address space".to_string()
                })?;
            } else {
                return Err("Cannot marshal special address space".to_string());
            }
        } else {
            // skipAttributeRemaining(typeByte) — the header and type byte
            // are consumed; skip the remaining data bytes of the attribute.
            match type_code {
                TYPECODE_STRING => {
                    if let Some(len) = self.pending_string_len.take() {
                        for _ in 0..len {
                            let _ = self.read_byte();
                        }
                    }
                }
                TYPECODE_BOOLEAN => {}
                _ => {
                    let len = self.pending_int_len.take().unwrap_or(0);
                    for _ in 0..len {
                        let _ = self.read_byte();
                    }
                }
            }
            return Err("Expecting space attribute".to_string());
        }
        Ok(spc)
    }

    // Ghidra: marshal.cc:831 PackedDecode::readBool
    fn read_bool(&mut self) -> bool {
        if let Some(tb) = self.pending_type.take() {
            (tb & packed_format::LENGTHCODE_MASK) != 0
        } else {
            false
        }
    }

    // Ghidra: marshal.cc:844 PackedDecode::readBool(const AttributeId &)
    /// Read a specific attribute as a boolean. Faithful to
    /// `PackedDecode::readBool(attribId)` (marshal.cc:844-851): the
    /// attribute list is rescanned from the element start, a match reads
    /// the type byte's length-code bit (`readBool`, marshal.cc:831-842),
    /// and the scan position is restored to the element start
    /// (marshal.cc:849). Divergence note (MARSHAL-READBOOL-0001
    /// residual): exhausting the list without a match returns `false`
    /// where the oracle's `findMatchingAttribute` throws
    /// `DecoderError("Attribute <name> is not present")` (marshal.cc:636).
    fn read_bool_attr(&mut self, attrib_id: &AttributeId) -> bool {
        // Rewind and find the attribute (curPos = startPos; marshal.cc:623).
        self.rewind_attributes();
        loop {
            let aid = self.next_attribute_id();
            if aid == 0 || aid == attrib_id.id {
                let res = self.read_bool();
                // curPos = startPos; (marshal.cc:849)
                self.rewind_attributes();
                return res;
            }
            // Skip the current value.
            let _ = self.read_string();
        }
    }

    // Ghidra: marshal.cc:853 PackedDecode::readSignedInteger
    fn read_signed_integer(&mut self) -> i64 {
        let len = self.pending_int_len.take().unwrap_or(0);
        let val = self.read_integer(len);
        let is_neg = self
            .pending_type
            .take()
            .map(|tb| Self::type_code(tb) == packed_format::TYPECODE_SIGNEDINT_NEGATIVE)
            .unwrap_or(false);
        if is_neg {
            -(val as i64)
        } else {
            val as i64
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::readSignedIntegerAttr
    fn read_signed_integer_attr(&mut self, attrib_id: &AttributeId) -> i64 {
        self.rewind_attributes();
        loop {
            let aid = self.next_attribute_id();
            if aid == 0 || aid == attrib_id.id {
                return self.read_signed_integer();
            }
            let _ = self.read_string();
        }
    }

    // Ghidra: marshal.cc:921 PackedDecode::readUnsignedInteger
    fn read_unsigned_integer(&mut self) -> u64 {
        let len = self.pending_int_len.take().unwrap_or(0);
        let _ = self.pending_type.take();
        self.read_integer(len)
    }

    // Ghidra: marshal.hh:512 PackedDecode::readUnsignedIntegerAttr
    fn read_unsigned_integer_attr(&mut self, attrib_id: &AttributeId) -> u64 {
        self.rewind_attributes();
        loop {
            let aid = self.next_attribute_id();
            if aid == 0 || aid == attrib_id.id {
                return self.read_unsigned_integer();
            }
            let _ = self.read_string();
        }
    }

    // Ghidra: marshal.cc:951 PackedDecode::readString
    fn read_string(&mut self) -> String {
        if let Some(len) = self.pending_string_len.take() {
            let bytes = &self.input[self.pos..self.pos + len.min(self.input.len() - self.pos)];
            self.pos += len.min(self.input.len() - self.pos);
            let _ = self.pending_type.take();
            String::from_utf8_lossy(bytes).to_string()
        } else {
            String::new()
        }
    }

    // Ghidra: marshal.hh:512 PackedDecode::readStringAttr
    fn read_string_attr(&mut self, attrib_id: &AttributeId) -> String {
        self.rewind_attributes();
        loop {
            let aid = self.next_attribute_id();
            if aid == 0 || aid == attrib_id.id {
                return self.read_string();
            }
            let _ = self.read_string();
        }
    }
}

/// Pending decode state for PackedDecode. These fields store the type info
/// from the attribute header, consumed by the corresponding read_* method.
impl PackedDecode {
    // Fields are stored in the struct definition; these are accessed via the
    // struct's fields. We use a separate impl block to avoid duplicating the
    // struct definition.
}

// Add pending fields to PackedDecode via a separate implementation.
// We need to add the fields to the struct. Let's use a workaround:
// The struct already exists above; we add the fields by using a thread-local
// or by modifying the struct definition. Since we can't modify it after
// definition, let's add the fields directly in the struct.

// Actually, the struct was already defined above without these fields.
// We need to add them. Let's redefine with the fields.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_id() {
        let a = AttributeId::new("name", 5);
        assert_eq!(a.get_name(), "name");
        assert_eq!(a.get_id(), 5);
        let b = AttributeId::new("other", 5);
        assert!(a == b); // equality by id
    }

    #[test]
    fn test_element_id() {
        let e = ElementId::new("scope", 10);
        assert_eq!(e.get_name(), "scope");
        assert_eq!(e.get_id(), 10);
    }

    #[test]
    fn test_registry() {
        let mut reg = IdRegistry::new();
        let id1 = reg.register_attribute("label");
        let id2 = reg.register_attribute("label"); // same name → same id
        assert_eq!(id1, 131);
        assert_eq!(id1, id2);
        assert_eq!(reg.find_attribute("label"), id1);
        assert_eq!(reg.find_attribute("nonexistent"), ATTRIB_UNKNOWN);
        let eid = reg.register_element("db");
        assert_eq!(eid, 68);
        assert_eq!(reg.find_element("db"), eid);
        assert!(reg.attribute_name(id1).is_some());
        assert_eq!(reg.register_attribute("runtime_order_a"), ATTRIB_UNKNOWN);
        assert_eq!(reg.register_attribute("runtime_order_b"), ATTRIB_UNKNOWN);
        assert_eq!(reg.register_element("runtime_order_a"), ELEM_UNKNOWN);
        assert_eq!(reg.register_element("runtime_order_b"), ELEM_UNKNOWN);
        assert!(reg.register_attribute_with_id("size", 19));
        assert!(!reg.register_attribute_with_id("size", 20));
        assert!(reg.register_element_with_id("data", 1));
        assert!(!reg.register_element_with_id("data", 2));
        assert_eq!(reg.find_attribute_in_scope("size", 1), ATTRIB_UNKNOWN);
        assert_eq!(reg.find_element_in_scope("data", 1), ELEM_UNKNOWN);
    }

    #[test]
    fn test_locked_id_tables_are_complete_and_bidirectional() {
        IdRegistry::initialize();
        IdRegistry::initialize();
        let reg = IdRegistry::new();
        assert_eq!(ATTRIBUTE_ID_TABLE.len(), 146);
        assert_eq!(ELEMENT_ID_TABLE.len(), 274);
        for &(name, id) in ATTRIBUTE_ID_TABLE {
            assert_eq!(reg.find_attribute(name), id);
            assert_eq!(reg.attribute_name(id), Some(name));
        }
        for &(name, id) in ELEMENT_ID_TABLE {
            assert_eq!(reg.find_element(name), id);
            assert_eq!(reg.element_name(id), Some(name));
        }
        assert_eq!(reg.attribute_name(0), None);
        assert_eq!(reg.element_name(0), None);
        assert_eq!(reg.find_attribute("size"), 19);
        assert_eq!(reg.find_attribute("space"), 20);
    }

    #[test]
    fn test_element() {
        let mut e = Element::new();
        e.set_name("head");
        e.add_attribute("locked", "1");
        e.add_content("hello");
        assert_eq!(e.get_name(), "head");
        assert_eq!(e.get_num_attributes(), 1);
        assert_eq!(e.get_attribute_name(0), "locked");
        assert_eq!(e.get_attribute_value_at(0), "1");
        assert_eq!(e.get_attribute_value("locked"), Some("1"));
        assert_eq!(e.get_attribute_value("missing"), None);
        assert_eq!(e.get_content(), "hello");
    }

    #[test]
    fn test_element_children() {
        let mut parent = Element::new();
        parent.set_name("parent");
        let mut child = Element::new();
        child.set_name("child");
        let child_arc = Arc::new(RwLock::new(child));
        parent.add_child(child_arc);
        assert_eq!(parent.get_children().len(), 1);
        assert_eq!(parent.get_children()[0].read().unwrap().get_name(), "child");
    }

    #[test]
    fn test_document() {
        let mut doc = Document::new();
        let mut root = Element::new();
        root.set_name("root");
        doc.set_root(Arc::new(RwLock::new(root)));
        assert!(doc.get_root().is_some());
        assert_eq!(doc.get_root().unwrap().read().unwrap().get_name(), "root");
    }

    #[test]
    fn test_tree_encoder_roundtrip() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        let mut enc = TreeEncoder::new(registry.clone());
        let head_id = ElementId::new("data", 1);
        let num_id = AttributeId::new("num", 132);
        enc.open_element(&head_id);
        enc.write_unsigned_integer(&num_id, 42);
        enc.write_string(&AttributeId::new("name", registry.read().unwrap().find_attribute("name")), "foo");
        enc.close_element(&head_id);
        let doc = enc.into_document();
        let root = doc.get_root().unwrap();
        let rg = root.read().unwrap();
        assert_eq!(rg.get_name(), "data");
        assert_eq!(rg.get_attribute_value("num"), Some("42"));
        assert_eq!(rg.get_attribute_value("name"), Some("foo"));
    }

    #[test]
    fn test_tree_decoder() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        // Build a tree manually.
        let mut root = Element::new();
        root.set_name("data");
        root.add_attribute("num", "42");
        let mut dec = TreeDecoder::new(Arc::new(RwLock::new(root)), registry.clone());
        let id = dec.open_element();
        assert_eq!(id, 1);
        // Read the num attribute.
        let aid = dec.next_attribute_id();
        assert_eq!(aid, 132);
        let val = dec.read_unsigned_integer();
        assert_eq!(val, 42);
        dec.close_element(id);
    }

    #[test]
    fn test_reserved_ids() {
        assert_eq!(ATTRIB_UNKNOWN, 159);
        assert_eq!(ELEM_UNKNOWN, 289);
        assert_eq!(ATTRIB_CONTENT, 1);
    }

    // ----- PackedEncode / PackedDecode tests -----

    #[test]
    fn test_packed_encode_element_roundtrip() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        // Encode.
        let mut enc = PackedEncode::new();
        let root = ElementId::new("data", 1);
        let num = AttributeId::new("num", 132);
        enc.open_element(&root);
        enc.write_unsigned_integer(&num, 42);
        enc.write_bool(&AttributeId::new("readonly", 17), true);
        enc.write_string(&AttributeId::new("name", registry.write().unwrap().register_attribute("name")), "hello");
        enc.close_element(&root);
        let bytes = enc.into_bytes();
        assert!(!bytes.is_empty());

        // Decode.
        let mut dec = PackedDecode::new(bytes, registry.clone());
        let eid = dec.open_element();
        assert_eq!(eid, 1);

        // Read attributes in order: num, readonly, name.
        let aid1 = dec.next_attribute_id();
        let val1 = dec.read_unsigned_integer();
        assert_eq!(aid1, 132);
        assert_eq!(val1, 42);

        let aid2 = dec.next_attribute_id();
        let val2 = dec.read_bool();
        // flag id should be non-zero (registered).
        assert_ne!(aid2, 0);
        assert!(val2);

        let _aid3 = dec.next_attribute_id();
        let val3 = dec.read_string();
        assert_eq!(val3, "hello");

        dec.close_element(eid);
    }

    #[test]
    fn test_packed_encode_signed_integer() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        let mut enc = PackedEncode::new();
        let attr = AttributeId::new("val", 24);
        enc.write_signed_integer(&attr, -100);
        let bytes = enc.into_bytes();

        let mut dec = PackedDecode::new(bytes, registry);
        dec.next_attribute_id();
        let val = dec.read_signed_integer();
        assert_eq!(val, -100);
    }

    #[test]
    fn test_packed_encode_large_unsigned() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        let mut enc = PackedEncode::new();
        let attr = AttributeId::new("value", 25);
        enc.write_unsigned_integer(&attr, 0x123456789A);
        let bytes = enc.into_bytes();

        let mut dec = PackedDecode::new(bytes, registry);
        dec.next_attribute_id();
        let val = dec.read_unsigned_integer();
        assert_eq!(val, 0x123456789A);
    }

    #[test]
    fn test_packed_encode_zero() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        let mut enc = PackedEncode::new();
        let attr = AttributeId::new("offset", 16);
        enc.write_unsigned_integer(&attr, 0);
        let bytes = enc.into_bytes();

        let mut dec = PackedDecode::new(bytes, registry);
        dec.next_attribute_id();
        let val = dec.read_unsigned_integer();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_packed_encode_extended_id() {
        let registry = Arc::new(RwLock::new(IdRegistry::new()));

        let mut enc = PackedEncode::new();
        let elem = ElementId::new("compiler_spec", 132); // > 0x1f → extended.
        enc.open_element(&elem);
        enc.close_element(&elem);
        let bytes = enc.into_bytes();

        let mut dec = PackedDecode::new(bytes, registry);
        let eid = dec.open_element();
        assert_eq!(eid, 132);
        dec.close_element(eid);
    }

    // ---- XML text ingestion (Rugra regression only; oracle parity is
    // observed by tests/oracle/xml_text_dom_1204, not by these tests). ----

    #[test]
    fn test_xml_text_basic_tree_and_attribute_order() {
        let doc = xml_tree(
            b"<compiler_spec><stackpointer register=\"rsp\" space=\"ram\" growth=\"down\"/></compiler_spec>",
        )
        .expect("parse succeeds");
        let root = doc.get_root().expect("root element");
        let root = root.read().unwrap();
        assert_eq!(root.get_name(), "compiler_spec");
        assert_eq!(root.get_content(), "");
        assert_eq!(root.get_children().len(), 1);
        let child = root.get_children()[0].read().unwrap();
        assert_eq!(child.get_name(), "stackpointer");
        assert_eq!(child.get_num_attributes(), 3);
        assert_eq!(child.get_attribute_name(0), "register");
        assert_eq!(child.get_attribute_value_at(0), "rsp");
        assert_eq!(child.get_attribute_name(1), "space");
        assert_eq!(child.get_attribute_value_at(1), "ram");
        assert_eq!(child.get_attribute_name(2), "growth");
        assert_eq!(child.get_attribute_value_at(2), "down");
        assert_eq!(child.get_children().len(), 0);
    }

    #[test]
    fn test_xml_text_content_and_whitespace_rules() {
        // Whitespace-only chardata is dropped (ignorableWhitespace); the
        // synthetic trailing '\n' after the root element is Misc, not content.
        let doc = xml_tree(b"<data>  \n\t  </data>").expect("parse succeeds");
        let root = doc.get_root().unwrap().read().unwrap();
        assert_eq!(root.get_name(), "data");
        assert_eq!(root.get_content(), "");

        let doc = xml_tree(b"<data>keep <b/> this</data>").expect("parse succeeds");
        let root = doc.get_root().unwrap().read().unwrap();
        // 'keep ' and ' this' are two significant CHARDATA pieces.
        assert_eq!(root.get_content(), "keep  this");
        assert_eq!(root.get_children().len(), 1);

        // Whitespace-only CDATA is dropped by the same print_content rule.
        let doc = xml_tree(b"<data><![CDATA[   ]]></data>").expect("parse succeeds");
        let root = doc.get_root().unwrap().read().unwrap();
        assert_eq!(root.get_content(), "");

        // CDATA keeps embedded markup characters as literal content.
        let doc = xml_tree(b"<data><![CDATA[x<y & z]]></data>").expect("parse succeeds");
        let root = doc.get_root().unwrap().read().unwrap();
        assert_eq!(root.get_content(), "x<y & z");
    }

    #[test]
    fn test_xml_text_entity_and_char_refs() {
        let doc = xml_tree(b"<r a=\"&lt;&amp;&quot;\">&#65;&#x42;&amp;</r>").expect("parse");
        let root = doc.get_root().unwrap().read().unwrap();
        assert_eq!(root.get_attribute_value("a"), Some("<&\""));
        assert_eq!(root.get_content(), "AB&");
    }

    #[test]
    fn test_convert_char_ref_wraparound_de_facto_cpp() {
        // KUNAUB-CHARREF-0001: the C++ `int4 val` accumulator in
        // convertCharRef (xml.cc:2337-2360) has no digit-count cap; on the
        // locked x86-64 oracle build the signed overflow wraps silently
        // (two's complement). These assertions pin hand-computed de-facto-C++
        // wrap values; with wrapping_mul/wrapping_add the result is
        // profile-independent (debug == release == de-facto oracle).
        // Non-overflow sanity first.
        assert_eq!(convert_char_ref("x41"), 0x41);
        assert_eq!(convert_char_ref("65"), 65);
        assert_eq!(convert_char_ref("x7fffffff"), i32::MAX);
        // Decimal 2^31 wraps to INT_MIN (classic signed wrap).
        assert_eq!(convert_char_ref("2147483648"), i32::MIN);
        // Decimal 2^32 wraps to 0.
        assert_eq!(convert_char_ref("4294967296"), 0);
        // Decimal 10^10-1 = 9999999999 wraps to 1410065407 (classic value).
        assert_eq!(convert_char_ref("9999999999"), 1410065407);
        // Hex 2^32 wraps to 0.
        assert_eq!(convert_char_ref("x100000000"), 0);
        // Hex 2^33-1 wraps to -1 (all ones).
        assert_eq!(convert_char_ref("x1ffffffff"), -1);
        // Nine hex 1s: 0x11111111*16 wraps back onto itself then +1.
        assert_eq!(convert_char_ref("x111111111"), 0x11111111);
    }

    #[test]
    fn test_convert_char_ref_overflow_push_truncates_low_byte() {
        // Downstream of the wrap: the grammar action appends the value via
        // string::operator+=(char) (xml.cc:1610/1628/1790), truncating to the
        // low byte. 0x141 = 321 -> low byte 0x41 = 'A' (ASCII identity).
        let mut buffer = String::new();
        push_reference_char(&mut buffer, convert_char_ref("x141"));
        assert_eq!(buffer, "A");
    }

    #[test]
    fn test_xml_text_prolog_comments_endtag_whitespace() {
        let doc = xml_tree(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!--c--><r> <!-- inner --> <c/></r>")
            .expect("parse succeeds");
        let root = doc.get_root().unwrap().read().unwrap();
        assert_eq!(root.get_name(), "r");
        // Whitespace around the inner comment is whitespace-only chardata
        // (dropped); the comment itself adds nothing.
        assert_eq!(root.get_content(), "");
        assert_eq!(root.get_children().len(), 1);
        assert_eq!(root.get_children()[0].read().unwrap().get_name(), "c");

        // End tag with whitespace, self-closing with whitespace.
        assert!(xml_tree(b"<r>x</r >").is_ok());
        assert!(xml_tree(b"<r />").is_ok());
        // The end tag name is not checked against the start tag name.
        assert!(xml_tree(b"<r>x</q>").is_ok());
        // A comment AFTER the root element is always a syntax error: the
        // document grammar admits exactly one trailing Misc, and the
        // scanner's synthetic end-of-stream '\n' can then never follow.
        let err = xml_tree(b"<r/><!--after-->").expect_err("trailing comment");
        assert_eq!(err.explain, "syntax error");
        // `]]` followed by a reference is ordinary content.
        let doc = xml_tree(b"<r>]]&gt;</r>").expect("raw ]] with ref parses");
        assert_eq!(doc.get_root().unwrap().read().unwrap().get_content(), "]]>");
        // `<!DOCTYPE` at the very first position is unreachable in the
        // grammar and reports the plain syntax error.
        let err = xml_tree(b"<!DOCTYPE x>").expect_err("dtd first");
        assert_eq!(err.explain, "syntax error");
        // After any prologpre item, `<!DOCTYPE` reports the DTD error.
        let err = xml_tree(b"<!--c--><!DOCTYPE x>").expect_err("dtd after misc");
        assert_eq!(err.explain, "DTD's not supported");
        let err = xml_tree(b"<?xml version=\"1.0\"?><!DOCTYPE x>").expect_err("dtd after decl");
        assert_eq!(err.explain, "DTD's not supported");
        // Processing instructions fail everywhere they can appear.
        let err = xml_tree(b"<!--c--><?php ?>").expect_err("pi after comment");
        assert_eq!(err.explain, "Processing instructions are not supported");
        let err = xml_tree(b"<r><?php ?></r>").expect_err("pi in content");
        assert_eq!(err.explain, "Processing instructions are not supported");
        // End tag with newline whitespace.
        assert!(xml_tree(b"<r>x</r\n>").is_ok());
        // '<' inside an attribute value is a syntax error.
        let err = xml_tree(b"<r a=\"<\"/>").expect_err("lt in attribute");
        assert_eq!(err.explain, "syntax error");
    }

    #[test]
    fn test_xml_text_error_messages() {
        let err = xml_tree(b"<r><b></r>").expect_err("mismatched nesting");
        assert_eq!(err.explain, "syntax error");
        let err = xml_tree(b"<r>").expect_err("unclosed");
        assert_eq!(err.explain, "syntax error");
        let err = xml_tree(b"<?php ?>").expect_err("processing instruction");
        assert_eq!(err.explain, "Processing instructions are not supported");
        let err = xml_tree(b"<!DOCTYPE x>").expect_err("dtd at first position");
        assert_eq!(err.explain, "syntax error");
        let err = xml_tree(b"<r/><r/>").expect_err("two roots");
        assert_eq!(err.explain, "syntax error");
        let err = xml_tree(b"").expect_err("empty input");
        assert_eq!(err.explain, "syntax error");
        let err = xml_tree(b"<r>]]>").map(|_| ()).expect_err("raw ]]> text");
        assert_eq!(err.explain, "syntax error");
    }

    #[test]
    fn test_document_storage_register_and_null_slot() {
        let mut storage = DocumentStorage::new();
        let doc1 = storage
            .parse_document(b"<colors><red/></colors>")
            .expect("parse succeeds");
        let red = doc1.get_root().unwrap().read().unwrap().children[0].clone();
        storage.register_tag(&red);
        assert!(storage.get_tag("red").is_some());
        assert!(storage.get_tag("blue").is_none());
        // Same-name registration overwrites.
        let doc2 = storage
            .parse_document(b"<other><red x=\"1\"/></other>")
            .expect("parse succeeds");
        let red2 = doc2.get_root().unwrap().read().unwrap().children[0].clone();
        storage.register_tag(&red2);
        let fetched = storage.get_tag("red").expect("still registered");
        assert_eq!(fetched.read().unwrap().get_attribute_value("x"), Some("1"));

        // A failed parse appends the null document slot first and keeps it.
        let before = storage.doclist_len();
        let err = storage
            .parse_document(b"<broken>")
            .expect_err("parse fails");
        assert_eq!(err.explain, "syntax error");
        assert_eq!(storage.doclist_len(), before + 1);
        // The container remains usable after the failure.
        storage
            .parse_document(b"<ok/>")
            .expect("storage usable after failure");

        let err = storage
            .open_document("/nonexistent/xml/text/dom/fixture.xml")
            .expect_err("open fails");
        assert_eq!(
            err.explain,
            "Unable to open xml document /nonexistent/xml/text/dom/fixture.xml"
        );
    }
    // Ghidra: marshal.cc:296/353 XmlDecode integer extraction semantics
    #[test]
    fn test_cpp_stream_integer_bases() {
        // istringstream unsetf semantics: hex/octal autodetect, failed
        // parse -> 0, sign handling.
        assert_eq!(super::cpp_stream_unsigned("0x288"), 0x288);
        assert_eq!(super::cpp_stream_unsigned("0X10"), 16);
        assert_eq!(super::cpp_stream_unsigned("010"), 8); // leading 0 -> octal
        assert_eq!(super::cpp_stream_unsigned("0"), 0);
        assert_eq!(super::cpp_stream_unsigned("0xfffffffffff0bdc1"), 0xfffffffffff0bdc1);
        assert_eq!(super::cpp_stream_unsigned("40"), 40);
        assert_eq!(super::cpp_stream_unsigned("  16"), 16); // leading ws skipped
        assert_eq!(super::cpp_stream_unsigned("0x"), 0); // bare 0x -> 0
        assert_eq!(super::cpp_stream_unsigned("zz"), 0); // failed parse -> 0
        assert_eq!(super::cpp_stream_unsigned("12zz"), 12); // longest prefix
        assert_eq!(super::cpp_stream_unsigned("08"), 0); // octal stops at 0
        assert_eq!(super::cpp_stream_signed("-5"), -5);
        assert_eq!(super::cpp_stream_signed("-0x10"), -16);
        assert_eq!(super::cpp_stream_signed("+3"), 3);
        assert_eq!(super::cpp_stream_signed(""), 0);
    }
}
