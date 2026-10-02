use rudra::address::RangeProperties;
use rudra::marshal::{AttributeId, Decoder, Element, ElementId, IdRegistry, TreeDecoder};
use std::sync::{Arc, RwLock};

const ELEM_RANGE: u32 = 12;
const ELEM_REGISTER: u32 = 14;
const ATTRIB_NAME: u32 = 14;
const ATTRIB_SPACE: u32 = 20;
const ATTRIB_FIRST: u32 = 27;
const ATTRIB_LAST: u32 = 28;
const ATTRIB_UNKNOWN: u32 = 159;

enum AttributeValue {
    Text(&'static str),
    Number(u64),
}

struct Attribute {
    id: u32,
    value: AttributeValue,
}

impl Attribute {
    fn text(id: u32, value: &'static str) -> Self {
        Self {
            id,
            value: AttributeValue::Text(value),
        }
    }

    fn number(id: u32, value: u64) -> Self {
        Self {
            id,
            value: AttributeValue::Number(value),
        }
    }

    fn ignored(id: u32) -> Self {
        Self::text(id, "ignored")
    }
}

struct TraceDecoder {
    element_id: u32,
    attributes: Vec<Attribute>,
    attribute_position: usize,
    current_attribute: usize,
    child_count: i32,
    trace: Vec<String>,
    element_open: bool,
    children_at_close: i32,
    child_open_count: i32,
    peek_count: std::cell::Cell<i32>,
}

impl TraceDecoder {
    fn new(element_id: u32, attributes: Vec<Attribute>, child_count: i32) -> Self {
        Self {
            element_id,
            attributes,
            attribute_position: 0,
            current_attribute: 0,
            child_count,
            trace: Vec::new(),
            element_open: false,
            children_at_close: -1,
            child_open_count: 0,
            peek_count: std::cell::Cell::new(0),
        }
    }
}

impl Decoder for TraceDecoder {
    fn peek_element(&self) -> u32 {
        self.peek_count.set(self.peek_count.get() + 1);
        if self.element_open && self.child_count != 0 {
            99
        } else {
            0
        }
    }

    fn open_element(&mut self) -> u32 {
        if self.element_open {
            self.child_open_count += 1;
            self.trace.push("open-child:99".to_string());
            return 99;
        }
        self.element_open = true;
        self.trace.push(format!("open:{}", self.element_id));
        self.element_id
    }

    fn open_element_matching(&mut self, elem_id: &ElementId) -> u32 {
        let id = self.open_element();
        if id == elem_id.id {
            id
        } else {
            0
        }
    }

    fn close_element(&mut self, id: u32) {
        self.trace.push(format!("close:{id}"));
        self.children_at_close = self.child_count;
        self.element_open = false;
    }

    fn close_element_skipping(&mut self, id: u32) {
        self.trace.push(format!("close-skipping:{id}"));
        self.children_at_close = self.child_count;
        self.element_open = false;
    }

    fn next_attribute_id(&mut self) -> u32 {
        if self.attribute_position == self.attributes.len() {
            self.trace.push("next:0".to_string());
            return 0;
        }
        self.current_attribute = self.attribute_position;
        let id = self.attributes[self.attribute_position].id;
        self.attribute_position += 1;
        self.trace.push(format!("next:{id}"));
        id
    }

    fn attribute_name(&self, id: u32) -> Option<String> {
        match id {
            ATTRIB_NAME => Some("name".to_string()),
            ATTRIB_SPACE => Some("space".to_string()),
            ATTRIB_FIRST => Some("first".to_string()),
            ATTRIB_LAST => Some("last".to_string()),
            ATTRIB_UNKNOWN => Some("(unknown)".to_string()),
            _ => None,
        }
    }

    fn element_name(&self, id: u32) -> Option<String> {
        match id {
            ELEM_RANGE => Some("range".to_string()),
            ELEM_REGISTER => Some("register".to_string()),
            77 => Some("bogus".to_string()),
            _ => None,
        }
    }

    fn rewind_attributes(&mut self) {
        self.attribute_position = 0;
        self.current_attribute = 0;
        self.trace.push("rewind".to_string());
    }

    fn read_bool(&mut self) -> bool {
        false
    }

    fn read_bool_attr(&mut self, _attrib_id: &AttributeId) -> bool {
        false
    }

    fn read_signed_integer(&mut self) -> i64 {
        0
    }

    fn read_signed_integer_attr(&mut self, _attrib_id: &AttributeId) -> i64 {
        0
    }

    fn read_unsigned_integer(&mut self) -> u64 {
        let value = match self.attributes[self.current_attribute].value {
            AttributeValue::Number(value) => value,
            AttributeValue::Text(_) => 0,
        };
        self.trace.push(format!("uint:{value}"));
        value
    }

    fn read_unsigned_integer_attr(&mut self, _attrib_id: &AttributeId) -> u64 {
        self.read_unsigned_integer()
    }

    fn read_string(&mut self) -> String {
        let value = match self.attributes[self.current_attribute].value {
            AttributeValue::Text(value) => value,
            AttributeValue::Number(_) => "",
        };
        self.trace.push(format!("string:{value}"));
        value.to_string()
    }

    fn read_string_attr(&mut self, _attrib_id: &AttributeId) -> String {
        self.read_string()
    }
}

fn observe(
    name: &str,
    props: &RangeProperties,
    decoder: &TraceDecoder,
    result: &str,
    error: &str,
) {
    println!(
        "case={name}|result={result}|error={error}|space={}|first={}|last={}|is_register={}|seen_last={}|trace={}|decoder_open={}|children_at_close={}|child_opens={}|peek_calls={}",
        props.space_name,
        props.first,
        props.last,
        u8::from(props.is_register),
        u8::from(props.seen_last),
        decoder.trace.join(","),
        u8::from(decoder.element_open),
        decoder.children_at_close,
        decoder.child_open_count,
        decoder.peek_count.get(),
    );
}

fn decode_and_observe(name: &str, props: &mut RangeProperties, decoder: &mut TraceDecoder) {
    match props.decode(decoder) {
        Ok(()) => observe(name, props, decoder, "OK", "-"),
        Err(error) => observe(name, props, decoder, "DecoderError", &error.to_string()),
    }
}

fn observe_tree(
    name: &str,
    props: &RangeProperties,
    trace: &[String],
    result: &str,
    error: &str,
) {
    println!(
        "case={name}|result={result}|error={error}|space={}|first={}|last={}|is_register={}|seen_last={}|trace={}|decoder_open=0|children_at_close=0|child_opens=0|peek_calls=2",
        props.space_name,
        props.first,
        props.last,
        u8::from(props.is_register),
        u8::from(props.seen_last),
        trace.join(","),
    );
}

fn main() {
    println!(
        "schema=1|fixture=CSPEC-RANGEPROPS-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    let mut defaults = RangeProperties::new();
    let mut defaults_decoder = TraceDecoder::new(ELEM_RANGE, Vec::new(), 0);
    decode_and_observe("defaults", &mut defaults, &mut defaults_decoder);

    let ordered_attributes = vec![
        Attribute::text(ATTRIB_SPACE, "ram"),
        Attribute::ignored(ATTRIB_UNKNOWN),
        Attribute::number(ATTRIB_FIRST, 16),
        Attribute::number(ATTRIB_LAST, 32),
    ];
    let mut ordered = RangeProperties::new();
    let mut ordered_decoder = TraceDecoder::new(ELEM_RANGE, ordered_attributes, 0);
    decode_and_observe("ordered_unknown", &mut ordered, &mut ordered_decoder);

    let name_then_space_attributes = vec![
        Attribute::text(ATTRIB_NAME, "RAX"),
        Attribute::text(ATTRIB_SPACE, "register"),
        Attribute::number(ATTRIB_FIRST, 8),
    ];
    let mut name_then_space = RangeProperties::new();
    let mut name_then_space_decoder =
        TraceDecoder::new(ELEM_REGISTER, name_then_space_attributes, 0);
    decode_and_observe(
        "name_then_space",
        &mut name_then_space,
        &mut name_then_space_decoder,
    );

    let range_name_attributes = vec![
        Attribute::text(ATTRIB_SPACE, "ram"),
        Attribute::text(ATTRIB_NAME, "RSP"),
        Attribute::number(ATTRIB_LAST, u64::MAX),
    ];
    let mut range_name = RangeProperties::new();
    let mut range_name_decoder = TraceDecoder::new(ELEM_RANGE, range_name_attributes, 0);
    decode_and_observe("range_name", &mut range_name, &mut range_name_decoder);

    let duplicate_attributes = vec![
        Attribute::number(ATTRIB_LAST, 5),
        Attribute::text(ATTRIB_NAME, "RAX"),
        Attribute::text(ATTRIB_SPACE, "ram"),
        Attribute::number(ATTRIB_LAST, 9),
        Attribute::text(ATTRIB_NAME, "RBX"),
    ];
    let mut duplicate = RangeProperties::new();
    let mut duplicate_decoder = TraceDecoder::new(ELEM_RANGE, duplicate_attributes, 0);
    decode_and_observe("duplicates", &mut duplicate, &mut duplicate_decoder);

    let first_persistent_attributes = vec![
        Attribute::text(ATTRIB_NAME, "RDI"),
        Attribute::number(ATTRIB_LAST, 7),
    ];
    let mut persistent = RangeProperties::new();
    let mut first_persistent_decoder =
        TraceDecoder::new(ELEM_REGISTER, first_persistent_attributes, 0);
    decode_and_observe(
        "persistent_first",
        &mut persistent,
        &mut first_persistent_decoder,
    );

    let second_persistent_attributes = vec![Attribute::number(ATTRIB_FIRST, 3)];
    let mut second_persistent_decoder =
        TraceDecoder::new(ELEM_RANGE, second_persistent_attributes, 0);
    decode_and_observe(
        "persistent_second",
        &mut persistent,
        &mut second_persistent_decoder,
    );

    let mut invalid_decoder = TraceDecoder::new(77, Vec::new(), 0);
    decode_and_observe(
        "invalid_after_success",
        &mut persistent,
        &mut invalid_decoder,
    );

    let child_attributes = vec![Attribute::text(ATTRIB_SPACE, "ram")];
    let mut child = RangeProperties::new();
    let mut child_decoder = TraceDecoder::new(ELEM_RANGE, child_attributes, 2);
    decode_and_observe("child_unvisited", &mut child, &mut child_decoder);

    let boundary_attributes = vec![
        Attribute::number(ATTRIB_FIRST, 0),
        Attribute::number(ATTRIB_LAST, u64::MAX),
    ];
    let mut boundary = RangeProperties::new();
    let mut boundary_decoder = TraceDecoder::new(ELEM_RANGE, boundary_attributes, 0);
    decode_and_observe("u64_boundary", &mut boundary, &mut boundary_decoder);

    // Real TreeDecoder over an in-memory Element: an unregistered attribute
    // name must resolve through IdRegistry::find_attribute to the locked
    // unknown id 159 and traversal must continue through later attributes.
    let mut unregistered_element = Element::new();
    unregistered_element.set_name("range");
    unregistered_element.add_attribute("space", "ram");
    unregistered_element.add_attribute("xmlunknown-attr", "ignored");
    unregistered_element.add_attribute("first", "16");
    unregistered_element.add_attribute("last", "32");
    let unregistered_root = Arc::new(RwLock::new(unregistered_element));
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    IdRegistry::initialize();

    let mut raw_trace: Vec<String> = Vec::new();
    let mut raw_decoder = TreeDecoder::new(unregistered_root.clone(), registry.clone());
    raw_trace.push(format!("peek:{}", raw_decoder.peek_element()));
    let raw_element_id = raw_decoder.open_element();
    raw_trace.push(format!("open:{raw_element_id}"));
    loop {
        let raw_attrib_id = raw_decoder.next_attribute_id();
        raw_trace.push(format!("next:{raw_attrib_id}"));
        if raw_attrib_id == 0 {
            break;
        }
        if raw_attrib_id == ATTRIB_SPACE || raw_attrib_id == ATTRIB_NAME {
            raw_trace.push(format!("string:{}", raw_decoder.read_string()));
        } else if raw_attrib_id == ATTRIB_FIRST || raw_attrib_id == ATTRIB_LAST {
            raw_trace.push(format!("uint:{}", raw_decoder.read_unsigned_integer()));
        }
    }
    raw_decoder.close_element(raw_element_id);
    raw_trace.push(format!("close:{raw_element_id}"));
    raw_trace.push(format!("peek:{}", raw_decoder.peek_element()));
    raw_trace.push(format!("open:{}", raw_decoder.open_element()));

    let mut unregistered_props = RangeProperties::new();
    let mut unregistered_decoder = TreeDecoder::new(unregistered_root.clone(), registry);
    match unregistered_props.decode(&mut unregistered_decoder) {
        Ok(()) => observe_tree(
            "tree_decoder_unregistered",
            &unregistered_props,
            &raw_trace,
            "OK",
            "-",
        ),
        Err(error) => observe_tree(
            "tree_decoder_unregistered",
            &unregistered_props,
            &raw_trace,
            "DecoderError",
            &error.to_string(),
        ),
    }
}
