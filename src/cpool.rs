//! Constant pool — faithful port of `cpool.hh` / `cpool.cc` (245 lines).
//!
//! Definitions to support a constant pool for deferred compilation languages
//! (i.e. Java byte-code). Byte-code languages refer to objects via encoded
//! references; the constant pool resolves these to concrete values, types, and
//! token names.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/cpool.{hh,cc}.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::marshal::{AttributeId, Decoder, ElementId, Encoder};
use crate::type_system::datatype::Datatype;
use crate::type_system::typefactory::TypeFactory;

const ATTRIB_CONTENT_ID: u32 = 1;
const ATTRIB_CONSTRUCTOR_ID: u32 = 4;
const ATTRIB_DESTRUCTOR_ID: u32 = 5;
const ATTRIB_A_ID: u32 = 80;
const ATTRIB_B_ID: u32 = 81;
const ATTRIB_LENGTH_ID: u32 = 82;
const ATTRIB_TAG_ID: u32 = 83;

const ELEM_DATA_ID: u32 = 1;
const ELEM_VALUE_ID: u32 = 9;
const ELEM_CONSTANTPOOL_ID: u32 = 109;
const ELEM_CPOOLREC_ID: u32 = 110;
const ELEM_REF_ID: u32 = 111;
const ELEM_TOKEN_ID: u32 = 112;

// RUDRA-GLUE: Rust materializes Ghidra's process-global AttributeId objects
// at call sites because AttributeId owns its name String.
fn attrib(name: &str, id: u32) -> AttributeId {
    AttributeId::new(name, id)
}

// RUDRA-GLUE: Rust materializes Ghidra's process-global ElementId objects at
// call sites because ElementId owns its name String.
fn elem(name: &str, id: u32) -> ElementId {
    ElementId::new(name, id)
}

/// Generic constant pool tag types. Faithful to the `CPoolRecord` enum
/// (cpool.hh:59).
pub mod cpool_tag {
    /// Constant value of data-type `type`, cpool operator can be eliminated.
    pub const PRIMITIVE: u32 = 0;
    /// Constant reference to string (passed back as `byte_data`).
    pub const STRING_LITERAL: u32 = 1;
    /// Reference to (system level) class object, `token` holds class name.
    pub const CLASS_REFERENCE: u32 = 2;
    /// Pointer to a method, name in `token`, signature in `type`.
    pub const POINTER_METHOD: u32 = 3;
    /// Pointer to a field, name in `token`, data-type in `type`.
    pub const POINTER_FIELD: u32 = 4;
    /// Integer length, `token` is language specific indicator.
    pub const ARRAY_LENGTH: u32 = 5;
    /// Boolean value, `token` is language specific indicator.
    pub const INSTANCE_OF: u32 = 6;
    /// Pointer to object, new name in `token`, new data-type in `type`.
    pub const CHECK_CAST: u32 = 7;
}

/// Additional boolean properties on a CPoolRecord. Faithful to the flags enum
/// (cpool.hh:69).
pub mod cpool_flags {
    /// Referenced method is a constructor.
    pub const IS_CONSTRUCTOR: u32 = 0x1;
    /// Referenced method is a destructor.
    pub const IS_DESTRUCTOR: u32 = 0x2;
}

/// A description of a byte-code object referenced by a constant. Faithful to
/// `CPoolRecord` (cpool.hh:56).
#[derive(Debug, Clone)]
pub struct CPoolRecord {
    /// Descriptor of the type of object.
    pub tag: u32,
    /// Additional boolean properties (constructor/destructor).
    pub flags: u32,
    /// Name or token associated with the object.
    pub token: String,
    /// Constant value of the object (if known).
    pub value: u64,
    /// Factory-owned canonical data-type associated with the object. This is
    /// the authoritative equivalent of Ghidra's `Datatype *type`.
    data_type: Option<Arc<Datatype>>,
    /// Compatibility display name derived from `data_type` whenever a type is
    /// installed. Consumers performing type analysis must use `get_type()`.
    pub type_name: String,
    /// For string literals, the raw byte data.
    pub byte_data: Option<Vec<u8>>,
}

impl Default for CPoolRecord {
    // Ghidra: cpool.hh:83 CPoolRecord::CPoolRecord(void)
    fn default() -> Self {
        Self::new()
    }
}

impl CPoolRecord {
    // Ghidra: cpool.hh:83 CPoolRecord::CPoolRecord(void)
    /// Construct an empty record. Faithful to the constructor (cpool.hh:83).
    pub fn new() -> Self {
        Self {
            tag: cpool_tag::PRIMITIVE,
            flags: 0,
            token: String::new(),
            value: 0,
            data_type: None,
            type_name: String::new(),
            byte_data: None,
        }
    }

    // Ghidra: cpool.hh:85 CPoolRecord::getTag(void) const
    /// Get the type of record. Faithful to `getTag`.
    pub fn get_tag(&self) -> u32 {
        self.tag
    }

    // Ghidra: cpool.hh:86 CPoolRecord::getToken(void) const
    /// Get name of method or data-type. Faithful to `getToken`.
    pub fn get_token(&self) -> &str {
        &self.token
    }

    // Ghidra: cpool.hh:87 CPoolRecord::getByteData(void) const
    /// Get string literal byte data. Faithful to `getByteData`.
    pub fn get_byte_data(&self) -> Option<&[u8]> {
        self.byte_data.as_deref()
    }

    // Ghidra: cpool.hh:88 CPoolRecord::getByteDataLength(void) const
    /// Number of bytes of string literal data. Faithful to `getByteDataLength`.
    pub fn get_byte_data_length(&self) -> usize {
        self.byte_data.as_ref().map_or(0, |d| d.len())
    }

    // Ghidra: cpool.hh:89 CPoolRecord::getType(void) const
    /// Get the factory-owned canonical data-type.
    pub fn get_type(&self) -> Option<&Arc<Datatype>> {
        self.data_type.as_ref()
    }

    // RUDRA-GLUE: Compatibility display accessor for legacy Rugra printers;
    // Ghidra callers use getType()->getName().
    /// Get the compatibility display name derived from the canonical type.
    pub fn get_type_name(&self) -> &str {
        &self.type_name
    }

    // RUDRA-GLUE: Rust keeps the Arc and its compatibility display name in
    // sync; Ghidra assigns the raw Datatype pointer directly as a friend.
    /// Install a factory-owned canonical data-type.
    pub fn set_type(&mut self, data_type: Arc<Datatype>) {
        self.type_name = data_type.get_name().to_string();
        self.data_type = Some(data_type);
    }

    // Ghidra: cpool.hh:90 CPoolRecord::getValue(void) const
    /// Get the constant value. Faithful to `getValue`.
    pub fn get_value(&self) -> u64 {
        self.value
    }

    // Ghidra: cpool.hh:91 CPoolRecord::isConstructor(void) const
    /// Is the object a constructor method? Faithful to `isConstructor`.
    pub fn is_constructor(&self) -> bool {
        (self.flags & cpool_flags::IS_CONSTRUCTOR) != 0
    }

    // Ghidra: cpool.hh:92 CPoolRecord::isDestructor(void) const
    /// Is the object a destructor method? Faithful to `isDestructor`.
    pub fn is_destructor(&self) -> bool {
        (self.flags & cpool_flags::IS_DESTRUCTOR) != 0
    }

    // RUDRA-GLUE: Named Rust helper for the branch chain in
    // CPoolRecord::encode (cpool.cc:36-51).
    /// Convert a tag to its string name for encoding. Faithful to the
    /// encode logic (cpool.cc:36-51).
    pub fn tag_to_string(tag: u32) -> &'static str {
        match tag {
            cpool_tag::POINTER_METHOD => "method",
            cpool_tag::POINTER_FIELD => "field",
            cpool_tag::INSTANCE_OF => "instanceof",
            cpool_tag::ARRAY_LENGTH => "arraylength",
            cpool_tag::CHECK_CAST => "checkcast",
            cpool_tag::STRING_LITERAL => "string",
            cpool_tag::CLASS_REFERENCE => "classref",
            _ => "primitive",
        }
    }

    // RUDRA-GLUE: Named Rust helper for the branch chain in
    // CPoolRecord::decode (cpool.cc:99-115).
    /// Convert a string name to a tag for decoding. Faithful to the decode
    /// logic (cpool.cc:99-115).
    pub fn string_to_tag(s: &str) -> u32 {
        match s {
            "method" => cpool_tag::POINTER_METHOD,
            "field" => cpool_tag::POINTER_FIELD,
            "instanceof" => cpool_tag::INSTANCE_OF,
            "arraylength" => cpool_tag::ARRAY_LENGTH,
            "checkcast" => cpool_tag::CHECK_CAST,
            "string" => cpool_tag::STRING_LITERAL,
            "classref" => cpool_tag::CLASS_REFERENCE,
            _ => cpool_tag::PRIMITIVE,
        }
    }

    // Ghidra: cpool.cc:32 CPoolRecord::encode(Encoder &) const
    /// Encode this record as a `<cpoolrec>` element, including value/data,
    /// flags, and the canonical data-type reference in Ghidra's exact order.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> Result<(), String> {
        let rec_elem = elem("cpoolrec", ELEM_CPOOLREC_ID);
        encoder.open_element(&rec_elem);
        encoder.write_string(&attrib("tag", ATTRIB_TAG_ID), Self::tag_to_string(self.tag));
        if self.is_constructor() {
            encoder.write_bool(&attrib("constructor", ATTRIB_CONSTRUCTOR_ID), true);
        }
        if self.is_destructor() {
            encoder.write_bool(&attrib("destructor", ATTRIB_DESTRUCTOR_ID), true);
        }
        if self.tag == cpool_tag::PRIMITIVE {
            let value_elem = elem("value", ELEM_VALUE_ID);
            encoder.open_element(&value_elem);
            encoder.write_unsigned_integer(&attrib("XMLcontent", ATTRIB_CONTENT_ID), self.value);
            encoder.close_element(&value_elem);
        }
        if let Some(bytes) = self.byte_data.as_ref() {
            let data_elem = elem("data", ELEM_DATA_ID);
            encoder.open_element(&data_elem);
            encoder.write_signed_integer(&attrib("length", ATTRIB_LENGTH_ID), bytes.len() as i64);
            let mut content = String::new();
            for (index, byte) in bytes.iter().enumerate() {
                // `uint1` is an unsigned-char typedef, so Ghidra's ostream
                // insertion writes one raw character after setw(2)'s '0'
                // padding; it does not format the numeric byte as hex.
                content.push('0');
                content.push(char::from(*byte));
                content.push(' ');
                if (index + 1) % 16 == 0 {
                    content.push('\n');
                }
            }
            encoder.write_string(&attrib("XMLcontent", ATTRIB_CONTENT_ID), &content);
            encoder.close_element(&data_elem);
        } else {
            let token_elem = elem("token", ELEM_TOKEN_ID);
            encoder.open_element(&token_elem);
            encoder.write_string(&attrib("XMLcontent", ATTRIB_CONTENT_ID), &self.token);
            encoder.close_element(&token_elem);
        }
        let data_type = self
            .data_type
            .as_ref()
            .ok_or_else(|| "Bad constant pool record: missing data-type".to_string())?;
        data_type.encode_ref(encoder);
        encoder.close_element(&rec_elem);
        Ok(())
    }

    // Ghidra: cpool.cc:89 CPoolRecord::decode(Decoder &,TypeFactory &)
    /// Decode a `<cpoolrec>` into this record. Mutations happen in Ghidra's
    /// source order, so an error leaves the same observable prefix of state.
    pub fn decode(
        &mut self,
        decoder: &mut dyn Decoder,
        typegrp: &mut TypeFactory,
    ) -> Result<(), String> {
        self.tag = cpool_tag::PRIMITIVE;
        self.value = 0;
        self.flags = 0;
        let elem_id = decoder.open_element_matching(&elem("cpoolrec", ELEM_CPOOLREC_ID));
        if elem_id != ELEM_CPOOLREC_ID {
            return Err("Expected <cpoolrec> element".to_string());
        }
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match attrib_id {
                ATTRIB_TAG_ID => self.tag = Self::string_to_tag(&decoder.read_string()),
                ATTRIB_CONSTRUCTOR_ID => {
                    if decoder.read_bool() {
                        self.flags |= cpool_flags::IS_CONSTRUCTOR;
                    }
                }
                ATTRIB_DESTRUCTOR_ID => {
                    if decoder.read_bool() {
                        self.flags |= cpool_flags::IS_DESTRUCTOR;
                    }
                }
                _ => {}
            }
        }
        if self.tag == cpool_tag::PRIMITIVE {
            let sub_id = decoder.open_element_matching(&elem("value", ELEM_VALUE_ID));
            if sub_id != ELEM_VALUE_ID {
                return Err(
                    "Expected <value> element in primitive constant pool record".to_string()
                );
            }
            loop {
                let attrib_id = decoder.next_attribute_id();
                if attrib_id == 0 {
                    break;
                }
                if attrib_id == ATTRIB_CONTENT_ID {
                    self.value = decoder.read_unsigned_integer();
                }
            }
            decoder.close_element(sub_id);
        }
        let sub_id = decoder.open_element();
        if sub_id == 0 {
            return Err("Bad constant pool record: missing <token> or <data>".to_string());
        }
        if sub_id == ELEM_TOKEN_ID {
            loop {
                let attrib_id = decoder.next_attribute_id();
                if attrib_id == 0 {
                    break;
                }
                if attrib_id == ATTRIB_CONTENT_ID {
                    self.token = decoder.read_string();
                }
            }
        } else {
            let mut length = 0;
            let mut content = String::new();
            loop {
                let attrib_id = decoder.next_attribute_id();
                if attrib_id == 0 {
                    break;
                }
                match attrib_id {
                    ATTRIB_LENGTH_ID => length = decoder.read_signed_integer(),
                    ATTRIB_CONTENT_ID => content = decoder.read_string(),
                    _ => {}
                }
            }
            if length < 0 {
                return Err("Bad constant pool record: negative <data> length".to_string());
            }
            let mut bytes = Vec::with_capacity(length as usize);
            for word in content.split_whitespace().take(length as usize) {
                let value = u32::from_str_radix(word, 16)
                    .map_err(|_| "Bad constant pool record: malformed <data>".to_string())?;
                bytes.push(value as u8);
            }
            if bytes.len() != length as usize {
                return Err("Bad constant pool record: short <data>".to_string());
            }
            self.byte_data = Some(bytes);
        }
        decoder.close_element(sub_id);
        if self.tag == cpool_tag::STRING_LITERAL && self.byte_data.is_none() {
            return Err("Bad constant pool record: missing <data>".to_string());
        }
        // TODO(TYPEFACTORY-CODEFLAGS-DECODE-0001): Ghidra calls
        // decodeTypeWithCodeFlags when either flag is set. Until that factory
        // API exists, decode_type consumes and canonicalizes the same pointer
        // type but cannot inject constructor/destructor flags into TypeCode.
        let data_type = typegrp.decode_type(decoder)?;
        self.set_type(data_type);
        decoder.close_element(elem_id);
        Ok(())
    }
}

/// A cheap (efficient) placeholder for a reference to a constant pool record.
/// Faithful to `ConstantPoolInternal::CheapSorter` (cpool.hh:175).
///
/// A reference can be 1 or more integers; in practice at most 2 are seen.
/// Ordered lexicographically by (a, b).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct CheapSorter {
    /// The first integer in a reference.
    pub a: u64,
    /// The second integer in a reference (or zero).
    pub b: u64,
}

impl CheapSorter {
    // Ghidra: cpool.hh:181 CheapSorter::CheapSorter(const vector<uintb> &)
    /// Construct from an array of reference integers. Faithful to the
    /// constructor (cpool.hh:181).
    pub fn from_refs(refs: &[u64]) -> Self {
        Self {
            a: refs.first().copied().unwrap_or(0),
            b: refs.get(1).copied().unwrap_or(0),
        }
    }

    // Ghidra: cpool.hh:195 CheapSorter::apply(vector<uintb> &) const
    /// Convert the reference back to a formal array of integers. Faithful to
    /// `apply` (cpool.hh:195).
    pub fn apply(&self) -> Vec<u64> {
        vec![self.a, self.b]
    }

    // Ghidra: cpool.cc:176 ConstantPoolInternal::CheapSorter::encode(Encoder &) const
    /// Encode the two-component reference as `<ref a="..." b="..."/>`.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        let ref_elem = elem("ref", ELEM_REF_ID);
        encoder.open_element(&ref_elem);
        encoder.write_unsigned_integer(&attrib("a", ATTRIB_A_ID), self.a);
        encoder.write_unsigned_integer(&attrib("b", ATTRIB_B_ID), self.b);
        encoder.close_element(&ref_elem);
    }

    // Ghidra: cpool.cc:187 ConstantPoolInternal::CheapSorter::decode(Decoder &)
    /// Decode a two-component reference from a `<ref>` element.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) -> Result<(), String> {
        let elem_id = decoder.open_element_matching(&elem("ref", ELEM_REF_ID));
        if elem_id != ELEM_REF_ID {
            return Err("Expected <ref> element".to_string());
        }
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match attrib_id {
                ATTRIB_A_ID => self.a = decoder.read_unsigned_integer(),
                ATTRIB_B_ID => self.b = decoder.read_unsigned_integer(),
                _ => {}
            }
        }
        decoder.close_element(elem_id);
        Ok(())
    }
}

/// An interface to the pool of constant objects for byte-code languages.
/// Faithful to `ConstantPool` (cpool.hh:104).
pub trait ConstantPool: Send + Sync {
    // Ghidra: cpool.hh:119 ConstantPool::getRecord(const vector<uintb> &) const
    /// Retrieve a constant pool record given a reference. Faithful to
    /// `getRecord`.
    fn get_record(&self, refs: &[u64]) -> Option<&CPoolRecord>;

    // Ghidra: cpool.hh:111 ConstantPool::createRecord(const vector<uintb> &)
    /// Allocate a new CPoolRecord associated with the reference. Faithful to
    /// `createRecord`. Returns a mutable reference to the new record.
    fn create_record(&mut self, refs: &[u64]) -> Result<&mut CPoolRecord, String>;

    // Ghidra: cpool.cc:157 ConstantPool::putRecord(const vector<uintb> &,uint4,const string &,Datatype *)
    /// Add a new constant pool record. Faithful to `putRecord`
    /// (cpool.cc:157).
    fn put_record(
        &mut self,
        refs: &[u64],
        tag: u32,
        tok: &str,
        data_type: Arc<Datatype>,
    ) -> Result<(), String> {
        let rec = self.create_record(refs)?;
        rec.tag = tag;
        rec.token = tok.to_string();
        rec.set_type(data_type);
        Ok(())
    }

    // Ghidra: cpool.cc:166 ConstantPool::decodeRecord(const vector<uintb> &,Decoder &,TypeFactory &)
    /// Allocate and decode a record. If decoding fails, the newly allocated
    /// partial record remains associated with `refs`, matching Ghidra.
    fn decode_record(
        &mut self,
        refs: &[u64],
        decoder: &mut dyn Decoder,
        typegrp: &mut TypeFactory,
    ) -> Result<&CPoolRecord, String> {
        self.create_record(refs)?.decode(decoder, typegrp)?;
        self.get_record(refs)
            .ok_or_else(|| "Decoded constant pool record disappeared".to_string())
    }

    // Ghidra: cpool.hh:141 ConstantPool::empty(void) const
    /// Is the container empty of records? Faithful to `empty`.
    fn is_empty(&self) -> bool;

    // Ghidra: cpool.hh:142 ConstantPool::clear(void)
    /// Release any (local) resources. Faithful to `clear`.
    fn clear(&mut self);
}

/// An in-memory implementation of ConstantPool storing records in a BTreeMap.
/// Faithful to `ConstantPoolInternal` (cpool.hh:165).
pub struct ConstantPoolInternal {
    /// Map from reference to constant pool record.
    cpool_map: BTreeMap<CheapSorter, CPoolRecord>,
}

impl Default for ConstantPoolInternal {
    // RUDRA-GLUE: Rust Default delegates to the empty C++ map state.
    fn default() -> Self {
        Self::new()
    }
}

impl ConstantPoolInternal {
    // RUDRA-GLUE: Rust constructor for the implicitly default-constructed
    // ConstantPoolInternal::cpoolMap.
    /// Construct an empty constant pool.
    pub fn new() -> Self {
        Self {
            cpool_map: BTreeMap::new(),
        }
    }

    // RUDRA-GLUE: Read-only map-size accessor for tests and diagnostics.
    /// Number of records in the pool.
    pub fn num_records(&self) -> usize {
        self.cpool_map.len()
    }

    // RUDRA-GLUE: Read-only iterator exposing the C++ map's native ordering.
    /// Iterate over all (reference, record) pairs.
    pub fn records(&self) -> impl Iterator<Item = (&CheapSorter, &CPoolRecord)> {
        self.cpool_map.iter()
    }

    // Ghidra: cpool.cc:218 ConstantPoolInternal::encode(Encoder &) const
    /// Encode all records to a stream. Faithful to `ConstantPoolInternal::encode`
    /// (cpool.cc:218). Emits `<constantpool>` with `<ref>` + `<cpoolrec>` children.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> Result<(), String> {
        let cp_elem = elem("constantpool", ELEM_CONSTANTPOOL_ID);
        encoder.open_element(&cp_elem);
        for (sorter, rec) in &self.cpool_map {
            sorter.encode(encoder);
            rec.encode(encoder)?;
        }
        encoder.close_element(&cp_elem);
        Ok(())
    }

    // Ghidra: cpool.cc:230 ConstantPoolInternal::decode(Decoder &,TypeFactory &)
    /// Restore records from a stream. Faithful to `ConstantPoolInternal::decode`
    /// (cpool.cc:230).
    pub fn decode(
        &mut self,
        decoder: &mut dyn Decoder,
        typegrp: &mut TypeFactory,
    ) -> Result<(), String> {
        let cp_id = decoder.open_element_matching(&elem("constantpool", ELEM_CONSTANTPOOL_ID));
        if cp_id != ELEM_CONSTANTPOOL_ID {
            return Err("Expected <constantpool> element".to_string());
        }
        while decoder.peek_element() != 0 {
            let next_id = decoder.peek_element();
            if next_id != ELEM_REF_ID {
                let next_name = decoder
                    .element_name(next_id)
                    .unwrap_or_else(|| format!("id:{next_id}"));
                return Err(format!("Expected <ref> element, got <{next_name}>"));
            }
            let mut sorter = CheapSorter::default();
            sorter.decode(decoder)?;
            let refs = sorter.apply();
            self.create_record(&refs)?.decode(decoder, typegrp)?;
        }
        decoder.close_element(cp_id);
        Ok(())
    }
}

impl ConstantPool for ConstantPoolInternal {
    // Ghidra: cpool.cc:207 ConstantPoolInternal::getRecord
    fn get_record(&self, refs: &[u64]) -> Option<&CPoolRecord> {
        let sorter = CheapSorter::from_refs(refs);
        self.cpool_map.get(&sorter)
    }

    // Ghidra: cpool.cc:196 ConstantPoolInternal::createRecord
    fn create_record(&mut self, refs: &[u64]) -> Result<&mut CPoolRecord, String> {
        let sorter = CheapSorter::from_refs(refs);
        match self.cpool_map.entry(sorter) {
            Entry::Vacant(entry) => Ok(entry.insert(CPoolRecord::new())),
            Entry::Occupied(entry) => Err(format!(
                "Creating duplicate entry in constant pool: {}",
                entry.get().get_token()
            )),
        }
    }

    // Ghidra: cpool.hh:165 ConstantPoolInternal::isEmpty
    fn is_empty(&self) -> bool {
        self.cpool_map.is_empty()
    }

    // Ghidra: cpool.hh:165 ConstantPoolInternal::clear
    fn clear(&mut self) {
        self.cpool_map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::{IdRegistry, PackedDecode, PackedEncode, TreeDecoder, TreeEncoder};
    use crate::type_system::datatype::TypeMetatype;
    use std::sync::RwLock;

    // RUDRA-GLUE: test-only fixture registering a plain 4-byte INT core type
    // via the faithful set_core_type_result twin. Ghidra test bootstrap has no
    // counterpart (the oracle fixture registers core types through the
    // architecture's TypeFactory directly); a conflicting registration is a
    // LowlevelError in the oracle (type.cc:3178 findAdd throws), surfaced here
    // as the same LowlevelError panic the pre-migration compat twin produced.
    fn fixture_type(factory: &mut TypeFactory, name: &str) -> Arc<Datatype> {
        factory
            .set_core_type_result(name, 4, TypeMetatype::Int, false)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    #[test]
    fn test_cpool_record_default() {
        let r = CPoolRecord::new();
        assert_eq!(r.get_tag(), cpool_tag::PRIMITIVE);
        assert_eq!(r.get_value(), 0);
        assert!(!r.is_constructor());
        assert!(!r.is_destructor());
    }

    #[test]
    fn test_tag_string_roundtrip() {
        for &tag in &[
            cpool_tag::PRIMITIVE,
            cpool_tag::STRING_LITERAL,
            cpool_tag::CLASS_REFERENCE,
            cpool_tag::POINTER_METHOD,
            cpool_tag::POINTER_FIELD,
            cpool_tag::ARRAY_LENGTH,
            cpool_tag::INSTANCE_OF,
            cpool_tag::CHECK_CAST,
        ] {
            let s = CPoolRecord::tag_to_string(tag);
            assert_eq!(CPoolRecord::string_to_tag(s), tag);
        }
    }

    #[test]
    fn test_cheap_sorter_ordering() {
        let s1 = CheapSorter { a: 1, b: 2 };
        let s2 = CheapSorter { a: 1, b: 3 };
        let s3 = CheapSorter { a: 2, b: 0 };
        assert!(s1 < s2);
        assert!(s2 < s3);
    }

    #[test]
    fn test_cheap_sorter_from_refs() {
        let s = CheapSorter::from_refs(&[10, 20]);
        assert_eq!(s.a, 10);
        assert_eq!(s.b, 20);
        let s2 = CheapSorter::from_refs(&[5]);
        assert_eq!(s2.a, 5);
        assert_eq!(s2.b, 0);
    }

    #[test]
    fn test_cheap_sorter_apply() {
        let s = CheapSorter { a: 7, b: 9 };
        assert_eq!(s.apply(), vec![7, 9]);
    }

    #[test]
    fn test_constant_pool_create_get() {
        let mut pool = ConstantPoolInternal::new();
        let mut factory = TypeFactory::new(8);
        let code_type = fixture_type(&mut factory, "cpool_create_type");
        assert!(pool.is_empty());
        {
            let rec = pool.create_record(&[1, 2]).unwrap();
            rec.tag = cpool_tag::POINTER_METHOD;
            rec.token = "main".to_string();
            rec.set_type(code_type.clone());
        }
        assert!(!pool.is_empty());
        assert_eq!(pool.num_records(), 1);
        let rec = pool.get_record(&[1, 2]).unwrap();
        assert_eq!(rec.get_tag(), cpool_tag::POINTER_METHOD);
        assert_eq!(rec.get_token(), "main");
        assert!(Arc::ptr_eq(rec.get_type().unwrap(), &code_type));
    }

    #[test]
    fn test_constant_pool_duplicate() {
        let mut pool = ConstantPoolInternal::new();
        pool.create_record(&[1]).unwrap();
        let result = pool.create_record(&[1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_pool_put_record() {
        let mut pool = ConstantPoolInternal::new();
        let mut factory = TypeFactory::new(8);
        let int_type = fixture_type(&mut factory, "cpool_put_type");
        pool.put_record(
            &[5, 0],
            cpool_tag::POINTER_FIELD,
            "field_x",
            int_type.clone(),
        )
        .unwrap();
        let rec = pool.get_record(&[5, 0]).unwrap();
        assert_eq!(rec.get_tag(), cpool_tag::POINTER_FIELD);
        assert_eq!(rec.get_token(), "field_x");
        assert_eq!(rec.get_type_name(), int_type.get_name());
        assert!(Arc::ptr_eq(rec.get_type().unwrap(), &int_type));
    }

    #[test]
    fn test_constant_pool_clear() {
        let mut pool = ConstantPoolInternal::new();
        let mut factory = TypeFactory::new(8);
        let int_type = fixture_type(&mut factory, "cpool_clear_type");
        pool.put_record(&[1], cpool_tag::PRIMITIVE, "", int_type.clone())
            .unwrap();
        pool.put_record(&[2], cpool_tag::PRIMITIVE, "", int_type)
            .unwrap();
        assert_eq!(pool.num_records(), 2);
        pool.clear();
        assert!(pool.is_empty());
    }

    #[test]
    fn test_constant_pool_string_literal() {
        let mut pool = ConstantPoolInternal::new();
        {
            let rec = pool.create_record(&[10]).unwrap();
            rec.tag = cpool_tag::STRING_LITERAL;
            rec.byte_data = Some(vec![b'H', b'i']);
        }
        let rec = pool.get_record(&[10]).unwrap();
        assert_eq!(rec.get_tag(), cpool_tag::STRING_LITERAL);
        assert_eq!(rec.get_byte_data(), Some(&b"Hi"[..]));
        assert_eq!(rec.get_byte_data_length(), 2);
    }

    #[test]
    fn test_constant_pool_constructor_flag() {
        let mut pool = ConstantPoolInternal::new();
        {
            let rec = pool.create_record(&[20]).unwrap();
            rec.tag = cpool_tag::POINTER_METHOD;
            rec.flags = cpool_flags::IS_CONSTRUCTOR;
        }
        let rec = pool.get_record(&[20]).unwrap();
        assert!(rec.is_constructor());
        assert!(!rec.is_destructor());
    }

    #[test]
    fn test_constant_pool_records_iter() {
        let mut pool = ConstantPoolInternal::new();
        let mut factory = TypeFactory::new(8);
        let int_type = fixture_type(&mut factory, "cpool_records_type");
        pool.put_record(&[1], cpool_tag::PRIMITIVE, "a", int_type.clone())
            .unwrap();
        pool.put_record(&[2], cpool_tag::PRIMITIVE, "b", int_type.clone())
            .unwrap();
        pool.put_record(&[3], cpool_tag::PRIMITIVE, "c", int_type)
            .unwrap();
        let names: Vec<_> = pool.records().map(|(_, r)| r.get_token()).collect();
        assert_eq!(names, vec!["a", "b", "c"]); // sorted by CheapSorter
    }

    #[test]
    fn test_reference_projection_and_duplicate_preserves_record() {
        let mut factory = TypeFactory::new(8);
        let original_type = fixture_type(&mut factory, "cpool_original_type");
        let replacement_type = fixture_type(&mut factory, "cpool_replacement_type");
        let mut pool = ConstantPoolInternal::new();
        pool.put_record(
            &[7, 3, 99],
            cpool_tag::POINTER_FIELD,
            "original",
            original_type.clone(),
        )
        .unwrap();

        assert!(pool.get_record(&[7, 3]).is_some());
        assert!(pool.get_record(&[7, 3, 1234]).is_some());
        assert!(pool.get_record(&[3, 7]).is_none());
        let error = pool
            .put_record(
                &[7, 3],
                cpool_tag::CHECK_CAST,
                "replacement",
                replacement_type,
            )
            .unwrap_err();
        assert_eq!(error, "Creating duplicate entry in constant pool: original");
        let record = pool.get_record(&[7, 3]).unwrap();
        assert_eq!(record.get_tag(), cpool_tag::POINTER_FIELD);
        assert_eq!(record.get_token(), "original");
        assert!(Arc::ptr_eq(record.get_type().unwrap(), &original_type));
    }

    #[test]
    fn test_tree_decode_preserves_type_identity_value_and_data() {
        let mut factory = TypeFactory::new(8);
        let int_type = fixture_type(&mut factory, "cpool_roundtrip_type");
        let int_name = int_type.get_name().to_string();
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        let mut encoder = TreeEncoder::new(registry.clone());
        let cp_elem = elem("constantpool", ELEM_CONSTANTPOOL_ID);
        let ref_elem = elem("ref", ELEM_REF_ID);
        let rec_elem = elem("cpoolrec", ELEM_CPOOLREC_ID);
        let value_elem = elem("value", ELEM_VALUE_ID);
        let token_elem = elem("token", ELEM_TOKEN_ID);
        let data_elem = elem("data", ELEM_DATA_ID);
        let typeref_elem = elem("typeref", 63);
        encoder.open_element(&cp_elem);
        encoder.open_element(&ref_elem);
        encoder.write_unsigned_integer(&attrib("a", ATTRIB_A_ID), 9);
        encoder.write_unsigned_integer(&attrib("b", ATTRIB_B_ID), 4);
        encoder.close_element(&ref_elem);
        encoder.open_element(&rec_elem);
        encoder.write_string(&attrib("tag", ATTRIB_TAG_ID), "primitive");
        encoder.open_element(&value_elem);
        encoder.write_unsigned_integer(&attrib("XMLcontent", ATTRIB_CONTENT_ID), 0x1122_3344);
        encoder.close_element(&value_elem);
        encoder.open_element(&token_elem);
        encoder.write_string(&attrib("XMLcontent", ATTRIB_CONTENT_ID), "primitive-token");
        encoder.close_element(&token_elem);
        encoder.open_element(&typeref_elem);
        encoder.write_string(&attrib("name", 14), &int_name);
        encoder.close_element(&typeref_elem);
        encoder.close_element(&rec_elem);
        encoder.open_element(&ref_elem);
        encoder.write_unsigned_integer(&attrib("a", ATTRIB_A_ID), 2);
        encoder.write_unsigned_integer(&attrib("b", ATTRIB_B_ID), 8);
        encoder.close_element(&ref_elem);
        encoder.open_element(&rec_elem);
        encoder.write_string(&attrib("tag", ATTRIB_TAG_ID), "string");
        encoder.open_element(&data_elem);
        encoder.write_signed_integer(&attrib("length", ATTRIB_LENGTH_ID), 17);
        encoder.write_string(
            &attrib("XMLcontent", ATTRIB_CONTENT_ID),
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 ",
        );
        encoder.close_element(&data_elem);
        encoder.open_element(&typeref_elem);
        encoder.write_string(&attrib("name", 14), &int_name);
        encoder.close_element(&typeref_elem);
        encoder.close_element(&rec_elem);
        encoder.close_element(&cp_elem);
        let document = encoder.into_document();
        let root = document.get_root().unwrap().clone();
        let mut decoder = TreeDecoder::new(root, registry);
        let mut decoded = ConstantPoolInternal::new();
        decoded.decode(&mut decoder, &mut factory).unwrap();

        let primitive = decoded.get_record(&[9, 4]).unwrap();
        assert_eq!(primitive.get_value(), 0x1122_3344);
        assert_eq!(primitive.get_token(), "primitive-token");
        assert!(Arc::ptr_eq(primitive.get_type().unwrap(), &int_type));
        let string = decoded.get_record(&[2, 8]).unwrap();
        assert_eq!(
            string.get_byte_data(),
            Some((0u8..17).collect::<Vec<_>>().as_slice())
        );
        assert!(Arc::ptr_eq(string.get_type().unwrap(), &int_type));
    }

    #[test]
    fn test_decode_error_keeps_inserted_partial_record() {
        let mut encoder = PackedEncode::new();
        let cp_elem = elem("constantpool", ELEM_CONSTANTPOOL_ID);
        let ref_elem = elem("ref", ELEM_REF_ID);
        let rec_elem = elem("cpoolrec", ELEM_CPOOLREC_ID);
        let token_elem = elem("token", ELEM_TOKEN_ID);
        encoder.open_element(&cp_elem);
        encoder.open_element(&ref_elem);
        encoder.write_unsigned_integer(&attrib("a", ATTRIB_A_ID), 13);
        encoder.write_unsigned_integer(&attrib("b", ATTRIB_B_ID), 6);
        encoder.close_element(&ref_elem);
        encoder.open_element(&rec_elem);
        encoder.write_string(&attrib("tag", ATTRIB_TAG_ID), "string");
        encoder.open_element(&token_elem);
        encoder.write_string(&attrib("XMLcontent", ATTRIB_CONTENT_ID), "not-data");
        encoder.close_element(&token_elem);
        encoder.close_element(&rec_elem);
        encoder.close_element(&cp_elem);

        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        let mut decoder = PackedDecode::new(encoder.into_bytes(), registry);
        let mut factory = TypeFactory::new(8);
        let mut pool = ConstantPoolInternal::new();
        let error = pool.decode(&mut decoder, &mut factory).unwrap_err();
        assert_eq!(error, "Bad constant pool record: missing <data>");
        assert_eq!(pool.num_records(), 1);
        let partial = pool.get_record(&[13, 6]).unwrap();
        assert_eq!(partial.get_tag(), cpool_tag::STRING_LITERAL);
        assert_eq!(partial.get_token(), "not-data");
        assert!(partial.get_type().is_none());
    }
}
