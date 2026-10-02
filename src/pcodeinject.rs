//! P-code injection engine — faithful port of `pcodeinject.hh` /
//! `pcodeinject.cc` plus the SLEIGH payload flavor from `inject_sleigh.hh` /
//! `inject_sleigh.cc`.
//!
//! P-code injection allows substituting user-defined p-code templates for
//! specific operations (CALL fixups, CALLOTHER fixups, call mechanism
//! patches, executable scripts).
//!
//! Key classes:
//! - `InjectParameter`: an input/output parameter to an injection payload
//! - `InjectContext`: context for resolving placeholders during injection
//! - `InjectPayload`: a container for injectable p-code operations.  The
//!   Rust struct flattens the Ghidra `InjectPayload` /
//!   `InjectPayloadSleigh` / `InjectPayloadCallfixup` hierarchy; the
//!   SLEIGH-only fields (`source`, `parsestring`, `tpl`) and the
//!   callfixup-only field (`target_symbol_names`) stay empty for payloads
//!   that never populate them.
//! - `PcodeInjectLibrary`: manager for all injection payloads, mirroring
//!   `PcodeInjectLibrary` (id-indexed `injection` vector + name→id maps +
//!   id→name vectors) and the SLEIGH library's `tempbase`/`slgh` members.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/
//! {pcodeinject,inject_sleigh}.{hh,cc}.

use crate::opcodes::OpCode;
use crate::pcoderaw::PcodeOpRaw;
use crate::pcoderaw::VarnodeRaw;
use crate::pcodeparse::{ConstructTpl, ConstTpl, HandleSelect, OpTpl, PcodeSnippet, SleighSymbolLookup, VarnodeTpl};
use crate::space::calc_mask;
use std::collections::BTreeMap;
use std::sync::Arc;

/// An input or output parameter to a p-code injection payload.
/// Corresponds to Ghidra's `InjectParameter` (pcodeinject.hh:55).
#[derive(Debug, Clone)]
pub struct InjectParameter {
    /// Name of the parameter
    pub name: String,
    /// Unique index for cross-referencing
    pub index: i32,
    /// Size of the parameter Varnode in bytes
    pub size: u32,
}

impl InjectParameter {
    // Ghidra: pcodeinject.hh:55 InjectParameter::new
    pub fn new(name: String, size: u32) -> Self {
        Self { name, index: 0, size }
    }
}

/// Injection payload types.
/// Corresponds to Ghidra's `InjectPayload` enum (pcodeinject.hh:103).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectPayloadType {
    /// Injection that replaces a CALL
    CallFixup = 1,
    /// Injection that replaces a user-defined p-code op (CALLOTHER)
    CallOtherFixup = 2,
    /// Injection to patch up data-flow around the caller/callee boundary
    CallMechanism = 3,
    /// Injection running as a stand-alone p-code script
    ExecutablePcode = 4,
}

/// A container for a set of p-code operations that can be injected.
/// Corresponds to Ghidra's `InjectPayload` (pcodeinject.hh:101) as extended
/// by `InjectPayloadSleigh` (inject_sleigh.hh:34) and
/// `InjectPayloadCallfixup` (inject_sleigh.hh:76).
#[derive(Debug, Clone)]
pub struct InjectPayload {
    // ---- InjectPayload base (pcodeinject.hh:101-114) ----
    /// Formal name of the payload
    pub name: String,
    /// Type of this payload
    pub payload_type: InjectPayloadType,
    /// True if the injection is generated dynamically
    pub dynamic: bool,
    /// True if injected COPYs are considered incidental
    pub incidental_copy: bool,
    /// Number of parameters shifted in the original call
    pub paramshift: i32,
    /// List of input parameters
    pub input_list: Vec<InjectParameter>,
    /// List of output parameters
    pub output: Vec<InjectParameter>,
    // ---- InjectPayloadSleigh (inject_sleigh.hh:34-38) ----
    /// A description of the document containing the SLEIGH syntax
    pub source: String,
    /// SLEIGH syntax describing the injection p-code (cleared once compiled)
    pub parsestring: String,
    /// The compiled p-code template (`ConstructTpl *tpl`)
    pub tpl: Option<ConstructTpl>,
    // ---- InjectPayloadCallfixup (inject_sleigh.hh:81) ----
    /// Names of specific functions to replace with this payload (callfixup
    /// `<target>` children); stays empty for other payload types.
    pub target_symbol_names: Vec<String>,
}

impl InjectPayload {
    // Ghidra: pcodeinject.hh:57 InjectPayload::InjectPayload
    /// Construct an empty payload. Faithful to `InjectPayload(nm,tp)`:
    /// name/type set, `dynamic`/`incidentalCopy` false, `paramshift` 0.
    pub fn new(name: String, payload_type: InjectPayloadType) -> Self {
        Self {
            name,
            payload_type,
            dynamic: false,
            incidental_copy: false,
            paramshift: 0,
            input_list: Vec::new(),
            output: Vec::new(),
            source: String::new(),
            parsestring: String::new(),
            tpl: None,
            target_symbol_names: Vec::new(),
        }
    }

    // Ghidra: inject_sleigh.cc:40 InjectPayloadSleigh::InjectPayloadSleigh
    /// Construct a SLEIGH payload in preparation for stream decode.
    /// Faithful to `InjectPayloadSleigh(src,nm,tp)`: base ctor plus
    /// `source = src`, `tpl = null`, `paramshift = 0`.
    pub fn new_sleigh(source: &str, name: &str, payload_type: InjectPayloadType) -> Self {
        let mut payload = Self::new(name.to_string(), payload_type);
        payload.source = source.to_string();
        payload
    }

    // Ghidra: pcodeinject.hh:56 InjectPayload::getParamshift
    pub fn get_paramshift(&self) -> i32 {
        self.paramshift
    }
    // Ghidra: pcodeinject.hh:56 InjectPayload::isDynamic
    pub fn is_dynamic(&self) -> bool {
        self.dynamic
    }
    // Ghidra: pcodeinject.hh:56 InjectPayload::isIncidentalCopy
    pub fn is_incidental_copy(&self) -> bool {
        self.incidental_copy
    }
    // Ghidra: pcodeinject.hh:56 InjectPayload::sizeInput
    pub fn size_input(&self) -> usize {
        self.input_list.len()
    }
    // Ghidra: pcodeinject.hh:56 InjectPayload::sizeOutput
    pub fn size_output(&self) -> usize {
        self.output.len()
    }

    // Ghidra: pcodeinject.hh:56 InjectPayload::addInput
    /// Add an input parameter to this payload.
    pub fn add_input(&mut self, name: String, size: u32) {
        self.input_list.push(InjectParameter::new(name, size));
    }

    // Ghidra: pcodeinject.hh:56 InjectPayload::addOutput
    /// Add an output parameter to this payload.
    pub fn add_output(&mut self, name: String, size: u32) {
        self.output.push(InjectParameter::new(name, size));
    }

    // Ghidra: pcodeinject.hh:56 InjectPayload::getInput
    /// Get an input parameter by index.
    pub fn get_input(&self, i: usize) -> Option<&InjectParameter> {
        self.input_list.get(i)
    }

    // Ghidra: pcodeinject.hh:56 InjectPayload::getOutput
    /// Get an output parameter by index.
    pub fn get_output(&self, i: usize) -> Option<&InjectParameter> {
        self.output.get(i)
    }

    // Ghidra: inject_sleigh.hh:51 InjectPayloadSleigh::getSource
    /// Get the payload source description.
    pub fn get_source(&self) -> &str {
        &self.source
    }

    // Ghidra: pcodeinject.cc:46 InjectPayload::decodeParameter
    /// Parse an `<input>` or `<output>` element describing an injection
    /// parameter.  Faithful to `decodeParameter` (pcodeinject.cc:46-64):
    /// name/size attributes in source order, unknown attributes ignored,
    /// empty name throws `Missing inject parameter name`.
    pub fn decode_parameter(
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(String, u32), String> {
        use crate::marshal::Decoder;
        let mut name = String::new();
        let mut size = 0u32;
        let elem_id = decoder.open_element();
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("name") => name = decoder.read_string(),
                Some("size") => size = decoder.read_unsigned_integer() as u32,
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        decoder.close_element(elem_id);
        if name.is_empty() {
            return Err("Missing inject parameter name".to_string());
        }
        Ok((name, size))
    }

    // Ghidra: pcodeinject.cc:67 InjectPayload::orderParameters
    /// Input and output parameters are assigned a unique index, inputs
    /// first then outputs, in list order.
    pub fn order_parameters(&mut self) {
        let mut id = 0i32;
        for param in &mut self.input_list {
            param.index = id;
            id += 1;
        }
        for param in &mut self.output {
            param.index = id;
            id += 1;
        }
    }

    // Ghidra: pcodeinject.cc:83 InjectPayload::decodePayloadAttributes
    /// Read the parameter-shift/dynamic/incidental-copy/inject attributes
    /// of the current `<pcode>` element.  Faithful to
    /// `decodePayloadAttributes` (pcodeinject.cc:83-106): `paramshift` and
    /// `dynamic` are reset first (`incidentalCopy` keeps its constructor
    /// value unless the attribute appears), and an `inject` attribute
    /// appends `@@inject_uponentry`/`@@inject_uponreturn` to the name.
    pub fn decode_payload_attributes(&mut self, decoder: &mut dyn crate::marshal::Decoder) {
        use crate::marshal::Decoder;
        self.paramshift = 0;
        self.dynamic = false;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("paramshift") => self.paramshift = decoder.read_signed_integer() as i32,
                Some("dynamic") => self.dynamic = decoder.read_bool(),
                Some("incidentalcopy") => self.incidental_copy = decoder.read_bool(),
                Some("inject") => {
                    let upon_type = decoder.read_string();
                    if upon_type == "uponentry" {
                        self.name = format!("{}@@inject_uponentry", self.name);
                    } else {
                        self.name = format!("{}@@inject_uponreturn", self.name);
                    }
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
    }

    // Ghidra: pcodeinject.cc:111 InjectPayload::decodePayloadParams
    /// Elements are processed until the first child that isn't an `<input>`
    /// or `<output>` tag is encountered.  The `<pcode>` element must be
    /// current and already opened.  Faithful to the oracle error path: a
    /// parameter element with an empty name makes
    /// `decodeParameter`'s LowlevelError (pcodeinject.cc:62-63) propagate
    /// out of `decodePayloadParams` and abort the whole decode.
    pub fn decode_payload_params(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            if sub_name == "input" {
                let (param_name, size) = Self::decode_parameter(decoder)?;
                self.input_list.push(InjectParameter::new(param_name, size));
            } else if sub_name == "output" {
                let (param_name, size) = Self::decode_parameter(decoder)?;
                self.output.push(InjectParameter::new(param_name, size));
            } else {
                break;
            }
        }
        self.order_parameters();
        Ok(())
    }

    // Ghidra: inject_sleigh.cc:72 InjectPayloadSleigh::decodeBody
    /// Read the raw p-code source from a `<body>` subtag.  Faithful to
    /// `decodeBody` (inject_sleigh.cc:72-82): the tag may be absent
    /// (`openElement()` returning 0 without pushing); a non-`<body>` tag is
    /// opened but never closed, matching the Ghidra stream corruption; an
    /// empty parsestring on a non-dynamic payload throws.
    ///
    /// RUDRA-GLUE: Ghidra's `readString(ATTRIB_CONTENT)` reads the current
    /// element's character content (marshal.cc:390-395); Rugra's
    /// `TreeDecoder` cannot surface element content through the `Decoder`
    /// trait, so the content of the `<body>` child is threaded in by the
    /// caller from the paired DOM handle (`body_content`).
    pub fn decode_body(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        body_content: Option<&str>,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element(); // Tag may not be present
        if decoder.element_name(elem_id).as_deref() == Some("body") {
            self.parsestring = body_content.unwrap_or("").to_string();
            decoder.close_element(elem_id);
        }
        if self.parsestring.is_empty() && !self.dynamic {
            return Err(format!("Missing <body> subtag in <pcode>: {}", self.source));
        }
        Ok(())
    }

    // Ghidra: inject_sleigh.cc:171 InjectPayloadCallfixup::decode
    /// Restore a `<callfixup>` element.  Faithful to
    /// `InjectPayloadCallfixup::decode` (inject_sleigh.cc:171-194): read the
    /// name attribute, walk children in document order (`<pcode>` must
    /// appear exactly once, `<target>` appends the target symbol name),
    /// throw when no `<pcode>` subtag was seen.
    pub fn decode_callfixup(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        body_content: Option<&str>,
    ) -> Result<(), String> {
        use crate::marshal::{AttributeId, Decoder};
        let elem_id = decoder.open_element();
        self.name = decoder.read_string_attr(&AttributeId::new("name", 0));
        let mut pcode_subtag = false;
        loop {
            let sub_id = decoder.open_element();
            if sub_id == 0 {
                break;
            }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            if sub_name == "pcode" {
                self.decode_payload_attributes(decoder);
                self.decode_payload_params(decoder)?;
                self.decode_body(decoder, body_content)?;
                pcode_subtag = true;
            } else if sub_name == "target" {
                self.target_symbol_names
                    .push(decoder.read_string_attr(&AttributeId::new("name", 0)));
            }
            decoder.close_element(sub_id);
        }
        decoder.close_element(elem_id);
        if !pcode_subtag {
            return Err(format!(
                "<callfixup> is missing <pcode> subtag: {}",
                self.name
            ));
        }
        Ok(())
    }

    // Ghidra: inject_sleigh.cc:201 InjectPayloadCallother::decode
    /// Restore a `<callotherfixup>` element.  Faithful to
    /// `InjectPayloadCallother::decode` (inject_sleigh.cc:201-214): the
    /// payload name comes from the `targetop` attribute and the first child
    /// must be `<pcode>`.
    pub fn decode_callother(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        body_content: Option<&str>,
    ) -> Result<(), String> {
        use crate::marshal::{AttributeId, Decoder};
        let elem_id = decoder.open_element();
        self.name = decoder.read_string_attr(&AttributeId::new("targetop", 0));
        let sub_id = decoder.open_element();
        if decoder.element_name(sub_id).as_deref() != Some("pcode") {
            return Err("<callotherfixup> does not contain a <pcode> tag".to_string());
        }
        self.decode_payload_attributes(decoder);
        self.decode_payload_params(decoder)?;
        self.decode_body(decoder, body_content)?;
        decoder.close_element(sub_id);
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: inject_sleigh.cc:84 InjectPayloadSleigh::decode
    /// Restore a raw `<pcode>` tag (used for uponentry/uponreturn call
    /// mechanisms).  Faithful to `InjectPayloadSleigh::decode`
    /// (inject_sleigh.cc:84-93).
    pub fn decode_pcode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        body_content: Option<&str>,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        self.decode_payload_attributes(decoder);
        self.decode_payload_params(decoder)?;
        self.decode_body(decoder, body_content)?;
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: inject_sleigh.cc:256 ExecutablePcodeSleigh::decode
    /// Restore a `<pcode>`/`<case_pcode>`/`<addr_pcode>`/`<default_pcode>`/
    /// `<size_pcode>` script element.  Faithful to
    /// `ExecutablePcodeSleigh::decode` (inject_sleigh.cc:256-269), including
    /// the exact DecoderError message for other element names.
    pub fn decode_executable(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        body_content: Option<&str>,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        match decoder.element_name(elem_id).as_deref() {
            Some("pcode") | Some("case_pcode") | Some("addr_pcode") | Some("default_pcode")
            | Some("size_pcode") => {}
            _ => {
                return Err(
                    "Expecting <pcode>, <case_pcode>, <addr_pcode>, <default_pcode>, or <size_pcode>"
                        .to_string(),
                )
            }
        }
        self.decode_payload_attributes(decoder);
        self.decode_payload_params(decoder)?;
        // openElement(ELEM_BODY) (inject_sleigh.cc:265): the body element
        // is mandatory — XmlDecode::openElement(elemId) throws
        // DecoderError when no child remains or the next child is not
        // <body> (marshal.cc:187/190, messages verbatim).
        let sub_id = decoder.open_element();
        match decoder.element_name(sub_id).as_deref() {
            Some("body") => {}
            _ => {
                return Err(match decoder.element_name(sub_id) {
                    Some(other) => {
                        format!("Expecting <body> but got <{}>", other)
                    }
                    None => "Expecting <body> but no remaining children in current element"
                        .to_string(),
                })
            }
        }
        self.parsestring = body_content.unwrap_or("").to_string();
        decoder.close_element(sub_id);
        decoder.close_element(elem_id);
        Ok(())
    }
}

/// Context needed to emit a p-code injection.
/// Corresponds to Ghidra's `InjectContext` (pcodeinject.hh:79).
#[derive(Debug, Clone)]
pub struct InjectContext {
    /// Address of instruction causing inject
    pub base_addr: u64,
    /// Address of following instruction
    pub next_addr: u64,
    /// If the injection is for a call, this is the address being called
    pub call_addr: u64,
    /// Input parameters (`inputlist`, `vector<VarnodeData>`)
    pub input_list: Vec<VarnodeRaw>,
    /// Output parameters (`output`, `vector<VarnodeData>`)
    pub output: Vec<VarnodeRaw>,
}

impl InjectContext {
    // Ghidra: pcodeinject.hh:79 InjectContext::new
    pub fn new() -> Self {
        Self {
            base_addr: 0,
            next_addr: 0,
            call_addr: 0,
            input_list: Vec::new(),
            output: Vec::new(),
        }
    }

    // Ghidra: pcodeinject.hh:88 InjectContext::clear
    pub fn clear(&mut self) {
        self.input_list.clear();
        self.output.clear();
    }
}

/// A trait for emitting injected p-code operations.
/// Corresponds to Ghidra's `PcodeEmit` callback (translate.hh:94), whose
/// `dump(addr,opc,outvar,vars,isize)` signature is mirrored with
/// `VarnodeRaw` standing in for `VarnodeData`.
pub trait PcodeEmit {
    // Ghidra: translate.hh:96 PcodeEmit::dump
    /// Emit a single p-code operation.
    fn dump(
        &mut self,
        addr: u64,
        opc: crate::opcodes::OpCode,
        inputs: &[VarnodeRaw],
        output: Option<VarnodeRaw>,
    );
}

/// A simple in-memory p-code emitter that collects emitted ops.
pub struct PcodeEmitArray {
    /// Collected operations: (addr, opcode, inputs, output)
    pub ops: Vec<(u64, crate::opcodes::OpCode, Vec<VarnodeRaw>, Option<VarnodeRaw>)>,
}

impl PcodeEmitArray {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }
    // RUDRA-GLUE: len (no Ghidra counterpart found)
    pub fn len(&self) -> usize {
        self.ops.len()
    }
    // RUDRA-GLUE: is_empty (no Ghidra counterpart found)
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

impl PcodeEmit for PcodeEmitArray {
    // RUDRA-GLUE: dump (no Ghidra counterpart found)
    fn dump(
        &mut self,
        addr: u64,
        opc: crate::opcodes::OpCode,
        inputs: &[VarnodeRaw],
        output: Option<VarnodeRaw>,
    ) {
        self.ops.push((addr, opc, inputs.to_vec(), output));
    }
}

// ---------------------------------------------------------------------------
// Injection template execution (inject_sleigh.cc:48 InjectPayloadSleigh::inject
// + semantics.cc PcodeBuilder::build + sleigh.cc SleighBuilder::dump /
// PcodeCacher::resolveRelatives / PcodeCacher::emit)
// ---------------------------------------------------------------------------

/// One resolved p-code op held by the injection cacher. Mirrors
/// `PcodeData` (sleigh.hh:46-50) as a value type; the label-reference
/// back-patch target is the `inputs[0]` of a relative-branch op.
// RUDRA-GLUE: value-type mirror of sleigh.hh:46 PcodeData because Rugra has
// no pooled VarnodeData arena; resolveRelatives mutates in place instead of
// through pool pointers.
struct PcodeDataInject {
    opc: OpCode,
    inputs: Vec<VarnodeRaw>,
    output: Option<VarnodeRaw>,
}

/// A label reference pending `resolveRelatives`. Mirrors
/// `PcodeCacher::RelativeRecord` (sleigh.hh:70-73): the referenced label id
/// sits in `inputs[0].offset` of `issued[op_index]`, and
/// `calling_index` is the issuing op's own index.
// RUDRA-GLUE: (op_index, calling_index) pair instead of a pool pointer.
struct RelativeRecordInject {
    op_index: usize,
    calling_index: usize,
}

/// The non-existent-label sentinel, faithful to sleigh.cc:104
/// (`labels.push_back(0xbadbeef)`).
const BADBEEF: usize = 0xbadbeef;

impl InjectPayload {
    /// Perform the injection of this payload into data-flow. Faithful to
    /// `InjectPayloadSleigh::inject` (inject_sleigh.cc:48-65): set up the
    /// operand handles from the context (`setupParameters`), run the compiled
    /// template through the builder (`SleighBuilder::build(tpl,-1)`), resolve
    /// label relatives (`PcodeCacher::resolveRelatives`), and emit every op
    /// with the injection base address (`PcodeCacher::emit(con.baseaddr,...)`).
    ///
    /// The ops are returned as `PcodeOpRaw` records (no SeqNum — the caller's
    /// bank adapter stamps the base address, exactly like `PcodeEmitFd::dump`
    /// receiving `addr` from `cacher.emit`). RUDRA-GLUE: Ghidra hands a live
    /// `PcodeEmit&` into `inject`; Rust's borrow rules forbid lending
    /// `&mut Funcdata` through `&self`, so the emit step materializes into a
    /// `PcodeEmitArray` first and the bank write happens in the caller
    /// (`Funcdata::inject_raw_ops_single`, the `PcodeEmitFd::dump` port).
    // Ghidra: inject_sleigh.cc:48 InjectPayloadSleigh::inject
    pub fn inject(&self, context: &InjectContext) -> Result<Vec<PcodeOpRaw>, String> {
        let empty_source = format!("Empty injection: {}", self.name);
        let tpl = self
            .tpl
            .as_ref()
            .ok_or_else(|| format!("Injection has no compiled template: {}", self.name))?;
        // inject_sleigh.cc:55-63 setupParameters: bind each input then each
        // output parameter (in list order) to a fixed handle carrying the
        // context varnode (space, offset, size) with offset_space = null.
        self.check_parameter_restrictions(context)?;
        let mut handles: Vec<VarnodeRaw> = Vec::with_capacity(context.input_list.len() + context.output.len());
        for vn in &context.input_list {
            handles.push(vn.clone());
        }
        for vn in &context.output {
            handles.push(vn.clone());
        }
        let builder = InjectBuilder {
            context,
            handles,
            issued: Vec::new(),
            label_refs: Vec::new(),
            labels: Vec::new(),
        };
        // inject_sleigh.cc:64-65: build + resolveRelatives + emit.
        let issued = builder.build(tpl)?;
        let issued = resolve_relatives(issued)?;
        if issued.is_empty() {
            // flow.cc:1188-1189 raises LowlevelError("Empty injection: " + name)
            // when the dead list did not grow; surface the same message here so
            // FlowInfo::do_injection can report it verbatim.
            return Err(empty_source);
        }
        // sleigh.cc:139-144 PcodeCacher::emit: every op is passed to the
        // emitter with the injection base address.
        let mut emit = PcodeEmitArray::new();
        for op in &issued {
            emit.dump(context.base_addr, op.opc, &op.inputs, op.output.clone());
        }
        Ok(emit
            .ops
            .into_iter()
            .map(|(_addr, opc, inputs, output)| {
                let mut raw = PcodeOpRaw::new(opc as i32);
                if let Some(out) = output {
                    raw.set_output(out);
                }
                for vn in inputs {
                    raw.add_input(vn);
                }
                raw
            })
            .collect())
    }

    /// Verify the context storage matches this payload's parameter
    /// restrictions. Faithful to `InjectPayloadSleigh::checkParameterRestrictions`
    /// (inject_sleigh.cc:105-131), messages verbatim.
    // Ghidra: inject_sleigh.cc:109 InjectPayloadSleigh::checkParameterRestrictions
    fn check_parameter_restrictions(&self, con: &InjectContext) -> Result<(), String> {
        if self.input_list.len() != con.input_list.len() {
            return Err(format!(
                "Injection parameter list has different number of parameters than p-code operation: {}",
                self.source
            ));
        }
        for (i, param) in self.input_list.iter().enumerate() {
            let sz = param.size;
            if sz != 0 && sz as usize != con.input_list[i].size {
                return Err(format!(
                    "P-code input parameter size does not match injection specification: {}",
                    self.source
                ));
            }
        }
        if self.output.len() != con.output.len() {
            return Err(format!(
                "Injection output does not match output of p-code operation: {}",
                self.source
            ));
        }
        for (i, param) in self.output.iter().enumerate() {
            let sz = param.size;
            if sz != 0 && sz as usize != con.output[i].size {
                return Err(format!(
                    "P-code output size does not match injection specification: {}",
                    self.source
                ));
            }
        }
        Ok(())
    }
}

/// Builder state for one template execution. Mirrors the `SleighBuilder`
/// walk over a `ConstructTpl` (semantics.cc:925-952 `PcodeBuilder::build`)
/// with the `PcodeCacher` accumulator (sleigh.hh:58) inlined.
// RUDRA-GLUE: struct-based builder because Rust has no ParserWalker; the
// injection-relevant walker state (fixed handles + inject addresses) is
// carried by value.
struct InjectBuilder<'c> {
    context: &'c InjectContext,
    /// FixedHandle per parameter index (inputs first, then outputs), from
    /// `setupParameters` (inject_sleigh.cc:134-159).
    handles: Vec<VarnodeRaw>,
    /// `PcodeCacher::issued`
    issued: Vec<PcodeDataInject>,
    /// `PcodeCacher::label_refs`
    label_refs: Vec<RelativeRecordInject>,
    /// `PcodeCacher::labels`
    labels: Vec<usize>,
}

impl<'c> InjectBuilder<'c> {
    /// Walk the template's op list. Faithful to `PcodeBuilder::build`
    /// (semantics.cc:925-952): BUILD/DELAY_SLOT/CROSSBUILD are forbidden in
    /// snippets (inject_sleigh.cc:59-61 comment), LABELBUILD records the
    /// label position, and every other op goes through `dump`
    /// (sleigh.cc:221 `SleighBuilder::dump`). Returns the issued ops plus
    /// the cacher's label tables for `resolveRelatives`.
    // Ghidra: semantics.cc:925 PcodeBuilder::build
    fn build(mut self, tpl: &ConstructTpl) -> Result<CacherState, String> {
        for op in &tpl.opvec {
            match op.opc {
                // semantics.hh:26-30 pseudo-opcodes; snippets cannot contain
                // them (the inject ParserWalker has no constructor state to
                // build/delay/cross against), so they are hard errors here.
                OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT | OpCode::CPUI_PTRSUB => {
                    return Err(format!(
                        "Injection snippet contains illegal build/delay-slot/cross-build op: {}",
                        self.payload_name()
                    ));
                }
                // LABELBUILD == CPUI_PTRADD (semantics.hh:30); the snippet
                // compiler emits it only from placeLabel with one const
                // input holding the label id.
                OpCode::CPUI_PTRADD => {
                    // sleigh.cc:399-403 SleighBuilder::setLabel:
                    // cache->addLabel(op->getIn(0)->getOffset().getReal()+getLabelBase())
                    // — getLabelBase() is 0 for the top-level injection build
                    // (labelcount starts at 0, semantics.cc:929-930).
                    let id = op
                        .inputs
                        .first()
                        .and_then(|vn| vn.offset.as_real())
                        .ok_or_else(|| "LABELBUILD without a constant label id".to_string())?
                        as usize;
                    self.add_label(id);
                }
                _ => self.dump_op(op)?,
            }
        }
        Ok(CacherState {
            issued: self.issued,
            label_refs: self.label_refs,
            labels: self.labels,
        })
    }

    // RUDRA-GLUE: payload_name (source description for error text)
    fn payload_name(&self) -> String {
        format!("inject @ {:#x}", self.context.base_addr)
    }

    /// Dump one op through the low-level interface. Faithful to
    /// `SleighBuilder::dump` (sleigh.cc:221-280) restricted to the injection
    /// subset: `setupParameters` always sets `hand.offset_space = null`
    /// (inject_sleigh.cc:152), so `VarnodeTpl::isDynamic`
    /// (semantics.cc:455-463) is always false and the dynamic LOAD/STORE
    /// expansion (sleigh.cc:229-247/261-278) is unreachable.
    // Ghidra: sleigh.cc:221 SleighBuilder::dump
    fn dump_op(&mut self, op: &OpTpl) -> Result<(), String> {
        let mut inputs = Vec::with_capacity(op.inputs.len());
        for vn_tpl in &op.inputs {
            inputs.push(self.generate_location(vn_tpl)?);
        }
        // sleigh.cc:252-255: a relative branch input records a label
        // reference. `invars->offset += getLabelBase()` adds 0 at the
        // top-level injection build, so the resolved offset stays the label
        // id that resolveRelatives rewrites.
        if !op.inputs.is_empty() {
            if let ConstTpl::JRelative(_) = op.inputs[0].offset {
                let calling_index = self.issued.len();
                self.label_refs.push(RelativeRecordInject {
                    op_index: calling_index,
                    calling_index,
                });
            }
        }
        let output = match &op.out {
            Some(out_tpl) => Some(self.generate_location(out_tpl)?),
            None => None,
        };
        self.issued.push(PcodeDataInject {
            opc: op.opc,
            inputs,
            output,
        });
        Ok(())
    }

    /// Resolve a template varnode into a concrete location. Faithful to
    /// `SleighBuilder::generateLocation` (sleigh.cc:160-175): space via
    /// `ConstTpl::fixSpace`, size via `fix`; a constant-space offset is
    /// masked to the varnode size, a unique-space offset is ORed with the
    /// (zero) injection unique offset, anything else wraps into the space.
    // Ghidra: sleigh.cc:152 SleighBuilder::generateLocation
    fn generate_location(&self, vn_tpl: &VarnodeTpl) -> Result<VarnodeRaw, String> {
        let space = self.fix_space(&vn_tpl.space)?;
        let size = self.fix(&vn_tpl.size)? as usize;
        let offset = if space == crate::space::AddressSpace::Const {
            self.fix(&vn_tpl.offset)? & calc_mask(size as i32)
        } else if space == crate::space::AddressSpace::Unique {
            // inject_sleigh.cc:61: SleighBuilder is constructed with
            // uniqueoffset = 0 for injections ("we don't need a unique
            // allocation mask").
            self.fix(&vn_tpl.offset)?
        } else {
            // space.hh:383 AddrSpace::wrapOffset — offsets within the space
            // bound pass through unchanged. RUDRA-GLUE: Rugra's AddressSpace
            // tag enum carries no `highest` metadata (ADDRESS-0001 family);
            // injection snippet offsets are in-bounds machine/unique
            // offsets, so the pass-through covers the reachable inputs and
            // the wrap-around reduction is a documented residual.
            self.fix(&vn_tpl.offset)?
        };
        Ok(VarnodeRaw::new(space, offset, size))
    }

    /// Resolve a ConstTpl to its value in context. Faithful to
    /// `ConstTpl::fix` (semantics.cc:116-179) for the injection-reachable
    /// const types. RUDRA-GLUE: `j_curspace`/`spaceid` positions where C++
    /// yields the AddrSpace heap pointer yield Rugra's stable `space_id()`
    /// tag (only observable in LOAD space-reference constants, where
    /// PcodeEmitFd reads it via getSpaceFromConst).
    // Ghidra: semantics.cc:116 ConstTpl::fix
    fn fix(&self, ct: &ConstTpl) -> Result<u64, String> {
        match ct {
            ConstTpl::Real(v) => Ok(*v),
            ConstTpl::JStart => Ok(self.context.base_addr),
            ConstTpl::JNext => Ok(self.context.next_addr),
            // inject_sleigh.cc never calls setN2addr, so the ParserContext
            // keeps its default (invalid Address, offset 0).
            ConstTpl::JNext2 => Ok(0),
            // ParserContext::getRefAddr is never set for injections either;
            // the default Address carries offset 0.
            ConstTpl::JFlowRef => Ok(0),
            // inject_sleigh.cc:52 setCalladdr(con.calladdr) feeds getDestAddr.
            ConstTpl::JFlowDest => Ok(self.context.call_addr),
            // ParserContext::getCurSpace()->getAddrSize() — the address size
            // of the instruction space. RUDRA-GLUE: Rugra's AddressSpace tag
            // enum carries no per-space metadata; the SLEIGH x86-64 machine
            // model that Rugra pins defines the default space with 8-byte
            // addresses (ADDRESS-0001 family residual).
            ConstTpl::JCurSpaceSize => Ok(8),
            ConstTpl::JCurSpace => Ok(crate::space::AddressSpace::Ram.space_id() as u64),
            ConstTpl::JRelative(id) => Ok(*id as u64),
            ConstTpl::SpaceId(space) => Ok(space.space_id() as u64),
            ConstTpl::Handle { index, select, plus } => {
                // semantics.cc:131-158: the handle fields, with
                // offset_space == null for injection handles.
                let hand = self
                    .handles
                    .get(*index as usize)
                    .ok_or_else(|| format!("Unallocated injection operand handle {}", index))?;
                match select {
                    HandleSelect::Space => Ok(hand.space.space_id() as u64),
                    HandleSelect::Offset => Ok(hand.offset),
                    HandleSelect::Size => Ok(hand.size as u64),
                    HandleSelect::OffsetPlus => {
                        if hand.space != crate::space::AddressSpace::Const {
                            // semantics.cc:146-148: adjust offset by the
                            // truncation amount.
                            Ok(hand.offset + (plus & 0xffff))
                        } else {
                            // semantics.cc:149-158: a constant is shifted by
                            // the byte-truncation selector.
                            Ok(hand.offset >> (8 * (plus >> 16)))
                        }
                    }
                }
            }
        }
    }

    /// Resolve a ConstTpl known to be a space. Faithful to
    /// `ConstTpl::fixSpace` (semantics.cc:181-205): j_curspace resolves to
    /// the instruction space (ram for injected machine-code addresses),
    /// handle/v_space to the operand's space, spaceid directly; anything
    /// else throws `ConstTpl is not a spaceid as expected` (verbatim).
    // Ghidra: semantics.cc:181 ConstTpl::fixSpace
    fn fix_space(&self, ct: &ConstTpl) -> Result<crate::space::AddressSpace, String> {
        match ct {
            ConstTpl::JCurSpace => Ok(crate::space::AddressSpace::Ram),
            ConstTpl::SpaceId(space) => Ok(*space),
            ConstTpl::Handle { index, select: HandleSelect::Space, .. } => self
                .handles
                .get(*index as usize)
                .map(|hand| hand.space)
                .ok_or_else(|| format!("Unallocated injection operand handle {}", index)),
            _ => Err("ConstTpl is not a spaceid as expected".to_string()),
        }
    }

    /// Record a label position. Faithful to `PcodeCacher::addLabel`
    /// (sleigh.cc:100-106): the labels vector grows to the id with the
    /// 0xbadbeef sentinel and slot `id` takes the next issue index.
    // Ghidra: sleigh.cc:100 PcodeCacher::addLabel
    fn add_label(&mut self, id: usize) {
        while self.labels.len() <= id {
            self.labels.push(BADBEEF);
        }
        self.labels[id] = self.issued.len();
    }
}

/// The `PcodeCacher` accumulator state after a build walk: issued ops plus
/// the label bookkeeping consumed by `resolveRelatives`.
// RUDRA-GLUE: value bundle mirroring sleigh.hh:58 PcodeCacher fields.
struct CacherState {
    issued: Vec<PcodeDataInject>,
    label_refs: Vec<RelativeRecordInject>,
    labels: Vec<usize>,
}

/// Rewrite relative branch offsets as label deltas. Faithful to
/// `PcodeCacher::resolveRelatives` (sleigh.cc:120-137): a reference to a
/// missing or unplaced label throws `Reference to non-existant sleigh label`
/// (verbatim); the resolved offset is `(labels[id] - calling_index)` masked
/// to the varnode size.
// Ghidra: sleigh.cc:120 PcodeCacher::resolveRelatives
fn resolve_relatives(mut cacher: CacherState) -> Result<Vec<PcodeDataInject>, String> {
    for record in &cacher.label_refs {
        let op = &mut cacher.issued[record.op_index];
        let vn = op
            .inputs
            .first_mut()
            .expect("label ref op must have input(0)");
        // sleigh.cc:127: the referenced label id sits in the varnode offset
        // after the build walk (JRelative resolved to its raw value).
        let id = vn.offset as usize;
        let label_pos = *cacher
            .labels
            .get(id)
            .ok_or("Reference to non-existant sleigh label")?;
        if label_pos == BADBEEF {
            return Err("Reference to non-existant sleigh label".to_string());
        }
        // sleigh.cc:130-132: relative index = label position - calling index,
        // masked into the varnode size.
        let res = (label_pos.wrapping_sub(record.calling_index) as u64) & calc_mask(vn.size as i32);
        vn.offset = res;
    }
    Ok(cacher.issued)
}

/// Manager for all injection payloads.
/// Corresponds to Ghidra's `PcodeInjectLibrary` (pcodeinject.hh:187) as
/// extended by `PcodeInjectLibrarySleigh` (inject_sleigh.hh:110): payloads
/// live in the id-indexed `injection` vector, each payload type has a
/// name→id map plus an id→name vector, and the SLEIGH flavor carries the
/// running unique-space `tempbase` and the SLEIGH symbol lookup (`slgh`).
pub struct PcodeInjectLibrary {
    /// All payloads by inject id (`injection`).  Payloads whose decode or
    /// registration failed remain here as unregistered orphans, matching
    /// Ghidra's non-transactional `injection` vector growth.
    pub injection: Vec<InjectPayload>,
    /// Call fixup name → inject id (`callFixupMap`)
    pub call_fixups: BTreeMap<String, i32>,
    /// Call fixup inject id → name (`callFixupNames`)
    pub call_fixup_names: Vec<String>,
    /// CALLOTHER fixup name → inject id (`callOtherFixupMap`)
    pub call_other_fixups: BTreeMap<String, i32>,
    /// CALLOTHER fixup inject id → name (`callOtherTarget`)
    pub call_other_target: Vec<String>,
    /// Call mechanism name → inject id (`callMechFixupMap`)
    pub call_mechanisms: BTreeMap<String, i32>,
    /// Call mechanism inject id → name (`callMechTarget`)
    pub call_mech_target: Vec<String>,
    /// P-code script name → inject id (`scriptMap`)
    pub script_map: BTreeMap<String, i32>,
    /// P-code script inject id → name (`scriptNames`)
    pub script_names: Vec<String>,
    /// Running unique-space offset for snippet temporaries
    /// (`PcodeInjectLibrarySleigh::tempbase`), initialized from
    /// `Translate::getUniqueStart(Translate::INJECT)`.
    pub tempbase: u64,
    /// The SLEIGH language symbol lookup (`PcodeInjectLibrarySleigh::slgh`)
    /// consulted when compiling snippet bodies.
    sleigh: Option<Arc<dyn SleighSymbolLookup + Send + Sync>>,
}

impl PcodeInjectLibrary {
    // Ghidra: inject_sleigh.cc:343 PcodeInjectLibrarySleigh::new
    /// Construct a library with the given unique-space base
    /// (`getUniqueStart(Translate::INJECT)`).
    pub fn new(tempbase: u64) -> Self {
        Self {
            injection: Vec::new(),
            call_fixups: BTreeMap::new(),
            call_fixup_names: Vec::new(),
            call_other_fixups: BTreeMap::new(),
            call_other_target: Vec::new(),
            call_mechanisms: BTreeMap::new(),
            call_mech_target: Vec::new(),
            script_map: BTreeMap::new(),
            script_names: Vec::new(),
            tempbase,
            sleigh: None,
        }
    }

    // Ghidra: inject_sleigh.cc:378-381 PcodeInjectLibrarySleigh::parseInject
    /// Install the SLEIGH language symbol lookup used when compiling
    /// snippet bodies; decoding before this is set mirrors the "language is
    /// instantiated" contract.
    pub fn set_sleigh_lookup(&mut self, lookup: Arc<dyn SleighSymbolLookup + Send + Sync>) {
        self.sleigh = Some(lookup);
    }

    // Ghidra: pcodeinject.hh:205 PcodeInjectLibrary::getPayload
    /// Get the payload registered under the given inject id.
    pub fn get_payload_by_id(&self, injectid: i32) -> Option<&InjectPayload> {
        self.injection.get(injectid as usize)
    }

    // RUDRA-GLUE: get_payload (no Ghidra counterpart found)
    /// Look a payload up by formal name.  Ghidra resolves names through the
    /// per-type maps; this convenience view scans `injection` in id order
    /// (first match wins) for callers like FlowInfo that hold a payload
    /// name.
    pub fn get_payload(&self, name: &str) -> Option<&InjectPayload> {
        self.injection.iter().find(|p| p.name == name)
    }

    // Ghidra: pcodeinject.cc:220 PcodeInjectLibrary::registerCallFixup
    /// Map a call-fixup name to a payload id.  Faithful to
    /// `registerCallFixup` (pcodeinject.cc:220-230): a duplicate name throws
    /// `Duplicate <callfixup>: <name>` before the names vector grows; the
    /// vector is extended with empty strings up to the id and the name is
    /// recorded at the id slot.
    pub fn register_call_fixup(&mut self, fixup_name: &str, injectid: i32) -> Result<(), String> {
        if self.call_fixups.contains_key(fixup_name) {
            return Err(format!("Duplicate <callfixup>: {}", fixup_name));
        }
        self.call_fixups.insert(fixup_name.to_string(), injectid);
        while self.call_fixup_names.len() <= injectid as usize {
            self.call_fixup_names.push(String::new());
        }
        self.call_fixup_names[injectid as usize] = fixup_name.to_string();
        Ok(())
    }

    // Ghidra: pcodeinject.cc:236 PcodeInjectLibrary::registerCallOtherFixup
    /// Map a callother-fixup name to a payload id.  Faithful to
    /// `registerCallOtherFixup` (pcodeinject.cc:236-246).
    pub fn register_call_other_fixup(
        &mut self,
        fixup_name: &str,
        injectid: i32,
    ) -> Result<(), String> {
        if self.call_other_fixups.contains_key(fixup_name) {
            return Err(format!("Duplicate <callotherfixup>: {}", fixup_name));
        }
        self.call_other_fixups.insert(fixup_name.to_string(), injectid);
        while self.call_other_target.len() <= injectid as usize {
            self.call_other_target.push(String::new());
        }
        self.call_other_target[injectid as usize] = fixup_name.to_string();
        Ok(())
    }

    // Ghidra: pcodeinject.cc:252 PcodeInjectLibrary::registerCallMechanism
    /// Map a call mechanism name to a payload id.  Faithful to
    /// `registerCallMechanism` (pcodeinject.cc:252-262).
    pub fn register_call_mechanism(
        &mut self,
        fixup_name: &str,
        injectid: i32,
    ) -> Result<(), String> {
        if self.call_mechanisms.contains_key(fixup_name) {
            return Err(format!("Duplicate <callmechanism>: {}", fixup_name));
        }
        self.call_mechanisms.insert(fixup_name.to_string(), injectid);
        while self.call_mech_target.len() <= injectid as usize {
            self.call_mech_target.push(String::new());
        }
        self.call_mech_target[injectid as usize] = fixup_name.to_string();
        Ok(())
    }

    // Ghidra: pcodeinject.cc:268 PcodeInjectLibrary::registerExeScript
    /// Map a p-code script name to a payload id.  Faithful to
    /// `registerExeScript` (pcodeinject.cc:268-278).
    pub fn register_exe_script(&mut self, script_name: &str, injectid: i32) -> Result<(), String> {
        if self.script_map.contains_key(script_name) {
            return Err(format!("Duplicate <script>: {}", script_name));
        }
        self.script_map.insert(script_name.to_string(), injectid);
        while self.script_names.len() <= injectid as usize {
            self.script_names.push(String::new());
        }
        self.script_names[injectid as usize] = script_name.to_string();
        Ok(())
    }

    // Ghidra: pcodeinject.cc:285 PcodeInjectLibrary::getPayloadId
    /// Look the payload id up in the symbol table for the given type.
    /// Returns -1 when there is no matching payload.
    pub fn get_payload_id(&self, inject_type: InjectPayloadType, nm: &str) -> i32 {
        match inject_type {
            InjectPayloadType::CallFixup => self.call_fixups.get(nm),
            InjectPayloadType::CallOtherFixup => self.call_other_fixups.get(nm),
            InjectPayloadType::CallMechanism => self.call_mechanisms.get(nm),
            InjectPayloadType::ExecutablePcode => self.script_map.get(nm),
        }
        .copied()
        .unwrap_or(-1)
    }

    // Ghidra: pcodeinject.cc:314 PcodeInjectLibrary::getCallFixupName
    /// Name of the call-fixup payload with the given id, or "" if out of
    /// range.
    pub fn get_call_fixup_name(&self, injectid: i32) -> String {
        if injectid < 0 || injectid as usize >= self.call_fixup_names.len() {
            return String::new();
        }
        self.call_fixup_names[injectid as usize].clone()
    }

    // Ghidra: pcodeinject.cc:324 PcodeInjectLibrary::getCallOtherTarget
    /// Name of the callother-fixup payload with the given id, or "" if out
    /// of range.
    pub fn get_call_other_target(&self, injectid: i32) -> String {
        if injectid < 0 || injectid as usize >= self.call_other_target.len() {
            return String::new();
        }
        self.call_other_target[injectid as usize].clone()
    }

    // Ghidra: pcodeinject.cc:334 PcodeInjectLibrary::getCallMechanismName
    /// Name of the call-mechanism payload with the given id, or "" if out
    /// of range.
    pub fn get_call_mechanism_name(&self, injectid: i32) -> String {
        if injectid < 0 || injectid as usize >= self.call_mech_target.len() {
            return String::new();
        }
        self.call_mech_target[injectid as usize].clone()
    }

    // Ghidra: inject_sleigh.cc:418 PcodeInjectLibrarySleigh::allocateInject
    /// Allocate a new payload of the given type and return its id.
    /// Faithful to `allocateInject` (inject_sleigh.cc:418-431): the id is
    /// the current vector size; CALLFIXUP/CALLOTHERFIXUP payloads start
    /// with the placeholder name "unknown" (the decode overwrites it),
    /// EXECUTABLEPCODE keeps the provided name, other types build a plain
    /// SLEIGH payload.
    pub fn allocate_inject(
        &mut self,
        source_name: &str,
        name: &str,
        tp: InjectPayloadType,
    ) -> i32 {
        let injectid = self.injection.len() as i32;
        let payload = match tp {
            InjectPayloadType::CallFixup => {
                // InjectPayloadCallfixup(sourceName)
                InjectPayload::new_sleigh(source_name, "unknown", InjectPayloadType::CallFixup)
            }
            InjectPayloadType::CallOtherFixup => {
                // InjectPayloadCallother(sourceName)
                InjectPayload::new_sleigh(
                    source_name,
                    "unknown",
                    InjectPayloadType::CallOtherFixup,
                )
            }
            InjectPayloadType::ExecutablePcode => {
                // ExecutablePcodeSleigh(glb, sourceName, name)
                let mut payload = InjectPayload::new_sleigh(
                    source_name,
                    name,
                    InjectPayloadType::ExecutablePcode,
                );
                // ExecutablePcode ctor (pcodeinject.cc:137-144)
                payload.source = source_name.to_string();
                payload
            }
            _ => InjectPayload::new_sleigh(source_name, name, tp),
        };
        self.injection.push(payload);
        injectid
    }

    // Ghidra: inject_sleigh.cc:433 PcodeInjectLibrarySleigh::registerInject
    /// Finalize a payload with the library: register the name/type mapping
    /// then compile the snippet body.  Faithful to `registerInject`
    /// (inject_sleigh.cc:433-463): dynamic payloads are converted in place
    /// to their dynamic form (Ghidra swaps in an `InjectPayloadDynamic`
    /// holding the same name/type/incidentalCopy/paramshift/inputlist/
    /// output fields — inject_sleigh.cc:282-295 — so the observable payload
    /// state is unchanged apart from the class identity), then the
    /// per-type register method runs BEFORE `parseInject`, so a compile
    /// failure leaves the registered map/name entry behind.
    pub fn register_inject(&mut self, injectid: i32) -> Result<(), String> {
        let idx = injectid as usize;
        // Dynamic conversion: the InjectPayloadDynamic constructor clones
        // exactly the base properties already held by this payload, so the
        // in-place payload state is already what Ghidra swaps in.  The
        // dynamic-only addrMap/decodeEntry debug surface is not reachable
        // from compiler-spec text ingest (registered residual).
        let (name, tp) = {
            let payload = &self.injection[idx];
            (payload.name.clone(), payload.payload_type)
        };
        match tp {
            InjectPayloadType::CallFixup => {
                self.register_call_fixup(&name, injectid)?;
                self.parse_inject(idx)?;
            }
            InjectPayloadType::CallOtherFixup => {
                self.register_call_other_fixup(&name, injectid)?;
                self.parse_inject(idx)?;
            }
            InjectPayloadType::CallMechanism => {
                self.register_call_mechanism(&name, injectid)?;
                self.parse_inject(idx)?;
            }
            InjectPayloadType::ExecutablePcode => {
                self.register_exe_script(&name, injectid)?;
                self.parse_inject(idx)?;
            }
        }
        Ok(())
    }

    // Ghidra: inject_sleigh.cc:373 PcodeInjectLibrarySleigh::parseInject
    /// Compile a payload's SLEIGH snippet into a p-code template.
    /// Faithful to `parseInject` (inject_sleigh.cc:373-416): dynamic
    /// payloads are skipped; the snippet compiler is seeded with the
    /// payload's input/output operands, executable scripts allocate from
    /// unique offset 0x2000 while other payloads continue from the
    /// library's `tempbase` (which then advances); a parse failure throws
    /// `<source>: Unable to compile pcode: <error>` leaving the registered
    /// map entry behind; on success the template replaces the parsestring.
    fn parse_inject(&mut self, index: usize) -> Result<(), String> {
        if self.injection[index].is_dynamic() {
            return Ok(());
        }
        let Some(sleigh) = self.sleigh.clone() else {
            return Err(
                "Registering pcode snippet before language is instantiated".to_string()
            );
        };
        let mut compiler = PcodeSnippet::new();
        compiler.set_sleigh_lookup(sleigh);
        let input_count = self.injection[index].size_input();
        for i in 0..input_count {
            let param = self.injection[index].get_input(i).expect("index in range").clone();
            compiler.add_operand(&param.name, param.index);
        }
        let output_count = self.injection[index].size_output();
        for i in 0..output_count {
            let param = self.injection[index].get_output(i).expect("index in range").clone();
            compiler.add_operand(&param.name, param.index);
        }
        let is_executable =
            self.injection[index].payload_type == InjectPayloadType::ExecutablePcode;
        if is_executable {
            // Don't need to deconflict with anything other injects
            compiler.set_unique_base(0x2000);
        } else {
            compiler.set_unique_base(self.tempbase);
        }
        let parsestring = self.injection[index].parsestring.clone();
        if !compiler.parse_stream(&parsestring) {
            let source = self.injection[index].source.clone();
            return Err(format!(
                "{}: Unable to compile pcode: {}",
                source,
                compiler.get_error_message()
            ));
        }
        if !is_executable {
            self.tempbase = compiler.get_unique_base();
        }
        let tpl = compiler.release_result();
        let payload = &mut self.injection[index];
        payload.tpl = tpl;
        payload.parsestring = String::new(); // No longer need the memory
        Ok(())
    }

    // Ghidra: pcodeinject.cc:352 PcodeInjectLibrary::decodeInject
    /// Parse and register an injection payload from a stream element.
    /// Faithful to `decodeInject` (pcodeinject.cc:352-359): allocate the
    /// payload, decode it, then register it.  A decode or compile failure
    /// leaves the allocated payload in the `injection` vector as an
    /// unregistered orphan (non-transactional, like Ghidra).
    ///
    /// RUDRA-GLUE: the extra `body_content` parameter carries the current
    /// payload's `<body>` character content, which Ghidra reads via
    /// `readString(ATTRIB_CONTENT)` but Rugra's `TreeDecoder` cannot
    /// surface through the `Decoder` trait (see `InjectPayload::decode_body`).
    pub fn decode_inject(
        &mut self,
        src: &str,
        nm: &str,
        tp: InjectPayloadType,
        decoder: &mut dyn crate::marshal::Decoder,
        body_content: Option<&str>,
    ) -> Result<i32, String> {
        let injectid = self.allocate_inject(src, nm, tp);
        let payload = &mut self.injection[injectid as usize];
        match tp {
            InjectPayloadType::CallFixup => payload.decode_callfixup(decoder, body_content)?,
            InjectPayloadType::CallOtherFixup => payload.decode_callother(decoder, body_content)?,
            InjectPayloadType::ExecutablePcode => {
                payload.decode_executable(decoder, body_content)?
            }
            InjectPayloadType::CallMechanism => payload.decode_pcode(decoder, body_content)?,
        }
        self.register_inject(injectid)?;
        Ok(injectid)
    }

    // Ghidra: inject_sleigh.cc:493 PcodeInjectLibrarySleigh::manualCallFixup
    /// Manually install a call-fixup payload from a raw snippet string.
    /// Faithful to `manualCallFixup` (inject_sleigh.cc:493-502).
    pub fn manual_call_fixup(&mut self, name: &str, snippet_string: &str) -> Result<i32, String> {
        let source_name = format!("(manual callfixup name=\"{}\")", name);
        let injectid = self.allocate_inject(
            &source_name,
            name,
            InjectPayloadType::CallFixup,
        );
        self.injection[injectid as usize].parsestring = snippet_string.to_string();
        self.register_inject(injectid)?;
        Ok(injectid)
    }

    // Ghidra: inject_sleigh.cc:504 PcodeInjectLibrarySleigh::manualCallOtherFixup
    /// Manually install a callother-fixup payload from names plus a raw
    /// snippet string.  Faithful to `manualCallOtherFixup`
    /// (inject_sleigh.cc:504-518).
    pub fn manual_call_other_fixup(
        &mut self,
        name: &str,
        outname: &str,
        inname: &[String],
        snippet: &str,
    ) -> Result<i32, String> {
        let source_name = format!("<manual callotherfixup name=\"{}\")", name);
        let injectid = self.allocate_inject(
            &source_name,
            name,
            InjectPayloadType::CallOtherFixup,
        );
        let payload = &mut self.injection[injectid as usize];
        for nm in inname {
            payload.input_list.push(InjectParameter::new(nm.clone(), 0));
        }
        if !outname.is_empty() {
            payload.output.push(InjectParameter::new(outname.to_string(), 0));
        }
        payload.order_parameters();
        payload.parsestring = snippet.to_string();
        self.register_inject(injectid)?;
        Ok(injectid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_parameter() {
        let p = InjectParameter::new("input0".into(), 4);
        assert_eq!(p.name, "input0");
        assert_eq!(p.size, 4);
    }

    #[test]
    fn test_inject_payload() {
        let mut p = InjectPayload::new("my_fixup".into(), InjectPayloadType::CallFixup);
        p.input_list.push(InjectParameter::new("in".into(), 8));
        assert_eq!(p.size_input(), 1);
        assert_eq!(p.payload_type, InjectPayloadType::CallFixup);
    }

    #[test]
    fn test_inject_context() {
        let mut ctx = InjectContext::new();
        ctx.base_addr = 0x1000;
        ctx.call_addr = 0x2000;
        ctx.input_list
            .push(VarnodeRaw::new(crate::space::AddressSpace::Ram, 0x100, 4));
        assert_eq!(ctx.input_list.len(), 1);
        ctx.clear();
        assert!(ctx.input_list.is_empty());
    }

    #[test]
    fn test_pcode_emit_array() {
        let mut emit = PcodeEmitArray::new();
        use crate::opcodes::OpCode;
        emit.dump(
            0x1000,
            OpCode::CPUI_COPY,
            &[VarnodeRaw::new(crate::space::AddressSpace::Unique, 0x200, 4)],
            Some(VarnodeRaw::new(crate::space::AddressSpace::Ram, 0x300, 4)),
        );
        assert_eq!(emit.len(), 1);
        assert_eq!(emit.ops[0].1, OpCode::CPUI_COPY);
    }

    #[test]
    fn test_payload_add_params() {
        let mut p = InjectPayload::new("test".into(), InjectPayloadType::CallFixup);
        p.add_input("in0".into(), 8);
        p.add_output("out0".into(), 8);
        assert_eq!(p.size_input(), 1);
        assert_eq!(p.size_output(), 1);
        assert_eq!(p.get_input(0).unwrap().name, "in0");
    }

    #[test]
    fn test_order_parameters() {
        let mut p = InjectPayload::new("test".into(), InjectPayloadType::CallFixup);
        p.add_input("in0".into(), 8);
        p.add_input("in1".into(), 4);
        p.add_output("out0".into(), 8);
        p.order_parameters();
        assert_eq!(p.get_input(0).unwrap().index, 0);
        assert_eq!(p.get_input(1).unwrap().index, 1);
        assert_eq!(p.get_output(0).unwrap().index, 2);
    }

    #[test]
    fn test_register_call_fixup_id_and_names() {
        // Faithful to registerCallFixup (pcodeinject.cc:220-230): duplicate
        // names fail, the names vector is id-indexed with "" padding.
        let mut lib = PcodeInjectLibrary::new(0x200);
        let id0 = lib.allocate_inject("s", "f0", InjectPayloadType::CallFixup);
        assert_eq!(id0, 0);
        lib.register_call_fixup("f0", id0).unwrap();
        let id1 = lib.allocate_inject("s", "f1", InjectPayloadType::CallFixup);
        lib.register_call_fixup("f1", id1).unwrap();
        assert_eq!(lib.get_payload_id(InjectPayloadType::CallFixup, "f1"), 1);
        assert_eq!(lib.get_call_fixup_name(0), "f0");
        assert_eq!(lib.get_call_fixup_name(1), "f1");
        assert_eq!(lib.get_call_fixup_name(-1), "");
        assert_eq!(lib.get_call_fixup_name(9), "");
        assert_eq!(
            lib.register_call_fixup("f0", 5).unwrap_err(),
            "Duplicate <callfixup>: f0"
        );
    }

    #[test]
    fn test_register_call_other_and_mechanism() {
        let mut lib = PcodeInjectLibrary::new(0x200);
        lib.register_call_other_fixup("myop", 0).unwrap();
        assert_eq!(lib.get_payload_id(InjectPayloadType::CallOtherFixup, "myop"), 0);
        assert_eq!(lib.get_call_other_target(0), "myop");
        assert_eq!(
            lib.register_call_other_fixup("myop", 1).unwrap_err(),
            "Duplicate <callotherfixup>: myop"
        );
        lib.register_call_mechanism("__thunk", 1).unwrap();
        assert_eq!(lib.get_payload_id(InjectPayloadType::CallMechanism, "__thunk"), 1);
        assert_eq!(lib.get_call_mechanism_name(1), "__thunk");
        assert_eq!(
            lib.register_call_mechanism("__thunk", 2).unwrap_err(),
            "Duplicate <callmechanism>: __thunk"
        );
    }

    #[test]
    fn test_register_exe_script() {
        let mut lib = PcodeInjectLibrary::new(0x200);
        lib.register_exe_script("script0", 0).unwrap();
        assert_eq!(lib.get_payload_id(InjectPayloadType::ExecutablePcode, "script0"), 0);
        assert_eq!(
            lib.register_exe_script("script0", 1).unwrap_err(),
            "Duplicate <script>: script0"
        );
    }

    #[test]
    fn test_decode_inject_orphan_on_decode_failure() {
        // Faithful to decodeInject (pcodeinject.cc:352-359): a payload whose
        // decode fails stays allocated in the injection vector (orphan id),
        // never registered in the map.
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        let mut lib = PcodeInjectLibrary::new(0x200);
        // <callfixup> with no <pcode> child → decode error.
        let root = Arc::new(std::sync::RwLock::new({
            let mut e = Element::new();
            e.set_name("callfixup");
            e.add_attribute("name", "broken");
            e
        }));
        let registry = Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        let mut decoder = TreeDecoder::new(root, registry);
        let err = lib
            .decode_inject("src", "", InjectPayloadType::CallFixup, &mut decoder, None)
            .unwrap_err();
        assert_eq!(err, "<callfixup> is missing <pcode> subtag: broken");
        assert_eq!(lib.injection.len(), 1);
        assert!(lib.call_fixups.is_empty());
        assert!(lib.call_fixup_names.is_empty());
    }

    #[test]
    fn test_parse_inject_requires_language() {
        // Faithful to parseInject (inject_sleigh.cc:378-381): registering a
        // snippet before the language is instantiated throws.
        let mut lib = PcodeInjectLibrary::new(0x200);
        let id = lib.allocate_inject("s", "f0", InjectPayloadType::CallFixup);
        lib.injection[id as usize].parsestring = "RAX = 0;".to_string();
        assert_eq!(
            lib.register_inject(id).unwrap_err(),
            "Registering pcode snippet before language is instantiated"
        );
        // The registerCallFixup step ran BEFORE parseInject: the map entry
        // is a non-transactional residual (faithful to Ghidra ordering).
        // InjectPayloadCallfixup's constructor name is "unknown" (the real
        // name only arrives via decode), so the residual registers under
        // "unknown" — matching Ghidra's manualCallFixup quirk.
        assert_eq!(lib.get_payload_id(InjectPayloadType::CallFixup, "unknown"), id);
        assert_eq!(lib.get_payload_id(InjectPayloadType::CallFixup, "f0"), -1);
    }

    // ---- InjectPayload::inject (inject_sleigh.cc:48) execution tests ----

    /// Build a library whose snippet compiler accepts operands/constants
    /// (a null SLEIGH symbol lookup wrapped in PredefinedJumpSymbols, the
    // language-instantiated stand-in used by parseInject).
    fn language_ready_library() -> PcodeInjectLibrary {
        use crate::pcodeparse::PredefinedJumpSymbols;
        struct EmptyHost;
        impl crate::pcodeparse::SleighSymbolLookup for EmptyHost {
            fn find_symbol(&self, _name: &str) -> Option<crate::pcodeparse::SleighSymbol> {
                None
            }
        }
        let mut lib = PcodeInjectLibrary::new(0x200);
        lib.set_sleigh_lookup(std::sync::Arc::new(PredefinedJumpSymbols::new(EmptyHost)));
        lib
    }

    fn run_snippet(lib: &mut PcodeInjectLibrary, snippet: &str) -> Vec<PcodeOpRaw> {
        let injectid = lib
            .manual_call_other_fixup("probe", "out", &["in0".to_string()], snippet)
            .expect("snippet compiles");
        let payload = lib.get_payload_by_id(injectid).expect("payload exists").clone();
        let mut context = InjectContext::new();
        context.base_addr = 0x1000;
        context.next_addr = 0x1004;
        context.call_addr = 0x2000;
        context
            .input_list
            .push(VarnodeRaw::new(crate::space::AddressSpace::Ram, 0x3000, 4));
        context
            .output
            .push(VarnodeRaw::new(crate::space::AddressSpace::Ram, 0x4000, 4));
        payload.inject(&context).expect("injection executes")
    }

    #[test]
    fn test_inject_execute_copy_snippet() {
        // `out = in0;` compiles to a single COPY whose operand varnodes are
        // substituted from the InjectContext (setupParameters,
        // inject_sleigh.cc:134-159).
        let ops = run_snippet(&mut language_ready_library(), "out = in0;");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].get_opcode(), OpCode::CPUI_COPY as i32);
        let input = &ops[0].inputs()[0];
        assert_eq!((input.space, input.offset, input.size), (crate::space::AddressSpace::Ram, 0x3000, 4));
        let output = ops[0].output().expect("COPY has output");
        assert_eq!((output.space, output.offset, output.size), (crate::space::AddressSpace::Ram, 0x4000, 4));
    }

    #[test]
    fn test_inject_execute_add_snippet() {
        // `out = in0 + 0x10:4;` compiles to a single INT_ADD whose output is
        // rewritten in place to the output operand (ExprTree::setOutput's
        // unnamed-temp rewrite, pcodecompile.cc:85-106); the constant is
        // masked to the varnode size in the const space (generateLocation,
        // sleigh.cc:169) and the operand handles are substituted from the
        // InjectContext (setupParameters, inject_sleigh.cc:134-159).
        let ops = run_snippet(&mut language_ready_library(), "out = in0 + 0x10:4;");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].get_opcode(), OpCode::CPUI_INT_ADD as i32);
        let operand = &ops[0].inputs()[0];
        assert_eq!((operand.space, operand.offset, operand.size), (crate::space::AddressSpace::Ram, 0x3000, 4));
        let constant = &ops[0].inputs()[1];
        assert_eq!(
            (constant.space, constant.offset, constant.size),
            (crate::space::AddressSpace::Const, 0x10, 4)
        );
        let output = ops[0].output().expect("INT_ADD has output");
        assert_eq!(
            (output.space, output.offset, output.size),
            (crate::space::AddressSpace::Ram, 0x4000, 4)
        );
    }

    #[test]
    fn test_inject_execute_label_branch_snippet() {
        // A snippet with an internal conditional branch resolves the label
        // reference as `labels[id] - calling_index` masked to the branch
        // varnode size (resolveRelatives, sleigh.cc:120-137): the CBRANCH is
        // issued at index 0 and the label precedes the second COPY at index
        // 2, so the relative offset is 2.
        let snippet = "if (in0) goto <over>; out = 0x1:4; <over> out = 0x2:4;";
        let ops = run_snippet(&mut language_ready_library(), snippet);
        let branch = ops
            .iter()
            .find(|op| op.get_opcode() == OpCode::CPUI_CBRANCH as i32)
            .expect("snippet contains CBRANCH");
        let target = &branch.inputs()[0];
        // The label jumpdest size is sizeof(uintm) = 4 (pcodeparse.y:199;
        // uintm is uint32_t, types.h:27) — pinned byte-exact by the
        // pcode_snippet_face_1204 fixture's st20/LF|clrlbl records.
        assert_eq!(
            (target.space, target.offset, target.size),
            (crate::space::AddressSpace::Const, 2, 4)
        );
        // Two COPYs into the output operand, the second from the post-label
        // constant 0x2.
        let copies: Vec<&PcodeOpRaw> = ops
            .iter()
            .filter(|op| op.get_opcode() == OpCode::CPUI_COPY as i32)
            .collect();
        assert_eq!(copies.len(), 2);
        let last_const = &copies[1].inputs()[0];
        assert_eq!(last_const.offset, 0x2);
    }

    #[test]
    fn test_inject_parameter_restriction_errors() {
        // checkParameterRestrictions (inject_sleigh.cc:105-131): a context
        // with the wrong input count fails with the verbatim message.
        let mut lib = language_ready_library();
        let injectid = lib
            .manual_call_other_fixup("probe", "out", &["in0".to_string()], "out = in0;")
            .expect("snippet compiles");
        let payload = lib.get_payload_by_id(injectid).expect("payload exists").clone();
        let mut context = InjectContext::new();
        context.base_addr = 0x1000;
        // No input_list entries: count mismatch (payload declares 1 input).
        // The source spelling is verbatim from manualCallOtherFixup
        // (inject_sleigh.cc:507), including its unbalanced quote/paren.
        assert_eq!(
            payload.inject(&context).unwrap_err(),
            "Injection parameter list has different number of parameters than p-code operation: <manual callotherfixup name=\"probe\")"
        );
    }

    #[test]
    fn test_inject_without_template_errors() {
        // A payload that never compiled has no template to execute.
        let mut payload = InjectPayload::new("broken".into(), InjectPayloadType::CallOtherFixup);
        payload.source = "test".to_string();
        let context = InjectContext::new();
        assert_eq!(
            payload.inject(&context).unwrap_err(),
            "Injection has no compiled template: broken"
        );
    }
}
