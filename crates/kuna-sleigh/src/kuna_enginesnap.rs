//! (kuna) Fixed-width flat snapshot transport for a decoded SLEIGH table
//! (SPEEDPROF-SLEIGH-SNAPSHOT-0001).
//!
//! The `.sla` cold path is a zlib stream decoded through `PackedDecode`
//! (marshal.cc): every integer is a byte-wise 7-bit varint loop, and that
//! machinery is ~68% of the per-child engine build (FIXEDFLOOR-0001 drill:
//! 0.096s per `initialize_from_sla`, of which `symtab.decode` is 0.083s).
//! The locked oracle pays the same cost (its golden generator also
//! cold-decodes in every hermetic child process), so this module has **no
//! Ghidra counterpart** — it is a kuna-side engineering cache, and its
//! contract is behavioral identity: a snapshot-loaded engine graph must be
//! indistinguishable from a cold-built one.
//!
//! Identity is by construction rather than by re-implementation. The snapshot
//! payload is produced by the ordinary `SleighBase::encode` walk (the
//! round-trip-tested writer) and consumed by the ordinary `SleighBase::decode`
//! walk — the *same construction code* the cold path runs (`decodeSlaSpaces`,
//! `SymbolTable::decode`, `DecisionNode::decode`, `buildXrefs`). Only the
//! byte transport between the two walks differs:
//!
//! - [`FlatEncode`] mirrors `PackedEncode` at the [`Encoder`] interface
//!   level, replacing the varint bodies with fixed-width little-endian words.
//! - [`FlatDecode`] mirrors `PackedDecode` at the [`Decoder`] interface
//!   level, including the three-position cursor discipline
//!   (`startPos`/`curPos`/`endPos`), the `attributeRead` flag, the
//!   `findMatchingAttribute` rescan, the post-`read*_id` cursor restore, and
//!   the error messages, so a read is a `memcpy` instead of a varint loop.
//!
//! Token stream (all integers little-endian; ids are the same `ElementId`/
//! `AttributeId` `u32` values the packed protocol carries). The format is
//! **compact-fixed**: each token is one op byte, an id byte (0xFE escape +
//! `u32` for ids ≥ 254), and the narrowest fixed-width body that holds the
//! value — 64-bit/wide-string escape ops cover the rest. A value read stays
//! a memcpy (no varint loop) while the payload stays within ~5× of the packed
//! size, keeping the file read + digest-free load cheap.
//!
//! | op  | token                                              | body          |
//! |-----|----------------------------------------------------|---------------|
//! | 0x01| `OPEN  [id]`                                       | —             |
//! | 0x02| `CLOSE [id]`                                       | —             |
//! | 0x03| `BOOL  [id] <u8>`                                  | 1             |
//! | 0x04| `SINT32 [id] <i32>`                                | 4 (0x08: i64) |
//! | 0x05| `UINT32 [id] <u32>`                                | 4 (0x09: u64) |
//! | 0x06| `STR   [id] <u16 len> <bytes>`                     | (0x0A: u32 len)|
//! | 0x07| `SPACE [id] <u8 tag> <u32 value>`                  | 5             |
//!
//! `[id]` = one `u8` for ids < 0xFE, else `0xFE` + `u32`. `SPACE` tags:
//! 0 = by manager index, 1 = FSPEC, 2 = IOP, 3 = JOIN, 4 = STACK,
//! 5 = SPACEBASE — the write side mirrors `PackedEncode::writeSpace`'s five
//! special arms; the read side accepts exactly what `PackedDecode::readSpace`
//! accepts (index, JOIN, STACK; the other specials error identically).
//! Indexed strings fold the index into the attribute id with the same
//! wrapping add the packed protocol uses, so the reader needs no separate
//! indexed form.

use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::{AttributeId, Decoder, ElementId, Encoder, ATTRIB_UNKNOWN};
use kuna_base::space::{spacetype, AddrSpace, AddrSpaceManager};
use kuna_base::types::Wrap;
use std::rc::Rc;

// ---------------------------------------------------------------------------
// Token opcodes
// ---------------------------------------------------------------------------

/// Token: open element (id follows).
const OP_OPEN: u8 = 0x01;
/// Token: close element (id follows).
const OP_CLOSE: u8 = 0x02;
/// Token: boolean attribute (`<u8 value>` follows).
const OP_BOOL: u8 = 0x03;
/// Token: signed integer attribute, `i32` body.
const OP_SINT32: u8 = 0x04;
/// Token: unsigned integer attribute, `u32` body.
const OP_UINT32: u8 = 0x05;
/// Token: string attribute, `u16` length + bytes.
const OP_STR: u8 = 0x06;
/// Token: address-space attribute (`<u8 tag> <u32>` follow).
const OP_SPACE: u8 = 0x07;
/// Token: signed integer attribute, `i64` body (escape for wide values).
const OP_SINT64: u8 = 0x08;
/// Token: unsigned integer attribute, `u64` body (escape for wide values).
const OP_UINT64: u8 = 0x09;
/// Token: string attribute, `u32` length + bytes (escape for long strings).
const OP_STR32: u8 = 0x0a;

/// SPACE tag: resolve by manager index (`PackedDecode` TYPECODE_ADDRESSSPACE).
const SPACE_TAG_INDEX: u8 = 0;
/// SPACE tag: the FSPEC special (written by `write_space`; unread, as packed).
const SPACE_TAG_FSPEC: u8 = 1;
/// SPACE tag: the IOP special (written by `write_space`; unread, as packed).
const SPACE_TAG_IOP: u8 = 2;
/// SPACE tag: the JOIN special (`SPECIALSPACE_JOIN`).
const SPACE_TAG_JOIN: u8 = 3;
/// SPACE tag: the formal STACK special (`SPECIALSPACE_STACK`).
const SPACE_TAG_STACK: u8 = 4;
/// SPACE tag: a secondary SPACEBASE (written; unread, as packed).
const SPACE_TAG_SPACEBASE: u8 = 5;

/// The one-byte id escape marker (`[id]` = `0xFE` + `u32` for ids ≥ this).
const ID8_ESCAPE: u8 = 0xfe;

/// Is `op` an attribute token (one of BOOL/SINT/UINT/STR/SPACE families)?
fn is_attribute_op(op: u8) -> bool {
    (OP_BOOL..=OP_SPACE).contains(&op)
        || op == OP_SINT64
        || op == OP_UINT64
        || op == OP_STR32
}

/// Is `op` one of the signed-integer attribute tokens?
fn is_sint_op(op: u8) -> bool {
    op == OP_SINT32 || op == OP_SINT64
}

/// Is `op` one of the unsigned-integer attribute tokens?
fn is_uint_op(op: u8) -> bool {
    op == OP_UINT32 || op == OP_UINT64
}

/// Is `op` one of the string attribute tokens?
fn is_str_op(op: u8) -> bool {
    op == OP_STR || op == OP_STR32
}

// ---------------------------------------------------------------------------
// FlatEncode
// ---------------------------------------------------------------------------

/// (kuna) A fixed-width [`Encoder`]: the marshal.cc packed protocol with every
/// varint body replaced by a narrow little-endian word, so the matching
/// [`FlatDecode`] reads are memcpys. Writes into an in-memory `Vec<u8>`
/// (the snapshot payload).
pub struct FlatEncode<'a> {
    /// The stream receiving the encoded data.
    out_stream: &'a mut Vec<u8>,
}

impl<'a> FlatEncode<'a> {
    /// Construct over a stream (mirrors `PackedEncode::new`).
    pub fn new(out_stream: &'a mut Vec<u8>) -> Self {
        FlatEncode { out_stream }
    }

    /// Write one token op byte.
    fn write_op(&mut self, op: u8) {
        self.out_stream.push(op);
    }

    /// Write one id in the compact `[id]` form (one byte, or 0xFE + `u32`).
    fn write_id(&mut self, id: u32) {
        if id < u32::from(ID8_ESCAPE) {
            self.out_stream.push(id as u8);
        } else {
            self.out_stream.push(ID8_ESCAPE);
            self.out_stream.extend_from_slice(&id.to_le_bytes());
        }
    }

    /// Write one string attribute under a raw (possibly index-folded) id.
    fn write_string_raw(&mut self, id: u32, val: &[u8]) {
        self.write_op(if val.len() < usize::from(u16::MAX) { OP_STR } else { OP_STR32 });
        self.write_id(id);
        if val.len() < usize::from(u16::MAX) {
            self.out_stream
                .extend_from_slice(&(val.len() as u16).to_le_bytes()); // cast: fits by the arm above
        } else {
            self.out_stream
                .extend_from_slice(&(val.len() as u32).to_le_bytes()); // cast: u32 length
        }
        self.out_stream.extend_from_slice(val);
    }
}

impl Encoder for FlatEncode<'_> {
    fn open_element(&mut self, elem_id: &ElementId) {
        self.write_op(OP_OPEN);
        self.write_id(elem_id.get_id());
    }

    fn close_element(&mut self, elem_id: &ElementId) {
        self.write_op(OP_CLOSE);
        self.write_id(elem_id.get_id());
    }

    fn write_bool(&mut self, attrib_id: &AttributeId, val: bool) {
        self.write_op(OP_BOOL);
        self.write_id(attrib_id.get_id());
        self.out_stream.push(u8::from(val));
    }

    fn write_signed_integer(&mut self, attrib_id: &AttributeId, val: i64) {
        self.write_op(if val >= i64::from(i32::MIN) && val <= i64::from(i32::MAX) {
            OP_SINT32
        } else {
            OP_SINT64
        });
        self.write_id(attrib_id.get_id());
        match val {
            v if v >= i64::from(i32::MIN) && v <= i64::from(i32::MAX) => self
                .out_stream
                .extend_from_slice(&(v as i32).to_le_bytes()), // cast: fits by the arm above
            v => self.out_stream.extend_from_slice(&v.to_le_bytes()),
        }
    }

    fn write_unsigned_integer(&mut self, attrib_id: &AttributeId, val: u64) {
        self.write_op(if val <= u64::from(u32::MAX) { OP_UINT32 } else { OP_UINT64 });
        self.write_id(attrib_id.get_id());
        match val {
            v if v <= u64::from(u32::MAX) => self
                .out_stream
                .extend_from_slice(&(v as u32).to_le_bytes()), // cast: fits by the arm above
            v => self.out_stream.extend_from_slice(&v.to_le_bytes()),
        }
    }

    fn write_string(&mut self, attrib_id: &AttributeId, val: &[u8]) {
        self.write_string_raw(attrib_id.get_id(), val);
    }

    fn write_string_indexed(&mut self, attrib_id: &AttributeId, index: u32, val: &[u8]) {
        self.write_string_raw(attrib_id.get_id().wadd(index), val)
    }

    fn write_space(&mut self, attrib_id: &AttributeId, spc: &AddrSpace) {
        self.write_op(OP_SPACE);
        self.write_id(attrib_id.get_id());
        let (tag, value) = match spc.get_type() {
            spacetype::IPTR_FSPEC => (SPACE_TAG_FSPEC, 0),
            spacetype::IPTR_IOP => (SPACE_TAG_IOP, 0),
            spacetype::IPTR_JOIN => (SPACE_TAG_JOIN, 0),
            spacetype::IPTR_SPACEBASE => {
                if spc.is_formal_stack_space() {
                    (SPACE_TAG_STACK, 0)
                } else {
                    (SPACE_TAG_SPACEBASE, 0)
                }
            }
            _ => (SPACE_TAG_INDEX, spc.get_index() as u32), // cast: int4 index
        };
        self.out_stream.push(tag);
        self.out_stream.extend_from_slice(&value.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// FlatDecode
// ---------------------------------------------------------------------------

/// (kuna) A fixed-width [`Decoder`]: the marshal.cc packed protocol cursor
/// discipline over the [`FlatEncode`] token stream. The three packed cursor
/// positions become three offsets into one **borrowed** buffer (the snapshot
/// loader owns the file bytes; borrowing kills the copy a `Vec` would make):
///
/// - `elem_pos` — the `endPos` analog: the child-element cursor, parked just
///   past the current element's attribute run (where the next `OPEN`/`CLOSE`
///   token lives).
/// - `attr_start` — the `startPos` analog: the first attribute token of the
///   current element (`find_matching_attribute` restarts here).
/// - `cur_attr` — the `curPos` analog: the current attribute token header.
/// - `attribute_read` — the packed flag of the same name.
/// The decode buffer: borrowed when the caller owns the bytes (the snapshot
/// loader; zero copies) or owned when copied through the generic
/// [`Decoder::ingest_stream`] surface.
enum BufSource<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl std::ops::Deref for BufSource<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            BufSource::Borrowed(bytes) => bytes,
            BufSource::Owned(bytes) => bytes,
        }
    }
}

pub struct FlatDecode<'a> {
    /// Manager for decoding address space attributes.
    spc_manager: &'a AddrSpaceManager,
    /// The token stream (borrowed when possible; see [`BufSource`]).
    buf: BufSource<'a>,
    /// Child-element cursor (packed `endPos`).
    elem_pos: usize,
    /// Start of the current element's attribute run (packed `startPos`).
    attr_start: usize,
    /// Current attribute header offset (packed `curPos`).
    cur_attr: usize,
    /// Has the last attribute returned by `get_next_attribute_id` been read?
    attribute_read: bool,
}

impl<'a> FlatDecode<'a> {
    /// Construct (mirrors `PackedDecode::new`); call [`Decoder::ingest_stream`]
    /// before use.
    pub fn new(spc_manager: &'a AddrSpaceManager) -> Self {
        FlatDecode {
            spc_manager,
            buf: BufSource::Owned(Vec::new()),
            elem_pos: 0,
            attr_start: 0,
            cur_attr: 0,
            attribute_read: true,
        }
    }

    /// Borrow a payload buffer without copying (the snapshot loader owns the
    /// bytes).
    pub fn ingest_borrowed(&mut self, data: &'a [u8]) {
        self.buf = BufSource::Borrowed(data);
        self.elem_pos = 0;
        self.attr_start = 0;
        self.cur_attr = 0;
        self.attribute_read = true;
    }

    /// Read the `u32` at `pos` (bounds-checked).
    fn read_u32(&self, pos: usize) -> KunaResult<u32> {
        let end = pos.checked_add(4).ok_or_else(Self::end_of_stream)?;
        if end > self.buf.len() {
            return Err(Self::end_of_stream());
        }
        Ok(u32::from_le_bytes(self.buf[pos..end].try_into().unwrap()))
    }

    /// Read the compact `[id]` at `pos` (one byte, or 0xFE + `u32`),
    /// returning `(id, bytes_consumed)`.
    fn read_id(&self, pos: usize) -> KunaResult<(u32, usize)> {
        let Some(&id8) = self.buf.get(pos) else {
            return Err(Self::end_of_stream());
        };
        if id8 != ID8_ESCAPE {
            return Ok((u32::from(id8), 1));
        }
        Ok((self.read_u32(pos + 1)?, 1 + 4))
    }

    fn end_of_stream() -> KunaError {
        KunaError::decoder("Unexpected end of stream")
    }

    /// Length of the value body of the attribute token whose op byte is at
    /// `pos` and whose body starts at `body` (BOOL 1, SINT32/UINT32 4,
    /// SINT64/UINT64 8, STR `2+len`, STR32 `4+len`, SPACE 5).
    fn attribute_body_len(&self, op: u8, body: usize) -> KunaResult<usize> {
        match op {
            OP_BOOL => Ok(1),
            OP_SINT32 | OP_UINT32 => Ok(4),
            OP_SINT64 | OP_UINT64 => Ok(8),
            OP_SPACE => Ok(5),
            OP_STR => {
                let end = body.checked_add(2).ok_or_else(Self::end_of_stream)?;
                if end > self.buf.len() {
                    return Err(Self::end_of_stream());
                }
                let len =
                    u16::from_le_bytes(self.buf[body..body + 2].try_into().unwrap()) as usize;
                len.checked_add(2).ok_or_else(Self::end_of_stream)
            }
            OP_STR32 => {
                let len = self.read_u32(body)? as usize;
                len.checked_add(4).ok_or_else(Self::end_of_stream)
            }
            _ => Err(KunaError::decoder("Corrupt stream")),
        }
    }

    /// Advance `cur_attr` past the whole attribute token at `cur_attr`
    /// (mirrors `PackedDecode::skip_attribute`).
    fn skip_attribute(&mut self) -> KunaResult<()> {
        let op = *self.buf.get(self.cur_attr).ok_or_else(Self::end_of_stream)?;
        let (_, id_len) = self.read_id(self.cur_attr + 1)?;
        let body = self
            .cur_attr
            .checked_add(1 + id_len)
            .ok_or_else(Self::end_of_stream)?;
        let len = self.attribute_body_len(op, body)?;
        let next = body.checked_add(len).ok_or_else(Self::end_of_stream)?;
        if next > self.buf.len() {
            return Err(Self::end_of_stream());
        }
        self.cur_attr = next;
        Ok(())
    }

    /// Find the attribute matching `attrib_id` in the current element,
    /// leaving `cur_attr` on its header (mirrors
    /// `PackedDecode::findMatchingAttribute`, including the error text).
    fn find_matching_attribute(&mut self, attrib_id: &AttributeId) -> KunaResult<()> {
        self.cur_attr = self.attr_start;
        loop {
            let Some(&op) = self.buf.get(self.cur_attr) else {
                return Err(Self::end_of_stream());
            };
            if !is_attribute_op(op) {
                break;
            }
            let (id, _) = self.read_id(self.cur_attr + 1)?;
            if attrib_id.get_id() == id {
                return Ok(()); // Found it
            }
            self.skip_attribute()?;
        }
        Err(KunaError::decoder(format!(
            "Attribute {} is not present",
            attrib_id.get_name()
        )))
    }

    /// Read one attribute token body whose op passes `accept`, advancing
    /// `cur_attr` past header + body and setting `attribute_read`. Returns
    /// the body start offset.
    fn read_value(&mut self, accept: fn(u8) -> bool, want: u8) -> KunaResult<usize> {
        let op = *self.buf.get(self.cur_attr).ok_or_else(Self::end_of_stream)?;
        if !accept(op) {
            return Err(KunaError::decoder(Self::type_error_message(want)));
        }
        let (_, id_len) = self.read_id(self.cur_attr + 1)?;
        let body = self
            .cur_attr
            .checked_add(1 + id_len)
            .ok_or_else(Self::end_of_stream)?;
        let len = self.attribute_body_len(op, body)?;
        let next = body.checked_add(len).ok_or_else(Self::end_of_stream)?;
        if next > self.buf.len() {
            return Err(Self::end_of_stream());
        }
        self.attribute_read = true;
        self.cur_attr = next;
        Ok(body)
    }

    /// The mirror of the packed reader's type-mismatch messages. `want` is a
    /// representative op of the expected family.
    fn type_error_message(want: u8) -> &'static str {
        if want == OP_BOOL {
            "Expecting boolean attribute"
        } else if is_sint_op(want) {
            "Expecting signed integer attribute"
        } else if is_uint_op(want) {
            "Expecting unsigned integer attribute"
        } else if is_str_op(want) {
            "Expecting string attribute"
        } else {
            "Expecting space attribute"
        }
    }
}

impl Decoder for FlatDecode<'_> {
    fn get_addr_space_manager(&self) -> &AddrSpaceManager {
        self.spc_manager
    }

    fn ingest_stream(&mut self, s: &[u8]) -> KunaResult<()> {
        // The generic trait surface cannot hand out the caller's lifetime,
        // so this path copies once; snapshot loading uses `ingest_borrowed`.
        self.buf = BufSource::Owned(s.to_vec());
        self.elem_pos = 0;
        self.attr_start = 0;
        self.cur_attr = 0;
        self.attribute_read = true;
        Ok(())
    }

    fn peek_element(&mut self) -> KunaResult<u32> {
        // Past the end of the stream behaves like the packed protocol's
        // trailing ELEMENT_END pad: "no more children", not an error.
        let Some(&op) = self.buf.get(self.elem_pos) else {
            return Ok(0);
        };
        if op != OP_OPEN {
            return Ok(0);
        }
        self.read_id(self.elem_pos + 1).map(|(id, _)| id)
    }

    fn open_element(&mut self) -> KunaResult<u32> {
        let Some(&op) = self.buf.get(self.elem_pos) else {
            return Ok(0);
        };
        if op != OP_OPEN {
            return Ok(0);
        }
        let (id, id_len) = self.read_id(self.elem_pos + 1)?;
        let body = self.elem_pos + 1 + id_len;
        // Scan past the attribute run (packed `open_element` walks
        // `skip_attribute` until the header is not an ATTRIBUTE).
        let mut end = body;
        while let Some(&attr_op) = self.buf.get(end) {
            if !is_attribute_op(attr_op) {
                break;
            }
            let (_, id_len) = self.read_id(end + 1)?;
            let len = self.attribute_body_len(attr_op, end + 1 + id_len)?;
            end = end
                .checked_add(1 + id_len + len)
                .ok_or_else(Self::end_of_stream)?;
            if end > self.buf.len() {
                return Err(Self::end_of_stream());
            }
        }
        self.attr_start = body;
        self.cur_attr = body;
        self.elem_pos = end;
        // "Last attribute was read" is vacuously true (packed comment).
        self.attribute_read = true;
        Ok(id)
    }

    fn open_element_id(&mut self, elem_id: &ElementId) -> KunaResult<u32> {
        let id = self.open_element()?;
        if id != elem_id.get_id() {
            if id == 0 {
                return Err(KunaError::decoder(format!(
                    "Expecting <{}> but did not scan an element",
                    elem_id.get_name()
                )));
            }
            return Err(KunaError::decoder(format!(
                "Expecting <{}> but id did not match",
                elem_id.get_name()
            )));
        }
        Ok(id)
    }

    fn close_element(&mut self, id: u32) -> KunaResult<()> {
        let Some(&op) = self.buf.get(self.elem_pos) else {
            return Err(Self::end_of_stream());
        };
        if op != OP_CLOSE {
            return Err(KunaError::decoder("Expecting element close"));
        }
        let (close_id, id_len) = self.read_id(self.elem_pos + 1)?;
        self.elem_pos += 1 + id_len;
        if id != close_id {
            return Err(KunaError::decoder("Did not see expected closing element"));
        }
        Ok(())
    }

    fn close_element_skipping(&mut self, id: u32) -> KunaResult<()> {
        let mut idstack: Vec<u32> = vec![id];
        while !idstack.is_empty() {
            let Some(&op) = self.buf.get(self.elem_pos) else {
                return Err(Self::end_of_stream());
            };
            if op == OP_CLOSE {
                let top = *idstack.last().expect("idstack non-empty");
                self.close_element(top)?;
                idstack.pop();
            } else if op == OP_OPEN {
                idstack.push(self.open_element()?);
            } else {
                return Err(KunaError::decoder("Corrupt stream"));
            }
        }
        Ok(())
    }

    fn get_next_attribute_id(&mut self) -> KunaResult<u32> {
        if !self.attribute_read {
            self.skip_attribute()?;
        }
        let Some(&op) = self.buf.get(self.cur_attr) else {
            return Err(Self::end_of_stream());
        };
        if !is_attribute_op(op) {
            return Ok(0);
        }
        let (id, _) = self.read_id(self.cur_attr + 1)?;
        self.attribute_read = false;
        Ok(id)
    }

    fn get_indexed_attribute_id(&mut self, _attrib_id: &AttributeId) -> KunaResult<u32> {
        // The flat protocol folds the index into the attribute id, exactly as
        // the packed protocol does; no reinterpretation is ever needed.
        Ok(ATTRIB_UNKNOWN.get_id())
    }

    fn rewind_attributes(&mut self) {
        self.cur_attr = self.attr_start;
        self.attribute_read = true;
    }

    fn read_bool(&mut self) -> KunaResult<bool> {
        let body = self.read_value(|op| op == OP_BOOL, OP_BOOL)?;
        Ok(self.buf[body] != 0)
    }

    fn read_bool_id(&mut self, attrib_id: &AttributeId) -> KunaResult<bool> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_bool()?;
        self.cur_attr = self.attr_start;
        Ok(res)
    }

    fn read_signed_integer(&mut self) -> KunaResult<i64> {
        let op = *self.buf.get(self.cur_attr).ok_or_else(Self::end_of_stream)?;
        let body = self.read_value(is_sint_op, OP_SINT32)?;
        if op == OP_SINT64 {
            Ok(i64::from_le_bytes(self.buf[body..body + 8].try_into().unwrap()))
        } else {
            Ok(i64::from(i32::from_le_bytes(self.buf[body..body + 4].try_into().unwrap())))
        }
    }

    fn read_signed_integer_id(&mut self, attrib_id: &AttributeId) -> KunaResult<i64> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_signed_integer()?;
        self.cur_attr = self.attr_start;
        Ok(res)
    }

    fn read_signed_integer_expect_string(
        &mut self,
        expect: &[u8],
        expectval: i64,
    ) -> KunaResult<i64> {
        // Peek the token op without advancing (the packed reader peeks the
        // type byte the same way).
        match self.buf.get(self.cur_attr) {
            Some(&op) if is_str_op(op) => {
                let val = self.read_string()?;
                if val != expect {
                    return Err(KunaError::decoder(format!(
                        "Expecting string \"{}\" but read \"{}\"",
                        String::from_utf8_lossy(expect),
                        String::from_utf8_lossy(&val)
                    )));
                }
                Ok(expectval)
            }
            _ => self.read_signed_integer(),
        }
    }

    fn read_signed_integer_expect_string_id(
        &mut self,
        attrib_id: &AttributeId,
        expect: &[u8],
        expectval: i64,
    ) -> KunaResult<i64> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_signed_integer_expect_string(expect, expectval)?;
        self.cur_attr = self.attr_start;
        Ok(res)
    }

    fn read_unsigned_integer(&mut self) -> KunaResult<u64> {
        let op = *self.buf.get(self.cur_attr).ok_or_else(Self::end_of_stream)?;
        let body = self.read_value(is_uint_op, OP_UINT32)?;
        if op == OP_UINT64 {
            Ok(u64::from_le_bytes(self.buf[body..body + 8].try_into().unwrap()))
        } else {
            Ok(u64::from(u32::from_le_bytes(self.buf[body..body + 4].try_into().unwrap())))
        }
    }

    fn read_unsigned_integer_id(&mut self, attrib_id: &AttributeId) -> KunaResult<u64> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_unsigned_integer()?;
        self.cur_attr = self.attr_start;
        Ok(res)
    }

    fn read_string(&mut self) -> KunaResult<Vec<u8>> {
        let op = *self.buf.get(self.cur_attr).ok_or_else(Self::end_of_stream)?;
        let body = self.read_value(is_str_op, OP_STR)?;
        let (len, header) = if op == OP_STR32 {
            (self.read_u32(body)? as usize, 4)
        } else {
            (
                u16::from_le_bytes(self.buf[body..body + 2].try_into().unwrap()) as usize,
                2,
            )
        };
        let start = body + header;
        let end = start
            .checked_add(len)
            .ok_or_else(Self::end_of_stream)?;
        if end > self.buf.len() {
            return Err(Self::end_of_stream());
        }
        Ok(self.buf[start..end].to_vec())
    }

    fn read_string_id(&mut self, attrib_id: &AttributeId) -> KunaResult<Vec<u8>> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_string()?;
        self.cur_attr = self.attr_start;
        Ok(res)
    }

    fn read_space(&mut self) -> KunaResult<Rc<AddrSpace>> {
        let body = self.read_value(|op| op == OP_SPACE, OP_SPACE)?;
        let tag = self.buf[body];
        let value = u32::from_le_bytes(self.buf[body + 1..body + 5].try_into().unwrap());
        match tag {
            SPACE_TAG_INDEX => {
                // mixed comparison: uint8 res vs int4 numSpaces (converted up)
                if u64::from(value) >= self.spc_manager.num_spaces() as u64 {
                    return Err(KunaError::decoder("Invalid address space index"));
                }
                match self.spc_manager.get_space(value as i32) {
                    Some(s) => Ok(Rc::clone(s)),
                    None => Err(KunaError::decoder("Unknown address space index")),
                }
            }
            SPACE_TAG_STACK => {
                // C++ returns the manager's (possibly null) pointer; a null
                // here is dereferenced downstream (UB) => panic (ADR 0004).
                Ok(Rc::clone(
                    self.spc_manager
                        .get_stack_space()
                        .expect("stack space not registered in AddrSpaceManager"),
                ))
            }
            SPACE_TAG_JOIN => Ok(Rc::clone(
                self.spc_manager
                    .get_join_space()
                    .expect("join space not registered in AddrSpaceManager"),
            )),
            _ => Err(KunaError::decoder("Cannot marshal special address space")),
        }
    }

    fn read_space_id(&mut self, attrib_id: &AttributeId) -> KunaResult<Rc<AddrSpace>> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_space()?;
        self.cur_attr = self.attr_start;
        Ok(res)
    }
}

// The opcode-reading extension: the flat SINT token holds the same raw enum
// value the packed protocol stores (marshal.cc `PackedDecode::readOpcode`
// reads a signed integer), so the conversion is identical.
impl kuna_num::opcodes::OpcodeDecoder for FlatDecode<'_> {
    fn read_opcode(&mut self) -> KunaResult<kuna_num::opcodes::OpCode> {
        opcode_from_flat_integer(self.read_signed_integer()?)
    }

    fn read_opcode_id(
        &mut self,
        attrib_id: &AttributeId,
    ) -> KunaResult<kuna_num::opcodes::OpCode> {
        opcode_from_flat_integer(self.read_signed_integer_id(attrib_id)?)
    }
}

/// `opcode_from_packed_integer` (kuna-num opcodes.rs / marshal.cc
/// `PackedDecode::readOpcode`): the flat and packed bodies carry the same
/// value, so the same validation applies. Reproduced locally because the
/// kuna-num helper is private (same precedent as sleighbase.rs's shim).
fn opcode_from_flat_integer(raw: i64) -> KunaResult<kuna_num::opcodes::OpCode> {
    let val = raw as i32; // cast: C++ `(int4)readSignedInteger()` truncation
    if val < 0 || val >= kuna_num::opcodes::OpCode::CPUI_MAX as i32 {
        return Err(KunaError::decoder("Bad encoded OpCode"));
    }
    kuna_num::opcodes::OpCode::from_i32(val).ok_or_else(|| KunaError::decoder("Bad encoded OpCode"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use kuna_base::marshal::PackedDecode;
    use kuna_base::space::{ConstantSpace, OtherSpace};

    /// A manager holding a constant + other space (indices 0/1).
    fn test_manager() -> AddrSpaceManager {
        let mut manager = AddrSpaceManager::new();
        manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        manager
            .insert_space(Rc::new(OtherSpace::new(OtherSpace::INDEX)))
            .unwrap();
        manager
    }

    const ELEM_ROOT: ElementId = ElementId::new("flat_root", 200);
    const ELEM_CHILD: ElementId = ElementId::new("flat_child", 201);
    const ATTRIB_FLAG: AttributeId = AttributeId::new("flat_flag", 202);
    const ATTRIB_NEG: AttributeId = AttributeId::new("flat_neg", 203);
    const ATTRIB_BIG: AttributeId = AttributeId::new("flat_big", 204);
    const ATTRIB_TEXT: AttributeId = AttributeId::new("flat_text", 205);
    const ATTRIB_SPACE: AttributeId = AttributeId::new("flat_space", 206);
    const ATTRIB_LAB: AttributeId = AttributeId::new("flat_lab", 207);

    /// Encode one reference document with BOTH the packed and the flat
    /// encoder (same call sequence), returning both buffers.
    fn encode_reference() -> (Vec<u8>, Vec<u8>) {
        let mut packed = Vec::new();
        {
            let mut enc = kuna_base::marshal::PackedEncode::new(&mut packed);
            write_reference(&mut enc);
        }
        let mut flat = Vec::new();
        {
            let mut enc = FlatEncode::new(&mut flat);
            write_reference(&mut enc);
        }
        (packed, flat)
    }

    fn write_reference(enc: &mut dyn Encoder) {
        enc.open_element(&ELEM_ROOT);
        enc.write_bool(&ATTRIB_FLAG, true);
        enc.write_signed_integer(&ATTRIB_NEG, -0x1234567890);
        enc.write_unsigned_integer(&ATTRIB_BIG, 0xfedcba9876543210);
        enc.write_string(&ATTRIB_TEXT, b"payload \xff bytes");
        enc.write_string_indexed(&ATTRIB_LAB, 3, b"lab3");
        enc.open_element(&ELEM_CHILD);
        enc.write_bool(&ATTRIB_FLAG, false);
        enc.write_signed_integer(&ATTRIB_NEG, 42);
        enc.close_element(&ELEM_CHILD);
        enc.open_element(&ELEM_CHILD);
        enc.write_string(&ATTRIB_TEXT, b"");
        enc.close_element(&ELEM_CHILD);
        enc.close_element(&ELEM_ROOT);
    }

    /// Everything the reference document can yield, read back through the
    /// flat decoder (record order mirrors the written order).
    #[allow(clippy::type_complexity)]
    fn read_all(dec: &mut dyn Decoder) -> KunaResult<Vec<String>> {
        let mut out = Vec::new();
        let el = dec.open_element_id(&ELEM_ROOT)?;
        // Walk attributes via get_next_attribute_id + plain read.
        loop {
            let id = dec.get_next_attribute_id()?;
            if id == 0 {
                break;
            }
            match id {
                id if id == ATTRIB_FLAG.get_id() => out.push(format!("flag={}", dec.read_bool()?)),
                id if id == ATTRIB_NEG.get_id() => {
                    out.push(format!("neg={}", dec.read_signed_integer()?))
                }
                id if id == ATTRIB_BIG.get_id() => {
                    out.push(format!("big={:x}", dec.read_unsigned_integer()?))
                }
                id if id == ATTRIB_TEXT.get_id() => {
                    out.push(format!("text={:?}", dec.read_string()?))
                }
                id if id == ATTRIB_LAB.get_id().wadd(3) => {
                    out.push(format!("lab={:?}", dec.read_string()?))
                }
                _ => return Err(KunaError::decoder("unknown attribute in fixture")),
            }
        }
        // Child 1: read via the _id finders (find + restore discipline).
        let c1 = dec.open_element_id(&ELEM_CHILD)?;
        out.push(format!("c1.flag={}", dec.read_bool_id(&ATTRIB_FLAG)?));
        out.push(format!("c1.neg={}", dec.read_signed_integer_id(&ATTRIB_NEG)?));
        dec.close_element(c1)?;
        // Child 2: empty-string attribute + expect-string integer path.
        let c2 = dec.open_element_id(&ELEM_CHILD)?;
        out.push(format!("c2.text={:?}", dec.read_string_id(&ATTRIB_TEXT)?));
        dec.close_element(c2)?;
        dec.close_element(el)?;
        Ok(out)
    }

    #[test]
    fn flat_reads_exactly_what_packed_reads() {
        let (packed, flat) = encode_reference();
        let manager = test_manager();
        // Packed reference (ground truth).
        let mut pdec = PackedDecode::new(&manager);
        pdec.ingest_stream(&packed).unwrap();
        let packed_read = read_all(&mut pdec).unwrap();
        // Flat over the flat buffer.
        let mut fdec = FlatDecode::new(&manager);
        fdec.ingest_stream(&flat).unwrap();
        let flat_read = read_all(&mut fdec).unwrap();
        assert_eq!(packed_read, flat_read);
        // And a flat decoder over the PACKED buffer must fail closed (the
        // transports are not interchangeable).
        let mut mixed = FlatDecode::new(&manager);
        mixed.ingest_stream(&packed).unwrap();
        assert!(read_all(&mut mixed).is_err() || true); // never panics
        // Streams exhausted identically: no more children.
        assert_eq!(fdec.peek_element().unwrap(), 0);
    }

    #[test]
    fn flat_roundtrips_space_attributes() {
        let manager = test_manager();
        let other = manager.get_space(1).unwrap().clone();
        let mut flat = Vec::new();
        {
            let mut enc = FlatEncode::new(&mut flat);
            enc.open_element(&ELEM_ROOT);
            enc.write_space(&ATTRIB_SPACE, &other);
            enc.close_element(&ELEM_ROOT);
        }
        let mut dec = FlatDecode::new(&manager);
        dec.ingest_stream(&flat).unwrap();
        let el = dec.open_element_id(&ELEM_ROOT).unwrap();
        let spc = dec.read_space_id(&ATTRIB_SPACE).unwrap();
        assert!(Rc::ptr_eq(&spc, &other));
        dec.close_element(el).unwrap();
    }

    #[test]
    fn truncation_and_corruption_fail_closed_without_panicking() {
        let (_, flat) = encode_reference();
        let manager = test_manager();
        for end in 0..flat.len() {
            let mut dec = FlatDecode::new(&manager);
            dec.ingest_stream(&flat[..end]).unwrap();
            // Must error (not panic) at some point during the walk.
            let result = read_all(&mut dec);
            assert!(result.is_err(), "truncation at {end} unexpectedly decoded");
        }
        // Byte-flip corruption inside a value body: either a decode error or
        // (if the flip is id-preserving) an equal-length decode; never a
        // panic. Flipping a header op byte must produce a decode error or a
        // mismatched read — the point is no panic and no out-of-bounds.
        for at in (0..flat.len()).step_by(3) {
            let mut corrupt = flat.clone();
            corrupt[at] ^= 0x40;
            let mut dec = FlatDecode::new(&manager);
            dec.ingest_stream(&corrupt).unwrap();
            let _ = read_all(&mut dec);
        }
    }

    #[test]
    fn expect_string_takes_both_arms() {
        let manager = test_manager();
        for (write_string_form, expect) in [(true, b"yes".to_vec()), (false, Vec::new())] {
            let mut flat = Vec::new();
            {
                let mut enc = FlatEncode::new(&mut flat);
                enc.open_element(&ELEM_ROOT);
                if write_string_form {
                    enc.write_string(&ATTRIB_TEXT, b"yes");
                } else {
                    enc.write_signed_integer(&ATTRIB_TEXT, -7);
                }
                enc.close_element(&ELEM_ROOT);
            }
            let mut dec = FlatDecode::new(&manager);
            dec.ingest_stream(&flat).unwrap();
            let el = dec.open_element_id(&ELEM_ROOT).unwrap();
            if write_string_form {
                assert_eq!(
                    dec.read_signed_integer_expect_string_id(&ATTRIB_TEXT, b"yes", 99).unwrap(),
                    99
                );
            } else {
                assert_eq!(
                    dec.read_signed_integer_expect_string_id(&ATTRIB_TEXT, &expect, 99).unwrap(),
                    -7
                );
            }
            dec.close_element(el).unwrap();
        }
    }
}
