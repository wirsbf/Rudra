//! Address representation and manipulation
//!
//! This module corresponds to Ghidra's `address.hh` and provides core address
//! types used throughout the decompiler.
//!
//! # Core Types
//!
//! - [`Address`] - A memory address in a specific address space
//! - [`SeqNum`] - Sequence number (address + order for P-code ops)
//! - [`Range`] - An address range (first, last)
//! - [`RangeList`] - A collection of non-overlapping address ranges

use crate::space::{attrib_offset, attrib_space, AddrSpace, SpaceRegistry, SpaceType};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::NonZeroU32;

// Ghidra: address.cc:25 ELEM_ADDR
/// Marshaling element `<addr>` (locked id 11, address.cc:25). Ghidra
/// declares this file-scope `ElementId` once; Rust mints it through a
/// constructor per call, the same pattern as pcodeparse.rs's duplicate.
pub fn elem_addr() -> crate::marshal::ElementId {
    crate::marshal::ElementId::new("addr", 11)
}

/// Memory address type (legacy offset carrier with an optional space tag)
///
/// Represents a virtual memory address in the target binary: an offset plus,
/// as of ADDRESS-0001 phase 1, an optional interned address-space tag that
/// mirrors Ghidra's `AddrSpace *base` slot (address.hh:61).
///
/// Corresponds to Ghidra's `Address` class in `address.hh`. The transitional
/// `None` space is the legacy spaceless form every pre-existing construction
/// site produces: `None`-to-`None` comparisons stay offset-only, so those
/// call sites behave exactly as before. `None` follows Ghidra's null-`base`
/// rules where the two models meet: it sorts before every real space
/// (address.hh:377) and never equals a space-carrying address
/// (address.hh:356 `base==op2.base` fails). It dies in phase 3 when the
/// space-carrying `SpaceAddress` and this type merge.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Address {
    /// Offset in bytes (address.hh:62 `offset`).
    offset: u64,
    /// Interned space tag for the `AddrSpace *base` slot (address.hh:61).
    /// `None` = legacy spaceless address (Ghidra's null `base`).
    space: Option<SpaceTag>,
}

// RUDRA-GLUE: SpaceTag (ADDRESS-0001 phase-1 transitional adapter; Ghidra
// stores a raw `AddrSpace *base` which cannot keep the legacy `Address`
// `Copy`. The tag is a copyable intern-table slot; the table keeps a strong
// handle so the space's allocation — and therefore its `identity_ptr` — can
// never be reused by a different space while the tag exists.)
/// Copyable interned identity of an [`AddrSpace`] registry handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpaceTag(NonZeroU32);

// RUDRA-GLUE: SPACE_TAG_TABLE (Ghidra's `base` is an architecture-owned
// pointer that needs no side table; Rust cannot store a pointer and stay
// `Copy`, so the tag resolves through this address.rs-owned table. The
// table is thread-local because the `AddrSpace` handle is an
// `Rc<RefCell<..>>` single-thread handle — SPACE-0001's documented
// residual — so tags, like the handles they came from, are thread-scoped:
// an `Address` carrying a tag must be compared, wrapped or printed on the
// thread whose spaces minted it. Phase-2 domain migrations inherit the
// existing one-Architecture-per-worker thread discipline.)
thread_local! {
    /// Slot + 1 = tag value; slot holds the strong space handle.
    static SPACE_TAG_TABLE: std::cell::RefCell<Vec<AddrSpace>> =
        std::cell::RefCell::new(Vec::new());
}

// RUDRA-GLUE: intern_space (no Ghidra counterpart; ADDRESS-0001 bridge)
/// Return the (stable, thread-scoped) tag for a space handle, interning it
/// on first sight. Two tags are equal iff they came from the same
/// `AddrSpace` allocation (Ghidra's pointer identity). The table holds a
/// strong handle so the space's allocation — and therefore its
/// `identity_ptr` — can never be reused by a different space while the
/// tag exists.
fn intern_space(spc: &AddrSpace) -> SpaceTag {
    let identity = spc.identity_ptr();
    SPACE_TAG_TABLE.with(|table| {
        let mut table = table.borrow_mut();
        for (slot, existing) in table.iter().enumerate() {
            if existing.identity_ptr() == identity {
                return SpaceTag(NonZeroU32::new(slot as u32 + 1).unwrap());
            }
        }
        table.push(spc.clone());
        SpaceTag(NonZeroU32::new(table.len() as u32).unwrap())
    })
}

// RUDRA-GLUE: resolve_space_tag (no Ghidra counterpart; ADDRESS-0001 bridge)
/// Resolve a tag back to its space handle. Panics for tags not issued on
/// this thread (see `SPACE_TAG_TABLE`'s thread-scope contract).
fn resolve_space_tag(tag: SpaceTag) -> AddrSpace {
    SPACE_TAG_TABLE.with(|table| {
        table
            .borrow()
            .get(tag.0.get() as usize - 1)
            .cloned()
            .expect("SpaceTag was not issued by intern_space on this thread")
    })
}

impl Address {
    /// Create a new address
    // RUDRA-GLUE: Scalar-address constructor; Ghidra also requires an AddrSpace, which this form omits (None = legacy spaceless).
    pub const fn new(addr: u64) -> Self {
        Address {
            offset: addr,
            space: None,
        }
    }

    // RUDRA-GLUE: with_space (ADDRESS-0001 phase-1 bridge; the Ghidra form is
    // the inline `Address(AddrSpace *id,uintb off)` at address.hh:270.)
    /// Create an address carrying a space handle, like Ghidra's basic
    /// `Address(AddrSpace*, uintb)` constructor. The space is interned into
    /// a copyable tag so `Address` stays `Copy`.
    pub fn with_space(spc: &AddrSpace, off: u64) -> Self {
        Address {
            offset: off,
            space: Some(intern_space(spc)),
        }
    }

    // RUDRA-GLUE: get_space (Ghidra's address.hh:323 returns the raw `base`
    // pointer, NULL if invalid; the tag table resolution is the Rust form.)
    /// The address space handle, or `None` for a legacy spaceless address
    /// (Ghidra's null `base`).
    pub fn get_space(&self) -> Option<AddrSpace> {
        self.space.map(resolve_space_tag)
    }

    // RUDRA-GLUE: from_space_address (ADDRESS-0001 phase-1 bridge between the
    // space-carrying `SpaceAddress` and this transitional type.)
    /// Cross the bridge from [`SpaceAddress`]: a real space becomes a tagged
    /// address, a null base becomes the legacy spaceless form. The
    /// `m_maximal` sentinel panics: the legacy type has no extremal form, and
    /// mapping it to `None` would flip its sort position from last to first.
    pub fn from_space_address(sa: &SpaceAddress) -> Self {
        match &sa.base {
            SpaceBase::Space(spc) => Address::with_space(spc, sa.offset),
            SpaceBase::Null => Address::new(sa.offset),
            SpaceBase::Maximal => panic!(
                "m_maximal sentinel cannot cross the legacy Address bridge (ADDRESS-0001)"
            ),
        }
    }

    // RUDRA-GLUE: to_space_address (ADDRESS-0001 phase-1 bridge; `None`
    // maps to `SpaceAddress::from_offset`'s null-base invalid form.)
    /// Cross the bridge to [`SpaceAddress`]: a tagged space carries over,
    /// `None` becomes the null-base (invalid) address with the same offset.
    pub fn to_space_address(&self) -> SpaceAddress {
        match self.space {
            Some(tag) => SpaceAddress::new(resolve_space_tag(tag), self.offset),
            None => SpaceAddress::from_offset(self.offset),
        }
    }

    /// Get the raw address value
    // Ghidra: address.hh:329 Address::getOffset
    pub const fn as_u64(&self) -> u64 {
        self.offset
    }

    // Ghidra: address.hh:423 Address::operator+(int8 off)
    /// Add an offset to the address. A tagged space wraps through the
    /// space's `wrapOffset` (address.hh:424); a legacy spaceless address
    /// plain-wraps (pre-phase-1 behavior).
    pub fn offset(&self, offset: i64) -> Self {
        let raw = self.offset.wrapping_add(offset as u64);
        Address {
            offset: match self.space.map(resolve_space_tag) {
                Some(spc) => spc.wrap_offset(raw),
                None => raw,
            },
            space: self.space,
        }
    }

    // Ghidra: address.cc:153 Address::overlap
    /// If `self + skip` falls in the range `[op, op+size)`, return the
    /// offset of `self+skip` relative to `op`. Otherwise return -1.
    /// Faithful to `Address::overlap` (address.cc:153-165) when both
    /// addresses carry spaces: same base pointer required, constants never
    /// overlap, distance wraps through the space. Legacy spaceless
    /// participants keep the pre-phase-1 offset-only behavior.
    pub fn overlap(&self, skip: i64, op: Address, size: i32) -> i32 {
        match (self.space, op.space) {
            (Some(a), Some(b)) => {
                if a != b {
                    return -1; // Must be in same address space to overlap
                }
                let spc = resolve_space_tag(a);
                if spc.get_type() == SpaceType::Constant {
                    return -1; // Must not be constants
                }
                let dist = spc.wrap_offset(
                    self.offset
                        .wrapping_add(skip as u64)
                        .wrapping_sub(op.offset),
                );
                if dist >= size as u64 {
                    return -1; // but must fall before op+size
                }
                dist as i32
            }
            _ => {
                let dist = self
                    .offset
                    .wrapping_add(skip as u64)
                    .wrapping_sub(op.offset);
                if dist >= size as u64 {
                    return -1;
                }
                dist as i32
            }
        }
    }

    // Ghidra: address.hh:285 Address::isInvalid
    /// Is this a Ghidra-invalid (null-`base`) address? For the legacy type
    /// that is exactly the spaceless form: every pre-phase-1 construction
    /// site mints Ghidra-invalid addresses, which is why `to_space_address`
    /// maps `None` to `SpaceAddress::from_offset` (the null-base form).
    pub fn is_invalid(&self) -> bool {
        self.space.is_none()
    }

    // Ghidra: address.cc:91 Address::isNull
    /// Check if address is null (0x0)
    pub fn is_null(&self) -> bool {
        self.offset == 0
    }

    // Ghidra: address.cc:91 Address::isAligned
    /// Check if address is aligned to the given boundary
    pub fn is_aligned(&self, alignment: u64) -> bool {
        self.offset % alignment == 0
    }

    // Ghidra: address.hh:423 Address::operator+(int8 off)
    /// Get the next address (`operator+(1)`; wraps through the space)
    pub fn next(&self) -> Self {
        self.offset(1)
    }

    // Ghidra: address.hh:433 Address::operator-(int8 off)
    /// Get the previous address (`operator-(1)`; wraps through the space)
    pub fn prev(&self) -> Self {
        self.offset(-1)
    }
}

// RUDRA-GLUE: PartialEq for Address (Ghidra compares the raw `base` pointers
// then offsets inline in address.hh:356-358; the intern tag is the pointer
// identity, and `None` — Ghidra's null base — equals only `None`.)
impl PartialEq for Address {
    // Ghidra: address.hh:356 Address::operator==
    fn eq(&self, other: &Self) -> bool {
        self.space == other.space && self.offset == other.offset
    }
}
impl Eq for Address {}

// RUDRA-GLUE: Ord for Address (Ghidra has operator< only, address.hh:375-393;
// Rust needs a total order for sorted containers, built from the same branch
// ladder.)
impl Ord for Address {
    // Ghidra: address.hh:375 Address::operator<
    /// Natural ordering (address.hh:368-393): space first, then offset.
    /// `None` (Ghidra's null base) sorts before every tagged space
    /// (address.hh:377); different tagged spaces order by index
    /// (address.hh:389); same space orders by offset (address.hh:391). The
    /// final tag tiebreak — unreachable inside one registry, where index and
    /// tag are bijective — keeps `Ord` consistent with `PartialEq` for the
    /// cross-registry test state of two distinct spaces sharing an index.
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.space, other.space) {
            (None, None) => self.offset.cmp(&other.offset),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => {
                if a != b {
                    let sa = resolve_space_tag(a);
                    let sb = resolve_space_tag(b);
                    return match sa.get_index().cmp(&sb.get_index()) {
                        Ordering::Equal => {
                            let by_offset = self.offset.cmp(&other.offset);
                            if by_offset != Ordering::Equal {
                                by_offset
                            } else {
                                a.0.cmp(&b.0)
                            }
                        }
                        order => order,
                    };
                }
                self.offset.cmp(&other.offset)
            }
        }
    }
}

impl PartialOrd for Address {
    // Ghidra: address.hh:398 Address::operator<=
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// RUDRA-GLUE: Hash for Address (Ghidra has no hash for Address; the key must
// agree with PartialEq: intern tag identity then offset.)
impl Hash for Address {
    // RUDRA-GLUE: fn hash — trait method required by Rust std Hash; delegates
    // to the space tag then offset, mirroring the PartialEq ordering above.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.space.hash(state);
        self.offset.hash(state);
    }
}

impl fmt::Display for Address {
    // Ghidra: address.cc:47 operator<<(ostream &s,const Address &addr)
    /// Debug/console form. A tagged space uses its `printRaw`
    /// (address.cc:50); the legacy spaceless form keeps the historical
    /// `0x{:x}` spelling so no existing output changes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.space.map(resolve_space_tag) {
            Some(spc) => write!(f, "{}", spc.print_raw(self.offset)),
            None => write!(f, "0x{:x}", self.offset),
        }
    }
}

impl fmt::LowerHex for Address {
    // Ghidra: address.cc:91 Address::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.offset)
    }
}

impl fmt::UpperHex for Address {
    // Ghidra: address.cc:91 Address::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self.offset)
    }
}

impl From<u64> for Address {
    // Ghidra: address.cc:91 Address::from
    fn from(addr: u64) -> Self {
        Address::new(addr)
    }
}

impl From<Address> for u64 {
    // Ghidra: address.cc:91 Address::from
    fn from(addr: Address) -> Self {
        addr.offset
    }
}

/// Sequence number for P-code operations within a single instruction
///
/// When a machine instruction translates to multiple P-code ops,
/// they are numbered sequentially using SeqNum.
///
/// Corresponds to Ghidra's `SeqNum` class in `address.hh`
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SeqNum {
    /// Address of the original machine instruction
    pub addr: Address,
    /// Immutable creation identity (`uniq` / `time` in Ghidra).
    pub time: u32,
    /// Mutable execution order within the containing basic block.
    pub order: u32,
}

impl SeqNum {
    // Ghidra: address.hh:130 SeqNum::SeqNum(const Address&,uintm)
    /// Create a sequence number with immutable `time` identity.
    ///
    /// Ghidra leaves `order` unset until block insertion. Rust initializes it
    /// to `time`, preserving deterministic pre-insertion behavior without
    /// conflating the fields after `set_order` is called.
    pub fn new(addr: Address, time: u32) -> Self {
        SeqNum {
            addr,
            time,
            order: time,
        }
    }

    // RUDRA-GLUE: convenience constructor for the next immutable creation id;
    // Ghidra increments PcodeOpBank::uniqid inline in op.cc:944.
    /// Get the next creation identity at the same address.
    pub fn next(&self) -> Self {
        SeqNum::new(self.addr, self.time + 1)
    }

    // Ghidra: address.hh:136 SeqNum::getAddr
    /// Get the address
    pub fn get_addr(&self) -> Address {
        self.addr
    }

    // Ghidra: address.hh:148 SeqNum::operator==
    /// Test Ghidra's time-only sequence identity.
    pub fn same_identity(&self, other: &Self) -> bool {
        self.time == other.time
    }

    // Ghidra: address.hh:139 SeqNum::getTime
    /// Get the immutable creation identity.
    pub fn get_time(&self) -> u32 {
        self.time
    }

    // Ghidra: address.hh:142 SeqNum::getOrder
    /// Get the mutable execution order within a basic block.
    pub fn get_order(&self) -> u32 {
        self.order
    }

    // Ghidra: address.hh:145 SeqNum::setOrder
    /// Set the execution order without changing this sequence's identity.
    pub fn set_order(&mut self, order: u32) {
        self.order = order;
    }

    // Ghidra: address.cc:69 SeqNum::decode
    /// Decode from string format "addr:order"
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        let addr = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).ok()?;
        let time = parts[1].parse().ok()?;
        Some(SeqNum::new(Address::new(addr), time))
    }

    // Ghidra: address.cc:60 SeqNum::encode
    /// Encode to string format "addr:order"
    pub fn encode(&self) -> String {
        format!("{}:{}", self.addr, self.time)
    }
}

impl PartialEq for SeqNum {
    // RUDRA-GLUE: Rust Eq must agree with Ord for BTree/Hash keys. Ghidra's
    // operator== is time-only; callers needing that semantic use
    // `same_identity`, while ordered keys use `(Address,time)` as operator<.
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.time == other.time
    }
}

impl Eq for SeqNum {}

impl PartialOrd for SeqNum {
    // Ghidra: address.hh:154 SeqNum::operator<
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeqNum {
    // Ghidra: address.hh:154 SeqNum::operator<
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.addr
            .cmp(&other.addr)
            .then_with(|| self.time.cmp(&other.time))
    }
}

impl Hash for SeqNum {
    // RUDRA-GLUE: Rust Hash must use the same immutable identity as Eq/Ord;
    // Ghidra's SeqNum keys are ordered by address.hh:154 operator<.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.time.hash(state);
    }
}

impl fmt::Display for SeqNum {
    // Ghidra: address.cc:32 operator<<(ostream&,const SeqNum&)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.time)
    }
}

/// Address range (inclusive first and last addresses)
///
/// Corresponds to Ghidra's `Range` class in `address.hh`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// First address in the range (inclusive)
    first: Address,
    /// Last address in the range (inclusive)
    last: Address,
}

impl Range {
    // Ghidra: address.cc:236 Range::new
    /// Create a new range
    ///
    /// Returns `None` if first > last
    pub fn new(first: Address, last: Address) -> Option<Self> {
        if first.as_u64() <= last.as_u64() {
            Some(Range { first, last })
        } else {
            None
        }
    }

    // Ghidra: address.cc:236 Range::getFirst
    /// Get the first address
    pub fn get_first(&self) -> Address {
        self.first
    }

    // Ghidra: address.cc:236 Range::getLast
    /// Get the last address
    pub fn get_last(&self) -> Address {
        self.last
    }

    // Ghidra: address.cc:236 Range::getFirstAddr
    /// Get the first address (Ghidra naming)
    pub fn get_first_addr(&self) -> Address {
        self.first
    }

    // Ghidra: address.cc:236 Range::getLastAddr
    /// Get the last address (Ghidra naming)
    pub fn get_last_addr(&self) -> Address {
        self.last
    }

    // Ghidra: address.cc:265 Range::getLastAddrOpen
    /// Get the last address + 1 (open end)
    pub fn get_last_addr_open(&self) -> Address {
        self.last.next()
    }

    // Ghidra: address.cc:236 Range::contains
    /// Check if an address is contained in this range
    pub fn contains(&self, addr: Address) -> bool {
        addr.as_u64() >= self.first.as_u64() && addr.as_u64() <= self.last.as_u64()
    }

    // Ghidra: address.cc:236 Range::size
    /// Get the size of the range in bytes
    pub fn size(&self) -> u64 {
        self.last.as_u64().saturating_sub(self.first.as_u64()).saturating_add(1)
    }

    // Ghidra: address.cc:236 Range::overlaps
    /// Check if this range overlaps with another
    pub fn overlaps(&self, other: &Range) -> bool {
        self.first.as_u64() <= other.last.as_u64()
            && other.first.as_u64() <= self.last.as_u64()
    }

    // Ghidra: address.cc:236 Range::isAdjacent
    /// Check if this range is adjacent to another
    pub fn is_adjacent(&self, other: &Range) -> bool {
        self.last.as_u64().saturating_add(1) == other.first.as_u64()
            || other.last.as_u64().saturating_add(1) == self.first.as_u64()
    }

    // Ghidra: address.cc:283 Range::printBounds
    /// Print bounds (for debugging)
    pub fn print_bounds(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.first, self.last)
    }

    // Ghidra: address.cc:304 Range::decode
    /// Decode from string format "first-last"
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return None;
        }
        let first = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).ok()?;
        let last = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).ok()?;
        Range::new(Address::new(first), Address::new(last))
    }

    // Ghidra: address.cc:316 Range::decodeFromAttributes
    /// Decode from attributes (XML-style)
    pub fn decode_from_attributes(first: &str, last: &str) -> Option<Self> {
        let first_addr = u64::from_str_radix(first.trim_start_matches("0x"), 16).ok()?;
        let last_addr = u64::from_str_radix(last.trim_start_matches("0x"), 16).ok()?;
        Range::new(Address::new(first_addr), Address::new(last_addr))
    }

    // Ghidra: address.cc:292 Range::encode
    /// Encode to string format "first-last"
    pub fn encode(&self) -> String {
        format!("{:x}-{:x}", self.first.as_u64(), self.last.as_u64())
    }
}

impl fmt::Display for Range {
    // Ghidra: address.cc:236 Range::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.print_bounds(f)
    }
}

/// Properties associated with a range
///
/// Corresponds to Ghidra's `RangeProperties` in address.hh
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeProperties {
    /// Name of the address space containing the range. For a register form,
    /// this temporarily holds the register name until an `AddrSpaceManager`
    /// is available.
    pub space_name: String,
    /// Offset of the first byte in the range.
    pub first: u64,
    /// Offset of the last byte in the range.
    pub last: u64,
    /// Whether a `name` attribute specified a register.
    pub is_register: bool,
    /// Whether the end of the range was explicitly specified.
    pub seen_last: bool,
}

impl RangeProperties {
    // Ghidra: address.hh:223 RangeProperties::RangeProperties(void)
    /// Construct empty, partially parsed range properties.
    pub fn new() -> Self {
        RangeProperties {
            space_name: String::new(),
            first: 0,
            last: 0,
            is_register: false,
            seen_last: false,
        }
    }

    // Ghidra: address.cc:354 RangeProperties::decode
    /// Decode a `<range>` or `<register>` element into this partial state.
    ///
    /// Fields are deliberately not reset before decoding. Recognized
    /// attributes mutate the object in source order, and an error does not
    /// roll back earlier mutations, matching Ghidra's in-place decode.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> anyhow::Result<()> {
        let elem_id = decoder.open_element();
        if elem_id != 12 && elem_id != 14 {
            anyhow::bail!("Expecting <range> or <register> element");
        }
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            if attrib_id == 20 {
                self.space_name = decoder.read_string();
            } else if attrib_id == 27 {
                self.first = decoder.read_unsigned_integer();
            } else if attrib_id == 28 {
                self.last = decoder.read_unsigned_integer();
                self.seen_last = true;
            } else if attrib_id == 14 {
                self.space_name = decoder.read_string();
                self.is_register = true;
            }
        }
        decoder.close_element(elem_id);
        Ok(())
    }
}

impl Default for RangeProperties {
    // Ghidra: address.hh:223 RangeProperties::RangeProperties(void)
    fn default() -> Self {
        RangeProperties::new()
    }
}

/// List of non-overlapping address ranges
///
/// Corresponds to Ghidra's `RangeList` class in `address.hh`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeList {
    /// Sorted list of non-overlapping ranges
    ranges: Vec<Range>,
}

impl RangeList {
    // Ghidra: address.hh:174 RangeList::new
    /// Create a new empty range list
    pub fn new() -> Self {
        RangeList { ranges: Vec::new() }
    }

    // Ghidra: address.cc:383 RangeList::insertRange
    /// Insert a range into the list, merging overlapping ranges
    pub fn insert_range(&mut self, new_range: Range) {
        if self.ranges.is_empty() {
            self.ranges.push(new_range);
            return;
        }

        let mut merged = new_range;
        let mut to_remove = Vec::new();

        for (i, existing) in self.ranges.iter().enumerate() {
            if merged.overlaps(existing) || merged.is_adjacent(existing) {
                // Merge the ranges
                let first = std::cmp::min(merged.first.as_u64(), existing.first.as_u64());
                let last = std::cmp::max(merged.last.as_u64(), existing.last.as_u64());
                merged = Range {
                    first: Address::new(first),
                    last: Address::new(last),
                };
                to_remove.push(i);
            }
        }

        // Remove merged ranges (in reverse order to maintain indices)
        for &i in to_remove.iter().rev() {
            self.ranges.remove(i);
        }

        // Insert merged range in sorted position
        let insert_pos = self.ranges
            .binary_search_by_key(&merged.first.as_u64(), |r| r.first.as_u64())
            .unwrap_or_else(|pos| pos);
        self.ranges.insert(insert_pos, merged);
    }

    // Ghidra: address.cc:417 RangeList::removeRange
    /// Remove a range from the list
    pub fn remove_range(&mut self, to_remove: Range) {
        let mut new_ranges = Vec::new();

        for existing in &self.ranges {
            if !existing.overlaps(&to_remove) {
                // No overlap, keep the range
                new_ranges.push(*existing);
            } else {
                // Handle partial overlap
                if existing.first.as_u64() < to_remove.first.as_u64() {
                    // Keep the part before the removed range
                    if let Some(range) = Range::new(
                        existing.first,
                        Address::new(to_remove.first.as_u64().saturating_sub(1))
                    ) {
                        new_ranges.push(range);
                    }
                }
                if existing.last.as_u64() > to_remove.last.as_u64() {
                    // Keep the part after the removed range
                    if let Some(range) = Range::new(
                        Address::new(to_remove.last.as_u64().saturating_add(1)),
                        existing.last
                    ) {
                        new_ranges.push(range);
                    }
                }
            }
        }

        self.ranges = new_ranges;
    }

    // Ghidra: address.cc:468 RangeList::inRange
    /// Check if an address is in any range in the list
    pub fn in_range(&self, addr: Address) -> bool {
        self.ranges.iter().any(|r| r.contains(addr))
    }

    // Ghidra: address.hh:174 RangeList::numRanges
    /// Get the number of ranges in the list
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    // Ghidra: address.hh:174 RangeList::empty
    /// Check if the list is empty
    pub fn empty(&self) -> bool {
        self.ranges.is_empty()
    }

    // Ghidra: address.hh:174 RangeList::ranges
    /// Get all ranges
    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }

    // Ghidra: address.hh:174 RangeList::begin
    /// Get iterator to beginning
    pub fn begin(&self) -> std::slice::Iter<'_, Range> {
        self.ranges.iter()
    }

    // Ghidra: address.hh:174 RangeList::end
    /// Get iterator to end
    pub fn end(&self) -> std::slice::Iter<'_, Range> {
        self.ranges.iter()
    }

    // Ghidra: address.cc:451 RangeList::merge
    /// Merge another RangeList into this one
    pub fn merge(&mut self, other: &RangeList) {
        for range in &other.ranges {
            self.insert_range(*range);
        }
    }

    // Ghidra: address.hh:174 RangeList::clear
    /// Clear all ranges
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    // Ghidra: address.cc:512 RangeList::longestFit
    /// Find the longest fit for an address
    pub fn longest_fit(&self, addr: Address) -> Option<&Range> {
        self.ranges.iter()
            .filter(|r| r.contains(addr))
            .max_by_key(|r| r.size())
    }

    // Ghidra: address.cc:588 RangeList::printBounds
    /// Print bounds of all ranges
    pub fn print_bounds(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, range) in self.ranges.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            range.print_bounds(f)?;
        }
        write!(f, "]")
    }

    // Ghidra: address.cc:618 RangeList::decode
    /// Decode from string format (comma-separated ranges)
    pub fn decode(s: &str) -> Option<Self> {
        let mut list = RangeList::new();
        if s.is_empty() {
            return Some(list);
        }
        for range_str in s.split(',') {
            let range = Range::decode(range_str.trim())?;
            list.insert_range(range);
        }
        Some(list)
    }

    // Ghidra: address.cc:604 RangeList::encode
    /// Encode to string format (comma-separated ranges)
    pub fn encode(&self) -> String {
        self.ranges
            .iter()
            .map(|r| r.encode())
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl Default for RangeList {
    // Ghidra: address.hh:174 RangeList::default
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RangeList {
    // Ghidra: address.hh:174 RangeList::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.print_bounds(f)
    }
}

// ============================================================================
// Space-aware Address/Range/RangeList (ADDRESS-0001)
// ----------------------------------------------------------------------------
// 1:1 port of Ghidra's `Address`/`Range`/`RangeList` (address.hh/address.cc)
// carrying a registry space handle, exactly like Ghidra's `AddrSpace *base`:
//   - an absent space (`base == None`) IS the invalid address
//     (address.hh:262-265, address.hh:285-287) — `ram:0` is NOT null;
//   - ordering is space identity first, then offset
//     (address.hh:375-393 `Address::operator<`), with the `m_minimal`/
//     `m_maximal` extremal sentinels (address.cc:91-102);
//   - offset arithmetic wraps through the real space's `wrapOffset`
//     (space.hh:383-391), so addrsize/wordsize come from the space;
//   - endianness-aware containment (`justifiedContain`, address.cc:131).
// The legacy `Address(u64)`/`Range`/`RangeList` above stay as the offset-only
// adapter for un-migrated consumers (varnode.rs/funcdata.rs switch in the
// VARNODE-0001/FUNCDATA waves). `SpaceAddress::from_offset` is the bridge.
// ============================================================================

// RUDRA-GLUE: SpaceBase (Ghidra stores a raw `AddrSpace *base` that is either
// null, the extremal pseudo-pointer `~((uintp)0)` from the m_maximal
// constructor, or a real space; Rust needs an explicit tagged enum because
// dereferencing a pseudo-pointer is not expressible safely.)
/// The `base` slot of a [`SpaceAddress`]: null (invalid), a real registry
/// space, or Ghidra's `m_maximal` sort sentinel.
#[derive(Clone, Debug)]
enum SpaceBase {
    /// Ghidra null `AddrSpace *` — the deliberately invalid address.
    Null,
    /// A real architecture-owned space handle.
    Space(AddrSpace),
    /// Ghidra's `(AddrSpace *)~((uintp)0)` m_maximal sentinel (address.cc:99).
    Maximal,
}

/// A low-level machine address: a space handle plus a byte offset.
///
/// Faithful to Ghidra's `Address` (address.hh:59): it represents an offset
/// only, never a length. The space handle supplies addrsize/wordsize/
/// endianness for wrapping, ordering and justified containment.
#[derive(Clone, Debug)]
pub struct SpaceAddress {
    /// Pointer to our address space (address.hh:61 `base`).
    base: SpaceBase,
    /// Offset in bytes (address.hh:62 `offset`).
    offset: u64,
}

impl SpaceAddress {
    // Ghidra: address.hh:263 Address::Address(void)
    /// Create an invalid address: `base` is null and, unlike C++ (which
    /// leaves `offset` indeterminate), the offset is normalized to 0 so that
    /// `invalid() == minimal()` bit-for-bit, exactly like the `m_minimal`
    /// constructor (address.cc:94-97).
    pub fn invalid() -> Self {
        SpaceAddress {
            base: SpaceBase::Null,
            offset: 0,
        }
    }

    // Ghidra: address.cc:91 Address::Address(mach_extreme ex)
    /// Initialize the `m_minimal` extremal address. Identical state to
    /// [`SpaceAddress::invalid`] (address.cc:94-97 sets base=null, offset=0).
    pub fn minimal() -> Self {
        SpaceAddress::invalid()
    }

    // Ghidra: address.cc:91 Address::Address(mach_extreme ex)
    /// Initialize the `m_maximal` extremal address (address.cc:99-101):
    /// the `~0` base sentinel with offset `~0`. Sorts after every real
    /// address; only a sentinel, never printed or dereferenced.
    pub fn maximal() -> Self {
        SpaceAddress {
            base: SpaceBase::Maximal,
            offset: u64::MAX,
        }
    }

    // Ghidra: address.hh:270 Address::Address(AddrSpace *id,uintb off)
    /// The basic constructor: a space handle and a byte offset.
    pub fn new(spc: AddrSpace, off: u64) -> Self {
        SpaceAddress {
            base: SpaceBase::Space(spc),
            offset: off,
        }
    }

    // RUDRA-GLUE: from_offset (bridge for the legacy offset-only `Address`;
    // Ghidra has no offset-without-space address — this is deliberately an
    /// invalid address per address.hh:285.)
    /// Wrap a bare legacy offset. The result carries no space, so
    /// `is_invalid()` is `true`: a bare `0x1000` is not `ram:0x1000`.
    pub fn from_offset(off: u64) -> Self {
        SpaceAddress {
            base: SpaceBase::Null,
            offset: off,
        }
    }

    // RUDRA-GLUE: same_base (Ghidra compares the raw `base` pointers inline
    // in operator==/containedBy/justifiedContain/overlap/isContiguous.)
    /// Pointer-identity test of the two `base` slots (both null counts as
    /// equal, mirroring C++ null == null).
    fn same_base(&self, op2: &SpaceAddress) -> bool {
        match (&self.base, &op2.base) {
            (SpaceBase::Null, SpaceBase::Null) => true,
            (SpaceBase::Maximal, SpaceBase::Maximal) => true,
            (SpaceBase::Space(a), SpaceBase::Space(b)) => a == b,
            _ => false,
        }
    }

    // Ghidra: address.hh:285 Address::isInvalid
    /// Is the address invalid? True exactly when the base slot is null
    /// (address.hh:286). The `m_maximal` sentinel is NOT invalid, matching
    /// Ghidra's null-only test.
    pub fn is_invalid(&self) -> bool {
        matches!(self.base, SpaceBase::Null)
    }

    // Ghidra: address.hh:292 Address::getAddrSize
    /// Number of bytes needed to encode the offset, taken from the space.
    /// Panics on an invalid/maximal address (Ghidra dereferences null).
    pub fn get_addr_size(&self) -> u32 {
        self.expect_space("getAddrSize").get_addr_size()
    }

    // Ghidra: address.hh:298 Address::isBigEndian
    /// Is data at this address big-endian encoded, per the space.
    /// Returns false on invalid/maximal addresses (Ghidra dereferences null).
    pub fn is_big_endian(&self) -> bool {
        match &self.base {
            SpaceBase::Space(spc) => spc.is_big_endian(),
            _ => false,
        }
    }

    // Ghidra: address.hh:305 Address::printRaw
    /// Short-hand/debug form: `invalid_addr` for an invalid address,
    /// otherwise the space's `printRaw` (space.cc:206).
    pub fn print_raw(&self) -> String {
        if self.is_invalid() {
            return "invalid_addr".to_string();
        }
        match &self.base {
            SpaceBase::Space(spc) => spc.print_raw(self.offset),
            // Ghidra would dereference the ~0 pseudo-pointer here (UB); the
            // maximal address is a sort sentinel, never printed.
            SpaceBase::Maximal => "invalid_addr".to_string(),
            SpaceBase::Null => unreachable!("is_invalid covers Null"),
        }
    }

    // Ghidra: address.hh:323 Address::getSpace
    /// The address space handle, or `None` if invalid. Also `None` for the
    /// `m_maximal` sentinel: Ghidra returns the ~0 pseudo-pointer that may
    /// only feed `operator<`, never be dereferenced.
    pub fn get_space(&self) -> Option<&AddrSpace> {
        match &self.base {
            SpaceBase::Space(spc) => Some(spc),
            _ => None,
        }
    }

    // Ghidra: address.hh:329 Address::getOffset
    /// The offset as an integer.
    pub fn get_offset(&self) -> u64 {
        self.offset
    }

    // Ghidra: address.hh:336 Address::getShortcut
    /// The space's shortcut character for read/printRaw.
    pub fn get_shortcut(&self) -> char {
        self.expect_space("getShortcut").get_shortcut()
    }

    // Ghidra: address.hh:423 Address::operator+(int8 off)
    /// Add bytes to the offset, wrapping through the space's `wrapOffset`
    /// (space.hh:383). On invalid/maximal addresses Ghidra dereferences a
    /// non-space; Rugra defensively plain-wraps the offset.
    pub fn add(&self, off: i64) -> Self {
        let offset = self.offset.wrapping_add(off as u64);
        SpaceAddress {
            base: self.base.clone(),
            offset: match &self.base {
                SpaceBase::Space(spc) => spc.wrap_offset(offset),
                _ => offset,
            },
        }
    }

    // Ghidra: address.hh:433 Address::operator-(int8 off)
    /// Subtract bytes from the offset, wrapping through the space's
    /// `wrapOffset`. Same invalid-state caveat as [`SpaceAddress::add`].
    pub fn sub(&self, off: i64) -> Self {
        let offset = self.offset.wrapping_sub(off as u64);
        SpaceAddress {
            base: self.base.clone(),
            offset: match &self.base {
                SpaceBase::Space(spc) => spc.wrap_offset(offset),
                _ => offset,
            },
        }
    }

    // Ghidra: address.hh:455 Address::isConstant
    /// Is this address in the constant space?
    pub fn is_constant(&self) -> bool {
        match &self.base {
            SpaceBase::Space(spc) => spc.get_type() == SpaceType::Constant,
            _ => false,
        }
    }

    // Ghidra: address.hh:461 Address::isJoin
    /// Is this address in the join space?
    pub fn is_join(&self) -> bool {
        match &self.base {
            SpaceBase::Space(spc) => spc.get_type() == SpaceType::Join,
            _ => false,
        }
    }

    // Ghidra: address.cc:110 Address::containedBy
    /// Is the `(self, sz)` byte range contained by the `(op2, sz2)` range?
    /// Faithful to address.cc:110-118: same base pointer required, then
    /// unsigned compare of the closed-range end offsets (uintb arithmetic).
    pub fn contained_by(&self, sz: i32, op2: &SpaceAddress, sz2: i32) -> bool {
        if !self.same_base(op2) {
            return false;
        }
        if op2.offset > self.offset {
            return false;
        }
        let off1 = self.offset.wrapping_add((sz - 1) as u64);
        let off2 = op2.offset.wrapping_add((sz2 - 1) as u64);
        off2 >= off1
    }

    // Ghidra: address.cc:131 Address::justifiedContain
    /// Endian-aware containment of `(op2, sz2)` inside `(self, sz)`.
    /// Faithful to address.cc:131-142: -1 unless properly contained; for a
    /// big-endian space (without `forceleft`) the result counts from the
    /// most-significant (highest) byte, i.e. `off1 - off2`; little-endian
    /// counts from the lowest byte. The uintb differences are truncated
    /// through an int4 cast exactly like C++.
    pub fn justified_contain(&self, sz: i32, op2: &SpaceAddress, sz2: i32, forceleft: bool) -> i32 {
        if !self.same_base(op2) {
            return -1;
        }
        if op2.offset < self.offset {
            return -1;
        }
        let off1 = self.offset.wrapping_add((sz - 1) as u64);
        let off2 = op2.offset.wrapping_add((sz2 - 1) as u64);
        if off2 > off1 {
            return -1;
        }
        if self.is_big_endian() && !forceleft {
            return ((off1.wrapping_sub(off2)) & 0xffff_ffff) as u32 as i32;
        }
        ((op2.offset.wrapping_sub(self.offset)) & 0xffff_ffff) as u32 as i32
    }

    // Ghidra: address.cc:153 Address::overlap
    /// If `self + skip` falls in `[op, op+size)`, return where in the
    /// interval it falls, else -1. Faithful to address.cc:153-165: same base
    /// pointer required, constants never overlap, and the distance is
    /// computed through the space's `wrapOffset` so it can wrap.
    pub fn overlap(&self, skip: i64, op: &SpaceAddress, size: i32) -> i32 {
        let spc = match (&self.base, &op.base) {
            (SpaceBase::Space(a), SpaceBase::Space(b)) if a == b => a,
            _ => return -1, // Must be in same address space to overlap
        };
        if spc.get_type() == SpaceType::Constant {
            return -1; // Must not be constants
        }
        let dist = spc.wrap_offset(
            self.offset
                .wrapping_add(skip as u64)
                .wrapping_sub(op.offset),
        );
        if dist >= size as u64 {
            return -1; // but must fall before op+size
        }
        dist as u32 as i32
    }

    // Ghidra: address.hh:445 Address::overlapJoin
    /// Like [`SpaceAddress::overlap`], but a join-space `op` range can be
    /// considered overlapped by its constituent pieces: dispatches to the
    /// space's `overlapJoin` (space.cc:126).
    pub fn overlap_join(&self, skip: i64, op: &SpaceAddress, size: i32) -> i32 {
        let Some(op_space) = op.get_space() else {
            // Ghidra dereferences op's base unconditionally; invalid/maximal
            // op addresses have no defined behavior there.
            return -1;
        };
        let Some(point_space) = self.get_space() else {
            return -1;
        };
        op_space.overlap_join(op.offset, size, point_space, self.offset, skip)
    }

    // Ghidra: address.cc:173 Address::isContiguous
    /// Does `(self, sz)` form a contiguous region with `(loaddr, losz)`,
    /// where `self` is the most significant piece? Faithful to
    /// address.cc:173-186: big-endian checks `wrap(self + sz) == loaddr`,
    /// little-endian checks `wrap(loaddr + losz) == self`.
    pub fn is_contiguous(&self, sz: i32, loaddr: &SpaceAddress, losz: i32) -> bool {
        if !self.same_base(loaddr) {
            return false;
        }
        let Some(spc) = self.get_space() else {
            return false;
        };
        if spc.is_big_endian() {
            let nextoff = spc.wrap_offset(self.offset.wrapping_add(sz as u64));
            if nextoff == loaddr.offset {
                return true;
            }
        } else {
            let nextoff = spc
                .wrap_offset(loaddr.offset.wrapping_add(losz as u64));
            if nextoff == self.offset {
                return true;
            }
        }
        false
    }

    // RUDRA-GLUE: expect_space (Ghidra's inline accessors dereference `base`
    // directly; Rust returns a clear error instead of null-dereferencing.)
    /// Borrow the real space or panic like Ghidra's null dereference.
    fn expect_space(&self, what: &str) -> &AddrSpace {
        match &self.base {
            SpaceBase::Space(spc) => spc,
            _ => panic!("Address::{} on an invalid or extremal address", what),
        }
    }

    // Ghidra: address.hh:469 Address::encode
    /// Save an `<addr>` element corresponding to this address: open the
    /// element, and for a non-null base let the space's `encodeAttributes`
    /// (space.cc:143) write the attributes, exactly like address.hh:469-474.
    /// A null base writes no attributes; the `m_maximal` sentinel (whose C++
    /// form would dereference the `~0` pseudo-pointer) also writes none.
    pub fn encode(&self, encoder: &mut dyn crate::marshal::Encoder) {
        encoder.open_element(&elem_addr());
        if let Some(spc) = self.get_space() {
            spc.encode_attributes(encoder, self.offset);
        }
        encoder.close_element(&elem_addr());
    }

    // Ghidra: address.hh:481 Address::encode (with size)
    /// Save an `<addr>` element with an extra `size` attribute
    /// (address.hh:481-486), routing through the space's 3-argument
    /// `encodeAttributes` (space.cc:156).
    pub fn encode_with_size(&self, encoder: &mut dyn crate::marshal::Encoder, size: i32) {
        encoder.open_element(&elem_addr());
        if let Some(spc) = self.get_space() {
            spc.encode_attributes_with_size(encoder, self.offset, size);
        }
        encoder.close_element(&elem_addr());
    }

    // Ghidra: address.cc:205 Address::decode
    /// Decode an address from an open element. Faithful to the C++ route
    /// (`Address::decode` → `VarnodeData::decode` → `decodeFromAttributes`,
    /// address.cc:205-212/pcoderaw.cc:100-130): the attribute walk looks for
    /// `space`; once seen the value resolves through the registry by name
    /// (XmlDecode::readSpace's `getSpaceByName`, marshal.cc:401-409 — an
    /// unknown name is `DecoderError("Unknown address space name: <nm>")`,
    /// an `Err` here), the attributes are rewound, and the space's
    /// `decodeAttributes` (space.cc:169) re-walks them for the offset
    /// (`LowlevelError("Address is missing offset")` as an `Err`). A
    /// `name` attribute (register form) needs the Translate register table
    /// and fails explicitly. An element with no `space` attribute yields the
    /// invalid address (Ghidra leaves the null base; Rust also normalizes
    /// the never-written offset to 0).
    pub fn decode(
        decoder: &mut dyn crate::marshal::Decoder,
        registry: &SpaceRegistry,
    ) -> Result<SpaceAddress, String> {
        let mut size = 0u32;
        SpaceAddress::decode_with_size(decoder, registry, &mut size)
    }

    // Ghidra: address.cc:226 Address::decode (with size)
    /// Decode an address and size from an open element
    /// (address.cc:226-234): identical to [`SpaceAddress::decode`] with the
    /// recovered size written through `size`.
    pub fn decode_with_size(
        decoder: &mut dyn crate::marshal::Decoder,
        registry: &SpaceRegistry,
        size: &mut u32,
    ) -> Result<SpaceAddress, String> {
        let elem_id = decoder.open_element();
        // VarnodeData::decodeFromAttributes (pcoderaw.cc:33; rewind :44,
        // re-walk :45): space starts null, size starts 0.
        let mut space: Option<AddrSpace> = None;
        let mut offset: u64 = 0;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break; // Its possible to have no attributes in an <addr/> tag
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("space") => {
                    // space = decoder.readSpace(); — name lookup via the
                    // manager (marshal.cc:401-409).
                    let nm = decoder.read_string();
                    let Some(spc) = registry.get_space_by_name(&nm) else {
                        return Err(format!("Unknown address space name: {}", nm));
                    };
                    // decoder.rewindAttributes();
                    decoder.rewind_attributes();
                    // offset = space->decodeAttributes(decoder,size);
                    offset = spc.decode_attributes(decoder, registry, size)?;
                    space = Some(spc);
                    break;
                }
                Some("name") => {
                    // ATTRIB_NAME resolves through
                    // Translate::getRegister (pcoderaw.cc:122-127); the
                    // register table is a SPACE-0001 residual.
                    return Err(
                        "register-name address decode requires the Translate register table"
                            .to_string(),
                    );
                }
                _ => {
                    // Unmatched attributes are skipped without reading
                    // their values (the C++ loop only advances the cursor).
                    let _ = decoder.read_string();
                }
            }
        }
        decoder.close_element(elem_id);
        match space {
            Some(spc) => Ok(SpaceAddress::new(spc, offset)),
            None => Ok(SpaceAddress::invalid()),
        }
    }
}

// RUDRA-GLUE: PartialEq for SpaceAddress (Ghidra compares `base` pointers
// then offsets inline in address.hh:356-358.)
impl PartialEq for SpaceAddress {
    // Ghidra: address.hh:356 Address::operator==
    fn eq(&self, other: &Self) -> bool {
        self.same_base(other) && self.offset == other.offset
    }
}
impl Eq for SpaceAddress {}

// RUDRA-GLUE: Ord for SpaceAddress (Ghidra has operator< and operator<= only;
// Rust needs a total order for sorted containers, built from the same
// branch ladder as address.hh:375-393.)
impl Ord for SpaceAddress {
    // Ghidra: address.hh:375 Address::operator<
    /// Natural ordering: space first, then offset. Addresses in the same
    /// space compare by offset; addresses in different spaces compare by
    /// space index, with the null base sorting before everything and the
    /// `m_maximal` sentinel after everything.
    fn cmp(&self, other: &Self) -> Ordering {
        if !self.same_base(other) {
            // address.hh:377-388 sentinel ladder.
            if self.is_invalid() {
                return Ordering::Less;
            } else if matches!(self.base, SpaceBase::Maximal) {
                return Ordering::Greater;
            } else if other.is_invalid() {
                return Ordering::Greater;
            } else if matches!(other.base, SpaceBase::Maximal) {
                return Ordering::Less;
            }
            // address.hh:389: different real spaces order by index. A same
            // index tie is impossible inside one registry; the Rc identity
            // tiebreak keeps Ord consistent with PartialEq if two distinct
            // space objects ever shared an index.
            let a = self.expect_space("operator<");
            let b = other.expect_space("operator<");
            return match a.get_index().cmp(&b.get_index()) {
                Ordering::Equal => a.identity_ptr().cmp(&b.identity_ptr()),
                order => order,
            };
        }
        // address.hh:391: same base (or both invalid/extremal) — by offset.
        self.offset.cmp(&other.offset)
    }
}

impl PartialOrd for SpaceAddress {
    // Ghidra: address.hh:398 Address::operator<=
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// RUDRA-GLUE: Hash for SpaceAddress (Ghidra has no hash; the handle-based
// identity must agree with PartialEq: base identity then offset.)
impl Hash for SpaceAddress {
    // RUDRA-GLUE: hash (Ghidra has no Hash for Address; consistent with
    // operator== so hash containers key the same pairs.)
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.base {
            SpaceBase::Null => 0u8.hash(state),
            SpaceBase::Maximal => 2u8.hash(state),
            SpaceBase::Space(spc) => {
                1u8.hash(state);
                spc.hash(state);
            }
        }
        self.offset.hash(state);
    }
}

impl fmt::Display for SpaceAddress {
    // Ghidra: address.cc:47 operator<<(ostream &s,const Address &addr)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.print_raw())
    }
}

/// A contiguous range of bytes in one address space.
///
/// Faithful to Ghidra's `Range` (address.hh:173): a space, the offset of the
/// first byte, and the offset of the last byte. Offsets are in bytes.
#[derive(Clone, Debug)]
pub struct SpaceRange {
    /// Space containing the range (address.hh:175 `spc`).
    spc: AddrSpace,
    /// Offset of the first byte (address.hh:176 `first`).
    first: u64,
    /// Offset of the last byte (address.hh:177 `last`).
    last: u64,
}

impl SpaceRange {
    // Ghidra: address.hh:185 Range::Range(AddrSpace *s,uintb f,uintb l)
    /// Construct a range from byte offsets. Like Ghidra's inline constructor
    /// this performs no validation; callers that need checks use
    /// [`SpaceRange::from_properties`].
    pub fn new(spc: AddrSpace, first: u64, last: u64) -> Self {
        SpaceRange { spc, first, last }
    }

    // Ghidra: address.cc:236 Range::Range(const RangeProperties &properties,const AddrSpaceManager *manage)
    /// Construct a range out of partially parsed properties. Faithful to the
    /// non-register path of address.cc:236-260: the space is looked up by
    /// name (`Undefined space: <name>` otherwise), a missing `last` becomes
    /// the space's `getHighest`, and any of `first > highest`,
    /// `last > highest`, `last < first` throws `Illegal range tag`.
    /// Ghidra's unreachable second null-check (address.cc:251-252) is dead
    /// code after the lookup and is not ported.
    pub fn from_properties(
        properties: &RangeProperties,
        manage: &SpaceRegistry,
    ) -> Result<Self, String> {
        if properties.is_register {
            // address.cc:239-246 resolves register names through
            // Translate::getRegister; the register table is a SPACE-0001
            // residual, so this state fails explicitly instead of guessing.
            return Err(format!(
                "register-name range requires the Translate register table: {}",
                properties.space_name
            ));
        }
        let Some(spc) = manage.get_space_by_name(&properties.space_name) else {
            return Err(format!("Undefined space: {}", properties.space_name));
        };
        let mut first = properties.first;
        let mut last = properties.last;
        if !properties.seen_last {
            last = spc.get_highest();
        }
        if first > spc.get_highest() || last > spc.get_highest() || last < first {
            return Err("Illegal range tag".to_string());
        }
        Ok(SpaceRange { spc, first, last })
    }

    // Ghidra: address.hh:189 Range::getSpace
    /// The address space containing this range.
    pub fn get_space(&self) -> &AddrSpace {
        &self.spc
    }

    // Ghidra: address.hh:190 Range::getFirst
    /// The offset of the first byte.
    pub fn get_first(&self) -> u64 {
        self.first
    }

    // Ghidra: address.hh:191 Range::getLast
    /// The offset of the last byte.
    pub fn get_last(&self) -> u64 {
        self.last
    }

    // Ghidra: address.hh:192 Range::getFirstAddr
    /// The address of the first byte.
    pub fn get_first_addr(&self) -> SpaceAddress {
        SpaceAddress::new(self.spc.clone(), self.first)
    }

    // Ghidra: address.hh:193 Range::getLastAddr
    /// The address of the last byte.
    pub fn get_last_addr(&self) -> SpaceAddress {
        SpaceAddress::new(self.spc.clone(), self.last)
    }

    // Ghidra: address.cc:265 Range::getLastAddrOpen
    /// The last address +1, updating the space: a `last` at the space's
    /// highest offset moves to offset 0 of the next space in order.
    /// Faithful to address.cc:265-279 INCLUDING its quirk: past the final
    /// space, `getNextSpaceInOrder` returns the `~0` sentinel
    /// (translate.cc:665) while this routine only checks for null, so the
    /// result is a maximal-sentinel-base address with offset 0 — NOT
    /// `Address(m_maximal)` (whose offset is `~0`). The quirk is observable
    /// through `operator==`/`operator<` and is reproduced exactly.
    pub fn get_last_addr_open(&self, manage: &SpaceRegistry) -> SpaceAddress {
        let mut curspc = self.spc.clone();
        let mut curlast = self.last;
        if curlast == curspc.get_highest() {
            match manage.get_next_space_in_order(Some(curspc.clone())) {
                Some(next) => {
                    curspc = next;
                    curlast = 0;
                }
                None => {
                    return SpaceAddress {
                        base: SpaceBase::Maximal,
                        offset: 0,
                    };
                }
            }
        } else {
            curlast += 1;
        }
        SpaceAddress::new(curspc, curlast)
    }

    // Ghidra: address.hh:490 Range::contains
    /// Is the address in this range? Faithful to address.hh:490-495: the
    /// space must be the identical object (an invalid address, whose space is
    /// null, is never contained), then `first <= offset <= last`.
    pub fn contains(&self, addr: &SpaceAddress) -> bool {
        let Some(addr_space) = addr.get_space() else {
            return false; // null space cannot equal this range's space
        };
        if self.spc != *addr_space {
            return false;
        }
        if self.first > addr.offset {
            return false;
        }
        if self.last < addr.offset {
            return false;
        }
        true
    }

    // Ghidra: address.cc:283 Range::printBounds
    /// Print like `ram: 7f-9c`.
    pub fn print_bounds(&self) -> String {
        format!("{}: {:x}-{:x}", self.spc.get_name(), self.first, self.last)
    }
}

// RUDRA-GLUE: PartialEq/Ord for SpaceRange (Ghidra sorts Ranges with
// operator< only, address.hh:202-205; std::set dedups on it, so Rust models
// equality as order-equivalence: same space index and same first offset.)
impl PartialEq for SpaceRange {
    // Ghidra: address.hh:202 Range::operator<
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for SpaceRange {}

impl Ord for SpaceRange {
    // Ghidra: address.hh:202 Range::operator<
    /// Compare on address space index, then the starting offset. The Rc
    /// identity tiebreak keeps Ord consistent with PartialEq for the
    /// impossible same-index-distinct-space state.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.spc.get_index().cmp(&other.spc.get_index()) {
            Ordering::Equal => self.first.cmp(&other.first).then_with(|| {
                self.spc.identity_ptr().cmp(&other.spc.identity_ptr())
            }),
            order => order,
        }
    }
}

impl PartialOrd for SpaceRange {
    // Ghidra: address.hh:202 Range::operator<
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A disjoint set of ranges, possibly across multiple address spaces.
///
/// Faithful to Ghidra's `RangeList` (address.hh:232): a sorted set of
/// `Range` objects (space index, then first offset). Inserting merges
/// strictly overlapping ranges of the same space; adjacent-but-disjoint
/// ranges stay separate, and ranges never merge across spaces.
#[derive(Clone, Debug, Default)]
pub struct SpaceRangeList {
    /// The sorted range objects (address.hh:233 `set<Range> tree`).
    tree: Vec<SpaceRange>,
}

impl SpaceRangeList {
    // Ghidra: address.hh:236 RangeList::RangeList(void)
    /// Construct an empty container.
    pub fn new() -> Self {
        SpaceRangeList { tree: Vec::new() }
    }

    // Ghidra: address.hh:237 RangeList::clear
    /// Clear to empty.
    pub fn clear(&mut self) {
        self.tree.clear();
    }

    // Ghidra: address.hh:238 RangeList::empty
    /// True if empty.
    pub fn empty(&self) -> bool {
        self.tree.is_empty()
    }

    // Ghidra: address.hh:241 RangeList::numRanges
    /// The number of Range objects in the container.
    pub fn num_ranges(&self) -> usize {
        self.tree.len()
    }

    // Ghidra: address.hh:239 RangeList::begin
    /// Iterate the ranges in sorted order (space index, then first).
    pub fn ranges(&self) -> &[SpaceRange] {
        &self.tree
    }

    // Ghidra: address.cc:540 RangeList::getFirstRange
    /// The first contiguous range, or None if empty.
    pub fn get_first_range(&self) -> Option<&SpaceRange> {
        self.tree.first()
    }

    // Ghidra: address.cc:548 RangeList::getLastRange
    /// The last contiguous range, or None if empty.
    pub fn get_last_range(&self) -> Option<&SpaceRange> {
        self.tree.last()
    }

    // RUDRA-GLUE: upper_bound_pos (Ghidra uses std::set::upper_bound on
    // Range(spc,off,off); Rust binary-searches the sorted Vec by the same
    // (index, first) key.)
    /// Index of the first range strictly greater than `Range(spc, off, off)`.
    fn upper_bound_pos(&self, spc: &AddrSpace, off: u64) -> usize {
        let mut lo = 0usize;
        let mut hi = self.tree.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let candidate = &self.tree[mid];
            let greater = match candidate
                .spc
                .get_index()
                .cmp(&spc.get_index())
            {
                Ordering::Greater => true,
                Ordering::Equal => candidate.first > off,
                Ordering::Less => false,
            };
            if greater {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    }

    // RUDRA-GLUE: insert_sorted (Ghidra's tree.insert keeps the existing
    // element for an equivalent key; the Vec insert mirrors that no-op.)
    /// Insert keeping (index, first) sort order; an equivalent key leaves
    /// the existing range in place, exactly like std::set::insert.
    fn insert_sorted(&mut self, range: SpaceRange) {
        let mut lo = 0usize;
        let mut hi = self.tree.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.tree[mid].cmp(&range) {
                Ordering::Less => lo = mid + 1,
                Ordering::Greater => hi = mid,
                Ordering::Equal => return, // std::set keeps the existing node
            }
        }
        self.tree.insert(lo, range);
    }

    // Ghidra: address.cc:383 RangeList::insertRange
    /// Insert a range, merging as appropriate to maintain the disjoint
    /// cover. Faithful to address.cc:383-410: iter1 back-steps to the first
    /// range with `last >= first` in the same space, iter2 stops at the
    /// first range with `first > last`, and everything between is folded
    /// into the new range. Ranges that merely touch (adjacent, disjoint)
    /// are NOT merged, and ranges in other spaces are never touched.
    pub fn insert_range(&mut self, spc: &AddrSpace, first: u64, last: u64) {
        let mut iter1 = self.upper_bound_pos(spc, first);
        if iter1 > 0 {
            iter1 -= 1;
            let prev = &self.tree[iter1];
            if prev.spc != *spc || prev.last < first {
                iter1 += 1;
            }
        }
        let iter2 = self.upper_bound_pos(spc, last);
        let (mut first, mut last) = (first, last);
        for existing in &self.tree[iter1..iter2] {
            if existing.first < first {
                first = existing.first;
            }
            if existing.last > last {
                last = existing.last;
            }
        }
        self.tree.drain(iter1..iter2);
        self.insert_sorted(SpaceRange::new(spc.clone(), first, last));
    }

    // Ghidra: address.cc:417 RangeList::removeRange
    /// Remove/narrow/split existing ranges to eliminate the indicated
    /// addresses while maintaining the disjoint cover. Faithful to
    /// address.cc:417-449: every range overlapping `[first, last]` in the
    /// given space is erased and its out-of-hole head/tail pieces are
    /// re-inserted.
    pub fn remove_range(&mut self, spc: &AddrSpace, first: u64, last: u64) {
        if self.tree.is_empty() {
            return; // Nothing to do
        }
        let mut iter1 = self.upper_bound_pos(spc, first);
        if iter1 > 0 {
            iter1 -= 1;
            let prev = &self.tree[iter1];
            if prev.spc != *spc || prev.last < first {
                iter1 += 1;
            }
        }
        let iter2 = self.upper_bound_pos(spc, last);
        let pieces: Vec<(u64, u64)> = self.tree[iter1..iter2]
            .iter()
            .map(|range| (range.first, range.last))
            .collect();
        self.tree.drain(iter1..iter2);
        for (a, b) in pieces {
            if a < first {
                self.insert_sorted(SpaceRange::new(spc.clone(), a, first.wrapping_sub(1)));
            }
            if b > last {
                self.insert_sorted(SpaceRange::new(spc.clone(), last.wrapping_add(1), b));
            }
        }
    }

    // Ghidra: address.cc:451 RangeList::merge
    /// Merge another range list into this one: each range of `op2`, in
    /// sorted order, goes through `insertRange`.
    pub fn merge(&mut self, op2: &SpaceRangeList) {
        for range in &op2.tree {
            self.insert_range(&range.spc, range.first, range.last);
        }
    }

    // Ghidra: address.cc:468 RangeList::inRange
    /// Is the indicated address range fully contained? Faithful to
    /// address.cc:468-487: an invalid address returns true ("we don't really
    /// care"), an empty container returns false, otherwise the last range
    /// whose `first <= offset` must be in the same space and reach
    /// `offset + size - 1`.
    pub fn in_range(&self, addr: &SpaceAddress, size: i32) -> bool {
        if addr.is_invalid() {
            return true; // We don't really care
        }
        if self.tree.is_empty() {
            return false;
        }
        let Some(spaceid) = addr.get_space() else {
            return false; // m_maximal sentinel: no Ghidra-defined behavior
        };
        let iter = self.upper_bound_pos(spaceid, addr.offset);
        if iter == 0 {
            return false;
        }
        let candidate = &self.tree[iter - 1];
        if candidate.spc != *spaceid {
            return false;
        }
        candidate.last >= addr.offset.wrapping_add((size - 1) as u64)
    }

    // Ghidra: address.cc:491 RangeList::getRange
    /// The range containing `(spaceid, offset)`, or None.
    pub fn get_range(&self, spaceid: &AddrSpace, offset: u64) -> Option<&SpaceRange> {
        if self.tree.is_empty() {
            return None;
        }
        let iter = self.upper_bound_pos(spaceid, offset);
        if iter == 0 {
            return None;
        }
        let candidate = &self.tree[iter - 1];
        if candidate.spc != *spaceid {
            return None;
        }
        if candidate.last >= offset {
            return Some(candidate);
        }
        None
    }

    // Ghidra: address.cc:512 RangeList::longestFit
    /// Size of the biggest contiguous sequence of addresses in this list
    /// containing the given address, chaining across adjacent ranges of the
    /// same space, stopping at `maxsize`. Faithful to address.cc:512-537.
    pub fn longest_fit(&self, addr: &SpaceAddress, maxsize: u64) -> u64 {
        if addr.is_invalid() {
            return 0;
        }
        if self.tree.is_empty() {
            return 0;
        }
        let Some(spaceid) = addr.get_space() else {
            return 0;
        };
        let mut offset = addr.offset;
        let mut iter = self.upper_bound_pos(spaceid, offset);
        if iter == 0 {
            return 0;
        }
        iter -= 1;
        let mut sizeres: u64 = 0;
        if self.tree[iter].last < offset {
            return sizeres;
        }
        loop {
            let candidate = &self.tree[iter];
            if candidate.spc != *spaceid {
                break;
            }
            if candidate.first > offset {
                break;
            }
            sizeres = sizeres
                .wrapping_add(candidate.last.wrapping_add(1).wrapping_sub(offset));
            offset = candidate.last.wrapping_add(1); // Try to chain on the next range
            if sizeres >= maxsize {
                break; // Don't bother if past maxsize
            }
            iter += 1; // Next range in the chain
            if iter >= self.tree.len() {
                break;
            }
        }
        sizeres
    }

    // Ghidra: address.cc:562 RangeList::getLastSignedRange
    /// Treating offsets with the high bit set as coming before offsets with
    /// the high bit clear, return the last/latest contiguous range within
    /// the given space. Faithful to address.cc:562-584: first the last range
    /// at or below the maximal signed value, otherwise the biggest negative
    /// range.
    pub fn get_last_signed_range(&self, spaceid: &AddrSpace) -> Option<&SpaceRange> {
        let midway = spaceid.get_highest() / 2; // Maximal signed value
        let mut iter = self.upper_bound_pos(spaceid, midway);
        if iter > 0 {
            iter -= 1;
            if self.tree[iter].spc == *spaceid {
                return Some(&self.tree[iter]);
            }
        }
        // If there were no "positive" ranges, search for biggest negative.
        let highest = spaceid.get_highest();
        let mut iter = self.upper_bound_pos(spaceid, highest);
        if iter > 0 {
            iter -= 1;
            if self.tree[iter].spc == *spaceid {
                return Some(&self.tree[iter]);
            }
        }
        None
    }

    // Ghidra: address.cc:588 RangeList::printBounds
    /// One line per disjoint range; `all` when empty. Each line carries a
    /// trailing newline exactly like the ostream version.
    pub fn print_bounds(&self) -> String {
        if self.tree.is_empty() {
            return "all\n".to_string();
        }
        let mut out = String::new();
        for range in &self.tree {
            out.push_str(&range.print_bounds());
            out.push('\n');
        }
        out
    }
}

// --- Bit-level helpers (faithful to address.cc/address.hh:576-590) ---

// Ghidra: address.hh:174 RangeList::signbitNegative
/// Return true if the sign-bit of the sized value is set (negative).
/// Faithful to `signbit_negative` (address.cc:641-647).
pub fn signbit_negative(val: u64, size: usize) -> bool {
    if size == 0 {
        return false;
    }
    let mask: u64 = 0x80u64 << (8 * (size - 1));
    (val & mask) != 0
}

// Ghidra: address.hh:174 RangeList::calcMask
/// Calculate an all-ones mask for the given byte size.
/// Faithful to `calc_mask` (address.hh:577). Equivalent to the `calc_mask`
/// already present in ruleaction.rs; centralised here for reuse.
pub fn calc_mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

// Ghidra: address.hh:174 RangeList::countLeadingZeros
/// Count leading zero bits in a 64-bit value. Faithful to
/// `count_leading_zeros` (address.cc:773).
pub fn count_leading_zeros(val: u64) -> i32 {
    if val == 0 {
        return 64;
    }
    val.leading_zeros() as i32
}

// Ghidra: address.hh:174 RangeList::leastsigbitSet
/// Return the index of the least-significant set bit, or -1 if val==0.
/// Faithful to `leastsigbit_set` (address.cc:714). Uses trailing_zeros for
/// an exact equivalent.
pub fn leastsigbit_set(val: u64) -> i32 {
    if val == 0 {
        -1
    } else {
        val.trailing_zeros() as i32
    }
}

// Ghidra: address.hh:174 RangeList::mostsigbitSet
/// Return the index of the most-significant set bit, or -1 if val==0.
/// Faithful to `mostsigbit_set` (address.cc:735).
pub fn mostsigbit_set(val: u64) -> i32 {
    if val == 0 {
        -1
    } else {
        63 - val.leading_zeros() as i32
    }
}

// Ghidra: address.hh:174 RangeList::coveringmask
/// Return the mask covering all set bits of `val`. Faithful to
/// `coveringmask` (address.cc:760). For val==0 returns 0; otherwise returns
/// `(1 << (msb+1)) - 1`, i.e. all bits from the least significant up to and
/// including the most-significant set bit.
pub fn coveringmask(val: u64) -> u64 {
    if val == 0 {
        return 0;
    }
    let msb = mostsigbit_set(val);
    if msb >= 63 {
        u64::MAX
    } else {
        (1u64 << (msb + 1)) - 1
    }
}

// Ghidra: address.hh:525 minimalmask
/// Return the smallest full-byte mask (0xff, 0xffff, 0xffffffff, or ~0)
/// that is >= val. Faithful to `minimalmask` (address.hh:525-534). This is
/// NOT `coveringmask` (address.cc:800, smallest 2^n-1 >= val): minimalmask
/// rounds up to a whole-byte boundary ladder; e.g. minimalmask(0x7ff)=0xffff
/// while coveringmask(0x7ff)=0x7ff, and minimalmask(0)=0xff while
/// coveringmask(0)=0. Consumers: ActionDeadCode::markConsumedParameters
/// (coreaction.cc:3856), gatherConsumedReturn (coreaction.cc:3884), and
/// JumpTable::foldInNormalization (jumptable.cc:2581).
pub fn minimalmask(val: u64) -> u64 {
    if val > 0xffffffff {
        return u64::MAX;
    }
    if val > 0xffff {
        return 0xffffffff;
    }
    if val > 0xff {
        return 0xffff;
    }
    0xff
}

// Ghidra: address.hh:174 RangeList::functionalEquality
/// Determine if two Varnodes hold the same value (immediate level).
/// Faithful to Ghidra's `functionalEquality` (expression.cc:520-526), using
/// only the level-0 test (expression.cc:404-417): identical varnode pointer,
/// or identical constants. The deeper structural comparison
/// (functionalEqualityLevel) is deferred. Returns true if provably equal.
pub fn functional_equality(
    vn1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    vn2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> bool {
    // level-0: same pointer → 0
    if std::sync::Arc::ptr_eq(vn1, vn2) {
        return true;
    }
    let v1 = vn1.read().unwrap();
    let v2 = vn2.read().unwrap();
    if v1.get_size() != v2.get_size() {
        return false;
    }
    // both constants → equal?
    if v1.is_constant() && v2.is_constant() {
        return v1.get_offset() == v2.get_offset();
    }
    // otherwise cannot immediately prove equality
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coveringmask() {
        assert_eq!(coveringmask(0), 0);
        assert_eq!(coveringmask(1), 1);
        assert_eq!(coveringmask(0xFF), 0xFF);
        assert_eq!(coveringmask(0x100), 0x1FF);
        assert_eq!(coveringmask(0x80), 0xFF);
        assert_eq!(coveringmask(0x8000_0000_0000_0000), u64::MAX);
    }

    #[test]
    fn test_minimalmask() {
        // Ghidra address.hh:525-534: whole-byte ladder, NOT coveringmask.
        assert_eq!(minimalmask(0), 0xff);
        assert_eq!(minimalmask(0xF), 0xff);
        assert_eq!(minimalmask(0xff), 0xff);
        assert_eq!(minimalmask(0x10), 0xff);
        assert_eq!(minimalmask(0x100), 0xffff);
        assert_eq!(minimalmask(0x7ff), 0xffff);
        assert_eq!(minimalmask(0xffff), 0xffff);
        assert_eq!(minimalmask(0x10000), 0xffffffff);
        assert_eq!(minimalmask(0xffffffff), 0xffffffff);
        assert_eq!(minimalmask(0x1_0000_0000), u64::MAX);
    }

    #[test]
    fn test_address_creation() {
        let addr = Address::new(0x1000);
        assert_eq!(addr.as_u64(), 0x1000);
        assert!(!addr.is_null());
    }

    #[test]
    fn test_address_alignment() {
        let addr = Address::new(0x1000);
        assert!(addr.is_aligned(0x10));
        assert!(!addr.is_aligned(0x2000));
    }

    #[test]
    fn test_seqnum() {
        let seq = SeqNum::new(Address::new(0x1000), 0);
        let next = seq.next();
        assert_eq!(next.addr, Address::new(0x1000));
        assert_eq!(next.time, 1);
        assert_eq!(next.order, 1);
    }

    #[test]
    fn test_seqnum_identity_ignores_mutable_order() {
        use std::collections::{BTreeSet, HashSet};

        let original = SeqNum::new(Address::new(0x1000), 7);
        let mut reordered = original;
        reordered.set_order(0xf000_0000);
        assert_eq!(original, reordered);
        assert_eq!(original.cmp(&reordered), std::cmp::Ordering::Equal);
        assert_eq!(BTreeSet::from([original]).get(&reordered), Some(&original));
        assert!(HashSet::from([original]).contains(&reordered));
    }

    #[test]
    fn test_range_creation() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();
        assert_eq!(range.get_first().as_u64(), 0x1000);
        assert_eq!(range.get_last().as_u64(), 0x2000);

        // Invalid range (first > last)
        assert!(Range::new(Address::new(0x2000), Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_range_contains() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();

        assert!(range.contains(Address::new(0x1000))); // First
        assert!(range.contains(Address::new(0x1500))); // Middle
        assert!(range.contains(Address::new(0x2000))); // Last
        assert!(!range.contains(Address::new(0x0FFF))); // Before
        assert!(!range.contains(Address::new(0x2001))); // After
    }

    #[test]
    fn test_range_list_insert() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        assert_eq!(list.num_ranges(), 1);

        // Non-overlapping range
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());
        assert_eq!(list.num_ranges(), 2);
    }

    #[test]
    fn test_range_list_merge() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x1500), Address::new(0x2500)).unwrap());

        // Should merge into one range
        assert_eq!(list.num_ranges(), 1);
        assert_eq!(list.ranges()[0].get_first().as_u64(), 0x1000);
        assert_eq!(list.ranges()[0].get_last().as_u64(), 0x2500);
    }

    #[test]
    fn test_seqnum_decode_encode() {
        let seq = SeqNum::new(Address::new(0x1000), 5);
        let encoded = seq.encode();
        let decoded = SeqNum::decode(&encoded).unwrap();
        assert_eq!(seq, decoded);
    }

    #[test]
    fn test_range_decode_encode() {
        let range = Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap();
        let encoded = range.encode();
        let decoded = Range::decode(&encoded).unwrap();
        assert_eq!(range.get_first(), decoded.get_first());
        assert_eq!(range.get_last(), decoded.get_last());
    }

    #[test]
    fn test_range_decode_from_attributes() {
        let range = Range::decode_from_attributes("0x1000", "0x2000").unwrap();
        assert_eq!(range.get_first().as_u64(), 0x1000);
        assert_eq!(range.get_last().as_u64(), 0x2000);
    }

    #[test]
    fn test_range_properties() {
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        use std::sync::{Arc, RwLock};

        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        {
            let mut ids = registry.write().unwrap();
            ids.register_element_with_id("range", 12);
            ids.register_attribute_with_id("name", 14);
            ids.register_attribute_with_id("space", 20);
            ids.register_attribute_with_id("first", 27);
            ids.register_attribute_with_id("last", 28);
            ids.register_attribute_with_id("unknown", 159);
        }
        let mut element = Element::new();
        element.set_name("range");
        element.add_attribute("name", "RAX");
        element.add_attribute("unknown", "ignored");
        element.add_attribute("space", "ram");
        element.add_attribute("first", "16");
        element.add_attribute("last", "32");
        let root = Arc::new(RwLock::new(element));
        let mut decoder = TreeDecoder::new(root, registry);
        let mut props = RangeProperties::new();

        props.decode(&mut decoder).unwrap();

        assert_eq!(props.space_name, "ram");
        assert_eq!(props.first, 16);
        assert_eq!(props.last, 32);
        assert!(props.is_register);
        assert!(props.seen_last);
    }

    #[test]
    fn test_range_properties_invalid_element_preserves_state() {
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        use std::sync::{Arc, RwLock};

        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        registry
            .write()
            .unwrap()
            .register_element_with_id("bogus", 77);
        let mut element = Element::new();
        element.set_name("bogus");
        let root = Arc::new(RwLock::new(element));
        let mut decoder = TreeDecoder::new(root, registry);
        let mut props = RangeProperties {
            space_name: "stack".to_string(),
            first: 4,
            last: 9,
            is_register: true,
            seen_last: true,
        };

        let error = props.decode(&mut decoder).unwrap_err();

        assert_eq!(error.to_string(), "Expecting <range> or <register> element");
        assert_eq!(props.space_name, "stack");
        assert_eq!(props.first, 4);
        assert_eq!(props.last, 9);
        assert!(props.is_register);
        assert!(props.seen_last);
    }

    #[test]
    fn test_range_list_decode_encode() {
        let mut list = RangeList::new();
        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());

        let encoded = list.encode();
        let decoded = RangeList::decode(&encoded).unwrap();
        assert_eq!(list.num_ranges(), decoded.num_ranges());
    }

    #[test]
    fn test_range_list_in_range() {
        let mut list = RangeList::new();

        list.insert_range(Range::new(Address::new(0x1000), Address::new(0x2000)).unwrap());
        list.insert_range(Range::new(Address::new(0x3000), Address::new(0x4000)).unwrap());

        assert!(list.in_range(Address::new(0x1500)));
        assert!(list.in_range(Address::new(0x3500)));
        assert!(!list.in_range(Address::new(0x2500)));
    }

    #[test]
    fn test_signbit_negative() {
        // size 1: sign bit is bit 7 (0x80).
        assert!(signbit_negative(0x80, 1));
        assert!(signbit_negative(0xff, 1));
        assert!(!signbit_negative(0x7f, 1));
        assert!(!signbit_negative(0x00, 1));
        // size 4: sign bit is bit 31 (0x80000000).
        assert!(signbit_negative(0x80000000, 4));
        assert!(!signbit_negative(0x7fffffff, 4));
    }

    #[test]
    fn test_calc_mask() {
        assert_eq!(calc_mask(0), 0);
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(2), 0xffff);
        assert_eq!(calc_mask(4), 0xffffffff);
        assert_eq!(calc_mask(8), u64::MAX);
    }

    #[test]
    fn test_leastsigbit_set() {
        assert_eq!(leastsigbit_set(0), -1);
        assert_eq!(leastsigbit_set(1), 0);
        assert_eq!(leastsigbit_set(0x100), 8);
        assert_eq!(leastsigbit_set(0x18), 3); // 0b11000 → bit 3
    }

    #[test]
    fn test_mostsigbit_set() {
        assert_eq!(mostsigbit_set(0), -1);
        assert_eq!(mostsigbit_set(1), 0);
        assert_eq!(mostsigbit_set(0x100), 8);
        assert_eq!(mostsigbit_set(0x18), 4); // 0b11000 → bit 4
    }

    #[test]
    fn test_count_leading_zeros() {
        // Faithful to count_leading_zeros (address.cc:773).
        assert_eq!(count_leading_zeros(0), 64);
        assert_eq!(count_leading_zeros(1), 63);
        assert_eq!(count_leading_zeros(0x100), 55);
        assert_eq!(count_leading_zeros(1u64 << 63), 0);
        assert_eq!(count_leading_zeros(u64::MAX), 0);
    }

    // ------------------------------------------------------------------------
    // ADDRESS-0001 space-aware regression tests (Rugra-side only; oracle
    // parity is proven by tests/oracle/address_space_handle_1204.* + runner).
    // ------------------------------------------------------------------------

    fn registry_with_ram() -> (crate::space::SpaceRegistry, AddrSpace) {
        let mut m = crate::space::SpaceRegistry::new();
        m.insert_space(AddrSpace::new_constant_space(false)).unwrap();
        m.insert_space(AddrSpace::new_other_space()).unwrap();
        m.insert_space(AddrSpace::new_unique_space(2, 0, false)).unwrap();
        m.insert_space(AddrSpace::new_space(
            crate::space::SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            crate::space::space_flags::HASPHYSICAL,
            0,
            0,
        ))
        .unwrap();
        m.insert_space(AddrSpace::new_space(
            crate::space::SpaceType::Processor,
            "register",
            false,
            8,
            1,
            4,
            crate::space::space_flags::HASPHYSICAL,
            0,
            0,
        ))
        .unwrap();
        let ram = m.get_space_by_name("ram").unwrap();
        (m, ram)
    }

    #[test]
    fn test_space_address_invalid_vs_ram0() {
        let (_m, ram) = registry_with_ram();
        let invalid = SpaceAddress::invalid();
        let ram0 = SpaceAddress::new(ram.clone(), 0);
        assert!(invalid.is_invalid());
        assert!(!ram0.is_invalid());
        assert_eq!(invalid.print_raw(), "invalid_addr");
        assert_eq!(ram0.print_raw(), "0x00000000");
        assert_ne!(invalid, ram0);
        assert!(invalid < ram0);
        assert!(SpaceAddress::minimal() == invalid);
        assert!(ram0 < SpaceAddress::maximal());
        assert_eq!(SpaceAddress::from_offset(0x1000).is_invalid(), true);
    }

    #[test]
    fn test_space_address_wrap_and_justified() {
        let mut m = crate::space::SpaceRegistry::new();
        let flash4 = AddrSpace::new_space(
            crate::space::SpaceType::Processor,
            "flash4",
            false,
            4,
            1,
            8,
            0,
            0,
            0,
        );
        m.insert_space(flash4.clone()).unwrap();
        let be = AddrSpace::new_space(
            crate::space::SpaceType::Processor,
            "be",
            true,
            8,
            1,
            9,
            0,
            0,
            0,
        );
        m.insert_space(be.clone()).unwrap();
        assert_eq!(
            SpaceAddress::new(flash4.clone(), 0xfffffffe)
                .add(3)
                .get_offset(),
            1
        );
        assert_eq!(
            SpaceAddress::new(flash4.clone(), 0x10).sub(0x11).get_offset(),
            0xffffffff
        );
        let container = SpaceAddress::new(be.clone(), 0x100);
        assert_eq!(
            container.justified_contain(8, &SpaceAddress::new(be.clone(), 0x100), 2, false),
            6
        );
        assert_eq!(
            container.justified_contain(8, &SpaceAddress::new(be.clone(), 0x100), 2, true),
            0
        );
        assert_eq!(
            SpaceAddress::new(be.clone(), 0x12)
                .overlap(0, &SpaceAddress::new(be.clone(), 0x10), 8),
            2
        );
    }

    #[test]
    fn test_space_range_list_isolation() {
        let (_m, ram) = registry_with_ram();
        let register = AddrSpace::new_space(
            crate::space::SpaceType::Processor,
            "register",
            false,
            8,
            1,
            4,
            0,
            0,
            0,
        );
        let mut rl = SpaceRangeList::new();
        rl.insert_range(&ram, 0x1000, 0x1fff);
        rl.insert_range(&register, 0x1000, 0x1fff);
        rl.insert_range(&ram, 0x2000, 0x2fff);
        // Adjacent same-space ranges are not merged; other spaces separate.
        assert_eq!(rl.num_ranges(), 3);
        assert_eq!(rl.print_bounds(), "ram: 1000-1fff\nram: 2000-2fff\nregister: 1000-1fff\n");
        assert!(rl.in_range(&SpaceAddress::new(ram.clone(), 0x1ffc), 4));
        assert!(!rl.in_range(&SpaceAddress::new(ram.clone(), 0x1ffd), 4));
        assert!(rl.in_range(&SpaceAddress::invalid(), 4));
        assert!(rl.get_range(&ram, 0x1500).is_some());
        assert!(rl.get_range(&register, 0x1500).is_some());
        // The ram range must not contain a register address.
        assert!(!rl
            .get_range(&ram, 0x1500)
            .unwrap()
            .contains(&SpaceAddress::new(register.clone(), 0x1500)));
        rl.insert_range(&ram, 0x1800, 0x2200);
        assert_eq!(rl.num_ranges(), 2);
        rl.remove_range(&ram, 0x1400, 0x17ff);
        assert_eq!(rl.num_ranges(), 3);
        assert_eq!(
            rl.ranges()[0].print_bounds(),
            "ram: 1000-13ff"
        );
    }

    #[test]
    fn test_space_range_properties_errors() {
        let (m, ram) = registry_with_ram();
        let mut props = RangeProperties::new();
        props.space_name = "ram".to_string();
        props.first = 0x100;
        props.seen_last = false;
        let range = SpaceRange::from_properties(&props, &m).unwrap();
        assert_eq!(range.get_last(), ram.get_highest());
        let mut bad = RangeProperties::new();
        bad.space_name = "nosuch".to_string();
        bad.seen_last = true;
        assert_eq!(
            SpaceRange::from_properties(&bad, &m),
            Err("Undefined space: nosuch".to_string())
        );
        let mut illegal = RangeProperties::new();
        illegal.space_name = "ram".to_string();
        illegal.first = 2;
        illegal.last = 1;
        illegal.seen_last = true;
        assert_eq!(
            SpaceRange::from_properties(&illegal, &m),
            Err("Illegal range tag".to_string())
        );
    }

    // --------------------------------------------------------------------
    // ADDRESS-0001 phase-1: legacy spaceless compatibility + space-tagged
    // comparison chain (single-side regression; oracle parity is proven by
    // tests/oracle/address_compat_order_1204.* + runner).
    // --------------------------------------------------------------------

    #[test]
    fn test_phase1_none_addresses_keep_offset_only_semantics() {
        // Every pre-phase-1 construction site produces None; ordering,
        // equality and hashing among them must be exactly the old u64
        // semantics.
        let mut addrs: Vec<Address> = vec![
            Address::new(0x2000),
            Address::new(0x1000),
            Address::new(0),
            Address::new(u64::MAX),
            Address::new(0x1500),
        ];
        addrs.sort();
        let offsets: Vec<u64> = addrs.iter().map(|a| a.as_u64()).collect();
        assert_eq!(offsets, vec![0, 0x1000, 0x1500, 0x2000, u64::MAX]);
        assert_eq!(Address::new(0x1000), Address::new(0x1000));
        assert_ne!(Address::new(0x1000), Address::new(0x1001));
        // Legacy display unchanged.
        assert_eq!(Address::new(0x1234).to_string(), "0x1234");
        // Hash/Ord key consistency for None addresses.
        use std::collections::{BTreeSet, HashSet};
        let set: HashSet<Address> = [0x10, 0x20, 0x10]
            .iter()
            .map(|&o| Address::new(o))
            .collect();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Address::new(0x10)));
        let bset: BTreeSet<Address> = [3, 1, 2]
            .iter()
            .map(|&o| Address::new(o))
            .collect();
        assert_eq!(
            bset.iter().map(|a| a.as_u64()).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // None arithmetic keeps the legacy plain wrap.
        assert_eq!(Address::new(0x10).offset(-0x11).as_u64(), u64::MAX);
        assert_eq!(Address::new(u64::MAX).next().as_u64(), 0);
        assert_eq!(Address::new(0).prev().as_u64(), u64::MAX);
    }

    #[test]
    fn test_phase1_space_tag_ordering_and_equivalence() {
        let (_m, ram) = registry_with_ram();
        let register = AddrSpace::new_space(
            crate::space::SpaceType::Processor,
            "register",
            false,
            8,
            1,
            4,
            crate::space::space_flags::HASPHYSICAL,
            0,
            0,
        );
        let ram_a = Address::with_space(&ram, 0x1000);
        let ram_b = Address::with_space(&ram, 0x800);
        let reg_a = Address::with_space(&register, 0x1000);
        // Same space: offset order (address.hh:391).
        assert!(ram_b < ram_a);
        // Different spaces: index order, ram(3) < register(4) (address.hh:389).
        assert!(ram_a < reg_a);
        // None (null base) sorts before every real space (address.hh:377)
        // and never equals one (address.hh:356).
        let none_a = Address::new(0x1000);
        assert!(none_a < ram_b);
        assert!(none_a < reg_a);
        assert_ne!(none_a, ram_a);
        // Equality needs the identical space and offset.
        assert_eq!(ram_a, Address::with_space(&ram, 0x1000));
        assert_ne!(ram_a, reg_a);
        assert_ne!(ram_a, ram_b);
        // Sorted container walks None first, then (index, offset).
        let mut all = vec![reg_a, ram_a, none_a, ram_b];
        all.sort();
        assert_eq!(
            all.iter().map(|a| a.as_u64()).collect::<Vec<_>>(),
            vec![0x1000, 0x800, 0x1000, 0x1000]
        );
        assert!(all[0].get_space().is_none());
        assert_eq!(all[1].get_space().unwrap().get_name(), "ram");
        assert_eq!(all[3].get_space().unwrap().get_name(), "register");
        // Interning is stable and idempotent for the same handle.
        assert_eq!(
            ram_a.get_space().unwrap().identity_ptr(),
            ram.identity_ptr()
        );
    }

    #[test]
    fn test_phase1_space_aware_wrap_and_overlap() {
        let mut m = crate::space::SpaceRegistry::new();
        let flash4 = AddrSpace::new_space(
            crate::space::SpaceType::Processor,
            "flash4",
            false,
            4,
            1,
            8,
            0,
            0,
            0,
        );
        m.insert_space(flash4.clone()).unwrap();
        let constant = AddrSpace::new_constant_space(false);
        m.insert_space(constant.clone()).unwrap();
        // operator+ wraps through the space (address.hh:423-425).
        assert_eq!(
            Address::with_space(&flash4, 0xfffffffe)
                .offset(3)
                .as_u64(),
            1
        );
        assert_eq!(
            Address::with_space(&flash4, 0x10).offset(-0x11).as_u64(),
            0xffffffff
        );
        // overlap: constants never overlap (address.cc:159); different
        // spaces never overlap (address.cc:158); wrap-aware distance
        // (address.cc:161).
        assert_eq!(
            Address::with_space(&constant, 0x10)
                .overlap(0, Address::with_space(&constant, 0x8), 16),
            -1
        );
        assert_eq!(
            Address::with_space(&flash4, 0x10)
                .overlap(0, Address::with_space(&constant, 0x8), 16),
            -1
        );
        assert_eq!(
            Address::with_space(&flash4, 0xfffffffe)
                .overlap(4, Address::with_space(&flash4, 0x1), 8),
            1
        );
    }

    #[test]
    fn test_phase1_space_address_bridge() {
        let (_m, ram) = registry_with_ram();
        let sa = SpaceAddress::new(ram.clone(), 0x1000);
        let bridged = Address::from_space_address(&sa);
        assert_eq!(bridged, Address::with_space(&ram, 0x1000));
        assert_eq!(bridged.to_space_address(), sa);
        // None <-> null base round trip.
        let none_sa = Address::new(0x1000).to_space_address();
        assert!(none_sa.is_invalid());
        assert_eq!(none_sa.get_offset(), 0x1000);
        assert_eq!(Address::from_space_address(&none_sa), Address::new(0x1000));
        // The maximal sentinel refuses to cross (would flip sort position).
        let result = std::panic::catch_unwind(|| {
            Address::from_space_address(&SpaceAddress::maximal())
        });
        assert!(result.is_err());
    }
}
