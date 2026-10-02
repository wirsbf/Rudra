//! Comment database — faithful port of `comment.hh` / `comment.cc` (406 lines).
//!
//! A database interface for high-level language comments. Comments are
//! attached to a specific function and code address, with properties
//! (user1/user2/user3/header/warning/warningheader) controlling display.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/comment.{hh,cc}.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::address::Address;
use crate::block::FlowBlock;
use crate::marshal::{AttributeId, Decoder, ElementId, Encoder};
use anyhow::{bail, Result};

/// Possible properties associated with a comment. Faithful to
/// `Comment::comment_type` (comment.hh:53).
pub mod comment_type {
    /// The first user defined property.
    pub const USER1: u32 = 1;
    /// The second user defined property.
    pub const USER2: u32 = 2;
    /// The third user defined property.
    pub const USER3: u32 = 4;
    /// The comment should be displayed in the function header.
    pub const HEADER: u32 = 8;
    /// The comment is auto-generated to alert the user.
    pub const WARNING: u32 = 16;
    /// The comment is auto-generated and should be in the header.
    pub const WARNINGHEADER: u32 = 32;
}

/// A comment attached to a specific function and code address. Faithful to
/// `Comment` (comment.hh:43).
#[derive(Debug)]
pub struct Comment {
    /// The properties associated with the comment.
    pub type_flags: u32,
    /// Sub-identifier for uniqueness.
    pub uniq: i32,
    /// Address of the function containing the comment.
    pub funcaddr: Address,
    /// Address associated with the comment.
    pub addr: Address,
    /// The body of the comment.
    pub text: String,
    /// True if this comment has already been emitted. Interior-mutable to
    /// mirror Ghidra's `mutable bool emitted` (comment.hh:50), which
    /// `setEmitted` mutates through a const receiver (comment.hh:63) —
    /// `PrintLanguage::emitLineComment` marks comments emitted while the
    /// sorter walks them const (printlanguage.cc:648). `AtomicBool` (not
    /// `Cell<bool>`) because `Funcdata` reaches a `Sync` bound through
    /// `ffi.rs`'s `Mutex<Option<Funcdata>>` lazy_static global; `Relaxed`
    /// orderings keep plain-bool semantics.
    pub emitted: AtomicBool,
}

// RUDRA-GLUE: field-wise Clone for the AtomicBool `emitted` member (C++'s
// implicit copy constructor copies the bool verbatim; AtomicBool has no
// Clone impl, so the current flag value is re-loaded into the copy).
impl Clone for Comment {
    // RUDRA-GLUE: std::clone::Clone trait impl — Rust language structure.
    fn clone(&self) -> Self {
        Self {
            type_flags: self.type_flags,
            uniq: self.uniq,
            funcaddr: self.funcaddr,
            addr: self.addr,
            text: self.text.clone(),
            emitted: AtomicBool::new(self.emitted.load(Ordering::Relaxed)),
        }
    }
}

impl Comment {
    // Ghidra: comment.cc:30 Comment::new
    /// Construct given properties, function address, comment address,
    /// uniqueness id, and text. Faithful to the constructor (comment.cc:30).
    pub fn new(tp: u32, fad: Address, ad: Address, uq: i32, txt: &str) -> Self {
        Self {
            type_flags: tp,
            uniq: uq,
            funcaddr: fad,
            addr: ad,
            text: txt.to_string(),
            emitted: AtomicBool::new(false),
        }
    }

    // Ghidra: comment.cc:30 Comment::newEmpty
    /// Construct an empty comment for use with decode.
    pub fn new_empty() -> Self {
        Self {
            type_flags: 0,
            uniq: 0,
            funcaddr: Address::new(0),
            addr: Address::new(0),
            text: String::new(),
            emitted: AtomicBool::new(false),
        }
    }

    // Ghidra: comment.hh:63 Comment::setEmitted
    /// Mark that this comment has been emitted. Faithful to `setEmitted`
    /// (const method on a `mutable` field, comment.hh:50/63).
    pub fn set_emitted(&self, val: bool) {
        self.emitted.store(val, Ordering::Relaxed);
    }

    // Ghidra: comment.cc:30 Comment::isEmitted
    /// Return true if this comment is already emitted.
    pub fn is_emitted(&self) -> bool {
        self.emitted.load(Ordering::Relaxed)
    }

    // Ghidra: comment.cc:30 Comment::getType
    /// Get the properties associated with the comment. Faithful to `getType`.
    pub fn get_type(&self) -> u32 {
        self.type_flags
    }

    // Ghidra: comment.cc:30 Comment::getFuncAddr
    /// Get the address of the function containing the comment.
    pub fn get_func_addr(&self) -> Address {
        self.funcaddr
    }

    // Ghidra: comment.cc:30 Comment::getAddr
    /// Get the address to which the instruction is attached.
    pub fn get_addr(&self) -> Address {
        self.addr
    }

    // Ghidra: comment.cc:30 Comment::getUniq
    /// Get the sub-sorting index. Faithful to `getUniq`.
    pub fn get_uniq(&self) -> i32 {
        self.uniq
    }

    // Ghidra: comment.cc:30 Comment::getText
    /// Get the body of the comment. Faithful to `getText`.
    pub fn get_text(&self) -> &str {
        &self.text
    }

    // Ghidra: comment.cc:37 Comment::encode
    /// Encode the comment to a stream. Faithful to `Comment::encode`
    /// (comment.cc:37).
    pub fn encode(&self, encoder: &mut dyn Encoder) -> Result<()> {
        let tpname = decode_comment_type(self.type_flags)?;
        let comment_elem = ElementId::new("comment", 0);
        let text_elem = ElementId::new("text", 0);
        encoder.open_element(&comment_elem);
        encoder.write_string(&AttributeId::new("type", 0), &tpname);
        encode_addr_child(encoder, self.funcaddr)?;
        encode_addr_child(encoder, self.addr)?;
        // Text content.
        encoder.open_element(&text_elem);
        encoder.write_string(&AttributeId::new("XMLcontent", 1), &self.text);
        encoder.close_element(&text_elem);
        encoder.close_element(&comment_elem);
        Ok(())
    }

    // Ghidra: comment.cc:57 Comment::decode
    /// Decode the comment from a stream. Faithful to `Comment::decode`
    /// (comment.cc:57).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) -> Result<()> {
        self.emitted = AtomicBool::new(false);
        self.type_flags = 0;
        let comment_id = decoder.open_element();
        // Read type attribute.
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 {
                break;
            }
            if decoder.attribute_name(aid).as_deref() == Some("type") {
                self.type_flags = encode_comment_type(&decoder.read_string())?;
            } else {
                // Ghidra's iterator advances independently of value reads.
            }
        }
        // Read two <addr> children (funcaddr, addr).
        self.funcaddr = read_addr_child(decoder)?;
        self.addr = read_addr_child(decoder)?;
        // Read <text> child if present.
        let sub_id = decoder.peek_element();
        if sub_id != 0 {
            decoder.open_element();
            self.text = decoder.read_string_attr(&AttributeId::new("XMLcontent", 1));
            decoder.close_element(sub_id);
        }
        decoder.close_element(comment_id);
        Ok(())
    }
}

// Ghidra: comment.cc:77 Comment::encodeCommentType
/// Convert a name string to a comment property. Faithful to
/// `encodeCommentType` (comment.cc:77). Unknown names are errors, matching
/// Ghidra's `LowlevelError` path.
pub fn encode_comment_type(name: &str) -> Result<u32> {
    Ok(match name {
        "user1" => comment_type::USER1,
        "user2" => comment_type::USER2,
        "user3" => comment_type::USER3,
        "header" => comment_type::HEADER,
        "warning" => comment_type::WARNING,
        "warningheader" => comment_type::WARNINGHEADER,
        _ => bail!("Unknown comment type: {name}"),
    })
}

// Ghidra: comment.cc:97 Comment::decodeCommentType
/// Convert a comment property to its string representation. Faithful to
/// `decodeCommentType` (comment.cc:97). Unknown values are errors, matching
/// Ghidra's `LowlevelError` path.
pub fn decode_comment_type(val: u32) -> Result<String> {
    Ok(match val {
        comment_type::USER1 => "user1".to_string(),
        comment_type::USER2 => "user2".to_string(),
        comment_type::USER3 => "user3".to_string(),
        comment_type::HEADER => "header".to_string(),
        comment_type::WARNING => "warning".to_string(),
        comment_type::WARNINGHEADER => "warningheader".to_string(),
        _ => bail!("Unknown comment type"),
    })
}

// Ghidra: space.cc:143 AddrSpace::encodeAttributes
/// Encode one `<addr>` child with distinct `space` and `offset` attributes.
fn encode_addr_child(encoder: &mut dyn Encoder, address: Address) -> Result<()> {
    let Some(space) = address.get_space() else {
        bail!("Cannot encode address without an address space");
    };
    let addr_elem = ElementId::new("addr", 0);
    encoder.open_element(&addr_elem);
    encoder.write_string(&AttributeId::new("space", 0), &space.get_name());
    encoder.write_unsigned_integer(&AttributeId::new("offset", 0), address.as_u64());
    encoder.close_element(&addr_elem);
    Ok(())
}

// Ghidra: address.cc:205 Address::decode
/// Read a single `<addr>` child and recover its required offset.
///
/// The current `Decoder` trait has no `AddrSpaceManager`, so this projection
/// validates and consumes the space name but returns the legacy offset-only
/// `Address`. Restoring the exact space handle remains an ADDRESS codec gap.
fn read_addr_child(decoder: &mut dyn Decoder) -> Result<Address> {
    let sub_id = decoder.peek_element();
    if sub_id == 0 {
        bail!("Address element is missing");
    }
    decoder.open_element();
    let mut saw_space = false;
    let mut offset = None;
    loop {
        let aid = decoder.next_attribute_id();
        if aid == 0 {
            break;
        }
        match decoder.attribute_name(aid).as_deref() {
            Some("space") => {
                saw_space = !decoder.read_string().is_empty();
            }
            Some("offset") => {
                offset = Some(decoder.read_unsigned_integer());
            }
            _ => {
                // Ghidra's AddrSpace::decodeAttributes ignores other attrs.
            }
        }
    }
    if !saw_space {
        bail!("Address is missing space");
    }
    let Some(offset) = offset else {
        bail!("Address is missing offset");
    };
    decoder.close_element(sub_id);
    Ok(Address::new(offset))
}

// Ghidra: comment.cc:30 Comment::commentSortKey
/// A sorting key for comments: (funcaddr, addr, uniq). Comments are ordered
/// first by function, then address, then the sub-sort index. Faithful to
/// `CommentOrder` (comment.hh:80).
fn comment_sort_key(c: &Comment) -> (u64, u64, i32) {
    (c.funcaddr.as_u64(), c.addr.as_u64(), c.uniq)
}

/// An in-memory implementation of the CommentDatabase API. Faithful to
/// `CommentDatabaseInternal` (comment.hh:161). All Comment objects are held in
/// memory in a sorted vector (by funcaddr, addr, uniq).
#[derive(Debug, Default, Clone)]
pub struct CommentDatabaseInternal {
    /// The sorted vector of Comments, keyed by (funcaddr, addr, uniq).
    comments: Vec<Comment>,
}

impl CommentDatabaseInternal {
    // Ghidra: comment.cc:134 CommentDatabaseInternal::new
    /// Construct an empty comment database.
    pub fn new() -> Self {
        Self::default()
    }

    // Ghidra: comment.cc:134 CommentDatabaseInternal::sort
    /// Keep the comments vector sorted by (funcaddr, addr, uniq).
    fn sort(&mut self) {
        self.comments
            .sort_by(|a, b| comment_sort_key(a).cmp(&comment_sort_key(b)));
    }

    // Ghidra: comment.cc:148 CommentDatabaseInternal::clear
    /// Clear all comments from this container. Faithful to `clear`
    /// (comment.cc:148).
    pub fn clear(&mut self) {
        self.comments.clear();
    }

    // Ghidra: comment.cc:158 CommentDatabaseInternal::clearType
    /// Clear all comments matching (one of) the indicated types, restricted to
    /// a specific function. Faithful to `clearType` (comment.cc:158).
    pub fn clear_type(&mut self, fad: Address, tp: u32) {
        self.comments
            .retain(|c| !(c.funcaddr == fad && (c.type_flags & tp) != 0));
    }

    // Ghidra: comment.cc:178 CommentDatabaseInternal::addComment
    /// Add a new comment to the container. Faithful to `addComment`
    /// (comment.cc:178). The uniqueness id is auto-assigned.
    pub fn add_comment(&mut self, tp: u32, fad: Address, ad: Address, txt: &str) {
        // Find the next uniq id for this (fad, ad) pair.
        let mut max_uniq = -1i32;
        for c in &self.comments {
            if c.funcaddr == fad && c.addr == ad {
                if c.uniq > max_uniq {
                    max_uniq = c.uniq;
                }
            }
        }
        let uniq = max_uniq + 1;
        let comment = Comment::new(tp, fad, ad, uniq, txt);
        self.comments.push(comment);
        self.sort();
    }

    // Ghidra: comment.cc:196 CommentDatabaseInternal::addCommentNoDuplicate
    /// Add a new comment, making sure there is no duplicate. Faithful to
    /// `addCommentNoDuplicate` (comment.cc:196). Returns true if a new Comment
    /// was created, false if there was a duplicate.
    pub fn add_comment_no_duplicate(
        &mut self,
        tp: u32,
        fad: Address,
        ad: Address,
        txt: &str,
    ) -> bool {
        // Check for an existing comment with the same text at this address.
        for c in &self.comments {
            if c.funcaddr == fad && c.addr == ad && c.text == txt {
                return false;
            }
        }
        self.add_comment(tp, fad, ad, txt);
        true
    }

    // Ghidra: comment.cc:134 CommentDatabaseInternal::numComments
    /// Number of comments in the database.
    pub fn num_comments(&self) -> usize {
        self.comments.len()
    }

    // Ghidra: comment.cc:134 CommentDatabaseInternal::commentsForFunction
    /// Iterate over all comments for a single function. Faithful to
    /// `beginComment`/`endComment`.
    pub fn comments_for_function(&self, fad: Address) -> impl Iterator<Item = &Comment> {
        self.comments.iter().filter(move |c| c.funcaddr == fad)
    }

    // Ghidra: comment.cc:134 CommentDatabaseInternal::allComments
    /// Iterate over all comments.
    pub fn all_comments(&self) -> impl Iterator<Item = &Comment> {
        self.comments.iter()
    }

    // Ghidra: comment.cc:242 CommentDatabaseInternal::encode
    /// Encode all comments to a stream. Faithful to `encode` (comment.cc:242).
    pub fn encode(&self, encoder: &mut dyn Encoder) -> Result<()> {
        let db_elem = ElementId::new("commentdb", 0);
        encoder.open_element(&db_elem);
        for c in &self.comments {
            c.encode(encoder)?;
        }
        encoder.close_element(&db_elem);
        Ok(())
    }

    // Ghidra: comment.cc:253 CommentDatabaseInternal::decode
    /// Decode all comments from a `<commentdb>` element. Faithful to `decode`
    /// (comment.cc:253).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) -> Result<()> {
        let db_id = decoder.open_element();
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let mut com = Comment::new_empty();
            com.decode(decoder)?;
            self.add_comment(
                com.get_type(),
                com.get_func_addr(),
                com.get_addr(),
                com.get_text(),
            );
        }
        decoder.close_element(db_id);
        Ok(())
    }
}

/// Header comment type for the CommentSorter. Faithful to the enum in
/// CommentSorter (comment.hh:197).
pub mod header_type {
    /// Basic header comments.
    pub const HEADER_BASIC: u32 = 0;
    /// Comment that can't be placed in code flow.
    pub const HEADER_UNPLACED: u32 = 1;
}

/// The sorting key for placing a Comment within a specific basic block.
/// Faithful to `CommentSorter::Subsort` (comment.hh:203): `index` is the
/// signed basic-block index, -1 for a function header, so header keys order
/// before every block key exactly as Ghidra's `int4` comparison does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subsort {
    /// Either the basic block index or -1 for a function header.
    pub index: i32,
    /// The order index within the basic block.
    pub order: u32,
    /// A final count to guarantee a unique sorting.
    pub pos: u32,
}

impl Subsort {
    // Ghidra: comment.hh:224 Subsort::setHeader
    /// Initialize the key for a header comment. Faithful to `setHeader`
    /// (comment.hh:224-227): sets `index = -1` and `order = headerType`,
    /// leaving `pos` untouched (the caller-owned uniqueness counter).
    pub fn set_header(&mut self, header_type: u32) {
        self.index = -1;
        self.order = header_type;
    }

    // Ghidra: comment.hh:233 Subsort::setBlock
    /// Initialize the key for a basic block position. Faithful to `setBlock`
    /// (comment.hh:233-236): sets `index`/`order`, leaving `pos` untouched.
    pub fn set_block(&mut self, i: i32, ord: u32) {
        self.index = i;
        self.order = ord;
    }
}

// Ghidra: block.hh:476 BlockBasic::contains
/// Determine if the given address is contained in the block's original range.
///
/// Ghidra projects `BlockBasic::contains` through the cover `RangeList`
/// (`cover.inRange(addr, 1)`, a single `[setInitialRange(beg,end)]` range for
/// blocks established by `Funcdata::setBasicBlockRange`). Rugra has no block
/// cover system, so the range is projected as `[start_addr, last-op addr]`
/// (`get_stop_addr`), same-space only — mirroring `RangeList::inRange`'s
/// per-space range lookup. The oracle fixture pins both sides to identical
/// ranges (block end == address of the last op in the block).
fn block_basic_contains(bb: &crate::block::BlockBasic, addr: &Address) -> bool {
    match (addr.get_space(), bb.start_addr.get_space()) {
        (Some(space), Some(block_space)) if space == block_space => {
            *addr >= bb.start_addr && *addr <= bb.get_stop_addr()
        }
        _ => false,
    }
}

/// A class for sorting comments into and within basic blocks. Faithful to
/// `CommentSorter` (comment.hh:195).
///
/// The decompiler maintains information about basic blocks that have been
/// entirely removed, in which case, the user can elect to not display the
/// corresponding comments. This class also acts as state for walking comments
/// within a specific basic block or within the header: `start`/`stop`/`opstop`
/// bound the current walk exactly as Ghidra's `map<Subsort,Comment *>::const_iterator`
/// members do (comment.hh:239-241). The iterators are modeled as ranks into
/// the sorted `commmap` (rank == `commmap.len()` is `end()`), and live in
/// `Cell`s because Ghidra's `start` is `mutable` inside const
/// `hasNext`/`getNext` (comment.hh:239, 250-251).
#[derive(Debug, Default)]
pub struct CommentSorter {
    /// Comments for the current function, sorted by block. Models Ghidra's
    /// `map<Subsort,Comment *>` as a sorted vector of (key, comment index).
    commmap: Vec<(Subsort, usize)>,
    /// The comments themselves (indexed by the commmap values). Rugra clones
    /// the placed Comment objects out of the (const) database; Ghidra stores
    /// raw pointers into it.
    comments: Vec<Comment>,
    /// Display unplaced comments in the header.
    display_unplaced_comments: bool,
    /// Iterator to the current comment being walked (`mutable start`,
    /// comment.hh:239).
    start: std::cell::Cell<usize>,
    /// Last comment in the current set being walked (`stop`, comment.hh:240).
    stop: std::cell::Cell<usize>,
    /// Statement landmark within the current set of comments (`opstop`,
    /// comment.hh:241).
    opstop: std::cell::Cell<usize>,
}

impl CommentSorter {
    // Ghidra: comment.hh:245 CommentSorter::CommentSorter
    /// Construct an empty sorter with `displayUnplacedComments = false`.
    pub fn new() -> Self {
        Self {
            commmap: Vec::new(),
            comments: Vec::new(),
            display_unplaced_comments: false,
            start: std::cell::Cell::new(0),
            stop: std::cell::Cell::new(0),
            opstop: std::cell::Cell::new(0),
        }
    }

    // RUDRA-GLUE: std::map<Subsort,Comment*>::lower_bound rank projection.
    // Ghidra's map iterators are node pointers; Rugra models the sorted map
    // as a vector and the iterator as its rank (first entry with key >= key).
    fn lower_bound_rank(&self, key: &Subsort) -> usize {
        self.commmap.partition_point(|(k, _)| *k < *key)
    }

    // RUDRA-GLUE: std::map<Subsort,Comment*>::upper_bound rank projection
    // (first entry with key > key).
    fn upper_bound_rank(&self, key: &Subsort) -> usize {
        self.commmap.partition_point(|(k, _)| *k <= *key)
    }

    // RUDRA-GLUE: PcodeOp::getParent accessor mirroring op.hh's `BlockBasic
    // *getParent(void)`; Rugra stores the parent as a Weak<dyn FlowBlock>.
    fn op_parent(
        op: &crate::op::PcodeOp,
    ) -> Option<std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>> {
        op.parent.as_ref().and_then(|w| w.upgrade())
    }

    // Ghidra: comment.cc:270 CommentSorter::findPosition
    /// Figure out position of given Comment and initialize its key. Faithful
    /// to `CommentSorter::findPosition` (comment.cc:270-325).
    ///
    /// Decision-order: (1) type 0 is never placed; (2) header/warningheader
    /// comments at the function entry address become `header_basic`; (3) the
    /// first op at or after the comment address (`PcodeOpTree` lower bound,
    /// op.cc:1146) places the comment in that op's block at the op's
    /// SeqNum::order when the block's range contains the address; (4) failing
    /// that, the op before the lower bound places it at the very end of its
    /// block (order 0xffffffff) when its block contains the address; (5) an
    /// exact-address op that migrated out of its original block still hangs
    /// the comment on it (backupOp); (6) an op-less function places every
    /// comment at block 0 order 0; (7) `displayUnplacedComments` salvages the
    /// comment as `header_unplaced`; otherwise (8) the block was excised and
    /// the comment is dropped. Dead ops (no parent) raise the same
    /// LowlevelError text as Ghidra (comment.cc:289/303).
    fn find_position(
        &self,
        subsort: &mut Subsort,
        comm: &Comment,
        fd: &crate::funcdata::Funcdata,
    ) -> Result<bool> {
        if comm.get_type() == 0 {
            return Ok(false);
        }
        let fad = *fd.get_address();
        if ((comm.get_type() & (comment_type::HEADER | comment_type::WARNINGHEADER)) != 0)
            && comm.get_addr() == fad
        {
            // If it is a header comment at the address associated with the
            // beginning of the function
            subsort.set_header(header_type::HEADER_BASIC);
            return Ok(true);
        }

        // Try to find block containing comment
        // Find op at lowest address greater or equal to comment's address.
        // The PcodeOpTree is sorted by SeqNum = (pc, uniq), so the lower
        // bound of SeqNum(addr, 0) is the first op whose address >= addr.
        let comm_addr = comm.get_addr();
        let ops_sorted: Vec<crate::op::PcodeOpRef> = fd.obank.optree.iter().cloned().collect();
        let opiter = ops_sorted
            .iter()
            .position(|o| o.0.read().unwrap().get_addr() >= comm_addr);

        let mut backup_op: Option<crate::op::PcodeOpRef> = None;
        if let Some(rank) = opiter {
            // If there is an op at or after the comment
            let op = ops_sorted[rank].clone();
            let op_read = op.0.read().unwrap();
            let block = match Self::op_parent(&op_read) {
                Some(b) => b,
                None => bail!("Dead op reaching CommentSorter"),
            };
            let block_read = block.read().unwrap();
            if let Some(bb) = block_read
                .as_any()
                .downcast_ref::<crate::block::BlockBasic>()
            {
                if block_basic_contains(bb, &comm_addr) {
                    // If the op's block contains the address:
                    // associate comment with this op
                    subsort.set_block(bb.get_index(), op_read.get_seq_num().order);
                    return Ok(true);
                }
            }
            if op_read.get_addr() == comm_addr {
                backup_op = Some(op.clone());
            }
        }
        if opiter.unwrap_or(ops_sorted.len()) > 0 {
            // If there is a previous op (--opiter)
            let prev = ops_sorted[opiter.unwrap_or(ops_sorted.len()) - 1].clone();
            let prev_read = prev.0.read().unwrap();
            let block = match Self::op_parent(&prev_read) {
                Some(b) => b,
                None => bail!("Dead op reaching CommentSorter"),
            };
            let block_read = block.read().unwrap();
            if let Some(bb) = block_read
                .as_any()
                .downcast_ref::<crate::block::BlockBasic>()
            {
                if block_basic_contains(bb, &comm_addr) {
                    // Treat the comment as being in this block at the very end
                    subsort.set_block(bb.get_index(), 0xffffffff);
                    return Ok(true);
                }
            }
        }
        if let Some(backup) = backup_op {
            // Its possible the op migrated from its original basic block.
            // Since the address matches exactly, hang the comment on it.
            let backup_read = backup.0.read().unwrap();
            let block = match Self::op_parent(&backup_read) {
                Some(b) => b,
                // Unreachable in the oracle: backupOp's parent was verified
                // non-null when the candidate was examined above.
                None => bail!("Dead op reaching CommentSorter"),
            };
            let index = block.read().unwrap().get_index();
            subsort.set_block(index, backup_read.get_seq_num().order);
            return Ok(true);
        }
        if ops_sorted.is_empty() {
            // If there are no ops at all: put comment at the beginning of the
            // first block
            subsort.set_block(0, 0);
            return Ok(true);
        }
        if self.display_unplaced_comments {
            subsort.set_header(header_type::HEADER_UNPLACED);
            return Ok(true);
        }
        Ok(false) // Basic block containing comment has been excised
    }

    // Ghidra: comment.cc:334 CommentSorter::setupFunctionList
    /// Collect and sort comments specific to the given function. Faithful to
    /// `setupFunctionList` (comment.cc:334-355): clears the map, records
    /// `displayUnplaced`, walks the database range for the function's address
    /// (every Comment of the function regardless of type — the type mask is
    /// applied by the consumers, printc.cc:3238/3280), and inserts each
    /// placeable comment under its findPosition key. The `pos` uniqueness
    /// counter starts at 0 once and increments only for placed comments,
    /// persisting across iterations.
    ///
    /// Errors: dead ops raise `Dead op reaching CommentSorter` (LowlevelError
    /// in Ghidra, comment.cc:289/303).
    pub fn setup_function_list(
        &mut self,
        tp: u32,
        fd: &crate::funcdata::Funcdata,
        db: &CommentDatabaseInternal,
        display_unplaced: bool,
    ) -> Result<()> {
        self.commmap.clear();
        self.comments.clear();
        // Ghidra's map::clear() invalidates start/stop/opstop; reset the rank
        // projections to end() of the now-empty map. Consumers always issue a
        // fresh setup* before walking.
        self.start.set(0);
        self.stop.set(0);
        self.opstop.set(0);
        self.display_unplaced_comments = display_unplaced;
        if tp == 0 {
            return Ok(());
        }
        let fd_addr = *fd.get_address();
        let mut subsort = Subsort {
            index: 0,
            order: 0,
            pos: 0,
        };

        for comm in db.comments_for_function(fd_addr) {
            if self.find_position(&mut subsort, comm, fd)? {
                let placed = comm.clone();
                placed.set_emitted(false);
                self.comments.push(placed);
                let idx = self.comments.len() - 1;
                self.commmap.push((subsort, idx));
                subsort.pos += 1; // Advance the uniqueness counter
            }
        }
        // Ghidra inserts into a sorted map; keys are unique (per-placement pos
        // counter), so sorting the collected pairs yields the identical map
        // iteration order.
        self.commmap.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(())
    }

    // Ghidra: comment.cc:379 CommentSorter::setupBlockList
    /// Find iterators that bound everything in the basic block. Faithful to
    /// `setupBlockList` (comment.cc:379-390): `start = lower_bound((bl,0,0))`
    /// and `stop = upper_bound((bl,0xffffffff,0xffffffff))`.
    pub fn setup_block_bounds(&self, bl_index: i32) {
        let mut subsort = Subsort {
            index: bl_index,
            order: 0,
            pos: 0,
        };
        self.start.set(self.lower_bound_rank(&subsort));
        subsort.order = 0xffffffff;
        subsort.pos = 0xffffffff;
        self.stop.set(self.upper_bound_rank(&subsort));
    }

    // Ghidra: comment.cc:362 CommentSorter::setupOpList
    /// Establish a p-code landmark within the current set of comments.
    /// Faithful to `setupOpList` (comment.cc:362-374): a NULL op sets
    /// `opstop = stop` (pick up any remaining comments in this basic block);
    /// otherwise `opstop = upper_bound((block, op order, 0xffffffff))`.
    /// `start` is intentionally left alone — successive landmarks emit only
    /// the comments between them.
    pub fn setup_op_stop(&self, op: Option<&crate::op::PcodeOpRef>) {
        let Some(op) = op else {
            self.opstop.set(self.stop.get());
            return;
        };
        let op_read = op.0.read().unwrap();
        let Some(parent) = Self::op_parent(&op_read) else {
            // RUDRA-GLUE: Ghidra dereferences op->getParent() unchecked
            // (comment.cc:370); every oracle caller passes an op obtained
            // from a block's op list. Guard by leaving the landmark alone.
            return;
        };
        let subsort = Subsort {
            index: parent.read().unwrap().get_index(),
            order: op_read.get_seq_num().order,
            pos: 0xffffffff,
        };
        self.opstop.set(self.upper_bound_rank(&subsort));
    }

    // Ghidra: comment.cc:394 CommentSorter::setupHeader
    /// Header comments are grouped together. Set up iterators. Faithful to
    /// `setupHeader` (comment.cc:394-404): `start =
    /// lower_bound((-1,headerType,0))`, then `opstop =
    /// upper_bound((-1,headerType,0xffffffff))`.
    pub fn setup_header(&self, header_type: u32) {
        let mut subsort = Subsort {
            index: -1,
            order: header_type,
            pos: 0,
        };
        self.start.set(self.lower_bound_rank(&subsort));
        subsort.pos = 0xffffffff;
        self.opstop.set(self.upper_bound_rank(&subsort));
    }

    // Ghidra: comment.hh:250 CommentSorter::hasNext
    /// Return true if there are more comments to emit in the current set.
    pub fn has_next(&self) -> bool {
        self.start.get() != self.opstop.get()
    }

    // Ghidra: comment.hh:251 CommentSorter::getNext
    /// Advance to the next comment, returning the current one. The caller
    /// guards with `has_next` (Ghidra's getNext has no bounds check).
    pub fn get_next(&self) -> &Comment {
        let rank = self.start.get();
        let res = &self.comments[self.commmap[rank].1];
        self.start.set(rank + 1);
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::{IdRegistry, TreeDecoder, TreeEncoder};
    use crate::space::{space_flags, AddrSpace, SpaceType};

    fn ram_space() -> AddrSpace {
        AddrSpace::new_space(
            SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            space_flags::HASPHYSICAL,
            0,
            0,
        )
    }

    #[test]
    fn test_comment_construction() {
        let c = Comment::new(
            comment_type::HEADER,
            Address::new(0x1000),
            Address::new(0x1000),
            0,
            "This is a header comment",
        );
        assert_eq!(c.get_type(), comment_type::HEADER);
        assert_eq!(c.get_func_addr().as_u64(), 0x1000);
        assert_eq!(c.get_addr().as_u64(), 0x1000);
        assert_eq!(c.get_uniq(), 0);
        assert_eq!(c.get_text(), "This is a header comment");
        assert!(!c.is_emitted());
    }

    #[test]
    fn test_comment_type_roundtrip() {
        for &tp in &[
            comment_type::USER1,
            comment_type::USER2,
            comment_type::USER3,
            comment_type::HEADER,
            comment_type::WARNING,
            comment_type::WARNINGHEADER,
        ] {
            let name = decode_comment_type(tp).unwrap();
            assert_eq!(encode_comment_type(&name).unwrap(), tp);
        }
        assert!(encode_comment_type("unknown").is_err());
        assert!(decode_comment_type(0).is_err());
    }

    #[test]
    fn test_database_add_comment() {
        let mut db = CommentDatabaseInternal::new();
        assert_eq!(db.num_comments(), 0);
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Warning!",
        );
        assert_eq!(db.num_comments(), 1);
    }

    #[test]
    fn test_database_add_no_duplicate() {
        let mut db = CommentDatabaseInternal::new();
        assert!(db.add_comment_no_duplicate(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Warning!"
        ));
        assert!(!db.add_comment_no_duplicate(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Warning!"
        ));
        assert_eq!(db.num_comments(), 1);
        // Different text → added.
        assert!(db.add_comment_no_duplicate(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Different"
        ));
        assert_eq!(db.num_comments(), 2);
    }

    #[test]
    fn test_database_clear_type() {
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "W",
        );
        db.add_comment(
            comment_type::HEADER,
            Address::new(0x1000),
            Address::new(0x3000),
            "H",
        );
        assert_eq!(db.num_comments(), 2);
        db.clear_type(Address::new(0x1000), comment_type::WARNING);
        assert_eq!(db.num_comments(), 1);
    }

    #[test]
    fn test_database_comments_for_function() {
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "A",
        );
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x3000),
            "B",
        );
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x5000),
            Address::new(0x6000),
            "C",
        );
        let func1: Vec<_> = db.comments_for_function(Address::new(0x1000)).collect();
        assert_eq!(func1.len(), 2);
        let func2: Vec<_> = db.comments_for_function(Address::new(0x5000)).collect();
        assert_eq!(func2.len(), 1);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        {
            let mut r = registry.write().unwrap();
            for nm in &["type", "space", "offset", "XMLcontent"] {
                r.register_attribute(nm);
            }
            for nm in &["comment", "commentdb", "addr", "text"] {
                r.register_element(nm);
            }
        }
        let ram = ram_space();
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::WARNING,
            Address::with_space(&ram, 0x1000),
            Address::with_space(&ram, 0x2000),
            "Test warning",
        );
        db.add_comment(
            comment_type::HEADER,
            Address::with_space(&ram, 0x1000),
            Address::with_space(&ram, 0x1000),
            "Header",
        );

        // Encode.
        let mut enc = TreeEncoder::new(registry.clone());
        db.encode(&mut enc).unwrap();
        let doc = enc.into_document();
        assert!(doc.get_root().is_some());

        // Decode into a fresh database.
        let root = doc.get_root().unwrap().clone();
        let mut db2 = CommentDatabaseInternal::new();
        let mut dec = TreeDecoder::new(root, registry.clone());
        db2.decode(&mut dec).unwrap();

        assert_eq!(db2.num_comments(), 2);
        let comments: Vec<_> = db2
            .comments_for_function(Address::new(0x1000))
            .map(|c| {
                (
                    c.get_type(),
                    c.get_addr().as_u64(),
                    c.get_text().to_string(),
                )
            })
            .collect();
        assert!(
            comments.iter().any(|(t, a, txt)| {
                *t == comment_type::WARNING && *a == 0x2000 && txt == "Test warning"
            }),
            "decoded comments: {comments:?}"
        );
        assert!(comments
            .iter()
            .any(|(t, a, txt)| { *t == comment_type::HEADER && *a == 0x1000 && txt == "Header" }));
    }

    #[test]
    fn test_decode_unknown_type_partial_state() {
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        {
            let mut r = registry.write().unwrap();
            r.register_attribute("type");
            r.register_element("comment");
        }
        let comment_elem = ElementId::new("comment", 0);
        let mut enc = TreeEncoder::new(registry.clone());
        enc.open_element(&comment_elem);
        enc.write_string(&AttributeId::new("type", 0), "bogus");
        enc.close_element(&comment_elem);
        let root = enc.into_document().get_root().unwrap().clone();

        let mut comment = Comment::new(
            comment_type::HEADER,
            Address::new(0xaaaa),
            Address::new(0xbbbb),
            7,
            "sentinel",
        );
        comment.set_emitted(true);
        let mut dec = TreeDecoder::new(root, registry);
        assert_eq!(
            comment.decode(&mut dec).unwrap_err().to_string(),
            "Unknown comment type: bogus"
        );
        assert_eq!(comment.get_type(), 0);
        assert!(!comment.is_emitted());
        assert_eq!(comment.get_func_addr().as_u64(), 0xaaaa);
        assert_eq!(comment.get_addr().as_u64(), 0xbbbb);
        assert_eq!(comment.get_uniq(), 7);
        assert_eq!(comment.get_text(), "sentinel");
    }

    #[test]
    fn test_decode_missing_offset_partial_state() {
        let registry = std::sync::Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        {
            let mut r = registry.write().unwrap();
            for nm in &["type", "space", "offset", "XMLcontent"] {
                r.register_attribute(nm);
            }
            for nm in &["comment", "addr", "text"] {
                r.register_element(nm);
            }
        }
        let comment_elem = ElementId::new("comment", 0);
        let addr_elem = ElementId::new("addr", 0);
        let mut enc = TreeEncoder::new(registry.clone());
        enc.open_element(&comment_elem);
        enc.write_string(&AttributeId::new("type", 0), "warning");
        enc.open_element(&addr_elem);
        enc.write_string(&AttributeId::new("space", 0), "ram");
        enc.close_element(&addr_elem);
        enc.close_element(&comment_elem);
        let root = enc.into_document().get_root().unwrap().clone();

        let mut comment = Comment::new(
            comment_type::HEADER,
            Address::new(0xaaaa),
            Address::new(0xbbbb),
            7,
            "sentinel",
        );
        comment.set_emitted(true);
        let mut dec = TreeDecoder::new(root, registry);
        assert_eq!(
            comment.decode(&mut dec).unwrap_err().to_string(),
            "Address is missing offset"
        );
        assert_eq!(comment.get_type(), comment_type::WARNING);
        assert!(!comment.is_emitted());
        assert_eq!(comment.get_func_addr().as_u64(), 0xaaaa);
        assert_eq!(comment.get_addr().as_u64(), 0xbbbb);
        assert_eq!(comment.get_uniq(), 7);
        assert_eq!(comment.get_text(), "sentinel");
    }

    #[test]
    fn test_subsort_ordering() {
        let mut header = Subsort::default();
        header.set_header(header_type::HEADER_BASIC);
        let mut block0 = Subsort::default();
        block0.set_block(0, 5);
        let mut block1 = Subsort::default();
        block1.set_block(1, 0);
        // Header (index=-1, a signed int4 in Ghidra) sorts before all blocks.
        assert!(header < block0);
        assert!(block0 < block1);
        // Within one block, order then pos; 0xffffffff is the block tail.
        let mut tail = block0;
        tail.order = 0xffffffff;
        assert!(block0 < tail);
        // setHeader/setBlock leave pos untouched (caller-owned counter).
        let mut keyed = Subsort {
            index: 7,
            order: 9,
            pos: 4,
        };
        keyed.set_block(2, 3);
        assert_eq!(keyed.pos, 4);
        keyed.set_header(header_type::HEADER_UNPLACED);
        assert_eq!(keyed.pos, 4);
        assert_eq!(keyed.index, -1);
        assert_eq!(keyed.order, header_type::HEADER_UNPLACED);
    }

    #[test]
    fn test_comment_sorter_header() {
        let mut fd = crate::funcdata::Funcdata::new("test", Address::new(0x1000), 16);
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::HEADER,
            Address::new(0x1000),
            Address::new(0x1000),
            "Function header",
        );
        db.add_comment(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            "Inline warning",
        );
        let mut sorter = CommentSorter::new();
        sorter
            .setup_function_list(
                comment_type::HEADER | comment_type::WARNING,
                &fd,
                &db,
                false,
            )
            .unwrap();
        // The header comment places at header_basic (index == -1); the
        // warning at 0x2000 has no ops to place against and
        // displayUnplacedComments is false, so it is excised. The
        // setupHeader(header_basic) window (comment.cc:394-404) walks only
        // the (-1, header_basic, *) keys.
        sorter.setup_header(header_type::HEADER_BASIC);
        let mut headers = Vec::new();
        while sorter.has_next() {
            headers.push(sorter.get_next().get_text().to_string());
        }
        assert_eq!(headers, vec!["Function header"]);
        // The header_unplaced window is empty (nothing was excised into it).
        sorter.setup_header(header_type::HEADER_UNPLACED);
        assert!(!sorter.has_next());
    }

    #[test]
    fn test_comment_sorter_header_walk_state_machine() {
        // Op-less Funcdata: every placeable comment lands at (0, 0) per
        // comment.cc:316-318, so block 0 carries them.
        let mut fd = crate::funcdata::Funcdata::new("test", Address::new(0x1000), 16);
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::HEADER,
            Address::new(0x1000),
            Address::new(0x1000),
            "hdr",
        );
        db.add_comment(
            comment_type::WARNINGHEADER,
            Address::new(0x1000),
            Address::new(0x1000),
            "whdr",
        );
        db.add_comment(comment_type::WARNING, Address::new(0x1000), Address::new(0x1000), "w");
        db.add_comment(comment_type::USER1, Address::new(0x1000), Address::new(0x1800), "u");
        let mut sorter = CommentSorter::new();
        sorter
            .setup_function_list(0xffff_ffff, &fd, &db, true)
            .unwrap();
        // header_basic walk: hdr, whdr in pos order; the inline warning (no
        // header bit, addr == fad) belongs to block 0, not the header.
        sorter.setup_header(header_type::HEADER_BASIC);
        let mut walked = Vec::new();
        while sorter.has_next() {
            let c = sorter.get_next();
            assert!(!c.is_emitted());
            walked.push(c.get_text().to_string());
        }
        assert!(!sorter.has_next());
        assert_eq!(walked, vec!["hdr", "whdr"]);
        // header_unplaced walk: only the excised USER1 comment (block 0's
        // setBlock(0,0) placement took "w" first; "u" at 0x1800 also lands at
        // block 0 order 0 since there are no ops at all).
        sorter.setup_header(header_type::HEADER_UNPLACED);
        assert!(!sorter.has_next());
        // Block 0 drain: "w" and "u" at order 0, pos order preserved.
        sorter.setup_block_bounds(0);
        sorter.setup_op_stop(None);
        let mut drained = Vec::new();
        while sorter.has_next() {
            drained.push(sorter.get_next().get_text().to_string());
        }
        assert_eq!(drained, vec!["w", "u"]);
    }

    #[test]
    fn test_comment_sorter_op_landmark_interleaving() {
        // Interleaved landmark walk (printc.cc:3234 protocol): successive
        // setupOpList calls narrow opstop while start persists, emitting only
        // the comments between landmarks; a comment placed by the previous-op
        // rule (order 0xffffffff) only surfaces at the NULL landmark.
        let ram = ram_space();
        let fd_addr = Address::with_space(&ram, 0x1000);
        let mut fd = crate::funcdata::Funcdata::new("test", fd_addr, 16);
        let mk_block = |fd: &mut crate::funcdata::Funcdata, start: u64| {
            let bb = std::sync::Arc::new(std::sync::RwLock::new(
                crate::block::BlockBasic::new(
                    fd.bblocks.get_size() as i32,
                    Address::with_space(&ram, start),
                ),
            ));
            fd.bblocks.add_block(bb.clone());
            bb
        };
        let bb0: std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>> = mk_block(&mut fd, 0x1000);
        let bb1: std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>> = mk_block(&mut fd, 0x1009);
        // Install the instruction covers the way the C++ oracle construction
        // does (Funcdata::setBasicBlockRange, funcdata.hh:556): a manually
        // built block without a cover is an incomplete state — Ghidra's
        // BlockBasic::contains/getStop read only the cover (block.hh:476,
        // block.cc:2328), with no last-op fallback.
        for (bb, beg, end) in [( &bb0, 0x1000u64, 0x100au64), (&bb1, 0x1009, 0x100e)] {
            bb.write()
                .unwrap()
                .as_any_mut()
                .downcast_mut::<crate::block::BlockBasic>()
                .expect("basic block")
                .set_initial_range(
                    Address::with_space(&ram, beg),
                    Address::with_space(&ram, end),
                );
        }
        // bb0: ops at 0x1000, 0x100a (range [0x1000, 0x100a]).
        let op_a = fd.new_op(0, Address::with_space(&ram, 0x1000));
        fd.op_insert_end(&op_a, &bb0);
        let op_b = fd.new_op(0, Address::with_space(&ram, 0x100a));
        fd.op_insert_end(&op_b, &bb0);
        // bb1: ops at 0x1009, 0x100e (range [0x1009, 0x100e]).
        let op_h = fd.new_op(0, Address::with_space(&ram, 0x1009));
        fd.op_insert_end(&op_h, &bb1);
        let op_i = fd.new_op(0, Address::with_space(&ram, 0x100e));
        fd.op_insert_end(&op_i, &bb1);
        let mut db = CommentDatabaseInternal::new();
        let mut c = |tp: u32, ad: u64, txt: &str| {
            db.add_comment(tp, fd_addr, Address::with_space(&ram, ad), txt)
        };
        c(comment_type::WARNING, 0x1000, "at-a");
        // 0x1007: lower bound is op@0x1009 (bb1 does not contain 0x1007) but
        // the previous op op@0x1000's block does -> (0, 0xffffffff).
        c(comment_type::WARNING, 0x1007, "tail");
        c(comment_type::WARNING, 0x100a, "at-b");
        let mut sorter = CommentSorter::new();
        sorter
            .setup_function_list(0xffff_ffff, &fd, &db, false)
            .unwrap();
        sorter.setup_block_bounds(0);
        let mut seq = Vec::new();
        for op in [&op_a, &op_b] {
            sorter.setup_op_stop(Some(op));
            while sorter.has_next() {
                seq.push(sorter.get_next().get_text().to_string());
            }
        }
        sorter.setup_op_stop(None);
        while sorter.has_next() {
            seq.push(format!("null:{}", sorter.get_next().get_text()));
        }
        assert_eq!(seq, vec!["at-a", "at-b", "null:tail"]);
    }

    #[test]
    fn test_comment_sorter_dead_op_error() {
        let ram = ram_space();
        let fd_addr = Address::with_space(&ram, 0x1000);
        let mut fd = crate::funcdata::Funcdata::new("test", fd_addr, 16);
        // A dead op (created, never inserted into a block) at the comment's
        // address: findPosition must fail with the oracle's LowlevelError.
        let _dead = fd.new_op(0, Address::with_space(&ram, 0x1010));
        let mut db = CommentDatabaseInternal::new();
        db.add_comment(
            comment_type::WARNING,
            fd_addr,
            Address::with_space(&ram, 0x1010),
            "doomed",
        );
        let mut sorter = CommentSorter::new();
        let err = sorter
            .setup_function_list(0xffff_ffff, &fd, &db, true)
            .unwrap_err();
        assert_eq!(err.to_string(), "Dead op reaching CommentSorter");
    }

    #[test]
    fn test_comment_sorter_direct_protocol_walks() {
        // The printc.rs consumers (emit_comment_block_tree /
        // emit_comment_group) drive the state machine directly since the
        // legacy Vec snapshots were removed: a block drain is
        // setup_block_bounds + setup_op_stop(None) (the cc:3265-3266 form),
        // and successive op landmarks narrow opstop while start persists
        // (the cc:3234 interleaving protocol).
        let ram = ram_space();
        let fd_addr = Address::with_space(&ram, 0x1000);
        let mut fd = crate::funcdata::Funcdata::new("test", fd_addr, 16);
        let bb0: std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>> =
            std::sync::Arc::new(std::sync::RwLock::new(crate::block::BlockBasic::new(
                0,
                Address::with_space(&ram, 0x1000),
            )));
        fd.bblocks.add_block(bb0.clone());
        // Legal cover [0x1000, 0x100a] as pinned by Funcdata::setBasicBlockRange
        // in the C++ oracle construction (funcdata.hh:556): all three comments
        // sit at exact op addresses, so the backupOp path would place them
        // identically, but the contains path is the one under test.
        bb0.write()
            .unwrap()
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("basic block")
            .set_initial_range(
                Address::with_space(&ram, 0x1000),
                Address::with_space(&ram, 0x100a),
            );
        let mut ops = Vec::new();
        for off in [0x1000u64, 0x1005, 0x100a] {
            let op = fd.new_op(0, Address::with_space(&ram, off));
            fd.op_insert_end(&op, &bb0);
            ops.push(op);
        }
        let mut db = CommentDatabaseInternal::new();
        let mut c = |ad: u64, txt: &str| {
            db.add_comment(
                comment_type::WARNING,
                fd_addr,
                Address::with_space(&ram, ad),
                txt,
            )
        };
        c(0x1000, "a");
        c(0x1005, "b");
        c(0x100a, "d");
        let mut sorter = CommentSorter::new();
        sorter
            .setup_function_list(0xffff_ffff, &fd, &db, false)
            .unwrap();
        // Full block drain: setup_block_bounds(0) + setup_op_stop(None).
        sorter.setup_block_bounds(0);
        sorter.setup_op_stop(None);
        let mut drain = Vec::new();
        while sorter.has_next() {
            drain.push(sorter.get_next().get_text().to_string());
        }
        assert_eq!(drain, vec!["a", "b", "d"]);
        // Interleaved landmarks: setup_block_bounds resets start to the
        // block window, then each op landmark emits only the comments at or
        // before it (comment.cc:362-374, start persists across landmarks).
        sorter.setup_block_bounds(0);
        let mut seq = Vec::new();
        for op in &ops {
            sorter.setup_op_stop(Some(op));
            while sorter.has_next() {
                seq.push(sorter.get_next().get_text().to_string());
            }
        }
        sorter.setup_op_stop(None);
        while sorter.has_next() {
            seq.push(format!("null:{}", sorter.get_next().get_text()));
        }
        assert_eq!(seq, vec!["a", "b", "d"]);
    }

    #[test]
    fn test_comment_emitted_interior_mutability() {
        // `mutable bool emitted` (comment.hh:50): setEmitted works through a
        // shared reference, so the sorter's walk (const getNext) plus
        // PrintLanguage::emitLineComment's comm->setEmitted(true)
        // (printlanguage.cc:648) reproduce the oracle's shared-flag
        // double-emission guard.
        let mut comm = Comment::new(
            comment_type::WARNING,
            Address::new(0x1000),
            Address::new(0x2000),
            0,
            "w",
        );
        let shared = &comm;
        assert!(!shared.is_emitted());
        shared.set_emitted(true);
        assert!(shared.is_emitted());
        shared.set_emitted(false);
        assert!(!shared.is_emitted());
        comm.set_emitted(true);
        assert!(comm.is_emitted());
    }
}

