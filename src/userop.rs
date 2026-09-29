//! User-defined P-code operations (CALLOTHER) management.
//!
//! Corresponds to Ghidra's `userop.hh` / `userop.cc` (1009 lines).
//!
//! The CALLOTHER opcode represents user-defined operations. This module manages
//! the association between CALLOTHER constant ids and specialized behavior
//! classes (volatile read/write, segment ops, jump-table assist, string ops,
//! injected code, etc.).
//!
//! Key classes:
//! - `UserPcodeOp`: base class for user-defined op definitions
//! - `UnspecializedPcodeOp`: default for unmapped CALLOTHERs
//! - `UserOpManage`: manager holding all registered user ops
//!
//! # Status
//! The typed descriptor registry has a locked 12.0.4 behavior fixture.
//! Dynamic specialized semantics remain at module L2 as documented in
//! `docs/api/userop.md`.

use std::collections::HashMap;
use std::sync::Arc;
use crate::op::PcodeOp;
use crate::type_system::Datatype;

/// User-op class encoded as an enum.
/// Corresponds to Ghidra's `UserPcodeOp::userop_type` (userop.hh:56).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UserOpType {
    Unspecialized = 1,
    Injected = 2,
    VolatileRead = 3,
    VolatileWrite = 4,
    Segment = 5,
    JumpAssist = 6,
    StringData = 7,
    Datatype = 8,
}

/// Boolean properties for CALLOTHER ops.
/// Corresponds to Ghidra's `UserPcodeOp::userop_flags` (userop.hh:50).
pub mod userop_flags {
    pub const ANNOTATION_ASSIGNMENT: u32 = 1;
    pub const NO_OPERATOR: u32 = 2;
    pub const DISPLAY_STRING: u32 = 4;
}

/// Built-in CALLOTHER ids. Faithful to `UserPcodeOp::BUILTIN_*`
/// (userop.cc:30-35). These are large, distinct values used as the
/// CALLOTHER constant id passed in input[0] of a CPUI_CALLOTHER op.
pub const BUILTIN_STRINGDATA: u32 = 0x1000_0000;
pub const BUILTIN_VOLATILE_READ: u32 = 0x1000_0001;
pub const BUILTIN_VOLATILE_WRITE: u32 = 0x1000_0002;
/// Built-in id for `memcpy`. Used by RuleStringStore.
pub const BUILTIN_MEMCPY: u32 = 0x1000_0003;
/// Built-in id for `strncpy` (Ghidra names it "strcpy"). Used by
/// RuleStringCopy for 1-byte (char) elements.
pub const BUILTIN_STRNCPY: u32 = 0x1000_0004;
/// Built-in id for `wcsncpy`. Used by RuleStringCopy for 2-byte
/// (wchar_t) elements.
pub const BUILTIN_WCSNCPY: u32 = 0x1000_0005;

/// The base class for a detailed definition of a user-defined p-code operation.
/// Corresponds to Ghidra's `UserPcodeOp` (userop.hh:47) as flattened with the
/// `InjectedUserOp` subclass (userop.hh:158): the `inject_id` field holds
/// `InjectedUserOp::injectid` (-1 for ops that are not injected).
#[derive(Debug, Clone)]
pub struct UserPcodeOp {
    /// Low-level name of the p-code operator
    pub name: String,
    /// Encoded class type
    pub op_type: UserOpType,
    /// Index passed in the CALLOTHER op (the constant id)
    pub userop_index: i32,
    /// Boolean attributes (userop_flags)
    pub flags: u32,
    /// Id of the injected payload for `InjectedUserOp` (-1 otherwise)
    pub inject_id: i32,
    /// Factory-canonical output type carried by a `DatatypeUserOp`.
    /// Other descriptor kinds leave this unset, matching the virtual base
    /// implementation's null return.
    local_output_type: Option<Arc<Datatype>>,
    /// Factory-canonical input types carried by a `DatatypeUserOp`.  Ghidra's
    /// constructor appends only non-null arguments, so this vector contains
    /// no holes and CALLOTHER slot 1 maps to element 0.
    local_input_types: Vec<Arc<Datatype>>,
}

impl UserPcodeOp {
    // Ghidra: userop.hh:47 UserPcodeOp::new
    pub fn new(name: String, op_type: UserOpType, index: i32) -> Self {
        Self {
            name,
            op_type,
            userop_index: index,
            flags: 0,
            inject_id: -1,
            local_output_type: None,
            local_input_types: Vec::new(),
        }
    }

    // Ghidra: userop.hh:47 UserPcodeOp::getName
    pub fn get_name(&self) -> &str { &self.name }
    // Ghidra: userop.hh:47 UserPcodeOp::getType
    pub fn get_type(&self) -> UserOpType { self.op_type }
    // Ghidra: userop.hh:47 UserPcodeOp::getIndex
    pub fn get_index(&self) -> i32 { self.userop_index }
    // Ghidra: userop.hh:47 UserPcodeOp::getDisplay
    pub fn get_display(&self) -> u32 {
        self.flags & (userop_flags::ANNOTATION_ASSIGNMENT | userop_flags::NO_OPERATOR | userop_flags::DISPLAY_STRING)
    }

    // Ghidra: userop.hh:101 UserPcodeOp::getOutputLocal
    /// Return the descriptor's fixed output type, if one was specified.
    pub fn get_output_local(&self) -> Option<&Arc<Datatype>> {
        self.local_output_type.as_ref()
    }

    // Ghidra: userop.hh:108 UserPcodeOp::getInputLocal
    /// Return the descriptor's fixed input type for a raw CALLOTHER slot.
    /// Slot zero is the user-op id, so typed operands begin at slot one.
    pub fn get_input_local(&self, slot: i32) -> Option<&Arc<Datatype>> {
        let typed_slot = usize::try_from(slot.checked_sub(1)?).ok()?;
        self.local_input_types.get(typed_slot)
    }

    // Ghidra: userop.hh:47 UserPcodeOp::getOperatorName
    /// Get the symbol representing this operation in decompiled code.
    /// Faithful to `UserPcodeOp::getOperatorName` (userop.hh:94-95).
    pub fn get_operator_name(&self, _op: &PcodeOp) -> String {
        self.name.clone()
    }

    // Ghidra: userop.cc:37 UserPcodeOp::extractAnnotationSize
    /// Assign a size to an annotation input. Faithful to
    /// `UserPcodeOp::extractAnnotationSize` (userop.cc:37-41).
    /// Base class throws; subclasses override.
    pub fn extract_annotation_size(&self) -> i32 {
        panic!("Unexpected annotation input for CALLOTHER {}", self.name);
    }

    // Ghidra: userop.hh:47 UserPcodeOp::isVolatileRead
    /// Check if this is a volatile read op.
    pub fn is_volatile_read(&self) -> bool {
        self.op_type == UserOpType::VolatileRead
    }

    // Ghidra: userop.hh:47 UserPcodeOp::isVolatileWrite
    /// Check if this is a volatile write op.
    pub fn is_volatile_write(&self) -> bool {
        self.op_type == UserOpType::VolatileWrite
    }

    // Ghidra: userop.hh:47 UserPcodeOp::isSegment
    /// Check if this is a segment op.
    pub fn is_segment(&self) -> bool {
        self.op_type == UserOpType::Segment
    }

    // Ghidra: userop.hh:47 UserPcodeOp::isJumpAssist
    /// Check if this is a jump-assist op.
    pub fn is_jump_assist(&self) -> bool {
        self.op_type == UserOpType::JumpAssist
    }

    // Ghidra: userop.hh:47 UserPcodeOp::isInjected
    /// Check if this is an injected op.
    pub fn is_injected(&self) -> bool {
        self.op_type == UserOpType::Injected
    }

    // Ghidra: userop.hh:47 UserPcodeOp::isStringData
    /// Check if this is a string-data op.
    pub fn is_string_data(&self) -> bool {
        self.op_type == UserOpType::StringData
    }
}

/// A user defined p-code op with input/output data-types.
/// Corresponds to Ghidra's `DatatypeUserOp` (userop.hh:140).
#[derive(Debug, Clone)]
pub struct DatatypeUserOp {
    pub base: UserPcodeOp,
}

impl DatatypeUserOp {
    // Ghidra: userop.cc:55 DatatypeUserOp::new
    pub fn new(name: String, index: i32, out: Option<Arc<Datatype>>, ins: Vec<Option<Arc<Datatype>>>) -> Self {
        let mut base = UserPcodeOp::new(name, UserOpType::Datatype, index);
        base.local_output_type = out;
        base.local_input_types = ins.into_iter().take(4).flatten().collect();
        Self { base }
    }

    // Ghidra: userop.cc:70 DatatypeUserOp::getOutputLocal
    /// Get the output data-type. Faithful to `DatatypeUserOp::getOutputLocal`.
    pub fn get_output_local(&self) -> Option<&Arc<Datatype>> {
        self.base.get_output_local()
    }

    // Ghidra: userop.cc:76 DatatypeUserOp::getInputLocal
    /// Get the input data-type at a given slot. Faithful to
    /// `DatatypeUserOp::getInputLocal` (userop.cc:76-83).
    pub fn get_input_local(&self, slot: i32) -> Option<&Arc<Datatype>> {
        self.base.get_input_local(slot)
    }
}

/// A volatile read user-op. Faithful to `VolatileReadOp` (userop.hh:188).
/// Returns the size of the volatile varnode being read.
#[derive(Debug, Clone)]
pub struct VolatileReadOp {
    pub base: UserPcodeOp,
}

impl VolatileReadOp {
    // Ghidra: userop.hh:188 VolatileReadOp::new
    pub fn new(name: String, index: i32) -> Self {
        Self { base: UserPcodeOp::new(name, UserOpType::VolatileRead, index) }
    }

    // Ghidra: userop.cc:143 VolatileReadOp::extractAnnotationSize
    /// Extract the annotation size for a volatile read. Faithful to
    /// `VolatileReadOp::extractAnnotationSize` (userop.cc:143-170).
    pub fn extract_annotation_size(vn: &crate::varnode::Varnode) -> i32 {
        vn.get_size() as i32
    }
}

/// A volatile write user-op. Faithful to `VolatileWriteOp` (userop.hh:203).
#[derive(Debug, Clone)]
pub struct VolatileWriteOp {
    pub base: UserPcodeOp,
}

impl VolatileWriteOp {
    // Ghidra: userop.hh:203 VolatileWriteOp::new
    pub fn new(name: String, index: i32) -> Self {
        Self { base: UserPcodeOp::new(name, UserOpType::VolatileWrite, index) }
    }

    // Ghidra: userop.cc:174 VolatileWriteOp::extractAnnotationSize
    /// Extract the annotation size for a volatile write. Faithful to
    /// `VolatileWriteOp::extractAnnotationSize` (userop.cc:174-186).
    pub fn extract_annotation_size(vn: &crate::varnode::Varnode) -> i32 {
        vn.get_size() as i32
    }

    // Ghidra: userop.cc:159 VolatileWriteOp::getInputLocal
    /// Input data-type of the volatile-write CALLOTHER, faithful to
    /// `VolatileWriteOp::getInputLocal` (userop.cc:159-172) — the write arm
    /// mirror of the VOLATILEOUT read arm (`VolatileReadOp::getOutputLocal`,
    /// userop.cc:128-141, wired in varnode.rs `op_output_type_local`):
    /// - cc:162-163: only input slot 2 (the value being written) of a
    ///   special-propagating op qualifies — the `special_prop` addlflag is
    ///   set by `Funcdata::replaceVolatile` only when the source varnode
    ///   was type-locked (funcdata_varnode.cc:761-762);
    /// - cc:164: `addr = op->getIn(1)->getAddr()` — the address of the
    ///   volatile memory (the annotation varnode built by newCodeRef);
    /// - cc:165: `size = op->getIn(2)->getSize()` — the size of the memory
    ///   being written (the written value's size);
    /// - cc:166-169: `queryProperties(addr,size,op->getAddr(),vflags)` on
    ///   the global scope (`uint4 vflags = 0` out-parameter discarded
    ///   unread) → `entry->getSizedType(addr,size)`; a null entry returns
    ///   null (cc:170-171).
    /// The `symboltab` thread stands in for the descriptor's
    /// `glb->symboltab` edge (the `Architecture *glb` field, userop.hh:74) —
    /// same Option-thread shape as the read arm (VARNODE-CALLOTHER-
    /// VOLATILEOUT-0001). The descriptor selection itself (C++ virtual
    /// dispatch on the VolatileWriteOp record selected by the CALLOTHER
    /// index constant, typeop.cc:855-863) is the dispatch site's duty —
    /// see the varnode.rs `op_input_type_local` CALLOTHER wiring row
    /// (USEROP-VOLATILEWRITE-INPUTLOCAL-0001) on the TODO board.
    pub fn get_input_local(
        op: &PcodeOp,
        slot: i32,
        type_factory: &Arc<std::sync::RwLock<crate::type_system::typefactory::TypeFactory>>,
        symboltab: Option<&Arc<std::sync::RwLock<crate::database::Database>>>,
    ) -> Option<Arc<Datatype>> {
        // cc:162-163: `if (!op->doesSpecialPropagation() || slot != 2)
        // return 0`.
        if !op.does_special_propagation() || slot != 2 {
            return None;
        }
        let symboltab = symboltab?;
        // cc:164: address of the volatile memory (annotation input, slot 1).
        let addr = *op.get_in(1)?.read().unwrap().get_addr();
        // cc:165: size of the memory being written (the value, slot 2).
        let size = op.get_in(2)?.read().unwrap().get_size() as i32;
        // cc:167: usepoint = the op's own address; vflags discarded.
        let usepoint = op.get_addr();
        let entry = {
            let db = symboltab
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            db.query_properties_entry(db.global_scope_id, addr, size, usepoint)?
        };
        // The Database read guard is dropped before taking the factory write
        // lock (get_sized_type mutates the factory caches) — same lock order
        // as the read arm.
        let mut factory = type_factory
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entry.get_sized_type(&mut factory, addr, size)
    }
}

/// A segment op. Faithful to `SegmentOp` (userop.hh:264; `TermPatternOp`
/// userop.hh:232). Handles segmented addressing (e.g., x86 real mode far
/// pointers).
#[derive(Debug, Clone)]
pub struct SegmentOp {
    pub base: UserPcodeOp,
    /// The address space this segment op operates on. Faithful to the
    /// `spc` field (userop.hh:265); `space` holds the space INDEX used by
    /// the segment-op vector in `UserOpManage::registerOp`.
    pub space: u32,
    /// The resolved `spc` AddrSpace handle (enum stand-in).
    pub space_id: crate::space::AddressSpace,
    /// Size in bytes of the base/selector input (0 = no base term).
    /// Faithful to `baseinsize` (userop.hh:241).
    pub baseinsize: i32,
    /// Size in bytes of the near-pointer input. Faithful to `innerinsize`.
    pub innerinsize: i32,
    /// Constant resolution varnode. Faithful to `constresolve`
    /// (userop.hh:249).
    pub constresolve: Option<crate::fspec::VarnodeData>,
    /// Id of the executable p-code payload. Faithful to `injectId`
    /// (userop.hh:246).
    pub inject_id: i32,
    /// Base resolution: how the segment base is computed.
    pub supports_index: bool,
    /// True if the joined pair base:near acts as a far pointer. Faithful to
    /// `supportsfarpointer` (userop.hh:269); set by the `farpointer="yes"`
    /// attribute in `<segmentop>` (userop.cc:240 `ATTRIB_FARPOINTER`).
    pub supports_far_pointer: bool,
}

impl SegmentOp {
    // Ghidra: userop.cc:183 SegmentOp::new
    pub fn new(name: String, index: i32) -> Self {
        Self {
            base: UserPcodeOp::new(name, UserOpType::Segment, index),
            space: 0,
            space_id: crate::space::AddressSpace::Register,
            baseinsize: 0,
            innerinsize: 0,
            constresolve: None,
            inject_id: -1,
            supports_index: false,
            supports_far_pointer: false,
        }
    }

    // Ghidra: userop.cc:183 SegmentOp::hasFarPointerSupport
    /// Return true if this op supports far pointers. Faithful to
    /// `SegmentOp::hasFarPointerSupport` (userop.hh:274).
    pub fn has_far_pointer_support(&self) -> bool {
        self.supports_far_pointer
    }

    // Ghidra: userop.cc:218 SegmentOp::execute
    /// Constant-fold a SEGMENTOP given constant inputs.
    ///
    /// Faithful to `SegmentOp::execute` (userop.cc:218-223). Ghidra evaluates
    /// the `<pcode>` body of the `<segmentop>` via `pcodeinjectlib`:
    ///   `ExecutablePcode *script = getPayload(injectId); return script->evaluate(input);`
    /// Rugra has no pcode-inject engine, so we evaluate the canonical
    /// segmented-address formula directly. For the only architecture Rugra
    /// models a segment on (x86 16-bit real mode, see
    /// `x86-16-real.pspec`/`x86-16.pspec`), the injected p-code is:
    ///   `res = (zext(base) << 4) + zext(inner);`
    /// i.e. `linear = (selector << 4) + offset`. This is the general
    /// real-mode form `segment_base + offset` with a fixed `base << 4`
    /// shift, matching Ghidra's bundled cspec definitions.
    ///
    /// Inputs follow Ghidra's `bindlist` ordering (userop.cc:198-215): with a
    /// base term present, `[base, inner]`; with no base term, `[inner]` only.
    /// Returns `None` if the input arity does not match a recognised segment
    /// form (Ghidra always has 1 or 2 inputs, declared in `decode`,
    /// userop.cc:280-289).
    pub fn execute(&self, inputs: &[u64]) -> Option<u64> {
        match inputs.len() {
            // base term present: linear = (base << 4) + inner
            2 => Some((inputs[0] << 4).wrapping_add(inputs[1])),
            // no base term (near pointer): linear = inner
            1 => Some(inputs[0]),
            _ => None,
        }
    }
}

/// Jump-table assist op. Faithful to `JumpAssistOp` (userop.hh:294).
/// Stores injection ids for switch-table resolution scripts.
#[derive(Debug, Clone)]
pub struct JumpAssistOp {
    pub base: UserPcodeOp,
    /// Injection id for index2case script (-1 if none).
    pub index2case: i32,
    /// Injection id for index2addr script (must be present).
    pub index2addr: i32,
    /// Injection id for default-address script (must be present).
    pub defaultaddr: i32,
    /// Injection id for calcsize script (-1 if none).
    pub calcsize: i32,
}

impl JumpAssistOp {
    // Ghidra: userop.cc:293 JumpAssistOp::new
    pub fn new(name: String, index: i32) -> Self {
        Self {
            base: UserPcodeOp::new(name, UserOpType::JumpAssist, index),
            index2case: -1,
            index2addr: -1,
            defaultaddr: -1,
            calcsize: -1,
        }
    }

    // Ghidra: userop.cc:293 JumpAssistOp::getIndex2case
    pub fn get_index2case(&self) -> i32 { self.index2case }
    // Ghidra: userop.cc:293 JumpAssistOp::getIndex2addr
    pub fn get_index2addr(&self) -> i32 { self.index2addr }
    // Ghidra: userop.cc:293 JumpAssistOp::getDefaultAddr
    pub fn get_default_addr(&self) -> i32 { self.defaultaddr }
    // Ghidra: userop.cc:293 JumpAssistOp::getCalcSize
    pub fn get_calc_size(&self) -> i32 { self.calcsize }
}

/// Internal string op. Displays as a quoted string in decompiled output.
/// Faithful to `InternalStringOp` (userop.hh:312).
#[derive(Debug, Clone)]
pub struct InternalStringOp {
    pub base: UserPcodeOp,
}

impl InternalStringOp {
    // Ghidra: userop.cc:355 InternalStringOp::new
    pub fn new(name: String, index: i32) -> Self {
        Self { base: UserPcodeOp::new(name, UserOpType::StringData, index) }
    }
}

/// Manager for all registered user-defined p-code operations.
/// Corresponds to Ghidra's `UserOpManage` (userop.hh).
pub struct UserOpManage {
    /// All registered user ops by index
    pub ops: Vec<Option<Box<UserPcodeOp>>>,
    /// Map from name to index
    pub name_map: HashMap<String, i32>,
    /// Segment ops registered by space index. Faithful to the segment-op
    /// vector in Ghidra's UserOpManage (userop.hh:347 `getSegmentOp`).
    pub segment_ops: HashMap<i32, SegmentOp>,
    /// Jump-assist ops decoded from `<jumpassist>` elements.  Ghidra stores
    /// these as `JumpAssistOp` records in the same `useroplist`; Rugra
    /// keeps the 4 inject ids in this side vector.
    pub jump_assist_ops: Vec<JumpAssistOp>,
    /// Built-in id (BUILTIN_*) → user op. Faithful to Ghidra's
    /// `UserOpManage::builtinmap` (userop.hh:342), populated by
    /// `registerBuiltin(uint4)` (userop.cc:432-484).
    pub builtin_map: HashMap<u32, Box<UserPcodeOp>>,
}

impl UserOpManage {
    // Ghidra: userop.cc:367 UserOpManage::new
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            name_map: HashMap::new(),
            segment_ops: HashMap::new(),
            jump_assist_ops: Vec::new(),
            builtin_map: HashMap::new(),
        }
    }

    // Ghidra: userop.cc:367 UserOpManage::getSegmentOp
    /// Look up the SegmentOp for the given space index. Faithful to
    /// `UserOpManage::getSegmentOp` (userop.hh:347).
    pub fn get_segment_op(&self, space_idx: i32) -> Option<&SegmentOp> {
        self.segment_ops.get(&space_idx)
    }

    // Ghidra: userop.cc:392 UserOpManage::initialize (per-op create+crossref)
    /// Create a new unspecialized op with the next auto index and
    /// cross-reference it (the per-op step of `initialize`,
    /// userop.cc:392-403; `registerOp` itself is `register_user_op`).
    pub fn register_op(&mut self, name: String, op_type: UserOpType) -> i32 {
        let index = self.ops.len() as i32;
        self.name_map.insert(name.clone(), index);
        self.ops
            .push(Some(Box::new(UserPcodeOp::new(name, op_type, index))));
        index
    }

    // Ghidra: userop.cc:490 UserOpManage::registerOp
    /// Register a user op at an EXPLICIT index, the exact
    /// `UserOpManage::registerOp(UserPcodeOp*)` crossref discipline
    /// (userop.cc:490-532): a name already mapped under a different index is
    /// a conflict (LowlevelError), an occupied slot with the same name is a
    /// customization (the old descriptor is replaced), and the index/name
    /// crossrefs are both (re)written. Returns the index on success.
    pub fn register_op_at_index(&mut self, name: &str, index: i32) -> Result<i32, String> {
        if index < 0 {
            return Err("UserOp not assigned an index".to_string());
        }
        if let Some(&other) = self.name_map.get(name) {
            if other != index {
                return Err(format!("Conflicting indices for userop name {name}"));
            }
        }
        while self.ops.len() <= index as usize {
            self.ops.push(None);
        }
        if let Some(existing) = &self.ops[index as usize] {
            if existing.get_name() != name {
                return Err(format!(
                    "User op {name} has same index as {}",
                    existing.get_name()
                ));
            }
            // We assume this registration customizes an existing userop
            // (the old spec is replaced — userop.cc:520-521).
        }
        self.ops[index as usize] = Some(Box::new(UserPcodeOp::new(
            name.to_string(),
            UserOpType::Unspecialized,
            index,
        )));
        self.name_map.insert(name.to_string(), index);
        Ok(index)
    }

    // Ghidra: userop.cc:392 UserOpManage::initialize
    /// Initialize the base user-op table from the translator's user-defined
    /// p-code op names (`translate->getUserOpNames`, the .sla `userop` list
    /// in CALLOTHER-index order). Faithful to `UserOpManage::initialize`
    /// (userop.cc:392-403): empty names are skipped, everything else is
    /// registered as an `UnspecializedPcodeOp` at its SLEIGH index — the
    /// base layer that later `<callotherfixup>`/`<segmentop>`/`<jumpassist>`
    /// decodes customize through the same registerOp index discipline. A
    /// registerOp LowlevelError (index conflict) propagates as `Err`.
    pub fn initialize(&mut self, basicops: &[&[u8]]) -> Result<(), String> {
        for (i, raw) in basicops.iter().enumerate() {
            if raw.is_empty() {
                continue;
            }
            let name = String::from_utf8_lossy(raw).into_owned();
            self.register_op_at_index(&name, i as i32).map(|_| ())?;
        }
        Ok(())
    }

    // Ghidra: userop.cc:408 UserOpManage::getOp
    /// Get a user op by its CALLOTHER index.  Faithful to `getOp(uint4)`
    /// (userop.cc:408-415): indices within the registered list index it
    /// directly, larger built-in ids fall through to `builtinmap`.
    pub fn get_op(&self, index: i32) -> Option<&UserPcodeOp> {
        if index >= 0 && (index as usize) < self.ops.len() {
            self.ops[index as usize].as_deref()
        } else {
            self.builtin_map.get(&(index as u32)).map(Box::as_ref)
        }
    }

    // Ghidra: userop.hh:101 UserPcodeOp::getOutputLocal
    /// Query fixed output metadata through the descriptor selected by the
    /// CALLOTHER index. `None` is the base-class result and tells TypeOp to
    /// use its size-derived fallback.
    pub fn get_output_local(&self, index: i32) -> Option<&Arc<Datatype>> {
        self.get_op(index)?.get_output_local()
    }

    // Ghidra: userop.hh:108 UserPcodeOp::getInputLocal
    /// Query fixed input metadata through the descriptor selected by the
    /// CALLOTHER index, including DatatypeUserOp's slot-minus-one mapping.
    pub fn get_input_local(&self, index: i32, slot: i32) -> Option<&Arc<Datatype>> {
        self.get_op(index)?.get_input_local(slot)
    }

    // Ghidra: userop.cc:367 UserOpManage::getIndexByName
    /// Get a user op index by name.
    pub fn get_index_by_name(&self, name: &str) -> Option<i32> {
        self.name_map.get(name).copied()
    }

    // Ghidra: userop.cc:367 UserOpManage::numOps
    /// Get the number of registered ops.
    pub fn num_ops(&self) -> usize { self.ops.len() }

    // Ghidra: userop.cc:367 UserOpManage::registerBuiltinById
    /// Ensure an active record exists for the given built-in op id. Faithful
    /// to Ghidra `UserOpManage::registerBuiltin(uint4)` (userop.cc:432-484).
    /// The built-in id (one of the `BUILTIN_*` constants) is stored in
    /// `builtin_map` and returned as the CALLOTHER constant index. Idempotent:
    /// repeated calls return the same id.
    pub fn register_builtin_by_id(&mut self, builtin_id: u32) -> u32 {
        self.try_register_builtin_by_id(builtin_id)
            .unwrap_or_else(|message| panic!("{message}"))
    }

    // Ghidra: userop.cc:432 UserOpManage::registerBuiltin
    /// Ensure an active record exists for the given built-in op id — the 1:1
    /// port of `UserOpManage::registerBuiltin(uint4)` (userop.cc:432-484).
    /// First registration wins exactly like `builtinmap` (cc:435-437); the
    /// bad-id arm throws without mutating any state (cc:479-480).
    ///
    /// The `type_factory` thread stands in for the oracle's `glb->types`
    /// reach (the `Architecture *glb` field, userop.hh:74/327): with it, the
    /// three DatatypeUserOp builtins (MEMCPY/STRNCPY/WCSNCPY) construct
    /// their ptr/char pointer metadata on demand exactly as cc:449-477
    /// builds it (see `datatype_builtin_local_types`); without it they fall
    /// to the metadata-less compat record. Rugra deliberately threads the
    /// factory instead of a back-pointer — the documented 2026-08-25 方案论证
    /// (docs/api/varnode.md, TYPEOP-LOCALTYPE-CALLOTHER-0001): a back-pointer
    /// on the process-wide shared factory would be cross-Architecture
    /// last-writer-wins pollution, and the reliable set point precedes the
    /// Arc wrap. `default_space_word_size` stands in for
    /// `glb->getDefaultDataSpace()->getWordSize()` (cc:452/462/472) — 1 for
    /// the locked x86-64 gcc corpus (ram space; same pin as the constseq
    /// typed entry).
    pub fn register_builtin(
        &mut self,
        builtin_id: u32,
        type_factory: Option<&Arc<std::sync::RwLock<crate::type_system::typefactory::TypeFactory>>>,
        default_space_word_size: usize,
    ) -> Result<u32, String> {
        if self.builtin_map.contains_key(&builtin_id) {
            return Ok(builtin_id);
        }
        let (name, op_type) = match builtin_id {
            BUILTIN_STRINGDATA => ("stringdata", UserOpType::StringData),
            BUILTIN_VOLATILE_READ => ("read_volatile", UserOpType::VolatileRead),
            BUILTIN_VOLATILE_WRITE => ("write_volatile", UserOpType::VolatileWrite),
            BUILTIN_MEMCPY => ("builtin_memcpy", UserOpType::Datatype),
            BUILTIN_STRNCPY => ("builtin_strncpy", UserOpType::Datatype),
            BUILTIN_WCSNCPY => ("builtin_wcsncpy", UserOpType::Datatype),
            _ => return Err("Bad built-in userop id".to_string()),
        };
        // userop.cc:439-481: per-id construction. The Datatype arms build a
        // full DatatypeUserOp with on-demand local metadata when the
        // TypeFactory thread is present (cc:449-477); without the thread the
        // metadata-less compat record is kept for callers that have no
        // owning Architecture.
        let mut op = if op_type == UserOpType::Datatype {
            match Self::datatype_builtin_local_types(
                builtin_id,
                type_factory,
                default_space_word_size,
            ) {
                Some((out_type, input_types)) => {
                    DatatypeUserOp::new(name.to_string(), builtin_id as i32, Some(out_type), input_types).base
                }
                None => UserPcodeOp::new(name.to_string(), op_type, builtin_id as i32),
            }
        } else {
            UserPcodeOp::new(name.to_string(), op_type, builtin_id as i32)
        };
        // userop.cc:355-359 InternalStringOp: the stringdata record carries
        // the display_string flag, steering PrintC::opCallother to the
        // character-constant emit instead of functional syntax.
        if builtin_id == BUILTIN_STRINGDATA {
            op.flags |= userop_flags::DISPLAY_STRING;
        }
        // userop.cc:443-447: the on-demand defaults construct the volatile
        // pair with functional=false — VolatileReadOp carries no_operator
        // (userop.hh:190-191), VolatileWriteOp carries annotation_assignment
        // (userop.hh:205-206). Only a cspec `format="functional"` element
        // (decodeVolatile, userop.cc:566-570) produces the zero-flag form.
        if builtin_id == BUILTIN_VOLATILE_READ {
            op.flags |= userop_flags::NO_OPERATOR;
        } else if builtin_id == BUILTIN_VOLATILE_WRITE {
            op.flags |= userop_flags::ANNOTATION_ASSIGNMENT;
        }
        self.builtin_map.insert(builtin_id, Box::new(op));
        Ok(builtin_id)
    }

    // Ghidra: userop.cc:432 UserOpManage::registerBuiltin (DatatypeUserOp arms)
    /// On-demand local-type construction for the three DatatypeUserOp
    /// builtins — the cc:449-477 slice of `registerBuiltin`, exactly as it
    /// builds them:
    /// - MEMCPY (cc:449-457): element `getTypeVoid()`;
    /// - STRNCPY (cc:459-467): element `getTypeChar(getSizeOfChar())`;
    /// - WCSNCPY (cc:469-477): element `getTypeChar(getSizeOfWChar())`;
    /// - every case: `ptrSize = getSizeOfPointer()` (cc:451/461/471),
    ///   `ptrType = getTypePointer(ptrSize, element, defaultDataSpace
    ///   .wordSize)` (cc:454/464/474), `intType = getBase(4, TYPE_INT)`
    ///   (cc:455/465/475), and the constructor layout
    ///   `out = in0 = in1 = ptrType, in2 = intType`
    ///   (cc:456/466/476 — DatatypeUserOp ctor userop.cc:55-68 compacts the
    ///   four leading non-null type arguments).
    /// Returns `None` when no TypeFactory thread is available — the
    /// metadata-less compat form. Live-pipeline equivalence holds either
    /// way: the only in-flight Datatype registrations (constseq
    /// `StringSequence/HeapSequence::buildStringCopy`, constseq.cc:360/751)
    /// go through the typed entry first, so first-wins yields the identical
    /// record.
    fn datatype_builtin_local_types(
        builtin_id: u32,
        type_factory: Option<&Arc<std::sync::RwLock<crate::type_system::typefactory::TypeFactory>>>,
        default_space_word_size: usize,
    ) -> Option<(
        Arc<Datatype>,
        Vec<Option<Arc<Datatype>>>,
    )> {
        let factory_arc = type_factory?;
        let mut factory = factory_arc
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // cc:451/461/471: int4 ptrSize = glb->types->getSizeOfPointer().
        let ptr_size = factory.get_size_of_pointer().max(0) as usize;
        // cc:453/463/473: the element type the pointer points at.
        let element = match builtin_id {
            BUILTIN_MEMCPY => factory.get_type_void(),
            BUILTIN_STRNCPY => factory
                .get_type_char(factory.get_size_of_char().max(0) as usize)
                .ok()?,
            BUILTIN_WCSNCPY => factory
                .get_type_char(factory.get_size_of_wchar().max(0) as usize)
                .ok()?,
            _ => return None,
        };
        // cc:454/464/474: ptrType = getTypePointer(ptrSize, element, ws).
        let ptr_type = factory.get_type_pointer(ptr_size, element, default_space_word_size);
        // cc:455/465/475: intType = getBase(4, TYPE_INT).
        let int_type = factory.get_base(4, crate::type_system::TypeMetatype::Int)?;
        Some((
            ptr_type.clone(),
            // cc:456/466/476: constructor layout out=in0=in1=ptrType,
            // in2=intType — three inputs after the separate output.
            vec![Some(ptr_type.clone()), Some(ptr_type), Some(int_type)],
        ))
    }

    // Ghidra: userop.cc:432 UserOpManage::registerBuiltin
    /// Fallible compat form of `register_builtin_by_id` with no TypeFactory
    /// thread (no owning Architecture), preserving Ghidra's exact bad-id
    /// exception and its no-mutation-on-error ordering. The Datatype
    /// builtins created through this path intentionally carry no local
    /// metadata; callers holding the Architecture TypeFactory must use
    /// `register_builtin` (canonical on-demand defaults) or
    /// `register_builtin_with_local_types` (explicit types) on first
    /// registration.
    pub fn try_register_builtin_by_id(&mut self, builtin_id: u32) -> Result<u32, String> {
        self.register_builtin(builtin_id, None, 1)
    }

    // Ghidra: userop.cc:432 UserOpManage::registerBuiltin
    /// Register one of Ghidra's three DatatypeUserOp builtins using the
    /// canonical `Arc<Datatype>` handles produced by the owning TypeFactory.
    /// The first registration wins exactly like `builtinmap`; later calls
    /// return the existing descriptor without replacing its metadata. This
    /// is the explicit-types entry used by the constseq typed path
    /// (`StringSequence/HeapSequence::register_builtin_typed`, the
    /// constseq.cc:360/751 mirrors); the canonical on-demand-defaults form
    /// of the same oracle switch arm is `register_builtin` (construction
    /// identity: `datatype_builtin_local_types` vs the constseq helper —
    /// same ptrSize/element/ptrType/intType derivation). The two entries
    /// produce identical records; consolidation into a single constseq call
    /// through `register_builtin` is a constseq-domain follow-up.
    pub fn register_builtin_with_local_types(
        &mut self,
        builtin_id: u32,
        out_type: Option<Arc<Datatype>>,
        input_types: Vec<Option<Arc<Datatype>>>,
    ) -> Result<u32, String> {
        if self.builtin_map.contains_key(&builtin_id) {
            return Ok(builtin_id);
        }
        let name = match builtin_id {
            BUILTIN_MEMCPY => "builtin_memcpy",
            BUILTIN_STRNCPY => "builtin_strncpy",
            BUILTIN_WCSNCPY => "builtin_wcsncpy",
            _ => return Err("Bad built-in userop id".to_string()),
        };
        let descriptor = DatatypeUserOp::new(
            name.to_string(),
            builtin_id as i32,
            out_type,
            input_types,
        );
        self.builtin_map
            .insert(builtin_id, Box::new(descriptor.base));
        Ok(builtin_id)
    }

    // Ghidra: userop.cc:367 UserOpManage::registerStringCopyOp
    /// Register the string-copy (`strncpy`/`wcsncpy`) CALLOTHER and return its
    /// CALLOTHER constant index. Used by RuleStringCopy. Faithful to the
    /// `glb->userops.registerBuiltin(BUILTIN_STRNCPY)` call embedded in
    /// `StringSequence::buildStringCopy` (constseq.cc:360).
    ///
    /// `char_size` selects the function: 1 → strncpy (BUILTIN_STRNCPY),
    /// 2 → wcsncpy (BUILTIN_WCSNCPY). No live callers (grep-verified
    /// 2026-09-27); callers holding the Architecture TypeFactory should
    /// prefer `register_builtin` so the DatatypeUserOp defaults carry
    /// their on-demand local metadata.
    pub fn register_string_copy_op(&mut self, char_size: i32) -> u32 {
        let builtin_id = if char_size == 2 { BUILTIN_WCSNCPY } else { BUILTIN_STRNCPY };
        self.register_builtin_by_id(builtin_id)
    }

    // Ghidra: userop.cc:367 UserOpManage::registerStringStoreOp
    /// Register the string-store (`memcpy`) CALLOTHER and return its CALLOTHER
    /// constant index. Used by RuleStringStore. Faithful to the
    /// `registerBuiltin(BUILTIN_MEMCPY)` call embedded in
    /// `HeapSequence::buildStringCopy` (constseq.cc:751). No live callers
    /// (grep-verified 2026-09-27); callers holding the Architecture
    /// TypeFactory should prefer `register_builtin` (on-demand metadata).
    pub fn register_string_store_op(&mut self) -> u32 {
        self.register_builtin_by_id(BUILTIN_MEMCPY)
    }

    // Ghidra: userop.cc:367 UserOpManage::getCallOtherName
    /// Look up the CALLOTHER name for a given constant id. Faithful to
    /// `UserOpManage::getOp(uint4)->getName()`. Checks built-ins first, then
    /// the by-index list.
    pub fn get_call_other_name(&self, index: u32) -> Option<&str> {
        // Built-in ids are large sentinel values (0x1000_00xx); small values
        // index the registered list.
        if index >= 0x1000_0000 {
            return self
                .builtin_map
                .get(&index)
                .map(|op| op.name.as_str());
        }
        self.get_op(index as i32).map(|op| op.name.as_str())
    }

    // RUGRA-GLUE: name-list convenience for `initialize_builtins` (the
    //   oracle `UserOpManage::initialize`, userop.cc:392-403, registers every
    //   user defined p-code op presented by the Architecture as
    //   UnspecializedPcodeOp; this pre-registers the six well-known names in
    //   the same unspecialized form and mirrors the by-id record). The 1:1
    //   port of `UserOpManage::registerBuiltin(uint4)` is the three-argument
    //   `register_builtin` above.
    /// Register a built-in op by name (unspecialized) and keep the faithful
    /// by-id record in sync.
    pub fn register_builtin_named(&mut self, name: &str, builtin_id: u32) {
        if self.get_index_by_name(name).is_none() {
            self.register_op(name.to_string(), UserOpType::Unspecialized);
        }
        // Also keep the faithful by-id record in sync.
        self.register_builtin_by_id(builtin_id);
    }

    // Ghidra: userop.cc:367 UserOpManage::initializeBuiltins
    /// Initialize all built-in CALLOTHER ids.
    pub fn initialize_builtins(&mut self) {
        self.register_builtin_named("string_data", BUILTIN_STRINGDATA);
        self.register_builtin_named("volatile_read", BUILTIN_VOLATILE_READ);
        self.register_builtin_named("volatile_write", BUILTIN_VOLATILE_WRITE);
        self.register_builtin_named("memcpy", BUILTIN_MEMCPY);
        self.register_builtin_named("strcpy", BUILTIN_STRNCPY);
        self.register_builtin_named("wcsncpy", BUILTIN_WCSNCPY);
    }

    // Ghidra: userop.cc:367 UserOpManage::getOpMut
    /// Get a mutable user op by its CALLOTHER index.
    pub fn get_op_mut(&mut self, index: i32) -> Option<&mut UserPcodeOp> {
        if index >= 0 && (index as usize) < self.ops.len() {
            self.ops[index as usize].as_deref_mut()
        } else {
            None
        }
    }

    // Ghidra: userop.cc:367 UserOpManage::isVolatileRead
    /// Check if an index corresponds to a volatile read.
    pub fn is_volatile_read(&self, index: i32) -> bool {
        self.get_op(index).map(|op| op.op_type == UserOpType::VolatileRead).unwrap_or(false)
    }

    // Ghidra: userop.cc:367 UserOpManage::isVolatileWrite
    /// Check if an index corresponds to a volatile write.
    pub fn is_volatile_write(&self, index: i32) -> bool {
        self.get_op(index).map(|op| op.op_type == UserOpType::VolatileWrite).unwrap_or(false)
    }

    // Ghidra: userop.cc:628 UserOpManage::manualCallOtherFixup
    /// Manually register a CALLOTHER fixup (replacement p-code for an
    /// unspecialized user op). Faithful to Ghidra
    /// UserOpManage::manualCallOtherFixup (userop.cc:628).
    pub fn manual_call_other_fixup(&mut self, userop_name: &str, _outname: &str, _innames: &[String]) -> i32 {
        self.register_op(userop_name.to_string(), UserOpType::Injected)
    }

    // Ghidra: userop.cc:490 UserOpManage::registerOp
    /// Register a fully decoded `UserPcodeOp`, customizing any existing
    /// record at the same index.  Faithful to `registerOp`
    /// (userop.cc:490-527): a same-name op with a different index throws
    /// `Conflicting indices for userop name`; an occupied index with a
    /// different name throws `User op X has same index as Y` while an
    /// identical name customizes the old record in place. `decode_segment_op`
    /// performs Ghidra's remaining segment-space cross-reference immediately
    /// after this common registration step.
    pub fn register_user_op(&mut self, op: UserPcodeOp) -> Result<(), String> {
        let ind = op.userop_index;
        if ind < 0 {
            return Err("UserOp not assigned an index".to_string());
        }
        if let Some(existing_index) = self.name_map.get(&op.name) {
            if *existing_index != ind {
                return Err(format!("Conflicting indices for userop name {}", op.name));
            }
        }
        while self.ops.len() <= ind as usize {
            self.ops.push(None);
        }
        if let Some(existing) = self.ops[ind as usize].as_deref() {
            if existing.name != op.name {
                return Err(format!(
                    "User op {} has same index as {}",
                    op.name, existing.name
                ));
            }
        }
        // We assume this registration customizes an existing userop: the
        // old spec is replaced.
        self.ops[ind as usize] = Some(Box::new(op));
        let installed = self.ops[ind as usize]
            .as_deref()
            .expect("registered userop slot must be populated");
        self.name_map.insert(installed.name.clone(), ind);
        Ok(())
    }

    // Ghidra: userop.cc:490 UserOpManage::registerOp
    /// Install a DatatypeUserOp in the same indexed descriptor container used
    /// by every other user-op specialization.  This deliberately consumes the
    /// wrapper so there is no second metadata table that can drift.
    pub fn register_datatype_user_op(&mut self, op: DatatypeUserOp) -> Result<(), String> {
        self.register_user_op(op.base)
    }

    // Ghidra: userop.cc:589 UserOpManage::decodeCallOtherFixup (+ userop.cc:85 InjectedUserOp::decode)
    /// Create an InjectedUserOp description from a `<callotherfixup>`
    /// element and register it.  Faithful to `decodeCallOtherFixup`
    /// (userop.cc:589-600) and `InjectedUserOp::decode` (userop.cc:85-96):
    /// the payload is decoded and registered in the injection library
    /// FIRST, then the callother target name must match an existing
    /// unspecialized user op or the error leaves the library registration
    /// behind as a non-transactional residual.
    pub fn decode_call_other_fixup(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        inject_lib: &mut crate::pcodeinject::PcodeInjectLibrary,
        body_content: Option<&str>,
    ) -> Result<(), String> {
        // InjectedUserOp::decode body (userop.cc:86-95).
        let injectid = inject_lib.decode_inject(
            "userop",
            "",
            crate::pcodeinject::InjectPayloadType::CallOtherFixup,
            decoder,
            body_content,
        )?;
        let name = inject_lib.get_call_other_target(injectid);
        let base = self.get_op_by_name(&name).cloned();
        // This tag overrides the base functionality of a userop
        // so the core userop name and index may already be defined
        let base = match base {
            Some(b) => b,
            None => return Err(format!("Unknown userop name in <callotherfixup>: {}", name)),
        };
        if base.op_type != UserOpType::Unspecialized {
            // Make sure the userop isn't used for some other purpose
            return Err(format!(
                "<callotherfixup> overloads userop with another purpose: {}",
                name
            ));
        }
        let useropindex = base.userop_index; // Get the index from the core userop
        let mut op = UserPcodeOp::new(name.clone(), UserOpType::Injected, useropindex);
        op.inject_id = injectid;
        self.register_user_op(op)
    }

    // Ghidra: userop.cc:533 UserOpManage::decodeSegmentOp (+ userop.cc:225 SegmentOp::decode)
    /// Create a SegmentOp description from a `<segmentop>` element and
    /// register it.  Faithful to `decodeSegmentOp` (userop.cc:533-545) and
    /// `SegmentOp::decode` (userop.cc:225-290): the op index is the current
    /// useroplist size, the space attribute is mandatory, the base userop
    /// must exist and be unspecialized, the `<pcode>` child must declare
    /// exactly one output and one or two inputs, and a decode failure
    /// discards only this op (the injected payload stays registered).
    pub fn decode_segment_op(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        inject_lib: &mut crate::pcodeinject::PcodeInjectLibrary,
        space_by_name: &dyn Fn(&str) -> Option<crate::space::AddressSpace>,
        register_lookup: &dyn Fn(&str) -> Option<crate::fspec::VarnodeData>,
        body_content: Option<&str>,
    ) -> Result<(), String> {
        use crate::marshal::Decoder as _;
        let mut s_op = SegmentOp::new(String::new(), self.ops.len() as i32);
        // SegmentOp::decode (userop.cc:225-290).
        let elem_id = decoder.open_element();
        let mut spc: Option<crate::space::AddressSpace> = None;
        s_op.inject_id = -1;
        s_op.baseinsize = 0;
        s_op.innerinsize = 0;
        s_op.supports_far_pointer = false;
        s_op.base.name = "segment".to_string(); // Default name, might be overridden by userop attribute
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("space") => {
                    let space_name = decoder.read_string();
                    spc = Some(space_by_name(&space_name).ok_or(
                        "Undefined space: ".to_string() + &space_name,
                    )?);
                }
                Some("farpointer") => {
                    // Ghidra sets the flag purely on attribute presence
                    // (userop.cc:240-241) without reading a value.
                    let _ = decoder.read_string();
                    s_op.supports_far_pointer = true;
                }
                Some("userop") => {
                    // Based on existing sleigh op
                    s_op.base.name = decoder.read_string();
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        let Some(space) = spc else {
            return Err("<segmentop> expecting space attribute".to_string());
        };
        s_op.space_id = space;
        let name = s_op.base.name.clone();
        let otherop = self.get_op_by_name(&name).cloned();
        let otherop = match otherop {
            Some(o) => o,
            None => return Err(format!("<segmentop> unknown userop {}", name)),
        };
        s_op.base.userop_index = otherop.userop_index;
        if otherop.op_type != UserOpType::Unspecialized {
            return Err(format!("Redefining userop {}", name));
        }
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            if sub_name == "constresolve" {
                decoder.open_element();
                if decoder.peek_element() != 0 {
                    // Address::decode(decoder,sz) — <addr space=.. offset=..>
                    // or <register name=..>.  VarnodeData::decodeFromAttributes
                    // (pcoderaw.cc:33-55) leaves the space null unless a
                    // `space` or `name` attribute appears.
                    let child = decoder.open_element();
                    let (space, offset, size) = read_varnode_attrs(decoder, register_lookup)?;
                    decoder.close_element(child);
                    if space.is_some() {
                        s_op.constresolve = Some(crate::fspec::VarnodeData {
                            space: space.unwrap(),
                            offset,
                            size,
                        });
                    }
                }
                decoder.close_element(sub_id);
            } else if sub_name == "pcode" {
                let nm = format!("{}_pcode", name);
                let source = "cspec";
                s_op.inject_id = inject_lib.decode_inject(
                    source,
                    &nm,
                    crate::pcodeinject::InjectPayloadType::ExecutablePcode,
                    decoder,
                    body_content,
                )?;
            } else {
                // Ghidra's loop only advances for constresolve/pcode
                // children (peek without open); mirror by consuming the
                // unknown child so the stream does not stall.
                let child = decoder.open_element();
                decoder.close_element_skipping(child);
            }
        }
        decoder.close_element(elem_id);
        if s_op.inject_id < 0 {
            return Err("Missing <pcode> child in <segmentop> tag".to_string());
        }
        let payload = inject_lib
            .get_payload_by_id(s_op.inject_id)
            .ok_or("Missing <pcode> child in <segmentop> tag".to_string())?;
        if payload.size_output() != 1 {
            return Err("<pcode> child of <segmentop> tag must declare one <output>".to_string());
        }
        if payload.size_input() == 1 {
            s_op.innerinsize = payload.get_input(0).map(|p| p.size).unwrap_or(0) as i32;
        } else if payload.size_input() == 2 {
            s_op.baseinsize = payload.get_input(0).map(|p| p.size).unwrap_or(0) as i32;
            s_op.innerinsize = payload.get_input(1).map(|p| p.size).unwrap_or(0) as i32;
        } else {
            return Err(
                "<pcode> child of <segmentop> tag must declare one or two <input> tags".to_string()
            );
        }
        // registerOp (userop.cc:490-527): the name/index crossrefs run
        // FIRST; only the tail of registerOp indexes the segment-op vector
        // (keyed by the space index, with the enum's stable id as the
        // index stand-in) and throws on a same-space collision.
        let space_index = s_op.space_id.space_id() as u32;
        s_op.space = space_index;
        self.register_user_op(s_op.base.clone())?;
        if self.segment_ops.contains_key(&(space_index as i32)) {
            return Err("Multiple segmentops defined for same space".to_string());
        }
        self.segment_ops.insert(space_index as i32, s_op);
        Ok(())
    }

    // Ghidra: userop.cc:606 UserOpManage::decodeJumpAssist (+ userop.cc:302 JumpAssistOp::decode)
    /// Create a JumpAssistOp from a `<jumpassist>` element and register it.
    /// Faithful to `decodeJumpAssist` (userop.cc:606-617) and
    /// `JumpAssistOp::decode` (userop.cc:302-353): duplicate `<*_pcode>`
    /// children throw, `<addr_pcode>`/`<default_pcode>` are mandatory, and
    /// the named user op must exist and be unspecialized.
    pub fn decode_jump_assist(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        inject_lib: &mut crate::pcodeinject::PcodeInjectLibrary,
        body_content: Option<&str>,
    ) -> Result<(), String> {
        use crate::marshal::{AttributeId, Decoder as _};
        let mut op = JumpAssistOp::new(String::new(), 0);
        // JumpAssistOp::decode (userop.cc:302-353).
        let elem_id = decoder.open_element();
        op.base.name = decoder.read_string_attr(&AttributeId::new("name", 0));
        // Mark as not present until we see a tag
        op.index2case = -1;
        op.index2addr = -1;
        op.defaultaddr = -1;
        op.calcsize = -1;
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            match sub_name.as_str() {
                "case_pcode" => {
                    if op.index2case != -1 {
                        return Err("Too many <case_pcode> tags".to_string());
                    }
                    op.index2case = inject_lib.decode_inject(
                        "jumpassistop",
                        &format!("{}_index2case", op.base.name),
                        crate::pcodeinject::InjectPayloadType::ExecutablePcode,
                        decoder,
                        body_content,
                    )?;
                }
                "addr_pcode" => {
                    if op.index2addr != -1 {
                        return Err("Too many <addr_pcode> tags".to_string());
                    }
                    op.index2addr = inject_lib.decode_inject(
                        "jumpassistop",
                        &format!("{}_index2addr", op.base.name),
                        crate::pcodeinject::InjectPayloadType::ExecutablePcode,
                        decoder,
                        body_content,
                    )?;
                }
                "default_pcode" => {
                    if op.defaultaddr != -1 {
                        return Err("Too many <default_pcode> tags".to_string());
                    }
                    op.defaultaddr = inject_lib.decode_inject(
                        "jumpassistop",
                        &format!("{}_defaultaddr", op.base.name),
                        crate::pcodeinject::InjectPayloadType::ExecutablePcode,
                        decoder,
                        body_content,
                    )?;
                }
                "size_pcode" => {
                    if op.calcsize != -1 {
                        return Err("Too many <size_pcode> tags".to_string());
                    }
                    op.calcsize = inject_lib.decode_inject(
                        "jumpassistop",
                        &format!("{}_calcsize", op.base.name),
                        crate::pcodeinject::InjectPayloadType::ExecutablePcode,
                        decoder,
                        body_content,
                    )?;
                }
                _ => {
                    // Ghidra's loop only advances on the four pcode tags
                    // (peek without open); consume the unknown child so the
                    // stream does not stall.
                    let child = decoder.open_element();
                    decoder.close_element_skipping(child);
                }
            }
        }
        decoder.close_element(elem_id);

        if op.index2addr == -1 {
            return Err(format!("userop: {} is missing <addr_pcode>", op.base.name));
        }
        if op.defaultaddr == -1 {
            return Err(format!("userop: {} is missing <default_pcode>", op.base.name));
        }
        let base = self.get_op_by_name(&op.base.name).cloned();
        // This tag overrides the base functionality of a userop
        // so the core userop name and index may already be defined
        let base = match base {
            Some(b) => b,
            None => {
                return Err(format!(
                    "Unknown userop name in <jumpassist>: {}",
                    op.base.name
                ))
            }
        };
        if base.op_type != UserOpType::Unspecialized {
            // Make sure the userop isn't used for some other purpose
            return Err(format!(
                "<jumpassist> overloads userop with another purpose: {}",
                op.base.name
            ));
        }
        op.base.userop_index = base.userop_index; // Get the index from the core userop
        let record = UserPcodeOp::new(
            op.base.name.clone(),
            UserOpType::JumpAssist,
            op.base.userop_index,
        );
        self.register_user_op(record)?;
        self.jump_assist_ops.push(op);
        Ok(())
    }

    // Ghidra: userop.cc:551 UserOpManage::decodeVolatile
    /// Register the volatile read/write built-ins from a `<volatile>`
    /// element.  Faithful to `decodeVolatile` (userop.cc:551-583): both
    /// `inputop` and `outputop` attributes are mandatory, `format`
    /// selects functional display, and a second registration throws.
    pub fn decode_volatile(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let mut read_op_name = String::new();
        let mut write_op_name = String::new();
        let mut functional_display = false;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("inputop") => read_op_name = decoder.read_string(),
                Some("outputop") => write_op_name = decoder.read_string(),
                Some("format") => {
                    let format = decoder.read_string();
                    if format == "functional" {
                        functional_display = true;
                    }
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        if read_op_name.is_empty() || write_op_name.is_empty() {
            return Err("Missing inputop/outputop attributes in <volatile> element".to_string());
        }
        if self.builtin_map.contains_key(&BUILTIN_VOLATILE_READ) {
            return Err("read_volatile user-op registered more than once".to_string());
        }
        if self.builtin_map.contains_key(&BUILTIN_VOLATILE_WRITE) {
            return Err("write_volatile user-op registered more than once".to_string());
        }
        // VolatileReadOp ctor (userop.hh:188-190): flags = functional ? 0
        // : no_operator.  VolatileWriteOp ctor (userop.hh:203-205): flags =
        // functional ? 0 : annotation_assignment.
        let mut vr_op = UserPcodeOp::new(read_op_name, UserOpType::VolatileRead, BUILTIN_VOLATILE_READ as i32);
        if !functional_display {
            vr_op.flags = userop_flags::NO_OPERATOR;
        }
        self.builtin_map
            .insert(BUILTIN_VOLATILE_READ, Box::new(vr_op));
        let mut vw_op = UserPcodeOp::new(write_op_name, UserOpType::VolatileWrite, BUILTIN_VOLATILE_WRITE as i32);
        if !functional_display {
            vw_op.flags = userop_flags::ANNOTATION_ASSIGNMENT;
        }
        self.builtin_map
            .insert(BUILTIN_VOLATILE_WRITE, Box::new(vw_op));
        Ok(())
    }

    // Ghidra: userop.cc:367 UserOpManage::getOpByName
    /// Get a UserPcodeOp by name. Faithful to Ghidra
    /// UserOpManage::getOp(string) (userop.cc:419).
    pub fn get_op_by_name(&self, name: &str) -> Option<&UserPcodeOp> {
        let idx = self.get_index_by_name(name)?;
        self.ops.get(idx as usize)?.as_deref()
    }
}

// Ghidra: pcoderaw.cc:33 VarnodeData::decodeFromAttributes
/// Collect the `space`/`offset`/`size` or `name` (register) attributes of
/// the current element into a VarnodeData triple.  Faithful to
/// `VarnodeData::decodeFromAttributes` (pcoderaw.cc:33-55): on `space` the
/// whole attribute set is re-scanned by the space decoder (Rugra collects
/// offset/size from the full pass), on `name` the whole varnode is replaced
/// by the named register; the space stays `None` (Ghidra's null sentinel)
/// unless a `space` or `name` attribute appears.
fn read_varnode_attrs(
    decoder: &mut dyn crate::marshal::Decoder,
    register_lookup: &dyn Fn(&str) -> Option<crate::fspec::VarnodeData>,
) -> Result<(Option<crate::space::AddressSpace>, u64, i32), String> {
    use crate::marshal::Decoder;
    let mut space: Option<crate::space::AddressSpace> = None;
    let mut offset = 0u64;
    let mut size = 0i32;
    let mut register_name: Option<String> = None;
    loop {
        let attrib_id = decoder.next_attribute_id();
        if attrib_id == 0 {
            break; // Its possible to have no attributes in an <addr/> tag
        }
        match decoder.attribute_name(attrib_id).as_deref() {
            Some("space") => {
                let space_name = decoder.read_string();
                space = Some(crate::pcodeparse::parse_space_name(&space_name));
            }
            Some("offset") => {
                offset = decoder.read_unsigned_integer();
            }
            Some("size") => {
                size = decoder.read_unsigned_integer() as i32;
            }
            Some("name") => {
                register_name = Some(decoder.read_string());
                break;
            }
            _ => {
                let _ = decoder.read_string();
            }
        }
    }
    if let Some(name) = register_name {
        let point = register_lookup(&name)
            .ok_or_else(|| format!("Unknown register name: {}", name))?;
        return Ok((Some(point.space), point.offset, point.size));
    }
    Ok((space, offset, size))
}

// Ghidra: userop.cc:367 UserOpManage::createUnspecialized
/// A user defined p-code op with no specialization.
/// Corresponds to Ghidra's `UnspecializedPcodeOp` (userop.hh:130).
pub fn create_unspecialized(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::Unspecialized, index)
}

// Ghidra: userop.cc:367 UserOpManage::createInjected
/// Create an injected user-op descriptor.
/// Corresponds to Ghidra's `InjectedUserOp`.
pub fn create_injected(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::Injected, index)
}

// Ghidra: userop.cc:367 UserOpManage::createVolatileRead
/// Create a volatile read user op.
/// Corresponds to Ghidra's `VolatileReadOp`.
pub fn create_volatile_read(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::VolatileRead, index)
}

// Ghidra: userop.cc:367 UserOpManage::createVolatileWrite
/// Create a volatile write user op.
/// Corresponds to Ghidra's `VolatileWriteOp`.
pub fn create_volatile_write(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::VolatileWrite, index)
}

// Ghidra: userop.cc:367 UserOpManage::createSegment
/// Create a segment op user op.
/// Corresponds to Ghidra's `SegmentOp`.
pub fn create_segment(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::Segment, index)
}

// Ghidra: userop.cc:367 UserOpManage::createJumpAssist
/// Create a jump-table assist user op.
/// Corresponds to Ghidra's `JumpAssistOp`.
pub fn create_jump_assist(name: String, index: i32) -> UserPcodeOp {
    UserPcodeOp::new(name, UserOpType::JumpAssist, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_op_basic() {
        let op = UserPcodeOp::new("memcpy".into(), UserOpType::Unspecialized, 4);
        assert_eq!(op.get_name(), "memcpy");
        assert_eq!(op.get_index(), 4);
        assert_eq!(op.get_type(), UserOpType::Unspecialized);
    }

    #[test]
    fn test_user_op_manage() {
        let mut mgr = UserOpManage::new();
        let idx = mgr.register_op("memcpy".into(), UserOpType::Unspecialized);
        assert_eq!(idx, 0);
        assert_eq!(mgr.num_ops(), 1);
        assert!(mgr.get_op(0).is_some());
        assert_eq!(mgr.get_index_by_name("memcpy"), Some(0));
        assert!(mgr.get_index_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_builtin_ids() {
        // Faithful to Ghidra userop.cc:30-35.
        assert_eq!(BUILTIN_MEMCPY, 0x1000_0003);
        assert_eq!(BUILTIN_VOLATILE_READ, 0x1000_0001);
        assert_eq!(BUILTIN_STRNCPY, 0x1000_0004);
        assert_eq!(BUILTIN_WCSNCPY, 0x1000_0005);
    }

    #[test]
    fn test_initialize_builtins() {
        let mut mgr = UserOpManage::new();
        mgr.initialize_builtins();
        assert!(mgr.get_index_by_name("memcpy").is_some());
        assert!(mgr.get_index_by_name("volatile_read").is_some());
        assert_eq!(mgr.num_ops(), 6);
    }

    #[test]
    fn test_register_builtin_by_id() {
        let mut mgr = UserOpManage::new();
        // Faithful to Ghidra registerBuiltin (userop.cc:432-484).
        let id = mgr.register_builtin_by_id(BUILTIN_STRNCPY);
        assert_eq!(id, BUILTIN_STRNCPY);
        // Idempotent.
        let id2 = mgr.register_builtin_by_id(BUILTIN_STRNCPY);
        assert_eq!(id2, BUILTIN_STRNCPY);
        assert_eq!(
            mgr.get_op(BUILTIN_STRNCPY as i32).unwrap().get_type(),
            UserOpType::Datatype,
        );
        assert!(mgr.get_output_local(BUILTIN_STRNCPY as i32).is_none());
        assert!(mgr
            .get_input_local(BUILTIN_STRNCPY as i32, 1)
            .is_none());
        // Name lookup.
        assert_eq!(mgr.get_call_other_name(BUILTIN_STRNCPY), Some("builtin_strncpy"));
        assert_eq!(mgr.get_call_other_name(BUILTIN_MEMCPY), None);
    }

    #[test]
    fn test_register_builtin_volatile_display_defaults() {
        // Faithful to Ghidra registerBuiltin's volatile defaults
        // (userop.cc:443-447): functional=false, so the read op carries
        // no_operator (userop.hh:190-191) and the write op carries
        // annotation_assignment (userop.hh:205-206). getDisplay()
        // (userop.hh:84-85) is then non-zero for both, which is what
        // Funcdata::replaceVolatile's hold decision reads (cc:758-759).
        let mut mgr = UserOpManage::new();
        mgr.register_builtin_by_id(BUILTIN_VOLATILE_READ);
        mgr.register_builtin_by_id(BUILTIN_VOLATILE_WRITE);
        let vr = mgr.get_op(BUILTIN_VOLATILE_READ as i32).unwrap();
        assert_eq!(vr.get_display(), userop_flags::NO_OPERATOR);
        let vw = mgr.get_op(BUILTIN_VOLATILE_WRITE as i32).unwrap();
        assert_eq!(vw.get_display(), userop_flags::ANNOTATION_ASSIGNMENT);
        // The zero-flag functional form only arises from a cspec
        // format="functional" element (decodeVolatile path,
        // userop.cc:566-570), not from this on-demand default.
    }

    #[test]
    fn test_register_string_copy_store_op() {
        let mut mgr = UserOpManage::new();
        // RuleStringCopy selects strncpy for 1-byte chars, wcsncpy for 2-byte.
        let sc1 = mgr.register_string_copy_op(1);
        assert_eq!(sc1, BUILTIN_STRNCPY);
        assert_eq!(mgr.get_call_other_name(sc1), Some("builtin_strncpy"));
        let sc2 = mgr.register_string_copy_op(2);
        assert_eq!(sc2, BUILTIN_WCSNCPY);
        assert_eq!(mgr.get_call_other_name(sc2), Some("builtin_wcsncpy"));
        // RuleStringStore selects memcpy.
        let ss = mgr.register_string_store_op();
        assert_eq!(ss, BUILTIN_MEMCPY);
        assert_eq!(mgr.get_call_other_name(ss), Some("builtin_memcpy"));
    }

    #[test]
    fn test_get_call_other_name_indexed() {
        let mut mgr = UserOpManage::new();
        let idx = mgr.register_op("custom_op".into(), UserOpType::Unspecialized);
        // Small ids index the registered list.
        assert_eq!(mgr.get_call_other_name(idx as u32), Some("custom_op"));
        // Large sentinel ids check the builtin map.
        assert_eq!(mgr.get_call_other_name(BUILTIN_VOLATILE_WRITE), None);
        mgr.register_builtin_by_id(BUILTIN_VOLATILE_WRITE);
        assert_eq!(mgr.get_call_other_name(BUILTIN_VOLATILE_WRITE), Some("write_volatile"));
    }

    #[test]
    fn test_create_specialized() {
        let vr = create_volatile_read("volread".into(), 0);
        assert_eq!(vr.get_type(), UserOpType::VolatileRead);
        let vw = create_volatile_write("volwrite".into(), 1);
        assert_eq!(vw.get_type(), UserOpType::VolatileWrite);
        let seg = create_segment("seg".into(), 2);
        assert_eq!(seg.get_type(), UserOpType::Segment);
        let ja = create_jump_assist("jump".into(), 3);
        assert_eq!(ja.get_type(), UserOpType::JumpAssist);
    }

    #[test]
    fn test_get_op_by_name() {
        let mut mgr = UserOpManage::new();
        mgr.register_op("memcpy".into(), UserOpType::Unspecialized);
        assert!(mgr.get_op_by_name("memcpy").is_some());
        assert_eq!(mgr.get_op_by_name("memcpy").unwrap().get_name(), "memcpy");
        assert!(mgr.get_op_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_manual_call_other_fixup() {
        let mut mgr = UserOpManage::new();
        let idx = mgr.manual_call_other_fixup("my_fixup", "out", &["in1".into(), "in2".into()]);
        assert!(mgr.get_op(idx).is_some());
        assert_eq!(mgr.get_op(idx).unwrap().get_type(), UserOpType::Injected);
    }

    #[test]
    fn test_datatype_user_op_compacts_null_inputs() {
        let factory = crate::type_system::typefactory::TypeFactory::new(8);
        let void_type = factory.get_type_void();
        let int_type = factory
            .get_base(4, crate::type_system::datatype::TypeMetatype::Int)
            .expect("canonical int type");
        let descriptor = DatatypeUserOp::new(
            "typed".to_string(),
            7,
            Some(void_type.clone()),
            vec![None, Some(int_type.clone()), None, Some(void_type.clone())],
        );

        assert!(std::sync::Arc::ptr_eq(
            descriptor.get_output_local().expect("output metadata"),
            &void_type,
        ));
        assert!(descriptor.get_input_local(0).is_none());
        assert!(std::sync::Arc::ptr_eq(
            descriptor.get_input_local(1).expect("compacted input zero"),
            &int_type,
        ));
        assert!(std::sync::Arc::ptr_eq(
            descriptor.get_input_local(2).expect("compacted input one"),
            &void_type,
        ));
        assert!(descriptor.get_input_local(3).is_none());
    }

    #[test]
    fn test_manager_preserves_typed_registration_error_state() {
        let factory = crate::type_system::typefactory::TypeFactory::new(8);
        let void_type = factory.get_type_void();
        let int_type = factory
            .get_base(4, crate::type_system::datatype::TypeMetatype::Int)
            .expect("canonical int type");
        let mut manager = UserOpManage::new();
        manager
            .register_user_op(UserPcodeOp::new(
                "typed".to_string(),
                UserOpType::Unspecialized,
                2,
            ))
            .expect("initial descriptor");
        manager
            .register_datatype_user_op(DatatypeUserOp::new(
                "typed".to_string(),
                2,
                Some(void_type.clone()),
                vec![Some(int_type.clone())],
            ))
            .expect("typed customization");

        assert!(manager.get_op(0).is_none());
        assert!(manager.get_op(1).is_none());
        assert_eq!(
            manager
                .register_datatype_user_op(DatatypeUserOp::new(
                    "typed".to_string(),
                    3,
                    Some(int_type.clone()),
                    Vec::new(),
                ))
                .unwrap_err(),
            "Conflicting indices for userop name typed",
        );
        assert!(manager.get_op(3).is_none());
        assert!(std::sync::Arc::ptr_eq(
            manager.get_output_local(2).expect("preserved output metadata"),
            &void_type,
        ));
    }

    #[test]
    fn test_typed_builtin_first_registration_wins() {
        let factory = crate::type_system::typefactory::TypeFactory::new(8);
        let void_type = factory.get_type_void();
        let int_type = factory
            .get_base(4, crate::type_system::datatype::TypeMetatype::Int)
            .expect("canonical int type");
        let mut manager = UserOpManage::new();
        manager
            .register_builtin_with_local_types(
                BUILTIN_MEMCPY,
                Some(void_type.clone()),
                vec![Some(int_type.clone())],
            )
            .expect("typed builtin");
        let first = manager
            .get_op(BUILTIN_MEMCPY as i32)
            .expect("first descriptor") as *const UserPcodeOp;
        manager
            .register_builtin_with_local_types(
                BUILTIN_MEMCPY,
                Some(int_type),
                Vec::new(),
            )
            .expect("repeated typed builtin");

        assert!(std::ptr::eq(
            first,
            manager
                .get_op(BUILTIN_MEMCPY as i32)
                .expect("stable descriptor") as *const UserPcodeOp,
        ));
        assert!(std::sync::Arc::ptr_eq(
            manager
                .get_output_local(BUILTIN_MEMCPY as i32)
                .expect("first output metadata"),
            &void_type,
        ));
    }

    #[test]
    fn test_segment_op_execute() {
        // Faithful to SegmentOp::execute (userop.cc:218-223) via the canonical
        // x86-16 real-mode formula res = (base << 4) + inner, matching the
        // injected p-code in x86-16-real.pspec / x86-16.pspec.
        let seg = SegmentOp::new("segment".into(), 0);
        // base=0x1234, inner=0x0002 -> (0x1234 << 4) + 2 = 0x12342.
        assert_eq!(seg.execute(&[0x1234, 0x0002]), Some(0x12342));
        // base=0x2000, inner=0x0010 -> 0x20010.
        assert_eq!(seg.execute(&[0x2000, 0x0010]), Some(0x20010));
        // base=0, inner=5 -> 5 (zero segment).
        assert_eq!(seg.execute(&[0, 5]), Some(5));
        // Near-pointer form (no base term): linear = inner.
        assert_eq!(seg.execute(&[0x1234]), Some(0x1234));
        // Wrapping arithmetic: (0xFFF...F << 4) + 0x10 overflows u64 to 0.
        assert_eq!(seg.execute(&[u64::MAX >> 4, 0x10]), Some(0));
        // Unrecognised arity -> None (Ghidra always declares 1 or 2 inputs).
        assert_eq!(seg.execute(&[]), None);
        assert_eq!(seg.execute(&[1, 2, 3]), None);
    }

    #[test]
    fn test_segment_op_far_pointer_support() {
        // Faithful to SegmentOp::hasFarPointerSupport (userop.hh:274) and the
        // `supportsfarpointer` field (userop.hh:269).
        let mut seg = SegmentOp::new("segment".into(), 0);
        assert!(!seg.has_far_pointer_support());
        seg.supports_far_pointer = true; // set by farpointer="yes" attribute
        assert!(seg.has_far_pointer_support());
    }

    /// Shared fixture for the DatatypeUserOp default-construction tests:
    /// a TypeFactory with setup_sizes run (type.cc:3137-3170 defaults:
    /// char=1, wchar=2, pointer=default data space addr size 8) — the same
    /// shape the owning Architecture installs before any registerBuiltin
    /// Datatype arm can run. The `standalone` flag mirrors Ghidra's own
    /// `SleighArchitecture::buildCoreTypes` (which registers the full
    /// char/wchar2/wchar4 family) instead of the DataOrg driver flavor
    /// (char + wchar_t(4) only, no size-2 wide char).
    fn datatype_default_factory(
        standalone: bool,
    ) -> Arc<std::sync::RwLock<crate::type_system::typefactory::TypeFactory>> {
        use crate::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
        let factory = if standalone {
            TypeFactory::new_flavor(8, CoreTypeFlavor::Standalone)
        } else {
            TypeFactory::new(8)
        };
        let factory = Arc::new(std::sync::RwLock::new(factory));
        factory
            .write()
            .unwrap()
            .setup_sizes(&crate::type_system::typefactory::SizeArchInputs {
                stack_spacebase_size: Some(8),
                default_data_space_addr_size: 8,
                default_size: 8,
                far_pointer: None,
            });
        factory
    }

    #[test]
    fn test_register_builtin_datatype_defaults() {
        // userop.cc:449-477: registerBuiltin's DatatypeUserOp arms construct
        // the ptr/char pointer metadata on demand from the architecture
        // TypeFactory — MEMCPY -> void*, STRNCPY -> char*, WCSNCPY ->
        // wchar* — out = in0 = in1 = ptrType, in2 = int4. WCSNCPY uses the
        // standalone-flavor factory (Ghidra buildCoreTypes registers
        // wchar2, typefactory core-type table); the DataOrg driver flavor
        // has no size-2 wide char and its degrade case is pinned separately
        // below.
        for (builtin_id, element_name, factory) in [
            (BUILTIN_MEMCPY, "void", datatype_default_factory(false)),
            (BUILTIN_STRNCPY, "char", datatype_default_factory(false)),
            (BUILTIN_WCSNCPY, "wchar2", datatype_default_factory(true)),
        ] {
            let mut mgr = UserOpManage::new();
            mgr.register_builtin(builtin_id, Some(&factory), 1)
                .expect("factory-backed on-demand default");
            let descriptor = mgr.get_op(builtin_id as i32).expect("registered record");
            assert_eq!(descriptor.get_type(), UserOpType::Datatype);
            assert_eq!(
                mgr.get_call_other_name(builtin_id),
                Some(match builtin_id {
                    BUILTIN_MEMCPY => "builtin_memcpy",
                    BUILTIN_STRNCPY => "builtin_strncpy",
                    _ => "builtin_wcsncpy",
                })
            );
            // cc:451/454: ptrType = getTypePointer(getSizeOfPointer()=8,
            // element, ws=1) — a size-8 pointer at the element.
            let out = mgr
                .get_output_local(builtin_id as i32)
                .expect("on-demand output metadata");
            assert_eq!(out.get_metatype(), crate::type_system::TypeMetatype::Pointer);
            assert_eq!(out.get_size(), 8);
            // cc:456/466/476: out = in0 = in1 = ptrType (same Arc).
            let in1 = mgr
                .get_input_local(builtin_id as i32, 1)
                .expect("slot-1 pointer metadata");
            let in2 = mgr
                .get_input_local(builtin_id as i32, 2)
                .expect("slot-2 pointer metadata");
            assert!(Arc::ptr_eq(&out, &in1));
            assert!(Arc::ptr_eq(&out, &in2));
            // The element type selects STRNCPY vs WCSNCPY vs MEMCPY
            // (cc:453/463/473): char (1), wchar (2), void (0); the
            // pointer's wordsize is the default-space word size (1 here).
            // Rugra char types are Int-metatype bases carrying the
            // CHARTYPE flag, so the element is identified by name/size.
            let crate::type_system::datatype::Datatype::Pointer(ptr) = &**in1 else {
                panic!("slot-1 metadata must be the constructed pointer");
            };
            let expected = match builtin_id {
                BUILTIN_MEMCPY => (0, "void", crate::type_system::TypeMetatype::Void),
                BUILTIN_STRNCPY => (1, "char", crate::type_system::TypeMetatype::Int),
                _ => (2, "wchar2", crate::type_system::TypeMetatype::Int),
            };
            assert_eq!(ptr.ptr_to.get_size(), expected.0, "element {element_name}");
            assert_eq!(ptr.ptr_to.get_name(), expected.1);
            assert_eq!(ptr.ptr_to.get_metatype(), expected.2);
            assert_eq!(ptr.wordsize, 1);
            // cc:455/465/475: in2' = getBase(4, TYPE_INT) — slot 3.
            let len = mgr
                .get_input_local(builtin_id as i32, 3)
                .expect("slot-3 int4 length metadata");
            assert_eq!(len.get_size(), 4);
            assert_eq!(len.get_metatype(), crate::type_system::TypeMetatype::Int);
            // Slot 0 is the CALLOTHER index constant; slot 4 is past the
            // compacted inputs (userop.cc:79-82).
            assert!(mgr.get_input_local(builtin_id as i32, 0).is_none());
            assert!(mgr.get_input_local(builtin_id as i32, 4).is_none());
            // cc:482: builtinmap[i] = res — idempotent, first record stable.
            let first = mgr.get_op(builtin_id as i32).unwrap() as *const UserPcodeOp;
            mgr.register_builtin(builtin_id, Some(&factory), 1)
                .expect("idempotent re-registration");
            assert!(std::ptr::eq(
                first,
                mgr.get_op(builtin_id as i32).unwrap() as *const UserPcodeOp
            ));
        }
    }

    #[test]
    fn test_register_builtin_datatype_first_wins_orders() {
        // First registration wins in both directions between the on-demand
        // defaults entry and the explicit-types entry — the live pipeline
        // shape (constseq typed path first, any later registerBuiltin a
        // no-op) and its reverse both keep the first record.
        let factory = datatype_default_factory(false);
        let void = factory.read().unwrap().get_type_void();
        let void_ptr = factory.write().unwrap().get_type_pointer(8, void, 1);
        let int4 = factory
            .read()
            .unwrap()
            .get_base(4, crate::type_system::TypeMetatype::Int)
            .expect("canonical int4");

        // Typed first (live-pipeline shape, constseq.cc:360/751 -> typed
        // entry) then the on-demand default entry: record preserved.
        let mut mgr = UserOpManage::new();
        mgr.register_builtin_with_local_types(
            BUILTIN_MEMCPY,
            Some(void_ptr.clone()),
            vec![Some(void_ptr.clone()), Some(int4.clone())],
        )
        .expect("typed registration");
        mgr.register_builtin(BUILTIN_MEMCPY, Some(&factory), 1)
        .expect("on-demand after typed");
        assert!(Arc::ptr_eq(
            &mgr.get_output_local(BUILTIN_MEMCPY as i32).unwrap(),
            &void_ptr
        ));

        // On-demand first then the typed entry: record preserved too
        // (cc:435-437 builtinmap lookup short-circuits both ways).
        let mut mgr = UserOpManage::new();
        mgr.register_builtin(BUILTIN_MEMCPY, Some(&factory), 1)
            .expect("on-demand registration");
        mgr.register_builtin_with_local_types(
            BUILTIN_MEMCPY,
            Some(void_ptr),
            vec![Some(int4)],
        )
        .expect("typed after on-demand");
        let out = mgr
            .get_output_local(BUILTIN_MEMCPY as i32)
            .expect("first record survives");
        assert_eq!(out.get_size(), 8);
        // The on-demand record's slot-2 int4 is still intact (first-wins).
        assert!(mgr.get_input_local(BUILTIN_MEMCPY as i32, 3).is_some());
    }

    #[test]
    fn test_register_builtin_wcsncpy_dataorg_degrade() {
        // Documented degrade on the DataOrg driver flavor: setup_sizes
        // defaults sizeOfWChar to 2 (type.cc:3151-3152) but the DataOrg
        // core-type table registers no size-2 wide char (only char(1) and
        // wchar_t(4)), so `getTypeChar(2)` raises "Request for unsupported
        // character data-type" (type.cc:3686). Ghidra's registerBuiltin
        // would propagate that LowlevelError; Rugra's thread keeps the
        // metadata-less compat record (the same `.ok()?` degrade the
        // constseq typed entry takes on this factory state). Unreachable
        // on live architectures — the same cspec data_organization that
        // builds the core types also sets sizeOfWChar to a size the char
        // cache holds (4 for x86-64 gcc).
        let factory = datatype_default_factory(false);
        assert!(
            factory.read().unwrap().get_type_char(2).is_err(),
            "DataOrg flavor must lack the size-2 wide char for this degrade case"
        );
        let mut mgr = UserOpManage::new();
        mgr.register_builtin(BUILTIN_WCSNCPY, Some(&factory), 1)
            .expect("degraded on-demand registration still returns the id");
        assert_eq!(mgr.get_call_other_name(BUILTIN_WCSNCPY), Some("builtin_wcsncpy"));
        assert!(mgr.get_output_local(BUILTIN_WCSNCPY as i32).is_none());
        assert!(mgr.get_input_local(BUILTIN_WCSNCPY as i32, 3).is_none());
    }

    #[test]
    fn test_register_builtin_bad_id() {
        // userop.cc:479-480: `default: throw LowlevelError("Bad built-in
        // userop id")` — no mutation on error.
        let factory = datatype_default_factory(false);
        let mut mgr = UserOpManage::new();
        assert_eq!(
            mgr.register_builtin(0x1000_00ff, Some(&factory), 1)
                .unwrap_err(),
            "Bad built-in userop id"
        );
        assert_eq!(
            mgr.try_register_builtin_by_id(0x1000_00ff).unwrap_err(),
            "Bad built-in userop id"
        );
        assert!(mgr.builtin_map.is_empty());
    }

    #[test]
    fn test_volatile_write_input_local_symbol_arm() {
        // userop.cc:159-172 VolatileWriteOp::getInputLocal — the write arm
        // mirror of test_output_type_local_volatile_read_symbol_arm
        // (varnode.rs, VARNODE-CALLOTHER-VOLATILEOUT-0001). A volatile
        // write CALLOTHER (write form, funcdata_varnode.cc:721-739:
        // in(0) = descriptor id constant, in(1) = volatile annotation at
        // the memory address, in(2) = value being written, no output) with
        // the special_prop addlflag (cc:761-762, type-locked source)
        // resolves slot 2's local type from the global scope symbol.
        use crate::address::{Address, SeqNum};
        use crate::database::{symbol_flags, Database};
        use crate::op::op_addl_flags;
        use crate::op::PcodeOp;
        use crate::opcodes::OpCode;
        use crate::type_system::datatype::{Datatype, TypeBase};
        use crate::type_system::typefactory::TypeFactory;
        use crate::type_system::TypeMetatype;

        let factory = Arc::new(std::sync::RwLock::new(TypeFactory::new(8)));
        factory.write().unwrap().set_default_alignment_map();

        // The write_volatile descriptor (UserOpManage::registerBuiltin,
        // userop.cc:446-447 — a VolatileWriteOp with no fixed metadata).
        let mut mgr = UserOpManage::new();
        let volatile_index = mgr.register_builtin_by_id(BUILTIN_VOLATILE_WRITE);
        let mgr = Arc::new(std::sync::RwLock::new(mgr));
        assert!(mgr
            .read()
            .unwrap()
            .get_op(volatile_index as i32)
            .unwrap()
            .is_volatile_write());

        // Global symbol "vol_reg" (int, 4 bytes) mapped at 0x1000; addr-tied
        // so the entry is in use at every usepoint (database.cc:115-120).
        let mut db = Database::new(false);
        let sym_dt = Arc::new(Datatype::Base(TypeBase::new(
            "int".into(),
            4,
            TypeMetatype::Int,
        )));
        let sym_id = db
            .add_symbol_mapped(0, "vol_reg", Some(sym_dt), Address::new(0x1000), 4)
            .expect("global symbol mapped");
        db.set_symbol_flag(0, sym_id, symbol_flags::ADDRTIED, true);
        let db = Arc::new(std::sync::RwLock::new(db));

        // The volatile write CALLOTHER.
        let mut id_vn = crate::varnode::Varnode::new(4, Address::new(volatile_index as u64));
        id_vn.set_flags(crate::varnode::varnode_flags::CONSTANT);
        let id_vn = Arc::new(std::sync::RwLock::new(id_vn));

        let mut ann_vn = crate::varnode::Varnode::new(4, Address::new(0x1000));
        ann_vn.set_flags(
            crate::varnode::varnode_flags::ANNOTATION | crate::varnode::varnode_flags::VOLATIL,
        );
        let ann_vn = Arc::new(std::sync::RwLock::new(ann_vn));

        let mut val_vn = crate::varnode::Varnode::new(4, Address::new(0x7f000000));
        let val_vn = Arc::new(std::sync::RwLock::new(val_vn));

        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x2000), 0), OpCode::CPUI_CALLOTHER);
        op.inrefs.push(id_vn.clone());
        op.inrefs.push(ann_vn);
        op.inrefs.push(val_vn);
        op.addlflags |= op_addl_flags::SPECIAL_PROP;

        // Positive (cc:164-169): slot 2 resolves the global symbol's sized
        // type at the volatile address.
        let got = VolatileWriteOp::get_input_local(&op, 2, &factory, Some(&db))
            .expect("volatile write resolves the global symbol's sized type");
        assert_eq!(got.get_name(), "int");
        assert_eq!(got.get_metatype(), TypeMetatype::Int);
        assert_eq!(got.get_size(), 4);

        // Negative 1 (cc:162-163): any slot other than 2 is not annotated.
        assert!(VolatileWriteOp::get_input_local(&op, 1, &factory, Some(&db)).is_none());
        assert!(VolatileWriteOp::get_input_local(&op, 3, &factory, Some(&db)).is_none());

        // Negative 2 (cc:162): no special propagation — the flag is set only
        // for a type-locked source.
        op.addlflags &= !op_addl_flags::SPECIAL_PROP;
        assert!(VolatileWriteOp::get_input_local(&op, 2, &factory, Some(&db)).is_none());
        op.addlflags |= op_addl_flags::SPECIAL_PROP;

        // Negative 3 (cc:168-171): no entry at the queried address.
        let mut miss_vn = crate::varnode::Varnode::new(4, Address::new(0x9000));
        miss_vn.set_flags(
            crate::varnode::varnode_flags::ANNOTATION | crate::varnode::varnode_flags::VOLATIL,
        );
        op.inrefs[1] = Arc::new(std::sync::RwLock::new(miss_vn));
        assert!(VolatileWriteOp::get_input_local(&op, 2, &factory, Some(&db)).is_none());

        // Negative 4: no symboltab thread (no owning Architecture).
        assert!(VolatileWriteOp::get_input_local(&op, 2, &factory, None).is_none());
    }
}
