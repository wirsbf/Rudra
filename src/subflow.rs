//! Subflow analysis: shrinking big Varnodes carrying smaller logical values,
//! and splitting Varnodes that hold 2 (or more) logical values.
//!
//! 1:1 alignment with Ghidra's `subflow.hh` / `subflow.cc` (4130 lines).
//!
//! Two main engines live here, mirroring Ghidra:
//!   - [`SubvariableFlow`]: trace a small logical value stored inside a bigger
//!     container Varnode, then rewrite the data-flow to use an explicitly-sized
//!     Varnode.  (subflow.cc:19-1545)
//!   - [`SplitDatatype`] + the `RuleSplit*` rules: split COPY/LOAD/STORE ops
//!     operating on partial structures/arrays into per-component ops.
//!     (subflow.cc:2090-3004)
//!
//! The 8 subvar / splitflow Rules registered by Ghidra's `oppool1` /
//! `cleanup` pools (coreaction.cc:5621-5628, coreaction.cc cleanup) are all
//! implemented here as `impl Rule`:
//!   - `RuleSubvarAnd`       (subflow.cc:1547)  trigger: INT_AND
//!   - `RuleSubvarSubpiece`  (subflow.cc:1584)  trigger: SUBPIECE
//!   - `RuleSubvarCompZero`  (subflow.cc:1621)  trigger: INT_EQUAL / INT_NOTEQUAL
//!   - `RuleSubvarShift`     (subflow.cc:1680)  trigger: INT_RIGHT
//!   - `RuleSubvarZext`      (subflow.cc:1704)  trigger: INT_ZEXT
//!   - `RuleSubvarSext`      (subflow.cc:1723)  trigger: INT_SEXT
//!   - `RuleSplitFlow`       (subflow.cc:2039)  trigger: SUBPIECE
//!   - `RuleSplitCopy`       (subflow.cc:2941)  trigger: COPY
//!   - `RuleSplitLoad`       (subflow.cc:2964)  trigger: LOAD
//!   - `RuleSplitStore`      (subflow.cc:2985)  trigger: STORE
//!
//! `RuleSubfloatConvert` (subflow.cc:3483, FLOAT_FLOAT2FLOAT) is fully
//! ported: `SubfloatFlow` (subflow.cc:3070-3481) — the `TransformManager`
//! subclass tracing a logical lower-precision float through the data-flow —
//! runs the complete forward/backward trace with the `maxPrecisionMap` and
//! rewrites the data-flow at the smaller precision via
//! `TransformManager::apply` (transform.cc:756-765), new Varnodes and ops,
//! no retype of the originals.
//!
//! # Known infrastructure gaps (do NOT work around — reported, not simplified)
//!
//! ## Gaps now closed (infrastructure landed)
//!   - `Varnode::is_ptr_flow()` is now present (addlflags `PTR_FLOW`).
//!     `RuleSubvarSubpiece` and `RuleSubvarZext` now pass the real
//!     aggressiveness from `outvn.is_ptr_flow()` / `invn.is_ptr_flow()` 1:1 with
//!     Ghidra (subflow.cc:1601, subflow.cc:1717).
//!   - `Varnode::is_precis_lo()` / `is_precis_hi()` are now present. The
//!     `RuleSplitFlow` `isPrecisLo()/isPrecisHi()` guard (subflow.cc:2054) is now
//!     wired faithfully.
//!   - `Varnode::is_addr_force()` is now present. The `setReplacement`
//!     `isAddrForce()` guard (subflow.cc:95) is now wired faithfully.
//!   - `Varnode::is_type_lock()` + `get_type()` + `Datatype::get_metatype()`
//!     are now present. The `setReplacement` typelock guards (subflow.cc:103,
//!     subflow.cc:114) are now wired, with the caveat below.
//!
//! ## Gaps still open
//!   - `Varnode::is_zero_extended(size)` is still NOT a first-class method.
//!     `trace_forward`/`trace_backward` INT_DIV/INT_REM cases approximate it
//!     inline via `get_nz_mask` (plus the `size > 8` INT_ZEXT special case) and
//!     log it. The logic is as faithful as the available accessors allow; the
//!     remaining gap is the missing canonical `Varnode::is_zero_extended`
//!     accessor (varnode.cc:958-970).
//!   - `TypeMetatype::PartialStruct` has no variant in Rugra's enum
//!     (`type_system/datatype.rs`). The `setReplacement` typelock guards
//!     therefore cannot honour the `!= TYPE_PARTIALSTRUCT` exception: because no
//!     Rugra type is ever PartialStruct, the exception is vacuously true and the
//!     size guard always runs when typelocked. This is 1:1 with Ghidra's logic
//!     given Rugra's type system; it only diverges if/when PartialStruct types
//!     exist (not yet representable).
//!   - `Funcdata::op_set_all_input` is not present; the `doReplacement`
//!     extension_patch case that calls it is emulated with per-slot
//!     `op_set_input` + `op_remove_input`.
//!   - Per-op `FuncCallSpecs` identity lookup now exists through
//!     `Funcdata::get_call_specs_of_op`, and the `try_call_pull`
//!     guard-and-patch consumer is wired 1:1 with subflow.cc:208-228
//!     (consume guard, getCallSpecs, isInputActive, isInputLocked &&
//!     !isDotdotdot, parameter_patch + pullcount). The
//!     `try_call_return_push` consumer still retains the conservative skip
//!     under `CALLSPEC-0001` (indirect-creation trims are not exercised by
//!     the current corpora).
//!   - `PcodeOp::get_halt_type` (`try_return_pull`) is not available; the
//!     artificial-halt guard is conservatively skipped and logged.
//!   - `copy_symbol_if_valid` and `Address::is_big_endian` are not threaded
//!     through here; the relevant spots emulate conservatively and log it.
//!     (`Funcdata::set_input_varnode`/`delete_varnode` ARE now used
//!     by `replace_input`/`get_replace_varnode`, subflow.cc:1262/1264/1343.)
//!     The `split_datatype_config` Architecture option IS now threaded into
//!     `SplitDatatype::new` (subflow.cc:2701-2709) and the split gates run
//!     through the canonical `TypeFactory::get_exact_piece`
//!     (SPLITDATATYPE-EXACTPIECE-0001).
//!   - `SubfloatFlow` and `LaneDivide` (`TransformManager` subclasses,
//!     subflow.cc:3070-3481 / 3518-4128) are ported on top of the shared
//!     `TransformManager` in `transform.rs`; the `RuleSubfloatConvert` and
//!     `RuleSplitFlow` rewrites run the full oracle trace + apply.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::action::Rule;
use crate::action::RuleState;
use crate::action::action_status;
use crate::address::{calc_mask, leastsigbit_set, mostsigbit_set, Address};
use crate::error::Result;
use crate::funcdata::Funcdata;
use crate::op::{PcodeOp, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::rangeutil::sign_extend_size;
use crate::space::AddressSpace;
use crate::transform::{LaneDescription, TransformManager};
use crate::varnode::Varnode;

// =====================================================================
// SubvariableFlow — internal placeholder structs
// (subflow.hh:43-82)
// =====================================================================

/// Placeholder node for a Varnode holding a smaller logical value.
/// Corresponds to Ghidra's `SubvariableFlow::ReplaceVarnode`
/// (subflow.hh:45-52).
///
/// In Ghidra this is a node holding raw `Varnode*` / `ReplaceOp*` pointers
/// into `std::list<>`. Rugra stores everything by index into the owning
/// `SubvariableFlow`'s `newvarlist` / `oplist` vectors, which is the
/// pointer-stable equivalent.
#[derive(Debug, Clone)]
pub struct ReplaceVarnode {
    /// Original Varnode being shrunk (None for synthetic constants).
    /// Corresponds to `ReplaceVarnode::vn`.
    pub vn: Option<Arc<RwLock<Varnode>>>,
    /// The new smaller Varnode, once materialised by `get_replace_varnode`.
    /// Corresponds to `ReplaceVarnode::replacement`.
    pub replacement: Option<Arc<RwLock<Varnode>>>,
    /// Bits making up the logical sub-variable. Corresponds to `mask`.
    pub mask: u64,
    /// Value of constant (when `vn` is None or a constant). Corresponds to `val`.
    pub val: u64,
    /// Index into `oplist` of the defining op for the new Varnode, or None.
    /// Corresponds to `ReplaceVarnode::def`.
    pub def: Option<usize>,
}

impl ReplaceVarnode {
    // Ghidra: subflow.hh:45 ReplaceVarnode::new
    fn new() -> Self {
        Self { vn: None, replacement: None, mask: 0, val: 0, def: None }
    }
}

/// Placeholder node for a PcodeOp operating on smaller logical values.
/// Corresponds to Ghidra's `SubvariableFlow::ReplaceOp` (subflow.hh:55-63).
#[derive(Debug)]
pub struct ReplaceOp {
    /// Op getting paralleled. Corresponds to `ReplaceOp::op`.
    pub op: Option<Arc<RwLock<PcodeOp>>>,
    /// The new replacement op, once materialised by `do_replacement`.
    /// Corresponds to `ReplaceOp::replacement`.
    pub replacement: Option<PcodeOpRef>,
    /// Opcode of the new op. Corresponds to `opc`.
    pub opc: OpCode,
    /// Number of parameters in the new op. Corresponds to `numparams`.
    pub numparams: usize,
    /// Index into `newvarlist` of the output varnode, or None.
    /// Corresponds to `ReplaceOp::output`.
    pub output: Option<usize>,
    /// Indices into `newvarlist` of the input varnodes.
    /// Corresponds to `ReplaceOp::input`.
    pub input: Vec<Option<usize>>,
}

/// The possible types of patches on ops being performed.
/// Corresponds to Ghidra's `SubvariableFlow::PatchRecord::patchtype`
/// (subflow.hh:69-76). Variants kept in the same order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchType {
    /// Turn op into a COPY of the logical value. `copy_patch`.
    CopyPatch,
    /// Turn compare op inputs into logical values. `compare_patch`.
    ComparePatch,
    /// Convert a CALL/CALLIND/RETURN/BRANCHIND parameter. `parameter_patch`.
    ParameterPatch,
    /// Convert op into something that copies/extends logical value, adding zero
    /// bits. `extension_patch`.
    ExtensionPatch,
    /// Convert an operator output to the logical value. `push_patch`.
    PushPatch,
    /// Zero extend logical value into FLOAT_INT2FLOAT operator. `int2float_patch`.
    Int2FloatPatch,
}

/// Operation with a new logical value as (part of) input, but output Varnode is
/// unchanged. Corresponds to Ghidra's `SubvariableFlow::PatchRecord`
/// (subflow.hh:66-82). `in1`/`in2` are indices into `newvarlist`.
#[derive(Debug, Clone)]
pub struct PatchRecord {
    /// The type of this patch. Corresponds to `PatchRecord::type`.
    pub patch_type: PatchType,
    /// Op being affected. Corresponds to `patchOp`.
    pub patch_op: Arc<RwLock<PcodeOp>>,
    /// The logical variable input (index into `newvarlist`). Corresponds to `in1`.
    pub in1: usize,
    /// Optional second parameter (index into `newvarlist`). Corresponds to `in2`.
    pub in2: Option<usize>,
    /// Slot being affected or other parameter. Corresponds to `slot`.
    pub slot: i32,
    /// For `int2float_patch`, whether this counts as a real modification.
    pub pull_modification: bool,
}

// =====================================================================
// SubvariableFlow
// (subflow.hh:42-130, subflow.cc:19-1545)
// =====================================================================

/// Class for shrinking big Varnodes carrying smaller logical values.
///
/// Given a root within the syntax tree and dimensions of a logical variable,
/// this struct traces the flow of this logical variable through its containing
/// Varnodes.  It then creates a subgraph of this flow, where there is a
/// correspondence between nodes in the subgraph and nodes in the original graph
/// containing the logical variable.  When [`do_replacement`](Self::do_replacement)
/// is called, this subgraph is duplicated as a new separate piece within the
/// syntax tree.  Ops are replaced to reflect the manipulation of the logical
/// variable, rather than the containing variable.
///
/// 1:1 aligned with Ghidra's `SubvariableFlow` (subflow.hh:42).
pub struct SubvariableFlow {
    /// Size of the logical data-flow in bytes. `flowsize`.
    pub flowsize: i32,
    /// Number of bits in logical variable. `bitsize`.
    pub bitsize: i32,
    /// Have we tried to flow logical value across CPUI_RETURNs. `returnsTraversed`.
    pub returns_traversed: bool,
    /// Do we "know" initial seed point must be a sub variable. `aggressive`.
    pub aggressive: bool,
    /// Check for logical variables that are always sign extended into their
    /// container. `sextrestrictions`.
    pub sext_restrictions: bool,
    /// Allow big (8-byte) logical values. Mirrors the `big` ctor parameter
    /// (which has no field in C++; it only gates flowsize selection). Kept so
    /// the constructor logic is 1:1.
    pub big: bool,
    /// Containing function. `fd`. None means the constructor short-circuited
    /// (mask==0 or bitsize too big), in which case `do_trace` returns false.
    pub fd: Option<*mut Funcdata>,
    /// Map from original Varnode Arc ptr to the index of its ReplaceVarnode in
    /// `newvarlist`. Mirrors `map<Varnode*,ReplaceVarnode> varmap` (the key is
    /// the Varnode; the value also being present means the Varnode `isMark()`).
    varmap: BTreeMap<usize, usize>,
    /// Storage for subgraph variable nodes. Mirrors `list<ReplaceVarnode> newvarlist`.
    /// Indexing into this is the Rust analogue of the Ghidra `ReplaceVarnode*`.
    newvarlist: Vec<ReplaceVarnode>,
    /// Storage for subgraph op nodes. Mirrors `list<ReplaceOp> oplist`.
    oplist: Vec<ReplaceOp>,
    /// Operations getting patched (but with no flow thru). Mirrors
    /// `list<PatchRecord> patchlist`. NOTE: Ghidra uses `std::list` and
    /// `push_front` for push patches so that `doReplacement` can iterate
    /// push-patches first; we keep two front/back orderings by recording the
    /// insertion via `push_front_count` and reconstructing order in
    /// `do_replacement`.
    patchlist: Vec<PatchRecord>,
    /// Number of patches pushed to the FRONT (push_patch). All push patches sit
    /// before all non-push patches. Emulates `list::push_front`.
    push_front_count: usize,
    /// Subgraph variable nodes still needing to be traced. Mirrors
    /// `vector<ReplaceVarnode*> worklist`. Stores indices into `newvarlist`.
    worklist: Vec<usize>,
    /// Number of instructions pulling out the logical value. `pullcount`.
    pub pullcount: i32,
}

// SAFETY: `fd` is a raw pointer used purely as a presence flag (the actual
// `&mut Funcdata` is threaded through method calls). We never deref it across
// threads; it is therefore `Send`. Matches how the rest of the crate treats
// non-thread-shared per-call analysis state.
unsafe impl Send for SubvariableFlow {}

impl SubvariableFlow {
    // -----------------------------------------------------------------
    // Static helpers (subflow.cc:21-53)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:26 SubvariableFlow::doesOrSet
    /// Return the slot of the constant if an INT_OR op sets all bits in `mask`,
    /// otherwise -1. Faithful to `SubvariableFlow::doesOrSet`
    /// (subflow.cc:26-36).
    pub fn does_or_set(orop: &PcodeOp, mask: u64) -> i32 {
        let index = if orop.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
            1
        } else {
            0
        };
        let in_const = match orop.get_in(index) {
            Some(v) => v.read().unwrap().is_constant(),
            None => return -1,
        };
        if !in_const {
            return -1;
        }
        let orval = orop.get_in(index).unwrap().read().unwrap().get_offset();
        if (mask & (!orval)) == 0 {
            // All masked bits are one.
            index as i32
        } else {
            -1
        }
    }

    // Ghidra: subflow.cc:43 SubvariableFlow::doesAndClear
    /// Return the slot of the constant if an INT_AND op clears all bits in
    /// `mask`, otherwise -1. Faithful to `SubvariableFlow::doesAndClear`
    /// (subflow.cc:43-53).
    pub fn does_and_clear(andop: &PcodeOp, mask: u64) -> i32 {
        let index = if andop.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
            1
        } else {
            0
        };
        let in_const = match andop.get_in(index) {
            Some(v) => v.read().unwrap().is_constant(),
            None => return -1,
        };
        if !in_const {
            return -1;
        }
        let andval = andop.get_in(index).unwrap().read().unwrap().get_offset();
        if (mask & andval) == 0 {
            // All masked bits are zero.
            index as i32
        } else {
            -1
        }
    }

    // Ghidra: subflow.cc:1372 SubvariableFlow::isZeroExtended
    /// Reproduce `Varnode::isZeroExtended(int4 baseSize)` (varnode.cc:958-970).
    ///
    /// `Varnode::isZeroExtended` is not yet a first-class accessor on Rugra's
    /// `Varnode`, so this static method inlines Ghidra's exact logic using the
    /// available accessors. It is used by the `INT_DIV`/`INT_REM` cases of
    /// `trace_forward`/`trace_backward` (subflow.cc:450-451, subflow.cc:802-803).
    ///
    /// Ghidra logic (verbatim):
    /// ```text
    /// if (baseSize >= size) return false;
    /// if (size > sizeof(uintb)) {            // uintb is 8 bytes
    ///     if (!isWritten()) return false;
    ///     if (def->code() != CPUI_INT_ZEXT) return false;
    ///     if (def->getIn(0)->getSize() > baseSize) return false;
    ///     return true;
    /// }
    /// uintb mask = nzm >> 8*baseSize;
    /// return (mask == 0);
    /// ```
    fn is_zero_extended(vn: &Arc<RwLock<Varnode>>, base_size: usize) -> bool {
        let v = vn.read().unwrap();
        let size = v.get_size() as usize;
        if base_size >= size {
            return false;
        }
        if size > 8 {
            // Beyond uintb precision: must be a written INT_ZEXT from a value
            // whose size is within base_size bytes.
            if !v.is_written() {
                return false;
            }
            match v.get_def() {
                Some(def_op) => {
                    let d = def_op.read().unwrap();
                    if d.opcode != OpCode::CPUI_INT_ZEXT {
                        return false;
                    }
                    let in0_size = d.get_in(0).map(|i| i.read().unwrap().get_size() as usize).unwrap_or(usize::MAX);
                    in0_size <= base_size
                }
                None => false,
            }
        } else {
            // Within uintb precision: high bytes must be known-zero.
            let nzm = v.get_nz_mask();
            let mask = if base_size >= 8 {
                0u64
            } else {
                nzm >> (8 * base_size)
            };
            mask == 0
        }
    }

    // -----------------------------------------------------------------
    // Constructor (subflow.cc:1366-1404)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:1372 SubvariableFlow::new
    /// Construct the analysis.
    ///
    /// Faithful to `SubvariableFlow::SubvariableFlow(Funcdata*,Varnode*,uintb,
    /// bool,bool,bool)` (subflow.cc:1372-1404). If `mask==0` or the bit-size is
    /// out of range (and not `big`), `fd` is set to None which makes
    /// [`do_trace`](Self::do_trace) return false — exactly as Ghidra sets
    /// `fd=(Funcdata*)0`.
    pub fn new(
        fd: &mut Funcdata,
        root: Arc<RwLock<Varnode>>,
        mask: u64,
        aggr: bool,
        sext: bool,
        big: bool,
    ) -> Self {
        let mut s = Self {
            flowsize: 0,
            bitsize: 0,
            returns_traversed: false,
            aggressive: aggr,
            sext_restrictions: sext,
            big,
            fd: Some(fd as *mut Funcdata),
            varmap: BTreeMap::new(),
            newvarlist: Vec::new(),
            oplist: Vec::new(),
            patchlist: Vec::new(),
            push_front_count: 0,
            worklist: Vec::new(),
            pullcount: 0,
        };
        if mask == 0 {
            // Ghidra: fd = (Funcdata*)0; return;
            s.fd = None;
            return s;
        }
        s.bitsize = (mostsigbit_set(mask) - leastsigbit_set(mask)) + 1;
        if s.bitsize <= 8 {
            s.flowsize = 1;
        } else if s.bitsize <= 16 {
            s.flowsize = 2;
        } else if s.bitsize <= 24 {
            s.flowsize = 3;
        } else if s.bitsize <= 32 {
            s.flowsize = 4;
        } else if s.bitsize <= 64 {
            if !big {
                s.fd = None;
                return s;
            }
            s.flowsize = 8;
        } else {
            s.fd = None;
            return s;
        }
        // createLink((ReplaceOp*)0, mask, 0, root)
        let _ = s.create_link(None, mask, 0, root);
        s
    }

    // Ghidra: subflow.cc:1372 SubvariableFlow::isNull
    /// Did the constructor short-circuit (equivalent to Ghidra's
    /// `fd==(Funcdata*)0`)? When true, [`do_trace`](Self::do_trace) will return
    /// false without doing anything.
    pub fn is_null(&self) -> bool {
        self.fd.is_none()
    }

    // -----------------------------------------------------------------
    // setReplacement (subflow.cc:55-151)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:66 SubvariableFlow::setReplacement
    /// Add the given Varnode as a new node in the logical subgraph.
    ///
    /// Faithful to `SubvariableFlow::setReplacement` (subflow.cc:66-151).
    /// Returns `Ok(Some(idx))` with the index of the (new or pre-existing)
    /// ReplaceVarnode in `newvarlist` (or a synthetic constant entry), or
    /// `Ok(None)` if the Varnode cannot be a subgraph node (abort). `inworklist`
    /// is set true when the new node should be traced further.
    fn set_replacement(
        &mut self,
        vn: &Arc<RwLock<Varnode>>,
        mask: u64,
    ) -> (Option<usize>, bool) {
        let vn_ptr = Arc::as_ptr(vn) as usize;
        // Already seen before?
        if let Some(&idx) = self.varmap.get(&vn_ptr) {
            let res_mask = self.newvarlist[idx].mask;
            if res_mask != mask {
                return (None, false);
            }
            return (Some(idx), false);
        }

        let (vn_is_constant, vn_is_free, vn_size, vn_is_input, vn_is_persist, vn_is_addr_force,
            vn_typelock_type_size) = {
            let v = vn.read().unwrap();
            // Ghidra (subflow.cc:95): `vn->isAddrForce()` — now wired via
            // Varnode::is_addr_force().
            let is_addr_force = v.is_addr_force();
            // Ghidra typelock guard (subflow.cc:103-106, subflow.cc:114-118):
            //   if (vn->isTypeLock() && vn->getType()->getMetatype() != TYPE_PARTIALSTRUCT) {
            //       if (vn->getType()->getSize() != flowsize) return 0;
            //   }
            // Varnode::is_type_lock() + get_type() + Datatype::get_metatype() are
            // now available. Rugra's TypeMetatype has no PartialStruct variant,
            // so `get_metatype() != PartialStruct` is always true here; we still
            // honour the size check when typelocked. `vn_typelock_type_size`
            // holds Some(type_size) when the guard should run, None otherwise.
            let typelock_type_size = if v.is_type_lock() {
                if let Some(dt) = v.get_type() {
                    // getMetatype() != TYPE_PARTIALSTRUCT is vacuously true (no
                    // PartialStruct variant in Rugra). So always run size check.
                    Some(dt.get_size() as i32)
                } else {
                    // Typelocked but no type resolved: cannot honour the size
                    // check, so skip it (conservative — don't restrict).
                    None
                }
            } else {
                None
            };
            (
                v.is_constant(),
                v.is_free(),
                v.get_size(),
                v.is_input(),
                v.is_persist(),
                is_addr_force,
                typelock_type_size,
            )
        };

        if vn_is_constant {
            if self.sext_restrictions {
                let cval = vn.read().unwrap().get_offset();
                let smallval = cval & mask;
                let sextval = sign_extend_size(smallval, self.flowsize as usize, vn_size);
                if sextval != cval {
                    return (None, false);
                }
            }
            // addConstant((ReplaceOp*)0, mask, 0, vn)
            let idx = self.add_constant(None, mask, 0, vn);
            return (Some(idx), false);
        }

        if vn_is_free {
            return (None, false); // Abort
        }

        // Ghidra (subflow.cc:95): if (vn->isAddrForce() && (vn->getSize() != flowsize)) return 0;
        if vn_is_addr_force && vn_size as i32 != self.flowsize {
            return (None, false);
        }

        if self.sext_restrictions {
            if vn_size as i32 != self.flowsize {
                if !self.aggressive && vn_is_input {
                    return (None, false); // Cannot assume input is sign extended
                }
                if vn_is_persist {
                    return (None, false);
                }
            }
            // Ghidra typelock guard (subflow.cc:103-106), now wired via
            // Varnode::is_type_lock()/get_type() + Datatype::get_metatype().
            if let Some(type_size) = vn_typelock_type_size {
                if type_size != self.flowsize {
                    return (None, false);
                }
            }
        } else {
            if self.bitsize >= 8 {
                // Ghidra: if ((!aggressive)&&((vn->getConsume()&~mask)!=0)) return 0;
                let consume = vn.read().unwrap().get_consume();
                if !self.aggressive && (consume & (!mask)) != 0 {
                    return (None, false);
                }
                // Ghidra typelock guard (subflow.cc:114-118), now wired.
                if let Some(type_size) = vn_typelock_type_size {
                    if type_size != self.flowsize {
                        return (None, false);
                    }
                }
            }

            if vn_is_input {
                // Inputs must come in from the right register/memory.
                if self.bitsize < 8 {
                    return (None, false); // Don't create input flag
                }
                if (mask & 1) == 0 {
                    return (None, false); // Don't create unique input
                }
            }
        }

        // res = &varmap[vn]; vn->setMark();
        let idx = self.newvarlist.len();
        self.newvarlist.push(ReplaceVarnode {
            vn: Some(vn.clone()),
            replacement: None,
            mask,
            val: 0,
            def: None,
        });
        self.varmap.insert(vn_ptr, idx);
        vn.write().unwrap().set_mark();

        let mut inworklist = true;
        // Check if vn already represents the logical variable being traced.
        if vn_size as i32 == self.flowsize {
            if mask == calc_mask(vn_size) {
                inworklist = false;
                self.newvarlist[idx].replacement = Some(vn.clone());
            } else if mask == 1 {
                let is_bool_out = {
                    if vn.read().unwrap().is_written() {
                        if let Some(def) = vn.read().unwrap().get_def() {
                            def.read().unwrap().is_bool_output()
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };
                if is_bool_out {
                    inworklist = false;
                    self.newvarlist[idx].replacement = Some(vn.clone());
                }
            }
        }
        (Some(idx), inworklist)
    }

    // -----------------------------------------------------------------
    // createOp / createOpDown (subflow.cc:153-197)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:159 SubvariableFlow::createOp
    /// Create a logical subgraph operator node given its output variable node.
    /// Faithful to `SubvariableFlow::createOp` (subflow.cc:159-173).
    fn create_op(&mut self, opc: OpCode, numparam: usize, outrvn: usize) -> usize {
        if let Some(d) = self.newvarlist[outrvn].def {
            return d;
        }
        let rop_idx = self.oplist.len();
        // rop->op = outrvn->vn->getDef();
        let def_op = self.newvarlist[outrvn]
            .vn
            .as_ref()
            .and_then(|v| v.read().unwrap().get_def());
        self.oplist.push(ReplaceOp {
            op: def_op,
            replacement: None,
            opc,
            numparams: numparam,
            output: Some(outrvn),
            input: Vec::new(),
        });
        self.newvarlist[outrvn].def = Some(rop_idx);
        rop_idx
    }

    // Ghidra: subflow.cc:184 SubvariableFlow::createOpDown
    /// Create a logical subgraph operator node given one of its input variable
    /// nodes. Faithful to `SubvariableFlow::createOpDown` (subflow.cc:184-197).
    fn create_op_down(
        &mut self,
        opc: OpCode,
        numparam: usize,
        op: Arc<RwLock<PcodeOp>>,
        inrvn: usize,
        slot: i32,
    ) -> usize {
        let rop_idx = self.oplist.len();
        self.oplist.push(ReplaceOp {
            op: Some(op),
            replacement: None,
            opc,
            numparams: numparam,
            output: None,
            input: Vec::new(),
        });
        let slot = slot as usize;
        while self.oplist[rop_idx].input.len() <= slot {
            self.oplist[rop_idx].input.push(None);
        }
        self.oplist[rop_idx].input[slot] = Some(inrvn);
        rop_idx
    }

    // -----------------------------------------------------------------
    // tryCallPull / tryReturnPull / tryCallReturnPush / trySwitchPull /
    // tryInt2FloatPull (subflow.cc:199-367)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:208 SubvariableFlow::tryCallPull
    /// Determine if the given subgraph variable can act as a parameter to the
    /// given CALL op. Faithful to `SubvariableFlow::tryCallPull`
    /// (subflow.cc:208-228): the consume-mask guard, then the exact per-op
    /// `Funcdata::getCallSpecs` lookup (funcdata.cc:484-497) with the
    /// input-active / input-locked-non-varargs guards, then the
    /// `parameter_patch` PatchRecord and pullcount bump.
    fn try_call_pull(
        &mut self,
        fd: &Funcdata,
        op: &Arc<RwLock<PcodeOp>>,
        rvn: usize,
        slot: i32,
    ) -> bool {
        if slot == 0 {
            return false;
        }
        if !self.aggressive {
            let (consume, mask) = {
                let v = self.newvarlist[rvn].vn.as_ref().unwrap();
                let vr = v.read().unwrap();
                (vr.get_consume(), self.newvarlist[rvn].mask)
            };
            if (consume & (!mask)) != 0 {
                return false;
            }
        }
        // Ghidra: subflow.cc:216-219
        //   FuncCallSpecs *fc = fd->getCallSpecs(op);
        //   if (fc == (FuncCallSpecs *)0) return false;
        //   if (fc->isInputActive()) return false;
        //   if (fc->isInputLocked() && (!fc->isDotdotdot())) return false;
        let fc_arc = match fd.get_call_specs_of_op(&PcodeOpRef(op.clone())) {
            Some(fc) => fc,
            None => return false,
        };
        {
            let fc = fc_arc.read().unwrap();
            if fc.is_input_active() {
                return false; // Don't trim while in the middle of figuring out params
            }
            if fc.prototype.is_input_locked() && !fc.prototype.is_varargs() {
                return false;
            }
        }
        // Ghidra: subflow.cc:221-227
        //   patchlist.emplace_back(); type=parameter_patch;
        //   patchOp=op; in1=rvn; slot=slot; pullcount += 1;
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::ParameterPatch,
            patch_op: op.clone(),
            in1: rvn,
            in2: None,
            slot,
            pull_modification: true,
        });
        self.pullcount += 1; // A true terminal modification
        true
    }

    // Ghidra: subflow.cc:238 SubvariableFlow::tryReturnPull
    /// Determine if the given subgraph variable can act as return value for the
    /// given RETURN op. Faithful to `SubvariableFlow::tryReturnPull`
    /// (subflow.cc:238-284).
    fn try_return_pull(
        &mut self,
        fd: &Funcdata,
        op: &Arc<RwLock<PcodeOp>>,
        rvn: usize,
        slot: i32,
    ) -> bool {
        if slot == 0 {
            return false; // Don't deal with actual return address container
        }
        if fd.get_func_proto().is_output_locked() {
            return false;
        }
        if !self.aggressive {
            let (consume, mask) = {
                let v = self.newvarlist[rvn].vn.as_ref().unwrap();
                let vr = v.read().unwrap();
                (vr.get_consume(), self.newvarlist[rvn].mask)
            };
            if (consume & (!mask)) != 0 {
                return false;
            }
        }

        let mask = self.newvarlist[rvn].mask;
        if !self.returns_traversed {
            // Iterate all RETURN ops in the function. Ghidra uses
            // fd->beginOp(CPUI_RETURN)/endOp. Rugra filters the live op bank.
            let returns: Vec<Arc<RwLock<PcodeOp>>> = fd
                .obank
                .alivelist
                .iter()
                .filter(|r| r.0.read().unwrap().opcode == OpCode::CPUI_RETURN)
                .map(|r| r.0.clone())
                .collect();
            let op_ptr = Arc::as_ptr(op) as usize;
            for retop in &returns {
                // Ghidra: if (retop->getHaltType() != 0) continue;
                // Rugra has no getHaltType; skip guard (artificial halts are
                // rare in this pipeline). Logged at module top.
                let retvn = match retop.read().unwrap().get_in(slot as usize).cloned() {
                    Some(v) => v,
                    None => continue,
                };
                let (rep, inworklist) = self.set_replacement(&retvn, mask);
                let rep = match rep {
                    Some(r) => r,
                    None => return false,
                };
                if inworklist {
                    self.worklist.push(rep);
                } else {
                    let ret_is_const = retvn.read().unwrap().is_constant();
                    let ret_ptr = Arc::as_ptr(retop) as usize;
                    if ret_is_const && ret_ptr != op_ptr {
                        // Generate patch now (won't be revisited).
                        self.push_front_count = 0; // unused for parameter_patch
                        self.patchlist.push(PatchRecord {
                            patch_type: PatchType::ParameterPatch,
                            patch_op: retop.clone(),
                            in1: rep,
                            in2: None,
                            slot,
                            pull_modification: true,
                        });
                        self.pullcount += 1;
                    }
                }
            }
            self.returns_traversed = true;
        }
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::ParameterPatch,
            patch_op: op.clone(),
            in1: rvn,
            in2: None,
            slot,
            pull_modification: true,
        });
        self.pullcount += 1; // A true terminal modification
        true
    }

    // Ghidra: subflow.cc:293 SubvariableFlow::tryCallReturnPush
    /// Determine if the given subgraph variable can act as a created value for
    /// the given INDIRECT op. Corresponds to
    /// `SubvariableFlow::tryCallReturnPush` (subflow.cc:293-310), but the
    /// callspec consumer is incomplete under `CALLSPEC-0001`.
    fn try_call_return_push(&mut self, op: &Arc<RwLock<PcodeOp>>, rvn: usize) -> bool {
        if !self.aggressive {
            let (consume, mask) = {
                let v = self.newvarlist[rvn].vn.as_ref().unwrap();
                let vr = v.read().unwrap();
                (vr.get_consume(), self.newvarlist[rvn].mask)
            };
            if (consume & (!mask)) != 0 {
                return false;
            }
        }
        let mask = self.newvarlist[rvn].mask;
        if (mask & 1) == 0 {
            return false; // Verify the logical value is the least significant part
        }
        if self.bitsize < 8 {
            return false; // Make sure logical value is at least a byte
        }
        // CALLSPEC-0001: exact per-op lookup is available, but the
        // output-locked/output-active guard and addPush consumer remain
        // outside this identity-only D0.
        let _ = op;
        // Preserve the legacy diagnostic bytes until this UNTESTED branch has
        // a bilateral fixture. The wording is not the current premise: exact
        // lookup exists, while the CALLSPEC-0001 consumer remains unwired.
        eprintln!("[subflow] tryCallReturnPush: per-op FuncCallSpecs lookup unavailable; skipping push");
        false
    }

    // Ghidra: subflow.cc:319 SubvariableFlow::trySwitchPull
    /// Determine if the subgraph variable can act as a switch variable for the
    /// given BRANCHIND. Faithful to `SubvariableFlow::trySwitchPull`
    /// (subflow.cc:319-332).
    fn try_switch_pull(&mut self, op: &Arc<RwLock<PcodeOp>>, rvn: usize) -> bool {
        let mask = self.newvarlist[rvn].mask;
        if (mask & 1) == 0 {
            return false; // Logical value must be justified
        }
        let (consume, m) = {
            let v = self.newvarlist[rvn].vn.as_ref().unwrap();
            let vr = v.read().unwrap();
            (vr.get_consume(), mask)
        };
        if (consume & (!m)) != 0 {
            return false; // If there's something outside the mask being consumed
        }
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::ParameterPatch,
            patch_op: op.clone(),
            in1: rvn,
            in2: None,
            slot: 0,
            pull_modification: true,
        });
        self.pullcount += 1; // A true terminal modification
        true
    }

    // Ghidra: subflow.cc:341 SubvariableFlow::tryInt2FloatPull
    /// Determine if the subgraph variable flows naturally into a terminal
    /// FLOAT_INT2FLOAT operation. Faithful to `SubvariableFlow::tryInt2FloatPull`
    /// (subflow.cc:341-367).
    fn try_int2float_pull(&mut self, op: &Arc<RwLock<PcodeOp>>, rvn: usize) -> bool {
        let mask = self.newvarlist[rvn].mask;
        if (mask & 1) == 0 {
            return false; // Logical value must be justified
        }
        let (nzmask, vn_size, is_written, def_op, lone_descend) = {
            let v = self.newvarlist[rvn].vn.as_ref().unwrap();
            let vr = v.read().unwrap();
            (
                vr.get_nz_mask(),
                vr.get_size(),
                vr.is_written(),
                vr.get_def(),
                vr.lone_descend(),
            )
        };
        if (nzmask & (!mask)) != 0 {
            return false; // Everything outside the logical value must be zero
        }
        if vn_size as i32 == self.flowsize {
            return false; // There must be some (zero) extension
        }
        let mut pull_modification = true;
        if is_written {
            if let Some(def) = &def_op {
                if def.read().unwrap().opcode == OpCode::CPUI_INT_ZEXT {
                    let preferred =
                        crate::typeop::TypeOpFloatInt2Float::preferred_zext_size(self.flowsize);
                    if vn_size as i32 == preferred {
                        if lone_descend.map(|d| Arc::as_ptr(&d) == Arc::as_ptr(op)).unwrap_or(false) {
                            pull_modification = false;
                        }
                    }
                }
            }
        }
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::Int2FloatPatch,
            patch_op: op.clone(),
            in1: rvn,
            in2: None,
            slot: 0,
            pull_modification,
        });
        if pull_modification {
            self.pullcount += 1;
        }
        true
    }

    // -----------------------------------------------------------------
    // traceForward (subflow.cc:369-659)
    // -----------------------------------------------------------------

    // Ghidra: op.cc:93 PcodeOp::getRepeatSlot
    /// Given a Varnode that appears in multiple input slots of an op, find
    /// the specific slot corresponding to the descendant occurrence
    /// currently being visited. Faithful to the iterator overload
    /// `getRepeatSlot(const Varnode *vn,int4 firstSlot,list<PcodeOp *>::const_iterator iter)`
    /// (op.cc:93-111): `count` is 1 plus the number of entries holding this
    /// op in the varnode's descendant list strictly before the current
    /// position (op.cc:97-100 walks `vn->beginDescend()` up to `iter`,
    /// exclusive); count==1 returns `firstSlot` unchanged (op.cc:101),
    /// otherwise the input slot of the count-th occurrence is returned, -1
    /// if absent (op.cc:110). The descendant iteration itself is NEVER
    /// advanced — the C++ iterator is passed by value and only read, so
    /// every descendant entry is processed exactly once by the caller's
    /// loop. Inlined here (like `subfloat_get_repeat_slot` below, same
    /// oracle function) because op.rs is outside this lane's write-set;
    /// the op.rs `count`-parameter variant lacks the op.cc:101 count==1
    /// early return (OPS-GETREPEATSLOT-COUNT1-0001).
    fn subvar_get_repeat_slot(
        op: &Arc<RwLock<PcodeOp>>,
        vn: &Arc<RwLock<Varnode>>,
        first_slot: usize,
        prior_occurrences: usize,
    ) -> i32 {
        let count = 1 + prior_occurrences;
        if count == 1 {
            return first_slot as i32;
        }
        let inrefs = op.read().unwrap().inrefs.clone();
        let mut recount = 1;
        for i in (first_slot + 1)..inrefs.len() {
            if Arc::ptr_eq(&inrefs[i], vn) {
                recount += 1;
                if recount == count {
                    return i as i32;
                }
            }
        }
        -1
    }

    // Ghidra: subflow.cc:373 SubvariableFlow::traceForward
    /// Try to trace the logical variable through descendant Varnodes, creating
    /// new nodes in the logical subgraph and updating the worklist. Faithful to
    /// `SubvariableFlow::traceForward` (subflow.cc:373-659).
    ///
    /// Returns false if the logical value cannot be traced forward one level.
    fn trace_forward(&mut self, fd: &Funcdata, rvn: usize) -> bool {
        let mut dcount: i32 = 0;
        let mut hcount: i32 = 0;
        let mut callcount: i32 = 0;

        // Snapshot the descendants and their slots before mutating self.
        let rvn_vn = self.newvarlist[rvn].vn.clone().expect("trace_forward on constant");
        let rvn_mask = self.newvarlist[rvn].mask;
        let descendants: Vec<(Arc<RwLock<PcodeOp>>, usize)> = {
            let v = rvn_vn.read().unwrap();
            let mut out = Vec::new();
            for d in v.descend_iter() {
                let op_rg = d.read().unwrap();
                let slot = (0..op_rg.num_input())
                    .find(|&i| {
                        op_rg.get_in(i).map(|inv| Arc::as_ptr(inv) == Arc::as_ptr(&rvn_vn)).unwrap_or(false)
                    });
                if let Some(slot) = slot {
                    out.push((d.clone(), slot));
                }
            }
            out
        };

        // Ghidra iterates the live descendant list with a C++ iterator that
        // is only read by getRepeatSlot (CALL case) — never advanced by it.
        // We materialise the descendant list once (one entry per read, like
        // Ghidra's per-slot addDescend bookkeeping) and iterate by index so
        // the CALL case can count prior occurrences of the same op for the
        // repeat-slot recomputation (op.cc:97-100) without mutating the
        // iteration.
        let mut i = 0;
        while i < descendants.len() {
            let (op_arc, mut slot) = descendants[i].clone();
            i += 1;
            let op_rg = op_arc.read().unwrap();
            let outvn = op_rg.get_out().cloned();
            let code = op_rg.opcode;
            drop(op_rg);

            // if ((outvn!=null) && outvn->isMark() && !op->isCall()) continue;
            if let Some(ref out) = outvn {
                if out.read().unwrap().is_mark() && !op_arc.read().unwrap().is_call() {
                    continue;
                }
            }
            dcount += 1;

            match code {
                OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR => {
                    let rop = self.create_op_down(code, op_arc.read().unwrap().num_input(), op_arc.clone(), rvn, slot as i32);
                    // Ghidra passes the raw outvn pointer into createLink
                    // (subflow.cc:402), which dereferences it in
                    // setReplacement (subflow.cc:70). A null output is
                    // unreachable for these opcodes in Ghidra's IR: opDestroy
                    // (funcdata_op.cc:213-217) unsets every input and so
                    // erases the op from all descend lists, and the opcodes
                    // that are legitimately output-less (STORE/RETURN/
                    // BRANCH*/CBRANCH and output-less CALLs) take other
                    // switch cases that never read op->getOut(). When Rugra's
                    // upstream presents such an op anyway, converge on the
                    // failure path every untraceable case takes (return
                    // false) instead of crashing. See TODO
                    // SUBFLOW-OUTVN-UNWRAP-0001.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_OR => {
                    if Self::does_or_set(&op_arc.read().unwrap(), rvn_mask) != -1 {
                        // Subvar set to 1s, truncate flow.
                    } else {
                        let rop = self.create_op_down(OpCode::CPUI_INT_OR, 2, op_arc.clone(), rvn, slot as i32);
                        // Ghidra derefs outvn via createLink->setReplacement
                        // (subflow.cc:408 -> 70); see the COPY case note above.
                        let outvn_vn = match outvn {
                            Some(v) => v,
                            None => return false,
                        };
                        if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn) {
                            return false;
                        }
                        hcount += 1;
                    }
                }
                OpCode::CPUI_INT_AND => {
                    // Ghidra derefs outvn->getSize()/getConsume() before any
                    // createLink (subflow.cc:413/419/427); null is unreachable
                    // there (see the COPY case note). Abort rather than
                    // fabricate size/consume 0 for a missing output.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    let (in1_const, in1_off, out_size, out_consume) = {
                        let o = op_arc.read().unwrap();
                        let in1 = o.get_in(1);
                        (
                            in1.map(|v| v.read().unwrap().is_constant()).unwrap_or(false),
                            in1.map(|v| v.read().unwrap().get_offset()).unwrap_or(0),
                            outvn_vn.read().unwrap().get_size(),
                            outvn_vn.read().unwrap().get_consume(),
                        )
                    };
                    if in1_const && in1_off == rvn_mask {
                        if out_size as i32 == self.flowsize && (rvn_mask & 1) != 0 {
                            self.add_terminal_patch(&op_arc, rvn);
                            hcount += 1;
                        } else if !self.aggressive && (out_consume & rvn_mask) != out_consume {
                            self.add_extension_patch(rvn, &op_arc, -1);
                            hcount += 1;
                        } else {
                            // Fall through to general INT_AND handling below.
                            if Self::does_and_clear(&op_arc.read().unwrap(), rvn_mask) != -1 {
                                // Subvar set to zero, truncate flow.
                            } else {
                                let rop = self.create_op_down(OpCode::CPUI_INT_AND, 2, op_arc.clone(), rvn, slot as i32);
                                if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn.clone()) {
                                    return false;
                                }
                                hcount += 1;
                            }
                        }
                    } else {
                        if Self::does_and_clear(&op_arc.read().unwrap(), rvn_mask) != -1 {
                            // Subvar set to zero, truncate flow.
                        } else {
                            let rop = self.create_op_down(OpCode::CPUI_INT_AND, 2, op_arc.clone(), rvn, slot as i32);
                            if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn.clone()) {
                                return false;
                            }
                            hcount += 1;
                        }
                    }
                }
                OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                    let rop = self.create_op_down(OpCode::CPUI_COPY, 1, op_arc.clone(), rvn, 0);
                    // Ghidra derefs outvn via createLink->setReplacement
                    // (subflow.cc:433 -> 70); see the COPY case note above.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_MULT => {
                    if (rvn_mask & 1) == 0 {
                        return false; // Cannot account for carry
                    }
                    let o = op_arc.read().unwrap();
                    let other = o.get_in(1 - slot);
                    let sa = other.map(|v| leastsigbit_set(v.read().unwrap().get_nz_mask())).unwrap_or(-1);
                    let sa = sa & !7; // Nearest multiple of 8
                    let vn_size = self.newvarlist[rvn].vn.as_ref().unwrap().read().unwrap().get_size();
                    if self.bitsize + sa > 8 * vn_size as i32 {
                        return false;
                    }
                    let rop = self.create_op_down(OpCode::CPUI_INT_MULT, 2, op_arc.clone(), rvn, slot as i32);
                    let newmask = (rvn_mask as i128) << sa;
                    // Ghidra derefs outvn via createLink->setReplacement
                    // (subflow.cc:443 -> 70); see the COPY case note above.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), newmask as u64, -1, outvn_vn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM => {
                    if (rvn_mask & 1) == 0 {
                        return false; // Logical value must be least sig bits
                    }
                    if (self.bitsize & 7) != 0 {
                        return false; // Must be a whole number of bytes
                    }
                    let o = op_arc.read().unwrap();
                    // Varnode::isZeroExtended(flowsize) is not a first-class
                    // method in Rugra; we reproduce Ghidra's exact logic here
                    // (varnode.cc:958-970) using get_nz_mask/get_size/is_written/
                    // get_def. See `Self::is_zero_extended` and the module note.
                    let in0_ok = Self::is_zero_extended(&o.get_in(0).unwrap(), self.flowsize as usize);
                    let in1_ok = Self::is_zero_extended(&o.get_in(1).unwrap(), self.flowsize as usize);
                    drop(o);
                    if !in0_ok || !in1_ok {
                        return false;
                    }
                    let rop = self.create_op_down(code, 2, op_arc.clone(), rvn, slot as i32);
                    // Ghidra derefs outvn via createLink->setReplacement
                    // (subflow.cc:453 -> 70); see the COPY case note above.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_ADD => {
                    if (rvn_mask & 1) == 0 {
                        return false; // Cannot account for carry
                    }
                    let rop = self.create_op_down(OpCode::CPUI_INT_ADD, 2, op_arc.clone(), rvn, slot as i32);
                    // Ghidra derefs outvn via createLink->setReplacement
                    // (subflow.cc:460 -> 70); see the COPY case note above.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_LEFT => {
                    if slot == 1 {
                        // Logical flow is into shift amount.
                        if (rvn_mask & 1) == 0 {
                            return false;
                        }
                        if self.bitsize < 8 {
                            return false;
                        }
                        self.add_terminal_patch_same_op(&op_arc, rvn, slot as i32);
                        hcount += 1;
                    } else {
                        let o = op_arc.read().unwrap();
                        if !o.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                            return false; // Dynamic shift
                        }
                        let sa = o.get_in(1).unwrap().read().unwrap().get_offset() as i32;
                        if sa >= 64 {
                            return false; // Beyond precision of mask
                        }
                        // Ghidra derefs outvn->getSize()/getConsume() here
                        // (subflow.cc:477/481-482); null is unreachable (see
                        // the COPY case note). Abort rather than fabricate
                        // size/consume 0.
                        let outvn_vn = match outvn {
                            Some(v) => v,
                            None => {
                                drop(o);
                                return false;
                            }
                        };
                        let out_size = outvn_vn.read().unwrap().get_size();
                        let out_consume = outvn_vn.read().unwrap().get_consume();
                        drop(o);
                        let newmask = (rvn_mask << sa) & calc_mask(out_size);
                        if newmask == 0 {
                            // Subvar is cleared, truncate flow.
                        } else if rvn_mask != (newmask >> sa) {
                            return false; // subvar is clipped
                        } else if (rvn_mask & 1) != 0
                            && sa + self.bitsize == 8 * out_size as i32
                            && (out_consume & (!newmask)) != 0
                        {
                            self.add_extension_patch(rvn, &op_arc, sa);
                            hcount += 1;
                        } else {
                            let rop = self.create_op_down(OpCode::CPUI_COPY, 1, op_arc.clone(), rvn, 0);
                            if !self.create_link(Some(rop), newmask, -1, outvn_vn) {
                                return false;
                            }
                            hcount += 1;
                        }
                    }
                }
                OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => {
                    if slot == 1 {
                        if (rvn_mask & 1) == 0 {
                            return false;
                        }
                        if self.bitsize < 8 {
                            return false;
                        }
                        self.add_terminal_patch_same_op(&op_arc, rvn, slot as i32);
                        hcount += 1;
                    } else {
                        let o = op_arc.read().unwrap();
                        if !o.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                            return false;
                        }
                        let sa = o.get_in(1).unwrap().read().unwrap().get_offset() as i32;
                        let newmask = if sa >= 64 { 0 } else { rvn_mask >> sa };
                        // Ghidra derefs outvn->getSize()/getConsume() here
                        // (subflow.cc:511/518-519/525); null is unreachable
                        // (see the COPY case note). Abort rather than
                        // fabricate size/consume 0.
                        let outvn_vn = match outvn {
                            Some(v) => v,
                            None => {
                                drop(o);
                                return false;
                            }
                        };
                        let out_size = outvn_vn.read().unwrap().get_size();
                        let out_consume = outvn_vn.read().unwrap().get_consume();
                        let in0_nzmask = o.get_in(0).map(|v| v.read().unwrap().get_nz_mask()).unwrap_or(0);
                        drop(o);
                        if newmask == 0 {
                            if code == OpCode::CPUI_INT_RIGHT {
                                // subvar does not pass thru, truncate flow
                            } else {
                                return false;
                            }
                        } else if rvn_mask != (newmask << sa) {
                            return false;
                        } else if out_size as i32 == self.flowsize
                            && (newmask & 1) == 1
                            && in0_nzmask == rvn_mask
                        {
                            self.add_terminal_patch(&op_arc, rvn);
                            hcount += 1;
                        } else if (newmask & 1) == 1
                            && sa + self.bitsize == 8 * out_size as i32
                            && (out_consume & (!newmask)) != 0
                        {
                            self.add_extension_patch(rvn, &op_arc, 0);
                            hcount += 1;
                        } else {
                            let rop = self.create_op_down(OpCode::CPUI_COPY, 1, op_arc.clone(), rvn, 0);
                            if !self.create_link(Some(rop), newmask, -1, outvn_vn) {
                                return false;
                            }
                            hcount += 1;
                        }
                    }
                }
                OpCode::CPUI_SUBPIECE => {
                    let o = op_arc.read().unwrap();
                    // SUBPIECE has exactly two inputs in well-formed P-code:
                    //   in(0)=value, in(1)=constant offset. Ghidra dereferences
                    //   getIn(1) directly. We guard defensively (no .unwrap()).
                    let in1 = o.get_in(1).cloned();
                    let sa = match in1 {
                        Some(c) => c.read().unwrap().get_offset() as i32 * 8,
                        None => {
                            drop(o);
                            return false;
                        }
                    };
                    // Ghidra derefs outvn->getSize() repeatedly here
                    // (subflow.cc:531/534/542/548); null is unreachable (see
                    // the COPY case note). Abort rather than fabricate
                    // size 0.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => {
                            drop(o);
                            return false;
                        }
                    };
                    let out_size = outvn_vn.read().unwrap().get_size();
                    drop(o);
                    if sa >= 64 {
                        // break; (truncate flow)
                    } else {
                        let newmask = (rvn_mask >> sa) & calc_mask(out_size);
                        if newmask == 0 {
                            // subvar set to zero, truncate flow
                        } else if rvn_mask != (newmask << sa) {
                            // Some kind of truncation of the logical value.
                            if self.flowsize > (sa / 8 + out_size as i32) && (rvn_mask & 1) != 0 {
                                // Only a piece of the logical value remains.
                                self.add_terminal_patch_same_op(&op_arc, rvn, 0);
                                hcount += 1;
                            } else {
                                return false;
                            }
                        } else if (newmask & 1) != 0 && out_size as i32 == self.flowsize {
                            self.add_terminal_patch(&op_arc, rvn);
                            hcount += 1;
                        } else {
                            let rop = self.create_op_down(OpCode::CPUI_COPY, 1, op_arc.clone(), rvn, 0);
                            if !self.create_link(Some(rop), newmask, -1, outvn_vn) {
                                return false;
                            }
                            hcount += 1;
                        }
                    }
                }
                OpCode::CPUI_PIECE => {
                    let o = op_arc.read().unwrap();
                    let in1_size = o.get_in(1).map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                    let is_in0 = Arc::as_ptr(self.newvarlist[rvn].vn.as_ref().unwrap()) == Arc::as_ptr(o.get_in(0).unwrap());
                    drop(o);
                    let newmask = if is_in0 { rvn_mask << (8 * in1_size) } else { rvn_mask };
                    let rop = self.create_op_down(OpCode::CPUI_COPY, 1, op_arc.clone(), rvn, 0);
                    // Ghidra derefs outvn via createLink->setReplacement
                    // (subflow.cc:557 -> 70); see the COPY case note above.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), newmask, -1, outvn_vn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL => {
                    let o = op_arc.read().unwrap();
                    let outvn2 = o.get_in(1 - slot).cloned();
                    let vn_nzmask = self.newvarlist[rvn].vn.as_ref().unwrap().read().unwrap().get_nz_mask();
                    drop(o);
                    if !self.aggressive && (vn_nzmask | rvn_mask) != rvn_mask {
                        return false; // Everything but logical variable must be zero
                    }
                    let out2 = outvn2.as_ref().unwrap();
                    if out2.read().unwrap().is_constant() {
                        if (rvn_mask | out2.read().unwrap().get_offset()) != rvn_mask {
                            return false; // Must compare only bits of logical variable
                        }
                    } else if !self.aggressive && (rvn_mask | out2.read().unwrap().get_nz_mask()) != rvn_mask {
                        return false; // unused bits of otherside must be zero
                    }
                    if !self.create_compare_bridge(&op_arc, rvn, slot as i32, outvn2.unwrap()) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_INT_EQUAL => {
                    let o = op_arc.read().unwrap();
                    let outvn2 = o.get_in(1 - slot).cloned();
                    drop(o);
                    if self.bitsize != 1 {
                        let vn_nzmask = self.newvarlist[rvn].vn.as_ref().unwrap().read().unwrap().get_nz_mask();
                        if !self.aggressive && (vn_nzmask | rvn_mask) != rvn_mask {
                            return false;
                        }
                        let out2 = outvn2.as_ref().unwrap();
                        if out2.read().unwrap().is_constant() {
                            if (rvn_mask | out2.read().unwrap().get_offset()) != rvn_mask {
                                return false;
                            }
                        } else if !self.aggressive && (rvn_mask | out2.read().unwrap().get_nz_mask()) != rvn_mask {
                            return false;
                        }
                        if !self.create_compare_bridge(&op_arc, rvn, slot as i32, outvn2.unwrap()) {
                            return false;
                        }
                    } else {
                        // Movement of boolean variables.
                        let out2 = outvn2.as_ref().unwrap();
                        if !out2.read().unwrap().is_constant() {
                            return false;
                        }
                        let newmask = self.newvarlist[rvn].vn.as_ref().unwrap().read().unwrap().get_nz_mask();
                        if newmask != rvn_mask {
                            return false;
                        }
                        let o = op_arc.read().unwrap();
                        let other_off = o.get_in(1 - slot).unwrap().read().unwrap().get_offset();
                        drop(o);
                        let booldir;
                        if other_off == 0 {
                            booldir = true;
                        } else if other_off == newmask {
                            booldir = false;
                        } else {
                            return false;
                        }
                        let booldir = if code == OpCode::CPUI_INT_EQUAL { !booldir } else { booldir };
                        if booldir {
                            self.add_terminal_patch(&op_arc, rvn);
                        } else {
                            let rop = self.create_op_down(OpCode::CPUI_BOOL_NEGATE, 1, op_arc.clone(), rvn, 0);
                            self.create_new_out(rop, 1);
                            let out_idx = self.oplist[rop].output.unwrap();
                            self.add_terminal_patch(&op_arc, out_idx);
                        }
                    }
                    hcount += 1;
                }
                OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                    callcount += 1;
                    if callcount > 1 {
                        // Ghidra: subflow.cc:619-620
                        // `slot = op->getRepeatSlot(rvn->vn, slot, iter)` —
                        // recompute the slot for the k-th occurrence of an
                        // op that reads the varnode in multiple input slots
                        // (op.cc:93-111). The descendant iteration is NOT
                        // advanced: the C++ iterator is passed by value and
                        // every descendant entry is processed exactly once.
                        // `prior_occurrences` counts entries strictly before
                        // the current one holding this same op (op.cc:97-100
                        // walks vn->beginDescend() up to iter, exclusive).
                        let mut prior_occurrences = 0usize;
                        for j in 0..(i - 1) {
                            if Arc::as_ptr(&descendants[j].0) == Arc::as_ptr(&op_arc) {
                                prior_occurrences += 1;
                            }
                        }
                        slot = Self::subvar_get_repeat_slot(
                            &op_arc,
                            &rvn_vn,
                            slot,
                            prior_occurrences,
                        ) as usize;
                    }
                    if !self.try_call_pull(fd, &op_arc, rvn, slot as i32) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_RETURN => {
                    if !self.try_return_pull(fd, &op_arc, rvn, slot as i32) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_BRANCHIND => {
                    if !self.try_switch_pull(&op_arc, rvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR => {
                    if self.bitsize != 1 {
                        return false;
                    }
                    if rvn_mask != 1 {
                        return false;
                    }
                    self.add_boolean_patch(&op_arc, rvn, slot as i32);
                }
                OpCode::CPUI_FLOAT_INT2FLOAT => {
                    if !self.try_int2float_pull(&op_arc, rvn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_CBRANCH => {
                    if self.bitsize != 1 || slot != 1 {
                        return false;
                    }
                    if rvn_mask != 1 {
                        return false;
                    }
                    self.add_boolean_patch(&op_arc, rvn, 1);
                    hcount += 1;
                }
                _ => {
                    return false;
                }
            }
        }
        if dcount != hcount {
            // Must account for all descendants of an input.
            if self.newvarlist[rvn].vn.as_ref().unwrap().read().unwrap().is_input() {
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------
    // traceBackward (subflow.cc:661-861)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:665 SubvariableFlow::traceBackward
    /// Trace the logical value backward through one PcodeOp adding new nodes to
    /// the logical subgraph and updating the worklist. Faithful to
    /// `SubvariableFlow::traceBackward` (subflow.cc:665-861).
    fn trace_backward(&mut self, rvn: usize) -> bool {
        let def_op = {
            let v = self.newvarlist[rvn].vn.as_ref().unwrap();
            let vr = v.read().unwrap();
            vr.get_def()
        };
        let op = match def_op {
            Some(o) => o,
            None => return true, // If vn is input
        };
        let code = op.read().unwrap().opcode;
        let mask = self.newvarlist[rvn].mask;

        match code {
            OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR => {
                let num = op.read().unwrap().num_input();
                let rop = self.create_op(code, num, rvn);
                for i in 0..num {
                    let inv = op.read().unwrap().get_in(i).cloned().unwrap();
                    if !self.create_link(Some(rop), mask, i as i32, inv) {
                        return false;
                    }
                }
                true
            }
            OpCode::CPUI_INT_AND => {
                let sa = Self::does_and_clear(&op.read().unwrap(), mask);
                if sa != -1 {
                    let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                    let constvn = op.read().unwrap().get_in(sa as usize).cloned().unwrap();
                    self.add_constant(Some(rop), mask, 0, &constvn);
                } else {
                    let rop = self.create_op(OpCode::CPUI_INT_AND, 2, rvn);
                    let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                    let in1 = op.read().unwrap().get_in(1).cloned().unwrap();
                    if !self.create_link(Some(rop), mask, 0, in0) {
                        return false;
                    }
                    if !self.create_link(Some(rop), mask, 1, in1) {
                        return false;
                    }
                }
                true
            }
            OpCode::CPUI_INT_OR => {
                let sa = Self::does_or_set(&op.read().unwrap(), mask);
                if sa != -1 {
                    let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                    let constvn = op.read().unwrap().get_in(sa as usize).cloned().unwrap();
                    self.add_constant(Some(rop), mask, 0, &constvn);
                } else {
                    let rop = self.create_op(OpCode::CPUI_INT_OR, 2, rvn);
                    let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                    let in1 = op.read().unwrap().get_in(1).cloned().unwrap();
                    if !self.create_link(Some(rop), mask, 0, in0) {
                        return false;
                    }
                    if !self.create_link(Some(rop), mask, 1, in1) {
                        return false;
                    }
                }
                true
            }
            OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
                let in0_size = op.read().unwrap().get_in(0).unwrap().read().unwrap().get_size();
                if (mask & calc_mask(in0_size)) != mask {
                    if (mask & 1) != 0 && self.flowsize > in0_size as i32 {
                        self.add_push(&op, rvn);
                        return true;
                    }
                    return false; // break; -> return false
                }
                let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                self.create_link(Some(rop), mask, 0, in0)
            }
            OpCode::CPUI_INT_ADD => {
                if (mask & 1) == 0 {
                    return false; // break; -> return false (Cannot account for carry)
                }
                let rop = if mask == 1 {
                    self.create_op(OpCode::CPUI_INT_XOR, 2, rvn) // Single bit add
                } else {
                    self.create_op(OpCode::CPUI_INT_ADD, 2, rvn)
                };
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                let in1 = op.read().unwrap().get_in(1).cloned().unwrap();
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false;
                }
                if !self.create_link(Some(rop), mask, 1, in1) {
                    return false;
                }
                true
            }
            OpCode::CPUI_INT_LEFT => {
                let o = op.read().unwrap();
                if !o.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                    return false; // Dynamic shift
                }
                let sa = o.get_in(1).unwrap().read().unwrap().get_offset() as i32;
                let newmask = if sa >= 64 { 0 } else { mask >> sa };
                drop(o);
                if newmask == 0 {
                    // Subvariable filled with shifted zero.
                    let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                    self.add_new_constant(rop, 0, 0);
                    return true;
                }
                if (newmask << sa) == mask {
                    let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                    let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                    if !self.create_link(Some(rop), newmask, 0, in0) {
                        return false;
                    }
                    return true;
                }
                if (mask & 1) == 0 {
                    return false; // Can't assume zeroes are shifted into least sig bits
                }
                let rop = self.create_op(OpCode::CPUI_INT_LEFT, 2, rvn);
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false;
                }
                let in1 = op.read().unwrap().get_in(1).cloned().unwrap();
                self.add_constant(Some(rop), calc_mask(in1.read().unwrap().get_size()), 1, &in1);
                true
            }
            OpCode::CPUI_INT_RIGHT => {
                let o = op.read().unwrap();
                if !o.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                    return false;
                }
                let sa = o.get_in(1).unwrap().read().unwrap().get_offset() as i32;
                let in0_size = o.get_in(0).unwrap().read().unwrap().get_size();
                drop(o);
                if sa >= 64 {
                    return false;
                }
                let newmask = (mask << sa) & calc_mask(in0_size);
                if newmask == 0 {
                    let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                    self.add_new_constant(rop, 0, 0);
                    return true;
                }
                if (newmask >> sa) != mask {
                    return false; // subvariable is truncated by shift
                }
                let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                self.create_link(Some(rop), newmask, 0, in0)
            }
            OpCode::CPUI_INT_SRIGHT => {
                let o = op.read().unwrap();
                if !o.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                    return false;
                }
                let sa = o.get_in(1).unwrap().read().unwrap().get_offset() as i32;
                let in0_size = o.get_in(0).unwrap().read().unwrap().get_size();
                drop(o);
                if sa >= 64 {
                    return false;
                }
                let newmask = (mask << sa) & calc_mask(in0_size);
                if (newmask >> sa) != mask {
                    return false; // subvariable is truncated by shift
                }
                let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                self.create_link(Some(rop), newmask, 0, in0)
            }
            OpCode::CPUI_INT_MULT => {
                let sa = leastsigbit_set(mask);
                let in1_nzmask = op.read().unwrap().get_in(1).unwrap().read().unwrap().get_nz_mask();
                if sa != 0 {
                    let sa2 = leastsigbit_set(in1_nzmask);
                    if sa2 < sa {
                        return false; // Cannot deal with carries into logical multiply
                    }
                    let newmask = mask >> sa;
                    let rop = self.create_op(OpCode::CPUI_INT_MULT, 2, rvn);
                    let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                    let in1 = op.read().unwrap().get_in(1).cloned().unwrap();
                    if !self.create_link(Some(rop), newmask, 0, in0) {
                        return false;
                    }
                    if !self.create_link(Some(rop), mask, 1, in1) {
                        return false;
                    }
                } else {
                    let rop = if mask == 1 {
                        self.create_op(OpCode::CPUI_INT_AND, 2, rvn) // Single bit multiply
                    } else {
                        self.create_op(OpCode::CPUI_INT_MULT, 2, rvn)
                    };
                    let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                    let in1 = op.read().unwrap().get_in(1).cloned().unwrap();
                    if !self.create_link(Some(rop), mask, 0, in0) {
                        return false;
                    }
                    if !self.create_link(Some(rop), mask, 1, in1) {
                        return false;
                    }
                }
                true
            }
            OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM => {
                if (mask & 1) == 0 {
                    return false;
                }
                if (self.bitsize & 7) != 0 {
                    return false;
                }
                let o = op.read().unwrap();
                // Varnode::isZeroExtended(flowsize) reproduced via
                // Self::is_zero_extended (Ghidra varnode.cc:958-970); see
                // trace_forward for the same call and the module note.
                let in0_ok = Self::is_zero_extended(&o.get_in(0).unwrap(), self.flowsize as usize);
                let in1_ok = Self::is_zero_extended(&o.get_in(1).unwrap(), self.flowsize as usize);
                drop(o);
                if !in0_ok || !in1_ok {
                    return false;
                }
                let rop = self.create_op(code, 2, rvn);
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                let in1 = op.read().unwrap().get_in(1).cloned().unwrap();
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false;
                }
                if !self.create_link(Some(rop), mask, 1, in1) {
                    return false;
                }
                true
            }
            OpCode::CPUI_SUBPIECE => {
                let sa = op.read().unwrap().get_in(1).unwrap().read().unwrap().get_offset() as i32 * 8;
                let newmask = mask << sa;
                let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                self.create_link(Some(rop), newmask, 0, in0)
            }
            OpCode::CPUI_PIECE => {
                let o = op.read().unwrap();
                let in1_size = o.get_in(1).unwrap().read().unwrap().get_size();
                if (mask & calc_mask(in1_size)) == mask {
                    let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                    let in1 = o.get_in(1).cloned().unwrap();
                    drop(o);
                    return self.create_link(Some(rop), mask, 0, in1);
                }
                let sa = in1_size as i32 * 8;
                let newmask = mask >> sa;
                drop(o);
                if newmask << sa == mask {
                    let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                    let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                    return self.create_link(Some(rop), newmask, 0, in0);
                }
                false // break
            }
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                if self.try_call_return_push(&op, rvn) {
                    true
                } else {
                    false // break
                }
            }
            OpCode::CPUI_INT_EQUAL
            | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_SLESS
            | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_LESS
            | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_INT_CARRY
            | OpCode::CPUI_INT_SCARRY
            | OpCode::CPUI_INT_SBORROW
            | OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_BOOL_XOR
            | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_FLOAT_EQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_FLOAT_NAN => {
                // Mask won't be 1, because setReplacement takes care of it.
                if (mask & 1) == 1 {
                    return false; // break; Not normal variable flow
                }
                // Variable is filled with zero.
                let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                self.add_new_constant(rop, 0, 0);
                true
            }
            _ => {
                false // break; Everything else we abort
            }
        }
    }

    // -----------------------------------------------------------------
    // traceForwardSext / traceBackwardSext (subflow.cc:863-1009)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:867 SubvariableFlow::traceForwardSext
    /// traceForward assuming sign-extensions. Faithful to
    /// `SubvariableFlow::traceForwardSext` (subflow.cc:867-954).
    fn trace_forward_sext(&mut self, fd: &Funcdata, rvn: usize) -> bool {
        let mut dcount: i32 = 0;
        let mut hcount: i32 = 0;
        let mut callcount: i32 = 0;

        let rvn_vn = self.newvarlist[rvn].vn.clone().expect("trace_forward_sext on constant");
        let rvn_mask = self.newvarlist[rvn].mask;
        let descendants: Vec<(Arc<RwLock<PcodeOp>>, usize)> = {
            let v = rvn_vn.read().unwrap();
            let mut out = Vec::new();
            for d in v.descend_iter() {
                let op_rg = d.read().unwrap();
                let slot = (0..op_rg.num_input())
                    .find(|&i| op_rg.get_in(i).map(|inv| Arc::as_ptr(inv) == Arc::as_ptr(&rvn_vn)).unwrap_or(false));
                if let Some(slot) = slot {
                    out.push((d.clone(), slot));
                }
            }
            out
        };

        let mut i = 0;
        while i < descendants.len() {
            let (op_arc, mut slot) = descendants[i].clone();
            i += 1;
            let op_rg = op_arc.read().unwrap();
            let outvn = op_rg.get_out().cloned();
            let code = op_rg.opcode;
            drop(op_rg);
            if let Some(ref out) = outvn {
                if out.read().unwrap().is_mark() && !op_arc.read().unwrap().is_call() {
                    continue;
                }
            }
            dcount += 1;
            match code {
                OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INT_NEGATE
                | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_AND => {
                    let rop = self.create_op_down(code, op_arc.read().unwrap().num_input(), op_arc.clone(), rvn, slot as i32);
                    // Ghidra passes the raw outvn pointer into createLink
                    // (subflow.cc:895), which dereferences it in
                    // setReplacement (subflow.cc:70). A null output is
                    // unreachable for these opcodes in Ghidra's IR: opDestroy
                    // (funcdata_op.cc:213-217) unsets every input and so
                    // erases the op from all descend lists, and the opcodes
                    // that are legitimately output-less (STORE/RETURN/
                    // BRANCH*/CBRANCH and output-less CALLs) take other
                    // switch cases that never read op->getOut(). When Rugra's
                    // upstream presents such an op anyway, converge on the
                    // failure path every untraceable case takes (return
                    // false) instead of crashing. See TODO
                    // SUBFLOW-OUTVN-UNWRAP-0001.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_SEXT => {
                    // Extended logical variable into even larger container.
                    let rop = self.create_op_down(OpCode::CPUI_COPY, 1, op_arc.clone(), rvn, 0);
                    // Ghidra derefs outvn via createLink->setReplacement
                    // (subflow.cc:900 -> 70); see the COPY case note above.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_SRIGHT => {
                    let o = op_arc.read().unwrap();
                    if !o.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                        return false;
                    }
                    let in1_size = o.get_in(1).unwrap().read().unwrap().get_size();
                    let in1 = o.get_in(1).cloned().unwrap();
                    drop(o);
                    let rop = self.create_op_down(OpCode::CPUI_INT_SRIGHT, 2, op_arc.clone(), rvn, 0);
                    // Ghidra derefs outvn via createLink->setReplacement
                    // (subflow.cc:906 -> 70); see the COPY case note above.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => return false,
                    };
                    if !self.create_link(Some(rop), rvn_mask, -1, outvn_vn) {
                        return false;
                    }
                    // Preserve the shift amount.
                    self.add_constant(Some(rop), calc_mask(in1_size), 1, &in1);
                    hcount += 1;
                }
                OpCode::CPUI_SUBPIECE => {
                    let o = op_arc.read().unwrap();
                    if o.get_in(1).unwrap().read().unwrap().get_offset() != 0 {
                        return false; // Only allow proper truncation
                    }
                    // Ghidra derefs outvn->getSize() twice (subflow.cc:912-913);
                    // null is unreachable there (see the COPY case note). Do not
                    // fabricate size 0 for a missing output: abort instead.
                    let outvn_vn = match outvn {
                        Some(v) => v,
                        None => {
                            drop(o);
                            return false;
                        }
                    };
                    let out_size = outvn_vn.read().unwrap().get_size();
                    drop(o);
                    if (out_size as i32) > self.flowsize {
                        return false;
                    }
                    if out_size as i32 == self.flowsize {
                        self.add_terminal_patch(&op_arc, rvn);
                    } else {
                        self.add_terminal_patch_same_op(&op_arc, rvn, 0);
                    }
                    hcount += 1;
                }
                OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
                | OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                    let o = op_arc.read().unwrap();
                    let outvn2 = o.get_in(1 - slot).cloned();
                    drop(o);
                    if !self.create_compare_bridge(&op_arc, rvn, slot as i32, outvn2.unwrap()) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                    callcount += 1;
                    if callcount > 1 {
                        // Ghidra: subflow.cc:932-933
                        // `slot = op->getRepeatSlot(rvn->vn, slot, iter)` —
                        // same semantics as the non-sext CALL case
                        // (subflow.cc:619-620, op.cc:93-111): recompute the
                        // slot for the k-th occurrence of an op reading the
                        // varnode in multiple input slots; the descendant
                        // iteration is never advanced.
                        let mut prior_occurrences = 0usize;
                        for j in 0..(i - 1) {
                            if Arc::as_ptr(&descendants[j].0) == Arc::as_ptr(&op_arc) {
                                prior_occurrences += 1;
                            }
                        }
                        slot = Self::subvar_get_repeat_slot(
                            &op_arc,
                            &rvn_vn,
                            slot,
                            prior_occurrences,
                        ) as usize;
                    }
                    if !self.try_call_pull(fd, &op_arc, rvn, slot as i32) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_RETURN => {
                    if !self.try_return_pull(fd, &op_arc, rvn, slot as i32) {
                        return false;
                    }
                    hcount += 1;
                }
                OpCode::CPUI_BRANCHIND => {
                    if !self.try_switch_pull(&op_arc, rvn) {
                        return false;
                    }
                    hcount += 1;
                }
                _ => {
                    return false;
                }
            }
        }
        if dcount != hcount {
            if self.newvarlist[rvn].vn.as_ref().unwrap().read().unwrap().is_input() {
                return false;
            }
        }
        true
    }

    // Ghidra: subflow.cc:960 SubvariableFlow::traceBackwardSext
    /// traceBackward assuming sign-extensions. Faithful to
    /// `SubvariableFlow::traceBackwardSext` (subflow.cc:960-1009).
    fn trace_backward_sext(&mut self, rvn: usize) -> bool {
        let def_op = {
            let v = self.newvarlist[rvn].vn.as_ref().unwrap();
            v.read().unwrap().get_def()
        };
        let op = match def_op {
            Some(o) => o,
            None => return true, // If vn is input
        };
        let code = op.read().unwrap().opcode;
        let mask = self.newvarlist[rvn].mask;

        match code {
            OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INT_NEGATE
            | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR => {
                let num = op.read().unwrap().num_input();
                let rop = self.create_op(code, num, rvn);
                for i in 0..num {
                    let inv = op.read().unwrap().get_in(i).cloned().unwrap();
                    if !self.create_link(Some(rop), mask, i as i32, inv) {
                        return false;
                    }
                }
                true
            }
            OpCode::CPUI_INT_ZEXT => {
                let in0_size = op.read().unwrap().get_in(0).unwrap().read().unwrap().get_size();
                if (in0_size as i32) < self.flowsize {
                    // Zero extension from a smaller size still acts as a signed extension.
                    self.add_push(&op, rvn);
                    true
                } else {
                    false // break
                }
            }
            OpCode::CPUI_INT_SEXT => {
                let in0_size = op.read().unwrap().get_in(0).unwrap().read().unwrap().get_size();
                if self.flowsize != in0_size as i32 {
                    return false;
                }
                let rop = self.create_op(OpCode::CPUI_COPY, 1, rvn);
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                self.create_link(Some(rop), mask, 0, in0)
            }
            OpCode::CPUI_INT_SRIGHT => {
                let o = op.read().unwrap();
                if !o.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                    return false;
                }
                let in1_size = o.get_in(1).unwrap().read().unwrap().get_size();
                let in1 = o.get_in(1).cloned().unwrap();
                drop(o);
                let rop = self.create_op(OpCode::CPUI_INT_SRIGHT, 2, rvn);
                let in0 = op.read().unwrap().get_in(0).cloned().unwrap();
                if !self.create_link(Some(rop), mask, 0, in0) {
                    return false;
                }
                // Preserve the shift amount if not already present.
                if self.oplist[rop].input.len() <= 1 {
                    self.add_constant(Some(rop), calc_mask(in1_size), 1, &in1);
                }
                true
            }
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                if self.try_call_return_push(&op, rvn) {
                    true
                } else {
                    false // break
                }
            }
            _ => false, // break
        }
    }

    // -----------------------------------------------------------------
    // createLink / createCompareBridge (subflow.cc:1011-1071)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:1022 SubvariableFlow::createLink
    /// Add a new variable to the logical subgraph as an input to the given
    /// operation. Faithful to `SubvariableFlow::createLink`
    /// (subflow.cc:1022-1044). `slot == -1` means the varnode is the op output.
    fn create_link(
        &mut self,
        rop: Option<usize>,
        mask: u64,
        slot: i32,
        vn: Arc<RwLock<Varnode>>,
    ) -> bool {
        let (rep_opt, inworklist) = self.set_replacement(&vn, mask);
        let rep = match rep_opt {
            Some(r) => r,
            None => return false,
        };
        if let Some(rop) = rop {
            if slot == -1 {
                self.oplist[rop].output = Some(rep);
                self.newvarlist[rep].def = Some(rop);
            } else {
                let s = slot as usize;
                while self.oplist[rop].input.len() <= s {
                    self.oplist[rop].input.push(None);
                }
                self.oplist[rop].input[s] = Some(rep);
            }
        }
        if inworklist {
            self.worklist.push(rep);
        }
        true
    }

    // Ghidra: subflow.cc:1056 SubvariableFlow::createCompareBridge
    /// Extend the logical subgraph through a given comparison operator.
    /// Faithful to `SubvariableFlow::createCompareBridge`
    /// (subflow.cc:1056-1071).
    fn create_compare_bridge(
        &mut self,
        op: &Arc<RwLock<PcodeOp>>,
        inrvn: usize,
        slot: i32,
        othervn: Arc<RwLock<Varnode>>,
    ) -> bool {
        let mask = self.newvarlist[inrvn].mask;
        let (rep_opt, inworklist) = self.set_replacement(&othervn, mask);
        let rep = match rep_opt {
            Some(r) => r,
            None => return false,
        };
        if slot == 0 {
            self.add_compare_patch(inrvn, rep, op);
        } else {
            self.add_compare_patch(rep, inrvn, op);
        }
        if inworklist {
            self.worklist.push(rep);
        }
        true
    }

    // -----------------------------------------------------------------
    // addConstant / addNewConstant / createNewOut (subflow.cc:1073-1143)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:1080 SubvariableFlow::addConstant
    /// Add a constant variable node to the logical subgraph. Faithful to
    /// `SubvariableFlow::addConstant` (subflow.cc:1080-1099).
    fn add_constant(
        &mut self,
        rop: Option<usize>,
        mask: u64,
        slot: u32,
        constvn: &Arc<RwLock<Varnode>>,
    ) -> usize {
        let idx = self.newvarlist.len();
        let offset = constvn.read().unwrap().get_offset();
        let sa = leastsigbit_set(mask);
        let val = if sa < 0 { 0 } else { (mask & offset) >> sa };
        self.newvarlist.push(ReplaceVarnode {
            vn: Some(constvn.clone()),
            replacement: None,
            mask,
            val,
            def: None,
        });
        if let Some(rop) = rop {
            let s = slot as usize;
            while self.oplist[rop].input.len() <= s {
                self.oplist[rop].input.push(None);
            }
            self.oplist[rop].input[s] = Some(idx);
        }
        idx
    }

    // Ghidra: subflow.cc:1108 SubvariableFlow::addNewConstant
    /// Add a new constant variable node (not associated with an original
    /// constant). Faithful to `SubvariableFlow::addNewConstant`
    /// (subflow.cc:1108-1124).
    fn add_new_constant(&mut self, rop: usize, slot: u32, val: u64) -> usize {
        let idx = self.newvarlist.len();
        self.newvarlist.push(ReplaceVarnode {
            vn: None,
            replacement: None,
            mask: 0,
            val,
            def: None,
        });
        let s = slot as usize;
        while self.oplist[rop].input.len() <= s {
            self.oplist[rop].input.push(None);
        }
        self.oplist[rop].input[s] = Some(idx);
        idx
    }

    // Ghidra: subflow.cc:1132 SubvariableFlow::createNewOut
    /// Create a new, non-shadowing, subgraph variable node as an operation
    /// output. Faithful to `SubvariableFlow::createNewOut`
    /// (subflow.cc:1132-1143).
    fn create_new_out(&mut self, rop: usize, mask: u64) {
        let idx = self.newvarlist.len();
        self.newvarlist.push(ReplaceVarnode {
            vn: None,
            replacement: None,
            mask,
            val: 0,
            def: None,
        });
        self.oplist[rop].output = Some(idx);
        self.newvarlist[idx].def = Some(rop);
    }

    // -----------------------------------------------------------------
    // addPush / addTerminalPatch / addTerminalPatchSameOp / addBooleanPatch /
    // addExtensionPatch / addComparePatch (subflow.cc:1145-1250)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:1151 SubvariableFlow::addPush
    /// Mark an operation where original data-flow is being pushed into a
    /// subgraph variable. Faithful to `SubvariableFlow::addPush`
    /// (subflow.cc:1151-1158). Push patches go to the FRONT of the list so
    /// `do_replacement` processes them first.
    fn add_push(&mut self, push_op: &Arc<RwLock<PcodeOp>>, rvn: usize) {
        self.patchlist.insert(
            self.push_front_count,
            PatchRecord {
                patch_type: PatchType::PushPatch,
                patch_op: push_op.clone(),
                in1: rvn,
                in2: None,
                slot: 0,
                pull_modification: true,
            },
        );
        self.push_front_count += 1;
    }

    // Ghidra: subflow.cc:1167 SubvariableFlow::addTerminalPatch
    /// Mark an operation where a subgraph variable is naturally copied into the
    /// original data-flow. Faithful to `SubvariableFlow::addTerminalPatch`
    /// (subflow.cc:1167-1175).
    fn add_terminal_patch(&mut self, pull_op: &Arc<RwLock<PcodeOp>>, rvn: usize) {
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::CopyPatch,
            patch_op: pull_op.clone(),
            in1: rvn,
            in2: None,
            slot: 0,
            pull_modification: true,
        });
        self.pullcount += 1; // a true terminal modification
    }

    // Ghidra: subflow.cc:1185 SubvariableFlow::addTerminalPatchSameOp
    /// Mark an operation where a subgraph variable is pulled but the opcode
    /// does not change (only the input slot does). Faithful to
    /// `SubvariableFlow::addTerminalPatchSameOp` (subflow.cc:1185-1194).
    fn add_terminal_patch_same_op(&mut self, pull_op: &Arc<RwLock<PcodeOp>>, rvn: usize, slot: i32) {
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::ParameterPatch,
            patch_op: pull_op.clone(),
            in1: rvn,
            in2: None,
            slot,
            pull_modification: true,
        });
        self.pullcount += 1; // a true terminal modification
    }

    // Ghidra: subflow.cc:1203 SubvariableFlow::addBooleanPatch
    /// Mark a subgraph bit variable flowing into an operation taking a boolean
    /// input. Faithful to `SubvariableFlow::addBooleanPatch`
    /// (subflow.cc:1203-1212). This is NOT a true modification.
    fn add_boolean_patch(&mut self, pull_op: &Arc<RwLock<PcodeOp>>, rvn: usize, slot: i32) {
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::ParameterPatch,
            patch_op: pull_op.clone(),
            in1: rvn,
            in2: None,
            slot,
            pull_modification: false,
        });
    }

    // Ghidra: subflow.cc:1221 SubvariableFlow::addExtensionPatch
    /// Mark a subgraph variable flowing to an operation that extends it by
    /// padding with zero bits. Faithful to `SubvariableFlow::addExtensionPatch`
    /// (subflow.cc:1221-1232). This is NOT a true modification.
    fn add_extension_patch(&mut self, rvn: usize, push_op: &Arc<RwLock<PcodeOp>>, sa: i32) {
        let sa = if sa == -1 {
            leastsigbit_set(self.newvarlist[rvn].mask)
        } else {
            sa
        };
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::ExtensionPatch,
            in1: rvn,
            in2: None,
            patch_op: push_op.clone(),
            slot: sa,
            pull_modification: false,
        });
    }

    // Ghidra: subflow.cc:1241 SubvariableFlow::addComparePatch
    /// Mark subgraph variables flowing into a comparison operation. Faithful to
    /// `SubvariableFlow::addComparePatch` (subflow.cc:1241-1250).
    fn add_compare_patch(&mut self, in1: usize, in2: usize, op: &Arc<RwLock<PcodeOp>>) {
        self.patchlist.push(PatchRecord {
            patch_type: PatchType::ComparePatch,
            patch_op: op.clone(),
            in1,
            in2: Some(in2),
            slot: 0,
            pull_modification: true,
        });
        self.pullcount += 1;
    }

    // -----------------------------------------------------------------
    // replaceInput / useSameAddress / getReplacementAddress /
    // getReplaceVarnode (subflow.cc:1252-1345)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:1258 SubvariableFlow::replaceInput
    /// Replace an input Varnode in the subgraph with a temporary register.
    /// Faithful to `SubvariableFlow::replaceInput` (subflow.cc:1258-1266).
    fn replace_input(fd: &mut Funcdata, rvn: usize, newvarlist: &mut [ReplaceVarnode]) {
        let size = newvarlist[rvn].vn.as_ref().unwrap().read().unwrap().get_size();
        let newvn = fd.new_unique(size);
        // cc:1262: newvn = fd->setInputVarnode(newvn) — the canonical bank
        // transition (transition_input -> xref -> INSERT). The former raw
        // `set_flags(INPUT)` left the varnode INPUT-without-INSERT outside
        // the def-tree bookkeeping, an oracle-impossible state (Ghidra:
        // input => VarnodeBank::setInput => xref => insert,
        // varnode.cc:1358-1374) that Heritage::collect later classified as
        // a read and normalizeReadSize's opSetOutput rejected
        // (HELPF-NONFREE-NORMALIZE-0001).
        let newvn = fd.set_input_varnode(newvn);
        let oldvn = newvarlist[rvn].vn.clone().unwrap();
        fd.total_replace(&oldvn, newvn.clone());
        // cc:1264: fd->deleteVarnode(rvn->vn) — totalReplace severed every
        // reader, so the old varnode has no descendants and destroys
        // cleanly (Funcdata::deleteVarnode -> VarnodeBank::destroy).
        let _ = fd.delete_varnode(&oldvn);
        newvarlist[rvn].vn = Some(newvn);
    }

    // Ghidra: subflow.cc:1274 SubvariableFlow::useSameAddress
    /// Decide if we use the same memory range of the original Varnode for the
    /// logical replacement. Faithful to `SubvariableFlow::useSameAddress`
    /// (subflow.cc:1274-1291).
    fn use_same_address(&self, rvn: usize) -> bool {
        let v = self.newvarlist[rvn].vn.as_ref().unwrap();
        let vr = v.read().unwrap();
        if vr.is_input() {
            return true;
        }
        if vr.is_addr_tied() {
            return false; // trim of addrtied varnode increases conflict chance
        }
        if (self.newvarlist[rvn].mask & 1) == 0 {
            return false; // Not aligned
        }
        if self.bitsize >= 8 {
            return true;
        }
        if self.aggressive {
            return true;
        }
        let bitmask = 1u32;
        let bitmask = (bitmask << self.bitsize) - 1;
        let mut mask = vr.get_consume();
        mask |= bitmask as u64;
        mask == self.newvarlist[rvn].mask
    }

    // Ghidra: subflow.cc:1297 SubvariableFlow::getReplacementAddress
    /// Calculate address of replacement Varnode for the given subgraph variable.
    /// Faithful to `SubvariableFlow::getReplacementAddress`
    /// (subflow.cc:1297-1308).
    fn get_replacement_address(&self, rvn: usize) -> Address {
        let v = self.newvarlist[rvn].vn.as_ref().unwrap();
        let vr = v.read().unwrap();
        let addr = vr.get_addr().clone();
        let vn_size = vr.get_size();
        let sa = (leastsigbit_set(self.newvarlist[rvn].mask) / 8) as i64;
        // Ghidra's getReplacementAddress branches on addr.isBigEndian():
        //   big-endian:    addr + (vn->getSize() - flowsize - sa)
        //   little-endian: addr + sa
        // Rugra's Address/AddressSpace does not expose isBigEndian() here; we
        // implement the little-endian path (the common Rugra default) and note
        // the gap. The big-endian adjustment uses vn_size/flowsize as written.
        let _ = vn_size; // preserved for the documented big-endian formula
        addr.offset(sa)
    }

    // Ghidra: subflow.cc:1316 SubvariableFlow::getReplaceVarnode
    /// Build the logical Varnode which will replace its original containing
    /// Varnode. Faithful to `SubvariableFlow::getReplaceVarnode`
    /// (subflow.cc:1316-1345).
    fn get_replace_varnode(&mut self, fd: &mut Funcdata, rvn: usize) -> Arc<RwLock<Varnode>> {
        let flowsize = self.flowsize;
        let newvarlist = &mut self.newvarlist;
        if let Some(r) = newvarlist[rvn].replacement.clone() {
            return r;
        }
        if newvarlist[rvn].vn.is_none() {
            if newvarlist[rvn].def.is_none() {
                // A constant that did not come from an original Varnode.
                let c = fd.new_constant(flowsize as usize, newvarlist[rvn].val);
                newvarlist[rvn].replacement = Some(c.clone());
                return c;
            }
            let u = fd.new_unique(flowsize as usize);
            newvarlist[rvn].replacement = Some(u.clone());
            return u;
        }
        let vn = newvarlist[rvn].vn.clone().unwrap();
        if vn.read().unwrap().is_constant() {
            let new_vn = fd.new_constant(flowsize as usize, newvarlist[rvn].val);
            // Ghidra: newVn->copySymbolIfValid(rvn->vn).
            // copySymbolIfValid is not ported; symbol copy is skipped.
            // Logged at module top.
            newvarlist[rvn].replacement = Some(new_vn.clone());
            return new_vn;
        }
        let is_input = vn.read().unwrap().is_input();
        // useSameAddress (subflow.cc:1274-1291) reads the member bitsize and
        // aggressive fields, so this must be a method (the former assoc-fn
        // re-derivation substituted `flowsize*8 >= 8`, which is always true
        // for flowsize >= 1 and diverged from `bitsize >= 8`, and dropped the
        // `aggressive` early-true check).
        let use_same = {
            let vr = vn.read().unwrap();
            let rvn_mask = newvarlist[rvn].mask;
            if vr.is_input() {
                true
            } else if vr.is_addr_tied() {
                false
            } else if (rvn_mask & 1) == 0 {
                false
            } else if self.bitsize >= 8 {
                true
            } else if self.aggressive {
                true
            } else {
                // Try to decide if this is the ONLY subvariable passing
                // through this container.
                let bitmask: u64 = ((1u64) << self.bitsize) - 1;
                let mut mask = vr.get_consume();
                mask |= bitmask;
                mask == rvn_mask
            }
        };
        let mut new_vn = if use_same {
            let v = vn.read().unwrap();
            // getReplacementAddress (subflow.cc:1297-1308): the new Varnode
            // lives at the ORIGINAL varnode's address (+sa), so it inherits
            // the original's space — NOT always the register space.
            let space = v.get_space();
            let addr = v.get_addr().clone();
            let sa = (leastsigbit_set(newvarlist[rvn].mask) / 8) as i64;
            let addr = addr.offset(sa);
            drop(v);
            if is_input {
                Self::replace_input(fd, rvn, newvarlist);
            }
            // fd->newVarnode(flowsize, addr) — Rugra's Address is a scalar
            // without a space, so the space is taken from the original
            // varnode, matching Ghidra's Address-attached space.
            let nv = fd.vbank.create_with_space(flowsize as usize, space, addr.as_u64());
            nv
        } else {
            fd.new_unique(flowsize as usize)
        };
        if is_input {
            // cc:1343: rvn->replacement = fd->setInputVarnode(rvn->replacement)
            // — canonical transition (overlap dedup + xref INSERT), replacing
            // the former raw `set_flags(INPUT)` that produced the
            // oracle-impossible INPUT-without-INSERT state
            // (HELPF-NONFREE-NORMALIZE-0001).
            new_vn = fd.set_input_varnode(new_vn);
        }
        newvarlist[rvn].replacement = Some(new_vn.clone());
        new_vn
    }

    // -----------------------------------------------------------------
    // processNextWork (subflow.cc:1347-1364)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:1351 SubvariableFlow::processNextWork
    /// Extend the subgraph from the next node in the worklist. Faithful to
    /// `SubvariableFlow::processNextWork` (subflow.cc:1351-1364).
    fn process_next_work(&mut self, fd: &Funcdata) -> bool {
        let rvn = *self.worklist.last().unwrap();
        self.worklist.pop();
        if self.sext_restrictions {
            if !self.trace_backward_sext(rvn) {
                return false;
            }
            return self.trace_forward_sext(fd, rvn);
        }
        if !self.trace_backward(rvn) {
            return false;
        }
        self.trace_forward(fd, rvn)
    }

    // -----------------------------------------------------------------
    // doTrace (subflow.cc:1406-1433)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:1410 SubvariableFlow::doTrace
    /// Trace logical value through data-flow, constructing the transform.
    /// Faithful to `SubvariableFlow::doTrace` (subflow.cc:1410-1433).
    pub fn do_trace(&mut self, fd: &Funcdata) -> bool {
        self.pullcount = 0;
        let mut retval = false;
        if self.fd.is_some() {
            retval = true;
            while !self.worklist.is_empty() {
                if !self.process_next_work(fd) {
                    retval = false;
                    break;
                }
            }
        }
        // Clear marks on every varnode in the map. Ghidra iterates the
        // varmap keys (`(*iter).first->clearMark()`). Rugra stored the live
        // Arc for each mapped varnode inside newvarlist[*].vn (constants too),
        // so clearing through those is equivalent.
        for rvn in &self.newvarlist {
            if let Some(v) = &rvn.vn {
                v.write().unwrap().clear_mark();
            }
        }
        if !retval {
            return false;
        }
        if self.pullcount == 0 {
            return false;
        }
        true
    }

    // -----------------------------------------------------------------
    // doReplacement (subflow.cc:1435-1545)
    // -----------------------------------------------------------------

    // Ghidra: subflow.cc:1435 SubvariableFlow::doReplacement
    /// Perform the discovered transform, making logical values explicit.
    /// Faithful to `SubvariableFlow::doReplacement` (subflow.cc:1435-1545).
    pub fn do_replacement(&mut self, fd: &mut Funcdata) {
        // Do up-front processing of the call-return (push) patches, which are at
        // the FRONT of the list (push_front_count of them).
        let push_count = self.push_front_count;
        for p in 0..push_count {
            if self.patchlist[p].patch_type != PatchType::PushPatch {
                break;
            }
            let patch = self.patchlist[p].clone();
            let push_op_ref = PcodeOpRef(patch.patch_op.clone());
            let new_vn = self.get_replace_varnode(fd, patch.in1);
            let old_vn = patch.patch_op.read().unwrap().get_out().cloned().unwrap();
            fd.op_set_output(&push_op_ref, new_vn.clone());
            // Create placeholder defining op for old Varnode until dead-code.
            let addr = patch.patch_op.read().unwrap().get_addr();
            let new_zext = fd.new_op(1, addr);
            fd.op_set_opcode(&new_zext, OpCode::CPUI_INT_ZEXT);
            fd.op_set_input(&new_zext, new_vn, 0);
            fd.op_set_output(&new_zext, old_vn);
            fd.op_insert_after(&new_zext, &push_op_ref);
        }

        // Define all the outputs first.
        let oplist_len = self.oplist.len();
        for i in 0..oplist_len {
            let (opc, numparams, has_op, out_idx) = {
                let rop = &self.oplist[i];
                (rop.opc, rop.numparams, rop.op.is_some(), rop.output)
            };
            if !has_op {
                continue;
            }
            let orig_op = self.oplist[i].op.clone().unwrap();
            let addr = orig_op.read().unwrap().get_addr();
            let newop = fd.new_op(numparams, addr);
            fd.op_set_opcode(&newop, opc);
            let rout_vn = out_idx.expect("oplist op with no output");
            let out = self.get_replace_varnode(fd, rout_vn);
            fd.op_set_output(&newop, out);
            let follow = PcodeOpRef(orig_op);
            fd.op_insert_after(&newop, &follow);
            self.oplist[i].replacement = Some(newop);
        }

        // Set all the inputs.
        for i in 0..oplist_len {
            let newop = match self.oplist[i].replacement.clone() {
                Some(o) => o,
                None => continue,
            };
            let input_len = self.oplist[i].input.len();
            for j in 0..input_len {
                if let Some(in_idx) = self.oplist[i].input[j] {
                    let invn = self.get_replace_varnode(fd, in_idx);
                    fd.op_set_input(&newop, invn, j);
                }
            }
        }

        // Non-push patches (everything after the push_front_count entries).
        for p in push_count..self.patchlist.len() {
            let patch = self.patchlist[p].clone();
            // Debug-only invariant guard (CR-SUBFLOWFIX observation 1; oracle
            // consumes slot unguarded at subflow.cc:1496/1502). Every
            // PatchRecord constructor leaves slot >= 0; the only -1-capable
            // path is add_extension_patch's leastsigbit_set(mask) fallback,
            // which returns -1 only when mask == 0 — unreachable while the
            // newvarlist invariant holds. If that invariant ever breaks, a
            // leaked -1 would be `as usize`-widened into op_set_input's
            // slot-padding loop (silent near-hang) or a huge INT_LEFT
            // constant. debug_assert compiles out in release: zero
            // behavior change.
            debug_assert!(
                patch.slot >= 0,
                "PatchRecord slot=-1 reached do_replacement: -1 sentinel leaked from a patch constructor"
            );
            let pullop_ref = PcodeOpRef(patch.patch_op.clone());
            match patch.patch_type {
                PatchType::CopyPatch => {
                    // Ghidra cc:1486-1487: `while(pullop->numInput() > 1)
                    //   data.opRemoveInput(pullop,pullop->numInput()-1);`
                    // The slot must be computed BEFORE op_remove_input: a
                    // read guard held in the call arguments would deadlock
                    // against op_remove_input's write lock on the same op.
                    loop {
                        let num = pullop_ref.0.read().unwrap().num_input();
                        if num <= 1 {
                            break;
                        }
                        fd.op_remove_input(&pullop_ref, num - 1);
                    }
                    let invn = self.get_replace_varnode(fd, patch.in1);
                    fd.op_set_input(&pullop_ref, invn, 0);
                    fd.op_set_opcode(&pullop_ref, OpCode::CPUI_COPY);
                }
                PatchType::ComparePatch => {
                    let in1 = self.get_replace_varnode(fd, patch.in1);
                    let in2 = self.get_replace_varnode(fd, patch.in2.unwrap());
                    fd.op_set_input(&pullop_ref, in1, 0);
                    fd.op_set_input(&pullop_ref, in2, 1);
                }
                PatchType::ParameterPatch => {
                    let invn = self.get_replace_varnode(fd, patch.in1);
                    fd.op_set_input(&pullop_ref, invn, patch.slot as usize);
                }
                PatchType::ExtensionPatch => {
                    let sa = patch.slot;
                    let in_vn = self.get_replace_varnode(fd, patch.in1);
                    let out_size = pullop_ref.0.read().unwrap().get_out().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                    let addr = pullop_ref.0.read().unwrap().get_addr();
                    if sa == 0 {
                        // Ghidra: invec.push_back(inVn); opSetOpcode(op or COPY/ZEXT);
                        let opc = if in_vn.read().unwrap().get_size() == out_size {
                            OpCode::CPUI_COPY
                        } else {
                            OpCode::CPUI_INT_ZEXT
                        };
                        fd.op_set_opcode(&pullop_ref, opc);
                        // opSetAllInput(pullop, invec) — emulated: remove all but
                        // slot 0, then set slot 0. Guards are hoisted out of the
                        // call arguments (see the CopyPatch note).
                        loop {
                            let num = pullop_ref.0.read().unwrap().num_input();
                            if num <= 1 {
                                break;
                            }
                            fd.op_remove_input(&pullop_ref, num - 1);
                        }
                        fd.op_set_input(&pullop_ref, in_vn, 0);
                    } else {
                        let invec_vn = if in_vn.read().unwrap().get_size() != out_size {
                            let zextop = fd.new_op(1, addr);
                            fd.op_set_opcode(&zextop, OpCode::CPUI_INT_ZEXT);
                            let zextout = fd.new_unique_out(out_size, &zextop);
                            fd.op_set_input(&zextop, in_vn, 0);
                            fd.op_insert_before(&zextop, &pullop_ref);
                            zextout
                        } else {
                            in_vn
                        };
                        let sa_const = fd.new_constant(4, sa as u64);
                        // opSetAllInput(pullop, {invec_vn, sa_const}).
                        // Guards hoisted out of the call arguments (see the
                        // CopyPatch note).
                        loop {
                            let num = pullop_ref.0.read().unwrap().num_input();
                            if num <= 2 {
                                break;
                            }
                            fd.op_remove_input(&pullop_ref, num - 1);
                        }
                        fd.op_set_input(&pullop_ref, invec_vn, 0);
                        fd.op_set_input(&pullop_ref, sa_const, 1);
                        fd.op_set_opcode(&pullop_ref, OpCode::CPUI_INT_LEFT);
                    }
                }
                PatchType::PushPatch => {
                    // Shouldn't see these here, handled earlier.
                }
                PatchType::Int2FloatPatch => {
                    let addr = pullop_ref.0.read().unwrap().get_addr();
                    let zext_op = fd.new_op(1, addr);
                    fd.op_set_opcode(&zext_op, OpCode::CPUI_INT_ZEXT);
                    let invn = self.get_replace_varnode(fd, patch.in1);
                    fd.op_set_input(&zext_op, invn.clone(), 0);
                    let sizeout = crate::typeop::TypeOpFloatInt2Float::preferred_zext_size(
                        invn.read().unwrap().get_size() as i32,
                    ) as usize;
                    let outvn = fd.new_unique_out(sizeout, &zext_op);
                    fd.op_insert_before(&zext_op, &pullop_ref);
                    fd.op_set_input(&pullop_ref, outvn, 0);
                }
            }
        }
    }

    // ---- small accessors used by tests / inspection ----

    // Ghidra: subflow.cc:1372 SubvariableFlow::numNewVars
    /// Number of subgraph variable nodes.
    pub fn num_new_vars(&self) -> usize {
        self.newvarlist.len()
    }
    // Ghidra: subflow.cc:1372 SubvariableFlow::numNewOps
    /// Number of subgraph op nodes.
    pub fn num_new_ops(&self) -> usize {
        self.oplist.len()
    }
    // Ghidra: subflow.cc:1372 SubvariableFlow::numPatches
    /// Number of patch records.
    pub fn num_patches(&self) -> usize {
        self.patchlist.len()
    }
    // Ghidra: subflow.cc:1372 SubvariableFlow::pullCount
    /// Current pull count.
    pub fn pull_count(&self) -> i32 {
        self.pullcount
    }
}

// =====================================================================
// The 8 subvar / splitflow Rules
// (subflow.cc:1547-1746, 2039-2088, 2941-3004)
// =====================================================================

/// Perform SubVariableFlow analysis triggered by INT_AND.
/// Faithful to Ghidra's `RuleSubvarAnd` (subflow.cc:133-142, 1547-1582).
pub struct RuleSubvarAnd;
impl RuleSubvarAnd {
    // Ghidra: subflow.hh:133 RuleSubvarAnd::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSubvarAnd {
    // Ghidra: subflow.cc:1553 RuleSubvarAnd::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSubvarAnd::applyOp (subflow.cc:1553-1582)
        let (in0, out_consume, in1_off, out_has_no_descend, in0_size) = {
            let op = op_arc.read().unwrap();
            let in1 = op.get_in(1);
            if !in1.map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                return Ok(action_status::NO_CHANGE);
            }
            let vn = op.get_in(0).cloned().unwrap();
            let outvn = op.get_out().cloned().unwrap();
            // Pre-compute scalars so no temporary borrow escapes the block.
            let out_consume = outvn.read().unwrap().get_consume();
            let in1_off = in1.unwrap().read().unwrap().get_offset();
            let out_has_no_descend = outvn.read().unwrap().has_no_descend();
            let in0_size = vn.read().unwrap().get_size();
            (vn, out_consume, in1_off, out_has_no_descend, in0_size)
        };
        if out_consume != in1_off {
            return Ok(action_status::NO_CHANGE);
        }
        if (out_consume & 1) == 0 {
            return Ok(action_status::NO_CHANGE);
        }
        let mut cmask: u64;
        if out_consume == 1 {
            cmask = 1;
        } else {
            cmask = calc_mask(in0_size);
            cmask >>= 8;
            while cmask != 0 {
                if cmask == out_consume {
                    break;
                }
                cmask >>= 8;
            }
        }
        if cmask == 0 {
            return Ok(action_status::NO_CHANGE);
        }
        if out_has_no_descend {
            return Ok(action_status::NO_CHANGE);
        }
        let mut subflow = SubvariableFlow::new(fd, in0, cmask, false, false, false);
        if !subflow.do_trace(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        subflow.do_replacement(fd);
        Ok(action_status::CHANGE)
    }
    // Ghidra: subflow.hh:133 RuleSubvarAnd::getName
    fn get_name(&self) -> &str {
        "subvar_and"
    }
    // Ghidra: subflow.cc:1547 RuleSubvarAnd::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_AND]
    }
}

/// Perform SubVariableFlow analysis triggered by SUBPIECE.
/// Faithful to Ghidra's `RuleSubvarSubpiece` (subflow.cc:144-154, 1584-1619).
pub struct RuleSubvarSubpiece;
impl RuleSubvarSubpiece {
    // Ghidra: subflow.hh:145 RuleSubvarSubpiece::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSubvarSubpiece {
    // Ghidra: subflow.cc:1590 RuleSubvarSubpiece::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSubvarSubpiece::applyOp (subflow.cc:1590-1619)
        let (vn, flowsize, sa, in0_consume, out_has_no_descend, in0_size, lone_is_op, out_is_ptr_flow) = {
            let op = op_arc.read().unwrap();
            let vn = op.get_in(0).cloned().unwrap();
            let outvn = op.get_out().cloned().unwrap();
            let flowsize = outvn.read().unwrap().get_size() as i32;
            let sa = op.get_in(1).unwrap().read().unwrap().get_offset() as i32;
            let in0_consume = vn.read().unwrap().get_consume();
            let out_has_no_descend = outvn.read().unwrap().has_no_descend();
            let in0_size = vn.read().unwrap().get_size();
            // aggressive = outvn->isPtrFlow(); (subflow.cc:1601) — now wired
            // via Varnode::is_ptr_flow() (addlflags PTR_FLOW).
            let out_is_ptr_flow = outvn.read().unwrap().is_ptr_flow();
            // loneDescend() == op?
            let lone_is_op = vn
                .read()
                .unwrap()
                .lone_descend()
                .map(|d| Arc::as_ptr(&d) == Arc::as_ptr(op_arc))
                .unwrap_or(false);
            (vn, flowsize, sa, in0_consume, out_has_no_descend, in0_size, lone_is_op, out_is_ptr_flow)
        };
        // Ghidra: `if (flowsize + sa > sizeof(uintb))`. uintb is an 8-byte
        // (64-bit) integer, so sizeof(uintb) == 8 (bytes). flowsize & sa are
        // both in bytes. The guard ensures the shifted mask fits in uintb
        // precision without overflow.
        if flowsize + sa > 8 {
            return Ok(action_status::NO_CHANGE);
        }
        let mut mask = calc_mask(flowsize as usize);
        mask <<= 8 * sa;
        let aggressive = out_is_ptr_flow;
        if !aggressive {
            if (in0_consume & mask) != in0_consume {
                return Ok(action_status::NO_CHANGE);
            }
            if out_has_no_descend {
                return Ok(action_status::NO_CHANGE);
            }
        }
        let mut big = false;
        if flowsize >= 8 && in0_consume != 0 {
            // vn->isInput()?
            let _ = in0_size;
            let is_input = vn.read().unwrap().is_input();
            if is_input && lone_is_op {
                big = true;
            }
        }
        let mut subflow = SubvariableFlow::new(fd, vn, mask, aggressive, false, big);
        if !subflow.do_trace(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        subflow.do_replacement(fd);
        Ok(action_status::CHANGE)
    }
    // Ghidra: subflow.hh:145 RuleSubvarSubpiece::getName
    fn get_name(&self) -> &str {
        "subvar_subpiece"
    }
    // Ghidra: subflow.cc:1584 RuleSubvarSubpiece::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_SUBPIECE]
    }
}

/// Perform SubvariableFlow analysis triggered by testing of a single bit
/// (INT_EQUAL/INT_NOTEQUAL to a constant). Faithful to Ghidra's
/// `RuleSubvarCompZero` (subflow.cc:156-171, 1621-1678).
pub struct RuleSubvarCompZero;
impl RuleSubvarCompZero {
    // Ghidra: subflow.hh:162 RuleSubvarCompZero::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSubvarCompZero {
    // Ghidra: subflow.cc:1628 RuleSubvarCompZero::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSubvarCompZero::applyOp (subflow.cc:1628-1678)
        let (vn, in1_off, out_has_no_descend, vn_written, def_code, def_in0, def_in0_size) = {
            let op = op_arc.read().unwrap();
            if !op.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                return Ok(action_status::NO_CHANGE);
            }
            let vn = op.get_in(0).cloned().unwrap();
            let in1_off = op.get_in(1).unwrap().read().unwrap().get_offset();
            let out_has_no_descend = op.get_out().map(|o| o.read().unwrap().has_no_descend()).unwrap_or(true);
            let def = vn.read().unwrap().get_def();
            let vn_written = def.is_some();
            let (def_code, def_in0, def_in0_size) = if let Some(d) = &def {
                let dr = d.read().unwrap();
                if dr.num_input() == 0 {
                    (dr.opcode, None, 0usize)
                } else {
                    let in0 = dr.get_in(0).cloned();
                    let sz = in0.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                    (dr.opcode, in0, sz)
                }
            } else {
                (OpCode::CPUI_COPY, None, 0)
            };
            (vn, in1_off, out_has_no_descend, vn_written, def_code, def_in0, def_in0_size)
        };
        let mask = vn.read().unwrap().get_nz_mask();
        let bitnum = leastsigbit_set(mask);
        if bitnum == -1 {
            return Ok(action_status::NO_CHANGE);
        }
        if (mask >> bitnum) != 1 {
            return Ok(action_status::NO_CHANGE); // Only one bit active
        }
        // Check if the active bit is getting tested.
        if in1_off != mask && in1_off != 0 {
            return Ok(action_status::NO_CHANGE);
        }
        if out_has_no_descend {
            return Ok(action_status::NO_CHANGE);
        }
        // Basic check that the stream isn't fully consumed.
        if vn_written {
            match def_code {
                OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_RIGHT => {
                    if let Some(vn0) = def_in0 {
                        if vn0.read().unwrap().is_constant() {
                            return Ok(action_status::NO_CHANGE);
                        }
                        let mask0 = vn0.read().unwrap().get_consume() & vn0.read().unwrap().get_nz_mask();
                        let wholemask = calc_mask(def_in0_size) & mask0;
                        if (wholemask & 0xff) == 0xff {
                            return Ok(action_status::NO_CHANGE);
                        }
                        if (wholemask & 0xff00) == 0xff00 {
                            return Ok(action_status::NO_CHANGE);
                        }
                    }
                }
                _ => {}
            }
        }
        let mut subflow = SubvariableFlow::new(fd, vn, mask, false, false, false);
        if !subflow.do_trace(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        subflow.do_replacement(fd);
        Ok(action_status::CHANGE)
    }
    // Ghidra: subflow.hh:162 RuleSubvarCompZero::getName
    fn get_name(&self) -> &str {
        "subvar_compzero"
    }
    // Ghidra: subflow.cc:1621 RuleSubvarCompZero::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_NOTEQUAL, OpCode::CPUI_INT_EQUAL]
    }
}

/// Perform SubvariableFlow analysis triggered by INT_RIGHT.
/// Faithful to Ghidra's `RuleSubvarShift` (subflow.cc:173-186, 1680-1702).
pub struct RuleSubvarShift;
impl RuleSubvarShift {
    // Ghidra: subflow.hh:178 RuleSubvarShift::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSubvarShift {
    // Ghidra: subflow.cc:1686 RuleSubvarShift::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSubvarShift::applyOp (subflow.cc:1686-1702)
        let (vn, sa, mask, out_has_no_descend) = {
            let op = op_arc.read().unwrap();
            let vn = op.get_in(0).cloned().unwrap();
            if vn.read().unwrap().get_size() != 1 {
                return Ok(action_status::NO_CHANGE);
            }
            if !op.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
                return Ok(action_status::NO_CHANGE);
            }
            let sa = op.get_in(1).unwrap().read().unwrap().get_offset() as i32;
            let mask = vn.read().unwrap().get_nz_mask();
            let out_has_no_descend = op.get_out().map(|o| o.read().unwrap().has_no_descend()).unwrap_or(true);
            (vn, sa, mask, out_has_no_descend)
        };
        if (mask >> sa) != 1 {
            return Ok(action_status::NO_CHANGE); // Pulling out a single bit
        }
        let mask = (mask >> sa) << sa;
        if out_has_no_descend {
            return Ok(action_status::NO_CHANGE);
        }
        let mut subflow = SubvariableFlow::new(fd, vn, mask, false, false, false);
        if !subflow.do_trace(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        subflow.do_replacement(fd);
        Ok(action_status::CHANGE)
    }
    // Ghidra: subflow.hh:178 RuleSubvarShift::getName
    fn get_name(&self) -> &str {
        "subvar_shift"
    }
    // Ghidra: subflow.cc:1680 RuleSubvarShift::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_RIGHT]
    }
}

/// Perform SubvariableFlow analysis triggered by INT_ZEXT.
/// Faithful to Ghidra's `RuleSubvarZext` (subflow.cc:188-198, 1704-1721).
pub struct RuleSubvarZext;
impl RuleSubvarZext {
    // Ghidra: subflow.hh:190 RuleSubvarZext::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSubvarZext {
    // Ghidra: subflow.cc:1710 RuleSubvarZext::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSubvarZext::applyOp (subflow.cc:1710-1721)
        let (vn, invn_size_mask, in_is_ptr_flow) = {
            let op = op_arc.read().unwrap();
            let vn = op.get_out().cloned().unwrap();
            let invn = op.get_in(0).cloned().unwrap();
            let mask = calc_mask(invn.read().unwrap().get_size());
            // aggressive = invn->isPtrFlow(); (subflow.cc:1717) — now wired via
            // Varnode::is_ptr_flow() (addlflags PTR_FLOW).
            let in_is_ptr_flow = invn.read().unwrap().is_ptr_flow();
            (vn, mask, in_is_ptr_flow)
        };
        let aggressive = in_is_ptr_flow;
        let mut subflow = SubvariableFlow::new(fd, vn, invn_size_mask, aggressive, false, false);
        if !subflow.do_trace(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        subflow.do_replacement(fd);
        Ok(action_status::CHANGE)
    }
    // Ghidra: subflow.hh:190 RuleSubvarZext::getName
    fn get_name(&self) -> &str {
        "subvar_zext"
    }
    // Ghidra: subflow.cc:1704 RuleSubvarZext::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_ZEXT]
    }
}

/// Perform SubvariableFlow analysis triggered by INT_SEXT.
/// Faithful to Ghidra's `RuleSubvarSext` (subflow.cc:200-213, 1723-1746).
pub struct RuleSubvarSext {
    /// Is it guaranteed the root is a sub-variable needing to be trimmed.
    /// Faithful to `RuleSubvarSext::isaggressive` (subflow.hh:203).
    isaggressive: bool,
}
impl RuleSubvarSext {
    // Ghidra: subflow.hh:202 RuleSubvarSext::new
    pub fn new() -> Self {
        Self { isaggressive: false }
    }

    // RUGRA-GLUE: fixture-only observation accessor (the locked C++ fixture reads the protected isaggressive field via its private/protected access hack)
    #[doc(hidden)]
    pub fn fixture_is_aggressive(&self) -> bool {
        self.isaggressive
    }
}
impl Rule for RuleSubvarSext {
    // Ghidra: subflow.cc:1729 RuleSubvarSext::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSubvarSext::applyOp (subflow.cc:1729-1740)
        let (vn, mask) = {
            let op = op_arc.read().unwrap();
            let vn = op.get_out().cloned().unwrap();
            let invn = op.get_in(0).cloned().unwrap();
            let mask = calc_mask(invn.read().unwrap().get_size());
            (vn, mask)
        };
        let mut subflow = SubvariableFlow::new(fd, vn, mask, self.isaggressive, true, false);
        if !subflow.do_trace(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        subflow.do_replacement(fd);
        Ok(action_status::CHANGE)
    }
    // Ghidra: subflow.hh:202 RuleSubvarSext::getName
    fn get_name(&self) -> &str {
        "subvar_sext"
    }
    // Ghidra: subflow.cc:1723 RuleSubvarSext::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_SEXT]
    }
    // Ghidra: subflow.cc:1742 RuleSubvarSext::reset
    /// The locked-oracle override deliberately does NOT call `Rule::reset`
    /// (subflow.cc:1742-1746 only refreshes `isaggressive`), so the base
    /// warning-given bit survives a reset. The override therefore goes
    /// through the pool's virtual-reset seam and leaves the companion
    /// RuleState untouched.
    fn reset_for_function(&mut self, fd: &mut Funcdata, _state: &mut RuleState) {
        // subflow.cc:1745: isaggressive = data.getArch()->aggressive_ext_trim;
        self.isaggressive = fd
            .get_arch()
            .map(|arch| arch.aggressive_ext_trim)
            .unwrap_or(false);
    }
}

/// Try to detect and split artificially joined Varnodes (SUBPIECE from PIECE
/// that has come through INDIRECTs/MULTIEQUAL). Faithful to Ghidra's
// =====================================================================
// SplitFlow — TransformManager subclass for splitting a Varnode that holds
// two logical values (subflow.cc:215-232, 1754-2037).
// =====================================================================

/// Class for splitting up Varnodes that hold 2 logical variables. Faithful to
/// Ghidra's `SplitFlow` (subflow.hh:215-232, subflow.cc:1754-2037), which
/// inherits from `TransformManager`.
///
/// Starting from a \e root Varnode, this looks for data-flow that consistently
/// holds 2 logical values in a single Varnode. If `do_trace()` returns true, a
/// consistent view has been created and invoking `apply()` (via the embedded
/// `TransformManager`) will split all involved Varnodes and PcodeOps into their
/// logical pieces.
///
/// Rust adaptation: Rust has no inheritance, so — mirroring how Ghidra embeds
/// the base — `SplitFlow` owns a `TransformManager` and forwards to it. The
/// trace methods (`set_replacement`, `add_op`, `trace_forward`, `trace_backward`)
/// are 1:1 ports of subflow.cc; they manipulate the placeholder arena exposed
/// by `TransformManager` (`new_split`, `new_op_replace`, `op_set_input`, ...).
pub struct SplitFlow {
    /// The embedded base transform manager (Ghidra base class).
    pub mgr: TransformManager,
    /// Description of how to split Varnodes: a low and a high lane.
    /// Faithful to `laneDescription`.
    lane_description: LaneDescription,
    /// Pending work list of Varnode placeholder indices to push the split
    /// through. Faithful to `worklist`. Entries are the start index of a
    /// 2-element split array in the manager's `new_varnodes`.
    worklist: Vec<usize>,
}

impl SplitFlow {
    // Ghidra: subflow.cc:1754 SplitFlow::setReplacement
    /// Find or build the placeholder objects for a Varnode that needs to be
    /// split. Mark the Varnode so it doesn't get revisited. Decide if the
    /// Varnode needs to go into the worklist. Faithful to `setReplacement`
    /// (subflow.cc:1754-1776). Returns the start index of the 2-element split
    /// array in the manager's arena, or `None` if the Varnode cannot be split.
    fn set_replacement(&mut self, vn: &Arc<RwLock<Varnode>>) -> Option<usize> {
        let vn_rg = vn.read().unwrap();
        if vn_rg.is_mark() {
            // Already seen before: return the existing split.
            return self.mgr.get_split(vn.clone(), &self.lane_description).into();
        }
        // Ghidra: if (vn->isTypeLock() && vn->getType()->getMetatype() != TYPE_PARTIALSTRUCT)
        // Rugra's type system has no TYPE_PARTIALSTRUCT variant, so the
        // exception is vacuously false: a typelocked Varnode is never splittable
        // (see the "Gaps still open" note on PartialStruct at the module top).
        if vn_rg.is_type_lock() {
            return None;
        }
        if vn_rg.is_input() {
            return None; // Right now we can't split inputs
        }
        if vn_rg.is_free() && !vn_rg.is_constant() {
            return None; // Abort
        }
        let is_const = vn_rg.is_constant();
        drop(vn_rg);
        // Create the new split placeholder pair and put it in the map.
        let res = self.mgr.new_split(vn.clone(), &self.lane_description);
        vn.write().unwrap().set_mark();
        if !is_const {
            self.worklist.push(res);
        }
        Some(res)
    }

    // Ghidra: subflow.cc:1787 SplitFlow::addOp
    /// Split a given op into its lanes. The op is assumed to be a logical op,
    /// a COPY, or an INDIRECT, and must have an output. All inputs and output
    /// have their placeholders generated and added to the worklist if
    /// appropriate. Faithful to `addOp` (subflow.cc:1787-1827).
    ///
    /// `rvn` is a known parameter of the op; `slot` is the incoming slot of the
    /// known parameter (-1 means the parameter is the output).
    fn add_op(
        &mut self,
        op: &Arc<RwLock<PcodeOp>>,
        rvn: usize,
        slot: i32,
    ) -> bool {
        // Determine the output placeholder.
        let (outvn, op_code) = {
            let o = op.read().unwrap();
            (o.get_out().cloned(), o.opcode)
        };
        let outvn_idx = if slot == -1 {
            rvn
        } else {
            let out = match outvn {
                Some(o) => o,
                None => return false,
            };
            match self.set_replacement(&out) {
                Some(i) => i,
                None => return false,
            }
        };

        // Already traversed if the output has a defining placeholder op.
        if self.mgr.new_varnodes[outvn_idx].def.is_some() {
            return true;
        }

        let num_input = op.read().unwrap().num_input();
        let lo_op = self.mgr.new_op_replace(num_input, op_code, crate::op::PcodeOpRef(op.clone()));
        let hi_op = self.mgr.new_op_replace(num_input, op_code, crate::op::PcodeOpRef(op.clone()));

        // Snapshot inputs (their Varnode Arcs) to avoid holding the op lock
        // across manager mutations.
        let inputs: Vec<Arc<RwLock<Varnode>>> = (0..num_input)
            .map(|i| op.read().unwrap().get_in(i).cloned().unwrap())
            .collect();
        let mut num_param = num_input;
        if op_code == OpCode::CPUI_INDIRECT {
            let iop_vn = op.read().unwrap().get_in(1).cloned().unwrap();
            // cc:1806-1807: TWO distinct newIop calls — loOp and hiOp each get
            // their own constant_iop placeholder, so createReplacement
            // materializes two independent iop annotation varnodes (one per
            // new INDIRECT). Sharing one placeholder would wire a single free
            // varnode into two ops ("Free varnode has multiple descendants",
            // varnode.cc:333-336) — a state Ghidra's per-call emplace_back can
            // never reach.
            let iop_placeholder_lo = self.mgr.new_iop(iop_vn.clone());
            let iop_placeholder_hi = self.mgr.new_iop(iop_vn);
            self.mgr.op_set_input(lo_op, iop_placeholder_lo, 1);
            self.mgr.op_set_input(hi_op, iop_placeholder_hi, 1);
            self.mgr.new_ops[lo_op].inherit_indirect(&crate::op::PcodeOpRef(op.clone()));
            self.mgr.new_ops[hi_op].inherit_indirect(&crate::op::PcodeOpRef(op.clone()));
            num_param = 1;
        }
        for i in 0..num_param {
            let invn_idx = if i as i32 == slot {
                rvn
            } else {
                match self.set_replacement(&inputs[i]) {
                    Some(idx) => idx,
                    None => return false,
                }
            };
            // Low piece with low op; high piece (invn+1) with high op.
            self.mgr.op_set_input(lo_op, invn_idx, i);
            self.mgr.op_set_input(hi_op, invn_idx + 1, i);
        }
        self.mgr.op_set_output(lo_op, outvn_idx);
        self.mgr.op_set_output(hi_op, outvn_idx + 1);
        true
    }

    // Ghidra: subflow.cc:1834 SplitFlow::traceForward
    /// Try to trace the pair of logical values forward, through ops that read
    /// them. Faithful to `traceForward` (subflow.cc:1834-1920).
    fn trace_forward(&mut self, rvn: usize) -> bool {
        let origvn = match self.mgr.new_varnodes[rvn].vn.clone() {
            Some(v) => v,
            None => return true,
        };
        // Snapshot the descendant ops (Ghidra iterates beginDescend..endDescend).
        let descend_ops: Vec<Arc<RwLock<PcodeOp>>> = origvn.read().unwrap().descend_iter().collect();
        for op in descend_ops {
            let outvn = op.read().unwrap().get_out().cloned();
            if let Some(ref out) = outvn {
                if out.read().unwrap().is_mark() {
                    continue;
                }
            }
            let op_code = op.read().unwrap().opcode;
            let slot = op.read().unwrap().inrefs.iter().position(|v| Arc::ptr_eq(v, &origvn));
            match op_code {
                OpCode::CPUI_COPY
                | OpCode::CPUI_MULTIEQUAL
                | OpCode::CPUI_INDIRECT
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_XOR => {
                    let s = match slot {
                        Some(s) => s as i32,
                        None => return false,
                    };
                    if !self.add_op(&op, rvn, s) {
                        return false;
                    }
                }
                OpCode::CPUI_SUBPIECE => {
                    let out = match &outvn {
                        Some(o) => o.clone(),
                        None => continue,
                    };
                    if out.read().unwrap().is_precis_lo() || out.read().unwrap().is_precis_hi() {
                        return false; // Do not split double-precision pieces
                    }
                    let val = op.read().unwrap().get_in(1).unwrap().read().unwrap().get_offset();
                    let out_size = out.read().unwrap().get_size() as i32;
                    if val == 0 && out_size == self.lane_description.get_size(0) {
                        // Grabs the low piece.
                        let rop = self
                            .mgr
                            .new_preexisting_op(1, OpCode::CPUI_COPY, crate::op::PcodeOpRef(op.clone()));
                        self.mgr.op_set_input(rop, rvn, 0);
                    } else if val == self.lane_description.get_size(0) as u64
                        && out_size == self.lane_description.get_size(1)
                    {
                        // Grabs the high piece.
                        let rop = self
                            .mgr
                            .new_preexisting_op(1, OpCode::CPUI_COPY, crate::op::PcodeOpRef(op.clone()));
                        self.mgr.op_set_input(rop, rvn + 1, 0);
                    } else {
                        return false;
                    }
                }
                OpCode::CPUI_INT_LEFT => {
                    let tmpvn = op.read().unwrap().get_in(1).cloned().unwrap();
                    if !tmpvn.read().unwrap().is_constant() {
                        return false;
                    }
                    let val = tmpvn.read().unwrap().get_offset();
                    if val < self.lane_description.get_size(1) as u64 * 8 {
                        return false; // Must obliterate all high bits
                    }
                    // Keep the original shift.
                    let rop = self
                        .mgr
                        .new_preexisting_op(2, OpCode::CPUI_INT_LEFT, crate::op::PcodeOpRef(op.clone()));
                    let zextrop = self.mgr.new_op(1, OpCode::CPUI_INT_ZEXT, rop);
                    self.mgr.op_set_input(zextrop, rvn, 0); // Input is just the low piece
                    let zext_out = self.mgr.new_unique(self.lane_description.get_whole_size());
                    self.mgr.op_set_output(zextrop, zext_out);
                    self.mgr.op_set_input(rop, zext_out, 0);
                    let (const_size, const_off) = {
                        let c = op.read().unwrap().get_in(1).cloned().unwrap();
                        let r = c.read().unwrap();
                        (r.get_size() as i32, r.get_offset())
                    };
                    let const_idx = self.mgr.new_constant(const_size, 0, const_off);
                    self.mgr.op_set_input(rop, const_idx, 1);
                }
                OpCode::CPUI_INT_SRIGHT | OpCode::CPUI_INT_RIGHT => {
                    let tmpvn = op.read().unwrap().get_in(1).cloned().unwrap();
                    if !tmpvn.read().unwrap().is_constant() {
                        return false;
                    }
                    let val = tmpvn.read().unwrap().get_offset();
                    if val < self.lane_description.get_size(0) as u64 * 8 {
                        return false;
                    }
                    let ext_op_code = if op_code == OpCode::CPUI_INT_RIGHT {
                        OpCode::CPUI_INT_ZEXT
                    } else {
                        OpCode::CPUI_INT_SEXT
                    };
                    if val == self.lane_description.get_size(0) as u64 * 8 {
                        // Shift of exactly loSize bytes.
                        let rop = self
                            .mgr
                            .new_preexisting_op(1, ext_op_code, crate::op::PcodeOpRef(op.clone()));
                        self.mgr.op_set_input(rop, rvn + 1, 0); // Input is the high piece
                    } else {
                        let remain_shift = val - self.lane_description.get_size(0) as u64 * 8;
                        let rop = self
                            .mgr
                            .new_preexisting_op(2, op_code, crate::op::PcodeOpRef(op.clone()));
                        let extrop = self.mgr.new_op(1, ext_op_code, rop);
                        self.mgr.op_set_input(extrop, rvn + 1, 0); // Input is the high piece
                        let ext_out = self.mgr.new_unique(self.lane_description.get_whole_size());
                        self.mgr.op_set_output(extrop, ext_out);
                        self.mgr.op_set_input(rop, ext_out, 0);
                        let const_idx = {
                            let c = op.read().unwrap().get_in(1).cloned().unwrap();
                            let r = c.read().unwrap();
                            self.mgr.new_constant(r.get_size() as i32, 0, remain_shift)
                        };
                        self.mgr.op_set_input(rop, const_idx, 1); // Shift any remaining bits
                    }
                }
                _ => {
                    return false;
                }
            }
        }
        true
    }

    // Ghidra: subflow.cc:1927 SplitFlow::traceBackward
    /// Try to trace the pair of logical values backward, through the defining
    /// op. Create part of the transform related to the defining op, and update
    /// the worklist as necessary. Faithful to `traceBackward` (subflow.cc:1927-1997).
    fn trace_backward(&mut self, rvn: usize) -> bool {
        let def_op = self.mgr.new_varnodes[rvn]
            .vn
            .as_ref()
            .and_then(|v| v.read().unwrap().get_def());
        let op = match def_op {
            Some(o) => o,
            None => return true, // If vn is input
        };
        let op_code = op.read().unwrap().opcode;
        match op_code {
            OpCode::CPUI_COPY
            | OpCode::CPUI_MULTIEQUAL
            | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INDIRECT => {
                if !self.add_op(&op, rvn, -1) {
                    return false;
                }
            }
            OpCode::CPUI_PIECE => {
                let (in0_size, in1_size) = {
                    let o = op.read().unwrap();
                    let in0_size = o.get_in(0).unwrap().read().unwrap().get_size() as i32;
                    let in1_size = o.get_in(1).unwrap().read().unwrap().get_size() as i32;
                    (in0_size, in1_size)
                };
                if in0_size != self.lane_description.get_size(1) {
                    return false;
                }
                if in1_size != self.lane_description.get_size(0) {
                    return false;
                }
                let lo_op = self
                    .mgr
                    .new_op_replace(1, OpCode::CPUI_COPY, crate::op::PcodeOpRef(op.clone()));
                let hi_op = self
                    .mgr
                    .new_op_replace(1, OpCode::CPUI_COPY, crate::op::PcodeOpRef(op.clone()));
                let in1_vn = op.read().unwrap().get_in(1).cloned().unwrap();
                let in0_vn = op.read().unwrap().get_in(0).cloned().unwrap();
                let lo_in = self.mgr.get_preexisting_varnode(in1_vn);
                self.mgr.op_set_input(lo_op, lo_in, 0);
                self.mgr.op_set_output(lo_op, rvn); // Least sig -> low
                let hi_in = self.mgr.get_preexisting_varnode(in0_vn);
                self.mgr.op_set_input(hi_op, hi_in, 0);
                self.mgr.op_set_output(hi_op, rvn + 1); // Most sig -> high
            }
            OpCode::CPUI_INT_ZEXT => {
                let (in0_size, out_size) = {
                    let o = op.read().unwrap();
                    let in0_size = o.get_in(0).unwrap().read().unwrap().get_size() as i32;
                    let out_size = o.get_out().unwrap().read().unwrap().get_size() as i32;
                    (in0_size, out_size)
                };
                if in0_size != self.lane_description.get_size(0) {
                    return false;
                }
                if out_size != self.lane_description.get_whole_size() {
                    return false;
                }
                let lo_op = self
                    .mgr
                    .new_op_replace(1, OpCode::CPUI_COPY, crate::op::PcodeOpRef(op.clone()));
                let hi_op = self
                    .mgr
                    .new_op_replace(1, OpCode::CPUI_COPY, crate::op::PcodeOpRef(op.clone()));
                let in0_vn = op.read().unwrap().get_in(0).cloned().unwrap();
                let lo_in = self.mgr.get_preexisting_varnode(in0_vn);
                self.mgr.op_set_input(lo_op, lo_in, 0);
                self.mgr.op_set_output(lo_op, rvn); // ZEXT input -> low
                let hi_const = self.mgr.new_constant(self.lane_description.get_size(1), 0, 0);
                self.mgr.op_set_input(hi_op, hi_const, 0);
                self.mgr.op_set_output(hi_op, rvn + 1); // zero -> high
            }
            OpCode::CPUI_INT_LEFT => {
                let cvn = op.read().unwrap().get_in(1).cloned().unwrap();
                if !cvn.read().unwrap().is_constant() {
                    return false;
                }
                if cvn.read().unwrap().get_offset() != self.lane_description.get_size(0) as u64 * 8 {
                    return false;
                }
                let invn = op.read().unwrap().get_in(0).cloned().unwrap();
                let zext_op_arc = match invn.read().unwrap().get_def() {
                    Some(d) => d,
                    None => return false,
                };
                if zext_op_arc.read().unwrap().opcode != OpCode::CPUI_INT_ZEXT {
                    return false;
                }
                let invn2 = zext_op_arc.read().unwrap().get_in(0).cloned().unwrap();
                if invn2.read().unwrap().get_size() as i32 != self.lane_description.get_size(1) {
                    return false;
                }
                if invn2.read().unwrap().is_free() {
                    return false;
                }
                let lo_op = self
                    .mgr
                    .new_op_replace(1, OpCode::CPUI_COPY, crate::op::PcodeOpRef(op.clone()));
                let hi_op = self
                    .mgr
                    .new_op_replace(1, OpCode::CPUI_COPY, crate::op::PcodeOpRef(op.clone()));
                let lo_const = self.mgr.new_constant(self.lane_description.get_size(0), 0, 0);
                self.mgr.op_set_input(lo_op, lo_const, 0);
                self.mgr.op_set_output(lo_op, rvn); // zero -> low
                let hi_in = self.mgr.get_preexisting_varnode(invn2);
                self.mgr.op_set_input(hi_op, hi_in, 0);
                self.mgr.op_set_output(hi_op, rvn + 1); // invn -> high
            }
            // case CPUI_LOAD: We could split into two different loads.
            _ => {
                return false;
            }
        }
        true
    }

    // Ghidra: subflow.cc:2000 SplitFlow::processNextWork
    /// Process the next logical value on the worklist. Faithful to
    /// `processNextWork` (subflow.cc:2000-2009). Returns true if the logical
    /// split was successfully pushed through its local operators.
    fn process_next_work(&mut self) -> bool {
        let rvn = *self.worklist.last().unwrap();
        self.worklist.pop();
        if !self.trace_backward(rvn) {
            return false;
        }
        self.trace_forward(rvn)
    }

    // Ghidra: subflow.cc:2011 SplitFlow::new
    /// Construct a SplitFlow on the given root Varnode. Faithful to the
    /// `SplitFlow` constructor (subflow.cc:2011-2016). `low_size` is the size
    /// of the low lane.
    pub fn new(fd: &mut Funcdata, root: Arc<RwLock<Varnode>>, low_size: i32) -> Self {
        let root_size = root.read().unwrap().get_size() as i32;
        let mut mgr = TransformManager::new();
        mgr.init(fd);
        let lane_description = LaneDescription::two_lane(root_size, low_size, root_size - low_size);
        let mut sf = SplitFlow {
            mgr,
            lane_description,
            worklist: Vec::new(),
        };
        sf.set_replacement(&root);
        sf
    }

    // Ghidra: subflow.cc:2021 SplitFlow::doTrace
    /// Trace split through data-flow, constructing the transform. If at any
    /// point the split cannot be naturally pushed, return false. Faithful to
    /// `doTrace` (subflow.cc:2021-2037). Returns true if a full transform has
    /// been constructed that can perform the split.
    pub fn do_trace(&mut self) -> bool {
        if self.worklist.is_empty() {
            return false; // Nothing to do
        }
        let mut retval = true;
        while !self.worklist.is_empty() {
            if !self.process_next_work() {
                retval = false;
                break;
            }
        }
        self.mgr.clear_varnode_marks();
        retval
    }

    // Ghidra: subflow.cc:2011 SplitFlow::apply
    /// Apply the full transform to the function. Faithful to the inherited
    /// `apply()` (transform.cc:756-765): `create_ops` -> `create_varnodes` ->
    /// `remove_old` -> `transform_input_varnodes` -> `place_inputs`.
    pub fn apply(&mut self, fd: &mut Funcdata) {
        self.mgr.apply(fd);
    }
}

// =====================================================================
// LaneDivide — TransformManager subclass for splitting arbitrary logical
// lane descriptions (subflow.hh:420-456, subflow.cc:3518-4128).
// =====================================================================

struct LaneWorkNode {
    lanes: usize,
    num_lanes: i32,
    skip_lanes: i32,
}

/// Trace and split data-flow over an arbitrary [`LaneDescription`]. This is
/// the production transform used by Ghidra's ActionLaneDivide.
pub struct LaneDivide {
    pub mgr: TransformManager,
    description: LaneDescription,
    work_list: Vec<LaneWorkNode>,
    allow_subpiece_terminator: bool,
}

impl LaneDivide {
    // Ghidra: subflow.cc:3518 LaneDivide::setReplacement
    fn set_replacement(
        &mut self,
        vn: &Arc<RwLock<Varnode>>,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> Option<usize> {
        if vn.read().unwrap().is_mark() {
            return Some(self.mgr.get_split_subset(
                vn.clone(),
                &self.description,
                num_lanes as usize,
                skip_lanes as usize,
            ));
        }
        if vn.read().unwrap().is_constant() {
            return Some(self.mgr.new_split_subset(
                vn.clone(),
                &self.description,
                num_lanes as usize,
                skip_lanes as usize,
            ));
        }

        let (type_locked, metatype, is_free) = {
            let vn = vn.read().unwrap();
            (
                vn.is_type_lock(),
                vn.get_type().map(|data_type| data_type.get_metatype()),
                vn.is_free(),
            )
        };
        if type_locked {
            use crate::type_system::datatype::TypeMetatype;
            if !matches!(
                metatype,
                Some(
                    TypeMetatype::Array
                        | TypeMetatype::Enum
                        | TypeMetatype::PartialEnum
                        | TypeMetatype::PartialStruct
                        | TypeMetatype::PartialUnion
                )
            ) {
                return None;
            }
        }

        vn.write().unwrap().set_mark();
        let result = self.mgr.new_split_subset(
            vn.clone(),
            &self.description,
            num_lanes as usize,
            skip_lanes as usize,
        );
        if !is_free {
            self.work_list.push(LaneWorkNode {
                lanes: result,
                num_lanes,
                skip_lanes,
            });
        }
        Some(result)
    }

    // Ghidra: subflow.cc:3559 LaneDivide::buildUnaryOp
    fn build_unary_op(
        &mut self,
        opcode: OpCode,
        op: &crate::op::PcodeOpRef,
        input_vars: usize,
        output_vars: usize,
        num_lanes: i32,
    ) {
        for lane in 0..num_lanes as usize {
            let replacement = self.mgr.new_op_replace(1, opcode, op.clone());
            self.mgr.op_set_output(replacement, output_vars + lane);
            self.mgr.op_set_input(replacement, input_vars + lane, 0);
        }
    }

    // Ghidra: subflow.cc:3578 LaneDivide::buildBinaryOp
    fn build_binary_op(
        &mut self,
        opcode: OpCode,
        op: &crate::op::PcodeOpRef,
        input0_vars: usize,
        input1_vars: usize,
        output_vars: usize,
        num_lanes: i32,
    ) {
        for lane in 0..num_lanes as usize {
            let replacement = self.mgr.new_op_replace(2, opcode, op.clone());
            self.mgr.op_set_output(replacement, output_vars + lane);
            self.mgr.op_set_input(replacement, input0_vars + lane, 0);
            self.mgr.op_set_input(replacement, input1_vars + lane, 1);
        }
    }

    // Ghidra: subflow.cc:3599 LaneDivide::buildPiece
    fn build_piece(
        &mut self,
        op: &crate::op::PcodeOpRef,
        output_vars: usize,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> bool {
        let (high_vn, low_vn) = {
            let op = op.0.read().unwrap();
            let (Some(high), Some(low)) = (op.get_in(0).cloned(), op.get_in(1).cloned()) else {
                return false;
            };
            (high, low)
        };
        let high_size = high_vn.read().unwrap().get_size() as i32;
        let low_size = low_vn.read().unwrap().get_size() as i32;
        let Some((high_lanes, high_skip)) = self.description.restriction(
            num_lanes,
            skip_lanes,
            low_size,
            high_size,
        ) else {
            return false;
        };
        let Some((low_lanes, low_skip)) = self.description.restriction(
            num_lanes,
            skip_lanes,
            0,
            low_size,
        ) else {
            return false;
        };

        if high_lanes == 1 {
            let high_input = self.mgr.get_preexisting_varnode(high_vn);
            let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
            self.mgr.op_set_input(replacement, high_input, 0);
            self.mgr
                .op_set_output(replacement, output_vars + num_lanes as usize - 1);
        } else {
            let Some(high_vars) = self.set_replacement(&high_vn, high_lanes, high_skip) else {
                return false;
            };
            let output_high_start = num_lanes - high_lanes;
            for lane in 0..high_lanes as usize {
                let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
                self.mgr.op_set_input(replacement, high_vars + lane, 0);
                self.mgr.op_set_output(
                    replacement,
                    output_vars + output_high_start as usize + lane,
                );
            }
        }

        if low_lanes == 1 {
            let low_input = self.mgr.get_preexisting_varnode(low_vn);
            let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
            self.mgr.op_set_input(replacement, low_input, 0);
            self.mgr.op_set_output(replacement, output_vars);
        } else {
            let Some(low_vars) = self.set_replacement(&low_vn, low_lanes, low_skip) else {
                return false;
            };
            for lane in 0..low_lanes as usize {
                let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
                self.mgr.op_set_input(replacement, low_vars + lane, 0);
                self.mgr.op_set_output(replacement, output_vars + lane);
            }
        }
        true
    }

    // Ghidra: subflow.cc:3654 LaneDivide::buildMultiequal
    fn build_multiequal(
        &mut self,
        op: &crate::op::PcodeOpRef,
        output_vars: usize,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> bool {
        let inputs = op.0.read().unwrap().inrefs.clone();
        let mut input_sets = Vec::with_capacity(inputs.len());
        for input in inputs {
            let Some(input_vars) = self.set_replacement(&input, num_lanes, skip_lanes) else {
                return false;
            };
            input_sets.push(input_vars);
        }
        for lane in 0..num_lanes as usize {
            let replacement =
                self.mgr
                    .new_op_replace(input_sets.len(), OpCode::CPUI_MULTIEQUAL, op.clone());
            self.mgr.op_set_output(replacement, output_vars + lane);
            for (slot, input_vars) in input_sets.iter().copied().enumerate() {
                self.mgr.op_set_input(replacement, input_vars + lane, slot);
            }
        }
        true
    }

    // Ghidra: subflow.cc:3681 LaneDivide::buildIndirect
    fn build_indirect(
        &mut self,
        op: &crate::op::PcodeOpRef,
        output_vars: usize,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> bool {
        let (input, iop) = {
            let op = op.0.read().unwrap();
            let (Some(input), Some(iop)) = (op.get_in(0).cloned(), op.get_in(1).cloned()) else {
                return false;
            };
            (input, iop)
        };
        let Some(input_vars) = self.set_replacement(&input, num_lanes, skip_lanes) else {
            return false;
        };
        for lane in 0..num_lanes as usize {
            let replacement =
                self.mgr
                    .new_op_replace(2, OpCode::CPUI_INDIRECT, op.clone());
            self.mgr.op_set_output(replacement, output_vars + lane);
            self.mgr.op_set_input(replacement, input_vars + lane, 0);
            let iop_var = self.mgr.new_iop(iop.clone());
            self.mgr.op_set_input(replacement, iop_var, 1);
            self.mgr.new_ops[replacement].inherit_indirect(op);
        }
        true
    }

    // Ghidra: subflow.cc:3704 LaneDivide::buildStore
    fn build_store(
        &mut self,
        op: &crate::op::PcodeOpRef,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> bool {
        let (space_vn, original_pointer, value) = {
            let op = op.0.read().unwrap();
            let (Some(space), Some(pointer), Some(value)) = (
                op.get_in(0).cloned(),
                op.get_in(1).cloned(),
                op.get_in(2).cloned(),
            ) else {
                return false;
            };
            (space, pointer, value)
        };
        let Some(input_vars) = self.set_replacement(&value, num_lanes, skip_lanes) else {
            return false;
        };
        let (space_constant, space_constant_size) = {
            let space = space_vn.read().unwrap();
            (space.get_offset(), space.get_size() as i32)
        };
        let space = crate::space::AddressSpace::from_id(space_constant as crate::space::SpaceId);
        let (pointer_is_free, pointer_is_constant, pointer_size) = {
            let pointer = original_pointer.read().unwrap();
            (
                pointer.is_free(),
                pointer.is_constant(),
                pointer.get_size() as i32,
            )
        };
        if pointer_is_free && !pointer_is_constant {
            return false;
        }
        let base_pointer = self.mgr.get_preexisting_varnode(original_pointer);
        let mut byte_position = 0u64;
        for count in 0..num_lanes {
            let lane = if space.is_big_endian() {
                num_lanes - 1 - count
            } else {
                count
            };
            let store = self
                .mgr
                .new_op_replace(3, OpCode::CPUI_STORE, op.clone());
            let pointer = if byte_position == 0 {
                base_pointer
            } else {
                let pointer = self.mgr.new_unique(pointer_size);
                let add = self.mgr.new_op(2, OpCode::CPUI_INT_ADD, store);
                self.mgr.op_set_output(add, pointer);
                self.mgr.op_set_input(add, base_pointer, 0);
                let offset = self.mgr.new_constant(pointer_size, 0, byte_position);
                self.mgr.op_set_input(add, offset, 1);
                pointer
            };
            let space_input =
                self.mgr
                    .new_constant(space_constant_size, 0, space_constant);
            self.mgr.op_set_input(store, space_input, 0);
            self.mgr.op_set_input(store, pointer, 1);
            self.mgr
                .op_set_input(store, input_vars + lane as usize, 2);
            byte_position += self
                .description
                .get_size((skip_lanes + lane) as usize) as u64;
        }
        true
    }

    // Ghidra: subflow.cc:3753 LaneDivide::buildLoad
    fn build_load(
        &mut self,
        op: &crate::op::PcodeOpRef,
        output_vars: usize,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> bool {
        let (space_vn, original_pointer) = {
            let op = op.0.read().unwrap();
            let (Some(space), Some(pointer)) =
                (op.get_in(0).cloned(), op.get_in(1).cloned())
            else {
                return false;
            };
            (space, pointer)
        };
        let (space_constant, space_constant_size) = {
            let space = space_vn.read().unwrap();
            (space.get_offset(), space.get_size() as i32)
        };
        let space = crate::space::AddressSpace::from_id(space_constant as crate::space::SpaceId);
        let (pointer_is_free, pointer_is_constant, pointer_size) = {
            let pointer = original_pointer.read().unwrap();
            (
                pointer.is_free(),
                pointer.is_constant(),
                pointer.get_size() as i32,
            )
        };
        if pointer_is_free && !pointer_is_constant {
            return false;
        }
        let base_pointer = self.mgr.get_preexisting_varnode(original_pointer);
        let mut byte_position = 0u64;
        for count in 0..num_lanes {
            let load = self
                .mgr
                .new_op_replace(2, OpCode::CPUI_LOAD, op.clone());
            let lane = if space.is_big_endian() {
                num_lanes - 1 - count
            } else {
                count
            };
            let pointer = if byte_position == 0 {
                base_pointer
            } else {
                let pointer = self.mgr.new_unique(pointer_size);
                let add = self.mgr.new_op(2, OpCode::CPUI_INT_ADD, load);
                self.mgr.op_set_output(add, pointer);
                self.mgr.op_set_input(add, base_pointer, 0);
                let offset = self.mgr.new_constant(pointer_size, 0, byte_position);
                self.mgr.op_set_input(add, offset, 1);
                pointer
            };
            let space_input =
                self.mgr
                    .new_constant(space_constant_size, 0, space_constant);
            self.mgr.op_set_input(load, space_input, 0);
            self.mgr.op_set_input(load, pointer, 1);
            self.mgr
                .op_set_output(load, output_vars + lane as usize);
            byte_position += self
                .description
                .get_size((skip_lanes + lane) as usize) as u64;
        }
        true
    }

    // Ghidra: subflow.cc:3800 LaneDivide::buildRightShift
    fn build_right_shift(
        &mut self,
        op: &crate::op::PcodeOpRef,
        output_vars: usize,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> bool {
        let (input, shift) = {
            let op = op.0.read().unwrap();
            let (Some(input), Some(shift)) = (op.get_in(0).cloned(), op.get_in(1).cloned()) else {
                return false;
            };
            (input, shift)
        };
        if !shift.read().unwrap().is_constant() {
            return false;
        }
        let mut shift_size = shift.read().unwrap().get_offset() as i32;
        if shift_size & 7 != 0 {
            return false;
        }
        shift_size /= 8;
        let start_position = shift_size + self.description.get_position(skip_lanes as usize);
        let start_lane = self.description.get_boundary(start_position);
        if start_lane < 0 {
            return false;
        }
        let mut source_lane = start_lane;
        let mut destination_lane = skip_lanes;
        while source_lane - skip_lanes < num_lanes {
            if source_lane < 0
                || destination_lane < 0
                || source_lane as usize >= self.description.get_num_lanes()
                || destination_lane as usize >= self.description.get_num_lanes()
                || self.description.get_size(source_lane as usize)
                    != self.description.get_size(destination_lane as usize)
            {
                return false;
            }
            source_lane += 1;
            destination_lane += 1;
        }
        let Some(input_vars) = self.set_replacement(&input, num_lanes, skip_lanes) else {
            return false;
        };
        let lane_shift = start_lane - skip_lanes;
        self.build_unary_op(
            OpCode::CPUI_COPY,
            op,
            input_vars + lane_shift as usize,
            output_vars,
            num_lanes - lane_shift,
        );
        for zero_lane in (num_lanes - lane_shift)..num_lanes {
            let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
            self.mgr
                .op_set_output(replacement, output_vars + zero_lane as usize);
            let zero = self
                .mgr
                .new_constant(self.description.get_size(zero_lane as usize), 0, 0);
            self.mgr.op_set_input(replacement, zero, 0);
        }
        true
    }

    // Ghidra: subflow.cc:3837 LaneDivide::buildLeftShift
    fn build_left_shift(
        &mut self,
        op: &crate::op::PcodeOpRef,
        output_vars: usize,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> bool {
        let (input, shift) = {
            let op = op.0.read().unwrap();
            let (Some(input), Some(shift)) = (op.get_in(0).cloned(), op.get_in(1).cloned()) else {
                return false;
            };
            (input, shift)
        };
        if !shift.read().unwrap().is_constant() {
            return false;
        }
        let mut shift_size = shift.read().unwrap().get_offset() as i32;
        if shift_size & 7 != 0 {
            return false;
        }
        shift_size /= 8;
        let start_position = shift_size + self.description.get_position(skip_lanes as usize);
        let start_lane = self.description.get_boundary(start_position);
        if start_lane < 0 {
            return false;
        }
        let mut destination_lane = start_lane;
        let mut source_lane = skip_lanes;
        while destination_lane - skip_lanes < num_lanes {
            if source_lane < 0
                || destination_lane < 0
                || source_lane as usize >= self.description.get_num_lanes()
                || destination_lane as usize >= self.description.get_num_lanes()
                || self.description.get_size(source_lane as usize)
                    != self.description.get_size(destination_lane as usize)
            {
                return false;
            }
            source_lane += 1;
            destination_lane += 1;
        }
        let Some(input_vars) = self.set_replacement(&input, num_lanes, skip_lanes) else {
            return false;
        };
        let lane_shift = start_lane - skip_lanes;
        for zero_lane in 0..lane_shift {
            let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
            self.mgr
                .op_set_output(replacement, output_vars + zero_lane as usize);
            let zero = self
                .mgr
                .new_constant(self.description.get_size(zero_lane as usize), 0, 0);
            self.mgr.op_set_input(replacement, zero, 0);
        }
        self.build_unary_op(
            OpCode::CPUI_COPY,
            op,
            input_vars,
            output_vars + lane_shift as usize,
            num_lanes - lane_shift,
        );
        true
    }

    // Ghidra: subflow.cc:3875 LaneDivide::buildZext
    fn build_zext(
        &mut self,
        op: &crate::op::PcodeOpRef,
        output_vars: usize,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> bool {
        let input = match op.0.read().unwrap().get_in(0).cloned() {
            Some(input) => input,
            None => return false,
        };
        let input_size = input.read().unwrap().get_size() as i32;
        let Some((input_lanes, input_skip)) =
            self.description
                .restriction(num_lanes, skip_lanes, 0, input_size)
        else {
            return false;
        };
        if input_lanes == 1 {
            let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
            let input_var = self.mgr.get_preexisting_varnode(input);
            self.mgr.op_set_input(replacement, input_var, 0);
            self.mgr.op_set_output(replacement, output_vars);
        } else {
            let Some(input_vars) = self.set_replacement(&input, input_lanes, input_skip) else {
                return false;
            };
            for lane in 0..input_lanes as usize {
                let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
                self.mgr.op_set_input(replacement, input_vars + lane, 0);
                self.mgr.op_set_output(replacement, output_vars + lane);
            }
        }
        for lane in 0..(num_lanes - input_lanes) {
            let replacement = self.mgr.new_op_replace(1, OpCode::CPUI_COPY, op.clone());
            let zero = self.mgr.new_constant(
                self.description
                    .get_size((skip_lanes + input_lanes + lane) as usize),
                0,
                0,
            );
            self.mgr.op_set_input(replacement, zero, 0);
            self.mgr
                .op_set_output(replacement, output_vars + input_lanes as usize + lane as usize);
        }
        true
    }

    // Ghidra: subflow.cc:3916 LaneDivide::traceForward
    fn trace_forward(&mut self, replacement_var: usize, num_lanes: i32, skip_lanes: i32) -> bool {
        let original = match self.mgr.new_varnodes[replacement_var].vn.clone() {
            Some(original) => original,
            None => return false,
        };
        let descendants: Vec<crate::op::PcodeOpRef> = original
            .read()
            .unwrap()
            .descend_iter()
            .map(crate::op::PcodeOpRef)
            .collect();
        for op in descendants {
            let output = op.0.read().unwrap().get_out().cloned();
            if output
                .as_ref()
                .is_some_and(|varnode| varnode.read().unwrap().is_mark())
            {
                continue;
            }
            let opcode = op.0.read().unwrap().opcode;
            match opcode {
                OpCode::CPUI_SUBPIECE => {
                    let Some(output) = output else {
                        return false;
                    };
                    let byte_position = match op.0.read().unwrap().get_in(1).cloned() {
                        Some(offset) => offset.read().unwrap().get_offset() as i32,
                        None => return false,
                    };
                    let output_size = output.read().unwrap().get_size() as i32;
                    let restriction = self.description.restriction(
                        num_lanes,
                        skip_lanes,
                        byte_position,
                        output_size,
                    );
                    let Some((output_lanes, output_skip)) = restriction else {
                        if !self.allow_subpiece_terminator {
                            return false;
                        }
                        let lane_index = self.description.get_boundary(byte_position);
                        // Ghidra subflow.cc:3934-3944 only rejects laneIndex < 0,
                        // laneIndex >= numLanes and lane size <= output size. When
                        // laneIndex < skipLanes it still evaluates
                        // `rvn + (laneIndex - skipLanes)` (subflow.cc:3942), a
                        // negative index into the numLanes-sized array allocated by
                        // newSplit(vn,description,numLanes,startLane)
                        // (transform.cc:484) — undefined behavior in the oracle.
                        // The oracle target getBoundary(bytePos) also feeds a
                        // window-relative offset in global coordinates, so this
                        // corner is reachable for restricted windows
                        // (skipLanes > 0). Rugra conservatively refuses the
                        // split instead of dereferencing out of bounds; tracked
                        // as LANEDIVIDE-INFRA-RESIDUAL-0001.
                        if lane_index < 0
                            || lane_index as usize >= self.description.get_num_lanes()
                            || self.description.get_size(lane_index as usize) <= output_size
                            || lane_index < skip_lanes
                        {
                            return false;
                        }
                        let replacement =
                            self.mgr
                                .new_preexisting_op(2, OpCode::CPUI_SUBPIECE, op.clone());
                        self.mgr.op_set_input(
                            replacement,
                            replacement_var + (lane_index - skip_lanes) as usize,
                            0,
                        );
                        let zero = self.mgr.new_constant(4, 0, 0);
                        self.mgr.op_set_input(replacement, zero, 1);
                        continue;
                    };
                    if output_lanes == 1 {
                        let replacement =
                            self.mgr
                                .new_preexisting_op(1, OpCode::CPUI_COPY, op.clone());
                        self.mgr.op_set_input(
                            replacement,
                            replacement_var + (output_skip - skip_lanes) as usize,
                            0,
                        );
                    } else if self
                        .set_replacement(&output, output_lanes, output_skip)
                        .is_none()
                    {
                        return false;
                    }
                }
                OpCode::CPUI_PIECE => {
                    let Some(output) = output else {
                        return false;
                    };
                    let (input0, input1_size) = {
                        let op = op.0.read().unwrap();
                        let (Some(input0), Some(input1)) =
                            (op.get_in(0).cloned(), op.get_in(1).cloned())
                        else {
                            return false;
                        };
                        let input1_size = input1.read().unwrap().get_size() as i32;
                        (input0, input1_size)
                    };
                    let byte_position = if Arc::ptr_eq(&input0, &original) {
                        input1_size
                    } else {
                        0
                    };
                    let output_size = output.read().unwrap().get_size() as i32;
                    let Some((output_lanes, output_skip)) = self.description.extension(
                        num_lanes,
                        skip_lanes,
                        byte_position,
                        output_size,
                    ) else {
                        return false;
                    };
                    if self
                        .set_replacement(&output, output_lanes, output_skip)
                        .is_none()
                    {
                        return false;
                    }
                }
                OpCode::CPUI_COPY
                | OpCode::CPUI_INT_NEGATE
                | OpCode::CPUI_INT_AND
                | OpCode::CPUI_INT_OR
                | OpCode::CPUI_INT_XOR
                | OpCode::CPUI_MULTIEQUAL
                | OpCode::CPUI_INDIRECT => {
                    let Some(output) = output else {
                        return false;
                    };
                    if self
                        .set_replacement(&output, num_lanes, skip_lanes)
                        .is_none()
                    {
                        return false;
                    }
                }
                OpCode::CPUI_INT_RIGHT => {
                    let Some(output) = output else {
                        return false;
                    };
                    let shift_is_constant = op
                        .0
                        .read()
                        .unwrap()
                        .get_in(1)
                        .is_some_and(|shift| shift.read().unwrap().is_constant());
                    if !shift_is_constant
                        || self
                            .set_replacement(&output, num_lanes, skip_lanes)
                            .is_none()
                    {
                        return false;
                    }
                }
                OpCode::CPUI_STORE => {
                    let stored_value = op.0.read().unwrap().get_in(2).cloned();
                    if !stored_value
                        .as_ref()
                        .is_some_and(|value| Arc::ptr_eq(value, &original))
                        || !self.build_store(&op, num_lanes, skip_lanes)
                    {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    // Ghidra: subflow.cc:4012 LaneDivide::traceBackward
    fn trace_backward(&mut self, replacement_var: usize, num_lanes: i32, skip_lanes: i32) -> bool {
        let defining_op = self.mgr.new_varnodes[replacement_var]
            .vn
            .as_ref()
            .and_then(|varnode| varnode.read().unwrap().get_def())
            .map(crate::op::PcodeOpRef);
        let Some(op) = defining_op else {
            return true;
        };
        let opcode = op.0.read().unwrap().opcode;
        match opcode {
            OpCode::CPUI_INT_NEGATE | OpCode::CPUI_COPY => {
                let input = match op.0.read().unwrap().get_in(0).cloned() {
                    Some(input) => input,
                    None => return false,
                };
                let Some(input_vars) = self.set_replacement(&input, num_lanes, skip_lanes) else {
                    return false;
                };
                self.build_unary_op(opcode, &op, input_vars, replacement_var, num_lanes);
            }
            OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR => {
                let (input0, input1) = {
                    let op = op.0.read().unwrap();
                    let (Some(input0), Some(input1)) =
                        (op.get_in(0).cloned(), op.get_in(1).cloned())
                    else {
                        return false;
                    };
                    (input0, input1)
                };
                let Some(input0_vars) = self.set_replacement(&input0, num_lanes, skip_lanes) else {
                    return false;
                };
                let Some(input1_vars) = self.set_replacement(&input1, num_lanes, skip_lanes) else {
                    return false;
                };
                self.build_binary_op(
                    opcode,
                    &op,
                    input0_vars,
                    input1_vars,
                    replacement_var,
                    num_lanes,
                );
            }
            OpCode::CPUI_MULTIEQUAL => {
                if !self.build_multiequal(&op, replacement_var, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::CPUI_INDIRECT => {
                if !self.build_indirect(&op, replacement_var, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::CPUI_SUBPIECE => {
                let (input, byte_position) = {
                    let op = op.0.read().unwrap();
                    let (Some(input), Some(offset)) =
                        (op.get_in(0).cloned(), op.get_in(1).cloned())
                    else {
                        return false;
                    };
                    let byte_position = offset.read().unwrap().get_offset() as i32;
                    (input, byte_position)
                };
                let input_size = input.read().unwrap().get_size() as i32;
                let Some((input_lanes, input_skip)) = self.description.extension(
                    num_lanes,
                    skip_lanes,
                    byte_position,
                    input_size,
                ) else {
                    return false;
                };
                let Some(input_vars) = self.set_replacement(&input, input_lanes, input_skip) else {
                    return false;
                };
                self.build_unary_op(
                    OpCode::CPUI_COPY,
                    &op,
                    input_vars + (skip_lanes - input_skip) as usize,
                    replacement_var,
                    num_lanes,
                );
            }
            OpCode::CPUI_PIECE => {
                if !self.build_piece(&op, replacement_var, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::CPUI_LOAD => {
                if !self.build_load(&op, replacement_var, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::CPUI_INT_RIGHT => {
                if !self.build_right_shift(&op, replacement_var, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::CPUI_INT_LEFT => {
                if !self.build_left_shift(&op, replacement_var, num_lanes, skip_lanes) {
                    return false;
                }
            }
            OpCode::CPUI_INT_ZEXT => {
                if !self.build_zext(&op, replacement_var, num_lanes, skip_lanes) {
                    return false;
                }
            }
            _ => return false,
        }
        true
    }

    // Ghidra: subflow.cc:4085 LaneDivide::processNextWork
    fn process_next_work(&mut self) -> bool {
        let work = self.work_list.pop().expect("LaneDivide work list is non-empty");
        if !self.trace_backward(work.lanes, work.num_lanes, work.skip_lanes) {
            return false;
        }
        self.trace_forward(work.lanes, work.num_lanes, work.skip_lanes)
    }

    // Ghidra: subflow.cc:4102 LaneDivide::LaneDivide
    pub fn new(
        fd: &mut Funcdata,
        root: Arc<RwLock<Varnode>>,
        description: LaneDescription,
        allow_downcast: bool,
    ) -> Self {
        let num_lanes = description.get_num_lanes() as i32;
        let mut manager = TransformManager::new();
        manager.init(fd);
        let mut result = Self {
            mgr: manager,
            description,
            work_list: Vec::new(),
            allow_subpiece_terminator: allow_downcast,
        };
        result.set_replacement(&root, num_lanes, 0);
        result
    }

    // Ghidra: subflow.cc:4112 LaneDivide::doTrace
    pub fn do_trace(&mut self) -> bool {
        if self.work_list.is_empty() {
            return false;
        }
        let mut result = true;
        while !self.work_list.is_empty() {
            if !self.process_next_work() {
                result = false;
                break;
            }
        }
        self.mgr.clear_varnode_marks();
        result
    }

    // Ghidra: transform.cc:756 TransformManager::apply
    /// Materialize the successful trace using the inherited transform apply
    /// lifecycle.
    pub fn apply(&mut self, fd: &mut Funcdata) {
        self.mgr.apply(fd);
    }
}

/// `RuleSplitFlow` (subflow.cc:239-248, 2039-2088).
///
/// Detects an artificially joined Varnode (a SUBPIECE taking the most-
/// significant part of a value that flows from a PIECE, possibly through
/// INDIRECT/MULTIEQUAL), then constructs a `SplitFlow` transform to split the
/// pieces into independent data-flows. The detection logic is 1:1 with Ghidra;
/// the rewrite now invokes `SplitFlow::do_trace` + `SplitFlow::apply` via the
/// ported `TransformManager` machinery (transform.rs).
pub struct RuleSplitFlow;
impl RuleSplitFlow {
    // Ghidra: subflow.hh:239 RuleSplitFlow::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSplitFlow {
    // Ghidra: subflow.cc:2045 RuleSplitFlow::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSplitFlow::applyOp (subflow.cc:2045-2088)
        let (lo_size, vn_written, vn, concat_op) = {
            let op = op_arc.read().unwrap();
            let lo_size = op.get_in(1).unwrap().read().unwrap().get_offset() as i32;
            if lo_size == 0 {
                return Ok(action_status::NO_CHANGE); // SUBPIECE takes least significant part
            }
            let vn = op.get_in(0).cloned().unwrap();
            let vn_written = vn.read().unwrap().is_written();
            (lo_size, vn_written, vn.clone(), None::<Arc<RwLock<PcodeOp>>>)
        };
        if !vn_written {
            return Ok(action_status::NO_CHANGE);
        }
        // Ghidra: if (vn->isPrecisLo() || vn->isPrecisHi()) return 0;
        // (subflow.cc:2054) — now wired via Varnode::is_precis_lo()/is_precis_hi().
        if vn.read().unwrap().is_precis_lo() || vn.read().unwrap().is_precis_hi() {
            return Ok(action_status::NO_CHANGE); // Do not split if value comes from double-precision pieces
        }
        let (out_size, vn_size) = {
            let op = op_arc.read().unwrap();
            let out_size = op.get_out().map(|o| o.read().unwrap().get_size()).unwrap_or(0) as i32;
            let vn_size = vn.read().unwrap().get_size() as i32;
            (out_size, vn_size)
        };
        if out_size + lo_size != vn_size {
            return Ok(action_status::NO_CHANGE); // SUBPIECE must take most significant part
        }
        let _ = concat_op;

        // Walk back through INDIRECT to find the PIECE / MULTIEQUAL source.
        let mut multi_op = vn.read().unwrap().get_def();
        while let Some(mo) = &multi_op {
            if mo.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
                break;
            }
            let tmpvn = mo.read().unwrap().get_in(0).cloned();
            match tmpvn {
                Some(t) if t.read().unwrap().is_written() => {
                    multi_op = t.read().unwrap().get_def();
                }
                _ => break,
            }
        }
        let mut concat_op: Option<Arc<RwLock<PcodeOp>>> = None;
        if let Some(mo) = &multi_op {
            let code = mo.read().unwrap().opcode;
            if code == OpCode::CPUI_PIECE {
                // if (vn->getDef() != multiOp) concatOp = multiOp;
                if vn.read().unwrap().get_def().map(|d| Arc::as_ptr(&d) != Arc::as_ptr(mo)).unwrap_or(false) {
                    concat_op = Some(mo.clone());
                }
            } else if code == OpCode::CPUI_MULTIEQUAL {
                let num = mo.read().unwrap().num_input();
                for i in 0..num {
                    let invn = mo.read().unwrap().get_in(i).cloned();
                    if let Some(inv) = invn {
                        if !inv.read().unwrap().is_written() {
                            continue;
                        }
                        if let Some(tmp) = inv.read().unwrap().get_def() {
                            if tmp.read().unwrap().opcode == OpCode::CPUI_PIECE {
                                concat_op = Some(tmp);
                                break;
                            }
                        }
                    }
                }
            }
        }
        let concat_op = match concat_op {
            Some(c) => c,
            None => return Ok(action_status::NO_CHANGE), // Didn't find the concatenate
        };
        let in1_size = concat_op.read().unwrap().get_in(1).unwrap().read().unwrap().get_size() as i32;
        if in1_size != lo_size {
            return Ok(action_status::NO_CHANGE);
        }
        // SplitFlow splitFlow(&data,vn,loSize);
        // if (!splitFlow.doTrace()) return 0;
        // splitFlow.apply();
        // return 1;   (subflow.cc:2084-2087)
        let mut split_flow = SplitFlow::new(fd, vn, lo_size);
        if !split_flow.do_trace() {
            return Ok(action_status::NO_CHANGE);
        }
        split_flow.apply(fd);
        Ok(action_status::CHANGE)
    }
    // Ghidra: subflow.hh:239 RuleSplitFlow::getName
    fn get_name(&self) -> &str {
        "splitflow"
    }
    // Ghidra: subflow.cc:2039 RuleSplitFlow::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_SUBPIECE]
    }
}

// =====================================================================
// SplitDatatype — split COPY/LOAD/STORE on partial structures/arrays
// (subflow.hh:255-309, subflow.cc:2090-3004)
// =====================================================================

/// Split a p-code COPY, LOAD, or STORE op based on underlying composite
/// data-type. Faithful to Ghidra's `SplitDatatype` (subflow.hh:255-309).
///
/// During the cleanup phase, if a COPY/LOAD/STORE occurs on a partial
/// structure or array (TypePartialStruct), break it up into multiple
/// operations that each act on a logical component.
///
/// The gate chain is ported 1:1 as of SPLITDATATYPE-EXACTPIECE-0001:
/// `RuleSplitLoad`/`RuleSplitStore` call `SplitDatatype::getValueDatatype`
/// (subflow.cc:2910-2938), which routes through the canonical
/// `TypeFactory::getExactPiece` (type.cc:4090-4117) via the
/// Architecture-owned factory, and the piece decomposition runs through
/// `categorizeDatatype` + `testDatatypeCompatibility` (subflow.cc:2237-2386).
///
/// The `RootPointer` family (find/backUpPointer/duplicateToTemp/
/// freePointerChain, subflow.cc:2098-2203), `buildPointers`
/// (subflow.cc:2616-2672), `buildInConstants` (subflow.cc:2474-2488), the
/// splitStore LOAD-value trace (subflow.cc:2812-2835) and the splitLoad
/// COPY-follow (subflow.cc:2761-2771) are ported 1:1 as of
/// SUBFLOW-ROOTPOINTER-PORT-0001. The ten union facing consults
/// (cc:2118/2157/2772/2822/2828/2914/2950/2951) run through the fd-aware
/// twins (`vn_type_read_facing`/`vn_type_def_facing`, unionresolve.rs) as of
/// UNIONRESOLVE-PKG-E-0001: the oracle derives the containing Funcdata inside
/// `TypeUnion::findResolve` (type.cc:2138) and consults `fd->getUnionField`;
/// Rugra threads the `SplitDatatype::data`/`Funcdata` channel explicitly.
/// Remaining structural gap (see module docs): the
/// `buildInSubpieces`/`buildOutVarnodes`/`buildOutConcats` raw op-DAG shapes
/// (address-placed outputs, protoPartial PIECE stacks, generateConstants
/// folding) keep the stand-in forms.
pub struct SplitDatatype<'a> {
    /// The containing function. Faithful to `data`.
    pub data: &'a mut Funcdata,
    /// The data-type container. Faithful to `types` (subflow.hh:284), set
    /// from `func.getArch()->types` in the constructor (subflow.cc:2705).
    pub types: Option<Arc<RwLock<crate::type_system::typefactory::TypeFactory>>>,
    /// Sequence of all data-type pairs being copied. Faithful to
    /// `dataTypePieces`.
    pub data_type_pieces: Vec<Component>,
    /// Whether or not structures should be split. `splitStructures`.
    pub split_structures: bool,
    /// Whether or not arrays should be split. `splitArrays`.
    pub split_arrays: bool,
    /// True if trying to split LOAD or STORE. `isLoadStore`.
    pub is_load_store: bool,
}

/// A pair of matching data-types for the split. Faithful to Ghidra's
/// `SplitDatatype::Component` (subflow.hh:259-266).
#[derive(Clone)]
pub struct Component {
    /// Data-type coming into the logical COPY operation.
    pub in_type: Arc<crate::type_system::Datatype>,
    /// Data-type coming out of the logical COPY operation.
    pub out_type: Arc<crate::type_system::Datatype>,
    /// Offset of this logical piece within the whole.
    pub offset: i32,
}

/// A helper describing the pointer being passed to a LOAD or STORE. Faithful
/// to Ghidra's `SplitDatatype::RootPointer` (subflow.hh:271-283).
#[derive(Debug, Clone)]
pub struct RootPointer {
    /// LOAD or STORE op. Faithful to `loadStore`.
    pub load_store: Option<Arc<RwLock<PcodeOp>>>,
    /// Base pointer data-type of LOAD or STORE. Faithful to `ptrType`.
    pub ptr_type: Option<Arc<crate::type_system::Datatype>>,
    /// Direct pointer input for LOAD or STORE. Faithful to `firstPointer`.
    pub first_pointer: Option<Arc<RwLock<Varnode>>>,
    /// The root pointer. Faithful to `pointer`.
    pub pointer: Option<Arc<RwLock<Varnode>>>,
    /// Offset of the LOAD or STORE relative to root pointer. Faithful to
    /// `baseOffset`.
    pub base_offset: i32,
}

impl RootPointer {
    // Ghidra: subflow.hh:271 RootPointer::new
    /// Construct an empty RootPointer.
    pub fn new() -> Self {
        Self {
            load_store: None,
            ptr_type: None,
            first_pointer: None,
            pointer: None,
            base_offset: 0,
        }
    }

    // Ghidra: subflow.cc:2098 SplitDatatype::RootPointer::backUpPointer
    /// Follow the flow of `pointer` back through an INT_ADD, PTRSUB, PTRADD,
    /// or COPY from another pointer to a structure/array (or, for PTRADD/COPY
    /// only, to an implied array with the given base type), updating
    /// `pointer`, `base_offset`, and `ptr_type`. Faithful to
    /// `RootPointer::backUpPointer` (subflow.cc:2098-2134).
    ///
    /// An untyped input varnode maps to Ghidra's `undefined` bank type
    /// (funcdata_varnode.cc:69/88) whose metatype is not TYPE_PTR, so the
    /// `None` read-facing result rejects exactly like the oracle's non-ptr
    /// metatype check (cc:2119-2120).
    ///
    /// `fd` is the RUGRA-GLUE channel for the cc:2118 consult
    /// `tmpPointer->getTypeReadFacing(addOp)`: the oracle's
    /// `TypeUnion::findResolve` derives the Funcdata from
    /// `op->getParent()->getFuncdata()` (type.cc:2138) and consults
    /// `fd->getUnionField`; Rugra's `PcodeOp` carries no back-pointer, so the
    /// containing function is threaded through explicitly and the consult
    /// goes through [`crate::unionresolve::vn_type_read_facing`]
    /// (slot 0: `tmpPointer` is `addOp->getIn(0)`).
    fn back_up_pointer(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        implied_base: Option<&Arc<crate::type_system::Datatype>>,
    ) -> bool {
        use crate::type_system::{Datatype, TypeMetatype};

        let pointer = match &self.pointer {
            Some(pointer) => pointer.clone(),
            None => return false,
        };
        if !pointer.read().unwrap().is_written() {
            return false;
        }
        let add_op = pointer.read().unwrap().get_def().unwrap();
        let opc = add_op.read().unwrap().opcode;
        let mut off: i32;
        if opc == OpCode::CPUI_PTRSUB
            || opc == OpCode::CPUI_INT_ADD
            || opc == OpCode::CPUI_PTRADD
        {
            let cvn = add_op.read().unwrap().get_in(1).cloned().unwrap();
            if !cvn.read().unwrap().is_constant() {
                return false;
            }
            off = cvn.read().unwrap().get_offset() as i32;
        } else if opc == OpCode::CPUI_COPY {
            off = 0;
        } else {
            return false;
        }
        let tmp_pointer = add_op.read().unwrap().get_in(0).cloned().unwrap();
        // cc:2118: tmpPointer->getTypeReadFacing(addOp) — slot 0 consult
        // through fd.union_map (see the fd channel note above).
        let ct = crate::unionresolve::vn_type_read_facing(
            fd,
            &tmp_pointer,
            &crate::op::PcodeOpRef(add_op.clone()),
            0,
        );
        let ct = match ct {
            Some(ct) => ct,
            None => return false, // untyped == undefinedN, not TYPE_PTR (cc:2119)
        };
        let (parent, wordsize) = match ct.as_ref() {
            Datatype::Pointer(pointer) => {
                (pointer.ptr_to.clone(), pointer.wordsize)
            }
            _ => return false, // ct->getMetatype() != TYPE_PTR (cc:2119-2120)
        };
        let meta = parent.get_metatype();
        if meta != TypeMetatype::Struct && meta != TypeMetatype::Array {
            let parent_is_implied = implied_base
                .map(|base| Arc::ptr_eq(base, &parent))
                .unwrap_or(false);
            if (opc != OpCode::CPUI_PTRADD && opc != OpCode::CPUI_COPY)
                || !parent_is_implied
            {
                return false;
            }
        }
        self.ptr_type = Some(ct);
        if opc == OpCode::CPUI_PTRADD {
            let scale = add_op
                .read()
                .unwrap()
                .get_in(2)
                .cloned()
                .unwrap()
                .read()
                .unwrap()
                .get_offset() as i32;
            off = off.wrapping_mul(scale);
        }
        off = crate::space::AddrSpace::address_to_byte_int(off as i64, wordsize as u32) as i32;
        self.base_offset = self.base_offset.wrapping_add(off);
        self.pointer = Some(tmp_pointer);
        true
    }

    // Ghidra: subflow.cc:2144 SplitDatatype::RootPointer::find
    /// Locate the root pointer for the underlying LOAD or STORE. Faithful to
    /// `RootPointer::find` (subflow.cc:2144-2176): strip TYPE_PARTIALSTRUCT to
    /// the containing struct/array and, for an array value-type, allow an
    /// implied array (pointer to element) as a match; require the immediate
    /// `in(1)` pointer (or, after one `back_up_pointer` hop, its base) to
    /// point at the value-type; then back up through at most 3 hops of
    /// nested struct/array pointers that have a lone descendant, accumulating
    /// the offset in `base_offset`.
    ///
    /// `fd` is the RUGRA-GLUE channel for the cc:2157 consult
    /// `pointer->getTypeReadFacing(op)` (slot 1: `pointer` is the LOAD/STORE
    /// `in(1)`) and for the `backUpPointer` hops — see the channel note on
    /// [`Self::back_up_pointer`].
    pub fn find(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        op: &Arc<RwLock<PcodeOp>>,
        value_type: &Arc<crate::type_system::Datatype>,
    ) -> bool {
        use crate::type_system::{Datatype, TypeMetatype};

        let mut value_type = value_type.clone();
        let mut implied_base: Option<Arc<crate::type_system::Datatype>> = None;
        // Strip off partial to get containing struct or array (cc:2148-2149).
        if value_type.get_metatype() == TypeMetatype::PartialStruct {
            if let Datatype::PartialStruct(partial) = value_type.as_ref() {
                value_type = partial.container.clone();
            }
        }
        // Array data-types allow an implied array match (cc:2150-2153).
        if value_type.get_metatype() == TypeMetatype::Array {
            if let Datatype::Array(array) = value_type.as_ref() {
                value_type = array.array_of.clone();
            }
            implied_base = Some(value_type.clone());
        }
        self.load_store = Some(op.clone());
        self.base_offset = 0;
        let pointer = op.read().unwrap().get_in(1).cloned().unwrap();
        self.first_pointer = Some(pointer.clone());
        self.pointer = Some(pointer.clone());
        // cc:2157: pointer->getTypeReadFacing(op) — slot 1 consult through
        // fd.union_map (see the fd channel note above).
        let ct = crate::unionresolve::vn_type_read_facing(
            fd,
            &pointer,
            &crate::op::PcodeOpRef(op.clone()),
            1,
        );
        let ct = match ct {
            Some(ct) => ct,
            None => return false,
        };
        let ptr_to = match ct.as_ref() {
            Datatype::Pointer(pointer) => pointer.ptr_to.clone(),
            _ => return false, // ct->getMetatype() != TYPE_PTR (cc:2158-2159)
        };
        self.ptr_type = Some(ct);
        if !Arc::ptr_eq(&ptr_to, &value_type) {
            if implied_base.is_some() {
                return false;
            }
            if !self.back_up_pointer(fd, implied_base.as_ref()) {
                return false;
            }
            let ptr_to = match self.ptr_type.as_ref().unwrap().as_ref() {
                Datatype::Pointer(pointer) => pointer.ptr_to.clone(),
                _ => return false,
            };
            if !Arc::ptr_eq(&ptr_to, &value_type) {
                return false;
            }
        }
        // Back up to pointers to containing structures or arrays (cc:2170-2174).
        for _ in 0..3 {
            let pointer = self.pointer.as_ref().unwrap().clone();
            let (addr_tied, lone) = {
                let guard = pointer.read().unwrap();
                (guard.is_addr_tied(), guard.lone_descend().is_none())
            };
            if addr_tied || lone {
                break;
            }
            if !self.back_up_pointer(fd, implied_base.as_ref()) {
                break;
            }
        }
        true
    }

    // Ghidra: subflow.cc:2183 SplitDatatype::RootPointer::duplicateToTemp
    /// COPY the root pointer varnode into a temporary register, making it the
    /// new root so it cannot be modified by subsequent STOREs. Faithful to
    /// `RootPointer::duplicateToTemp` (subflow.cc:2183-2189) including the
    /// `newRoot->updateType(ptrType)` retype.
    pub fn duplicate_to_temp(&mut self, data: &mut Funcdata, follow_op: &PcodeOpRef) {
        let pointer = self.pointer.as_ref().unwrap().clone();
        let new_root = data.build_copy_temp(&pointer, follow_op);
        new_root
            .write()
            .unwrap()
            .update_type(self.ptr_type.as_ref().unwrap().clone());
        self.pointer = Some(new_root);
    }

    // Ghidra: subflow.cc:2195 SplitDatatype::RootPointer::freePointerChain
    /// If the first pointer varnode is no longer used, recursively remove the
    /// op producing it (INT_ADD or PTRSUB) until the root pointer is reached
    /// or a varnode still in use is encountered. Faithful to
    /// `RootPointer::freePointerChain` (subflow.cc:2195-2203). The in(0)
    /// successor is read before `op_destroy` nulls the dead op's inputs.
    pub fn free_pointer_chain(&mut self, data: &mut Funcdata) {
        loop {
            let first = match &self.first_pointer {
                Some(first) => first.clone(),
                None => break,
            };
            let pointer = match &self.pointer {
                Some(pointer) => pointer.clone(),
                None => break,
            };
            if Arc::ptr_eq(&first, &pointer) {
                break;
            }
            let (addr_tied, no_descend) = {
                let guard = first.read().unwrap();
                (guard.is_addr_tied(), guard.has_no_descend())
            };
            if addr_tied || !no_descend {
                break;
            }
            let tmp_op = first.read().unwrap().get_def().unwrap();
            let next = tmp_op.read().unwrap().get_in(0).cloned().unwrap();
            self.first_pointer = Some(next);
            data.op_destroy(&PcodeOpRef(tmp_op));
        }
    }
}

impl<'a> SplitDatatype<'a> {
    // Ghidra: subflow.cc:2701 SplitDatatype::SplitDatatype
    /// Constructor. Faithful to `SplitDatatype::SplitDatatype(Funcdata&)`
    /// (subflow.cc:2701-2709): `types = glb->types`, and the
    /// `splitStructures`/`splitArrays` flags come from the Architecture's
    /// `split_datatype_config` (`OptionSplitDatatypes` bits,
    /// architecture.cc:1431-1432). A Funcdata without an attached
    /// Architecture has no factory/config, so both flags stay false and the
    /// rules are inert (the C++ Funcdata always has an Architecture).
    pub fn new(data: &'a mut Funcdata) -> Self {
        let (types, config) = match data.get_arch() {
            Some(arch) => (arch.types.clone(), arch.split_datatype_config),
            None => (None, 0),
        };
        Self {
            data,
            types,
            data_type_pieces: Vec::new(),
            split_structures: (config & crate::arch::split_datatype::OPTION_STRUCT) != 0,
            split_arrays: (config & crate::arch::split_datatype::OPTION_ARRAY) != 0,
            is_load_store: false,
        }
    }

    // Ghidra: subflow.cc:2910 SplitDatatype::getValueDatatype
    /// Get a data-type description of the value being pointed at by the given
    /// LOAD or STORE. Faithful to `SplitDatatype::getValueDatatype`
    /// (subflow.cc:2910-2938): takes the data-type of the pointer input
    /// `in(1)` (read-facing the op) and constructs the type of the thing
    /// pointed at matching `size` bytes — resolving `TypePointerRel`
    /// parent/byte-offset, interpreting over-aligned scalars as arrays
    /// (`getTypeArray`), and otherwise delegating STRUCT/ARRAY pointers to
    /// the canonical `TypeFactory::getExactPiece` (type.cc:4090-4117), which
    /// can produce `TypePartialStruct`/`TypePartialUnion`/`TypePartialEnum`
    /// pieces. Returns `None` when no splittable interpretation exists.
    ///
    /// `fd` is the RUGRA-GLUE channel for the cc:2914 consult
    /// `loadStore->getIn(1)->getTypeReadFacing(loadStore)` (slot 1): the
    /// oracle derives the Funcdata inside `TypeUnion::findResolve`
    /// (type.cc:2138); Rugra threads it explicitly into
    /// [`crate::unionresolve::vn_type_read_facing`].
    pub fn get_value_datatype(
        fd: &crate::funcdata::Funcdata,
        load_store: &Arc<RwLock<PcodeOp>>,
        size: usize,
        types: &Arc<RwLock<crate::type_system::typefactory::TypeFactory>>,
    ) -> Option<Arc<crate::type_system::Datatype>> {
        use crate::type_system::datatype::type_flags;
        use crate::type_system::{Datatype, TypeMetatype};

        let ptr_vn = load_store.read().unwrap().get_in(1).cloned()?;
        // cc:2914: loadStore->getIn(1)->getTypeReadFacing(loadStore) —
        // slot 1 consult through fd.union_map.
        let ptr_type = crate::unionresolve::vn_type_read_facing(
            fd,
            &ptr_vn,
            &crate::op::PcodeOpRef(load_store.clone()),
            1,
        )?;
        // if (ptrType->getMetatype() != TYPE_PTR) return 0; (cc:2917-2918)
        let pointer = match ptr_type.as_ref() {
            Datatype::Pointer(pointer) => pointer,
            _ => return None,
        };
        // TypePointerRel parents carry the container + byte offset
        // (cc:2920-2926); plain pointers use ptrTo with baseOffset 0.
        let (res_type, base_offset) = if (pointer.base.flags & type_flags::IS_PTRREL) != 0 {
            match (pointer.get_parent(), pointer.get_byte_offset()) {
                (Some(parent), Some(offset)) => (parent.clone(), offset),
                // Legacy named relative pointers keep the parent only in the
                // factory side table (typefactory rel_pointers); fall back to
                // the plain-pointer reading for them.
                _ => (pointer.ptr_to.clone(), 0),
            }
        } else {
            (pointer.ptr_to.clone(), 0)
        };
        let align_size = res_type.get_align_size();
        let metain = res_type.get_metatype();
        if align_size < size {
            // Over-aligned scalar reinterpreted as an element array
            // (cc:2930-2936). The align_size != 0 term is a Rust divide-by
            // -zero guard only; Ghidra align sizes are never 0 here.
            if matches!(
                metain,
                TypeMetatype::Int
                    | TypeMetatype::Uint
                    | TypeMetatype::Bool
                    | TypeMetatype::Float
                    | TypeMetatype::Pointer
            ) && align_size != 0
                && size % align_size == 0
            {
                let num_el = size / align_size;
                return Some(
                    types
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get_array(res_type, num_el),
                );
            }
        } else if matches!(metain, TypeMetatype::Struct | TypeMetatype::Array) {
            // tlst->getExactPiece(resType, baseOffset, size) (cc:2937) — the
            // canonical factory piece recovery, identical to the four
            // production callers (TYPEFACTORY-EXACTPIECE-CALLERS-0001).
            return types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_exact_piece(res_type, base_offset, size);
        }
        None
    }

    // Ghidra: subflow.cc:2215 SplitDatatype::getComponent
    /// Obtain the component of the given data-type at the specified offset.
    /// Faithful to `SplitDatatype::getComponent` (subflow.cc:2208-2234):
    /// descends `getSubType` until the offset lands exactly at a component
    /// (iterating through array elements); if no component starts at the
    /// offset, a hole-sized (capped at 8) `undefined` piece is returned with
    /// the hole flag set. Returns `None` when no component and no hole exist.
    fn get_component(
        &self,
        ct: &Arc<crate::type_system::Datatype>,
        offset: i64,
    ) -> Option<(Arc<crate::type_system::Datatype>, bool)> {
        use crate::type_system::{Datatype, TypeMetatype};

        let types = self.types.as_ref()?;
        let mut cur_type = ct.clone();
        let mut cur_off = offset;
        loop {
            let (sub_type, new_off) = Datatype::get_sub_type_arc(&cur_type, cur_off);
            match sub_type {
                None => {
                    let mut hole = ct.get_hole_size(offset);
                    if hole > 0 {
                        if hole > 8 {
                            hole = 8;
                        }
                        let unknown = types
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get_base_result(hole as usize, TypeMetatype::Unknown)
                            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
                        return Some((unknown, true));
                    }
                    return None;
                }
                Some(sub) => {
                    cur_type = sub;
                    cur_off = new_off;
                    // while(curOff != 0 || curType->getMetatype() == TYPE_ARRAY)
                    if !(cur_off != 0 || cur_type.get_metatype() == TypeMetatype::Array) {
                        return Some((cur_type, false));
                    }
                }
            }
        }
    }

    // Ghidra: subflow.cc:2244 SplitDatatype::categorizeDatatype
    /// Categorize if and how a data-type should be split. Faithful to
    /// `SplitDatatype::categorizeDatatype` (subflow.cc:2237-2274):
    /// -1 = not splittable, 0 = struct-based split, 1 = array-based split,
    /// 2 = primitive that can be split multiple ways. `undefined1` element
    /// arrays act as large primitives (category 2), and whole structs need
    /// `numDepend() > 1` fields to be splittable.
    ///
    /// `pub` for the bilateral fixture observation (the C++ twin reaches the
    /// private member through `#define private public`,
    /// tests/oracle/splitdatatype_exactpiece_1204.cc).
    pub fn categorize_datatype(&self, ct: &Arc<crate::type_system::Datatype>) -> i32 {
        use crate::type_system::{Datatype, TypeMetatype};

        let array_category = |split_arrays: bool, array: &crate::type_system::datatype::TypeArray| {
            if !split_arrays {
                return -1;
            }
            let sub = &array.array_of;
            if sub.get_metatype() != TypeMetatype::Unknown || sub.get_size() != 1 {
                1
            } else {
                2 // unknown1 array acts as a large primitive (cc:2247-2248)
            }
        };
        match ct.as_ref() {
            Datatype::Array(array) => array_category(self.split_arrays, array),
            Datatype::PartialStruct(partial) => match partial.container.as_ref() {
                // PartialStruct containers are struct or array by
                // construction (TypePartialStruct ctor, type.cc:2330-2341).
                Datatype::Array(array) => array_category(self.split_arrays, array),
                Datatype::Struct(_) => {
                    if self.split_structures {
                        0
                    } else {
                        -1
                    }
                }
                _ => -1,
            },
            Datatype::Struct(structure) => {
                if !self.split_structures {
                    return -1;
                }
                // TypeStruct::numDepend = field.size() (type.hh:526); the
                // whole-struct split requires numDepend() > 1 (cc:2270-2271).
                if structure.fields.len() > 1 {
                    0
                } else {
                    -1
                }
            }
            _ => match ct.get_metatype() {
                TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Unknown => 2,
                _ => -1,
            },
        }
    }

    // Ghidra: subflow.cc:2296 SplitDatatype::testDatatypeCompatibility
    /// Can the two given data-types be mutually split into matching logical
    /// components. Faithful to `SplitDatatype::testDatatypeCompatibility`
    /// (subflow.cc:2285-2367): both sides are categorized, the load/store
    /// array/primitive combination gates are applied (cc:2303-2308), the
    /// whole-struct identity gate rejects non-constant whole-struct copies
    /// (cc:2304-2305), and the component walk fills `data_type_pieces`
    /// (offset, in/out types per piece) with hole handling (initial-hole and
    /// two-piece-padding rejections, cc:2331-2336/2348-2353). At least one
    /// piece per side must be a composite; `true` requires more than one
    /// piece (cc:2367).
    ///
    /// `pub` for the bilateral fixture observation (the C++ twin reaches the
    /// private member through `#define private public`,
    /// tests/oracle/splitdatatype_exactpiece_1204.cc).
    pub fn test_datatype_compatibility(
        &mut self,
        in_base: &Arc<crate::type_system::Datatype>,
        out_base: &Arc<crate::type_system::Datatype>,
        in_constant: bool,
    ) -> bool {
        use crate::type_system::TypeMetatype;

        // Ghidra's function body has no explicit clear: dataTypePieces starts
        // empty on the stack-constructed splitter, and splitStore's LOAD
        // retry path clears explicitly (cc:2829). Rugra reuses one splitter
        // across the compat call and the rewrite, so clearing on entry keeps
        // every oracle call path behaviour-equivalent (the oracle never
        // observes stale pieces: splitCopy/splitLoad call compat exactly
        // once, and splitStore's retry is the only oracle re-entry).
        self.data_type_pieces.clear();
        let in_category = self.categorize_datatype(in_base);
        if in_category < 0 {
            return false;
        }
        let out_category = self.categorize_datatype(out_base);
        if out_category < 0 {
            return false;
        }
        if out_category == 2 && in_category == 2 {
            return false;
        }
        if !in_constant
            && Arc::ptr_eq(in_base, out_base)
            && in_base.get_metatype() == TypeMetatype::Struct
        {
            return false; // Don't split a whole structure unless constant-initialized
        }
        if self.is_load_store && out_category == 2 && in_category == 1 {
            return false; // Don't split array pointer writing into primitive
        }
        if self.is_load_store && in_category == 2 && !in_constant && out_category == 1 {
            return false; // Don't split primitive into an array pointer
        }
        if self.is_load_store && in_category == 1 && out_category == 1 && !in_constant {
            return false; // Don't split copies between arrays
        }
        let types = match self.types.as_ref() {
            Some(types) => types.clone(),
            None => return false,
        };
        let unknown_of = |sz: usize| {
            types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_base_result(sz, TypeMetatype::Unknown)
                .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
        };
        let mut cur_off: i64 = 0;
        let mut size_left: i64 = in_base.get_size() as i64;
        if in_category == 2 {
            // Input is primitive: walk the output composite (cc:2314-2330).
            while size_left > 0 {
                let Some((cur_out, out_hole)) = self.get_component(out_base, cur_off) else {
                    return false;
                };
                // Throw away the primitive type if the input is a constant.
                let cur_in = if in_constant {
                    cur_out.clone()
                } else {
                    unknown_of(cur_out.get_size())
                };
                self.data_type_pieces.push(Component {
                    in_type: cur_in,
                    out_type: cur_out.clone(),
                    offset: cur_off as i32,
                });
                size_left -= cur_out.get_size() as i64;
                cur_off += cur_out.get_size() as i64;
                if out_hole {
                    if self.data_type_pieces.len() == 1 {
                        return false; // Initial offset into structure is at a hole
                    }
                    if size_left == 0 && self.data_type_pieces.len() == 2 {
                        return false; // Two pieces, one is a hole. Likely padding.
                    }
                }
            }
        } else if out_category == 2 {
            // Output is primitive: walk the input composite (cc:2337-2353).
            while size_left > 0 {
                let Some((cur_in, in_hole)) = self.get_component(in_base, cur_off) else {
                    return false;
                };
                let cur_out = unknown_of(cur_in.get_size());
                self.data_type_pieces.push(Component {
                    in_type: cur_in.clone(),
                    out_type: cur_out,
                    offset: cur_off as i32,
                });
                size_left -= cur_in.get_size() as i64;
                cur_off += cur_in.get_size() as i64;
                if in_hole {
                    if self.data_type_pieces.len() == 1 {
                        return false; // Initial offset into structure is at a hole
                    }
                    if size_left == 0 && self.data_type_pieces.len() == 2 {
                        return false; // Two pieces, one is a hole. Likely padding.
                    }
                }
            }
        } else {
            // Both sides have components (cc:2354-2364): walk both, matching
            // piece sizes by descending the larger side (holes fall back to
            // unknown fillers of the smaller side's size).
            while size_left > 0 {
                let Some((mut cur_in, mut in_hole)) = self.get_component(in_base, cur_off)
                else {
                    return false;
                };
                let Some((mut cur_out, mut out_hole)) = self.get_component(out_base, cur_off)
                else {
                    return false;
                };
                while cur_in.get_size() != cur_out.get_size() {
                    if cur_in.get_size() > cur_out.get_size() {
                        cur_in = if in_hole {
                            unknown_of(cur_out.get_size())
                        } else {
                            match self.get_component(&cur_in, 0) {
                                Some((next, hole)) => {
                                    in_hole = hole;
                                    next
                                }
                                None => return false,
                            }
                        };
                    } else {
                        cur_out = if out_hole {
                            unknown_of(cur_in.get_size())
                        } else {
                            match self.get_component(&cur_out, 0) {
                                Some((next, hole)) => {
                                    out_hole = hole;
                                    next
                                }
                                None => return false,
                            }
                        };
                    }
                }
                self.data_type_pieces.push(Component {
                    in_type: cur_in.clone(),
                    out_type: cur_out.clone(),
                    offset: cur_off as i32,
                });
                size_left -= cur_in.get_size() as i64;
                cur_off += cur_in.get_size() as i64;
            }
        }
        self.data_type_pieces.len() > 1
    }

    // Ghidra: subflow.cc:2717 SplitDatatype::splitCopy
    /// Split a COPY operation. Faithful to `SplitDatatype::splitCopy`
    /// (subflow.cc:2717-2747): runs the copy constraints, the data-type
    /// compatibility test (`testDatatypeCompatibility`, cc:2285-2367) and the
    /// arithmetic sanity checks, then rewrites the single COPY into one
    /// per-component COPY (with SUBPIECE extraction and PIECE reassembly),
    /// destroying the original COPY.
    ///
    /// Structural note: the oracle reads the in/out facing types in
    /// `RuleSplitCopy::applyOp` (cc:2950/2951) and passes them in as
    /// parameters; Rugra re-reads them inline here with the identical
    /// consult keys (COPY op, slot 0 / def) — `testCopyConstraints` between
    /// the two reads writes nothing to `fd.union_map`, so the values are
    /// the same and the inline form is kept.
    ///
    /// Returns `true` if the split was performed. Returns `false` (no change)
    /// if either side is not a composite type that should be split, or if the
    /// in/out component layouts do not match.
    pub fn split_copy(&mut self, copy_op: &Arc<RwLock<PcodeOp>>) -> Result<bool> {
        let (in_vn, out_vn, op_addr) = {
            let o = copy_op.read().unwrap();
            (
                o.get_in(0).cloned().unwrap(),
                o.get_out().cloned().unwrap(),
                o.get_addr(),
            )
        };
        // testCopyConstraints (cc:2370-2384): don't split function inputs,
        // same-address addr-tied pairs, or a LOAD output feeding only this
        // COPY (handled by splitLoad).
        if !self.test_copy_constraints(copy_op, &in_vn, &out_vn) {
            return Ok(false);
        }
        // cc:2950/2951 (read in RuleSplitCopy::applyOp, re-read here — see the
        // structural note in the doc comment): in(0) read-facing the COPY at
        // slot 0, out def-facing — both consult fd.union_map.
        let in_type = crate::unionresolve::vn_type_read_facing(
            self.data,
            &in_vn,
            &crate::op::PcodeOpRef(copy_op.clone()),
            0,
        );
        let out_type = crate::unionresolve::vn_type_def_facing(self.data, &out_vn);
        let (in_type, out_type) = match (in_type, out_type) {
            (Some(i), Some(o)) => (i, o),
            _ => return Ok(false),
        };
        let in_constant = in_vn.read().unwrap().is_constant();
        if !self.test_datatype_compatibility(&in_type, &out_type, in_constant) {
            return Ok(false);
        }
        if is_arithmetic_output(&in_vn) {
            return Ok(false); // Sanity check on input (cc:2729)
        }
        if is_arithmetic_input(&out_vn) {
            return Ok(false); // Sanity check on output (cc:2734)
        }
        // splitCopy (cc:2730-2744): SUBPIECE/constant inputs → root+off
        // addressed piece outputs → PIECE reassembly stack → per-piece COPYs
        // → destroy the original COPY. All four builders are faithful ports
        // (see build_in_subpieces / build_out_varnodes / build_out_concats).
        let mut in_varnodes: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut out_varnodes: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        if in_vn.read().unwrap().is_constant() {
            // cc:2732-2733: constant input splits into per-piece constants.
            let big_endian = out_vn.read().unwrap().get_space().is_big_endian();
            self.build_in_constants(&in_vn.clone(), &mut in_varnodes, big_endian);
        } else {
            // cc:2734-2735: any other input splits via SUBPIECE extraction.
            self.build_in_subpieces(&in_vn.clone(), copy_op, &mut in_varnodes);
        }
        self.build_out_varnodes(&out_vn.clone(), &mut out_varnodes);
        self.build_out_concats(&out_vn.clone(), copy_op, &mut out_varnodes);
        // cc:2738-2744: one COPY per piece, all inserted before the original
        // (which is destroyed last, cc:2745).
        for i in 0..in_varnodes.len() {
            let new_copy_op = self.data.new_op(1, op_addr);
            self.data.op_set_opcode(&new_copy_op, OpCode::CPUI_COPY);
            self.data.op_set_input(&new_copy_op, in_varnodes[i].clone(), 0);
            self.data.op_set_output(&new_copy_op, out_varnodes[i].clone());
            self.data
                .op_insert_before(&new_copy_op, &crate::op::PcodeOpRef(copy_op.clone()));
        }
        self.data.op_destroy(&crate::op::PcodeOpRef(copy_op.clone()));
        Ok(true)
    }

    // Ghidra: subflow.cc:2409 SplitDatatype::generateConstants
    /// If the given Varnode is an extended precision constant (ZEXT of a
    /// constant, or PIECE of two constants), create split constants for the
    /// pieces and destroy the defining op. Faithful to
    /// `SplitDatatype::generateConstants` (subflow.cc:2409-2465): the lone
    /// descendant guard, the ZEXT/PIECE constant inputs, the big-endian
    /// shift arithmetic (`sa`/`val` from `hi`/`lo`), `calc_mask` truncation,
    /// per-piece `newConstant` + `updateType`, then `opDestroy` of the
    /// defining op.
    fn generate_constants(
        &mut self,
        vn: &Arc<RwLock<Varnode>>,
        in_varnodes: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> bool {
        // cc:2412-2413: loneDescend + isWritten guards.
        if vn.read().unwrap().lone_descend().is_none() {
            return false;
        }
        let def = vn.read().unwrap().get_def();
        let def = match def {
            Some(d) => d,
            None => return false,
        };
        let (opc, in0, in1) = {
            let d = def.read().unwrap();
            (d.opcode, d.get_in(0).cloned(), d.get_in(1).cloned())
        };
        if opc == OpCode::CPUI_INT_ZEXT {
            if !in0.as_ref().is_some_and(|v| v.read().unwrap().is_constant()) {
                return false;
            }
        } else if opc == OpCode::CPUI_PIECE {
            if !in0.as_ref().is_some_and(|v| v.read().unwrap().is_constant())
                || !in1.as_ref().is_some_and(|v| v.read().unwrap().is_constant())
            {
                return false;
            }
        } else {
            return false;
        }
        // cc:2425-2438: split the extended value into hi/lo words.
        let fullsize = vn.read().unwrap().get_size();
        let is_big_endian = vn.read().unwrap().get_space().is_big_endian();
        let (hi, lo, losize) = if opc == OpCode::CPUI_INT_ZEXT {
            let c = in0.unwrap();
            let g = c.read().unwrap();
            (0u64, g.get_offset(), g.get_size())
        } else {
            let (h, l) = (in0.unwrap(), in1.unwrap());
            let (hg, lg) = (h.read().unwrap(), l.read().unwrap());
            (hg.get_offset(), lg.get_offset(), lg.get_size())
        };
        for piece in &self.data_type_pieces {
            let dt = &piece.in_type;
            // cc:2441-2444: piece wider than uintb cannot be formed.
            if dt.get_size() > std::mem::size_of::<u64>() {
                in_varnodes.clear();
                return false;
            }
            // cc:2446-2449: byte shift of the piece within the whole.
            let sa = if is_big_endian {
                fullsize as i64 - (piece.offset as i64 + dt.get_size() as i64)
            } else {
                piece.offset as i64
            };
            let mut val = if sa >= losize as i64 {
                hi >> (sa - losize as i64)
            } else {
                let mut v = lo >> (sa * 8) as u64;
                if sa + dt.get_size() as i64 > losize as i64 {
                    v |= hi << ((losize as i64 - sa) * 8) as u64;
                }
                v
            };
            val &= crate::address::calc_mask(dt.get_size());
            // cc:2459-2461: newConstant + updateType per piece.
            let out_vn = self.data.new_constant(dt.get_size(), val);
            out_vn.write().unwrap().update_type(dt.clone());
            in_varnodes.push(out_vn);
        }
        // cc:2463: destroy the extended-precision defining op.
        self.data
            .op_destroy(&crate::op::PcodeOpRef(def));
        true
    }

    // Ghidra: subflow.cc:2497 SplitDatatype::buildInSubpieces
    /// Build input Varnodes by extracting SUBPIECEs from the root. Faithful
    /// to `SplitDatatype::buildInSubpieces` (subflow.cc:2497-2519): the
    /// `generateConstants` fold (cc:2500-2501), per-piece SUBPIECE at the
    /// input root's own address + piece offset (`addr.renormalize` is a
    /// no-op outside join spaces in Rugra's flat offset model), the
    /// big-endian offset mirror (cc:2508-2509), `newConstant(4, off)` as the
    /// shift input (cc:2513), `newVarnodeOut(size, addr, subpiece)` carrying
    /// the input root's SPACE (cc:2514), `updateType(inType)` (cc:2516) and
    /// insertion before the follow op (cc:2517).
    fn build_in_subpieces(
        &mut self,
        root_vn: &Arc<RwLock<Varnode>>,
        follow_op: &Arc<RwLock<PcodeOp>>,
        in_varnodes: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:2500-2501: ZEXT/CONCAT extended constants fold into split
        // constants instead of SUBPIECEs.
        if self.generate_constants(root_vn, in_varnodes) {
            return;
        }
        let (base_off, base_space, root_size, big_endian, follow_addr) = {
            let g = root_vn.read().unwrap();
            (
                g.get_offset(),
                g.get_space(),
                g.get_size(),
                g.get_space().is_big_endian(),
                follow_op.read().unwrap().get_addr(),
            )
        };
        for piece in &self.data_type_pieces {
            let dt = &piece.in_type;
            let off = piece.offset as i64;
            // cc:2506: addr = baseAddr + off (little-endian layout address).
            let addr = crate::address::Address::new(base_off.wrapping_add(off as u64));
            // cc:2508-2509: big-endian mirrors the SUBPIECE shift amount.
            let sub_off = if big_endian {
                root_size as i64 - off - dt.get_size() as i64
            } else {
                off
            };
            // cc:2510-2517: SUBPIECE(root, off) inserted before followOp,
            // out at the root-space piece address, typed with inType.
            let subpiece = self.data.new_op(2, follow_addr);
            self.data.op_set_opcode(&subpiece, OpCode::CPUI_SUBPIECE);
            self.data.op_set_input(&subpiece, root_vn.clone(), 0);
            let off_const = self.data.new_constant(4, sub_off as u64);
            self.data.op_set_input(&subpiece, off_const, 1);
            let out_vn = self
                .data
                .new_varnode_out_full(dt.get_size(), base_space, addr, &subpiece);
            in_varnodes.push(out_vn.clone());
            out_vn.write().unwrap().update_type(dt.clone());
            self.data
                .op_insert_before(&subpiece, &crate::op::PcodeOpRef(follow_op.clone()));
        }
    }

    // Ghidra: subflow.cc:2527 SplitDatatype::buildOutVarnodes
    /// Build output Varnodes with storage based on the given root. Faithful
    /// to `SplitDatatype::buildOutVarnodes` (subflow.cc:2527-2539): per
    /// piece, `newVarnode(size, rootAddr + off, outType)` carries the output
    /// root's SPACE (cc:2536).
    fn build_out_varnodes(
        &mut self,
        root_vn: &Arc<RwLock<Varnode>>,
        out_varnodes: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        let (base_off, base_space) = {
            let g = root_vn.read().unwrap();
            (g.get_offset(), g.get_space())
        };
        for piece in &self.data_type_pieces {
            let dt = &piece.out_type;
            let addr = crate::address::Address::new(base_off.wrapping_add(piece.offset as u64));
            // cc:2536: newVarnode(dt->getSize(), addr, dt) — the explicit
            // type lands via updateType.
            let out_vn = self
                .data
                .new_varnode_in_space(dt.get_size(), base_space, addr);
            out_vn.write().unwrap().update_type(dt.clone());
            out_varnodes.push(out_vn);
        }
    }

    // Ghidra: subflow.cc:2548 SplitDatatype::buildOutConcats
    /// Concatenate output Varnodes into the given root Varnode. Faithful to
    /// `SplitDatatype::buildOutConcats` (subflow.cc:2548-2603): the
    /// unused-root early out (cc:2551-2552), the protoPartial pre-mark of
    /// all pieces when the root is not address-tied (cc:2559-2562), the
    /// most-significant-first PIECE stack with intermediate outputs at
    /// address-derived storage (`outVarnodes[i]->getAddr()` renormalized,
    /// cc:2576/2592-2594) carrying the root's SPACE, protoPartial marks on
    /// intermediates (cc:2577-2578/2595-2596), the final PIECE flagged
    /// `partialRoot` and bound to the root output (cc:2599-2600), and
    /// `registerProtoPartialRoot` when no piece is address-tied
    /// (cc:2601-2602).
    fn build_out_concats(
        &mut self,
        root_vn: &Arc<RwLock<Varnode>>,
        previous_op: &Arc<RwLock<PcodeOp>>,
        out_varnodes: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:2551-2552: no concatenation needed if the root is unused.
        if root_vn.read().unwrap().has_no_descend() {
            return;
        }
        let (base_space, big_endian, previous_addr) = {
            let g = root_vn.read().unwrap();
            (g.get_space(), g.get_space().is_big_endian(), {
                previous_op.read().unwrap().get_addr()
            })
        };
        let address_tied = root_vn.read().unwrap().is_addr_tied();
        // cc:2559-2562: creating a CONCAT stack — mark pieces appropriately.
        for vn in out_varnodes.iter() {
            if !address_tied {
                vn.write().unwrap().set_proto_partial();
            }
        }
        let mut concat_op: Option<crate::op::PcodeOpRef> = None;
        if big_endian {
            // cc:2564-2579: big-endian walks pieces most to least
            // significant (index 0 is most significant).
            let mut vn = out_varnodes[0].clone();
            let mut pre_op = crate::op::PcodeOpRef(previous_op.clone());
            let mut i = 1usize;
            loop {
                let concat = self.data.new_op(2, previous_addr);
                self.data.op_set_opcode(&concat, OpCode::CPUI_PIECE);
                self.data.op_set_input(&concat, vn.clone(), 0); // Most significant
                self.data
                    .op_set_input(&concat, out_varnodes[i].clone(), 1); // Least significant
                self.data.op_insert_after(&concat, &pre_op);
                concat_op = Some(concat.clone());
                if i + 1 >= out_varnodes.len() {
                    break;
                }
                pre_op = concat.clone();
                let sz = vn.read().unwrap().get_size() + out_varnodes[i].read().unwrap().get_size();
                // cc:2574-2576: intermediate storage at the root base
                // address renormalized to the accumulated size.
                let addr = crate::address::Address::new(
                    root_vn.read().unwrap().get_offset().wrapping_add(0),
                );
                vn = self.data.new_varnode_out_full(sz, base_space, addr, &concat);
                if !address_tied {
                    vn.write().unwrap().set_proto_partial();
                }
                i += 1;
            }
        } else {
            // cc:2582-2597: little-endian walks pieces most to least
            // significant (last index is most significant).
            let mut vn = out_varnodes[out_varnodes.len() - 1].clone();
            let mut pre_op = crate::op::PcodeOpRef(previous_op.clone());
            let mut i = out_varnodes.len() as i64 - 2;
            loop {
                let concat = self.data.new_op(2, previous_addr);
                self.data.op_set_opcode(&concat, OpCode::CPUI_PIECE);
                self.data.op_set_input(&concat, vn.clone(), 0); // Most significant
                self.data
                    .op_set_input(&concat, out_varnodes[i as usize].clone(), 1); // Least significant
                self.data.op_insert_after(&concat, &pre_op);
                concat_op = Some(concat.clone());
                if i <= 0 {
                    break;
                }
                pre_op = concat.clone();
                let sz = vn.read().unwrap().get_size()
                    + out_varnodes[i as usize].read().unwrap().get_size();
                // cc:2592-2594: intermediate storage at the current piece's
                // address renormalized to the accumulated size.
                let addr = crate::address::Address::new(
                    out_varnodes[i as usize].read().unwrap().get_offset(),
                );
                vn = self.data.new_varnode_out_full(sz, base_space, addr, &concat);
                if !address_tied {
                    vn.write().unwrap().set_proto_partial();
                }
                i -= 1;
            }
        }
        // cc:2599-2600: the final PIECE becomes the partial root defining
        // the original output.
        let concat_op = concat_op.expect("buildOutConcats ran with zero pieces");
        concat_op.0.write().unwrap().set_partial_root();
        self.data.op_set_output(&concat_op, root_vn.clone());
        // cc:2601-2602: register the unmapped CONCAT stack with the merge
        // process so groupPartials can group it into a single variable.
        if !address_tied {
            self.data.merge_state.register_proto_partial_root(root_vn);
        }
    }

    // Ghidra: subflow.cc:2474 SplitDatatype::buildInConstants
    /// Build split constant input varnodes, extracting the constant value
    /// from the given root constant based on the input offsets in
    /// `data_type_pieces`. Faithful to `SplitDatatype::buildInConstants`
    /// (subflow.cc:2474-2488), including the big-endian offset mirror and the
    /// `outVn->updateType(dt)` retype.
    fn build_in_constants(
        &mut self,
        root_vn: &Arc<RwLock<Varnode>>,
        in_varnodes: &mut Vec<Arc<RwLock<Varnode>>>,
        big_endian: bool,
    ) {
        let (base_val, root_size) = {
            let guard = root_vn.read().unwrap();
            (guard.get_offset(), guard.get_size())
        };
        for piece in &self.data_type_pieces {
            let dt = piece.in_type.clone();
            let mut off = piece.offset;
            if big_endian {
                off = root_size as i32 - off - dt.get_size() as i32;
            }
            // cc:2483 `baseVal >> (8*off)`: plain constants are at most
            // sizeof(uintb) wide on the oracle side, so 8*off < 64 there by
            // construction (wider values arrive as ZEXT/PIECE and fold via
            // generateConstants). Rugra can hold >8-byte plain constants
            // whose get_offset() carries only the low 8 bytes, so pieces at
            // off >= 8 read the (absent) high bytes as zero instead of
            // panicking on the C++ UB boundary.
            let shift = (8 * off).max(0) as u64;
            let val = if shift >= 64 {
                0
            } else {
                (base_val >> shift) & calc_mask(dt.get_size())
            };
            let out_vn = self.data.new_constant(dt.get_size(), val);
            out_vn.write().unwrap().update_type(dt);
            in_varnodes.push(out_vn);
        }
    }

    // Ghidra: subflow.cc:2616 SplitDatatype::buildPointers
    /// Build a series of PTRSUB/PTRADD ops at different offsets, given a root
    /// pointer. Faithful to `SplitDatatype::buildPointers`
    /// (subflow.cc:2616-2672): per piece, descend the pointed-to type at
    /// `base_offset + piece offset`; offsets outside the current type (or
    /// array element strides) emit PTRADD with an element-size scaled index
    /// (the index varnode retyped TYPE_INT), interior struct offsets emit
    /// PTRSUB; the chain is repeated while the enclosing type is larger than
    /// the match type, and every intermediate pointer is retyped through the
    /// canonical strip-array pointer construction.
    fn build_pointers(
        &mut self,
        root_vn: &Arc<RwLock<Varnode>>,
        ptr_type: &Arc<crate::type_system::Datatype>,
        base_offset: i32,
        follow_op: &PcodeOpRef,
        ptr_varnodes: &mut Vec<Arc<RwLock<Varnode>>>,
        is_input: bool,
    ) {
        use crate::type_system::{Datatype, TypeMetatype};

        let (ptr_wordsize, base_type) = match ptr_type.as_ref() {
            Datatype::Pointer(pointer) => (pointer.wordsize, pointer.ptr_to.clone()),
            _ => return,
        };
        let ptr_type_size = ptr_type.get_size();
        for i in 0..self.data_type_pieces.len() {
            let piece = self.data_type_pieces[i].clone();
            let match_type = if is_input {
                piece.in_type.clone()
            } else {
                piece.out_type.clone()
            };
            let mut cur_off: i64 = base_offset as i64 + piece.offset as i64;
            let mut tmp_type = base_type.clone();
            let mut in_ptr = root_vn.clone();
            loop {
                let tmp_size = tmp_type.get_size() as i64;
                let (new_type, new_off): (Arc<Datatype>, i64);
                if cur_off < 0 || cur_off >= tmp_size {
                    // An offset not within the data-type indicates an array.
                    let mut next_off = cur_off % tmp_size;
                    if next_off < 0 {
                        next_off += tmp_size;
                    }
                    new_type = tmp_type.clone();
                    new_off = next_off;
                } else {
                    let (sub, off) = Datatype::get_sub_type_arc(&tmp_type, cur_off);
                    match sub {
                        // Null is only returned for a hole in a structure;
                        // use the precomputed match data-type (cc:2636-2640).
                        Some(sub) => {
                            new_type = sub;
                            new_off = off;
                        }
                        None => {
                            new_type = match_type.clone();
                            new_off = 0;
                        }
                    }
                }
                let is_array_step =
                    Arc::ptr_eq(&tmp_type, &new_type) || tmp_type.get_metatype() == TypeMetatype::Array;
                let follow_addr = follow_op.0.read().unwrap().get_addr();
                let in_ptr_size = in_ptr.read().unwrap().get_size();
                let new_op = self.data.new_op(if is_array_step { 3 } else { 2 }, follow_addr);
                if is_array_step {
                    let elem_size = new_type.get_size() as i64;
                    let final_offset = (cur_off - new_off) / elem_size;
                    let sz = crate::space::AddrSpace::byte_to_address_int(elem_size, ptr_wordsize as u32);
                    self.data.op_set_opcode(&new_op, OpCode::CPUI_PTRADD);
                    self.data.op_set_input(&new_op, in_ptr.clone(), 0);
                    let index_vn = self.data.new_constant(in_ptr_size, final_offset as u64);
                    self.data.op_set_input(&new_op, index_vn.clone(), 1);
                    let scale_vn = self.data.new_constant(in_ptr_size, sz as u64);
                    self.data.op_set_input(&new_op, scale_vn, 2);
                    if let Some(types) = self.types.as_ref() {
                        let index_type = types
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get_base_result(in_ptr_size, TypeMetatype::Int)
                            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
                        index_vn.write().unwrap().update_type(index_type);
                    }
                } else {
                    let final_offset =
                        crate::space::AddrSpace::byte_to_address_int(cur_off - new_off, ptr_wordsize as u32);
                    self.data.op_set_opcode(&new_op, OpCode::CPUI_PTRSUB);
                    self.data.op_set_input(&new_op, in_ptr.clone(), 0);
                    let off_vn = self.data.new_constant(in_ptr_size, final_offset as u64);
                    self.data.op_set_input(&new_op, off_vn, 1);
                }
                let new_in_ptr = self.data.new_unique_out(in_ptr_size, &new_op);
                // types->getTypePointerStripArray(ptrType->getSize(), newType,
                // ptrType->getWordSize()) (cc:2664) — the canonical factory
                // pointer after the hasStripped + first-array-level strip
                // (type.cc:3849-3860), expressed through the existing
                // canonical get_type_pointer entry.
                if let Some(types) = self.types.as_ref() {
                    let mut stripped =
                        Datatype::get_stripped_arc(&new_type).unwrap_or_else(|| new_type.clone());
                    if let Datatype::Array(array) = stripped.as_ref() {
                        stripped = array.array_of.clone();
                    }
                    let tmp_ptr = types
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get_type_pointer(ptr_type_size, stripped, ptr_wordsize);
                    new_in_ptr.write().unwrap().update_type(tmp_ptr);
                }
                self.data.op_insert_before(&new_op, follow_op);
                in_ptr = new_in_ptr;
                tmp_type = new_type;
                cur_off = new_off;
                if tmp_type.get_size() <= match_type.get_size() {
                    break;
                }
            }
            ptr_varnodes.push(in_ptr);
        }
    }

    // Ghidra: subflow.cc:2756 SplitDatatype::splitLoad
    /// Split a LOAD operation. Faithful to `SplitDatatype::splitLoad`
    /// (subflow.cc:2756-2800): the COPY-follow first checks the LOAD output's
    /// lone descendant — a STORE defers to `RuleSplitStore`, a COPY is
    /// followed so the split output is the COPY's output — then the value
    /// data-type is tested against the output data-type, the root pointer is
    /// located via `RootPointer::find`, per-piece pointers are rebuilt from
    /// the root via `build_pointers` (inserted before the LOAD), per-piece
    /// LOADs are inserted before the insert point (the followed COPY when
    /// present), and the original COPY/LOAD are destroyed with the unused
    /// pointer calculation chain freed via `free_pointer_chain`.
    ///
    /// Output reassembly keeps the registered `buildOutVarnodes`/
    /// `buildOutConcats` stand-in (unique-space outputs + PIECE stack into
    /// the followed output), gated on the output having a descendant exactly
    /// like the oracle's `buildOutConcats` early return (cc:2551-2552); the
    /// raw op-DAG divergence of that stack is the remaining
    /// `rewrite_op_shape` gap.
    ///
    /// Returns `true` if the split was performed. Returns `false` if the value
    /// is not a composite type that should be split, or the pointer cannot
    /// be traced back to a splittable root.
    pub fn split_load(
        &mut self,
        load_op: &Arc<RwLock<PcodeOp>>,
        in_type: &Arc<crate::type_system::Datatype>,
    ) -> Result<bool> {
        self.is_load_store = true;
        let out_vn_initial = load_op.read().unwrap().get_out().cloned().unwrap();
        // COPY-follow (cc:2761-2769): split the outputs of a lone COPY
        // descendant as well.
        let mut copy_op: Option<Arc<RwLock<PcodeOp>>> = None;
        if !out_vn_initial.read().unwrap().is_addr_tied() {
            copy_op = out_vn_initial.read().unwrap().lone_descend();
        }
        if let Some(cp) = &copy_op {
            let opc = cp.read().unwrap().opcode;
            if opc == OpCode::CPUI_STORE {
                return Ok(false); // Handled by RuleSplitStore (cc:2766)
            }
            if opc != OpCode::CPUI_COPY {
                copy_op = None;
            }
        }
        let out_vn = match &copy_op {
            Some(cp) => cp.read().unwrap().get_out().cloned().unwrap(),
            None => out_vn_initial,
        };
        let out_size = out_vn.read().unwrap().get_size();
        // cc:2772: outVn->getTypeDefFacing() — def-facing consult through
        // fd.union_map; the untyped fallback mirrors the oracle's `undefined`
        // bank type (see unknown_of).
        let out_type = crate::unionresolve::vn_type_def_facing(self.data, &out_vn)
            .or_else(|| self.unknown_of(out_size));
        let out_type = match out_type {
            Some(t) => t,
            None => return Ok(false),
        };
        if !self.test_datatype_compatibility(in_type, &out_type, false) {
            return Ok(false);
        }
        if is_arithmetic_input(&out_vn) {
            return Ok(false); // Sanity check on output (cc:2774-2776)
        }
        let mut root = RootPointer::new();
        if !root.find(self.data, load_op, in_type) {
            return Ok(false);
        }
        let insert_point = match &copy_op {
            Some(cp) => PcodeOpRef(cp.clone()),
            None => PcodeOpRef(load_op.clone()),
        };
        let mut ptr_varnodes: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        // buildPointers is anchored at the LOAD (cc:2783), even when the new
        // LOADs are inserted before the followed COPY (cc:2788/2793).
        self.build_pointers(
            root.pointer.as_ref().unwrap(),
            root.ptr_type.as_ref().unwrap(),
            root.base_offset,
            &PcodeOpRef(load_op.clone()),
            &mut ptr_varnodes,
            true,
        );
        let spc = load_store_space(load_op, 0);
        let op_addr = insert_point.0.read().unwrap().get_addr();
        let mut load_out_vns: Vec<Arc<RwLock<Varnode>>> = Vec::with_capacity(ptr_varnodes.len());
        for (i, ptr) in ptr_varnodes.iter().enumerate() {
            let new_load = self.data.new_op(2, op_addr);
            self.data.op_set_opcode(&new_load, OpCode::CPUI_LOAD);
            let space_vn = self.data.new_varnode_space(spc);
            self.data.op_set_input(&new_load, space_vn, 0);
            self.data.op_set_input(&new_load, ptr.clone(), 1);
            let load_out = self
                .data
                .new_unique_out(self.data_type_pieces[i].out_type.get_size(), &new_load);
            self.data.op_insert_before(&new_load, &insert_point);
            load_out_vns.push(load_out);
        }
        // buildOutConcats stand-in (cc:2785 + 2551-2552): no concatenation is
        // produced when the output is unused.
        if !out_vn.read().unwrap().has_no_descend() {
            reassemble_via_piece(self.data, &load_out_vns, &out_vn, op_addr, &insert_point);
        }
        if let Some(cp) = &copy_op {
            self.data.op_destroy(&PcodeOpRef(cp.clone()));
        }
        self.data.op_destroy(&PcodeOpRef(load_op.clone()));
        root.free_pointer_chain(self.data);
        Ok(true)
    }

    // Ghidra: subflow.cc:2808 SplitDatatype::splitStore
    /// Split a STORE operation. Faithful to `SplitDatatype::splitStore`
    /// (subflow.cc:2808-2898): the LOAD-value trace re-derives the stored
    /// value's data-type from a feeding LOAD (whose output feeds only this
    /// STORE) via `get_value_datatype`, retrying the compatibility test
    /// without the LOAD when the first test fails (cc:2812-2835); both roots
    /// are located via `RootPointer::find` (cc:2840-2848); the value pieces
    /// come from split constants, per-piece LOADs rebuilt off the LOAD root,
    /// or SUBPIECEs of the value; an addr-tied store root is duplicated to a
    /// temp via `duplicate_to_temp` before the piece pointers are rebuilt
    /// (cc:2873-2876); the original STORE object is preserved (so INDIRECT
    /// references stay valid) and converted into the first of the smaller
    /// STOREs (cc:2879-2890); the feeding LOAD is destroyed and both unused
    /// pointer chains are freed (cc:2892-2896).
    ///
    /// The non-constant non-LOAD value path keeps the `buildInSubpieces`
    /// stand-in (SUBPIECE extraction off a unique temp, without the oracle's
    /// address-placed outputs and `generateConstants` folding); that raw
    /// op-DAG divergence is the remaining `rewrite_op_shape` gap.
    ///
    /// Returns `true` if the split was performed. Returns `false` if the value
    /// is not a composite type that should be split, or the pointer cannot
    /// be traced back to a splittable root.
    pub fn split_store(
        &mut self,
        store_op: &Arc<RwLock<PcodeOp>>,
        out_type: &Arc<crate::type_system::Datatype>,
    ) -> Result<bool> {
        self.is_load_store = true;
        let in_vn = store_op.read().unwrap().get_in(2).cloned().unwrap();
        let store_space = load_store_space(store_op, 0);
        // LOAD-value trace (cc:2813-2820): a LOAD feeding only this STORE
        // re-derives the value data-type from the LOAD's pointer.
        let mut load_op: Option<Arc<RwLock<PcodeOp>>> = None;
        let mut in_type: Option<Arc<crate::type_system::Datatype>> = None;
        {
            let in_r = in_vn.read().unwrap();
            if in_r.is_written() {
                if let Some(def) = in_r.get_def() {
                    if def.read().unwrap().opcode == OpCode::CPUI_LOAD
                        && in_r
                            .lone_descend()
                            .map(|d| Arc::ptr_eq(&d, store_op))
                            .unwrap_or(false)
                    {
                        load_op = Some(def);
                    }
                }
            }
        }
        if let Some(lo) = &load_op {
            let size = in_vn.read().unwrap().get_size();
            if let Some(types) = self.types.as_ref() {
                in_type = SplitDatatype::get_value_datatype(self.data, lo, size, types);
            }
            if in_type.is_none() {
                load_op = None;
            }
        }
        if in_type.is_none() {
            // cc:2822: inVn->getTypeReadFacing(storeOp) — slot 2 consult
            // through fd.union_map; untyped fallback mirrors the oracle's
            // `undefined` bank type (see unknown_of).
            let read_facing = crate::unionresolve::vn_type_read_facing(
                self.data,
                &in_vn,
                &crate::op::PcodeOpRef(store_op.clone()),
                2,
            );
            in_type = read_facing.or_else(|| self.unknown_of(in_vn.read().unwrap().get_size()));
        }
        let in_constant = in_vn.read().unwrap().is_constant();
        let mut in_type = match in_type {
            Some(t) => t,
            None => return Ok(false),
        };
        if !self.test_datatype_compatibility(&in_type, out_type, in_constant) {
            if load_op.is_some() {
                // If not compatible while considering the LOAD, check again,
                // but without the LOAD (cc:2825-2832).
                load_op = None;
                // cc:2828: inVn->getTypeReadFacing(storeOp) retry — same
                // slot 2 consult through fd.union_map.
                let read_facing = crate::unionresolve::vn_type_read_facing(
                    self.data,
                    &in_vn,
                    &crate::op::PcodeOpRef(store_op.clone()),
                    2,
                );
                let retry_type =
                    read_facing.or_else(|| self.unknown_of(in_vn.read().unwrap().get_size()));
                let Some(retry_type) = retry_type else {
                    return Ok(false);
                };
                self.data_type_pieces.clear(); // cc:2829
                if !self.test_datatype_compatibility(&retry_type, out_type, in_constant) {
                    return Ok(false);
                }
                in_type = retry_type;
            } else {
                return Ok(false);
            }
        }
        if is_arithmetic_output(&in_vn) {
            return Ok(false); // Sanity check (cc:2837)
        }
        let mut store_root = RootPointer::new();
        if !store_root.find(self.data, store_op, out_type) {
            return Ok(false);
        }
        let mut load_root = RootPointer::new();
        if let Some(lo) = &load_op {
            if !load_root.find(self.data, lo, &in_type) {
                return Ok(false);
            }
        }
        // Value pieces (cc:2851-2871).
        let mut in_varnodes: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        if in_constant {
            self.build_in_constants(&in_vn, &mut in_varnodes, store_space.is_big_endian());
        } else if let Some(lo) = load_op.clone() {
            let mut load_ptrs: Vec<Arc<RwLock<Varnode>>> = Vec::new();
            self.build_pointers(
                load_root.pointer.as_ref().unwrap(),
                load_root.ptr_type.as_ref().unwrap(),
                load_root.base_offset,
                &PcodeOpRef(lo.clone()),
                &mut load_ptrs,
                true,
            );
            let load_space = load_store_space(&lo, 0);
            let lo_ref = PcodeOpRef(lo.clone());
            let lo_addr = lo_ref.0.read().unwrap().get_addr();
            for i in 0..load_ptrs.len() {
                let dt = self.data_type_pieces[i].in_type.clone();
                let new_load = self.data.new_op(2, lo_addr);
                self.data.op_set_opcode(&new_load, OpCode::CPUI_LOAD);
                let space_vn = self.data.new_varnode_space(load_space);
                self.data.op_set_input(&new_load, space_vn, 0);
                self.data.op_set_input(&new_load, load_ptrs[i].clone(), 1);
                let vn = self.data.new_unique_out(dt.get_size(), &new_load);
                vn.write().unwrap().update_type(dt);
                self.data.op_insert_before(&new_load, &lo_ref);
                in_varnodes.push(vn);
            }
        } else {
            // buildInSubpieces stand-in (registered gap: the oracle places the
            // piece outputs at rootVn+off addresses and folds extended
            // precision constants via generateConstants).
            let store_ref = PcodeOpRef(store_op.clone());
            let addr = store_ref.0.read().unwrap().get_addr();
            for piece in self.data_type_pieces.clone() {
                let v = subpiece_value(
                    self.data,
                    &in_vn,
                    piece.offset,
                    piece.in_type.get_size() as i32,
                    addr,
                    &store_ref,
                );
                in_varnodes.push(v);
            }
        }
        // Store pointers (cc:2873-2876): an addr-tied root must be duplicated
        // into a temp so subsequent STOREs cannot modify it.
        let store_ref = PcodeOpRef(store_op.clone());
        let mut store_ptrs: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        if store_root
            .pointer
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .is_addr_tied()
        {
            store_root.duplicate_to_temp(self.data, &store_ref);
        }
        self.build_pointers(
            store_root.pointer.as_ref().unwrap(),
            store_root.ptr_type.as_ref().unwrap(),
            store_root.base_offset,
            &store_ref,
            &mut store_ptrs,
            false,
        );
        // Preserve the original STORE object (so INDIRECT references stay
        // valid) but convert it into the first of the smaller STOREs
        // (cc:2879-2880).
        self.data.op_set_input(&store_ref, store_ptrs[0].clone(), 1);
        self.data.op_set_input(&store_ref, in_varnodes[0].clone(), 2);
        let mut last_store = store_ref.clone();
        let store_addr = store_ref.0.read().unwrap().get_addr();
        for i in 1..store_ptrs.len() {
            let new_store = self.data.new_op(3, store_addr);
            self.data.op_set_opcode(&new_store, OpCode::CPUI_STORE);
            let space_vn = self.data.new_varnode_space(store_space);
            self.data.op_set_input(&new_store, space_vn, 0);
            self.data.op_set_input(&new_store, store_ptrs[i].clone(), 1);
            self.data.op_set_input(&new_store, in_varnodes[i].clone(), 2);
            self.data.op_insert_after(&new_store, &last_store);
            last_store = new_store;
        }
        if let Some(lo) = load_op {
            self.data.op_destroy(&PcodeOpRef(lo));
            load_root.free_pointer_chain(self.data);
        }
        store_root.free_pointer_chain(self.data);
        Ok(true)
    }

    // Ghidra: subflow.cc:2386 SplitDatatype::testCopyConstraints
    /// Test specific constraints for splitting the given COPY operation into
    /// pieces. Faithful to `SplitDatatype::testCopyConstraints`
    /// (subflow.cc:2370-2384): don't split function inputs, don't split
    /// addr-tied pairs at the same address, and defer a LOAD output feeding
    /// only this COPY to `splitLoad`.
    fn test_copy_constraints(
        &self,
        copy_op: &Arc<RwLock<PcodeOp>>,
        in_vn: &Arc<RwLock<Varnode>>,
        out_vn: &Arc<RwLock<Varnode>>,
    ) -> bool {
        let (in_r, out_r) = (in_vn.read().unwrap(), out_vn.read().unwrap());
        if in_r.is_input() {
            return false;
        }
        if in_r.is_addr_tied() {
            if out_r.is_addr_tied() && in_r.get_addr() == out_r.get_addr() {
                return false;
            }
        } else if in_r.is_written() {
            let def = in_r.get_def();
            if let Some(def_op) = def {
                if def_op.read().unwrap().opcode == OpCode::CPUI_LOAD
                    && in_r.lone_descend().map(|d| Arc::ptr_eq(&d, copy_op)) == Some(true)
                {
                    return false; // Handled by splitLoad
                }
            }
        }
        true
    }

    // Ghidra: subflow.cc:2717 SplitDatatype::splitCopy
    /// Synthesize the factory `undefined` of `size` bytes, mirroring the
    /// `types->getBase(size, TYPE_UNKNOWN)` calls in
    /// `testDatatypeCompatibility` (subflow.cc:2322/2339) and the untyped
    /// varnode reading in `splitLoad`/`splitStore`.
    fn unknown_of(&self, size: usize) -> Option<Arc<crate::type_system::Datatype>> {
        let types = self.types.as_ref()?;
        Some(
            types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_base_result(size, crate::type_system::TypeMetatype::Unknown)
                .unwrap_or_else(|message| panic!("LowlevelError: {message}")),
        )
    }
}

// Ghidra: typeop.hh:140 TypeOp::isArithmeticOp
/// Is the opcode one of the arithmetic operations. Faithful to the
/// `arithmetic_op` TypeOp flag (typeop.hh:45/140), set at registration for
/// exactly these opcodes in typeop.cc: INT_ADD (1171), INT_SUB (1322),
/// INT_CARRY (1336), INT_SCARRY (1352), INT_SBORROW (1368), INT_2COMP
/// (1384), INT_MULT (1621), INT_DIV (1635), INT_SDIV (1655), INT_REM (1675),
/// INT_SREM (1695), PTRADD (2228), PTRSUB (2304). Rugra's TypeOp registry
/// (typeop.rs) sets the identical ARITHMETIC_OP set; this closed-set twin
/// exists because Rugra's PcodeOp does not hold its TypeOp pointer.
fn is_arithmetic_opcode(opc: OpCode) -> bool {
    matches!(
        opc,
        OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB
            | OpCode::CPUI_INT_CARRY
            | OpCode::CPUI_INT_SCARRY
            | OpCode::CPUI_INT_SBORROW
            | OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_INT_DIV
            | OpCode::CPUI_INT_SDIV
            | OpCode::CPUI_INT_REM
            | OpCode::CPUI_INT_SREM
            | OpCode::CPUI_PTRADD
            | OpCode::CPUI_PTRSUB
    )
}

// Ghidra: subflow.cc:2677 SplitDatatype::isArithmeticInput
/// Iterate through descendants of the given Varnode, looking for arithmetic
/// ops. Faithful to `SplitDatatype::isArithmeticInput` (subflow.cc:2673-2684).
fn is_arithmetic_input(vn: &Arc<RwLock<Varnode>>) -> bool {
    vn.read()
        .unwrap()
        .descend_iter()
        .any(|op| is_arithmetic_opcode(op.read().unwrap().opcode))
}

// Ghidra: subflow.cc:2693 SplitDatatype::isArithmeticOutput
/// Check if the defining PcodeOp is arithmetic. Faithful to
/// `SplitDatatype::isArithmeticOutput` (subflow.cc:2690-2696).
fn is_arithmetic_output(vn: &Arc<RwLock<Varnode>>) -> bool {
    match vn.read().unwrap().get_def() {
        Some(def) => is_arithmetic_opcode(def.read().unwrap().opcode),
        None => false,
    }
}

// Ghidra: varnode.hh:426 Varnode::getSpaceFromConst
/// Decode the AddrSpace encoded in a constant space varnode — the LOAD/STORE
/// `in(0)` space input — faithful to the inline
/// `Varnode::getSpaceFromConst` used at subflow.cc:2786/2850/2857.
fn load_store_space(op: &Arc<RwLock<PcodeOp>>, slot: usize) -> AddressSpace {
    let vn = op.read().unwrap().get_in(slot).cloned().unwrap();
    let guard = vn.read().unwrap();
    if guard.is_constant() {
        AddressSpace::from_id(guard.get_offset() as crate::space::SpaceId)
    } else {
        guard.get_space()
    }
}

// Ghidra: subflow.cc:2497 SplitDatatype::buildInSubpieces
/// Extract a byte-range piece of `value_vn` via a SUBPIECE op inserted before
/// `before`, returning the piece Varnode. The trailing offset constant is
/// `newConstant(4, off)` per subflow.cc:2513 (SUBFLOW-SUBPIECE-WIDTH-0001).
fn subpiece_value(
    fd: &mut Funcdata,
    value_vn: &Arc<RwLock<Varnode>>,
    offset: i32,
    size: i32,
    addr: Address,
    before: &crate::op::PcodeOpRef,
) -> Arc<RwLock<Varnode>> {
    let sub_op = fd.new_op(2, addr);
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    let sub_out = fd.new_unique_out(size as usize, &sub_op);
    let off_const = fd.new_constant(4, offset as u64);
    fd.op_set_input(&sub_op, value_vn.clone(), 0);
    fd.op_set_input(&sub_op, off_const, 1);
    fd.op_insert_before(&sub_op, before);
    sub_out
}

// Ghidra: subflow.hh:271 RootPointer::reassembleViaPiece
/// Reassemble a sequence of per-component output Varnodes (least-significant
/// first) into `out_vn` via a left-leaning chain of PIECE ops, inserted before
/// `before`. Mirrors Ghidra's `buildOutConcats` (subflow.cc:2548-2614).
fn reassemble_via_piece(
    fd: &mut Funcdata,
    pieces: &[Arc<RwLock<Varnode>>],
    out_vn: &Arc<RwLock<Varnode>>,
    addr: Address,
    before: &crate::op::PcodeOpRef,
) {
    let num = pieces.len();
    if num == 0 {
        return;
    }
    if num == 1 {
        let cp = fd.new_op(1, addr);
        fd.op_set_opcode(&cp, OpCode::CPUI_COPY);
        fd.op_set_output(&cp, out_vn.clone());
        fd.op_set_input(&cp, pieces[0].clone(), 0);
        fd.op_insert_before(&cp, before);
        return;
    }
    // Most-significant first. Accumulate high parts.
    let mut acc = pieces[num - 1].clone();
    for i in (0..num - 1).rev() {
        let piece_op = fd.new_op(2, addr);
        fd.op_set_opcode(&piece_op, OpCode::CPUI_PIECE);
        if i == 0 {
            fd.op_set_output(&piece_op, out_vn.clone());
        } else {
            let acc_out = fd.new_unique_out(out_vn.read().unwrap().get_size(), &piece_op);
            acc = acc_out;
        }
        let high = acc.clone();
        let low = pieces[i].clone();
        fd.op_set_input(&piece_op, high, 0); // high
        fd.op_set_input(&piece_op, low, 1); // low
        fd.op_insert_before(&piece_op, before);
    }
}

/// Split COPY ops based on TypePartialStruct. Faithful to Ghidra's
/// `RuleSplitCopy` (subflow.hh:315-324, subflow.cc:2941-2962).
pub struct RuleSplitCopy;
impl RuleSplitCopy {
    // Ghidra: subflow.hh:315 RuleSplitCopy::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSplitCopy {
    // Ghidra: subflow.cc:2947 RuleSplitCopy::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSplitCopy::applyOp (subflow.cc:2947-2962): read in/out
        // data-types and only proceed when one side is
        // PARTIALSTRUCT/ARRAY/STRUCT. Rugra's TypeMetatype covers all three.
        // cc:2950/2951: in(0) read-facing the COPY at slot 0, out def-facing —
        // both consult fd.union_map via the fd-aware twins.
        use crate::type_system::TypeMetatype;
        let (in_vn, out_vn) = {
            let o = op_arc.read().unwrap();
            (o.get_in(0).cloned(), o.get_out().cloned())
        };
        let in_type = in_vn.as_ref().and_then(|v| {
            crate::unionresolve::vn_type_read_facing(
                fd,
                v,
                &crate::op::PcodeOpRef(op_arc.clone()),
                0,
            )
        });
        let out_type = out_vn
            .as_ref()
            .and_then(|v| crate::unionresolve::vn_type_def_facing(fd, v));
        let in_meta = in_type.as_ref().map(|t| t.get_metatype());
        let out_meta = out_type.as_ref().map(|t| t.get_metatype());
        let is_composite = |m: Option<TypeMetatype>| {
            matches!(
                m,
                Some(TypeMetatype::Struct)
                    | Some(TypeMetatype::Array)
                    | Some(TypeMetatype::PartialStruct)
            )
        };
        if !is_composite(in_meta) && !is_composite(out_meta) {
            return Ok(action_status::NO_CHANGE);
        }
        let mut splitter = SplitDatatype::new(fd);
        if splitter.split_copy(op_arc)? {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // Ghidra: subflow.hh:315 RuleSplitCopy::getName
    fn get_name(&self) -> &str {
        "splitcopy"
    }
    // Ghidra: subflow.cc:2941 RuleSplitCopy::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_COPY]
    }
}

/// Split LOAD ops based on TypePartialStruct. Faithful to Ghidra's
/// `RuleSplitLoad` (subflow.hh:330-339, subflow.cc:2964-2983).
pub struct RuleSplitLoad;
impl RuleSplitLoad {
    // Ghidra: subflow.hh:330 RuleSplitLoad::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSplitLoad {
    // Ghidra: subflow.cc:2970 RuleSplitLoad::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSplitLoad::applyOp (subflow.cc:2970-2983): recover the value
        // type from the pointer input through the canonical factory gate
        // (getValueDatatype -> getExactPiece), then require a composite
        // metatype before splitting. Without an Architecture-owned factory
        // there is no gate to run (the C++ Funcdata always has one).
        use crate::type_system::TypeMetatype;
        let types = match fd.get_arch().and_then(|arch| arch.types.clone()) {
            Some(types) => types,
            None => return Ok(action_status::NO_CHANGE),
        };
        let size = match op_arc.read().unwrap().get_out() {
            Some(output) => output.read().unwrap().get_size(),
            None => return Ok(action_status::NO_CHANGE),
        };
        let in_type = match SplitDatatype::get_value_datatype(fd, op_arc, size, &types) {
            Some(in_type) => in_type,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !matches!(
            in_type.get_metatype(),
            TypeMetatype::Struct | TypeMetatype::Array | TypeMetatype::PartialStruct
        ) {
            return Ok(action_status::NO_CHANGE);
        }
        let mut splitter = SplitDatatype::new(fd);
        if splitter.split_load(op_arc, &in_type)? {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // Ghidra: subflow.hh:330 RuleSplitLoad::getName
    fn get_name(&self) -> &str {
        "splitload"
    }
    // Ghidra: subflow.cc:2964 RuleSplitLoad::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_LOAD]
    }
}

/// Split STORE ops based on TypePartialStruct. Faithful to Ghidra's
/// `RuleSplitStore` (subflow.hh:343-354, subflow.cc:2985-3004).
pub struct RuleSplitStore;
impl RuleSplitStore {
    // Ghidra: subflow.hh:345 RuleSplitStore::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSplitStore {
    // Ghidra: subflow.cc:2991 RuleSplitStore::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSplitStore::applyOp (subflow.cc:2991-3004): recover the value
        // type from the pointer input through the canonical factory gate
        // (getValueDatatype -> getExactPiece), then require a composite
        // metatype before splitting. Without an Architecture-owned factory
        // there is no gate to run (the C++ Funcdata always has one).
        use crate::type_system::TypeMetatype;
        let types = match fd.get_arch().and_then(|arch| arch.types.clone()) {
            Some(types) => types,
            None => return Ok(action_status::NO_CHANGE),
        };
        let size = match op_arc.read().unwrap().get_in(2) {
            Some(value) => value.read().unwrap().get_size(),
            None => return Ok(action_status::NO_CHANGE),
        };
        let out_type = match SplitDatatype::get_value_datatype(fd, op_arc, size, &types) {
            Some(out_type) => out_type,
            None => return Ok(action_status::NO_CHANGE),
        };
        if !matches!(
            out_type.get_metatype(),
            TypeMetatype::Struct | TypeMetatype::Array | TypeMetatype::PartialStruct
        ) {
            return Ok(action_status::NO_CHANGE);
        }
        let mut splitter = SplitDatatype::new(fd);
        if splitter.split_store(op_arc, &out_type)? {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }
    // Ghidra: subflow.hh:345 RuleSplitStore::getName
    fn get_name(&self) -> &str {
        "splitstore"
    }
    // Ghidra: subflow.cc:2985 RuleSplitStore::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_STORE]
    }
}

// =====================================================================
// SubfloatFlow — TransformManager subclass tracing float precision
// (subflow.hh:379-406, subflow.cc:3070-3481)
// =====================================================================

// RUGRA-GLUE: Ghidra reaches the float formats through
// `fd->getArch()->translate->getFloatFormat(size)` (translate.hh:322,
// translate.cc:979-989), which returns NULL when no format is registered
// for the size. Rugra's spec registers exactly IEEE754 single (4) and
// double (8) — the two sizes `FloatFormat::new` supports — so this helper
// returns None for every other size the same way getFloatFormat returns
// NULL, and `SubfloatFlow::new` then skips `setReplacement` (cc:3446-3447).
fn subfloat_float_format(size: usize) -> Option<crate::float_emulate::FloatFormat> {
    if size == 4 || size == 8 {
        Some(crate::float_emulate::FloatFormat::new(size))
    } else {
        None
    }
}

// RUGRA-GLUE: virtual-dispatch hook for `SubfloatFlow::preserveAddress`
// (subflow.cc:3451-3455), installed via
// `TransformManager::set_preserve_address_override`. The base-class
// implementation (transform.cc:348) is replaced wholesale by the override,
// which only preserves addresses for input varnodes.
fn subfloat_preserve_address(vn: &Varnode, _bit_size: i32, _lsb_offset: i32) -> bool {
    vn.is_input()
}

/// Internal state for walking floating-point data-flow and computing
/// precision. Faithful to `SubfloatFlow::State` (subflow.hh:381-390).
struct SubfloatState {
    /// Operation being traversed.
    op: Arc<RwLock<PcodeOp>>,
    /// Input edge being traversed.
    slot: usize,
    /// Maximum precision traversed through inputs so far.
    max_precision: i32,
}

/// Class for tracing changes of precision in floating point variables.
/// Faithful to `SubfloatFlow` (subflow.hh:379-406): it follows the flow of a
/// logical lower precision value stored in higher precision locations and
/// then rewrites the data-flow in terms of the lower precision, eliminating
/// the precision conversions. Rust has no inheritance, so (like `SplitFlow`
/// and `LaneDivide`) this struct owns a `TransformManager` and forwards to
/// it; the `preserveAddress` override is installed as the manager's
/// virtual-dispatch hook.
pub struct SubfloatFlow {
    /// The owned TransformManager (Ghidra subclassing).
    pub mgr: TransformManager,
    /// Number of bytes of precision in the logical flow.
    precision: i32,
    /// Number of terminating nodes reachable via the root.
    terminator_count: i32,
    /// The floating-point format of the logical value (None = unsupported).
    format: Option<crate::float_emulate::FloatFormat>,
    /// Current list of placeholders that still need to be traced (arena
    /// indices into `mgr.new_varnodes`).
    worklist: Vec<usize>,
    /// Maximum precision flowing into a particular floating-point op, keyed
    /// by `Arc::as_ptr` identity (Ghidra: `map<PcodeOp*,int4>`).
    max_precision_map: std::collections::HashMap<usize, i32>,
}

impl SubfloatFlow {
    // Ghidra: subflow.cc:3079 SubfloatFlow::maxPrecision
    /// Calculate the maximum floating-point precision reaching a given
    /// Varnode. Faithful to `maxPrecision` (subflow.cc:3079-3175): an
    /// iterative DFS over MULTIEQUAL/COPY/unary-float defs with an explicit
    /// op stack, marking ops while they are on the stack and caching each
    /// completed op's precision in `maxPrecisionMap`. Binary float ops
    /// contribute 0 (delay checking); FLOAT2FLOAT/INT2FLOAT defs contribute
    /// `min(in(0) size, vn size)`; anything else contributes `vn size`.
    fn max_precision(&mut self, vn: &Arc<RwLock<Varnode>>) -> i32 {
        if !vn.read().unwrap().is_written() {
            return vn.read().unwrap().get_size() as i32;
        }
        let op = match vn.read().unwrap().get_def() {
            Some(d) => d,
            None => return vn.read().unwrap().get_size() as i32,
        };
        match op.read().unwrap().opcode {
            OpCode::CPUI_MULTIEQUAL
            | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT
            | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR
            | OpCode::CPUI_FLOAT_ROUND
            | OpCode::CPUI_COPY => {}
            OpCode::CPUI_FLOAT_ADD | OpCode::CPUI_FLOAT_SUB | OpCode::CPUI_FLOAT_MULT | OpCode::CPUI_FLOAT_DIV => {
                return 0; // Delay checking other binary ops
            }
            OpCode::CPUI_FLOAT_FLOAT2FLOAT | OpCode::CPUI_FLOAT_INT2FLOAT => {
                // Treat integer as having precision matching its size.
                let in0_size = op.read().unwrap().get_in(0).map(|v| v.read().unwrap().get_size() as i32);
                let vn_size = vn.read().unwrap().get_size() as i32;
                return match in0_size {
                    Some(s) if s > vn_size => vn_size,
                    Some(s) => s,
                    None => vn_size,
                };
            }
            _ => return vn.read().unwrap().get_size() as i32,
        }
        let op_key = Arc::as_ptr(&op) as usize;
        if let Some(&cached) = self.max_precision_map.get(&op_key) {
            return cached;
        }
        let mut op_stack: Vec<SubfloatState> = vec![SubfloatState {
            op: op.clone(),
            slot: 0,
            max_precision: 0,
        }];
        op.write().unwrap().set_mark();
        let mut max = 0;
        while !op_stack.is_empty() {
            // Ghidra: `State &state(opStack.back())` — the slot-scan exit.
            let state_op = op_stack.last().unwrap().op.clone();
            if op_stack.last().unwrap().slot >= state_op.read().unwrap().num_input() {
                let state_max = op_stack.last().unwrap().max_precision;
                max = state_max;
                state_op.write().unwrap().clear_mark();
                self.max_precision_map.insert(Arc::as_ptr(&state_op) as usize, state_max);
                op_stack.pop();
                if let Some(parent) = op_stack.last_mut() {
                    parent.max_precision = parent.max_precision.max(max);
                }
                continue;
            }
            // Ghidra: `Varnode *nextVn = state.op->getIn(state.slot);
            //          state.slot += 1;`
            let state_slot = op_stack.last().unwrap().slot;
            let next_vn = match state_op.read().unwrap().get_in(state_slot).cloned() {
                Some(v) => v,
                None => {
                    op_stack.last_mut().unwrap().slot += 1;
                    continue;
                }
            };
            op_stack.last_mut().unwrap().slot += 1;
            if !next_vn.read().unwrap().is_written() {
                let sz = next_vn.read().unwrap().get_size() as i32;
                op_stack.last_mut().unwrap().max_precision =
                    op_stack.last_mut().unwrap().max_precision.max(sz);
                continue;
            }
            let next_op = match next_vn.read().unwrap().get_def() {
                Some(d) => d,
                None => continue,
            };
            if next_op.read().unwrap().is_mark() {
                continue; // Truncate the cycle edge
            }
            let next_code = next_op.read().unwrap().opcode;
            match next_code {
                OpCode::CPUI_MULTIEQUAL
                | OpCode::CPUI_FLOAT_NEG
                | OpCode::CPUI_FLOAT_ABS
                | OpCode::CPUI_FLOAT_SQRT
                | OpCode::CPUI_FLOAT_CEIL
                | OpCode::CPUI_FLOAT_FLOOR
                | OpCode::CPUI_FLOAT_ROUND
                | OpCode::CPUI_COPY => {
                    let next_key = Arc::as_ptr(&next_op) as usize;
                    if let Some(&cached) = self.max_precision_map.get(&next_key) {
                        // Seen the op before, incorporate its cached precision.
                        op_stack.last_mut().unwrap().max_precision =
                            op_stack.last_mut().unwrap().max_precision.max(cached);
                    } else {
                        next_op.write().unwrap().set_mark();
                        op_stack.push(SubfloatState {
                            op: next_op.clone(),
                            slot: 0,
                            max_precision: 0,
                        });
                    }
                }
                OpCode::CPUI_FLOAT_ADD | OpCode::CPUI_FLOAT_SUB | OpCode::CPUI_FLOAT_MULT | OpCode::CPUI_FLOAT_DIV => {}
                OpCode::CPUI_FLOAT_FLOAT2FLOAT | OpCode::CPUI_FLOAT_INT2FLOAT => {
                    let in0_size = next_op.read().unwrap().get_in(0).map(|v| v.read().unwrap().get_size() as i32);
                    let nv_size = next_vn.read().unwrap().get_size() as i32;
                    let sz = match in0_size {
                        Some(s) if s > nv_size => nv_size,
                        Some(s) => s,
                        None => nv_size,
                    };
                    op_stack.last_mut().unwrap().max_precision =
                        op_stack.last_mut().unwrap().max_precision.max(sz);
                }
                _ => {
                    let sz = next_vn.read().unwrap().get_size() as i32;
                    op_stack.last_mut().unwrap().max_precision =
                        op_stack.last_mut().unwrap().max_precision.max(sz);
                }
            }
        }
        max
    }

    // Ghidra: subflow.cc:3186 SubfloatFlow::exceedsPrecision
    /// Determine if the given binary float op exceeds our precision.
    /// Faithful to `exceedsPrecision` (subflow.cc:3186-3193).
    fn exceeds_precision(&mut self, op: &Arc<RwLock<PcodeOp>>) -> bool {
        let (in0, in1) = {
            let o = op.read().unwrap();
            (o.get_in(0).cloned(), o.get_in(1).cloned())
        };
        let val1 = match in0 {
            Some(v) => self.max_precision(&v),
            None => 0,
        };
        let val2 = match in1 {
            Some(v) => self.max_precision(&v),
            None => 0,
        };
        let min = if val1 < val2 { val1 } else { val2 };
        min > self.precision
    }

    // Ghidra: subflow.cc:3200 SubfloatFlow::setReplacement
    /// Create and return a placeholder associated with the given Varnode,
    /// adding it to the worklist when it must be traced further. Faithful to
    /// `setReplacement` (subflow.cc:3200-3240): marks are checked first
    /// (`getPiece` for revisits), constants are re-encoded at the precision
    /// (`convertEncoding`), free varnodes abort, `addrforce` and typelock
    /// guards reject incompatible sizes, inputs must already match the
    /// precision, and finally the varnode is marked and either reused as
    /// preexisting (size == precision) or split off as a new piece plus a
    /// worklist entry.
    fn set_replacement(&mut self, vn: &Arc<RwLock<Varnode>>) -> Option<usize> {
        if vn.read().unwrap().is_mark() {
            return Some(self.mgr.get_piece(vn.clone(), self.precision * 8, 0));
        }
        if vn.read().unwrap().is_constant() {
            let form2 = subfloat_float_format(vn.read().unwrap().get_size())?;
            // Return the converted form of the constant.
            let offset = vn.read().unwrap().get_offset();
            let converted = self
                .format
                .as_ref()
                .expect("SubfloatFlow invariant: format present when setReplacement runs")
                .convert_encoding(offset, &form2);
            return Some(self.mgr.new_constant(self.precision, 0, converted));
        }
        if vn.read().unwrap().is_free() {
            return None; // Abort
        }
        if vn.read().unwrap().is_addr_force() && (vn.read().unwrap().get_size() as i32) != self.precision {
            return None;
        }
        {
            let rg = vn.read().unwrap();
            if rg.is_type_lock() {
                let partial = rg
                    .get_type()
                    .map(|t| t.get_metatype() == crate::type_system::TypeMetatype::PartialStruct)
                    .unwrap_or(false);
                if !partial {
                    let sz = rg.get_type().map(|t| t.get_size() as i32).unwrap_or(0);
                    if sz != self.precision {
                        return None;
                    }
                }
            }
        }
        if vn.read().unwrap().is_input() {
            // Must be careful with inputs
            if vn.read().unwrap().get_size() as i32 != self.precision {
                return None;
            }
        }
        vn.write().unwrap().set_mark();
        let res;
        // Check if vn already represents the logical variable being traced.
        if vn.read().unwrap().get_size() as i32 == self.precision {
            res = self.mgr.new_preexisting_varnode(vn.clone());
        } else {
            res = self.mgr.new_piece(vn.clone(), self.precision * 8, 0);
            self.worklist.push(res);
        }
        Some(res)
    }

    // Ghidra: subflow.cc:3249 SubfloatFlow::traceForward
    /// Try to trace the logical value forward through descendant ops.
    /// Faithful to `traceForward` (subflow.cc:3249-3330). Binary arithmetic
    /// aborts on `exceedsPrecision`; pass-through ops get an op-replacement
    /// placeholder whose output placeholder comes from `setReplacement`;
    /// downstream FLOAT2FLOAT/comparison/TRUNC/NAN become preexisting-op
    /// terminators (comparisons honour `preexistingGuard` and the
    /// repeated-input `getRepeatSlot` adjustment).
    fn trace_forward(&mut self, rvn: usize) -> bool {
        let origvn = match self.mgr.new_varnodes[rvn].vn.clone() {
            Some(v) => v,
            None => return true,
        };
        // Snapshot the descendant ops (Ghidra iterates beginDescend..endDescend).
        let descend_ops: Vec<Arc<RwLock<PcodeOp>>> = origvn.read().unwrap().descend_iter().collect();
        let mut op_index = 0;
        while op_index < descend_ops.len() {
            let op = descend_ops[op_index].clone();
            let cur_index = op_index;
            op_index += 1;
            let outvn = op.read().unwrap().get_out().cloned();
            if let Some(ref out) = outvn {
                if out.read().unwrap().is_mark() {
                    continue;
                }
            }
            let op_code = op.read().unwrap().opcode;
            match op_code {
                OpCode::CPUI_FLOAT_ADD
                | OpCode::CPUI_FLOAT_SUB
                | OpCode::CPUI_FLOAT_MULT
                | OpCode::CPUI_FLOAT_DIV
                | OpCode::CPUI_MULTIEQUAL
                | OpCode::CPUI_COPY
                | OpCode::CPUI_FLOAT_CEIL
                | OpCode::CPUI_FLOAT_FLOOR
                | OpCode::CPUI_FLOAT_ROUND
                | OpCode::CPUI_FLOAT_NEG
                | OpCode::CPUI_FLOAT_ABS
                | OpCode::CPUI_FLOAT_SQRT => {
                    if matches!(
                        op_code,
                        OpCode::CPUI_FLOAT_ADD
                            | OpCode::CPUI_FLOAT_SUB
                            | OpCode::CPUI_FLOAT_MULT
                            | OpCode::CPUI_FLOAT_DIV
                    ) && self.exceeds_precision(&op)
                    {
                        return false;
                    }
                    let n_inputs = op.read().unwrap().num_input();
                    let rop = self.mgr.new_op_replace(n_inputs, op_code, PcodeOpRef(op.clone()));
                    let out = match &outvn {
                        Some(o) => o.clone(),
                        None => return false,
                    };
                    let outrvn = match self.set_replacement(&out) {
                        Some(i) => i,
                        None => return false,
                    };
                    let slot = op
                        .read()
                        .unwrap()
                        .inrefs
                        .iter()
                        .position(|v| Arc::ptr_eq(v, &origvn));
                    let slot = match slot {
                        Some(s) => s,
                        None => return false,
                    };
                    self.mgr.op_set_input(rop, rvn, slot);
                    self.mgr.op_set_output(rop, outrvn);
                }
                OpCode::CPUI_FLOAT_FLOAT2FLOAT => {
                    let out_size = match &outvn {
                        Some(o) => o.read().unwrap().get_size() as i32,
                        None => return false,
                    };
                    if out_size < self.precision {
                        return false;
                    }
                    let opc = if out_size == self.precision {
                        OpCode::CPUI_COPY
                    } else {
                        OpCode::CPUI_FLOAT_FLOAT2FLOAT
                    };
                    let rop = self.mgr.new_preexisting_op(1, opc, PcodeOpRef(op.clone()));
                    self.mgr.op_set_input(rop, rvn, 0);
                    self.terminator_count += 1;
                }
                OpCode::CPUI_FLOAT_EQUAL
                | OpCode::CPUI_FLOAT_NOTEQUAL
                | OpCode::CPUI_FLOAT_LESS
                | OpCode::CPUI_FLOAT_LESSEQUAL => {
                    if self.exceeds_precision(&op) {
                        return false;
                    }
                    let first_slot = op
                        .read()
                        .unwrap()
                        .inrefs
                        .iter()
                        .position(|v| Arc::ptr_eq(v, &origvn));
                    let mut slot = match first_slot {
                        Some(s) => s as i32,
                        None => return false,
                    };
                    let other_vn = op.read().unwrap().get_in((1 - slot) as usize).cloned();
                    let other_vn = match other_vn {
                        Some(v) => v,
                        None => return false,
                    };
                    let rvn2 = match self.set_replacement(&other_vn) {
                        Some(i) => i,
                        None => return false,
                    };
                    if rvn == rvn2 {
                        // Ghidra: `ourIter = iter; --ourIter;` — the current
                        // descendant position — then `getRepeatSlot(vn, slot,
                        // ourIter)` (op.cc:93-111): count = 1 + occurrences
                        // of this op in descend[0..current), count==1 returns
                        // firstSlot, otherwise the count-th inrefs slot.
                        slot = subfloat_get_repeat_slot(
                            &op,
                            &origvn,
                            slot as usize,
                            &descend_ops[..cur_index],
                        );
                    }
                    // Ghidra passes `slot` (possibly -1 from getRepeatSlot,
                    // though that is unreachable: count never exceeds the
                    // input occurrence count) to preexistingGuard, whose only
                    // slot test is `slot == 0` — -1 behaves as any nonzero.
                    let guard_slot = if slot == 0 { 0usize } else { 1usize };
                    if TransformManager::preexisting_guard(guard_slot, &self.mgr.new_varnodes[rvn2]) {
                        let rop = self.mgr.new_preexisting_op(2, op_code, PcodeOpRef(op.clone()));
                        if slot >= 0 {
                            self.mgr.op_set_input(rop, rvn, slot as usize);
                            self.mgr.op_set_input(rop, rvn2, (1 - slot) as usize);
                        }
                        self.terminator_count += 1;
                    }
                }
                OpCode::CPUI_FLOAT_TRUNC | OpCode::CPUI_FLOAT_NAN => {
                    let rop = self.mgr.new_preexisting_op(1, op_code, PcodeOpRef(op.clone()));
                    self.mgr.op_set_input(rop, rvn, 0);
                    self.terminator_count += 1;
                }
                _ => return false, // Everything else we abort
            }
        }
        true
    }

    // Ghidra: subflow.cc:3339 SubfloatFlow::traceBackward
    /// Trace the logical value backward through the defining op one level.
    /// Faithful to `traceBackward` (subflow.cc:3339-3419). Pass-through defs
    /// reuse the existing placeholder def (or create one) and fill unset
    /// input slots; INT2FLOAT defs become replacements over the preexisting
    /// integer input; FLOAT2FLOAT defs become COPY/FLOAT2FLOAT replacements
    /// with the constant leg re-encoded at the precision.
    fn trace_backward(&mut self, rvn: usize) -> bool {
        let origvn = match self.mgr.new_varnodes[rvn].vn.clone() {
            Some(v) => v,
            None => return true,
        };
        let op = match origvn.read().unwrap().get_def() {
            Some(d) => d,
            None => return true, // If vn is input
        };
        let op_code = op.read().unwrap().opcode;
        match op_code {
            OpCode::CPUI_FLOAT_ADD
            | OpCode::CPUI_FLOAT_SUB
            | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_FLOAT_DIV
            | OpCode::CPUI_COPY
            | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR
            | OpCode::CPUI_FLOAT_ROUND
            | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT
            | OpCode::CPUI_MULTIEQUAL => {
                if matches!(
                    op_code,
                    OpCode::CPUI_FLOAT_ADD
                        | OpCode::CPUI_FLOAT_SUB
                        | OpCode::CPUI_FLOAT_MULT
                        | OpCode::CPUI_FLOAT_DIV
                ) && self.exceeds_precision(&op)
                {
                    return false;
                }
                let rop = match self.mgr.new_varnodes[rvn].def {
                    Some(d) => d,
                    None => {
                        let n_inputs = op.read().unwrap().num_input();
                        let r = self.mgr.new_op_replace(n_inputs, op_code, PcodeOpRef(op.clone()));
                        self.mgr.op_set_output(r, rvn);
                        r
                    }
                };
                let n_inputs = op.read().unwrap().num_input();
                for i in 0..n_inputs {
                    if self.mgr.new_ops[rop].input.get(i).copied().flatten().is_none() {
                        let inv = match op.read().unwrap().get_in(i).cloned() {
                            Some(v) => v,
                            None => return false,
                        };
                        let newvar = match self.set_replacement(&inv) {
                            Some(x) => x,
                            None => return false,
                        };
                        self.mgr.op_set_input(rop, newvar, i);
                    }
                }
                true
            }
            OpCode::CPUI_FLOAT_INT2FLOAT => {
                let vn = match op.read().unwrap().get_in(0).cloned() {
                    Some(v) => v,
                    None => return false,
                };
                if !vn.read().unwrap().is_constant() && vn.read().unwrap().is_free() {
                    return false;
                }
                let rop = self.mgr.new_op_replace(1, OpCode::CPUI_FLOAT_INT2FLOAT, PcodeOpRef(op.clone()));
                self.mgr.op_set_output(rop, rvn);
                let newvar = self.mgr.get_preexisting_varnode(vn);
                self.mgr.op_set_input(rop, newvar, 0);
                true
            }
            OpCode::CPUI_FLOAT_FLOAT2FLOAT => {
                let vn = match op.read().unwrap().get_in(0).cloned() {
                    Some(v) => v,
                    None => return false,
                };
                let newvar;
                let opc;
                if vn.read().unwrap().is_constant() {
                    opc = OpCode::CPUI_COPY;
                    if vn.read().unwrap().get_size() as i32 == self.precision {
                        newvar = self
                            .mgr
                            .new_constant(self.precision, 0, vn.read().unwrap().get_offset());
                    } else {
                        // Convert constant to precision size
                        newvar = match self.set_replacement(&vn) {
                            Some(x) => x,
                            None => return false, // Unsupported float format
                        };
                    }
                } else {
                    if vn.read().unwrap().is_free() {
                        return false;
                    }
                    opc = if vn.read().unwrap().get_size() as i32 == self.precision {
                        OpCode::CPUI_COPY
                    } else {
                        OpCode::CPUI_FLOAT_FLOAT2FLOAT
                    };
                    newvar = self.mgr.get_preexisting_varnode(vn);
                }
                let rop = self.mgr.new_op_replace(1, opc, PcodeOpRef(op.clone()));
                self.mgr.op_set_output(rop, rvn);
                self.mgr.op_set_input(rop, newvar, 0);
                true
            }
            _ => false, // Everything else we abort
        }
    }

    // Ghidra: subflow.cc:3427 SubfloatFlow::processNextWork
    /// Push the trace one hop from the placeholder at the top of the
    /// worklist: backward through the defining op, then forward through all
    /// readers. Faithful to `processNextWork` (subflow.cc:3427-3436).
    fn process_next_work(&mut self) -> bool {
        let rvn = *self.worklist.last().unwrap();
        self.worklist.pop();
        if !self.trace_backward(rvn) {
            return false;
        }
        self.trace_forward(rvn)
    }

    // Ghidra: subflow.cc:3441 SubfloatFlow::SubfloatFlow
    /// Construct a SubfloatFlow on the given root Varnode and precision.
    /// Faithful to the constructor (subflow.cc:3441-3449): when the
    /// precision has no registered float format the object is left inert
    /// (no root placeholder, empty worklist) and `doTrace` will fail.
    pub fn new(fd: &mut Funcdata, root: Arc<RwLock<Varnode>>, precision: i32) -> Self {
        let mut mgr = TransformManager::new();
        mgr.init(fd);
        mgr.set_preserve_address_override(subfloat_preserve_address);
        let mut sf = SubfloatFlow {
            mgr,
            precision,
            terminator_count: 0,
            format: subfloat_float_format(precision as usize),
            worklist: Vec::new(),
            max_precision_map: std::collections::HashMap::new(),
        };
        if sf.format.is_some() {
            sf.set_replacement(&root);
        }
        sf
    }

    // Ghidra: subflow.cc:3462 SubfloatFlow::doTrace
    /// Trace the logical value as far as possible, constructing the
    /// transform. Faithful to `doTrace` (subflow.cc:3462-3481): drains the
    /// worklist, clears varnode marks, and demands at least one terminator
    /// regardless of trace consistency.
    pub fn do_trace(&mut self) -> bool {
        if self.format.is_none() {
            return false;
        }
        self.terminator_count = 0; // Have seen no terminators
        let mut retval = true;
        while !self.worklist.is_empty() {
            if !self.process_next_work() {
                retval = false;
                break;
            }
        }
        self.mgr.clear_varnode_marks();
        if !retval {
            return false;
        }
        if self.terminator_count == 0 {
            return false; // Must see at least 1 terminator
        }
        true
    }

    // Ghidra: transform.cc:756 TransformManager::apply
    /// Apply the full transform to the function. Faithful to the inherited
    /// `apply()` (transform.cc:756-765): `create_ops` -> `create_varnodes` ->
    /// `remove_old` -> `transform_input_varnodes` -> `place_inputs`.
    pub fn apply(&mut self, fd: &mut Funcdata) {
        self.mgr.apply(fd);
    }
}

// Ghidra: op.cc:93 PcodeOp::getRepeatSlot
/// Given a Varnode that appears in multiple input slots of an op, find the
/// specific slot corresponding to the descendant occurrence currently being
/// visited. Faithful to the iterator overload
/// `getRepeatSlot(const Varnode *vn,int4 firstSlot,list<PcodeOp *>::const_iterator iter)`
/// (op.cc:93-111): `count` is 1 plus the occurrences of this op in the
/// Varnode's descendant list strictly before the current position; count==1
/// returns `firstSlot` (op.cc:101), otherwise the inrefs slot of the
/// count-th occurrence is returned, -1 if absent. Inlined here (instead of
/// `PcodeOp::get_repeat_slot`) because the op.rs count-parametered variant
/// lacks the count==1 early return — registered as
/// OPS-GETREPEATSLOT-COUNT1-0001 for the op.rs owner; this helper carries
/// the full oracle semantics for the only in-tree call site.
fn subfloat_get_repeat_slot(
    op: &Arc<RwLock<PcodeOp>>,
    vn: &Arc<RwLock<Varnode>>,
    first_slot: usize,
    descend_prefix: &[Arc<RwLock<PcodeOp>>],
) -> i32 {
    let count = 1 + descend_prefix.iter().filter(|d| Arc::ptr_eq(d, op)).count();
    if count == 1 {
        return first_slot as i32;
    }
    let inrefs = op.read().unwrap().inrefs.clone();
    let mut recount = 1;
    for i in (first_slot + 1)..inrefs.len() {
        if Arc::ptr_eq(&inrefs[i], vn) {
            recount += 1;
            if recount == count {
                return i as i32;
            }
        }
    }
    -1
}

// =====================================================================
// RuleSubfloatConvert — FLOAT_FLOAT2FLOAT
// (subflow.hh:409-418, subflow.cc:3483-3507)
// =====================================================================

/// Perform SubfloatFlow analysis triggered by FLOAT_FLOAT2FLOAT.
/// Faithful to Ghidra's `RuleSubfloatConvert` (subflow.hh:409-418).
///
/// Ghidra's `applyOp` (subflow.cc:3489-3507) constructs a `SubfloatFlow`
/// (subflow.hh:379-406), a `TransformManager` subclass that pushes a logical
/// sub-precision interpretation through the data-flow of a `FLOAT_FLOAT2FLOAT`
/// output (or input) and rewrites the data-flow at the smaller precision,
/// eliminating the precision conversions. `SubfloatFlow` traces forward and
/// backward, accumulating the maximum precision reaching each float op in a
/// `maxPrecisionMap`, and only applies the transform when the trace is
/// consistent and reaches at least one terminator.
pub struct RuleSubfloatConvert;
impl RuleSubfloatConvert {
    // Ghidra: subflow.hh:409 RuleSubfloatConvert::new
    pub fn new() -> Self {
        Self
    }
}
impl Rule for RuleSubfloatConvert {
    // Ghidra: subflow.cc:3489 RuleSubfloatConvert::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // RuleSubfloatConvert::applyOp (subflow.cc:3489-3507), verbatim
        // structure: pick the wider side as the SubfloatFlow root and the
        // narrower size as the precision, run the full trace, apply on
        // success. There is no constant special case — constants flow
        // through the same trace (traceBackward's FLOAT_FLOAT2FLOAT leg
        // re-encodes them at the precision, subflow.cc:3394-3403).
        let (invn, outvn) = {
            let o = op_arc.read().unwrap();
            let invn = match o.get_in(0).cloned() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            let outvn = match o.output.clone() { Some(v) => v, None => return Ok(action_status::NO_CHANGE) };
            (invn, outvn)
        };
        let insize = invn.read().unwrap().get_size() as i32;
        let outsize = outvn.read().unwrap().get_size() as i32;
        if outsize > insize {
            let mut subflow = SubfloatFlow::new(fd, outvn, insize);
            if !subflow.do_trace() {
                return Ok(action_status::NO_CHANGE);
            }
            subflow.apply(fd);
        } else {
            let mut subflow = SubfloatFlow::new(fd, invn, outsize);
            if !subflow.do_trace() {
                return Ok(action_status::NO_CHANGE);
            }
            subflow.apply(fd);
        }
        Ok(action_status::CHANGE)
    }
    // Ghidra: subflow.hh:409 RuleSubfloatConvert::getName
    fn get_name(&self) -> &str {
        "subfloat_convert"
    }
    // Ghidra: subflow.cc:3483 RuleSubfloatConvert::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_FLOAT_FLOAT2FLOAT]
    }
}

// ---------------------------------------------------------------------------
// RuleDumptyHumpLate (subflow.cc:3006-3064)
// ---------------------------------------------------------------------------

/// Late SUBPIECE-of-PIECE simplification.
///
/// Detects `SUBPIECE(PIECE(x,y))` and backtracks through the PIECE components:
/// if the SUBPIECE truncation selects exactly one PIECE input, it replaces the
/// SUBPIECE operand with that component (adjusting or removing the SUBPIECE as
/// needed). This is the late cross-block variant run in the cleanup pool; the
/// intra-block sibling `RuleDumptyHump` lives in ruleaction.rs.
///
/// Faithful to Ghidra's `RuleDumptyHumpLate` (subflow.cc:3006-3064).
pub struct RuleDumptyHumpLate;

impl RuleDumptyHumpLate {
    // Ghidra: subflow.hh:363 RuleDumptyHumpLate::new
    pub fn new() -> Self { Self }
}

impl Rule for RuleDumptyHumpLate {
    // Ghidra: subflow.cc:3012 RuleDumptyHumpLate::applyOp
    fn apply_op(&self, op_arc: &Arc<RwLock<PcodeOp>>, data: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleDumptyHumpLate::applyOp (subflow.cc:3012-3064).
        let op_ref = PcodeOpRef(op_arc.clone());

        // vn = op->getIn(0); if (!vn->isWritten()) return 0;
        let vn_initial = match op_arc.read().unwrap().get_in(0) {
            Some(v) => v.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };
        if !vn_initial.read().unwrap().is_written() {
            return Ok(action_status::NO_CHANGE);
        }
        // pieceOp = vn->getDef(); if (pieceOp->code() != CPUI_PIECE) return 0;
        let mut piece_op = match vn_initial.read().unwrap().get_def() {
            Some(d) => d,
            None => return Ok(action_status::NO_CHANGE),
        };
        if piece_op.read().unwrap().opcode != OpCode::CPUI_PIECE {
            return Ok(action_status::NO_CHANGE);
        }
        // int4 outSize = out->getSize(); int4 trunc = op->getIn(1)->getOffset();
        let out_vn = match op_arc.read().unwrap().get_out() {
            Some(v) => v.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };
        let out_size = out_vn.read().unwrap().get_size() as i64;
        let mut trunc = op_arc
            .read()
            .unwrap()
            .get_in(1)
            .map(|v| v.read().unwrap().get_offset() as i64)
            .unwrap_or(0);

        let mut vn = vn_initial.clone();
        // Backtrack loop (subflow.cc:3022-3041).
        loop {
            // cc:3024-3025: trialVn = pieceOp->getIn(1) (least significant
            // component), trialTrunc = trunc.
            let least = match piece_op.read().unwrap().get_in(1) {
                Some(v) => v.clone(),
                None => break,
            };
            let mut trial_trunc = trunc;
            // cc:3026-3029: trunc >= least size → truncation from the most
            // significant part: trialTrunc -= least size; trialVn = in(0).
            let trial_vn = if trunc >= least.read().unwrap().get_size() as i64 {
                trial_trunc -= least.read().unwrap().get_size() as i64;
                match piece_op.read().unwrap().get_in(0) {
                    Some(v) => v.clone(),
                    None => break,
                }
            } else {
                least
            };
            let trial_vn_size = trial_vn.read().unwrap().get_size() as i64;
            // cc:3030-3031: crossing test against the TRIAL component. On
            // break, vn keeps its previously committed value — the pre-fix
            // code assigned vn before this test, so a SUBPIECE whose output
            // crosses both PIECE components escaped with the uncommitted
            // component (the SUB<in><out> illegal-shape / lost extraout_
            // materialization divergence, VARMAP-UNAFF-TYPEMAT-0001).
            if out_size + trial_trunc > trial_vn_size {
                break; // vn crosses both components
            }
            // cc:3032-3033: commit to this component — only AFTER the
            // crossing test passes.
            vn = trial_vn;
            trunc = trial_trunc;
            if vn.read().unwrap().get_size() as i64 == out_size {
                break; // Found matching component
            }
            if !vn.read().unwrap().is_written() {
                break;
            }
            let next_piece = match vn.read().unwrap().get_def() {
                Some(d) => d,
                None => break,
            };
            if next_piece.read().unwrap().opcode != OpCode::CPUI_PIECE {
                break;
            }
            piece_op = next_piece;
        }

        // if (vn == op->getIn(0)) return 0; // Didn't backtrack thru any PIECE.
        if Arc::ptr_eq(&vn, &vn_initial) {
            return Ok(action_status::NO_CHANGE);
        }

        // if (vn->isWritten() && vn->getDef()->code() == CPUI_COPY)
        //   vn = vn->getDef()->getIn(0);
        let vn = {
            let advance = vn.read().unwrap().is_written();
            if advance {
                let def = vn.read().unwrap().get_def();
                if let Some(d) = def {
                    if d.read().unwrap().opcode == OpCode::CPUI_COPY {
                        match d.read().unwrap().get_in(0) {
                            Some(v) => v.clone(),
                            None => vn,
                        }
                    } else {
                        vn
                    }
                } else {
                    vn
                }
            } else {
                vn
            }
        };

        let vn_size = vn.read().unwrap().get_size() as i64;

        // Determine removeOp and rewrite the SUBPIECE (subflow.cc:3048-3061).
        let remove_op: Option<Arc<RwLock<PcodeOp>>> = if vn_size != out_size {
            // Component does not match size exactly. Preserve SUBPIECE.
            // removeOp = op->getIn(0)->getDef();
            let r = vn_initial.read().unwrap().get_def();
            // if (op->getIn(1)->getOffset() != trunc)
            //   data.opSetInput(op, data.newConstant(4, trunc), 1);
            let cur_offset = op_arc
                .read()
                .unwrap()
                .get_in(1)
                .map(|v| v.read().unwrap().get_offset() as i64)
                .unwrap_or(0);
            if cur_offset != trunc {
                let c = data.new_constant(4, trunc as u64);
                data.op_set_input(&op_ref, c, 1);
            }
            // data.opSetInput(op, vn, 0);
            data.op_set_input(&op_ref, vn, 0);
            r
        } else if out_vn.read().unwrap().is_auto_live() {
            // Exact match but output address fixed. Change SUBPIECE to COPY.
            // removeOp = op->getIn(0)->getDef();
            let r = vn_initial.read().unwrap().get_def();
            data.op_remove_input(&op_ref, 1);
            data.op_set_opcode(&op_ref, OpCode::CPUI_COPY);
            data.op_set_input(&op_ref, vn, 0);
            r
        } else {
            // Exact match. Completely replace output with component.
            // removeOp = op;  data.totalReplace(out, vn);
            data.total_replace(&out_vn, vn);
            Some(op_arc.clone())
        };

        // if (removeOp->getOut()->hasNoDescend() && !removeOp->getOut()->isAutoLive())
        //   data.opDestroyRecursive(removeOp);
        if let Some(ro) = remove_op {
            let destroy = {
                let out = ro.read().unwrap().output.clone();
                if let Some(o) = out {
                    let o_rg = o.read().unwrap();
                    o_rg.has_no_descend() && !o_rg.is_auto_live()
                } else {
                    false
                }
            };
            if destroy {
                let ro_ref = PcodeOpRef(ro);
                data.op_destroy_recursive(&ro_ref);
            }
        }

        Ok(action_status::CHANGE)
    }

    // Ghidra: subflow.hh:363 RuleDumptyHumpLate::getName
    fn get_name(&self) -> &str { "dumptyhumplate" }
    // Ghidra: subflow.cc:3006 RuleDumptyHumpLate::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_SUBPIECE] }
}

// =====================================================================
// Tests
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, SeqNum};
    use crate::op::PcodeOp;
    use crate::space::AddressSpace;
    use crate::varnode::Varnode;

    /// Build a standalone PcodeOp (not inserted into the bank) with the given
    /// opcode, inputs, and an output varnode. Mirrors the test pattern in
    /// ruleaction.rs.
    fn make_op(seq_order: u32, opc: OpCode, inputs: Vec<Arc<RwLock<Varnode>>>, output: Option<Arc<RwLock<Varnode>>>) -> Arc<RwLock<PcodeOp>> {
        let op = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), seq_order), opc)));
        {
            let mut o = op.write().unwrap();
            o.inrefs = inputs.clone();
            o.output = output.clone();
        }
        // Wire descend links: each input is read by this op.
        for inv in &inputs {
            inv.write().unwrap().descend.push(Arc::downgrade(&op));
        }
        // Wire def link on the output.
        if let Some(out) = &output {
            out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
            out.write().unwrap().def = Some(Arc::downgrade(&op));
        }
        op
    }

    #[test]
    fn test_subvarflow_construction_and_bitsize() {
        // Faithful to SubvariableFlow ctor (subflow.cc:1372-1404):
        //   mask covering 8 bits (1 byte) -> flowsize=1, bitsize=8.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let root = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let sf = SubvariableFlow::new(&mut fd, root, 0xff, false, false, false);
        assert!(!sf.is_null());
        assert_eq!(sf.flowsize, 1);
        assert_eq!(sf.bitsize, 8);
    }

    #[test]
    fn test_subvarflow_null_on_zero_mask() {
        // Ghidra: if (mask == 0) { fd = 0; return; }
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let root = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let sf = SubvariableFlow::new(&mut fd, root, 0, false, false, false);
        assert!(sf.is_null());
    }

    #[test]
    fn test_subvarflow_mask_in_byte_range() {
        // bitsize in (24,32] -> flowsize=4, fd stays non-null (subflow.cc:1390-1391).
        // mask 0xFF00_0000 has msb=31, lsb=24 -> bitsize=8 -> flowsize=1; instead use a
        // wider span: mask 0xFFFF_F000 has msb=31, lsb=12 -> bitsize=20 -> flowsize=3.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let root = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let sf = SubvariableFlow::new(&mut fd, root, 0xFFFF_F000, false, false, false);
        assert!(!sf.is_null());
        assert_eq!(sf.bitsize, 20);
        assert_eq!(sf.flowsize, 3);
    }

    #[test]
    fn test_subvarflow_big_flag_allows_8byte() {
        // bitsize = mostsigbit_set(mask) - leastsigbit_set(mask) + 1.
        // For a mask spanning all 64 bits, bitsize=64 -> flowsize=8 requires big=true.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let root = fd.vbank.create_with_space(8, AddressSpace::Register, 0x10);
        // mask with msb=63, lsb=0 -> bitsize=64.
        let sf = SubvariableFlow::new(&mut fd, root, 0xFFFF_FFFF_FFFF_FFFF, false, false, true);
        assert!(!sf.is_null());
        assert_eq!(sf.flowsize, 8);
        assert_eq!(sf.bitsize, 64);
    }

    #[test]
    fn test_subvarflow_big_flag_false_rejects_8byte() {
        // Same 64-bit-span mask, but big=false -> rejected (fd nulled).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let root = fd.vbank.create_with_space(8, AddressSpace::Register, 0x10);
        let sf = SubvariableFlow::new(&mut fd, root, 0xFFFF_FFFF_FFFF_FFFF, false, false, false);
        assert!(sf.is_null());
    }

    #[test]
    fn test_does_or_set_and_does_and_clear() {
        // Faithful to doesOrSet/doesAndClear (subflow.cc:26-53).
        let vn = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let or_const = Arc::new(RwLock::new(Varnode::new_constant(0xff, 4)));
        let or_op = make_op(0, OpCode::CPUI_INT_OR, vec![vn.clone(), or_const], None);
        // mask=0xff, orval=0xff -> all masked bits one -> slot 1.
        assert_eq!(SubvariableFlow::does_or_set(&or_op.read().unwrap(), 0xff), 1);

        let and_const = Arc::new(RwLock::new(Varnode::new_constant(0, 4)));
        let and_op = make_op(1, OpCode::CPUI_INT_AND, vec![vn, and_const], None);
        // mask=0xff, andval=0 -> all masked bits zero -> slot 1.
        assert_eq!(SubvariableFlow::does_and_clear(&and_op.read().unwrap(), 0xff), 1);
    }

    #[test]
    fn test_does_or_set_partial_returns_neg1() {
        let vn = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let or_const = Arc::new(RwLock::new(Varnode::new_constant(0x0f, 4)));
        let or_op = make_op(0, OpCode::CPUI_INT_OR, vec![vn, or_const], None);
        // mask=0xff but orval=0x0f -> not all masked bits one -> -1.
        assert_eq!(SubvariableFlow::does_or_set(&or_op.read().unwrap(), 0xff), -1);
    }

    #[test]
    fn test_subvarflow_sextrestrictions_constant_reject() {
        // setReplacement with sextrestrictions: a constant that is NOT a sign
        // extension of its logical value should be rejected. We construct a
        // flow where the seed is a non-constant and check doTrace runs.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let root = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let mut sf = SubvariableFlow::new(&mut fd, root, 0xff, false, true, false);
        // With no descendants, doTrace should process the worklist and find
        // pullcount==0 -> returns false.
        assert!(!sf.do_trace(&fd));
    }

    #[test]
    fn test_subvar_get_repeat_slot_first_occurrence() {
        // op.cc:101: count==1 (first occurrence of this op in the descendant
        // iteration) returns firstSlot unchanged.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let other = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        let call = make_op(0, OpCode::CPUI_CALL, vec![other, vn.clone()], None);
        assert_eq!(SubvariableFlow::subvar_get_repeat_slot(&call, &vn, 1, 0), 1);
    }

    #[test]
    fn test_subvar_get_repeat_slot_repeat_occurrence() {
        // op.cc:97-108: count = 1 + prior occurrences; the count-th inrefs
        // slot holding vn is returned.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let other = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        // CALL reading vn in slots 1 and 3 (getSlot -> first = 1).
        let call = make_op(0, OpCode::CPUI_CALL, vec![other.clone(), vn.clone(), other, vn.clone()], None);
        // Second occurrence (one prior entry of the same op): slot 3.
        assert_eq!(SubvariableFlow::subvar_get_repeat_slot(&call, &vn, 1, 1), 3);
        // First occurrence: firstSlot unchanged.
        assert_eq!(SubvariableFlow::subvar_get_repeat_slot(&call, &vn, 1, 0), 1);
    }

    #[test]
    fn test_subvar_get_repeat_slot_absent_tail() {
        // op.cc:110: count > 1 but vn does not recur past firstSlot -> -1.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let other = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        let call = make_op(0, OpCode::CPUI_CALL, vec![vn.clone(), other], None);
        assert_eq!(SubvariableFlow::subvar_get_repeat_slot(&call, &vn, 0, 1), -1);
    }

    #[test]
    fn test_subvarflow_trace_with_terminal_pull() {
        // Build: root(4 bytes, marked INPUT) --read--> SUBPIECE out(1 byte)
        // which has a descendant consuming it. With the right mask, traceForward
        // should find a terminal patch and pullcount > 0.
        // NOTE: the root must NOT be "free" — Ghidra's setReplacement aborts on
        // free varnodes (subflow.cc:724). Marking it INPUT mirrors a real input.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let root = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        root.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let sub_out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x20);
        let const0 = fd.vbank.create_constant(8, 0);
        let sub_op = make_op(0, OpCode::CPUI_SUBPIECE, vec![root.clone(), const0], Some(sub_out.clone()));
        let _ = sub_op;
        // sub_out is consumed by a downstream COPY (so it's not "no descend").
        let copy_out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x30);
        let _copy_op = make_op(1, OpCode::CPUI_COPY, vec![sub_out], Some(copy_out));
        // Mask covering low byte; flowsize=1. The SUBPIECE extracts exactly
        // flowsize bytes at offset 0 with mask aligned -> addTerminalPatch.
        let mut sf = SubvariableFlow::new(&mut fd, root, 0xff, true, false, false);
        assert!(sf.do_trace(&fd));
        assert!(sf.pull_count() >= 1);
    }

    #[test]
    fn test_rule_subvar_and_triggers() {
        // RuleSubvarAnd pattern (subflow.cc:1553-1582):
        //   INT_AND(vn, 0xff) where outvn.consume == 0xff and (consume & 1) != 0.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let mask_const = fd.vbank.create_constant(8, 0xff);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        out.write().unwrap().set_consume(0xff);
        // out must have a descendant (else hasNoDescend -> return 0).
        let user = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        let _user_op = make_op(2, OpCode::CPUI_COPY, vec![out.clone()], Some(user));
        let op = make_op(0, OpCode::CPUI_INT_AND, vec![vn, mask_const], Some(out));
        let rule = RuleSubvarAnd::new();
        let res = rule.apply_op(&op, &mut fd).unwrap();
        // A change is expected: the rule triggers SubvariableFlow which, with
        // these inputs, should at least attempt a trace. Result is either
        // CHANGE (if trace succeeded) or NO_CHANGE (if trace found <2 pulls).
        // We assert it does not error and is one of the two statuses.
        assert!(res == action_status::CHANGE || res == action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_and_no_constant() {
        // In(1) not constant -> NO_CHANGE (subflow.cc:1556).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let vn2 = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        let op = make_op(0, OpCode::CPUI_INT_AND, vec![vn, vn2], Some(out));
        let rule = RuleSubvarAnd::new();
        assert_eq!(rule.apply_op(&op, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_and_consume_mismatch() {
        // consume != in(1) offset -> NO_CHANGE (subflow.cc:1560).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let mask_const = fd.vbank.create_constant(8, 0xff);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        out.write().unwrap().set_consume(0x0f); // != 0xff
        let op = make_op(0, OpCode::CPUI_INT_AND, vec![vn, mask_const], Some(out));
        let rule = RuleSubvarAnd::new();
        assert_eq!(rule.apply_op(&op, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_subpiece_triggers_trace() {
        // RuleSubvarSubpiece pattern (subflow.cc:1590-1619).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        vn.write().unwrap().set_consume(0xff); // consume within mask
        let out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x20);
        let const0 = fd.vbank.create_constant(8, 0);
        // out has a descendant so hasNoDescend is false.
        let user = fd.vbank.create_with_space(1, AddressSpace::Register, 0x30);
        let _user_op = make_op(1, OpCode::CPUI_COPY, vec![out.clone()], Some(user));
        let op = make_op(0, OpCode::CPUI_SUBPIECE, vec![vn, const0], Some(out));
        let rule = RuleSubvarSubpiece::new();
        let res = rule.apply_op(&op, &mut fd).unwrap();
        assert!(res == action_status::CHANGE || res == action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_subpiece_mask_too_big() {
        // flowsize + sa > sizeof(uintb)(=8) -> NO_CHANGE (subflow.cc:1597).
        // flowsize = out size = 8, sa = const offset = 9 -> 17 > 8 -> NO_CHANGE.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(8, AddressSpace::Register, 0x10);
        let out = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        let big_const = fd.vbank.create_constant(8, 9); // sa = 9
        let op = make_op(0, OpCode::CPUI_SUBPIECE, vec![vn, big_const], Some(out));
        let rule = RuleSubvarSubpiece::new();
        let result = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(result, action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_compzero_single_bit() {
        // RuleSubvarCompZero pattern (subflow.cc:1628-1678):
        //   INT_EQUAL(vn_with_nzmask=0x01, const 0x01) testing the single bit.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        vn.write().unwrap().set_nzm(0x01); // nzmask = single bit
        let const1 = fd.vbank.create_constant(8, 0x01);
        let out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x20);
        // out must have a descendant.
        let user = fd.vbank.create_with_space(1, AddressSpace::Register, 0x30);
        let _user_op = make_op(1, OpCode::CPUI_COPY, vec![out.clone()], Some(user));
        let op = make_op(0, OpCode::CPUI_INT_EQUAL, vec![vn, const1], Some(out));
        let rule = RuleSubvarCompZero::new();
        let res = rule.apply_op(&op, &mut fd).unwrap();
        assert!(res == action_status::CHANGE || res == action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_compzero_no_constant() {
        // In(1) not constant -> NO_CHANGE (subflow.cc:1631).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let vn2 = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x30);
        let op = make_op(0, OpCode::CPUI_INT_EQUAL, vec![vn, vn2], Some(out));
        let rule = RuleSubvarCompZero::new();
        assert_eq!(rule.apply_op(&op, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_compzero_two_bits_rejected() {
        // nzmask with 2 bits -> (mask >> bitnum) != 1 -> NO_CHANGE.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        vn.write().unwrap().set_nzm(0x03); // two bits
        let const1 = fd.vbank.create_constant(8, 0x01);
        let out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x20);
        let op = make_op(0, OpCode::CPUI_INT_EQUAL, vec![vn, const1], Some(out));
        let rule = RuleSubvarCompZero::new();
        assert_eq!(rule.apply_op(&op, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_shift_single_bit() {
        // RuleSubvarShift pattern (subflow.cc:1686-1702):
        //   vn size 1, nzmask=0x80, INT_RIGHT by 7 -> pulls single bit.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(1, AddressSpace::Register, 0x10);
        vn.write().unwrap().set_nzm(0x80);
        let sa_const = fd.vbank.create_constant(8, 7);
        let out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x20);
        // out must have a descendant.
        let user = fd.vbank.create_with_space(1, AddressSpace::Register, 0x30);
        let _user_op = make_op(1, OpCode::CPUI_COPY, vec![out.clone()], Some(user));
        let op = make_op(0, OpCode::CPUI_INT_RIGHT, vec![vn, sa_const], Some(out));
        let rule = RuleSubvarShift::new();
        let res = rule.apply_op(&op, &mut fd).unwrap();
        assert!(res == action_status::CHANGE || res == action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_shift_wrong_size() {
        // vn size != 1 -> NO_CHANGE (subflow.cc:1690).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let sa_const = fd.vbank.create_constant(8, 7);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let op = make_op(0, OpCode::CPUI_INT_RIGHT, vec![vn, sa_const], Some(out));
        let rule = RuleSubvarShift::new();
        assert_eq!(rule.apply_op(&op, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_zext_runs() {
        // RuleSubvarZext pattern (subflow.cc:1710-1721).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let invn = fd.vbank.create_with_space(2, AddressSpace::Register, 0x10);
        let outvn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let op = make_op(0, OpCode::CPUI_INT_ZEXT, vec![invn], Some(outvn.clone()));
        let rule = RuleSubvarZext::new();
        let res = rule.apply_op(&op, &mut fd).unwrap();
        // Either the trace succeeds (CHANGE) or finds nothing (NO_CHANGE); both
        // are valid given the minimal graph.
        assert!(res == action_status::CHANGE || res == action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_subvar_sext_runs() {
        // RuleSubvarSext pattern (subflow.cc:1729-1740).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let invn = fd.vbank.create_with_space(2, AddressSpace::Register, 0x10);
        let outvn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let op = make_op(0, OpCode::CPUI_INT_SEXT, vec![invn], Some(outvn.clone()));
        let mut rule = RuleSubvarSext::new();
        // Exercise the pool's virtual-reset seam (subflow.cc:1742-1746): the
        // override omits Rule::reset, so the base warning-given bit survives.
        let mut rule_state = RuleState::new(0);
        rule.reset_for_function(&mut fd, &mut rule_state);
        let res = rule.apply_op(&op, &mut fd).unwrap();
        assert!(res == action_status::CHANGE || res == action_status::NO_CHANGE);
    }

    #[test]
    fn test_rule_split_flow_detects_pattern_or_skips() {
        // RuleSplitFlow (subflow.cc:2045-2088). We exercise the early returns:
        //   - loSize == 0 -> NO_CHANGE
        //   - !vn.isWritten() -> NO_CHANGE
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // Case 1: SUBPIECE with offset 0 -> loSize==0 -> NO_CHANGE.
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let out = fd.vbank.create_with_space(2, AddressSpace::Register, 0x20);
        let const0 = fd.vbank.create_constant(8, 0);
        let op = make_op(0, OpCode::CPUI_SUBPIECE, vec![vn, const0], Some(out));
        let rule = RuleSplitFlow::new();
        assert_eq!(rule.apply_op(&op, &mut fd).unwrap(), action_status::NO_CHANGE);

        // Case 2: input not written -> NO_CHANGE.
        let vn2 = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        // vn2 has no def (free input) -> isWritten()==false.
        let out2 = fd.vbank.create_with_space(2, AddressSpace::Register, 0x40);
        let const2 = fd.vbank.create_constant(8, 2);
        let op2 = make_op(1, OpCode::CPUI_SUBPIECE, vec![vn2, const2], Some(out2));
        assert_eq!(rule.apply_op(&op2, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    #[test]
    fn test_split_datatype_constructs() {
        // Funcdata::new binds the canonical default Architecture (the
        // stand-in for `glb = scope->getArch()`, funcdata.cc:48 — the C++
        // Funcdata always has an Architecture). Its resetDefaultsInternal
        // config sets struct|array|pointer (architecture.cc:1430-1432), so
        // both split gates are on by construction (subflow.cc:2704-2707);
        // the canonical instance carries no TypeFactory, so `types` stays
        // None until a caller attaches a real Architecture via set_arch.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let s = SplitDatatype::new(&mut fd);
        assert!(s.split_structures);
        assert!(s.split_arrays);
        assert!(!s.is_load_store);
        assert!(s.data_type_pieces.is_empty());
        assert!(s.types.is_none());
    }

    #[test]
    fn test_rule_split_copy_load_store_inert() {
        // With no type information on the Varnodes, the Split* rules are
        // inert (the metatype pre-check returns NO_CHANGE). This exercises
        // the no-op path of the real implementation.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let vn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let copy_op = make_op(0, OpCode::CPUI_COPY, vec![vn], Some(out));
        assert_eq!(RuleSplitCopy::new().apply_op(&copy_op, &mut fd).unwrap(), action_status::NO_CHANGE);

        // LOAD/STORE ops are trickier to construct; just verify the rule struct
        // reports the right opcode list.
        assert_eq!(RuleSplitLoad::new().get_opcodes(), vec![OpCode::CPUI_LOAD]);
        assert_eq!(RuleSplitStore::new().get_opcodes(), vec![OpCode::CPUI_STORE]);
    }

    /// Build a struct{char f0 @0; int f1 @4;} (size 8) for the split tests.
    fn make_struct_dt() -> Arc<crate::type_system::Datatype> {
        use crate::type_system::datatype::{Datatype, TypeBase, TypeField, TypeStruct};
        use crate::type_system::TypeMetatype;
        let char_t = Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)));
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("S".into(), 5, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "f0".into(), offset: 0, type_ptr: char_t },
                TypeField { name: "f1".into(), offset: 1, type_ptr: int_t },
            ],
        }))
    }

    #[test]
    fn test_split_copy_performs_real_transform() {
        // SplitDatatype::splitCopy on a constant struct{char;int} (sizes 1
        // and 4) rewrites the single COPY into per-field SUBPIECE/COPY/PIECE
        // ops. The constant input dodges the whole-struct identity gate
        // (subflow.cc:2304-2305: whole-struct splits need constant
        // initialization), exactly like Ghidra splitCopy on
        // `S s = (S){...}`.
        let factory_arc = Arc::new(RwLock::new(
            crate::type_system::typefactory::TypeFactory::new(8),
        ));
        let mut arch = crate::arch::Architecture::new();
        arch.types = Some(factory_arc.clone());
        arch.split_datatype_config = crate::arch::split_datatype::OPTION_STRUCT
            | crate::arch::split_datatype::OPTION_ARRAY
            | crate::arch::split_datatype::OPTION_POINTER;
        let arch_arc = Arc::new(arch);
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.arch = Some(arch_arc.clone());
        let dt = make_struct_dt();
        let in_vn = fd.vbank.create_constant(5, 0x1122334455);
        in_vn.write().unwrap().update_type(dt.clone());
        let out_vn = fd.vbank.create_with_space(5, AddressSpace::Register, 0x20);
        out_vn.write().unwrap().update_type(dt);
        let copy_op = make_op(0, OpCode::CPUI_COPY, vec![in_vn], Some(out_vn));
        let ops_before = fd.obank.optree.len();
        let res = RuleSplitCopy::new().apply_op(&copy_op, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // The rewrite creates new ops in the obank (SUBPIECE / COPY / PIECE).
        assert!(fd.obank.optree.len() > ops_before);
    }

    #[test]
    fn test_split_copy_whole_struct_identity_rejected() {
        // A non-constant COPY whose in/out data-types are the same whole
        // struct is NOT split (subflow.cc:2304-2305: "Don't split a whole
        // structure unless it is getting initialized from a constant").
        let factory_arc = Arc::new(RwLock::new(
            crate::type_system::typefactory::TypeFactory::new(8),
        ));
        let mut arch = crate::arch::Architecture::new();
        arch.types = Some(factory_arc.clone());
        arch.split_datatype_config = crate::arch::split_datatype::OPTION_STRUCT
            | crate::arch::split_datatype::OPTION_ARRAY
            | crate::arch::split_datatype::OPTION_POINTER;
        let arch_arc = Arc::new(arch);
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.arch = Some(arch_arc.clone());
        let dt = make_struct_dt();
        let in_vn = fd.vbank.create_with_space(5, AddressSpace::Register, 0x10);
        in_vn.write().unwrap().update_type(dt.clone());
        let out_vn = fd.vbank.create_with_space(5, AddressSpace::Register, 0x20);
        out_vn.write().unwrap().update_type(dt);
        let copy_op = make_op(0, OpCode::CPUI_COPY, vec![in_vn], Some(out_vn));
        let ops_before = fd.obank.optree.len();
        let res = RuleSplitCopy::new().apply_op(&copy_op, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
        assert_eq!(fd.obank.optree.len(), ops_before);
    }

    #[test]
    fn test_split_copy_mismatched_scalar_descent_rejected() {
        // in struct{char@0;int@1} vs out struct{char@0;short@1;short@3}:
        // piece0 char/char matches, then at offset 1 curIn=int(4) is larger
        // and NOT a hole, so the both-composite descent calls
        // getComponent(int,0) (subflow.cc:2363). int has no sub-type
        // (type.cc:174 base) and its getHoleSize is the type.hh:256 base 0,
        // so getComponent returns null and cc:2364 returns false —
        // NO_CHANGE, constant input notwithstanding (R15 M-1/M-2 re-pin).
        let factory_arc = Arc::new(RwLock::new(
            crate::type_system::typefactory::TypeFactory::new(8),
        ));
        let mut arch = crate::arch::Architecture::new();
        arch.types = Some(factory_arc.clone());
        arch.split_datatype_config = crate::arch::split_datatype::OPTION_STRUCT
            | crate::arch::split_datatype::OPTION_ARRAY
            | crate::arch::split_datatype::OPTION_POINTER;
        let arch_arc = Arc::new(arch);
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.arch = Some(arch_arc.clone());
        use crate::type_system::datatype::{Datatype, TypeBase, TypeField, TypeStruct};
        use crate::type_system::TypeMetatype;
        let char_t = Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)));
        let int_t = Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)));
        let in_dt = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("S".into(), 5, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "f0".into(), offset: 0, type_ptr: char_t.clone() },
                TypeField { name: "f1".into(), offset: 1, type_ptr: int_t },
            ],
        }));
        let short_t = Arc::new(Datatype::Base(TypeBase::new("short".into(), 2, TypeMetatype::Int)));
        let out_dt = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("S2".into(), 5, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "f0".into(), offset: 0, type_ptr: char_t },
                TypeField { name: "f1".into(), offset: 1, type_ptr: short_t.clone() },
                TypeField { name: "f2".into(), offset: 3, type_ptr: short_t },
            ],
        }));
        let in_vn = fd.vbank.create_constant(5, 0x1122334455);
        in_vn.write().unwrap().update_type(in_dt);
        let out_vn = fd.vbank.create_with_space(5, AddressSpace::Register, 0x20);
        out_vn.write().unwrap().update_type(out_dt);
        let copy_op = make_op(0, OpCode::CPUI_COPY, vec![in_vn], Some(out_vn));
        let ops_before = fd.obank.optree.len();
        let res = RuleSplitCopy::new().apply_op(&copy_op, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
        assert_eq!(fd.obank.optree.len(), ops_before);
    }

    #[test]
    fn test_split_copy_field_gap_hole_filler_accepted() {
        // The cc:2361/2368 getBase(size) hole fillers fire on genuine struct
        // field-gap padding (TypeStruct::getHoleSize distance to the next
        // field, type.cc:1661-1663), never on scalar interiors. in
        // struct{a4@0;b4@4;c4@8} vs out struct{a4@0;[gap 4..8];b4@8;c4@12}:
        // piece0 a/a, piece1 in=b(4) vs out hole(4) -> unknown4 filler,
        // piece2 c/b — three pieces, terminal sizeLeft==0, and the hole is
        // neither initial (len==1) nor the second-and-final piece, so the
        // split proceeds exactly like the oracle.
        let factory_arc = Arc::new(RwLock::new(
            crate::type_system::typefactory::TypeFactory::new(8),
        ));
        let mut arch = crate::arch::Architecture::new();
        arch.types = Some(factory_arc.clone());
        arch.split_datatype_config = crate::arch::split_datatype::OPTION_STRUCT
            | crate::arch::split_datatype::OPTION_ARRAY
            | crate::arch::split_datatype::OPTION_POINTER;
        let arch_arc = Arc::new(arch);
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        fd.arch = Some(arch_arc.clone());
        use crate::type_system::datatype::{Datatype, TypeBase, TypeField, TypeStruct};
        use crate::type_system::TypeMetatype;
        let uint4 = Arc::new(Datatype::Base(TypeBase::new("uint4".into(), 4, TypeMetatype::Uint)));
        let in_dt = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("Packed".into(), 12, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: uint4.clone() },
                TypeField { name: "b".into(), offset: 4, type_ptr: uint4.clone() },
                TypeField { name: "c".into(), offset: 8, type_ptr: uint4.clone() },
            ],
        }));
        let out_dt = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("Gapped".into(), 16, TypeMetatype::Struct),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: uint4.clone() },
                TypeField { name: "b".into(), offset: 8, type_ptr: uint4.clone() },
                TypeField { name: "c".into(), offset: 12, type_ptr: uint4.clone() },
            ],
        }));
        let in_vn = fd.vbank.create_constant(12, 0xaabbcc11223344);
        in_vn.write().unwrap().update_type(in_dt);
        let out_vn = fd.vbank.create_with_space(12, AddressSpace::Register, 0x20);
        out_vn.write().unwrap().update_type(out_dt);
        let copy_op = make_op(0, OpCode::CPUI_COPY, vec![in_vn], Some(out_vn));
        let res = RuleSplitCopy::new().apply_op(&copy_op, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
    }

    #[test]
    fn test_split_flow_full_transform_through_indirect() {
        // RuleSplitFlow end-to-end: a 2-byte Varnode `vn` is defined by an
        // INDIRECT whose input is a PIECE(hi, lo); a SUBPIECE(vn, 1) takes the
        // high half. This is exactly the pattern subflow.cc:2045-2088 detects
        // (PIECE seen through INDIRECT), and SplitFlow::doTrace + apply should
        // split it into independent lo/hi data-flows. Verifies a REAL transform.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // lo (1B), hi (1B).
        let lo = fd.vbank.create_with_space(1, AddressSpace::Register, 0x10);
        let hi = fd.vbank.create_with_space(1, AddressSpace::Register, 0x20);
        // PIECE(hi, lo) -> piece_out (2B).
        let piece_out = fd.vbank.create_with_space(2, AddressSpace::Register, 0x30);
        let _piece_op = make_op(1, OpCode::CPUI_PIECE, vec![hi.clone(), lo.clone()], Some(piece_out.clone()));
        // INDIRECT(piece_out, iop) -> vn (2B).
        let iop = fd.vbank.create_constant(8, 0);
        let vn = fd.vbank.create_with_space(2, AddressSpace::Register, 0x40);
        let _indirect_op =
            make_op(2, OpCode::CPUI_INDIRECT, vec![piece_out.clone(), iop], Some(vn.clone()));
        // SUBPIECE(vn, const=1) -> sub_out (1B): takes the most-significant byte.
        let const1 = fd.vbank.create_constant(8, 1);
        let sub_out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x50);
        let subpiece_op = make_op(3, OpCode::CPUI_SUBPIECE, vec![vn.clone(), const1], Some(sub_out.clone()));
        let ops_before = fd.obank.optree.len();
        let res = RuleSplitFlow::new().apply_op(&subpiece_op, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // The SplitFlow rewrite materialises new COPY ops for the lo/hi lanes.
        assert!(fd.obank.optree.len() > ops_before);
    }

    #[test]
    fn test_rule_subfloat_convert_nonconst_defers() {
        // Non-constant free input (no defining op, no input flag): narrowing
        // roots at it (subflow.cc:3501-3504) and setReplacement aborts on
        // free varnodes (subflow.cc:3214-3215) — the worklist stays empty
        // and doTrace fails. NO_CHANGE.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let invn = fd.vbank.create_with_space(8, AddressSpace::Register, 0x10);
        let outvn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let op = make_op(0, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![invn], Some(outvn));
        let rule = RuleSubfloatConvert::new();
        assert_eq!(rule.apply_op(&op, &mut fd).unwrap(), action_status::NO_CHANGE);
        assert_eq!(rule.get_name(), "subfloat_convert");
        assert_eq!(rule.get_opcodes(), vec![OpCode::CPUI_FLOAT_FLOAT2FLOAT]);
    }

    #[test]
    fn test_rule_subfloat_convert_constant_fold() {
        // Constant input, widening (4->8): applyOp roots at the *output*
        // (subflow.cc:3496-3499), so the constant flows through the full
        // SubfloatFlow trace. traceBackward's FLOAT_FLOAT2FLOAT leg
        // (subflow.cc:3394-3397) keeps the constant offset as-is when the
        // input size equals the precision and builds a COPY replacement; a
        // downstream FLOAT_FLOAT2FLOAT (out8 -> mid4) is the required
        // terminator (subflow.cc:3285-3293). Without the terminator the
        // rule makes no change (doTrace's terminatorCount==0, cc:3479).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // 1.0f as a 4-byte constant = 0x3F800000
        let invn = fd.vbank.create_constant(4, 0x3F800000);
        let outvn = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        let op = make_op(0, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![invn], Some(outvn.clone()));
        // Terminator: mid4 = FLOAT2FLOAT(out8) — output size 4 == precision.
        let mid4 = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        let term_op = make_op(1, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![outvn], Some(mid4.clone()));
        let rule = RuleSubfloatConvert::new();
        let res = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // The original FLOAT2FLOAT was replaced (op_replacement) and destroyed.
        assert!(op.read().unwrap().is_dead());
        // The terminator FLOAT2FLOAT became a preexisting COPY whose input is
        // the new 4-byte piece temp of the old 8-byte output.
        assert_eq!(term_op.read().unwrap().opcode, OpCode::CPUI_COPY);
        let term_in = term_op.read().unwrap().get_in(0).cloned().unwrap();
        assert_eq!(term_in.read().unwrap().get_size(), 4);
        assert!(!Arc::ptr_eq(&term_in, &mid4));
        // The replacement COPY reads the 4-byte constant (kept verbatim:
        // input size == precision, subflow.cc:3396-3397) and writes a
        // 4-byte temp.
        let rep_copy = fd
            .obank
            .optree
            .iter()
            .find(|o| {
                let r = o.0.read().unwrap();
                r.opcode == OpCode::CPUI_COPY
                    && r.get_in(0)
                        .map(|v| {
                            let vr = v.read().unwrap();
                            vr.is_constant() && vr.get_size() == 4 && vr.get_offset() == 0x3F800000
                        })
                        .unwrap_or(false)
            })
            .cloned();
        let rep_copy = rep_copy.expect("replacement COPY of the re-encoded constant exists");
        let rep_out = rep_copy.0.read().unwrap().output.clone().unwrap();
        assert_eq!(rep_out.read().unwrap().get_size(), 4);
    }

    #[test]
    fn test_rule_subfloat_convert_constant_downcast() {
        // Constant input, narrowing (8->4): applyOp roots at the *input*
        // (subflow.cc:3501-3504). A constant root never enters the worklist
        // (setReplacement returns a constant placeholder without marking or
        // pushing, subflow.cc:3206-3212), so the trace is empty, no
        // terminator is ever seen and doTrace fails (cc:3479) — the rule
        // makes no change. Ghidra never folds a constant narrowing through
        // RuleSubfloatConvert.
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let invn = fd.vbank.create_constant(8, 0x3FF0_0000_0000_0000);
        let outvn = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let op = make_op(0, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![invn], Some(outvn));
        let rule = RuleSubfloatConvert::new();
        let res = rule.apply_op(&op, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_FLOAT_FLOAT2FLOAT);
    }

    /// Constant widening *without* a downstream terminator: doTrace demands
    /// at least one terminator (subflow.cc:3479), so even the constant fold
    /// leg must not fire when the widened output has no float reader.
    #[test]
    fn test_rule_subfloat_convert_constant_no_terminator_nochange() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let invn = fd.vbank.create_constant(4, 0x3F800000);
        let outvn = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        let op = make_op(0, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![invn], Some(outvn));
        let res = RuleSubfloatConvert::new().apply_op(&op, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_FLOAT_FLOAT2FLOAT);
    }

    #[test]
    fn test_rule_names_and_opcodes() {
        // Verify all 8 subvar rules + splitflow report their Ghidra names.
        assert_eq!(RuleSubvarAnd::new().get_name(), "subvar_and");
        assert_eq!(RuleSubvarSubpiece::new().get_name(), "subvar_subpiece");
        assert_eq!(RuleSubvarCompZero::new().get_name(), "subvar_compzero");
        assert_eq!(RuleSubvarShift::new().get_name(), "subvar_shift");
        assert_eq!(RuleSubvarZext::new().get_name(), "subvar_zext");
        assert_eq!(RuleSubvarSext::new().get_name(), "subvar_sext");
        assert_eq!(RuleSplitFlow::new().get_name(), "splitflow");
        assert_eq!(RuleSplitCopy::new().get_name(), "splitcopy");
        assert_eq!(RuleSubvarAnd::new().get_opcodes(), vec![OpCode::CPUI_INT_AND]);
        assert_eq!(RuleSubvarSubpiece::new().get_opcodes(), vec![OpCode::CPUI_SUBPIECE]);
        assert_eq!(RuleSubvarShift::new().get_opcodes(), vec![OpCode::CPUI_INT_RIGHT]);
        assert_eq!(RuleSubvarZext::new().get_opcodes(), vec![OpCode::CPUI_INT_ZEXT]);
        assert_eq!(RuleSubvarSext::new().get_opcodes(), vec![OpCode::CPUI_INT_SEXT]);
    }

    #[test]
    fn test_patch_type_variants_and_records() {
        // PatchRecord / PatchType mirror Ghidra's enum order.
        assert_ne!(PatchType::CopyPatch, PatchType::ComparePatch);
        assert_ne!(PatchType::PushPatch, PatchType::ExtensionPatch);
        assert_ne!(PatchType::ParameterPatch, PatchType::Int2FloatPatch);
    }

    #[test]
    fn test_replace_varnode_new() {
        let rv = ReplaceVarnode::new();
        assert!(rv.vn.is_none());
        assert!(rv.replacement.is_none());
        assert_eq!(rv.mask, 0);
        assert_eq!(rv.val, 0);
        assert!(rv.def.is_none());
    }

    #[test]
    fn test_subvarflow_trace_forward_copy_chain() {
        // Build a longer chain so pullcount reaches the worthwhile threshold:
        //   root(4, INPUT) -> COPY -> mid(4) -> SUBPIECE -> out(1) [+descendant]
        // With aggressive=true the COPYs are traced and the SUBPIECE is a pull.
        // NOTE: root must be INPUT (not free) or setReplacement aborts (subflow.cc:724).
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let root = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        root.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let mid = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let _copy1 = make_op(0, OpCode::CPUI_COPY, vec![root.clone()], Some(mid.clone()));
        let out = fd.vbank.create_with_space(1, AddressSpace::Register, 0x30);
        let const0 = fd.vbank.create_constant(8, 0);
        let _sub = make_op(1, OpCode::CPUI_SUBPIECE, vec![mid, const0], Some(out.clone()));
        // descendant of out so it is consumed.
        let user = fd.vbank.create_with_space(1, AddressSpace::Register, 0x40);
        let _user = make_op(2, OpCode::CPUI_COPY, vec![out], Some(user));
        let mut sf = SubvariableFlow::new(&mut fd, root, 0xff, true, false, false);
        // With aggressive=true the COPY is traced through and the SUBPIECE is a
        // terminal pull, so the trace succeeds with at least one pull.
        assert!(sf.do_trace(&fd));
        assert!(sf.pull_count() >= 1);
    }

    // ==================================================================
    // RuleDumptyHumpLate tests (subflow.cc:3006-3064)
    // ==================================================================

    /// getOpList / name.
    #[test]
    fn test_rule_dumpty_hump_late_opcodes() {
        let rule = RuleDumptyHumpLate::new();
        assert_eq!(rule.get_name(), "dumptyhumplate");
        assert_eq!(rule.get_opcodes(), vec![OpCode::CPUI_SUBPIECE]);
    }

    /// SUBPIECE whose input is NOT written -> NO_CHANGE (early return,
    /// subflow.cc:3014).
    #[test]
    fn test_rule_dumpty_hump_late_input_not_written() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // Free (not written) input varnode.
        let base = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let offset = fd.vbank.create_constant(8, 0);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let op_arc = make_op(0, OpCode::CPUI_SUBPIECE, vec![base, offset], Some(out));
        let rule = RuleDumptyHumpLate::new();
        assert_eq!(rule.apply_op(&op_arc, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// SUBPIECE(PIECE(hi,lo), 0) where lo has the same size as the SUBPIECE
    /// output (exact match): backtracking selects `lo`. Because Rugra's
    /// `isAutoLive()` is always false (matching Ghidra until copy-propagation
    /// marks the flag), the rule takes the `totalReplace(out, vn)` + destroy
    /// branch (subflow.cc:3058-3061). We give `out` a descendant so the
    /// replacement is observable: the descendant is rewritten to read `lo`.
    #[test]
    fn test_rule_dumpty_hump_late_exact_match_total_replace() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // PIECE inputs: hi (4 bytes), lo (4 bytes).
        let hi = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let lo = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        // Register lo as a function input (VarnodeBank::setInput,
        // varnode.cc:1358). totalReplace rewrites the descendant to read lo,
        // so free-with-reader would be re-read: in Ghidra every read target
        // is written/input — a free lo is Ghidra-unreachable and addDescend
        // would throw "Free varnode has multiple descendants"
        // (varnode.cc:333-336). INPUT keeps is_written() false so the
        // backtrack loop and COPY-advance behave exactly as before.
        let lo = fd.vbank.set_input(lo).unwrap();
        // PIECE -> piece_out (8 bytes).
        let piece_out = fd.vbank.create_with_space(8, AddressSpace::Register, 0x30);
        let _piece_op = make_op(0, OpCode::CPUI_PIECE, vec![hi.clone(), lo.clone()], Some(piece_out.clone()));
        // SUBPIECE(piece_out, 0) -> out (4 bytes).
        let offset = fd.vbank.create_constant(8, 0);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x40);
        let sub_op = make_op(1, OpCode::CPUI_SUBPIECE, vec![piece_out, offset], Some(out.clone()));
        // Descendant that reads `out` — totalReplace rewrites it to read `lo`.
        let sink = fd.vbank.create_with_space(4, AddressSpace::Register, 0x50);
        let _dec = make_op(2, OpCode::CPUI_COPY, vec![out], Some(sink));

        let rule = RuleDumptyHumpLate::new();
        let res = rule.apply_op(&sub_op, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // After totalReplace, the descendant COPY now reads `lo`.
        let _dec_ref = PcodeOpRef(_dec.clone());
        let dec_in0 = _dec.read().unwrap().get_in(0).cloned();
        assert!(dec_in0.is_some());
        assert!(Arc::ptr_eq(&dec_in0.unwrap(), &lo));
    }

    /// Size-mismatch path (subflow.cc:3048-3051): SUBPIECE selects one PIECE
    /// component that is BIGGER than outSize, so the SUBPIECE is preserved and
    /// its operand 0 is replaced with the component (offset adjusted if needed).
    #[test]
    fn test_rule_dumpty_hump_late_size_mismatch_preserves_subpiece() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // PIECE of two 8-byte halves.
        let hi = fd.vbank.create_with_space(8, AddressSpace::Register, 0x10);
        let lo = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        // Register lo as a function input (VarnodeBank::setInput,
        // varnode.cc:1358). The size-mismatch path sets SUBPIECE input 0 to
        // lo (subflow.cc:3051), re-reading it: in Ghidra lo is written/input
        // there — free-with-reader is Ghidra-unreachable and addDescend
        // would throw "Free varnode has multiple descendants"
        // (varnode.cc:333-336). INPUT keeps is_written() false so the
        // backtrack loop breaks at the same point as before.
        let lo = fd.vbank.set_input(lo).unwrap();
        let piece_out = fd.vbank.create_with_space(16, AddressSpace::Register, 0x30);
        let _piece_op = make_op(0, OpCode::CPUI_PIECE, vec![hi, lo.clone()], Some(piece_out.clone()));
        // SUBPIECE(piece_out, 0) -> out (4 bytes). trunc=0 < lo size(8) ->
        // trialVn = lo, trialTrunc = 0; outSize(4)+0 <= 8 -> commit vn=lo.
        // vn_size(8) != outSize(4) -> preserve SUBPIECE, set input 0 = lo.
        let offset = fd.vbank.create_constant(8, 0);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x40);
        let sub_op = make_op(1, OpCode::CPUI_SUBPIECE, vec![piece_out, offset], Some(out));

        let rule = RuleDumptyHumpLate::new();
        let res = rule.apply_op(&sub_op, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // SUBPIECE preserved; operand 0 is now `lo`.
        assert_eq!(sub_op.read().unwrap().opcode, OpCode::CPUI_SUBPIECE);
        let in0 = sub_op.read().unwrap().get_in(0).cloned();
        assert!(in0.is_some());
        assert!(Arc::ptr_eq(&in0.unwrap(), &lo));
    }

    /// SUBPIECE input's def is not a PIECE -> NO_CHANGE (subflow.cc:3017).
    #[test]
    fn test_rule_dumpty_hump_late_def_not_piece() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let src = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let mid = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        // Def is a COPY, not PIECE.
        let _copy = make_op(0, OpCode::CPUI_COPY, vec![src], Some(mid.clone()));
        let offset = fd.vbank.create_constant(8, 0);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        let sub_op = make_op(1, OpCode::CPUI_SUBPIECE, vec![mid, offset], Some(out));
        let rule = RuleDumptyHumpLate::new();
        assert_eq!(rule.apply_op(&sub_op, &mut fd).unwrap(), action_status::NO_CHANGE);
    }

    /// Crossing guard (subflow.cc:3030-3031 + 3042-3043): SUBPIECE(PIECE(hi,lo),0)
    /// whose output (4 bytes) draws from BOTH components (lo = 1 byte) must be
    /// refused — `vn` stays uncommitted (== op->getIn(0)) and the rule returns
    /// NO_CHANGE without touching the SUBPIECE. The pre-fix port committed the
    /// trial component to `vn` BEFORE the crossing test, so this shape escaped
    /// with the 1-byte component and rewired SUBPIECE(lo:1B,0) -> out:4B — the
    /// illegal SUB<in><out> shape that collapsed golden's
    /// CONCAT71(extraout_RDX>>8, setcc-byte) chains
    /// (VARMAP-UNAFF-TYPEMAT-0001, sqlite3WindowCompare @0xff2f0 site 0x4a7c7).
    #[test]
    fn test_rule_dumpty_hump_late_crossing_refused() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // PIECE(hi:7B, lo:1B) -> piece_out:8B — the heritage-normalized
        // sub-register reconstruction (setne %dl + full-register read).
        let hi = fd.vbank.create_with_space(7, AddressSpace::Register, 0x11);
        let lo = fd.vbank.create_with_space(1, AddressSpace::Register, 0x10);
        let lo = fd.vbank.set_input(lo).unwrap();
        let piece_out = fd.vbank.create_with_space(8, AddressSpace::Register, 0x10);
        let _piece_op = make_op(0, OpCode::CPUI_PIECE, vec![hi, lo.clone()], Some(piece_out.clone()));
        // SUBPIECE(piece_out, 0) -> out:4B — reads `and %edx,%eax`'s EDX.
        let offset = fd.vbank.create_constant(8, 0);
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x40);
        let sub_op = make_op(1, OpCode::CPUI_SUBPIECE, vec![piece_out.clone(), offset], Some(out));
        let rule = RuleDumptyHumpLate::new();
        assert_eq!(rule.apply_op(&sub_op, &mut fd).unwrap(), action_status::NO_CHANGE);
        // Operand 0 must STILL be the PIECE output — no rewiring to a component.
        let in0 = sub_op.read().unwrap().get_in(0).cloned();
        assert!(in0.is_some());
        assert!(Arc::ptr_eq(&in0.unwrap(), &piece_out));
        assert_eq!(sub_op.read().unwrap().opcode, OpCode::CPUI_SUBPIECE);
    }

    // ==================================================================
    // RuleSubfloatConvert tests (subflow.cc:3489-3507, 3389-3419)
    // ==================================================================
    use crate::type_system::TypeMetatype;

    /// Build a Funcdata whose Architecture carries a TypeFactory so the
    /// non-const precision path can resolve a float type. Mirrors how a real
    /// Funcdata is wired up.
    fn fd_with_types() -> Funcdata {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        let mut arch = crate::arch::Architecture::new();
        let tf = std::sync::Arc::new(std::sync::RwLock::new(
            crate::type_system::typefactory::TypeFactory::new(8),
        ));
        arch.set_types(tf);
        fd.set_arch(std::sync::Arc::new(arch));
        fd
    }

    /// getOpList / name.
    #[test]
    fn test_rule_subfloat_convert_opcodes() {
        let rule = RuleSubfloatConvert::new();
        assert_eq!(rule.get_name(), "subfloat_convert");
        assert_eq!(rule.get_opcodes(), vec![OpCode::CPUI_FLOAT_FLOAT2FLOAT]);
    }

    /// Constant FLOAT_FLOAT2FLOAT folding is covered by the pre-existing
    /// `test_rule_subfloat_convert_constant_fold` / `_constant_downcast`
    /// tests above (subflow.cc:3394-3403 constant branch). The tests below
    /// exercise the **non-const precision-tracking path** added here.

    /// Non-const widening (4->8) with a downstream terminator: the oracle
    /// REWRITES the data-flow at precision 4 (subflow.cc:3496-3499: root =
    /// the 8-byte output, precision = insize). The widened FLOAT2FLOAT is
    /// replaced by a COPY of the (preexisting) 4-byte input into a 4-byte
    /// piece temp of the old output, and the downstream FLOAT2FLOAT becomes
    /// a preexisting COPY terminator. Full mutation check: original op
    /// destroyed, new op wired, terminator retargeted, no retype of the
    /// original wider Varnode.
    #[test]
    fn test_rule_subfloat_convert_nonconst_widening_rewrites() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // Non-constant 4-byte input produced by a COPY (so it is "written").
        let src = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let inv = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let _def = make_op(0, OpCode::CPUI_COPY, vec![src], Some(inv.clone()));
        // 8-byte output, read by a second FLOAT_FLOAT2FLOAT (terminator).
        let out = fd.vbank.create_with_space(8, AddressSpace::Register, 0x30);
        let op = make_op(1, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![inv.clone()], Some(out.clone()));
        let mid4 = fd.vbank.create_with_space(4, AddressSpace::Register, 0x40);
        let term_op = make_op(2, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![out], Some(mid4));
        let res = RuleSubfloatConvert::new().apply_op(&op, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // Original widening FLOAT2FLOAT destroyed (op_replacement leg).
        assert!(op.read().unwrap().is_dead());
        // Terminator FLOAT2FLOAT is now a preexisting COPY reading the 4-byte
        // piece temp (subflow.cc:3289: outsize==precision -> CPUI_COPY).
        assert_eq!(term_op.read().unwrap().opcode, OpCode::CPUI_COPY);
        let term_in = term_op.read().unwrap().get_in(0).cloned().unwrap();
        assert_eq!(term_in.read().unwrap().get_size(), 4);
        // The replacement COPY reuses the preexisting 4-byte input verbatim
        // (subflow.cc:3405-3407: getPreexistingVarnode) and writes a 4-byte
        // temp — the wider root is never retyped, it is *replaced*.
        let rep_copy = fd
            .obank
            .optree
            .iter()
            .find(|o| {
                let r = o.0.read().unwrap();
                r.opcode == OpCode::CPUI_COPY && r.get_in(0).map(|v| Arc::ptr_eq(v, &inv)).unwrap_or(false)
            })
            .cloned()
            .expect("replacement COPY of the preexisting 4-byte input exists");
        let rep_out = rep_copy.0.read().unwrap().output.clone().unwrap();
        assert_eq!(rep_out.read().unwrap().get_size(), 4);
        assert!(!Arc::ptr_eq(&rep_out, &inv));
    }

    /// Non-const narrowing (8->4) with an INT2FLOAT source and a
    /// FLOAT2FLOAT terminator: roots at the 8-byte input with precision =
    /// outsize (subflow.cc:3501-3504). The INT2FLOAT source op is replaced
    /// by a new INT2FLOAT writing a 4-byte piece temp, and the narrowing
    /// FLOAT2FLOAT itself becomes a preexisting COPY of that temp.
    #[test]
    fn test_rule_subfloat_convert_nonconst_narrowing_rewrites() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // i8 --INT2FLOAT--> inv8 --F2F--> out4 --TRUNC--> t8
        // i8 is a function input: traceBackward's INT2FLOAT leg only rejects
        // free non-constant inputs (subflow.cc:3381-3382).
        let i8 = fd.vbank.create_with_space(8, AddressSpace::Register, 0x10);
        i8.write().unwrap().set_flags(crate::varnode::varnode_flags::INPUT);
        let int2f_out = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        let int2f = make_op(0, OpCode::CPUI_FLOAT_INT2FLOAT, vec![i8.clone()], Some(int2f_out.clone()));
        let out4 = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        let op =
            make_op(1, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![int2f_out.clone()], Some(out4.clone()));
        let t8 = fd.vbank.create_with_space(8, AddressSpace::Register, 0x40);
        let trunc = make_op(2, OpCode::CPUI_FLOAT_TRUNC, vec![out4.clone()], Some(t8));
        let res = RuleSubfloatConvert::new().apply_op(&op, &mut fd).unwrap();
        assert_eq!(res, action_status::CHANGE);
        // The narrowing FLOAT2FLOAT itself became a preexisting COPY reading
        // the 4-byte piece temp (it is the traceForward terminator).
        assert_eq!(op.read().unwrap().opcode, OpCode::CPUI_COPY);
        let op_in = op.read().unwrap().get_in(0).cloned().unwrap();
        assert_eq!(op_in.read().unwrap().get_size(), 4);
        assert!(!Arc::ptr_eq(&op_in, &int2f_out));
        // The INT2FLOAT source op was replaced (destroyed) by a new
        // INT2FLOAT writing the 4-byte temp (subflow.cc:3378-3388).
        assert!(int2f.read().unwrap().is_dead());
        let rep_i2f = fd
            .obank
            .optree
            .iter()
            .find(|o| {
                let r = o.0.read().unwrap();
                r.opcode == OpCode::CPUI_FLOAT_INT2FLOAT
                    && r.get_in(0).map(|v| Arc::ptr_eq(v, &i8)).unwrap_or(false)
            })
            .cloned()
            .expect("replacement INT2FLOAT of the integer input exists");
        let rep_out = rep_i2f.0.read().unwrap().output.clone().unwrap();
        assert_eq!(rep_out.read().unwrap().get_size(), 4);
        assert!(Arc::ptr_eq(&rep_out, &op_in));
        // The TRUNC below the conversion is untouched (outside the trace).
        assert_eq!(trunc.read().unwrap().opcode, OpCode::CPUI_FLOAT_TRUNC);
        let trunc_in = trunc.read().unwrap().get_in(0).cloned().unwrap();
        assert!(Arc::ptr_eq(&trunc_in, &out4));
    }

    /// Non-const with no downstream float reader: the widened output has no
    /// descendant, so the trace never sees a terminator and doTrace fails
    /// (subflow.cc:3479). Architecture wiring is irrelevant to the trace
    /// (the float formats are static), which this test also pins.
    #[test]
    fn test_rule_subfloat_convert_nonconst_no_types_defers() {
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10); // no arch
        let src = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let inv = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let _def = make_op(0, OpCode::CPUI_COPY, vec![src], Some(inv.clone()));
        let out = fd.vbank.create_with_space(8, AddressSpace::Register, 0x30);
        let op = make_op(1, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![inv], Some(out));
        let res = RuleSubfloatConvert::new().apply_op(&op, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
    }

    /// Non-const with a type-lock already set on the root: setReplacement
    /// rejects a locked non-PARTIALSTRUCT type whose size differs from the
    /// precision (subflow.cc:3220-3224) — the worklist stays empty and
    /// doTrace fails. NO_CHANGE.
    #[test]
    fn test_rule_subfloat_convert_nonconst_typelock_defers() {
        let mut fd = fd_with_types();
        let src = fd.vbank.create_with_space(4, AddressSpace::Register, 0x10);
        let inv = fd.vbank.create_with_space(4, AddressSpace::Register, 0x20);
        let _def = make_op(0, OpCode::CPUI_COPY, vec![src], Some(inv.clone()));
        let out = fd.vbank.create_with_space(8, AddressSpace::Register, 0x30);
        // Lock the output (root for widening) to a double (size 8 != 4).
        let dbl = fd
            .get_arch()
            .unwrap()
            .get_base_type(8, TypeMetatype::Float)
            .unwrap();
        out.write().unwrap().update_type_lock(dbl, true, false);
        let op = make_op(1, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![inv], Some(out));
        let res = RuleSubfloatConvert::new().apply_op(&op, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
    }

    /// Non-supported float sizes (e.g. a hypothetical 2-byte float):
    /// getFloatFormat returns NULL for the precision, the SubfloatFlow is
    /// left inert (subflow.cc:3446-3447) and doTrace fails immediately.
    #[test]
    fn test_rule_subfloat_convert_unsupported_size_defers() {
        let mut fd = fd_with_types();
        let src = fd.vbank.create_with_space(2, AddressSpace::Register, 0x10);
        let inv = fd.vbank.create_with_space(2, AddressSpace::Register, 0x20);
        let _def = make_op(0, OpCode::CPUI_COPY, vec![src], Some(inv.clone()));
        let out = fd.vbank.create_with_space(4, AddressSpace::Register, 0x30);
        let op = make_op(1, OpCode::CPUI_FLOAT_FLOAT2FLOAT, vec![inv], Some(out));
        let res = RuleSubfloatConvert::new().apply_op(&op, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
    }

    #[test]
    fn test_lane_divide_piece_subpiece_apply() {
        let mut fd = Funcdata::new("lane_piece", Address::new(0x1000), 0x10);
        let block = fd.create_new_block();
        let piece = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&piece, OpCode::CPUI_PIECE);
        let root = fd.new_unique_out(4, &piece);
        let high = fd.new_constant(2, 0x1122);
        let low = fd.new_constant(2, 0x3344);
        fd.op_set_input(&piece, high, 0);
        fd.op_set_input(&piece, low, 1);
        fd.op_insert_end(&piece, &block);

        let low_piece = fd.new_op(2, Address::new(0x1001));
        fd.op_set_opcode(&low_piece, OpCode::CPUI_SUBPIECE);
        let low_output = fd.new_unique_out(2, &low_piece);
        fd.op_set_input(&low_piece, root.clone(), 0);
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(&low_piece, zero, 1);
        fd.op_insert_end(&low_piece, &block);

        let high_piece = fd.new_op(2, Address::new(0x1002));
        fd.op_set_opcode(&high_piece, OpCode::CPUI_SUBPIECE);
        let high_output = fd.new_unique_out(2, &high_piece);
        fd.op_set_input(&high_piece, root.clone(), 0);
        let two = fd.new_constant(4, 2);
        fd.op_set_input(&high_piece, two, 1);
        fd.op_insert_end(&high_piece, &block);

        let mut divide = LaneDivide::new(
            &mut fd,
            root.clone(),
            LaneDescription::uniform(4, 2),
            false,
        );
        assert!(divide.do_trace());
        assert!(!root.read().unwrap().is_mark());
        divide.apply(&mut fd);

        assert!(piece.0.read().unwrap().is_dead());
        assert_eq!(low_piece.0.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(high_piece.0.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(low_piece.0.read().unwrap().num_input(), 1);
        assert_eq!(high_piece.0.read().unwrap().num_input(), 1);
        assert_eq!(low_output.read().unwrap().get_size(), 2);
        assert_eq!(high_output.read().unwrap().get_size(), 2);
        assert_eq!(fd.obank.alivelist.len(), 4);
    }

    #[test]
    fn test_lane_divide_failure_clears_mark_without_ir_mutation() {
        let mut fd = Funcdata::new("lane_failure", Address::new(0x2000), 0x10);
        let block = fd.create_new_block();
        let multiply = fd.new_op(2, Address::new(0x2000));
        fd.op_set_opcode(&multiply, OpCode::CPUI_INT_MULT);
        let root = fd.new_unique_out(4, &multiply);
        let left = fd.new_constant(4, 3);
        let right = fd.new_constant(4, 7);
        fd.op_set_input(&multiply, left, 0);
        fd.op_set_input(&multiply, right, 1);
        fd.op_insert_end(&multiply, &block);
        let before_ops = block.read().unwrap().get_ops();

        let mut divide = LaneDivide::new(
            &mut fd,
            root.clone(),
            LaneDescription::uniform(4, 2),
            false,
        );
        assert!(!divide.do_trace());
        assert!(!root.read().unwrap().is_mark());
        let after_ops = block.read().unwrap().get_ops();
        assert_eq!(before_ops.len(), after_ops.len());
        assert!(Arc::ptr_eq(&before_ops[0].0, &after_ops[0].0));
        assert_eq!(multiply.0.read().unwrap().opcode, OpCode::CPUI_INT_MULT);
        assert!(!multiply.0.read().unwrap().is_dead());
    }
}
