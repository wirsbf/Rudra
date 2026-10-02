//! Union resolution — faithful port of `unionresolve.hh` / `unionresolve.cc`
//! (1110 lines).
//!
//! Analysis for resolving which field of a union data-type is being accessed
//! at a specific point in the data-flow. `ScoreUnionFields` scores all
//! possible fields of a union for a specific Varnode access edge.
//!
//! The full Ghidra scoring algorithm is implemented as the typed
//! [`ScoreUnionFields`] API, which threads `Arc<Datatype>`,
//! `Arc<RwLock<PcodeOp>>`, and `Arc<RwLock<Varnode>>` exactly as Ghidra
//! threads raw `Datatype*`/`PcodeOp*`/`Varnode*`. The TypeFactory is held
//! as `Arc<RwLock<TypeFactory>>` — the mutable twin of Ghidra's
//! `TypeFactory&` — because the scoring interning arms
//! (`getTypePointerStripArray` cc:1022, `downChain` cc:435,
//! `getTypePointer` cc:665) mutate the factory. The scoring tables in
//! [`score_trial_down`](ScoreUnionFields::score_trial_down) and
//! [`score_trial_up`](ScoreUnionFields::score_trial_up) are 1:1 with
//! unionresolve.cc:305-833.
//!
//! Pipeline producers (wired 2026-09-23, UNIONRESOLVE-PIPELINE-WIRING-0001):
//! four call sites populate `Funcdata::union_map` via `setUnionField`, all
//! routing through `resolve_in_flow` below — `ActionSetCasts::resolveUnion`
//! (coreaction.cc:2499 → coreaction.rs `resolve_union`), `castOutput`
//! (coreaction.cc:2556 → coreaction.rs), the typeprop driver
//! (coreaction.cc:5083 → coreaction.rs), and `RulePieceStructure`
//! (ruleaction.cc:7678 → ruleaction.rs). The oracle entry points
//! `TypePointer::resolveInFlow`/`TypeUnion::resolveInFlow` (type.cc:1177 /
//! type.cc:2125) are mirrored as the fd-aware free functions in the
//! "Pipeline wiring" section below; `varnode.rs` keeps the degenerate
//! map-miss forms of varnode.cc:626-672 (EJ2 write-domain lease), with the
//! fd-aware twins `vn_type_read_facing`/`vn_type_def_facing`/
//! `vn_high_type_read_facing`/`vn_high_type_def_facing` living here.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/unionresolve.{hh,cc}.

use std::sync::{Arc, RwLock};

use crate::op::{PcodeOp, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::type_system::datatype::{Datatype, TypeField, TypeMetatype, TypeUnion};
use crate::type_system::TypeFactory;
use crate::varnode::Varnode;

// ===========================================================================
// ResolvedUnion — unionresolve.hh:39 / unionresolve.cc:25
// ===========================================================================

/// A data-type \e resolved from an associated TypeUnion or TypeStruct.
/// Faithful to `ResolvedUnion` (unionresolve.hh:39).
#[derive(Debug, Clone)]
pub struct ResolvedUnion {
    /// The resolved data-type (Ghidra `resolve`).
    pub resolve: Arc<Datatype>,
    /// Union or Structure being resolved (Ghidra `baseType`).
    pub base_type: Arc<Datatype>,
    /// Index of field referenced by `resolve`, or -1 for the whole union.
    pub field_num: i32,
    /// If true, resolution cannot be overridden.
    pub lock: bool,
}

impl ResolvedUnion {
    // Ghidra: unionresolve.cc:25 ResolvedUnion::ResolvedUnion(Datatype*)
    /// Construct a data-type that resolves to itself. Faithful to the
    /// constructor `ResolvedUnion::ResolvedUnion(Datatype *parent)`
    /// (unionresolve.hh:46). The base type is the parent with any pointer
    /// layer stripped (cc:29-30); `field_num` is -1.
    pub fn new(parent: Arc<Datatype>) -> Self {
        let base_type = strip_pointer_layer(&parent);
        Self { resolve: parent, base_type, field_num: -1, lock: false }
    }

    // Ghidra: unionresolve.cc:40 ResolvedUnion::ResolvedUnion(Datatype*,int4,TypeFactory&)
    /// Construct a reference to a specific field. Faithful to
    /// `ResolvedUnion::ResolvedUnion(Datatype *parent,int4 fldNum,
    /// TypeFactory &typegrp)` (unionresolve.hh:47), including the cc:43-44
    /// PARTIALUNION unwrap and the cc:51-55 pointer-parent arm (resolve is a
    /// POINTER to the field, sized by the parent pointer). The pointer is
    /// interned through [`TypeFactory::get_type_pointer`] (type.cc:3867
    /// `findAdd` canonicalization + one `getStripped` step on the pointee),
    /// so the resolve Arc is factory-owned exactly as Ghidra's returned
    /// `Datatype*` is: downstream `Arc::ptr_eq` identity comparisons —
    /// cast.cc:303-304 `castStandard`'s `curtype == reqtype` no-cast
    /// short-circuit and the facing/lock identity family — hit against
    /// pointers minted by any other `get_type_pointer` call site.
    pub fn with_field(parent: Arc<Datatype>, fld_num: i32, typegrp: &mut TypeFactory) -> Self {
        // cc:43-44: a partial-union parent resolves within its container.
        let unwrapped;
        let parent = match parent.as_ref() {
            Datatype::PartialUnion(pu) => {
                unwrapped = pu.container.clone();
                &unwrapped
            }
            _ => &parent,
        };
        let base_type = parent.clone();
        let resolve = if fld_num < 0 {
            parent.clone()
        } else {
            match parent.as_ref() {
                // cc:51-55: field = ptrTo->getDepend(fldNum); resolve =
                // typegrp.getTypePointer(parent.size, field, wordSize).
                Datatype::Pointer(pointer) => {
                    let field = get_depend(pointer.ptr_to.as_ref(), fld_num as usize);
                    typegrp.get_type_pointer(parent.get_size(), field, pointer.wordsize)
                }
                _ => get_depend(parent.as_ref(), fld_num as usize),
            }
        };
        Self { resolve, base_type, field_num: fld_num, lock: false }
    }

    // RUDRA-GLUE: Stringly-typed constructor for callers that only have a
    //   type name and cannot readily produce an Arc<Datatype>. Not present in
    //   Ghidra; included so existing Rudra call-sites keep compiling.
    pub fn new_self(parent_name: &str) -> Self {
        let parent = name_placeholder(parent_name);
        Self::new(parent)
    }

    // RUDRA-GLUE: Stringly-typed field constructor. See `new_self`.
    pub fn new_field(parent_name: &str, field_name: &str, fld_num: i32) -> Self {
        let parent = name_placeholder(parent_name);
        let base_type = parent.clone();
        Self { resolve: name_placeholder(field_name), base_type, field_num: fld_num, lock: false }
    }

    // Ghidra: unionresolve.hh:48 ResolvedUnion::getDatatype
    /// Get the resolved data-type. Faithful to `getDatatype`.
    pub fn get_datatype(&self) -> &Arc<Datatype> { &self.resolve }

    // Ghidra: unionresolve.hh:49 ResolvedUnion::getBase
    /// Get the union or structure being referenced. Faithful to `getBase`.
    pub fn get_base(&self) -> &Arc<Datatype> { &self.base_type }

    // Ghidra: unionresolve.hh:50 ResolvedUnion::getFieldNum
    /// Get the index of the resolved field or -1. Faithful to `getFieldNum`.
    pub fn get_field_num(&self) -> i32 { self.field_num }

    // Ghidra: unionresolve.hh:51 ResolvedUnion::isLocked
    /// Is this locked against overrides? Faithful to `isLocked`.
    pub fn is_locked(&self) -> bool { self.lock }

    // Ghidra: unionresolve.hh:52 ResolvedUnion::setLock
    /// Set whether this resolution is locked. Faithful to `setLock`.
    pub fn set_lock(&mut self, val: bool) { self.lock = val; }

    // RUDRA-GLUE: name-based view of `resolve`. See `new_self`.
    pub fn get_datatype_name(&self) -> &str { self.resolve.get_name() }

    // RUDRA-GLUE: name-based view of `baseType`. See `new_self`.
    pub fn get_base_name(&self) -> &str { self.base_type.get_name() }
}

// ===========================================================================
// ResolveEdge — unionresolve.hh:60 / unionresolve.cc:64 / inline op< :172
// ===========================================================================

/// A data-flow edge to which a resolved data-type can be assigned. Faithful
/// to `ResolveEdge` (unionresolve.hh:60).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveEdge {
    /// Id of base data-type being resolved (cc:61).
    pub type_id: u64,
    /// Immutable id of the PcodeOp edge — `SeqNum::time` (cc:62).
    pub op_time: u32,
    /// Encoding of the slot and pointer-ness (cc:63).
    pub encoding: i32,
}

impl ResolveEdge {
    // Ghidra: unionresolve.cc:64 ResolveEdge::ResolveEdge
    /// Construct from a parent data-type, a PcodeOp, and a slot. Faithful to
    /// `ResolveEdge::ResolveEdge(const Datatype *parent,const PcodeOp *op,
    /// int4 slot)` (unionresolve.hh:65).
    pub fn new(parent: &Datatype, op: &PcodeOp, slot: i32) -> Self {
        let op_time = op.get_time();
        let mut encoding = slot;
        let type_id = match parent.get_metatype() {
            TypeMetatype::Pointer => {
                let pointee = pointee_of(parent);
                encoding += 0x1000;
                pointee.get_id()
            }
            // cc:73-74: a partial union keys by its container union id (the
            // encoding is NOT bumped, unlike the pointer arm).
            TypeMetatype::PartialUnion => match parent {
                Datatype::PartialUnion(pu) => pu.container.get_id(),
                _ => unreachable!("metatype PartialUnion without PartialUnion"),
            },
            _ => parent.get_id(),
        };
        Self { type_id, op_time, encoding }
    }

    // RUDRA-GLUE: Component-wise constructor for tests/edge cases that already
    //   hold the resolved fields. Mirrors the Ghidra struct layout directly.
    pub fn from_components(type_id: u64, op_time: u32, slot: i32, is_pointer: bool) -> Self {
        let encoding = if is_pointer { slot + 0x1000 } else { slot };
        Self { type_id, op_time, encoding }
    }
}

impl PartialOrd for ResolveEdge {
    // Ghidra: unionresolve.hh:172 ResolveEdge::operator<
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ResolveEdge {
    // Ghidra: unionresolve.hh:172 ResolveEdge::operator<
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.type_id
            .cmp(&other.type_id)
            .then_with(|| self.encoding.cmp(&other.encoding))
            .then_with(|| self.op_time.cmp(&other.op_time))
    }
}

// ===========================================================================
// Trial — unionresolve.hh:84
// ===========================================================================

/// Direction of trial fit. Faithful to `dir_type` (unionresolve.hh:87).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirType {
    /// Push the fit down \e with the data-flow (cc:88 `fit_down`).
    FitDown,
    /// Push the fit up \e against the data-flow (cc:89 `fit_up`).
    FitUp,
}

/// A trial data-type fitted to a specific place in the data-flow. Faithful
/// to `ScoreUnionFields::Trial` (unionresolve.hh:84).
#[derive(Debug, Clone)]
pub struct Trial {
    /// The Varnode we are testing for data-type fit (cc:91 `vn`).
    pub vn: Arc<RwLock<Varnode>>,
    /// The PcodeOp reading the Varnode, or `None` for an upward trial (cc:92).
    pub op: Option<Arc<RwLock<PcodeOp>>>,
    /// The slot reading the Varnode, or -1 (cc:93 `inslot`).
    pub in_slot: i32,
    /// Direction to push fit (cc:94 `direction`).
    pub direction: DirType,
    /// Field can be accessed as an array (cc:95 `array`).
    pub is_array: bool,
    /// The putative data-type of the Varnode (cc:96 `fitType`).
    pub fit_type: Arc<Datatype>,
    /// The original field being scored by this trial (cc:97 `scoreIndex`).
    pub score_index: i32,
}

impl Trial {
    // Ghidra: unionresolve.hh:106 Trial::Trial(PcodeOp*,int4,Datatype*,int4,bool)
    /// Construct a downward trial for a Varnode being read. Faithful to the
    /// downward constructor (unionresolve.hh:106-107).
    pub fn new_down(
        op: Arc<RwLock<PcodeOp>>, slot: i32, ct: Arc<Datatype>, index: i32, is_array: bool,
    ) -> Self {
        let vn = {
            let op_rg = op.read().unwrap();
            op_rg.get_in(slot as usize).cloned().expect("Trial::new_down: slot out of range")
        };
        Self { vn, op: Some(op), in_slot: slot, direction: DirType::FitDown,
            is_array, fit_type: ct, score_index: index }
    }

    // Ghidra: unionresolve.hh:115 Trial::Trial(Varnode*,Datatype*,int4,bool)
    /// Construct an upward trial for a Varnode. Faithful to the upward
    /// constructor (unionresolve.hh:115-116).
    pub fn new_up(vn: Arc<RwLock<Varnode>>, ct: Arc<Datatype>, index: i32, is_array: bool) -> Self {
        Self { vn, op: None, in_slot: -1, direction: DirType::FitUp,
            is_array, fit_type: ct, score_index: index }
    }
}

// ===========================================================================
// VisitMark — unionresolve.hh:120
// ===========================================================================

/// A mark accumulated when a given Varnode is visited with a specific field
/// index. Faithful to `VisitMark` (unionresolve.hh:120).
#[derive(Debug, Clone)]
pub struct VisitMark {
    /// Varnode reached by the trial field (cc:121 `vn`). Stored as the Arc
    /// pointer address so the mark is `PartialEq + Ord`.
    pub vn_key: usize,
    /// Index of the trial field (cc:122 `index`).
    pub index: i32,
}

impl VisitMark {
    // Ghidra: unionresolve.hh:122 VisitMark::VisitMark
    /// Construct from a Varnode handle and field index. Faithful to the
    /// constructor (unionresolve.hh:124).
    pub fn new(vn: &Arc<RwLock<Varnode>>, index: i32) -> Self {
        Self { vn_key: Arc::as_ptr(vn) as usize, index }
    }

    // RUDRA-GLUE: Component-wise constructor for the legacy tests.
    pub fn from_id(vn_id: u64, index: i32) -> Self {
        Self { vn_key: vn_id as usize, index }
    }
}

impl PartialEq for VisitMark {
    // RUDRA-GLUE: Rust Ord requires PartialEq; Ghidra defines only the
    // component-wise VisitMark::operator< ordering at unionresolve.hh:130.
    fn eq(&self, other: &Self) -> bool { self.vn_key == other.vn_key && self.index == other.index }
}
impl Eq for VisitMark {}
impl PartialOrd for VisitMark {
    // RUDRA-GLUE: Rust Ord requires PartialOrd; this delegates to cmp(), which
    // implements Ghidra's VisitMark::operator< key order (vn, then index).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}
impl Ord for VisitMark {
    // Ghidra: unionresolve.hh:130 VisitMark::operator<
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.vn_key.cmp(&other.vn_key) {
            std::cmp::Ordering::Equal => self.index.cmp(&other.index),
            ord => ord,
        }
    }
}

// ===========================================================================
// Constants — unionresolve.cc:79-81
// ===========================================================================

/// Threshold of trials over which to cancel additional passes. Faithful to
/// `ScoreUnionFields::threshold` (unionresolve.cc:79).
pub const THRESHOLD: i32 = 256;

/// Maximum number of levels to score through. Faithful to
/// `ScoreUnionFields::maxPasses` (unionresolve.cc:80).
pub const MAX_PASSES: i32 = 6;

/// Maximum number of trials to evaluate. Faithful to
/// `ScoreUnionFields::maxTrials` (unionresolve.cc:81).
pub const MAX_TRIALS: i32 = 1024;

// ===========================================================================
// ScoreUnionFields — unionresolve.hh:82
// ===========================================================================

/// Analyze data-flow to resolve which field of a union data-type is being
/// accessed. Faithful to `ScoreUnionFields` (unionresolve.hh:82).
pub struct ScoreUnionFields<'t> {
    /// The factory containing data-types (cc:136 `typegrp`). Held as the
    /// shared mutable twin of Ghidra's `TypeFactory&`: the scoring interning
    /// arms mutate the factory in Ghidra (getTypePointerStripArray cc:1022,
    /// downChain cc:435, getTypePointer cc:665).
    pub typegrp: Arc<RwLock<TypeFactory>>,
    /// The function being scored, for the locked call-spec consults
    /// (scoreParameter cc:184 / scoreReturnType cc:204). Ghidra derives it
    /// from `op->getParent()->getFuncdata()`; Rudra PcodeOps carry no
    /// Funcdata back-pointer, so the caller threads it. `None` falls back to
    /// the unlocked-param heuristic arms of both scorers.
    pub fd: Option<&'t crate::funcdata::Funcdata>,
    /// Score for each field, indexed by `fieldNum + 1` (whole union is
    /// index 0) (cc:137 `scores`).
    pub scores: Vec<i32>,
    /// Field corresponding to each score (cc:138 `fields`).
    pub fields: Vec<Arc<Datatype>>,
    /// Places that have already been visited (cc:139 `visited`).
    pub visited: std::collections::BTreeSet<VisitMark>,
    /// Current trials being pushed (cc:140 `trialCurrent`).
    pub trial_current: Vec<Trial>,
    /// Next set of trials (cc:141 `trialNext`).
    pub trial_next: Vec<Trial>,
    /// The best result (cc:142 `result`).
    pub result: ResolvedUnion,
    /// Number of trials evaluated so far (cc:143 `trialCount`).
    pub trial_count: i32,
}

impl<'t> ScoreUnionFields<'t> {
    // Ghidra: unionresolve.cc:990 ScoreUnionFields::ScoreUnionFields(TypeFactory&,Datatype*,PcodeOp*,int4)
    /// Score a data-type involving a union against a data-flow edge.
    /// Faithful to the primary constructor (unionresolve.cc:990-1037).
    pub fn new(
        typegrp: Arc<RwLock<TypeFactory>>, parent_type: Arc<Datatype>,
        op: Arc<RwLock<PcodeOp>>, slot: i32,
        fd: Option<&'t crate::funcdata::Funcdata>,
    ) -> Self {
        let result = ResolvedUnion::new(parent_type.clone());
        {
            let op_rg = op.read().unwrap();
            if test_simple_cases(&op_rg, slot, parent_type.as_ref()) {
                return Self::empty(typegrp, result);
            }
        }
        let word_size = if parent_type.get_metatype() == TypeMetatype::Pointer {
            pointee_word_size(parent_type.as_ref())
        } else { 0 };
        let num_fields = num_depend(result.base_type.as_ref());
        let mut scores = vec![0i32; num_fields + 1];
        let mut fields: Vec<Arc<Datatype>> = vec![Arc::new(empty_placeholder()); num_fields + 1];
        let mut visited = std::collections::BTreeSet::new();
        let mut trial_current: Vec<Trial> = Vec::new();
        let vn = {
            let op_rg = op.read().unwrap();
            if slot < 0 { op_rg.get_out().cloned() } else { op_rg.get_in(slot as usize).cloned() }
        };
        let vn = vn.expect("ScoreUnionFields::new: op has no varnode at slot");
        {
            let vn_rg = vn.read().unwrap();
            if vn_rg.get_size() != parent_type.get_size() {
                scores[0] -= 10;
            } else {
                if slot < 0 {
                    trial_current.push(Trial::new_up(vn.clone(), parent_type.clone(), 0, false));
                } else {
                    trial_current.push(Trial::new_down(op.clone(), slot, parent_type.clone(), 0, false));
                }
            }
        }
        fields[0] = parent_type.clone();
        visited.insert(VisitMark::new(&vn, 0));
        for i in 0..num_fields {
            let mut field_type = get_depend(result.base_type.as_ref(), i);
            let mut is_array = false;
            if word_size != 0 {
                if field_type.get_metatype() == TypeMetatype::Array { is_array = true; }
                let mut tg = typegrp.write().unwrap();
                field_type = get_type_pointer_strip_array(
                    &mut tg, parent_type.get_size(), field_type, word_size);
            }
            let vn_size = vn.read().unwrap().get_size();
            if vn_size != field_type.get_size() {
                scores[i + 1] -= 10;
            } else if slot < 0 {
                trial_current.push(Trial::new_up(vn.clone(), field_type.clone(), (i + 1) as i32, is_array));
            } else {
                trial_current.push(Trial::new_down(op.clone(), slot, field_type.clone(), (i + 1) as i32, is_array));
            }
            fields[i + 1] = field_type;
            visited.insert(VisitMark::new(&vn, (i + 1) as i32));
        }
        let mut s = Self {
            typegrp, fd, scores, fields, visited, trial_current,
            trial_next: Vec::new(), result, trial_count: 0,
        };
        s.run_passes();
        s.compute_best_index();
        s
    }

    // Ghidra: unionresolve.cc:1050 ScoreUnionFields::ScoreUnionFields(TypeFactory&,TypeUnion*,int4,PcodeOp*)
    /// Score a union against a SUBPIECE truncation. Faithful to the
    /// SUBPIECE constructor (unionresolve.cc:1050-1072).
    pub fn new_for_subpiece(
        typegrp: Arc<RwLock<TypeFactory>>, union_type: Arc<Datatype>,
        offset: i64, op: Arc<RwLock<PcodeOp>>,
        fd: Option<&'t crate::funcdata::Funcdata>,
    ) -> Self {
        let result = ResolvedUnion::new(union_type.clone());
        let vn = {
            let op_rg = op.read().unwrap();
            op_rg.get_out().cloned().expect("ScoreUnionFields::new_for_subpiece: op has no output")
        };
        let (union_fields, num_fields) = union_field_list(union_type.as_ref());
        let mut scores = vec![0i32; num_fields + 1];
        let mut fields: Vec<Arc<Datatype>> = vec![Arc::new(empty_placeholder()); num_fields + 1];
        fields[0] = union_type.clone();
        scores[0] = -10;
        let mut s = Self {
            typegrp, fd, scores, fields,
            visited: std::collections::BTreeSet::new(),
            trial_current: Vec::new(), trial_next: Vec::new(),
            result, trial_count: 0,
        };
        let vn_size = vn.read().unwrap().get_size();
        for (i, uf) in union_fields.iter().enumerate() {
            s.fields[i + 1] = uf.type_ptr.clone();
            if uf.type_ptr.get_size() != vn_size || uf.offset as i64 != offset {
                s.scores[i + 1] = -10;
                continue;
            }
            s.new_trials_down(&vn, uf.type_ptr.clone(), (i + 1) as i32, false);
        }
        std::mem::swap(&mut s.trial_current, &mut s.trial_next);
        if s.trial_current.len() > 1 { s.run_passes(); }
        s.compute_best_index();
        s
    }

    // Ghidra: unionresolve.cc:1083 ScoreUnionFields::ScoreUnionFields(TypeFactory&,TypeUnion*,int4,PcodeOp*,int4)
    /// Score a union against an implied truncation at a data-flow edge.
    /// Faithful to the implied-truncation constructor (unionresolve.cc:1083-1108).
    pub fn new_for_implied_trunc(
        typegrp: Arc<RwLock<TypeFactory>>, union_type: Arc<Datatype>,
        offset: i64, op: Arc<RwLock<PcodeOp>>, slot: i32,
        fd: Option<&'t crate::funcdata::Funcdata>,
    ) -> Self {
        let result = ResolvedUnion::new(union_type.clone());
        let vn = {
            let op_rg = op.read().unwrap();
            if slot < 0 { op_rg.get_out().cloned() } else { op_rg.get_in(slot as usize).cloned() }
                .expect("ScoreUnionFields::new_for_implied_trunc: op has no varnode at slot")
        };
        let (union_fields, num_fields) = union_field_list(union_type.as_ref());
        let mut scores = vec![0i32; num_fields + 1];
        let mut fields: Vec<Arc<Datatype>> = vec![Arc::new(empty_placeholder()); num_fields + 1];
        fields[0] = union_type.clone();
        scores[0] = -10;
        let mut visited = std::collections::BTreeSet::new();
        let mut trial_current: Vec<Trial> = Vec::new();
        let vn_size = vn.read().unwrap().get_size();
        for (i, uf) in union_fields.iter().enumerate() {
            let field_offset = uf.offset as i64;
            let ct_opt = score_truncation_inplace(
                &mut scores, &uf.type_ptr, vn_size,
                offset - field_offset, (i + 1) as i32, &result.base_type);
            fields[i + 1] = uf.type_ptr.clone();
            if let Some(ct) = ct_opt {
                if slot < 0 {
                    trial_current.push(Trial::new_up(vn.clone(), ct, (i + 1) as i32, false));
                } else {
                    trial_current.push(Trial::new_down(op.clone(), slot, ct, (i + 1) as i32, false));
                }
                visited.insert(VisitMark::new(&vn, (i + 1) as i32));
            }
        }
        let mut s = Self {
            typegrp, fd, scores, fields, visited, trial_current,
            trial_next: Vec::new(), result, trial_count: 0,
        };
        if s.trial_current.len() > 1 { s.run_passes(); }
        s.compute_best_index();
        s
    }

    // RUDRA-GLUE: Minimal constructor for the legacy string-based tests and
    //   for callers that build the scores/fields vectors by hand.
    pub fn with_field_names(parent_name: &str, field_names: &[String]) -> Self {
        let parent = name_placeholder(parent_name);
        let mut fields: Vec<Arc<Datatype>> = Vec::with_capacity(field_names.len() + 1);
        fields.push(parent.clone());
        for n in field_names { fields.push(name_placeholder(n)); }
        let scores = vec![0i32; fields.len()];
        Self {
            typegrp: Arc::new(RwLock::new(TypeFactory::new(8))),
            fd: None, scores, fields,
            visited: std::collections::BTreeSet::new(),
            trial_current: Vec::new(), trial_next: Vec::new(),
            result: ResolvedUnion::new(parent), trial_count: 0,
        }
    }

    // RUDRA-GLUE: Construct an empty scorer holding just an initial result.
    fn empty(typegrp: Arc<RwLock<TypeFactory>>, result: ResolvedUnion) -> Self {
        Self {
            typegrp, fd: None, scores: Vec::new(), fields: Vec::new(),
            visited: std::collections::BTreeSet::new(),
            trial_current: Vec::new(), trial_next: Vec::new(),
            result, trial_count: 0,
        }
    }

    // Ghidra: unionresolve.hh:166 ScoreUnionFields::getResult
    /// Get the resulting best field resolution. Faithful to `getResult`.
    pub fn get_result(&self) -> &ResolvedUnion { &self.result }

    // RUDRA-GLUE: number of slots (whole union + N fields).
    pub fn num_fields(&self) -> usize { self.fields.len() }

    // RUDRA-GLUE: add to scores[index].
    pub fn add_score(&mut self, index: usize, score: i32) {
        if index < self.scores.len() { self.scores[index] += score; }
    }

    // Ghidra: unionresolve.cc:945 ScoreUnionFields::computeBestIndex
    /// Assuming scoring is complete, compute the best index. Faithful to
    /// `computeBestIndex` (unionresolve.cc:945-958).
    pub fn compute_best_index(&mut self) {
        if self.scores.is_empty() { return; }
        let mut best_idx = 0usize;
        let mut best_score = self.scores[0];
        for (i, &score) in self.scores.iter().enumerate().skip(1) {
            if score > best_score { best_score = score; best_idx = i; }
        }
        self.result.field_num = best_idx as i32 - 1;
        self.result.resolve = self.fields[best_idx].clone();
    }

    // Ghidra: unionresolve.cc:931 ScoreUnionFields::runOneLevel
    /// Run through each current trial and compute its score. Faithful to
    /// `runOneLevel` (unionresolve.cc:931-943).
    fn run_one_level(&mut self, last_pass: bool) {
        let current = std::mem::take(&mut self.trial_current);
        for trial in current {
            self.trial_count += 1;
            if self.trial_count > MAX_TRIALS { self.trial_current.clear(); return; }
            self.score_trial_down(&trial, last_pass);
            self.score_trial_up(&trial, last_pass);
        }
    }

    // Ghidra: unionresolve.cc:963 ScoreUnionFields::run
    /// Try to fit each possible field over multiple levels of the data-flow.
    /// Faithful to `run` (unionresolve.cc:963-980).
    fn run_passes(&mut self) {
        self.trial_count = 0;
        for pass in 0..MAX_PASSES {
            if self.trial_current.is_empty() { break; }
            if self.trial_count > THRESHOLD { break; }
            if pass + 1 == MAX_PASSES {
                self.run_one_level(true);
            } else {
                self.run_one_level(false);
                std::mem::swap(&mut self.trial_current, &mut self.trial_next);
                self.trial_next.clear();
            }
        }
    }

    // Ghidra: unionresolve.cc:88 ScoreUnionFields::testArrayArithmetic
    /// Check if the given PcodeOp is doing array arithmetic with union-sized
    /// elements. Faithful to `testArrayArithmetic` (unionresolve.cc:88-112).
    fn test_array_arithmetic(op: &PcodeOp, in_slot: i32, base_size: usize) -> bool {
        if op.get_opcode() == OpCode::CPUI_INT_ADD {
            let other_slot = (1 - in_slot) as usize;
            if let Some(other) = op.get_in(other_slot) {
                let other_rg = other.read().unwrap();
                if other_rg.is_constant() {
                    if other_rg.get_offset() >= base_size as u64 { return true; }
                } else if other_rg.is_written() {
                    if let Some(mult_op) = other_rg.get_def() {
                        let mult_rg = mult_op.read().unwrap();
                        if mult_rg.get_opcode() == OpCode::CPUI_INT_MULT {
                            if let Some(vn2) = mult_rg.get_in(1) {
                                let vn2_rg = vn2.read().unwrap();
                                if vn2_rg.is_constant() && vn2_rg.get_offset() >= base_size as u64 {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        } else if op.get_opcode() == OpCode::CPUI_PTRADD {
            if let Some(vn) = op.get_in(2) {
                let vn_rg = vn.read().unwrap();
                if vn_rg.get_offset() >= base_size as u64 { return true; }
            }
        }
        false
    }

    // Ghidra: unionresolve.cc:119 ScoreUnionFields::testSimpleCases
    /// Identify cases where we know the union shouldn't be resolved to a
    /// field. Faithful to `testSimpleCases` (unionresolve.cc:119-137).
    fn score_simple_cases_inner(op: &PcodeOp, in_slot: i32, parent: &Datatype) -> bool {
        if op.is_marker() { return true; }
        if parent.get_metatype() == TypeMetatype::Pointer {
            if in_slot < 0 { return true; }
            // cc:94/101/108 compare against result.baseType->getSize() —
            // the pointer-stripped union size, not the pointer size.
            let base_size = match parent {
                Datatype::Pointer(p) => p.ptr_to.get_size(),
                _ => parent.get_size(),
            };
            if Self::test_array_arithmetic(op, in_slot, base_size) { return true; }
        }
        if op.get_opcode() != OpCode::CPUI_COPY { return false; }
        if in_slot < 0 { return false; }
        if let Some(out) = op.get_out() {
            let out_rg = out.read().unwrap();
            if out_rg.is_type_lock() { return false; }
        }
        true
    }

    // Ghidra: unionresolve.cc:144 ScoreUnionFields::scoreLockedType
    /// Score a trial data-type against a locked data-type. Faithful to
    /// `scoreLockedType` (unionresolve.cc:144-176).
    fn score_locked_type(ct: &Datatype, lock_type: &Datatype) -> i32 {
        let mut score = 0i32;
        let mut ct = ct;
        let mut lock_type = lock_type;
        // cc:149-150: the identity bonus is checked once, before the
        // pointer-peel loop (no in-loop re-check).
        if std::ptr::eq(ct, lock_type) { score += 5; }
        while ct.get_metatype() == TypeMetatype::Pointer {
            if lock_type.get_metatype() != TypeMetatype::Pointer { break; }
            score += 5;
            ct = pointee_of(ct);
            lock_type = pointee_of(lock_type);
        }
        let ct_meta = ct.get_metatype();
        let vn_meta = lock_type.get_metatype();
        if ct_meta == vn_meta {
            if matches!(ct_meta,
                TypeMetatype::Struct | TypeMetatype::Union
                | TypeMetatype::Array | TypeMetatype::Code) {
                score += 10;
            } else { score += 3; }
        } else {
            if (ct_meta == TypeMetatype::Int && vn_meta == TypeMetatype::Uint)
                || (ct_meta == TypeMetatype::Uint && vn_meta == TypeMetatype::Int) {
                score -= 1;
            } else { score -= 5; }
            if ct.get_size() != lock_type.get_size() { score -= 2; }
        }
        score
    }

    // Ghidra: unionresolve.cc:184 ScoreUnionFields::scoreParameter
    /// Score a trial data-type against a call parameter. Faithful to
    /// `scoreParameter` (unionresolve.cc:184-197).
    fn score_parameter(
        ct: &Datatype,
        fd: &crate::funcdata::Funcdata,
        call_op: &PcodeOpRef,
        param_slot: i32,
    ) -> i32 {
        if let Some(fc) = fd.get_call_specs_of_op(call_op) {
            let fc = fc.read().unwrap();
            if fc.is_input_locked() && (fc.prototype.num_params() as i32) > param_slot {
                if let Some(param) = fc.prototype.get_param(param_slot as usize) {
                    return Self::score_locked_type(ct, param.data_type.as_ref());
                }
            }
        }
        let meta = ct.get_metatype();
        if matches!(meta,
            TypeMetatype::Array | TypeMetatype::Struct
            | TypeMetatype::Union | TypeMetatype::Code) { -1 } else { 0 }
    }

    // Ghidra: unionresolve.cc:204 ScoreUnionFields::scoreReturnType
    /// Score a trial data-type against a CALL's return type. Faithful to
    /// `scoreReturnType` (unionresolve.cc:204-217).
    fn score_return_type(
        ct: &Datatype,
        fd: &crate::funcdata::Funcdata,
        call_op: &PcodeOpRef,
    ) -> i32 {
        if let Some(fc) = fd.get_call_specs_of_op(call_op) {
            let fc = fc.read().unwrap();
            if fc.is_output_locked() {
                return Self::score_locked_type(ct, fc.prototype.return_type.as_ref());
            }
        }
        let meta = ct.get_metatype();
        if matches!(meta,
            TypeMetatype::Array | TypeMetatype::Struct
            | TypeMetatype::Union | TypeMetatype::Code) { -1 } else { 0 }
    }

    // Ghidra: unionresolve.cc:227 ScoreUnionFields::derefPointer
    /// Score a trial data-type as a pointer being dereferenced by LOAD/STORE.
    /// Faithful to `derefPointer` (unionresolve.cc:227-246).
    fn deref_pointer(ct: &Datatype, vn_size: usize) -> (Option<Arc<Datatype>>, i32) {
        let mut score = 0i32;
        let mut res_type: Option<Arc<Datatype>> = None;
        if ct.get_metatype() == TypeMetatype::Pointer {
            // Seed with the canonical pointee Arc (Ghidra:
            // ((TypePointer*)ct)->getPtrTo()); each descent step takes the
            // canonical component Arc from the virtual getSubType dispatch.
            let ptr_seed = match ct {
                Datatype::Pointer(p) => p.ptr_to.clone(),
                _ => return (res_type, score),
            };
            let mut ptr_to: Option<Arc<Datatype>> = Some(ptr_seed);
            while let Some(p) = &ptr_to {
                if p.get_size() > vn_size {
                    let (sub, _newoff) = p.get_sub_type(0);
                    ptr_to = sub;
                } else { break; }
            }
            if let Some(p) = &ptr_to {
                if p.get_size() == vn_size { score = 10; res_type = ptr_to.clone(); }
            }
        } else { score = -10; }
        (res_type, score)
    }

    // Ghidra: unionresolve.cc:253 ScoreUnionFields::newTrialsDown
    /// Create new downward trials for each read of `vn`. Faithful to
    /// `newTrialsDown` (unionresolve.cc:253-268).
    fn new_trials_down(
        &mut self, vn: &Arc<RwLock<Varnode>>, ct: Arc<Datatype>,
        score_index: i32, is_array: bool,
    ) {
        let mark = VisitMark::new(vn, score_index);
        if !self.visited.insert(mark) { return; }
        let (is_type_lock, locked_type, descends) = {
            let vn_rg = vn.read().unwrap();
            let lt = if vn_rg.is_type_lock() { vn_rg.get_type() } else { None };
            let ds: Vec<Arc<RwLock<PcodeOp>>> = vn_rg.descend_iter().collect();
            (vn_rg.is_type_lock(), lt, ds)
        };
        if is_type_lock {
            if let Some(lt) = locked_type {
                self.scores[score_index as usize] += Self::score_locked_type(ct.as_ref(), lt.as_ref());
            }
            return;
        }
        for op in descends {
            let slot = {
                let op_rg = op.read().unwrap();
                op_rg.slot_of_input(vn).map(|s| s as i32).unwrap_or(-1)
            };
            self.trial_next.push(Trial::new_down(op, slot, ct.clone(), score_index, is_array));
        }
    }

    // Ghidra: unionresolve.cc:276 ScoreUnionFields::newTrials
    /// Create new trials (down + up) for the input slot of an op. Faithful
    /// to `newTrials` (unionresolve.cc:276-296).
    fn new_trials(
        &mut self, op: &Arc<RwLock<PcodeOp>>, slot: i32, ct: Arc<Datatype>,
        score_index: i32, is_array: bool,
    ) {
        let vn = {
            let op_rg = op.read().unwrap();
            op_rg.get_in(slot as usize).cloned().expect("ScoreUnionFields::new_trials: slot out of range")
        };
        let mark = VisitMark::new(&vn, score_index);
        if !self.visited.insert(mark) { return; }
        let (is_type_lock, locked_type, descends) = {
            let vn_rg = vn.read().unwrap();
            let lt = if vn_rg.is_type_lock() { vn_rg.get_type() } else { None };
            let ds: Vec<Arc<RwLock<PcodeOp>>> = vn_rg.descend_iter().collect();
            (vn_rg.is_type_lock(), lt, ds)
        };
        if is_type_lock {
            if let Some(lt) = locked_type {
                self.scores[score_index as usize] += Self::score_locked_type(ct.as_ref(), lt.as_ref());
            }
            return;
        }
        self.trial_next.push(Trial::new_up(vn.clone(), ct.clone(), score_index, is_array));
        for read_op in descends {
            let inslot = {
                let op_rg = read_op.read().unwrap();
                op_rg.slot_of_input(&vn).map(|s| s as i32).unwrap_or(-1)
            };
            if Arc::ptr_eq(&read_op, op) && inslot == slot { continue; }
            self.trial_next.push(Trial::new_down(read_op, inslot, ct.clone(), score_index, is_array));
        }
    }

    // Ghidra: unionresolve.cc:305 ScoreUnionFields::scoreTrialDown
    /// Fit a trial's data-type to its op's input and accumulate a score.
    /// Faithful to `scoreTrialDown` (unionresolve.cc:305-640).
    fn score_trial_down(&mut self, trial: &Trial, last_level: bool) {
        if trial.direction == DirType::FitUp { return; }
        let op = match &trial.op { Some(o) => o.clone(), None => return };
        let (op_code, out_vn, _in0, in1, in2, out_size, in1_offset_const, in2_offset_const) = {
            let op_rg = op.read().unwrap();
            let out_vn = op_rg.get_out().cloned();
            let in0 = op_rg.get_in(0).cloned();
            let in1 = op_rg.get_in(1).cloned();
            let in2 = op_rg.get_in(2).cloned();
            let out_size = out_vn.as_ref().map(|v| v.read().unwrap().get_size());
            let in1_off = in1.as_ref()
                .filter(|v| v.read().unwrap().is_constant())
                .map(|v| v.read().unwrap().get_offset());
            let in2_off = in2.as_ref()
                .filter(|v| v.read().unwrap().is_constant())
                .map(|v| v.read().unwrap().get_offset());
            (op_rg.get_opcode(), out_vn, in0, in1, in2, out_size, in1_off, in2_off)
        };
        let meta = trial.fit_type.get_metatype();
        let mut score: i32 = 0;
        let mut res_type: Option<Arc<Datatype>> = None;
        match op_code {
            OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => {
                res_type = Some(trial.fit_type.clone());
            }
            OpCode::CPUI_LOAD => {
                if let Some(out_sz) = out_size {
                    let (rt, s) = Self::deref_pointer(trial.fit_type.as_ref(), out_sz);
                    score = s;
                    res_type = rt;
                }
            }
            OpCode::CPUI_STORE => {
                if trial.in_slot == 1 {
                    let vn_size = in2.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
                    let (ptr_to, s) = Self::deref_pointer(trial.fit_type.as_ref(), vn_size);
                    score = s;
                    if let Some(pt) = ptr_to {
                        if !last_level {
                            self.new_trials(&op, 2, pt, trial.score_index, trial.is_array);
                        }
                    }
                } else if trial.in_slot == 2 {
                    if meta == TypeMetatype::Code { score = -5; } else { score = 1; }
                }
            }
            OpCode::CPUI_CBRANCH => {
                if meta == TypeMetatype::Bool { score = 10; } else { score = -10; }
            }
            OpCode::CPUI_BRANCHIND => {
                if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Array | TypeMetatype::Struct
                    | TypeMetatype::Union | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            OpCode::CPUI_CALL | OpCode::CPUI_CALLOTHER => {
                let _ = in1;
                if trial.in_slot > 0 {
                    score = match self.fd {
                        // cc:352-353: scoreParameter consults the locked
                        // call-specs; absent/unlocked specs fall back to the
                        // generic param heuristic inside score_parameter.
                        Some(fd) => Self::score_parameter(
                            trial.fit_type.as_ref(), fd,
                            &crate::op::PcodeOpRef(op.clone()), trial.in_slot - 1),
                        None => {
                            if matches!(meta,
                                TypeMetatype::Array | TypeMetatype::Struct
                                | TypeMetatype::Union | TypeMetatype::Code) {
                                -1
                            } else { 0 }
                        }
                    };
                }
            }
            OpCode::CPUI_CALLIND => {
                if trial.in_slot == 0 {
                    if meta == TypeMetatype::Pointer {
                        let ptrto = pointee_of(trial.fit_type.as_ref());
                        if ptrto.get_metatype() == TypeMetatype::Code { score = 10; } else { score = -10; }
                    }
                } else {
                    // cc:367-368: scoreParameter for the indirect input slot.
                    score = match self.fd {
                        Some(fd) => Self::score_parameter(
                            trial.fit_type.as_ref(), fd,
                            &crate::op::PcodeOpRef(op.clone()), trial.in_slot - 1),
                        None => {
                            if matches!(meta,
                                TypeMetatype::Array | TypeMetatype::Struct
                                | TypeMetatype::Union | TypeMetatype::Code) {
                                -1
                            } else { 0 }
                        }
                    };
                }
            }
            OpCode::CPUI_RETURN => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct
                    | TypeMetatype::Union | TypeMetatype::Code) {
                    score = -1;
                }
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -1;
                } else { score = 1; }
            }
            OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Unknown
                    | TypeMetatype::Uint | TypeMetatype::Bool) {
                    score = -1;
                } else { score = 5; }
            }
            OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_CARRY => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Unknown | TypeMetatype::Uint) {
                    score = 5;
                } else if meta == TypeMetatype::Int { score = -5; }
            }
            OpCode::CPUI_INT_ZEXT => {
                if meta == TypeMetatype::Uint { score = 2; }
                else if matches!(meta, TypeMetatype::Int | TypeMetatype::Bool) { score = 1; }
                else if meta == TypeMetatype::Unknown { score = 0; }
                else { score = -5; }
            }
            OpCode::CPUI_INT_SEXT => {
                if meta == TypeMetatype::Int { score = 2; }
                else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Bool) { score = 1; }
                else if meta == TypeMetatype::Unknown { score = 0; }
                else { score = -5; }
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_PTRSUB => {
                if meta == TypeMetatype::Pointer {
                    if trial.in_slot >= 0 {
                        // cc:429-438: the offset is the constant on the OTHER
                        // input slot (1 - inslot); the drill is the virtual
                        // TypePointer::downChain(off, par, parOff, array),
                        // and score 5 is added only when the drill succeeds.
                        let other_off_const = {
                            let op_rg = op.read().unwrap();
                            op_rg.get_in((1 - trial.in_slot) as usize).and_then(|v| {
                                let vr = v.read().unwrap();
                                if vr.is_constant() { Some(vr.get_offset() as i64) } else { None }
                            })
                        };
                        if let Some(off) = other_off_const {
                            let typegrp_arc = self.typegrp.clone();
                            let mut tg = typegrp_arc.write().unwrap();
                            let mut chain_off = off;
                            let mut par: Option<Arc<Datatype>> = None;
                            let mut par_off: i64 = 0;
                            if let Some(rt) = tg.down_chain_virtual(
                                &trial.fit_type, &mut chain_off, &mut par, &mut par_off,
                                trial.is_array) {
                                res_type = Some(rt);
                                score = 5;
                            }
                        } else if trial.is_array {
                            score = 1;
                            let mut el_size = 1usize;
                            if let Some(ref vn1) = in1 {
                                if vn1.read().unwrap().is_written() {
                                    if let Some(mult_op) = vn1.read().unwrap().get_def() {
                                        let mult_rg = mult_op.read().unwrap();
                                        if mult_rg.get_opcode() == OpCode::CPUI_INT_MULT {
                                            if let Some(mult_vn) = mult_rg.get_in(1) {
                                                let mv = mult_vn.read().unwrap();
                                                if mv.is_constant() { el_size = mv.get_offset() as usize; }
                                            }
                                        }
                                    }
                                }
                            }
                            let base = trial.fit_type.as_ref();
                            if let Some(ptr_to) = pointer_pointee(base) {
                                if ptr_to.get_align_size() == el_size {
                                    score = 5;
                                    res_type = Some(trial.fit_type.clone());
                                }
                            }
                        } else { score = 5; }
                    }
                } else if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            OpCode::CPUI_INT_2COMP => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Unknown | TypeMetatype::Bool) {
                    score = -1;
                } else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR | OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -1;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 2; }
            }
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT => {
                if trial.in_slot == 0 {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float) {
                        score = -5;
                    } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                        score = -1;
                    } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 2; }
                } else {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float | TypeMetatype::Pointer) {
                        score = -5;
                    } else { score = 1; }
                }
            }
            OpCode::CPUI_INT_SRIGHT => {
                if trial.in_slot == 0 {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float) {
                        score = -5;
                    } else if matches!(meta,
                        TypeMetatype::Pointer | TypeMetatype::Bool
                        | TypeMetatype::Uint | TypeMetatype::Unknown) {
                        score = -1;
                    } else { score = 2; }
                } else {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float | TypeMetatype::Pointer) {
                        score = -5;
                    } else { score = 1; }
                }
            }
            OpCode::CPUI_INT_MULT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else { score = 5; }
            }
            OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 5; }
            }
            OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_SREM => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_XOR | OpCode::CPUI_BOOL_OR => {
                if meta == TypeMetatype::Bool { score = 10; }
                else if matches!(meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Unknown) {
                    score = -1;
                } else { score = -10; }
            }
            OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_FLOAT_NAN | OpCode::CPUI_FLOAT_ADD | OpCode::CPUI_FLOAT_DIV
            | OpCode::CPUI_FLOAT_MULT | OpCode::CPUI_FLOAT_SUB | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS | OpCode::CPUI_FLOAT_SQRT | OpCode::CPUI_FLOAT_FLOAT2FLOAT
            | OpCode::CPUI_FLOAT_TRUNC | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR | OpCode::CPUI_FLOAT_ROUND => {
                if meta == TypeMetatype::Float { score = 10; } else { score = -10; }
            }
            OpCode::CPUI_FLOAT_INT2FLOAT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if meta == TypeMetatype::Pointer { score = -5; }
                else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_PIECE => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                }
            }
            OpCode::CPUI_SUBPIECE => {
                let offset = in1_offset_const.unwrap_or(0) as i64;
                let vn_size = out_size.unwrap_or(0);
                if let Some(rt) = self.score_truncation(
                    &trial.fit_type, vn_size, offset, trial.score_index) {
                    res_type = Some(rt);
                }
            }
            OpCode::CPUI_PTRADD => {
                if meta == TypeMetatype::Pointer {
                    if trial.in_slot == 0 {
                        let ptr_to = pointee_of(trial.fit_type.as_ref());
                        let stride = in2_offset_const.unwrap_or(0) as usize;
                        if ptr_to.get_align_size() == stride {
                            score = 10;
                            res_type = Some(trial.fit_type.clone());
                        }
                    } else { score = -10; }
                } else if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            OpCode::CPUI_SEGMENTOP => {
                if trial.in_slot == 2 {
                    if meta == TypeMetatype::Pointer { score = 5; }
                    else if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float) {
                        score = -5;
                    } else { score = -1; }
                } else {
                    if matches!(meta,
                        TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                        | TypeMetatype::Code | TypeMetatype::Float | TypeMetatype::Pointer) {
                        score = -2;
                    }
                }
            }
            _ => { score = -10; }
        }
        self.scores[trial.score_index as usize] += score;
        if let Some(rt) = res_type {
            if !last_level {
                if let Some(out) = out_vn {
                    self.new_trials_down(&out, rt, trial.score_index, trial.is_array);
                }
            }
        }
    }

    // Ghidra: unionresolve.cc:642 ScoreUnionFields::scoreTrialUp
    /// Fit a trial's data-type against the op that defines its Varnode.
    /// Faithful to `scoreTrialUp` (unionresolve.cc:642-833).
    fn score_trial_up(&mut self, trial: &Trial, last_level: bool) {
        if trial.direction == DirType::FitDown { return; }
        let mut score: i32 = 0;
        let mut res_type: Option<Arc<Datatype>> = None;
        let (is_written, is_constant) = {
            let vn_rg = trial.vn.read().unwrap();
            (vn_rg.is_written(), vn_rg.is_constant())
        };
        if !is_written {
            if is_constant { self.score_constant_fit(trial); }
            return;
        }
        let def = { let vn_rg = trial.vn.read().unwrap(); vn_rg.get_def() };
        let def = match def { Some(d) => d, None => return };
        let (def_code, in1_off_const, in2_off_const) = {
            let def_rg = def.read().unwrap();
            let in1_off = def_rg.get_in(1).and_then(|v| {
                let vrg = v.read().unwrap();
                if vrg.is_constant() { Some(vrg.get_offset()) } else { None }
            });
            let in2_off = def_rg.get_in(2).and_then(|v| {
                let vrg = v.read().unwrap();
                if vrg.is_constant() { Some(vrg.get_offset()) } else { None }
            });
            (def_rg.get_opcode(), in1_off, in2_off)
        };
        let meta = trial.fit_type.get_metatype();
        let mut new_slot = 0i32;
        match def_code {
            OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => {
                res_type = Some(trial.fit_type.clone());
            }
            // cc:664-666: wrap the trial type in a pointer sized by the
            // pointer input (slot 1, wordsize 1) and recurse on that input.
            OpCode::CPUI_LOAD => {
                let ptr_size = {
                    let def_rg = def.read().unwrap();
                    def_rg.get_in(1).map(|v| v.read().unwrap().get_size())
                };
                if let Some(sz) = ptr_size {
                    let typegrp_arc = self.typegrp.clone();
                    let mut tg = typegrp_arc.write().unwrap();
                    res_type = Some(tg.get_type_pointer(sz, trial.fit_type.clone(), 1));
                    new_slot = 1;
                }
            }
            OpCode::CPUI_CALL | OpCode::CPUI_CALLOTHER | OpCode::CPUI_CALLIND => {
                // cc:668-672: scoreReturnType consults the locked output
                // prototype; the fallback heuristic lives inside it.
                score = match self.fd {
                    Some(fd) => Self::score_return_type(
                        trial.fit_type.as_ref(), fd,
                        &crate::op::PcodeOpRef(def.clone())),
                    None => {
                        if matches!(meta,
                            TypeMetatype::Array | TypeMetatype::Struct
                            | TypeMetatype::Union | TypeMetatype::Code) {
                            -1
                        } else { 0 }
                    }
                };
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW
            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_CARRY
            | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_XOR | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL | OpCode::CPUI_FLOAT_NAN => {
                if meta == TypeMetatype::Bool { score = 10; }
                else if trial.fit_type.get_size() == 1 { score = 1; }
                else { score = -10; }
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_PTRSUB => {
                if meta == TypeMetatype::Pointer { score = 5; }
                else if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            OpCode::CPUI_INT_2COMP => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Unknown | TypeMetatype::Bool) {
                    score = -1;
                } else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR | OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -1;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 2; }
            }
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -1;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 2; }
            }
            OpCode::CPUI_INT_SRIGHT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else if matches!(meta,
                    TypeMetatype::Pointer | TypeMetatype::Bool
                    | TypeMetatype::Uint | TypeMetatype::Unknown) {
                    score = -1;
                } else { score = 2; }
            }
            OpCode::CPUI_INT_MULT => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else { score = 5; }
            }
            OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else if matches!(meta, TypeMetatype::Uint | TypeMetatype::Unknown) { score = 5; }
            }
            OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_SREM => {
                if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -10;
                } else if matches!(meta, TypeMetatype::Pointer | TypeMetatype::Bool) {
                    score = -2;
                } else if meta == TypeMetatype::Int { score = 5; }
            }
            OpCode::CPUI_FLOAT_ADD | OpCode::CPUI_FLOAT_DIV | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_FLOAT_SUB | OpCode::CPUI_FLOAT_NEG | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT | OpCode::CPUI_FLOAT_FLOAT2FLOAT | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR | OpCode::CPUI_FLOAT_ROUND | OpCode::CPUI_FLOAT_INT2FLOAT => {
                if meta == TypeMetatype::Float { score = 10; } else { score = -10; }
            }
            OpCode::CPUI_FLOAT_TRUNC => {
                if matches!(meta, TypeMetatype::Int | TypeMetatype::Uint) { score = 2; }
                else { score = -2; }
            }
            OpCode::CPUI_PIECE => {
                if matches!(meta, TypeMetatype::Float | TypeMetatype::Bool) { score = -5; }
                else if matches!(meta, TypeMetatype::Code | TypeMetatype::Pointer) { score = -2; }
            }
            OpCode::CPUI_SUBPIECE => {
                if matches!(meta, TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Bool) {
                    if in1_off_const == Some(0) { score = 3; } else { score = 1; }
                } else { score = -5; }
            }
            OpCode::CPUI_PTRADD => {
                if meta == TypeMetatype::Pointer {
                    let ptr_to = pointee_of(trial.fit_type.as_ref());
                    let stride = in2_off_const.unwrap_or(0) as usize;
                    if ptr_to.get_align_size() == stride { score = 10; } else { score = 2; }
                } else if matches!(meta,
                    TypeMetatype::Array | TypeMetatype::Struct | TypeMetatype::Union
                    | TypeMetatype::Code | TypeMetatype::Float) {
                    score = -5;
                } else { score = 1; }
            }
            _ => { score = -10; }
        }
        self.scores[trial.score_index as usize] += score;
        if let Some(rt) = res_type {
            if !last_level {
                self.new_trials(&def, new_slot, rt, trial.score_index, trial.is_array);
            }
        }
    }

    // Ghidra: unionresolve.cc:843 ScoreUnionFields::scoreTruncation
    /// Score a truncation in the data-flow. Faithful to `scoreTruncation`
    /// (unionresolve.cc:843-879).
    fn score_truncation(
        &mut self, ct_in: &Arc<Datatype>, vn_size: usize, offset: i64, score_index: i32,
    ) -> Option<Arc<Datatype>> {
        let idx = score_index as usize;
        if ct_in.get_metatype() == TypeMetatype::Union {
            let union_dt = as_union(ct_in.as_ref());
            let mut score = -10i32;
            let mut recurse: Option<Arc<Datatype>> = None;
            if let Some(u) = union_dt {
                for field in &u.fields {
                    if field.offset as i64 == offset && field.type_ptr.get_size() == vn_size {
                        score = 10;
                        // cc:856-857: the +5 bonus is the identity
                        // result.getBase() == unionDt (pointer compare).
                        if Arc::ptr_eq(&self.result.base_type, ct_in) { score += 5; }
                        recurse = None;
                        break;
                    }
                }
            }
            self.scores[idx] += score;
            return recurse;
        }
        let mut score = 10i32;
        let mut cur_off = offset;
        let mut ct: Option<Arc<Datatype>> = Some(ct_in.clone());
        while let Some(c) = &ct {
            if cur_off == 0 && c.get_size() == vn_size { break; }
            if c.get_metatype() == TypeMetatype::Int || c.get_metatype() == TypeMetatype::Uint {
                if c.get_size() >= vn_size + cur_off as usize { score = 1; ct = None; break; }
            }
            let (sub, new_off) = c.get_sub_type(cur_off);
            cur_off = new_off;
            ct = sub;
        }
        if ct.is_none() { score = -10; }
        self.scores[idx] += score;
        ct
    }

    // Ghidra: unionresolve.cc:884 ScoreUnionFields::scoreConstantFit
    /// Score a trial data-type against a constant Varnode. Faithful to
    /// `scoreConstantFit` (unionresolve.cc:884-926).
    fn score_constant_fit(&mut self, trial: &Trial) {
        let (size, val, meta) = {
            let vn_rg = trial.vn.read().unwrap();
            (vn_rg.get_size(), vn_rg.get_offset(), trial.fit_type.get_metatype())
        };
        let mut score: i32;
        if meta == TypeMetatype::Bool {
            score = if size == 1 && val < 2 { 2 } else { -2 };
        } else if meta == TypeMetatype::Float {
            score = -1;
            let fmt = crate::float_emulate::FloatFormat::new(size);
            let exp = fmt.extract_exponent_code(val) as i32;
            if exp < 7 && exp > -4 { score = 2; }
        } else if matches!(meta,
            TypeMetatype::Int | TypeMetatype::Uint | TypeMetatype::Pointer) {
            if val == 0 {
                score = 2;
            } else {
                let looks_like_pointer = bit_transition_count(val, size) >= 3;
                if meta == TypeMetatype::Pointer {
                    score = if looks_like_pointer { 2 } else { -2 };
                } else {
                    score = if looks_like_pointer { 1 } else { 2 };
                }
            }
        } else { score = -2; }
        self.scores[trial.score_index as usize] += score;
    }

    // RUDRA-GLUE: Legacy entry-point kept for the old Funcdata-scanning test
    //   path. The real Ghidra entry is the `new(...)` constructor above.
    pub fn run_on_func(&mut self, fd: &crate::funcdata::Funcdata) {
        for op_ref in fd.obank.iter_alive() {
            let op_rg = op_ref.0.read().unwrap();
            match op_rg.get_opcode() {
                OpCode::CPUI_SUBPIECE => {
                    if let Some(offset_vn) = op_rg.get_in(1) {
                        let offset_rg = offset_vn.read().unwrap();
                        if offset_rg.is_constant() {
                            let offset = offset_rg.get_offset() as usize;
                            if offset < self.fields.len() { self.add_score(offset, 1); }
                        }
                    }
                }
                OpCode::CPUI_INT_AND => {
                    if let Some(mask_vn) = op_rg.get_in(1) {
                        let mask_rg = mask_vn.read().unwrap();
                        if mask_rg.is_constant() {
                            let mask = mask_rg.get_offset();
                            if mask != 0 && mask != u64::MAX && self.fields.len() > 1 {
                                self.add_score(1, 1);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        self.compute_best_index();
    }
}

// ===========================================================================
// Pipeline wiring — type.cc resolveInFlow/findResolve virtual dispatch +
// varnode.cc:626-672 read/def-facing (UNIONRESOLVE-PIPELINE-WIRING-0001)
// ===========================================================================
//
// Ghidra dispatches `Datatype::resolveInFlow` / `Datatype::findResolve`
// virtually per concrete subclass (type.hh:279-280). Rudra's `Datatype` is an
// enum in type_system/datatype.rs with no Funcdata back-pointer, so the
// virtual dispatch is mirrored here as free functions threading `fd` — the
// same pattern the type layer already uses for `find_truncation`'s
// `resolutions` channel. `varnode.rs`'s own read-facing methods stay
// degenerate (EJ write-domain); these helpers are the fd-aware twins the
// Action/Rule call sites consult.

// Ghidra: type.cc:1177 TypePointer::resolveInFlow + type.cc:2125 TypeUnion::resolveInFlow
//   + type.cc:1283 TypeArray::resolveInFlow + type.cc:1929 TypeStruct::resolveInFlow
//   + type.cc:2498 TypePartialUnion::resolveInFlow + type.cc:574 Datatype::resolveInFlow
/// Resolve a data-type based on its use at a data-flow edge, consulting and
/// populating `Funcdata::union_map` exactly as the oracle virtual dispatch
/// does:
///
/// - `TypePointer` (type.cc:1177-1190): only when the pointee is a union —
///   consult the map, else score via [`ScoreUnionFields`] and write the edge.
///   A pointer to anything else returns `this` unchanged.
/// - `TypeUnion` (type.cc:2125-2135): consult, else score + write.
/// - `TypeArray` (type.cc:1283-1296) / `TypeStruct` (type.cc:1929-1942):
///   consult, else `scoreSingleComponent` + `ResolvedUnion(parent, fieldNum)`
///   fill and write.
/// - `TypePartialUnion` (type.cc:2498-2515): truncation walk down the
///   container (resolveTruncation through unions, getSubType otherwise);
///   no map write happens on this path.
/// - base `Datatype` (type.cc:574-578): return `this`.
///
/// Callers gate on `ct->needsResolution()` exactly as the oracle call sites
/// do (coreaction.cc:2496/2499, 2545/2554-2556, 5081-5083; ruleaction.cc:7678).
pub fn resolve_in_flow(
    fd: &mut crate::funcdata::Funcdata,
    ct: &Arc<Datatype>,
    op: &PcodeOpRef,
    slot: i32,
) -> Arc<Datatype> {
    match ct.as_ref() {
        // type.cc:1177-1190 TypePointer::resolveInFlow
        Datatype::Pointer(p) if p.ptr_to.get_metatype() == TypeMetatype::Union => {
            if let Some(res) = fd.get_union_field(ct.as_ref(), op, slot) {
                return res.get_datatype().clone();
            }
            let Some(typegrp) = fd.get_arch().and_then(|a| a.types.clone()) else {
                // No TypeFactory: cannot score (detached fixtures only).
                return ct.clone();
            };
            // cc:1185-1187: ScoreUnionFields scoreFields(*types,this,op,slot);
            //   fd->setUnionField(this,op,slot,scoreFields.getResult());
            let result = ScoreUnionFields::new(
                typegrp,
                ct.clone(),
                op.0.clone(),
                slot,
                Some(&*fd),
            )
            .result
            .clone();
            fd.set_union_field(ct.as_ref(), op, slot, result.clone());
            result.get_datatype().clone()
        }
        // type.cc:2125-2135 TypeUnion::resolveInFlow
        Datatype::Union(_) => {
            if let Some(res) = fd.get_union_field(ct.as_ref(), op, slot) {
                return res.get_datatype().clone();
            }
            let Some(typegrp) = fd.get_arch().and_then(|a| a.types.clone()) else {
                return ct.clone();
            };
            let result = ScoreUnionFields::new(
                typegrp,
                ct.clone(),
                op.0.clone(),
                slot,
                Some(&*fd),
            )
            .result
            .clone();
            fd.set_union_field(ct.as_ref(), op, slot, result.clone());
            result.get_datatype().clone()
        }
        // type.cc:1283-1296 TypeArray::resolveInFlow and
        // type.cc:1929-1942 TypeStruct::resolveInFlow share this shape.
        Datatype::Array(_) | Datatype::Struct(_) => {
            if let Some(res) = fd.get_union_field(ct.as_ref(), op, slot) {
                return res.get_datatype().clone();
            }
            let Some(typegrp_arc) = fd.get_arch().and_then(|a| a.types.clone()) else {
                // cc:1293 ResolvedUnion(this,fieldNum,*types) needs the
                // factory for the field construction; without it the edge is
                // left unresolved (base-arm return-this).
                return ct.clone();
            };
            let field_num = crate::type_system::datatype::TypeStruct::score_single_component(
                ct.as_ref(),
                fd,
                op,
                slot,
            );
            let comp_fill = {
                // cc:1293 ResolvedUnion(this,fieldNum,*types): the factory
                // interns the pointer arm (unionresolve.cc:54), so this is a
                // write guard — same lock discipline as the union arms'
                // ScoreUnionFields interning (cc:1185).
                let mut tg = typegrp_arc.write().unwrap();
                ResolvedUnion::with_field(ct.clone(), field_num, &mut tg)
            };
            fd.set_union_field(ct.as_ref(), op, slot, comp_fill.clone());
            comp_fill.get_datatype().clone()
        }
        // type.cc:2498-2515 TypePartialUnion::resolveInFlow
        Datatype::PartialUnion(pu) => {
            let size = pu.base.size;
            let mut cur_type: Option<Arc<Datatype>> = Some(pu.container.clone());
            let mut cur_off = pu.offset;
            while let Some(c) = cur_type.clone() {
                if c.get_size() <= size {
                    break;
                }
                if c.get_metatype() == TypeMetatype::Union {
                    // cc:2505: curType->resolveTruncation(curOff,op,slot,&curOff)
                    match union_resolve_truncation(fd, &c, cur_off, op, slot) {
                        Some((field, new_off)) => {
                            cur_off = new_off;
                            cur_type = Some(field.type_ptr.clone());
                        }
                        None => cur_type = None,
                    }
                } else {
                    let (sub, new_off) = c.get_sub_type(cur_off);
                    cur_off = new_off;
                    cur_type = sub;
                }
            }
            if let Some(c) = cur_type {
                if c.get_size() == size {
                    return c;
                }
            }
            // cc:2514: return stripped;
            pu.stripped.clone().unwrap_or_else(|| ct.clone())
        }
        // type.cc:574-578 Datatype::resolveInFlow (base): return this.
        _ => ct.clone(),
    }
}

// Ghidra: type.cc:2147 TypeUnion::resolveTruncation
/// Resolve which union field is used for a truncation, scoring when no
/// cached resolution exists. Faithful to `TypeUnion::resolveTruncation`
/// (type.cc:2147-2177): consult `union_map`; on hit with `fieldNum >= 0`
/// return the field with `newoff = offset - field->offset`; on miss score
/// via the SUBPIECE constructor (cc:2160, slot 1 is artificial) or the
/// implied-truncation constructor (cc:2168), write the edge, and return the
/// field when one was chosen. Returns `None` when no field resolves.
pub fn union_resolve_truncation(
    fd: &mut crate::funcdata::Funcdata,
    union_type: &Arc<Datatype>,
    offset: i64,
    op: &PcodeOpRef,
    slot: i32,
) -> Option<(TypeField, i64)> {
    let Datatype::Union(u) = union_type.as_ref() else {
        return None;
    };
    // cc:2151-2158: cached resolution wins; fieldNum < 0 falls through to
    // the null return WITHOUT scoring (only a full miss scores).
    if let Some(res) = fd.get_union_field(union_type.as_ref(), op, slot) {
        if res.get_field_num() >= 0 {
            let field = u.fields.get(res.get_field_num() as usize)?;
            return Some((field.clone(), offset - field.offset as i64));
        }
        return None;
    }
    let Some(typegrp) = fd.get_arch().and_then(|a| a.types.clone()) else {
        return None;
    };
    let (result, subpiece_form) = {
        let op_code = op.0.read().unwrap().opcode;
        if op_code == OpCode::CPUI_SUBPIECE && slot == 1 {
            // cc:2159-2165: the slot is artificial in this case.
            let s = ScoreUnionFields::new_for_subpiece(
                typegrp,
                union_type.clone(),
                offset,
                op.0.clone(),
                Some(&*fd),
            );
            (s.result.clone(), true)
        } else {
            // cc:2167-2174.
            let s = ScoreUnionFields::new_for_implied_trunc(
                typegrp,
                union_type.clone(),
                offset,
                op.0.clone(),
                slot,
                Some(&*fd),
            );
            (s.result.clone(), false)
        }
    };
    fd.set_union_field(union_type.as_ref(), op, slot, result.clone());
    if result.get_field_num() >= 0 {
        let field = u.fields.get(result.get_field_num() as usize)?;
        let new_off = if subpiece_form { 0 } else { offset - field.offset as i64 };
        return Some((field.clone(), new_off));
    }
    None
}

// Ghidra: type.cc:1192 TypePointer::findResolve + type.cc:2137 TypeUnion::findResolve
//   + type.cc:1298 TypeArray::findResolve + type.cc:1944 TypeStruct::findResolve
//   + type.cc:2517 TypePartialUnion::findResolve + type.cc:586 Datatype::findResolve
/// Find a previously calculated resolution for this data-type at the given
/// edge, WITHOUT scoring. The const consult mirror of [`resolve_in_flow`]:
///
/// - `TypePointer` (type.cc:1192-1202): union pointee consults the map, else
///   returns `this`.
/// - `TypeUnion` (type.cc:2137-2145): consult, else `this`.
/// - `TypeArray` (type.cc:1298-1306): consult, else the ELEMENT type
///   ("assume referring to the element").
/// - `TypeStruct` (type.cc:1944-1952): consult, else `field[0].type`.
/// - `TypePartialUnion` (type.cc:2517-2534): container walk delegating to
///   `findResolve` through unions / `getSubType` otherwise; the result must
///   exactly match the partial size, else the stripped twin.
pub fn find_resolve(
    fd: &crate::funcdata::Funcdata,
    ct: &Arc<Datatype>,
    op: &PcodeOpRef,
    slot: i32,
) -> Arc<Datatype> {
    let consulted = |fd: &crate::funcdata::Funcdata| -> Option<Arc<Datatype>> {
        fd.get_union_field(ct.as_ref(), op, slot)
            .map(|res| res.get_datatype().clone())
    };
    match ct.as_ref() {
        // type.cc:1192-1202 TypePointer::findResolve
        Datatype::Pointer(p) if p.ptr_to.get_metatype() == TypeMetatype::Union => {
            consulted(fd).unwrap_or_else(|| ct.clone())
        }
        // type.cc:2137-2145 TypeUnion::findResolve
        Datatype::Union(_) => consulted(fd).unwrap_or_else(|| ct.clone()),
        // type.cc:1298-1306 TypeArray::findResolve
        Datatype::Array(a) => consulted(fd).unwrap_or_else(|| a.array_of.clone()),
        // type.cc:1944-1952 TypeStruct::findResolve
        Datatype::Struct(s) => consulted(fd).unwrap_or_else(|| {
            // cc:1951: field[0].type — the arm is only reached for
            // single-field structs via needsResolution callers, but Ghidra
            // indexes field[0] unconditionally.
            s.fields
                .first()
                .map(|f| f.type_ptr.clone())
                .unwrap_or_else(|| ct.clone())
        }),
        // type.cc:2517-2534 TypePartialUnion::findResolve
        Datatype::PartialUnion(pu) => {
            let size = pu.base.size;
            let mut cur_type: Option<Arc<Datatype>> = Some(pu.container.clone());
            let mut cur_off = pu.offset;
            while let Some(c) = cur_type.clone() {
                if c.get_size() <= size {
                    break;
                }
                if c.get_metatype() == TypeMetatype::Union {
                    // cc:2524-2525: newType = curType->findResolve(op,slot);
                    //   curType = (newType == curType) ? null : newType;
                    let new_type = find_resolve(fd, &c, op, slot);
                    if Arc::ptr_eq(&new_type, &c) {
                        cur_type = None;
                    } else {
                        cur_type = Some(new_type);
                    }
                } else {
                    let (sub, new_off) = c.get_sub_type(cur_off);
                    cur_off = new_off;
                    cur_type = sub;
                }
            }
            if let Some(c) = cur_type {
                if c.get_size() == size {
                    return c;
                }
            }
            // cc:2533: return stripped;
            pu.stripped.clone().unwrap_or_else(|| ct.clone())
        }
        // type.cc:586-590 Datatype::findResolve (base): return this.
        _ => ct.clone(),
    }
}

// Ghidra: type.cc:2201 TypeUnion::findCompatibleResolve + type.cc:1308
//   TypeArray::findCompatibleResolve + type.cc:1954 TypeStruct::findCompatibleResolve
//   + type.cc:2536 TypePartialUnion::findCompatibleResolve + type.cc:596 Datatype::findCompatibleResolve
/// If this data-type has an alternate form matching `ct`, return the field
/// index of that form, else -1. The virtual-dispatch mirror used by
/// `ActionSetCasts::tryResolutionAdjustment` (coreaction.cc:2436/2441):
///
/// - base (type.cc:596-600): always -1.
/// - `TypeUnion` (type.cc:2201-2221): a non-resolution `ct` matches a field
///   by pointer identity at offset 0; a resolution `ct` matches through a
///   same-size non-resolution field whose own `findCompatibleResolve`
///   accepts `ct` (mutual recursion through the argument type).
/// - `TypeArray` (type.cc:1308-1318) / `TypeStruct` (type.cc:1954-1964):
///   offset-0 element/field mutual-recursion arm, then direct identity.
/// - `TypePartialUnion` (type.cc:2536-2540): delegates to the container.
pub fn find_compatible_resolve(ct: &Arc<Datatype>, other: &Arc<Datatype>) -> i32 {
    match ct.as_ref() {
        // type.cc:2201-2221 TypeUnion::findCompatibleResolve
        Datatype::Union(u) => {
            if !other.needs_resolution() {
                // cc:2205-2208: field[i].type == ct (pointer identity).
                for (i, f) in u.fields.iter().enumerate() {
                    if Arc::ptr_eq(&f.type_ptr, other) && f.offset == 0 {
                        return i as i32;
                    }
                }
            } else {
                // cc:2211-2218.
                for (i, f) in u.fields.iter().enumerate() {
                    if f.offset != 0 {
                        continue;
                    }
                    if f.type_ptr.get_size() != other.get_size() {
                        continue;
                    }
                    if f.type_ptr.needs_resolution() {
                        continue;
                    }
                    if find_compatible_resolve(other, &f.type_ptr) >= 0 {
                        return i as i32;
                    }
                }
            }
            -1
        }
        // type.cc:1308-1318 TypeArray::findCompatibleResolve
        Datatype::Array(a) => {
            if other.needs_resolution() && !a.array_of.needs_resolution() {
                if find_compatible_resolve(other, &a.array_of) >= 0 {
                    return 0;
                }
            }
            if Arc::ptr_eq(&a.array_of, other) {
                return 0;
            }
            -1
        }
        // type.cc:1954-1964 TypeStruct::findCompatibleResolve
        Datatype::Struct(s) => {
            let Some(field_type) = s.fields.first().map(|f| f.type_ptr.clone()) else {
                return -1;
            };
            if other.needs_resolution() && !field_type.needs_resolution() {
                if find_compatible_resolve(other, &field_type) >= 0 {
                    return 0;
                }
            }
            if Arc::ptr_eq(&field_type, other) {
                return 0;
            }
            -1
        }
        // type.cc:2536-2540 TypePartialUnion::findCompatibleResolve
        Datatype::PartialUnion(pu) => find_compatible_resolve(&pu.container, other),
        // type.cc:596-600 Datatype::findCompatibleResolve (base).
        _ => -1,
    }
}

// Ghidra: varnode.cc:639 Varnode::getTypeReadFacing
/// The resolved data-type of `vn` as read by `op` at `slot` — the fd-aware
/// twin of the degenerate `Varnode::get_type_read_facing_op` (varnode.rs
/// write-domain): `type->findResolve(op, slot)` when the instance type
/// needs resolution (varnode.cc:639-645).
pub fn vn_type_read_facing(
    fd: &crate::funcdata::Funcdata,
    vn: &Arc<RwLock<Varnode>>,
    op: &PcodeOpRef,
    slot: i32,
) -> Option<Arc<Datatype>> {
    let ct = vn.read().unwrap().get_type()?;
    if !ct.needs_resolution() {
        return Some(ct);
    }
    Some(find_resolve(fd, &ct, op, slot))
}

// Ghidra: varnode.cc:626 Varnode::getTypeDefFacing
/// The resolved data-type of `vn` as written by its defining op —
/// `type->findResolve(def, -1)` when the instance type needs resolution
/// (varnode.cc:626-632).
pub fn vn_type_def_facing(
    fd: &crate::funcdata::Funcdata,
    vn: &Arc<RwLock<Varnode>>,
) -> Option<Arc<Datatype>> {
    let (ct, def) = {
        let rg = vn.read().unwrap();
        (rg.get_type(), rg.get_def())
    };
    let ct = ct?;
    if !ct.needs_resolution() {
        return Some(ct);
    }
    let def = def?;
    Some(find_resolve(fd, &ct, &PcodeOpRef(def), -1))
}

// Ghidra: varnode.cc:665 Varnode::getHighTypeReadFacing
/// The resolved HighVariable type of `vn` as read by `op` at `slot` —
/// `ct->findResolve(op, slot)` when the high type needs resolution
/// (varnode.cc:665-672). This is the read the ② `(char **)` leaf takes
/// (TypeOpStore::getInputCast, typeop.cc:525/527).
pub fn vn_high_type_read_facing(
    fd: &crate::funcdata::Funcdata,
    vn: &Arc<RwLock<Varnode>>,
    op: &PcodeOpRef,
    slot: i32,
) -> Option<Arc<Datatype>> {
    let ct = {
        let rg = vn.read().unwrap();
        rg.high.as_ref().map(|h| h.read().unwrap().get_type())
    }?;
    if !ct.needs_resolution() {
        return Some(ct);
    }
    Some(find_resolve(fd, &ct, op, slot))
}

// Ghidra: varnode.cc:651 Varnode::getHighTypeDefFacing
/// The resolved HighVariable type of `vn` as written by its defining op —
/// `ct->findResolve(def, -1)` when the high type needs resolution
/// (varnode.cc:651-658).
pub fn vn_high_type_def_facing(
    fd: &crate::funcdata::Funcdata,
    vn: &Arc<RwLock<Varnode>>,
) -> Option<Arc<Datatype>> {
    let (ct, def) = {
        let rg = vn.read().unwrap();
        (rg.high.as_ref().map(|h| h.read().unwrap().get_type()), rg.get_def())
    };
    let ct = ct?;
    if !ct.needs_resolution() {
        return Some(ct);
    }
    let def = def?;
    Some(find_resolve(fd, &ct, &PcodeOpRef(def), -1))
}

// ===========================================================================
// Free helpers — porting Ghidra inline / virtual dispatch used by the scorer
// ===========================================================================

// RUDRA-GLUE: free-function form of ScoreUnionFields::testSimpleCases, used
//   by the `new` constructor before `self` exists (cc:993).
/// Identify cases where the union should not be resolved to a field.
/// Faithful to `ScoreUnionFields::testSimpleCases` (unionresolve.cc:119-137).
fn test_simple_cases(op: &PcodeOp, in_slot: i32, parent: &Datatype) -> bool {
    ScoreUnionFields::score_simple_cases_inner(op, in_slot, parent)
}

// RUDRA-GLUE: `ScoreUnionFields::scoreTruncation` free-function form taking
//   the scores slice directly, for use during construction.
/// Score an implied truncation, returning the recurse-type if any.
/// Faithful to `ScoreUnionFields::scoreTruncation` (unionresolve.cc:843-879).
fn score_truncation_inplace(
    scores: &mut [i32], ct_in: &Arc<Datatype>, vn_size: usize, offset: i64, score_index: i32,
    result_base: &Arc<Datatype>,
) -> Option<Arc<Datatype>> {
    let idx = score_index as usize;
    if ct_in.get_metatype() == TypeMetatype::Union {
        let union_dt = as_union(ct_in.as_ref());
        let mut score = -10i32;
        if let Some(u) = union_dt {
            for field in &u.fields {
                if field.offset as i64 == offset && field.type_ptr.get_size() == vn_size {
                    score = 10;
                    // cc:856-857: result.getBase() == unionDt identity bonus.
                    if Arc::ptr_eq(result_base, ct_in) { score += 5; }
                    break;
                }
            }
        }
        scores[idx] += score;
        return None;
    }
    let mut score = 10i32;
    let mut cur_off = offset;
    let mut ct: Option<Arc<Datatype>> = Some(ct_in.clone());
    while let Some(c) = &ct {
        if cur_off == 0 && c.get_size() == vn_size { break; }
        if c.get_metatype() == TypeMetatype::Int || c.get_metatype() == TypeMetatype::Uint {
            if c.get_size() >= vn_size + cur_off as usize { score = 1; ct = None; break; }
        }
        let (sub, new_off) = c.get_sub_type(cur_off);
        cur_off = new_off;
        ct = sub;
    }
    if ct.is_none() { score = -10; }
    scores[idx] += score;
    ct
}

// RUDRA-GLUE: Datatype::numDepend / getDepend aggregator. Mirrors Ghidra's
//   per-variant virtual dispatch.
/// Number of dependency sub-types. Faithful to `Datatype::numDepend`.
fn num_depend(dt: &Datatype) -> usize {
    match dt {
        Datatype::Struct(s) => s.fields.len(),
        Datatype::Union(u) => u.fields.len(),
        Datatype::Pointer(_) | Datatype::Array(_) | Datatype::Code(_) => 1,
        _ => 0,
    }
}

// RUDRA-GLUE: `Datatype::getDepend(i)` aggregator.
/// Get the i-th dependency sub-type. Faithful to `Datatype::getDepend`.
/// Public for the pipeline wiring (coreaction.cc:2441
/// `inType->getDepend(inResolve)` in tryResolutionAdjustment).
pub fn get_depend(dt: &Datatype, i: usize) -> Arc<Datatype> {
    match dt {
        Datatype::Struct(s) => s.fields[i].type_ptr.clone(),
        Datatype::Union(u) => u.fields[i].type_ptr.clone(),
        Datatype::Pointer(p) => p.ptr_to.clone(),
        Datatype::Array(a) => a.array_of.clone(),
        Datatype::Code(c) => c.proto.as_ref()
            .map(|p| p.return_type.clone())
            .unwrap_or_else(|| Arc::new(empty_placeholder())),
        _ => Arc::new(empty_placeholder()),
    }
}

// RUDRA-GLUE: equivalent of `parent->getDepend(fldNum)` used by the
//   ResolvedUnion field constructor (cc:53,57).
/// Get the i-th dependency sub-type as a borrowed reference.
fn depend_at(dt: &Datatype, i: usize) -> Arc<Datatype> { get_depend(dt, i) }

// RUDRA-GLUE: Datatype pointer helpers.
/// Borrow the pointee of a pointer type, or the type itself if not a pointer.
fn pointee_of(dt: &Datatype) -> &Datatype {
    match dt { Datatype::Pointer(p) => p.ptr_to.as_ref(), _ => dt }
}

// RUDRA-GLUE: Rust enum downcast for repeated TypePointer::getPtrTo uses;
// Ghidra performs checked TYPE_PTR casts inline and has no such free helper.
/// `Some(pointee)` if `dt` is a pointer, else `None`.
fn pointer_pointee(dt: &Datatype) -> Option<&Datatype> {
    match dt { Datatype::Pointer(p) => Some(p.ptr_to.as_ref()), _ => None }
}

// RUDRA-GLUE: Rust enum downcast replacing Ghidra's inline TypeUnion pointer
// casts; unionresolve.cc declares no standalone asUnion helper.
/// `Some(&TypeUnion)` for union types.
fn as_union(dt: &Datatype) -> Option<&TypeUnion> {
    match dt { Datatype::Union(u) => Some(u), _ => None }
}

// RUDRA-GLUE: Arc ownership helper for inline TypePointer::getPtrTo operations
// such as unionresolve.cc:30 and :70; Ghidra returns borrowed raw pointers.
/// Strip one pointer layer, returning a cloned Arc for ownership.
fn strip_pointer_layer(dt: &Arc<Datatype>) -> Arc<Datatype> {
    match dt.as_ref() { Datatype::Pointer(p) => p.ptr_to.clone(), _ => dt.clone() }
}

// RUDRA-GLUE: Rust enum helper for the conditional getWordSize expression at
// unionresolve.cc:995; Ghidra has no standalone pointeeWordSize function.
/// Word size of a pointer type (0 if not a pointer).
fn pointee_word_size(dt: &Datatype) -> usize {
    match dt { Datatype::Pointer(p) => p.wordsize, _ => 0 }
}

// RUDRA-GLUE: Return the (field list, field count) for a union-typed parent.
fn union_field_list(dt: &Datatype) -> (Vec<TypeField>, usize) {
    match dt {
        Datatype::Union(u) => { let count = u.fields.len(); (u.fields.clone(), count) }
        _ => (Vec::new(), 0),
    }
}

// Ghidra: type.cc:3849 TypeFactory::getTypePointerStripArray
/// Construct a pointer to the given data-type, stripping the formal
/// stripped twin and one ARRAY level from the pointee first. Faithful to
/// `TypeFactory::getTypePointerStripArray` (type.cc:3849-3859): the result
/// is factory-INTERNED through findAdd (the cc:3858 calcTruncate step is
/// the known TYPE-0001 structural residual), so pointer-identity
/// comparisons see the canonical instance.
fn get_type_pointer_strip_array(
    typegrp: &mut TypeFactory, size: usize, ptrto: Arc<Datatype>, wordsize: usize,
) -> Arc<Datatype> {
    let mut pt = ptrto;
    // cc:3851-3852: strip the formal twin, then the first array level.
    if let Some(stripped) = Datatype::get_stripped_arc(&pt) { pt = stripped; }
    if let Datatype::Array(a) = pt.as_ref() { pt = a.array_of.clone(); }
    typegrp.get_type_pointer(size, pt, wordsize)
}

// RUDRA-GLUE: Ghidra `bit_transitions(val,size)` (address.cc). Counts the
//   number of 0->1 and 1->0 bit transitions in the bottom `size*8` bits.
fn bit_transition_count(val: u64, size: usize) -> u32 {
    let bits = (size as u32).saturating_mul(8);
    if bits == 0 { return 0; }
    let mut transitions = 0u32;
    let mut prev = val & 1;
    for i in 1..bits {
        let bit = (val >> i) & 1;
        if bit != prev { transitions += 1; prev = bit; }
    }
    transitions
}

// RUDRA-GLUE: Construct a placeholder Datatype for the legacy string ctors.
fn name_placeholder(name: &str) -> Arc<Datatype> {
    Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
        name.to_string(), 0, TypeMetatype::Unknown)))
}

// RUDRA-GLUE: A distinct empty placeholder for score slots that Ghidra leaves
//   as `(Datatype *)0`.
fn empty_placeholder() -> Datatype {
    Datatype::Base(crate::type_system::datatype::TypeBase::new(
        String::new(), 0, TypeMetatype::Unknown))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_union_self() {
        let r = ResolvedUnion::new_self("union_tag");
        assert_eq!(r.get_datatype_name(), "union_tag");
        assert_eq!(r.get_base_name(), "union_tag");
        assert_eq!(r.get_field_num(), -1);
        assert!(!r.is_locked());
    }

    #[test]
    fn test_resolved_union_field() {
        let r = ResolvedUnion::new_field("union_tag", "field_x", 2);
        assert_eq!(r.get_datatype_name(), "field_x");
        assert_eq!(r.get_base_name(), "union_tag");
        assert_eq!(r.get_field_num(), 2);
    }

    #[test]
    fn test_resolved_union_lock() {
        let mut r = ResolvedUnion::new_self("u");
        r.set_lock(true);
        assert!(r.is_locked());
        r.set_lock(false);
        assert!(!r.is_locked());
    }

    #[test]
    fn test_resolve_edge_ordering() {
        let e1 = ResolveEdge::from_components(1, 10, 0, false);
        let e2 = ResolveEdge::from_components(1, 10, 1, false);
        let e3 = ResolveEdge::from_components(2, 5, 0, false);
        assert!(e1 < e2);
        assert!(e2 < e3);
    }

    #[test]
    fn test_resolve_edge_pointer_encoding() {
        let e_no_ptr = ResolveEdge::from_components(1, 10, 0, false);
        let e_ptr = ResolveEdge::from_components(1, 10, 0, true);
        assert_eq!(e_no_ptr.encoding, 0);
        assert_eq!(e_ptr.encoding, 0x1000);
        assert!(e_no_ptr < e_ptr);
    }

    #[test]
    fn test_visit_mark_ordering() {
        // Use from_id for deterministic key ordering (Arc pointer addresses
        // are not guaranteed to reflect allocation order).
        let m1 = VisitMark::from_id(0x100, 0);
        let m1b = VisitMark::from_id(0x100, 1);
        let m2 = VisitMark::from_id(0x200, 0);
        assert!(m1 < m1b);  // same vn, lower index first
        assert!(m1b < m2);  // lower vn_key first
        let a = VisitMark::from_id(0x100, 0);
        let b = VisitMark::from_id(0x100, 1);
        assert!(a < b);
    }

    #[test]
    fn test_constants_match_ghidra() {
        assert_eq!(MAX_PASSES, 6);
        assert_eq!(THRESHOLD, 256);
        assert_eq!(MAX_TRIALS, 1024);
        assert!(MAX_TRIALS > THRESHOLD);
    }

    #[test]
    fn test_with_field_names_construction() {
        let s = ScoreUnionFields::with_field_names(
            "union_tag", &["field_a".to_string(), "field_b".to_string()]);
        assert_eq!(s.num_fields(), 3);
        assert_eq!(s.scores.len(), 3);
        assert_eq!(s.fields[0].get_name(), "union_tag");
        assert_eq!(s.fields[1].get_name(), "field_a");
        assert_eq!(s.fields[2].get_name(), "field_b");
    }

    #[test]
    fn test_compute_best_index_whole_union() {
        let mut s = ScoreUnionFields::with_field_names("u", &["a".to_string(), "b".to_string()]);
        s.compute_best_index();
        assert_eq!(s.get_result().get_field_num(), -1);
    }

    #[test]
    fn test_compute_best_index_specific_field() {
        let mut s = ScoreUnionFields::with_field_names("u", &["a".to_string(), "b".to_string()]);
        s.add_score(2, 5);
        s.compute_best_index();
        assert_eq!(s.get_result().get_field_num(), 1);
        assert_eq!(s.get_result().get_datatype_name(), "b");
    }

    #[test]
    fn test_score_locked_type_int_uint_mismatch() {
        let int_t = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int));
        let uint_t = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "uint".into(), 4, TypeMetatype::Uint));
        assert_eq!(ScoreUnionFields::score_locked_type(&int_t, &uint_t), -1);
        let other_int = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int));
        assert_eq!(ScoreUnionFields::score_locked_type(&int_t, &other_int), 3);
    }

    #[test]
    fn test_score_locked_type_struct_container_match() {
        let mk_struct = |name: &str| {
            Datatype::Struct(crate::type_system::datatype::TypeStruct {
                base: crate::type_system::datatype::TypeBase::new(
                    name.into(), 8, TypeMetatype::Struct),
                fields: vec![],
            })
        };
        let container = mk_struct("T");
        assert_eq!(ScoreUnionFields::score_locked_type(&container, &container), 15);
    }

    #[test]
    fn test_deref_pointer_size_match() {
        let int_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int)));
        let ptr = Datatype::Pointer(crate::type_system::datatype::TypePointer {
            base: crate::type_system::datatype::TypeBase::new(
                "int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int_t, wordsize: 1,
        });
        let (rt, score) = ScoreUnionFields::deref_pointer(&ptr, 4);
        assert_eq!(score, 10);
        assert!(rt.is_some());
        assert_eq!(rt.unwrap().get_size(), 4);
        let (rt, score) = ScoreUnionFields::deref_pointer(&ptr, 1);
        assert_eq!(score, 0);
        assert!(rt.is_none());
        let base = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int));
        let (rt, score) = ScoreUnionFields::deref_pointer(&base, 4);
        assert_eq!(score, -10);
        assert!(rt.is_none());
    }

    #[test]
    fn test_bit_transition_count() {
        assert_eq!(bit_transition_count(0, 1), 0);
        assert_eq!(bit_transition_count(0xff, 1), 0);
        assert_eq!(bit_transition_count(0x55, 1), 7);
        assert_eq!(bit_transition_count(0x01, 1), 1);
    }

    #[test]
    fn test_num_depend_and_get_depend() {
        let int_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int)));
        let char_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "char".into(), 1, TypeMetatype::Int)));
        let u = Datatype::Union(crate::type_system::datatype::TypeUnion {
            base: crate::type_system::datatype::TypeBase::new("U".into(), 4, TypeMetatype::Union),
            fields: vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: int_t },
                TypeField { name: "b".into(), offset: 0, type_ptr: char_t },
            ],
        });
        assert_eq!(num_depend(&u), 2);
        // get_depend returns the field TYPE (type_ptr), not the field name.
        assert_eq!(get_depend(&u, 0).get_name(), "int");
        assert_eq!(get_depend(&u, 1).get_name(), "char");
        let int_base = Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int));
        assert_eq!(num_depend(&int_base), 0);
    }

    fn mk_union(name: &str, size: usize) -> Arc<Datatype> {
        Arc::new(Datatype::Union(TypeUnion {
            base: crate::type_system::datatype::TypeBase::new(
                name.into(), size, TypeMetatype::Union),
            fields: vec![],
        }))
    }

    #[test]
    fn test_resolve_edge_partial_union_keys_by_container() {
        use crate::address::{Address, SeqNum};
        use crate::opcodes::OpCode as Op;
        let union_dt = mk_union("U", 8);
        let pu = Datatype::PartialUnion(crate::type_system::datatype::TypePartialUnion::new(
            union_dt.clone(), 0, 4, None));
        let op = crate::op::PcodeOp::new(SeqNum::new(Address::new(0x1000), 7), Op::CPUI_COPY);
        let edge = ResolveEdge::new(&pu, &op, 1);
        // cc:73-74: key = container union id, encoding NOT bumped.
        assert_eq!(edge.type_id, union_dt.get_id());
        assert_eq!(edge.encoding, 1);
        let plain = ResolveEdge::new(union_dt.as_ref(), &op, 1);
        assert_eq!(edge.type_id, plain.type_id);
    }

    #[test]
    fn test_with_field_pointer_parent_builds_field_pointer() {
        let set_struct = Arc::new(Datatype::Struct(crate::type_system::datatype::TypeStruct {
            base: crate::type_system::datatype::TypeBase::new(
                "Set".into(), 16, TypeMetatype::Struct),
            fields: vec![],
        }));
        let union_dt = Arc::new(Datatype::Union(TypeUnion {
            base: crate::type_system::datatype::TypeBase::new(
                "U".into(), 16, TypeMetatype::Union),
            fields: vec![TypeField {
                name: "Set".into(), offset: 0, type_ptr: set_struct.clone(),
            }],
        }));
        let parent = Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer::new(
            8, union_dt, 1)));
        let mut factory = TypeFactory::new(8);
        factory.set_default_alignment_map();
        // cc:51-55: pointer parent resolves to a POINTER to the field.
        let r = ResolvedUnion::with_field(parent.clone(), 0, &mut factory);
        assert_eq!(r.get_field_num(), 0);
        let resolve = r.get_datatype();
        assert!(matches!(resolve.as_ref(), Datatype::Pointer(_)));
        assert_eq!(resolve.get_size(), 8);
        match resolve.as_ref() {
            Datatype::Pointer(p) => assert!(Arc::ptr_eq(&p.ptr_to, &set_struct)),
            _ => unreachable!(),
        }
        // fldNum < 0 resolves to the parent itself (cc:48-49).
        let r_self = ResolvedUnion::with_field(parent.clone(), -1, &mut factory);
        assert_eq!(r_self.get_field_num(), -1);
        assert!(Arc::ptr_eq(r_self.get_datatype(), &parent));
        // UNIONRESOLVE-PKG-G-0001: the pointer arm interns through the
        // factory (cc:54 typegrp.getTypePointer) — a second mint of the same
        // (size, field, wordsize) pointer returns the identical Arc, which
        // is what cast.cc:303's `curtype == reqtype` short-circuit rides on.
        let again = factory.get_type_pointer(8, set_struct.clone(), 1);
        assert!(
            Arc::ptr_eq(r.get_datatype(), &again),
            "with_field pointer arm must be factory-interned"
        );
    }

    #[test]
    fn test_with_field_partial_union_parent_unwraps_container() {
        let union_dt = mk_union("U", 8);
        let int_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int)));
        let union_field = Arc::new(Datatype::Union(TypeUnion {
            base: crate::type_system::datatype::TypeBase::new(
                "U".into(), 8, TypeMetatype::Union),
            fields: vec![TypeField { name: "x".into(), offset: 0, type_ptr: int_t.clone() }],
        }));
        let union_dt = union_field;
        let pu = Arc::new(Datatype::PartialUnion(
            crate::type_system::datatype::TypePartialUnion::new(union_dt.clone(), 0, 4, None)));
        let mut factory = TypeFactory::new(8);
        // cc:43-44: the partial-union parent resolves within the container.
        let r = ResolvedUnion::with_field(pu, 0, &mut factory);
        assert!(Arc::ptr_eq(r.get_base(), &union_dt));
        assert!(Arc::ptr_eq(r.get_datatype(), &int_t));
    }

    #[test]
    fn test_get_type_pointer_strip_array_interns_pointer() {
        let mut factory = TypeFactory::new(8);
        factory.set_default_alignment_map();
        let elem = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "char".into(), 1, TypeMetatype::Int)));
        let arr = Arc::new(Datatype::Array(crate::type_system::datatype::TypeArray {
            base: crate::type_system::datatype::TypeBase::new(
                "char[4]".into(), 4, TypeMetatype::Array),
            array_of: elem.clone(),
            num_elements: 4,
        }));
        // type.cc:3849-3859: the result is a POINTER (8B) to the stripped
        // element, interned so repeat calls return the same instance.
        let p1 = get_type_pointer_strip_array(&mut factory, 8, arr, 1);
        assert!(matches!(p1.as_ref(), Datatype::Pointer(_)));
        assert_eq!(p1.get_size(), 8);
        match p1.as_ref() {
            Datatype::Pointer(p) => assert!(Arc::ptr_eq(&p.ptr_to, &elem)),
            _ => unreachable!(),
        }
        let arr2 = Arc::new(Datatype::Array(crate::type_system::datatype::TypeArray {
            base: crate::type_system::datatype::TypeBase::new(
                "char[4]".into(), 4, TypeMetatype::Array),
            array_of: elem.clone(),
            num_elements: 4,
        }));
        let p2 = get_type_pointer_strip_array(&mut factory, 8, arr2, 1);
        assert!(Arc::ptr_eq(&p1, &p2), "strip-array pointer must be interned");
    }

    #[test]
    fn test_simple_cases_array_arith_uses_stripped_union_size() {
        use crate::address::{Address, SeqNum};
        use crate::opcodes::OpCode as Op;
        // union U is 32 bytes; the pointer parent is 8 bytes.
        let union_dt = mk_union("U", 32);
        let parent = Datatype::Pointer(crate::type_system::datatype::TypePointer::new(
            8, union_dt, 1));
        let mut op = crate::op::PcodeOp::new(
            SeqNum::new(Address::new(0x2000), 1), Op::CPUI_INT_ADD);
        op.inrefs = vec![
            std::sync::Arc::new(std::sync::RwLock::new(
                crate::varnode::Varnode::new_register(0x10, 8))),
            std::sync::Arc::new(std::sync::RwLock::new(
                crate::varnode::Varnode::new_constant(16, 8))),
        ];
        // cc:94 + cc:993: 16 < union size 32 → NOT array arithmetic (the
        // old code compared against the pointer size 8 and fired).
        assert!(!ScoreUnionFields::score_simple_cases_inner(&op, 0, &parent));
        // >= union size still fires the simple case.
        op.inrefs[1] = std::sync::Arc::new(std::sync::RwLock::new(
            crate::varnode::Varnode::new_constant(32, 8)));
        assert!(ScoreUnionFields::score_simple_cases_inner(&op, 0, &parent));
    }

    #[test]
    fn test_resolved_union_typed_new_strips_pointer() {
        let int_t = Arc::new(Datatype::Base(crate::type_system::datatype::TypeBase::new(
            "int".into(), 4, TypeMetatype::Int)));
        let ptr = Arc::new(Datatype::Pointer(crate::type_system::datatype::TypePointer {
            base: crate::type_system::datatype::TypeBase::new(
                "int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: int_t.clone(), wordsize: 1,
        }));
        let r = ResolvedUnion::new(ptr.clone());
        assert_eq!(r.resolve.get_name(), "int *");
        assert_eq!(r.base_type.get_name(), "int");
        assert_eq!(r.field_num, -1);
    }
}
