//! Expression analysis infrastructure: TermOrder, AdditiveEdge, AddExpression.
//!
//! Corresponds to Ghidra's `expression.hh` / `expression.cc`.
//! Used by RuleCollectTerms (constant folding + factoring in additive trees),
//! RuleScarry/RuleSborrow (deep forms), and other rules that need to compare
//! or reorder additive expressions.

use std::sync::{Arc, RwLock};
use crate::varnode::Varnode;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::address::calc_mask;

/// A term in an additive expression. Corresponds to Ghidra's `AdditiveEdge`.
#[derive(Clone)]
pub struct AdditiveEdge {
    /// The op that reads this term
    pub op: Arc<RwLock<PcodeOp>>,
    /// The input slot of the term in that op
    pub slot: usize,
    /// The term Varnode
    pub vn: Arc<RwLock<Varnode>>,
    /// Optional multiplier op (INT_MULT) applied to the term
    pub mult: Option<Arc<RwLock<PcodeOp>>>,
}

impl AdditiveEdge {
    // Ghidra: expression.hh:106 AdditiveEdge::new
    pub fn new(op: Arc<RwLock<PcodeOp>>, slot: usize, mult: Option<Arc<RwLock<PcodeOp>>>) -> Self {
        let vn = op.read().unwrap().inrefs.get(slot).cloned().unwrap();
        Self { op, slot, vn, mult }
    }
    // Ghidra: expression.hh:106 AdditiveEdge::getMultiplier
    pub fn get_multiplier(&self) -> &Option<Arc<RwLock<PcodeOp>>> { &self.mult }
    // Ghidra: expression.hh:106 AdditiveEdge::getOp
    pub fn get_op(&self) -> &Arc<RwLock<PcodeOp>> { &self.op }
    // Ghidra: expression.hh:106 AdditiveEdge::getSlot
    pub fn get_slot(&self) -> usize { self.slot }
    // Ghidra: expression.hh:106 AdditiveEdge::getVarnode
    pub fn get_varnode(&self) -> &Arc<RwLock<Varnode>> { &self.vn }
}

/// A class for ordering Varnode terms in an additive expression.
/// Corresponds to Ghidra's `TermOrder` (expression.hh:124).
pub struct TermOrder {
    root: Arc<RwLock<PcodeOp>>,
    terms: Vec<AdditiveEdge>,
    sorter: Vec<usize>, // indices into terms, sorted
    /// PERF-RULEBODY2-0001: pooled scratch for sortTerms — the oracle's
    /// additiveCompare key projection (expression.cc:292 `sort` comparator)
    /// allocates nothing; the former per-call `keys` Vec paid one malloc per
    /// rule try. Pure storage reuse, no semantic change.
    sort_keys: Vec<TermSortKey>,
    /// PERF-RULEBODY2-0001: pooled collect scratch (the former per-call
    /// opstack Vec paid one malloc per try; the oracle reuses no vector but
    /// builds its opstack on the stack-allocated vector template — the
    /// allocator round-trip is Rust-side storage cost only).
    opstack: Vec<(Arc<RwLock<PcodeOp>>, Option<Arc<RwLock<PcodeOp>>>)>,
}

/// Sort key of an additive term (the additiveCompare projection,
/// expression.cc:292 / varnode.cc:1153-1175 termOrder).
type TermSortKey = (u8, u8, crate::space::AddressSpace, u64);

// PERF-RULEBODY2-0001: thread-local scratch pools backing TermOrder's four
// Vecs. TermOrder is a rule-body-only helper (RuleCollectTerms) constructed
// once per rule try; pooling the buffers removes the per-try heap allocs
// while keeping every drop of an Arc handle at the same observable moment
// (the clear() calls in Drop run exactly where the owned Vecs used to
// destruct). Pools are capped; overflow vectors fall to the allocator.
mod term_scratch {
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::RwLock;

    use crate::op::PcodeOp;

    use super::{AdditiveEdge, TermSortKey};

    thread_local! {
        static TERMS: RefCell<Vec<Vec<AdditiveEdge>>> = const { RefCell::new(Vec::new()) };
        static SORTERS: RefCell<Vec<Vec<usize>>> = const { RefCell::new(Vec::new()) };
        static KEYS: RefCell<Vec<Vec<TermSortKey>>> = const { RefCell::new(Vec::new()) };
        static OPSTACKS: RefCell<
            Vec<Vec<(Arc<RwLock<PcodeOp>>, Option<Arc<RwLock<PcodeOp>>>)>>,
        > = const { RefCell::new(Vec::new()) };
    }

    const POOL_CAP: usize = 4;

    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch-pool take/give pair (pure
    // Rust storage reuse; no Ghidra counterpart — the oracle's vectors
    // allocate per call, which is exactly the cost this removes).
    pub fn take_terms() -> Vec<AdditiveEdge> {
        TERMS.with(|p| p.borrow_mut().pop()).unwrap_or_default()
    }
    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch-pool take (storage-only)
    pub fn take_sorters() -> Vec<usize> {
        SORTERS.with(|p| p.borrow_mut().pop()).unwrap_or_default()
    }
    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch-pool take (storage-only)
    pub fn take_keys() -> Vec<TermSortKey> {
        KEYS.with(|p| p.borrow_mut().pop()).unwrap_or_default()
    }
    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch-pool take (storage-only)
    pub fn take_opstacks() -> Vec<(Arc<RwLock<PcodeOp>>, Option<Arc<RwLock<PcodeOp>>>)> {
        OPSTACKS.with(|p| p.borrow_mut().pop()).unwrap_or_default()
    }

    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch-pool give (storage-only)
    pub fn give_terms(v: Vec<AdditiveEdge>) {
        if v.capacity() > 0 {
            TERMS.with(|p| {
                let mut pool = p.borrow_mut();
                if pool.len() < POOL_CAP {
                    pool.push(v);
                }
            });
        }
    }
    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch-pool give (storage-only)
    pub fn give_sorters(v: Vec<usize>) {
        if v.capacity() > 0 {
            SORTERS.with(|p| {
                let mut pool = p.borrow_mut();
                if pool.len() < POOL_CAP {
                    pool.push(v);
                }
            });
        }
    }
    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch-pool give (storage-only)
    pub fn give_keys(v: Vec<TermSortKey>) {
        if v.capacity() > 0 {
            KEYS.with(|p| {
                let mut pool = p.borrow_mut();
                if pool.len() < POOL_CAP {
                    pool.push(v);
                }
            });
        }
    }
    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch-pool give (storage-only)
    pub fn give_opstacks(v: Vec<(Arc<RwLock<PcodeOp>>, Option<Arc<RwLock<PcodeOp>>>)>) {
        if v.capacity() > 0 {
            OPSTACKS.with(|p| {
                let mut pool = p.borrow_mut();
                if pool.len() < POOL_CAP {
                    pool.push(v);
                }
            });
        }
    }
}

impl TermOrder {
    // Ghidra: expression.hh:124 TermOrder::new
    pub fn new(root: Arc<RwLock<PcodeOp>>) -> Self {
        Self {
            root,
            terms: term_scratch::take_terms(),
            sorter: term_scratch::take_sorters(),
            sort_keys: term_scratch::take_keys(),
            opstack: term_scratch::take_opstacks(),
        }
    }

    // Ghidra: expression.hh:124 TermOrder::getSize
    pub fn get_size(&self) -> usize { self.terms.len() }

    // Ghidra: expression.cc:236 TermOrder::collect
    /// Collect all the terms in the additive expression rooted at `root`.
    /// Faithful to `TermOrder::collect` (expression.cc:236-283).
    /// PERF-OPPOOL-0001: one PcodeOp read per stack pop (the input Arc list
    /// is cloned once per op, not re-locked per edge), one Varnode read per
    /// edge covering isWritten/loneDescend/def together, and AdditiveEdge is
    /// constructed directly from the already-cloned handle (its constructor
    /// re-locks the reading op, expression.hh:106 `vn = op->getIn(slot)` is a
    /// raw read in the oracle). Same LIFO stack order, same per-slot scan
    /// order, same term push order as the oracle loop.
    pub fn collect(&mut self) {
        // PERF-RULEBODY2-0001: the input scan runs under one per-op read
        // guard instead of cloning the inrefs Vec first — the oracle reads
        // `curop->getIn(i)` as raw pointers (expression.cc:254), and each
        // pushed AdditiveEdge clones exactly the handles it stores. The
        // former form paid one heap alloc plus an Arc round-trip pair for
        // EVERY input (then cloned the pushed ones a second time).
        // Same LIFO stack order, same per-slot scan order, same term push
        // order as the oracle loop.
        self.opstack.clear();
        self.opstack.push((self.root.clone(), None));
        while let Some((curop, multop)) = self.opstack.pop() {
            let op = curop.read().unwrap();
            for (i, curvn) in op.inrefs.iter().enumerate() {
                // One Varnode lock per edge: the three fields the oracle
                // reads as isWritten / loneDescend / getDef.
                let (is_written, lone, subop) = {
                    let vn = curvn.read().unwrap();
                    (
                        vn.is_written(),
                        vn.lone_descend().is_some(),
                        vn.def.as_ref().and_then(|w| w.upgrade()),
                    )
                };
                if !is_written || !lone {
                    self.terms.push(AdditiveEdge {
                        op: curop.clone(),
                        slot: i,
                        vn: curvn.clone(),
                        mult: multop.clone(),
                    });
                    continue;
                }
                let Some(subop) = subop else {
                    self.terms.push(AdditiveEdge {
                        op: curop.clone(),
                        slot: i,
                        vn: curvn.clone(),
                        mult: multop.clone(),
                    });
                    continue;
                };
                let subopc = subop.read().unwrap().opcode;
                if subopc != OpCode::CPUI_INT_ADD {
                    if subopc == OpCode::CPUI_INT_MULT {
                        // One lock on the MULT op: constant check on in(1)
                        // and the in(0) handle together.
                        let (coef_constant, mult_in0) = {
                            let so = subop.read().unwrap();
                            (
                                so.inrefs
                                    .get(1)
                                    .map_or(false, |v| v.read().unwrap().is_constant()),
                                so.inrefs.get(0).cloned(),
                            )
                        };
                        if coef_constant {
                            if let Some(in0_vn) = mult_in0 {
                                let addop =
                                    in0_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                                if let Some(ao) = addop {
                                    if ao.read().unwrap().opcode == OpCode::CPUI_INT_ADD {
                                        // Ghidra checks the underlying ADD output,
                                        // not the outer MULT output. The latter was
                                        // already proven lone-use through curvn.
                                        let add_output =
                                            ao.read().unwrap().output.clone();
                                        let out_lone = add_output.as_ref().map_or(
                                            false,
                                            |output| output.read().unwrap().lone_descend().is_some(),
                                        );
                                        if out_lone {
                                            self.opstack.push((ao, Some(subop.clone())));
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    self.terms.push(AdditiveEdge {
                        op: curop.clone(),
                        slot: i,
                        vn: curvn.clone(),
                        mult: multop.clone(),
                    });
                    continue;
                }
                self.opstack.push((subop, multop.clone()));
            }
        }
    }

    // Ghidra: expression.cc:285 TermOrder::sortTerms
    /// Sort terms with `Varnode::term_order` (constant class, coefficient-
    /// stripped storage address), matching Ghidra's `additiveCompare` key.
    /// Faithful to `TermOrder::sortTerms` (expression.cc:285-293).
    /// PERF-OPPOOL-0001: the additiveCompare projection (constant class,
    /// MULT-stripped storage address — varnode.cc:1153-1175 termOrder) is
    /// precomputed once per term instead of paying the Varnode/def-op lock
    /// pair per comparison. Equal keys keep the stable relative order the
    /// previous per-comparison form produced (Rust sort_by is stable; the
    /// projection is identical, so Less/Greater/Equal verdicts per pair are
    /// unchanged).
    pub fn sort_terms(&mut self) {
        let term_key =
            |edge: &AdditiveEdge| -> TermSortKey {
                let vn = edge.vn.read().unwrap();
                if vn.is_constant() {
                    // Constants form one tie class that sorts after every
                    // non-constant (varnode.cc:1157-1160).
                    return (1, 0, crate::space::AddressSpace::Const, 0);
                }
                // varnode.cc:1162-1172: strip one INT_MULT(_, constant) wrapper.
                let base = vn.get_def().and_then(|def| {
                    let operation = def.read().unwrap();
                    if operation.get_opcode() != OpCode::CPUI_INT_MULT {
                        return None;
                    }
                    let coefficient = operation.get_in(1)?;
                    if !coefficient.read().unwrap().is_constant() {
                        return None;
                    }
                    operation.get_in(0).cloned()
                });
                if let Some(base) = base {
                    let base = base.read().unwrap();
                    (
                        0,
                        base.address_space.space_id(),
                        base.address_space,
                        base.loc.as_u64(),
                    )
                } else {
                    (
                        0,
                        vn.address_space.space_id(),
                        vn.address_space,
                        vn.loc.as_u64(),
                    )
                }
            };
        // PERF-RULEBODY2-0001: the key projection lands in the pooled
        // sort_keys buffer (cleared each call); the sorter is rebuilt into
        // its pooled buffer. Same stable sort, same comparator verdicts.
        self.sort_keys.clear();
        self.sort_keys.extend(self.terms.iter().map(term_key));
        self.sorter.clear();
        self.sorter.extend(0..self.terms.len());
        self.sorter.sort_by(|&a, &b| {
            if Arc::ptr_eq(&self.terms[a].vn, &self.terms[b].vn) {
                return std::cmp::Ordering::Equal;
            }
            self.sort_keys[a].cmp(&self.sort_keys[b])
        });
    }

    // RUDRA-GLUE: PERF-RULEBODY2-0001 scratch return — returns the four
    // buffers (after clear) to the thread-local pools. The clear() calls
    // drop exactly the Arc handles the owned Vecs used to drop at the same
    // statement-end moment, so the observable destruction order is
    // unchanged; nothing Ghidra-side corresponds (the oracle's vectors
    // destruct at scope exit either way).
    fn return_scratch(&mut self) {
        self.terms.clear();
        self.sorter.clear();
        self.sort_keys.clear();
        self.opstack.clear();
        term_scratch::give_terms(std::mem::take(&mut self.terms));
        term_scratch::give_sorters(std::mem::take(&mut self.sorter));
        term_scratch::give_keys(std::mem::take(&mut self.sort_keys));
        term_scratch::give_opstacks(std::mem::take(&mut self.opstack));
    }

    // Ghidra: expression.hh:124 TermOrder::getSort
    /// Get the sorted list of term indices.
    pub fn get_sort(&self) -> &[usize] { &self.sorter }

    // Ghidra: expression.hh:124 TermOrder::getTerm
    /// Get a term by index.
    pub fn get_term(&self, idx: usize) -> Option<&AdditiveEdge> {
        self.terms.get(idx)
    }
}

impl Drop for TermOrder {
    // RUDRA-GLUE: PERF-RULEBODY2-0001 pooled-buffer recycle (no Ghidra
    // counterpart; storage-only).
    fn drop(&mut self) {
        self.return_scratch();
    }
}

/// A term in an AddExpression.
#[derive(Clone)]
struct ExprTerm {
    vn: Arc<RwLock<Varnode>>,
    coeff: u64,
}

impl ExprTerm {
    // Ghidra: expression.cc:299 AddExpression::Term::isEquivalent
    fn is_equivalent(&self, op2: &ExprTerm) -> bool {
        if self.coeff != op2.coeff { return false; }
        functional_equality(&self.vn, &op2.vn)
    }
}

/// Lightweight matching of two additive expressions (up to 2 terms).
/// Corresponds to Ghidra's `AddExpression` (expression.hh:141).
pub struct AddExpression {
    constval: u64,
    num_terms: usize,
    terms: [Option<ExprTerm>; 2],
}

impl AddExpression {
    // Ghidra: expression.hh:141 AddExpression::new
    pub fn new() -> Self {
        Self { constval: 0, num_terms: 0, terms: [None, None] }
    }

    // Ghidra: expression.hh:141 AddExpression::add
    fn add(&mut self, vn: Arc<RwLock<Varnode>>, coeff: u64) {
        if self.num_terms < 2 {
            self.terms[self.num_terms] = Some(ExprTerm { vn, coeff });
            self.num_terms += 1;
        }
    }

    // Ghidra: expression.cc:333 AddExpression::gather
    /// Recursively collect terms. Faithful to `AddExpression::gather`
    /// (expression.cc:333-363).
    fn gather(&mut self, vn: &Arc<RwLock<Varnode>>, coeff: u64, depth: i32) {
        let v = vn.read().unwrap();
        if v.is_constant() {
            self.constval = self.constval.wrapping_add(coeff.wrapping_mul(v.get_offset()));
            let mask = calc_mask(v.get_size());
            self.constval &= mask;
            return;
        }
        let is_written = v.is_written();
        let def = v.def.as_ref().and_then(|w| w.upgrade());
        drop(v);
        if is_written {
            if let Some(op) = def {
                let opc = op.read().unwrap().opcode;
                if opc == OpCode::CPUI_INT_ADD {
                    let in1_const = op.read().unwrap().inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant());
                    let new_depth = if !in1_const { depth - 1 } else { depth };
                    if new_depth >= 0 {
                        let in0 = op.read().unwrap().inrefs[0].clone();
                        let in1 = op.read().unwrap().inrefs[1].clone();
                        self.gather(&in0, coeff, new_depth);
                        self.gather(&in1, coeff, new_depth);
                        return;
                    }
                } else if opc == OpCode::CPUI_INT_MULT {
                    let in1_const = op.read().unwrap().inrefs.get(1).map_or(false, |v| v.read().unwrap().is_constant());
                    if in1_const {
                        let mult_val = op.read().unwrap().inrefs[1].read().unwrap().get_offset();
                        let vn_size = op.read().unwrap().inrefs[1].read().unwrap().get_size();
                        let new_coeff = coeff.wrapping_mul(mult_val) & calc_mask(vn_size);
                        let in0 = op.read().unwrap().inrefs[0].clone();
                        self.gather(&in0, new_coeff, depth);
                        return;
                    }
                }
            }
        }
        self.add(vn.clone(), coeff);
    }

    // Ghidra: expression.cc:368 AddExpression::gatherTwoTermsSubtract
    /// Gather terms from two roots being subtracted.
    pub fn gather_two_terms_subtract(&mut self, a: &Arc<RwLock<Varnode>>, b: &Arc<RwLock<Varnode>>) {
        let depth = if a.read().unwrap().is_constant() || b.read().unwrap().is_constant() { 1 } else { 0 };
        self.gather(a, 1, depth);
        let b_size = b.read().unwrap().get_size();
        self.gather(b, calc_mask(b_size), depth);
    }

    // Ghidra: expression.cc:379 AddExpression::gatherTwoTermsAdd
    /// Gather terms from two roots being added.
    pub fn gather_two_terms_add(&mut self, a: &Arc<RwLock<Varnode>>, b: &Arc<RwLock<Varnode>>) {
        let depth = if a.read().unwrap().is_constant() || b.read().unwrap().is_constant() { 1 } else { 0 };
        self.gather(a, 1, depth);
        self.gather(b, 1, depth);
    }

    // Ghidra: expression.cc:389 AddExpression::gatherTwoTermsRoot
    /// Gather up to 2 terms from a single root.
    pub fn gather_two_terms_root(&mut self, root: &Arc<RwLock<Varnode>>) {
        self.gather(root, 1, 1);
    }

    // Ghidra: expression.cc:309 AddExpression::isEquivalent
    /// Determine if two expressions are equivalent.
    pub fn is_equivalent(&self, op2: &AddExpression) -> bool {
        if self.constval != op2.constval { return false; }
        if self.num_terms != op2.num_terms { return false; }
        if self.num_terms == 1 {
            if let (Some(t0), Some(o0)) = (&self.terms[0], &op2.terms[0]) {
                return t0.is_equivalent(o0);
            }
        } else if self.num_terms == 2 {
            if let (Some(t0), Some(t1), Some(o0), Some(o1)) = (&self.terms[0], &self.terms[1], &op2.terms[0], &op2.terms[1]) {
                if t0.is_equivalent(o0) && t1.is_equivalent(o1) { return true; }
                if t0.is_equivalent(o1) && t1.is_equivalent(o0) { return true; }
            }
        }
        false
    }
}

// ===========================================================================
// BooleanMatch — expression.cc:57-216
// ===========================================================================

/// Boolean value correlation codes. Faithful to the enum in
/// `BooleanMatch` (expression.hh:84-88).
pub mod boolean_match {
    /// Pair always holds the same value.
    pub const SAME: i32 = 1;
    /// Pair always holds complementary values.
    pub const COMPLEMENTARY: i32 = 2;
    /// Pair values are uncorrelated.
    pub const UNCORRELATED: i32 = 3;
}

// Ghidra: expression.hh:141 AddExpression::sameOpComplement
/// Check if two comparison ops are complements via the `x < n, n-1 < x`
/// pattern. Faithful to `BooleanMatch::sameOpComplement`
/// (expression.cc:57-86).
fn same_op_complement(
    bin1op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    bin2op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
) -> bool {
    use crate::address::signbit_negative;
    let op1 = bin1op.read().unwrap();
    let op2 = bin2op.read().unwrap();
    let opcode = op1.opcode;
    if opcode == OpCode::CPUI_INT_SLESS || opcode == OpCode::CPUI_INT_LESS {
        // Find constant slot in op1.
        let constslot = if op1.inrefs.get(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
            1
        } else {
            0
        };
        // op1.inrefs[constslot] must be constant.
        if !op1.inrefs.get(constslot).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
            return false;
        }
        // op2.inrefs[1-constslot] must be constant.
        if !op2.inrefs.get(1 - constslot).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) {
            return false;
        }
        // The non-constant inputs must match.
        let vn1 = &op1.inrefs[1 - constslot];
        let vn2 = &op2.inrefs[constslot];
        if !varnode_same(vn1, vn2) {
            return false;
        }
        let mut val1 = op1.inrefs[constslot].read().unwrap().get_offset();
        let mut val2 = op2.inrefs[1 - constslot].read().unwrap().get_offset();
        if constslot != 0 {
            std::mem::swap(&mut val2, &mut val1);
        }
        if val1.wrapping_add(1) != val2 {
            return false;
        }
        if val2 == 0 && opcode == OpCode::CPUI_INT_LESS {
            return false; // Corner case for unsigned.
        }
        if opcode == OpCode::CPUI_INT_SLESS {
            let sz = op1.inrefs[constslot].read().unwrap().get_size();
            if signbit_negative(val2, sz) && !signbit_negative(val1, sz) {
                return false;
            }
        }
        return true;
    }
    false
}

// Ghidra: expression.hh:141 AddExpression::varnodeSame
/// Check if two Varnodes hold the same value. Faithful to
/// `BooleanMatch::varnodeSame` (expression.cc:93-100).
fn varnode_same(
    a: &std::sync::Arc<std::sync::RwLock<Varnode>>,
    b: &std::sync::Arc<std::sync::RwLock<Varnode>>,
) -> bool {
    if std::sync::Arc::ptr_eq(a, b) {
        return true;
    }
    let ra = a.read().unwrap();
    let rb = b.read().unwrap();
    if ra.is_constant() && rb.is_constant() {
        return ra.get_offset() == rb.get_offset();
    }
    false
}

// Ghidra: expression.hh:141 AddExpression::booleanMatchEvaluate
/// Determine if two boolean Varnodes hold related values. Faithful to
/// `BooleanMatch::evaluate` (expression.cc:111-216).
///
/// Returns `boolean_match::SAME`, `boolean_match::COMPLEMENTARY`, or
/// `boolean_match::UNCORRELATED`. Trees constructing each Varnode are
/// examined up to `depth` levels.
pub fn boolean_match_evaluate(
    vn1: &std::sync::Arc<std::sync::RwLock<Varnode>>,
    vn2: &std::sync::Arc<std::sync::RwLock<Varnode>>,
    depth: i32,
) -> i32 {
    use crate::opcodes::get_booleanflip;
    if std::sync::Arc::ptr_eq(vn1, vn2) {
        return boolean_match::SAME;
    }
    // Handle BOOL_NEGATE on vn1.
    let (op1, opc1) = {
        let r = vn1.read().unwrap();
        if r.is_written() {
            let (def, opc) = match r.get_def() {
                Some(d) => {
                    let opc = d.read().unwrap().opcode;
                    (d, opc)
                }
                None => return boolean_match::UNCORRELATED,
            };
            if opc == OpCode::CPUI_BOOL_NEGATE {
                // Recurse with flipped result.
                let in0 = def.read().unwrap().inrefs.get(0).cloned();
                drop(r);
                if let Some(in0) = in0 {
                    let res = boolean_match_evaluate(&in0, vn2, depth);
                    return if res == boolean_match::SAME {
                        boolean_match::COMPLEMENTARY
                    } else if res == boolean_match::COMPLEMENTARY {
                        boolean_match::SAME
                    } else {
                        res
                    };
                }
                return boolean_match::UNCORRELATED;
            }
            (Some(def), opc)
        } else {
            drop(r);
            (None, OpCode::CPUI_MAX)
        }
    };
    // Handle BOOL_NEGATE on vn2.
    let op2 = {
        let r = vn2.read().unwrap();
        if r.is_written() {
            let (def, opc) = match r.get_def() {
                Some(d) => {
                    let opc = d.read().unwrap().opcode;
                    (d, opc)
                }
                None => return boolean_match::UNCORRELATED,
            };
            if opc == OpCode::CPUI_BOOL_NEGATE {
                let in0 = def.read().unwrap().inrefs.get(0).cloned();
                drop(r);
                if let Some(in0) = in0 {
                    let res = boolean_match_evaluate(vn1, &in0, depth);
                    return if res == boolean_match::SAME {
                        boolean_match::COMPLEMENTARY
                    } else if res == boolean_match::COMPLEMENTARY {
                        boolean_match::SAME
                    } else {
                        res
                    };
                }
                return boolean_match::UNCORRELATED;
            }
            Some(def)
        } else {
            drop(r);
            return boolean_match::UNCORRELATED;
        }
    };
    let op1 = match op1 { Some(o) => o, None => return boolean_match::UNCORRELATED };
    let op2 = match op2 { Some(o) => o, None => return boolean_match::UNCORRELATED };
    let opc2 = op2.read().unwrap().opcode;

    // Both must be bool-output ops.
    if !op1.read().unwrap().is_bool_output() || !op2.read().unwrap().is_bool_output() {
        return boolean_match::UNCORRELATED;
    }

    // Check BOOL_AND/OR/XOR recursion.
    if depth != 0 && matches!(opc1, OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR) {
        if matches!(opc2, OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR) {
            if opc1 == opc2
                || (opc1 == OpCode::CPUI_BOOL_AND && opc2 == OpCode::CPUI_BOOL_OR)
                || (opc1 == OpCode::CPUI_BOOL_OR && opc2 == OpCode::CPUI_BOOL_AND)
            {
                let op1_in0 = op1.read().unwrap().inrefs.get(0).cloned();
                let op1_in1 = op1.read().unwrap().inrefs.get(1).cloned();
                let op2_in0 = op2.read().unwrap().inrefs.get(0).cloned();
                let op2_in1 = op2.read().unwrap().inrefs.get(1).cloned();
                let (Some(op1_in0), Some(op1_in1), Some(op2_in0), Some(op2_in1)) =
                    (op1_in0, op1_in1, op2_in0, op2_in1)
                else {
                    return boolean_match::UNCORRELATED;
                };
                let mut pair1 = boolean_match_evaluate(&op1_in0, &op2_in0, depth - 1);
                let pair2;
                if pair1 == boolean_match::UNCORRELATED {
                    pair1 = boolean_match_evaluate(&op1_in0, &op2_in1, depth - 1);
                    if pair1 == boolean_match::UNCORRELATED {
                        return boolean_match::UNCORRELATED;
                    }
                    pair2 = boolean_match_evaluate(&op1_in1, &op2_in0, depth - 1);
                } else {
                    let p2 = boolean_match_evaluate(&op1_in1, &op2_in1, depth - 1);
                    pair2 = p2;
                }
                if pair2 == boolean_match::UNCORRELATED {
                    return boolean_match::UNCORRELATED;
                }
                if opc1 == opc2 {
                    if pair1 == boolean_match::SAME && pair2 == boolean_match::SAME {
                        return boolean_match::SAME;
                    } else if opc1 == OpCode::CPUI_BOOL_XOR {
                        if pair1 == boolean_match::COMPLEMENTARY && pair2 == boolean_match::COMPLEMENTARY {
                            return boolean_match::SAME;
                        }
                        return boolean_match::COMPLEMENTARY;
                    }
                } else {
                    // Must be BOOL_AND and BOOL_OR.
                    if pair1 == boolean_match::COMPLEMENTARY && pair2 == boolean_match::COMPLEMENTARY {
                        return boolean_match::COMPLEMENTARY; // De Morgan's Law.
                    }
                }
            }
        }
    } else {
        // Two boolean output ops, compare directly.
        if opc1 == opc2 {
            let num_inputs = op1.read().unwrap().inrefs.len();
            let mut same_op = true;
            for i in 0..num_inputs {
                let in1 = &op1.read().unwrap().inrefs[i];
                let in2 = &op2.read().unwrap().inrefs[i];
                if !varnode_same(in1, in2) {
                    same_op = false;
                    break;
                }
            }
            if same_op {
                return boolean_match::SAME;
            }
            if same_op_complement(&op1, &op2) {
                return boolean_match::COMPLEMENTARY;
            }
            return boolean_match::UNCORRELATED;
        }
        // Check if binary ops are complements.
        let mut reorder = false;
        let flip_opc = get_booleanflip(opc2, &mut reorder);
        if opc1 != flip_opc {
            return boolean_match::UNCORRELATED;
        }
        let slot1 = 0;
        let slot2 = if reorder { 1 } else { 0 };
        let in1_0 = op1.read().unwrap().inrefs.get(slot1).cloned();
        let in2_slot2 = op2.read().unwrap().inrefs.get(slot2).cloned();
        let in1_1 = op1.read().unwrap().inrefs.get(1 - slot1).cloned();
        let in2_1ms = op2.read().unwrap().inrefs.get(1 - slot2).cloned();
        match (in1_0, in2_slot2, in1_1, in2_1ms) {
            (Some(a), Some(b), Some(c), Some(d)) => {
                if !varnode_same(&a, &b) {
                    return boolean_match::UNCORRELATED;
                }
                if !varnode_same(&c, &d) {
                    return boolean_match::UNCORRELATED;
                }
                return boolean_match::COMPLEMENTARY;
            }
            _ => return boolean_match::UNCORRELATED,
        }
    }
    boolean_match::UNCORRELATED
}

// ===========================================================================
// functionalEqualityLevel — expression.cc:404-512
// ===========================================================================

// Ghidra: expression.cc:404 functionalEqualityLevel0
/// Level-0 functional equality test. Faithful to `functionalEqualityLevel0`
/// (expression.cc:404-417). Returns:
/// - 0 if vn1 and vn2 definitely hold the same value
/// - -1 if they do not (or cannot be immediately verified)
/// - 1 if the same value depends on ops writing to vn1 and vn2
fn functional_equality_level0(
    vn1: &Arc<RwLock<Varnode>>,
    vn2: &Arc<RwLock<Varnode>>,
) -> i32 {
    if Arc::ptr_eq(vn1, vn2) {
        return 0;
    }
    let v1 = vn1.read().unwrap();
    let v2 = vn2.read().unwrap();
    if v1.get_size() != v2.get_size() {
        return -1;
    }
    if v1.is_constant() {
        if v2.is_constant() {
            return if v1.get_offset() == v2.get_offset() { 0 } else { -1 };
        }
        return -1;
    }
    if v1.is_free() || v2.is_free() {
        return -1;
    }
    1
}

/// Result of `functional_equality_level`: the equality code plus the raw
/// contents written to Ghidra's two output-pair buffers.
#[derive(Debug, Clone)]
pub struct FunctionalEqualityResult {
    /// -1 = not equal, 0 = equal, >0 = contingent on the first `code` pairs.
    pub code: i32,
    /// Raw `(res1[i], res2[i])` slots written by Ghidra. If `code > 0`, the
    /// first `code` slots must hold the same value for equality. Slots can
    /// also be present for non-positive results because Ghidra writes its
    /// output arrays before all comparisons are complete.
    pub pairs: Vec<(Arc<RwLock<Varnode>>, Arc<RwLock<Varnode>>)>,
}

// Ghidra: expression.cc:432 functionalEqualityLevel
/// Try to determine if vn1 and vn2 contain the same value. Faithful to
/// `functionalEqualityLevel` (expression.cc:432-512).
///
/// Returns a `FunctionalEqualityResult` with:
/// - `code == -1`: not equal / cannot verify
/// - `code == 0`: definitely equal
/// - `code > 0`: contingent on the first `code` entries of `pairs`
///
/// `pairs` preserves every raw output-buffer slot written by Ghidra, including
/// writes made before a later `code == 0` or `code == -1` return.
pub fn functional_equality_level(
    vn1: &Arc<RwLock<Varnode>>,
    vn2: &Arc<RwLock<Varnode>>,
) -> FunctionalEqualityResult {
    let testval = functional_equality_level0(vn1, vn2);
    if testval != 1 {
        return FunctionalEqualityResult { code: testval, pairs: Vec::new() };
    }
    // Both must be written for a deeper comparison.
    let (is_written1, is_written2, def1, def2) = {
        let v1 = vn1.read().unwrap();
        let v2 = vn2.read().unwrap();
        (v1.is_written(), v2.is_written(), v1.get_def(), v2.get_def())
    };
    if !is_written1 || !is_written2 {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    }
    let Some(op1_arc) = def1 else {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    };
    let Some(op2_arc) = def2 else {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    };
    let op1 = op1_arc.read().unwrap();
    let op2 = op2_arc.read().unwrap();
    let opc = op1.opcode;
    if opc != op2.opcode {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    }
    let mut num = op1.inrefs.len();
    if num != op2.inrefs.len() {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    }
    if op1.is_marker() || op2.is_call() {
        return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
    }
    if opc == OpCode::CPUI_LOAD {
        // Two loads produce the same result if same address and same instruction.
        if op1.get_addr() != op2.get_addr() {
            return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
        }
    }
    if num >= 3 {
        if opc != OpCode::CPUI_PTRADD {
            return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
        }
        // Check element-size constant (slot 2) is equal.
        let off1 = op1.get_in(2).map(|v| v.read().unwrap().get_offset());
        let off2 = op2.get_in(2).map(|v| v.read().unwrap().get_offset());
        if off1 != off2 {
            return FunctionalEqualityResult { code: -1, pairs: Vec::new() };
        }
        num = 2;
    }
    // Ghidra writes both output buffers in input-slot order before comparing
    // the inputs. Preserve those raw writes even if a later comparison returns
    // zero or negative.
    let mut pairs = Vec::with_capacity(num);
    for i in 0..num {
        pairs.push((op1.inrefs[i].clone(), op2.inrefs[i].clone()));
    }
    // Drop the op read guards before further reads.
    drop(op1);
    drop(op2);

    let testval = functional_equality_level0(&pairs[0].0, &pairs[0].1);
    if testval == 0 {
        if num == 1 {
            return FunctionalEqualityResult { code: 0, pairs };
        }
        let testval2 = functional_equality_level0(&pairs[1].0, &pairs[1].1);
        if testval2 == 0 {
            return FunctionalEqualityResult { code: 0, pairs };
        }
        if testval2 < 0 {
            return FunctionalEqualityResult { code: -1, pairs };
        }
        // Match is contingent on the second pair.
        pairs[0] = pairs[1].clone();
        return FunctionalEqualityResult { code: 1, pairs };
    }
    if num == 1 {
        return FunctionalEqualityResult { code: testval, pairs };
    }
    let testval2 = functional_equality_level0(&pairs[1].0, &pairs[1].1);
    if testval2 == 0 {
        return FunctionalEqualityResult { code: testval, pairs };
    }
    let unmatchsize = if testval == 1 && testval2 == 1 { 2 } else { -1 };

    // Check commutativity.
    let is_commutative = opc.is_commutative();
    if !is_commutative {
        return FunctionalEqualityResult { code: unmatchsize, pairs };
    }
    // Try flipping for commutative operators.
    let comm1 = functional_equality_level0(&pairs[0].0, &pairs[1].1);
    let comm2 = functional_equality_level0(&pairs[1].0, &pairs[0].1);
    if comm1 == 0 && comm2 == 0 {
        return FunctionalEqualityResult { code: 0, pairs };
    }
    if comm1 < 0 || comm2 < 0 {
        return FunctionalEqualityResult { code: unmatchsize, pairs };
    }
    if comm1 == 0 {
        // Left-over unmatch is res1[1] and res2[0].
        pairs[0].0 = pairs[1].0.clone();
        return FunctionalEqualityResult { code: 1, pairs };
    }
    if comm2 == 0 {
        // Left-over unmatch is res1[0] and res2[1].
        pairs[0].1 = pairs[1].1.clone();
        return FunctionalEqualityResult { code: 1, pairs };
    }
    // comm1==1 AND comm2==1.
    if unmatchsize == 2 {
        // Prefer the original ordering.
        return FunctionalEqualityResult { code: 2, pairs };
    }
    // Ghidra swaps only the res2 output buffer.
    let res2_slot0 = pairs[0].1.clone();
    pairs[0].1 = pairs[1].1.clone();
    pairs[1].1 = res2_slot0;
    FunctionalEqualityResult { code: 2, pairs }
}

// Ghidra: expression.cc:432 functionalEqualityLevel (code-only projection)
/// Code-only projection of [`functional_equality_level`] for callers that
/// never read the output pairs (RuleMultiCollapse's cc:3280 gate,
/// ActionDirectWrite's dedup scan, NodeJoin::findDups' cc:1936-1938 gate,
/// and the `functional_equality` wrapper). PERF-ACTIONPOOL-ITER-0001: the
/// oracle's res1/res2 buffer writes are raw pointer stores
/// (expression.cc:475-477) with no observable effect when the caller
/// discards the buffers — this form keeps both op guards held and reads
/// the input handles by borrow, so the discarded buffer costs zero Arc
/// round-trips. Every test reads the same fields in the same order; the
/// returned code is bit-identical to `functional_equality_level(..).code`.
pub fn functional_equality_level_code(
    vn1: &Arc<RwLock<Varnode>>,
    vn2: &Arc<RwLock<Varnode>>,
) -> i32 {
    let testval = functional_equality_level0(vn1, vn2);
    if testval != 1 {
        return testval;
    }
    // Both must be written for a deeper comparison.
    let (is_written1, is_written2, def1, def2) = {
        let v1 = vn1.read().unwrap();
        let v2 = vn2.read().unwrap();
        (v1.is_written(), v2.is_written(), v1.get_def(), v2.get_def())
    };
    if !is_written1 || !is_written2 {
        return -1;
    }
    let Some(op1_arc) = def1 else {
        return -1;
    };
    let Some(op2_arc) = def2 else {
        return -1;
    };
    let op1 = op1_arc.read().unwrap();
    let op2 = op2_arc.read().unwrap();
    let opc = op1.opcode;
    if opc != op2.opcode {
        return -1;
    }
    let mut num = op1.inrefs.len();
    if num != op2.inrefs.len() {
        return -1;
    }
    if op1.is_marker() || op2.is_call() {
        return -1;
    }
    if opc == OpCode::CPUI_LOAD {
        // Two loads produce the same result if same address and same instruction.
        if op1.get_addr() != op2.get_addr() {
            return -1;
        }
    }
    if num >= 3 {
        if opc != OpCode::CPUI_PTRADD {
            return -1;
        }
        // Check element-size constant (slot 2) is equal.
        let off1 = op1.get_in(2).map(|v| v.read().unwrap().get_offset());
        let off2 = op2.get_in(2).map(|v| v.read().unwrap().get_offset());
        if off1 != off2 {
            return -1;
        }
        num = 2;
    }
    // Input pairs stay borrowed under the op guards (read-read nesting).
    let testval = functional_equality_level0(&op1.inrefs[0], &op2.inrefs[0]);
    if testval == 0 {
        if num == 1 {
            return 0;
        }
        let testval2 = functional_equality_level0(&op1.inrefs[1], &op2.inrefs[1]);
        if testval2 == 0 {
            return 0;
        }
        if testval2 < 0 {
            return -1;
        }
        // Match is contingent on the second pair.
        return 1;
    }
    if num == 1 {
        return testval;
    }
    let testval2 = functional_equality_level0(&op1.inrefs[1], &op2.inrefs[1]);
    if testval2 == 0 {
        return testval;
    }
    let unmatchsize = if testval == 1 && testval2 == 1 { 2 } else { -1 };

    // Check commutativity.
    let is_commutative = opc.is_commutative();
    if !is_commutative {
        return unmatchsize;
    }
    // Try flipping for commutative operators.
    let comm1 = functional_equality_level0(&op1.inrefs[0], &op2.inrefs[1]);
    let comm2 = functional_equality_level0(&op1.inrefs[1], &op2.inrefs[0]);
    if comm1 == 0 && comm2 == 0 {
        return 0;
    }
    if comm1 < 0 || comm2 < 0 {
        return unmatchsize;
    }
    if comm1 == 0 {
        return 1;
    }
    if comm2 == 0 {
        return 1;
    }
    // comm1==1 AND comm2==1.
    2
}

// Ghidra: expression.cc:520 functionalEquality
/// Determine whether two Varnodes are immediately provable as equivalent.
/// The output buffers are intentionally local, matching Ghidra's wrapper.
/// PERF-ACTIONPOOL-ITER-0001: routes through the code-only projection —
/// the oracle wrapper discards the buffers, so this caller never pays the
/// pair materialization.
pub fn functional_equality(
    vn1: &Arc<RwLock<Varnode>>,
    vn2: &Arc<RwLock<Varnode>>,
) -> bool {
    functional_equality_level_code(vn1, vn2) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, SeqNum};
    use crate::varnode::varnode_flags;

    fn equality_input(offset: u64, size: usize) -> Arc<RwLock<Varnode>> {
        let vn = Arc::new(RwLock::new(Varnode::new_register(offset, size)));
        vn.write().unwrap().set_flags(varnode_flags::INPUT);
        vn
    }

    fn equality_output(
        opcode: OpCode,
        inputs: Vec<Arc<RwLock<Varnode>>>,
        offset: u64,
        time: u32,
    ) -> (Arc<RwLock<Varnode>>, Arc<RwLock<PcodeOp>>) {
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), time),
            opcode,
        )));
        {
            let mut guard = op.write().unwrap();
            guard.set_opcode_flags(opcode);
            guard.inrefs = inputs;
        }
        let output = Arc::new(RwLock::new(Varnode::new_unique(offset, 8)));
        {
            let mut guard = output.write().unwrap();
            guard.set_flags(varnode_flags::WRITTEN);
            guard.def = Some(Arc::downgrade(&op));
        }
        op.write().unwrap().output = Some(output.clone());
        (output, op)
    }

    #[test]
    fn test_add_expression_constants() {
        // Two constants 3 + 5 → constval=8, 0 terms
        let mut expr = AddExpression::new();
        let a = Arc::new(RwLock::new(Varnode::new_constant(4, 3)));
        let b = Arc::new(RwLock::new(Varnode::new_constant(4, 5)));
        expr.gather_two_terms_add(&a, &b);
        assert_eq!(expr.constval, 8);
        assert_eq!(expr.num_terms, 0);
    }

    #[test]
    fn test_add_expression_equiv() {
        // V + 3 should be equivalent to V + 3
        let v = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let c3 = Arc::new(RwLock::new(Varnode::new_constant(4, 3)));
        let mut expr1 = AddExpression::new();
        expr1.gather_two_terms_add(&v, &c3);
        let mut expr2 = AddExpression::new();
        expr2.gather_two_terms_add(&v, &c3);
        assert!(expr1.is_equivalent(&expr2));
    }

    #[test]
    fn test_functional_equality_level_same_pointer() {
        let v = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let r = functional_equality_level(&v, &v);
        assert_eq!(r.code, 0);
    }

    #[test]
    fn test_boolean_match_same_pointer() {
        let v = Arc::new(RwLock::new(Varnode::new_register(0x10, 1)));
        assert_eq!(boolean_match_evaluate(&v, &v, 1), boolean_match::SAME);
    }

    #[test]
    fn test_boolean_match_uncorrelated_constants() {
        let c1 = Arc::new(RwLock::new(Varnode::new_constant(1, 1)));
        let c2 = Arc::new(RwLock::new(Varnode::new_constant(0, 1)));
        // Two different constants, neither written → uncorrelated.
        assert_eq!(boolean_match_evaluate(&c1, &c2, 1), boolean_match::UNCORRELATED);
    }

    #[test]
    fn test_boolean_match_complement_via_flip() {
        // V == 5  and  V != 5  are complementary.
        use crate::address::SeqNum;
        let v = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let c5 = Arc::new(RwLock::new(Varnode::new_constant(5, 4)));
        let eq_op = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_INT_EQUAL)));
        eq_op.write().unwrap().inrefs = vec![v.clone(), c5.clone()];
        eq_op.write().unwrap().flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
        let eq_out = Arc::new(RwLock::new(Varnode::new_register(0x20, 1)));
        eq_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        eq_op.write().unwrap().output = Some(eq_out.clone());
        eq_out.write().unwrap().def = Some(Arc::downgrade(&eq_op));

        let ne_op = Arc::new(RwLock::new(PcodeOp::new(SeqNum::new(Address::new(0x1000), 1), OpCode::CPUI_INT_NOTEQUAL)));
        ne_op.write().unwrap().inrefs = vec![v.clone(), c5.clone()];
        ne_op.write().unwrap().flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
        let ne_out = Arc::new(RwLock::new(Varnode::new_register(0x21, 1)));
        ne_out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
        ne_op.write().unwrap().output = Some(ne_out.clone());
        ne_out.write().unwrap().def = Some(Arc::downgrade(&ne_op));

        assert_eq!(boolean_match_evaluate(&eq_out, &ne_out, 1), boolean_match::COMPLEMENTARY);
    }

    #[test]
    fn test_functional_equality_level_constants_equal() {
        let c1 = Arc::new(RwLock::new(Varnode::new_constant(4, 42)));
        let c2 = Arc::new(RwLock::new(Varnode::new_constant(4, 42)));
        let r = functional_equality_level(&c1, &c2);
        assert_eq!(r.code, 0);
    }

    #[test]
    fn test_functional_equality_level_constants_unequal() {
        let c1 = Arc::new(RwLock::new(Varnode::new_constant(4, 42)));
        let c2 = Arc::new(RwLock::new(Varnode::new_constant(4, 99)));
        let r = functional_equality_level(&c1, &c2);
        assert_eq!(r.code, -1);
    }

    #[test]
    fn test_functional_equality_level_different_sizes() {
        let c1 = Arc::new(RwLock::new(Varnode::new_constant(4, 42)));
        let c2 = Arc::new(RwLock::new(Varnode::new_constant(8, 42)));
        let r = functional_equality_level(&c1, &c2);
        assert_eq!(r.code, -1);
    }

    #[test]
    fn test_functional_equality_level_free_varnodes() {
        // Two distinct free (unwritten) register varnodes → code 1 (might be
        // equal, depends on ops). But since they're not written, the deeper
        // check returns -1.
        let v1 = Arc::new(RwLock::new(Varnode::new_register(0x10, 4)));
        let v2 = Arc::new(RwLock::new(Varnode::new_register(0x20, 4)));
        let r = functional_equality_level(&v1, &v2);
        assert_eq!(r.code, -1); // Not written → -1.
    }

    #[test]
    fn test_functional_equality_level_unary_contingent_preserves_raw_pair() {
        let left = equality_input(0x10, 4);
        let right = equality_input(0x20, 4);
        let (out1, _op1) = equality_output(OpCode::CPUI_INT_ZEXT, vec![left.clone()], 0x100, 1);
        let (out2, _op2) = equality_output(OpCode::CPUI_INT_ZEXT, vec![right.clone()], 0x200, 2);
        let result = functional_equality_level(&out1, &out2);

        assert_eq!(result.code, 1);
        assert_eq!(result.pairs.len(), 1);
        assert!(Arc::ptr_eq(&result.pairs[0].0, &left));
        assert!(Arc::ptr_eq(&result.pairs[0].1, &right));
    }

    #[test]
    fn test_functional_equality_level_binary_slot1_exact_keeps_raw_slots() {
        let left = equality_input(0x10, 8);
        let right = equality_input(0x20, 8);
        let shared = equality_input(0x30, 8);
        let (out1, _op1) = equality_output(
            OpCode::CPUI_INT_SUB,
            vec![left.clone(), shared.clone()],
            0x100,
            1,
        );
        let (out2, _op2) = equality_output(
            OpCode::CPUI_INT_SUB,
            vec![right.clone(), shared.clone()],
            0x200,
            2,
        );
        let result = functional_equality_level(&out1, &out2);

        assert_eq!(result.code, 1);
        assert_eq!(result.pairs.len(), 2);
        assert!(Arc::ptr_eq(&result.pairs[0].0, &left));
        assert!(Arc::ptr_eq(&result.pairs[0].1, &right));
        assert!(Arc::ptr_eq(&result.pairs[1].0, &shared));
        assert!(Arc::ptr_eq(&result.pairs[1].1, &shared));
    }

    #[test]
    fn test_functional_equality_level_noncommutative_code2_keeps_original_order() {
        let left0 = equality_input(0x10, 8);
        let left1 = equality_input(0x18, 8);
        let right0 = equality_input(0x20, 8);
        let right1 = equality_input(0x28, 8);
        let (out1, _op1) = equality_output(
            OpCode::CPUI_INT_SUB,
            vec![left0.clone(), left1.clone()],
            0x100,
            1,
        );
        let (out2, _op2) = equality_output(
            OpCode::CPUI_INT_SUB,
            vec![right0.clone(), right1.clone()],
            0x200,
            2,
        );
        let result = functional_equality_level(&out1, &out2);

        assert_eq!(result.code, 2);
        assert_eq!(result.pairs.len(), 2);
        assert!(Arc::ptr_eq(&result.pairs[0].0, &left0));
        assert!(Arc::ptr_eq(&result.pairs[0].1, &right0));
        assert!(Arc::ptr_eq(&result.pairs[1].0, &left1));
        assert!(Arc::ptr_eq(&result.pairs[1].1, &right1));
    }

    #[test]
    fn test_functional_equality_level_cross_impossible_keeps_original_order() {
        let left0 = equality_input(0x10, 4);
        let left1 = equality_input(0x18, 8);
        let right0 = equality_input(0x20, 4);
        let right1 = equality_input(0x28, 8);
        let (out1, _op1) = equality_output(
            OpCode::CPUI_INT_ADD,
            vec![left0.clone(), left1.clone()],
            0x100,
            1,
        );
        let (out2, _op2) = equality_output(
            OpCode::CPUI_INT_ADD,
            vec![right0.clone(), right1.clone()],
            0x200,
            2,
        );
        let result = functional_equality_level(&out1, &out2);

        assert_eq!(result.code, 2);
        assert_eq!(result.pairs.len(), 2);
        assert!(Arc::ptr_eq(&result.pairs[0].0, &left0));
        assert!(Arc::ptr_eq(&result.pairs[0].1, &right0));
        assert!(Arc::ptr_eq(&result.pairs[1].0, &left1));
        assert!(Arc::ptr_eq(&result.pairs[1].1, &right1));
    }

    #[test]
    fn test_functional_equality_level_negative_retains_prior_raw_writes() {
        let shared = equality_input(0x10, 8);
        let left_constant = Arc::new(RwLock::new(Varnode::new_constant(1, 8)));
        let right_constant = Arc::new(RwLock::new(Varnode::new_constant(2, 8)));
        let (out1, _op1) = equality_output(
            OpCode::CPUI_INT_SUB,
            vec![shared.clone(), left_constant.clone()],
            0x100,
            1,
        );
        let (out2, _op2) = equality_output(
            OpCode::CPUI_INT_SUB,
            vec![shared.clone(), right_constant.clone()],
            0x200,
            2,
        );
        let result = functional_equality_level(&out1, &out2);

        assert_eq!(result.code, -1);
        assert_eq!(result.pairs.len(), 2);
        assert!(Arc::ptr_eq(&result.pairs[0].0, &shared));
        assert!(Arc::ptr_eq(&result.pairs[0].1, &shared));
        assert!(Arc::ptr_eq(&result.pairs[1].0, &left_constant));
        assert!(Arc::ptr_eq(&result.pairs[1].1, &right_constant));
    }
}
