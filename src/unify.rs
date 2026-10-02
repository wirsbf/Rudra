//! Unification-based P-code pattern matching infrastructure.
//!
//! 1:1 port of Ghidra's `unify.hh` / `unify.cc`. This module provides a
//! generic, declarative pattern-matching engine over the P-code data-flow
//! graph. A pattern is expressed as a tree of `UnifyConstraint` objects
//! (grouped via `ConstraintGroup` / `ConstraintOr`); the engine performs a
//! depth-first backtracking search, enumerating every assignment of ops /
//! varnodes / constants that simultaneously satisfies all constraints.
//!
//! The engine is the substrate for Ghidra's user-defined "Dolphin" rules
//! (`rulecompile.cc`); rules are normally compiled into a `ConstraintGroup`
//! whose head matches a root `PcodeOp`.
//!
//! # Architecture (mirrors Ghidra)
//! - `UnifyDatatype`: a tagged slot in the match state, holding an op /
//!   varnode / constant / block value (`unify.hh:25`).
//! - `RHSConstant` trait + concrete classes: right-hand-side constant
//!   expressions evaluated against the live state (`unify.hh:59`).
//! - `TraverseConstraint` enum: per-constraint iteration state (count,
//!   descend, group) (`unify.hh:152`).
//! - `UnifyConstraint` trait + concrete classes: predicates / actions, each
//!   with `initialize` / `step` / `build_traverse_state` (`unify.hh:201`).
//! - `UnifyState`: the live match state (storemap + traverselist + Funcdata)
//!   (`unify.hh:608`).
//! - `UnifyCPrinter`: emits a C++ rule from a constraint tree (`unify.hh:627`).
//! - `RuleMatcher`: a thin driver (Ghidra drives this inline; we expose it as
//!   a convenience entry point).

use std::sync::{Arc, RwLock};

use crate::address::calc_mask;
use crate::funcdata::Funcdata;
use crate::op::{PcodeOp, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::varnode::{varnode_flags, Varnode};

// Convenience type aliases (Ghidra uses raw `PcodeOp *` / `Varnode *`; the
// Rust equivalent is a refcounted, lock-protected node).
type OpArc = Arc<RwLock<PcodeOp>>;
type VnArc = Arc<RwLock<Varnode>>;

/// `max(a,b)` helper standing in for the C++ ternary used in `maxnum`
/// computations throughout unify.hh.
// RUDRA-GLUE: free helper replacing C++ ternary max(a,b) used in maxnum computations
fn imax(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

// ===========================================================================
// UnifyDatatype (unify.hh:25, unify.cc:21-143)
// ===========================================================================

/// The four kinds of value that can live in a unify state slot.
/// Corresponds to `UnifyDatatype::{op_type,var_type,const_type,block_type}`
/// (unify.hh:27-29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatatypeKind {
    /// A `PcodeOp *` slot.
    OpType,
    /// A `Varnode *` slot.
    VarType,
    /// A `uintb` constant slot.
    ConstType,
    /// A `BlockBasic *` slot.
    BlockType,
}

impl DatatypeKind {
    /// Base name used to synthesize slot variable names.
    /// Faithful to `UnifyDatatype::getBaseName` (unify.cc:128-143).
    // Ghidra: unify.cc:128 UnifyDatatype::getBaseName
    pub fn base_name(self) -> &'static str {
        // unify.cc:128
        match self {
            DatatypeKind::OpType => "op",
            DatatypeKind::VarType => "vn",
            DatatypeKind::BlockType => "bl",
            DatatypeKind::ConstType => "cn",
        }
    }
}

/// A tagged slot capable of holding an op / varnode / constant / block.
///
/// Corresponds to Ghidra's `UnifyDatatype` (unify.hh:25). Ghidra uses a C++
/// union; we model the same with an explicit kind plus optional payload
/// fields. A slot's kind is fixed at construction (via `collectTypes`) and the
/// payload is filled in as the matcher binds values.
#[derive(Debug, Clone)]
pub struct UnifyDatatype {
    kind: DatatypeKind,
    op: Option<OpArc>,
    vn: Option<VnArc>,
    cn: u64,
    bl: Option<usize>,
}

impl Default for UnifyDatatype {
    /// Ghidra's default constructor sets `type = op_type` (unify.hh:39).
    // RUDRA-GLUE: Rust Default trait impl; Ghidra uses default-constructed UnifyDatatype inline (unify.hh:39)
    fn default() -> Self {
        Self { kind: DatatypeKind::OpType, op: None, vn: None, cn: 0, bl: None }
    }
}

impl UnifyDatatype {
    /// Construct an empty slot of the given kind.
    /// Faithful to `UnifyDatatype(uint4 tp)` (unify.cc:21-36).
    // Ghidra: unify.cc:21 UnifyDatatype::UnifyDatatype
    pub fn new(kind: DatatypeKind) -> Self {
        // unify.cc:21
        Self { kind, op: None, vn: None, cn: 0, bl: None }
    }

    /// Return this slot's kind. Faithful to `getType` (unify.hh:44).
    // Ghidra: unify.hh:44 UnifyDatatype::getType
    pub fn get_type(&self) -> DatatypeKind { self.kind }

    /// Bind an op into this slot. Faithful to `setOp` (unify.hh:45).
    // Ghidra: unify.hh:45 UnifyDatatype::setOp
    pub fn set_op(&mut self, o: OpArc) { self.op = Some(o); }

    /// Read the bound op. Faithful to `getOp` (unify.hh:46).
    // Ghidra: unify.hh:46 UnifyDatatype::getOp
    pub fn get_op(&self) -> Option<OpArc> { self.op.clone() }

    /// Bind a varnode into this slot. Faithful to `setVarnode` (unify.hh:47).
    // Ghidra: unify.hh:47 UnifyDatatype::setVarnode
    pub fn set_varnode(&mut self, v: VnArc) { self.vn = Some(v); }

    /// Read the bound varnode. Faithful to `getVarnode` (unify.hh:48).
    // Ghidra: unify.hh:48 UnifyDatatype::getVarnode
    pub fn get_varnode(&self) -> Option<VnArc> { self.vn.clone() }

    /// Bind a block index into this slot. Faithful to `setBlock` (unify.hh:49).
    // Ghidra: unify.hh:49 UnifyDatatype::setBlock
    pub fn set_block(&mut self, b: usize) { self.bl = Some(b); }

    /// Read the bound block. Faithful to `getBlock` (unify.hh:50).
    // Ghidra: unify.hh:50 UnifyDatatype::getBlock
    pub fn get_block(&self) -> Option<usize> { self.bl }

    /// Bind a constant into this slot. Faithful to `setConstant`
    /// (unify.hh:51, unify.cc:100-104).
    // Ghidra: unify.cc:100 UnifyDatatype::setConstant
    pub fn set_constant(&mut self, val: u64) {
        // unify.cc:100
        self.cn = val;
    }

    /// Read the bound constant. Faithful to `getConstant` (unify.hh:52).
    // Ghidra: unify.hh:52 UnifyDatatype::getConstant
    pub fn get_constant(&self) -> u64 { self.cn }

    /// Emit a C variable declaration for this slot.
    /// Faithful to `UnifyDatatype::printVarDecl` (unify.cc:106-126).
    // Ghidra: unify.cc:106 UnifyDatatype::printVarDecl
    pub fn print_var_decl(&self, s: &mut String, id: usize, printer: &UnifyCPrinter) {
        // unify.cc:106
        printer.print_indent(s);
        match self.kind {
            DatatypeKind::OpType => s.push_str("PcodeOp *"),
            DatatypeKind::VarType => s.push_str("Varnode *"),
            DatatypeKind::BlockType => s.push_str("BlockBasic *"),
            DatatypeKind::ConstType => s.push_str("uintb "),
        }
        s.push_str(&printer.get_name(id));
        s.push_str(";\n");
    }
}

// ===========================================================================
// RHSConstant (unify.hh:59, unify.cc:145-375)
// ===========================================================================

/// A construction that yields a `uintb` constant on the right-hand side of an
/// expression. Corresponds to the `RHSConstant` abstract class (unify.hh:59).
pub trait RHSConstant: Send + Sync {
    /// Evaluate this constant against the live match state.
    /// Faithful to `RHSConstant::getConstant` (unify.hh:63).
    // Ghidra: unify.hh:63 RHSConstant::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64;

    /// Deep-clone this RHS expression. Faithful to `RHSConstant::clone`
    /// (unify.hh:62).
    // Ghidra: unify.hh:62 RHSConstant::clone
    fn clone_box(&self) -> Box<dyn RHSConstant>;

    /// Render this expression as C source. Faithful to
    /// `RHSConstant::writeExpression` (unify.hh:64).
    // Ghidra: unify.hh:64 RHSConstant::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter);
}

/// `#name` - a previously bound named constant slot.
/// Faithful to `ConstantNamed` (unify.hh:67-75, unify.cc:145-155).
#[derive(Debug, Clone)]
pub struct ConstantNamed { constindex: usize }

impl ConstantNamed {
    // Ghidra: unify.hh:70 ConstantNamed::ConstantNamed
    pub fn new(id: usize) -> Self { Self { constindex: id } }
    // Ghidra: unify.hh:71 ConstantNamed::getId
    pub fn get_id(&self) -> usize { self.constindex }
}

impl RHSConstant for ConstantNamed {
    // Ghidra: unify.cc:145 ConstantNamed::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64 {
        // unify.cc:145
        state.data(self.constindex).get_constant()
    }
    // Ghidra: unify.hh:72 ConstantNamed::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> { Box::new(self.clone()) }
    // Ghidra: unify.cc:151 ConstantNamed::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter) {
        // unify.cc:151
        s.push_str(&printer.get_name(self.constindex));
    }
}

/// An absolute numeric constant. Faithful to `ConstantAbsolute`
/// (unify.hh:77-85, unify.cc:157-167).
#[derive(Debug, Clone)]
pub struct ConstantAbsolute { val: u64 }

impl ConstantAbsolute {
    // Ghidra: unify.hh:80 ConstantAbsolute::ConstantAbsolute
    pub fn new(v: u64) -> Self { Self { val: v } }
    // Ghidra: unify.hh:81 ConstantAbsolute::getVal
    pub fn get_val(&self) -> u64 { self.val }
}

impl RHSConstant for ConstantAbsolute {
    // Ghidra: unify.cc:157 ConstantAbsolute::getConstant
    fn get_constant(&self, _state: &UnifyState) -> u64 {
        // unify.cc:157
        self.val
    }
    // Ghidra: unify.hh:82 ConstantAbsolute::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> { Box::new(self.clone()) }
    // Ghidra: unify.cc:163 ConstantAbsolute::writeExpression
    fn write_expression(&self, s: &mut String, _printer: &UnifyCPrinter) {
        // unify.cc:163
        s.push_str(&format!("(uintb)0x{:x}", self.val));
    }
}

/// A varnode's non-zero mask. Faithful to `ConstantNZMask`
/// (unify.hh:87-94, unify.cc:169-180).
#[derive(Debug, Clone)]
pub struct ConstantNZMask { varindex: usize }

impl ConstantNZMask {
    // Ghidra: unify.hh:90 ConstantNZMask::ConstantNZMask
    pub fn new(ind: usize) -> Self {
        Self { varindex: ind }
    }
}

impl RHSConstant for ConstantNZMask {
    // Ghidra: unify.cc:169 ConstantNZMask::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64 {
        // unify.cc:169
        state.data(self.varindex).get_varnode()
            .map(|v| v.read().unwrap().get_nz_mask()).unwrap_or(0)
    }
    // Ghidra: unify.hh:91 ConstantNZMask::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> { Box::new(self.clone()) }
    // Ghidra: unify.cc:176 ConstantNZMask::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter) {
        // unify.cc:176
        s.push_str(&printer.get_name(self.varindex));
        s.push_str("->getNZMask()");
    }
}

/// A varnode's consume mask. Faithful to `ConstantConsumed`
/// (unify.hh:96-103, unify.cc:182-193).
#[derive(Debug, Clone)]
pub struct ConstantConsumed { varindex: usize }

impl ConstantConsumed {
    // Ghidra: unify.hh:99 ConstantConsumed::ConstantConsumed
    pub fn new(ind: usize) -> Self {
        Self { varindex: ind }
    }
}

impl RHSConstant for ConstantConsumed {
    // Ghidra: unify.cc:182 ConstantConsumed::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64 {
        // unify.cc:182
        state.data(self.varindex).get_varnode()
            .map(|v| v.read().unwrap().get_consume()).unwrap_or(0)
    }
    // Ghidra: unify.hh:100 ConstantConsumed::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> { Box::new(self.clone()) }
    // Ghidra: unify.cc:189 ConstantConsumed::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter) {
        // unify.cc:189
        s.push_str(&printer.get_name(self.varindex));
        s.push_str("->getConsume()");
    }
}

/// A varnode's offset. Faithful to `ConstantOffset`
/// (unify.hh:105-112, unify.cc:195-206).
#[derive(Debug, Clone)]
pub struct ConstantOffset { varindex: usize }

impl ConstantOffset {
    // Ghidra: unify.hh:108 ConstantOffset::ConstantOffset
    pub fn new(ind: usize) -> Self {
        Self { varindex: ind }
    }
}

impl RHSConstant for ConstantOffset {
    // Ghidra: unify.cc:195 ConstantOffset::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64 {
        // unify.cc:195
        state.data(self.varindex).get_varnode()
            .map(|v| v.read().unwrap().get_offset()).unwrap_or(0)
    }
    // Ghidra: unify.hh:109 ConstantOffset::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> { Box::new(self.clone()) }
    // Ghidra: unify.cc:202 ConstantOffset::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter) {
        // unify.cc:202
        s.push_str(&printer.get_name(self.varindex));
        s.push_str("->getOffset()");
    }
}

/// 1 if the varnode is constant, else 0. Faithful to `ConstantIsConstant`
/// (unify.hh:114-121, unify.cc:208-219).
#[derive(Debug, Clone)]
pub struct ConstantIsConstant { varindex: usize }

impl ConstantIsConstant {
    // Ghidra: unify.hh:117 ConstantIsConstant::ConstantIsConstant
    pub fn new(ind: usize) -> Self {
        Self { varindex: ind }
    }
}

impl RHSConstant for ConstantIsConstant {
    // Ghidra: unify.cc:208 ConstantIsConstant::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64 {
        // unify.cc:208
        state.data(self.varindex).get_varnode()
            .map(|v| if v.read().unwrap().is_constant() { 1 } else { 0 })
            .unwrap_or(0)
    }
    // Ghidra: unify.hh:118 ConstantIsConstant::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> { Box::new(self.clone()) }
    // Ghidra: unify.cc:215 ConstantIsConstant::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter) {
        // unify.cc:215
        s.push_str("(uintb)");
        s.push_str(&printer.get_name(self.varindex));
        s.push_str("->isConstant()");
    }
}

/// 1 if the varnode's heritage is known, else 0. Faithful to
/// `ConstantHeritageKnown` (unify.hh:123-130, unify.cc:221-232).
#[derive(Debug, Clone)]
pub struct ConstantHeritageKnown { varindex: usize }

impl ConstantHeritageKnown {
    // Ghidra: unify.hh:126 ConstantHeritageKnown::ConstantHeritageKnown
    pub fn new(ind: usize) -> Self {
        Self { varindex: ind }
    }
}

impl RHSConstant for ConstantHeritageKnown {
    // Ghidra: unify.cc:221 ConstantHeritageKnown::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64 {
        // unify.cc:221
        state.data(self.varindex).get_varnode()
            .map(|v| if is_heritage_known(&v.read().unwrap()) { 1 } else { 0 })
            .unwrap_or(0)
    }
    // Ghidra: unify.hh:127 ConstantHeritageKnown::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> { Box::new(self.clone()) }
    // Ghidra: unify.cc:228 ConstantHeritageKnown::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter) {
        // unify.cc:228
        s.push_str("(uintb)");
        s.push_str(&printer.get_name(self.varindex));
        s.push_str("->isHeritageKnown()");
    }
}

/// A varnode's size as a constant. Faithful to `ConstantVarnodeSize`
/// (unify.hh:132-139, unify.cc:234-245).
#[derive(Debug, Clone)]
pub struct ConstantVarnodeSize { varindex: usize }

impl ConstantVarnodeSize {
    // Ghidra: unify.hh:135 ConstantVarnodeSize::ConstantVarnodeSize
    pub fn new(ind: usize) -> Self {
        Self { varindex: ind }
    }
}

impl RHSConstant for ConstantVarnodeSize {
    // Ghidra: unify.cc:234 ConstantVarnodeSize::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64 {
        // unify.cc:234
        state.data(self.varindex).get_varnode()
            .map(|v| v.read().unwrap().get_size() as u64).unwrap_or(0)
    }
    // Ghidra: unify.hh:136 ConstantVarnodeSize::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> { Box::new(self.clone()) }
    // Ghidra: unify.cc:241 ConstantVarnodeSize::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter) {
        // unify.cc:241
        s.push_str("(uintb)");
        s.push_str(&printer.get_name(self.varindex));
        s.push_str("->getSize()");
    }
}

/// A binary/unary constant expression evaluated via `OpBehavior`.
/// Faithful to `ConstantExpression` (unify.hh:141-150, unify.cc:247-375).
pub struct ConstantExpression {
    expr1: Box<dyn RHSConstant>,
    expr2: Option<Box<dyn RHSConstant>>,
    opc: OpCode,
}

impl Clone for ConstantExpression {
    // Ghidra: unify.cc:255 ConstantExpression::clone
    fn clone(&self) -> Self {
        let e2 = self.expr2.as_ref().map(|e| e.clone_box());
        Self { expr1: self.expr1.clone_box(), expr2: e2, opc: self.opc }
    }
}

impl std::fmt::Debug for ConstantExpression {
    // RUDRA-GLUE: Rust Debug impl for ConstantExpression; Ghidra uses print() instead
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConstantExpression").field("opc", &self.opc).finish()
    }
}

impl ConstantExpression {
    /// Construct a binary expression. `expr2 = None` denotes a unary op.
    // Ghidra: unify.hh:145 ConstantExpression::ConstantExpression
    pub fn new(e1: Box<dyn RHSConstant>, e2: Option<Box<dyn RHSConstant>>, oc: OpCode) -> Self {
        Self { expr1: e1, expr2: e2, opc: oc }
    }
}

impl RHSConstant for ConstantExpression {
    // Ghidra: unify.cc:265 ConstantExpression::getConstant
    fn get_constant(&self, state: &UnifyState) -> u64 {
        // unify.cc:265
        let c1 = self.expr1.get_constant(state);
        match &self.expr2 {
            None => crate::opbehavior::evaluate_unary(self.opc, 8, 8, c1).unwrap_or(0),
            Some(e2) => {
                let c2 = e2.get_constant(state);
                crate::opbehavior::evaluate_binary(self.opc, 8, 8, c1, c2).unwrap_or(0)
            }
        }
    }
    // Ghidra: unify.cc:255 ConstantExpression::clone
    fn clone_box(&self) -> Box<dyn RHSConstant> {
        // unify.cc:255
        let e2 = self.expr2.as_ref().map(|e| e.clone_box());
        Box::new(ConstantExpression::new(self.expr1.clone_box(), e2, self.opc))
    }
    // Ghidra: unify.cc:284 ConstantExpression::writeExpression
    fn write_expression(&self, s: &mut String, printer: &UnifyCPrinter) {
        // unify.cc:284
        let (opname, is_func) = operator_syntax(self.opc);
        match &self.expr2 {
            None => {
                if is_func {
                    s.push_str(opname); s.push('(');
                    self.expr1.write_expression(s, printer); s.push(')');
                } else {
                    s.push_str(opname);
                    self.expr1.write_expression(s, printer);
                }
            }
            Some(e2) => {
                if is_func {
                    s.push_str(opname); s.push('(');
                    self.expr1.write_expression(s, printer); s.push(',');
                    e2.write_expression(s, printer); s.push(')');
                } else {
                    s.push('(');
                    self.expr1.write_expression(s, printer);
                    s.push_str(opname);
                    e2.write_expression(s, printer); s.push(')');
                }
            }
        }
    }
}

/// Returns `(operator_string, is_function_form)` for the CPrinter.
/// Faithful to the switch in `ConstantExpression::writeExpression`
/// (unify.cc:289-374).
// RUDRA-GLUE: free helper used by ConstantExpression::writeExpression (unify.cc:284-375) for C-operator lookup
fn operator_syntax(opc: OpCode) -> (&'static str, bool) {
    match opc {
        OpCode::CPUI_INT_ADD => (" + ", false),
        OpCode::CPUI_INT_SUB => (" - ", false),
        OpCode::CPUI_INT_AND => (" & ", false),
        OpCode::CPUI_INT_OR => (" | ", false),
        OpCode::CPUI_INT_XOR => (" ^ ", false),
        OpCode::CPUI_INT_MULT => (" * ", false),
        OpCode::CPUI_INT_DIV => (" / ", false),
        OpCode::CPUI_INT_REM => (" % ", false),
        OpCode::CPUI_INT_LEFT => (" << ", false),
        OpCode::CPUI_INT_RIGHT => (" >> ", false),
        OpCode::CPUI_INT_SRIGHT => (" s>> ", false),
        OpCode::CPUI_INT_SDIV => (" s/ ", false),
        OpCode::CPUI_INT_SREM => (" s% ", false),
        OpCode::CPUI_INT_EQUAL => (" == ", false),
        OpCode::CPUI_INT_NOTEQUAL => (" != ", false),
        OpCode::CPUI_INT_LESS => (" < ", false),
        OpCode::CPUI_INT_LESSEQUAL => (" <= ", false),
        OpCode::CPUI_INT_SLESS => (" s< ", false),
        OpCode::CPUI_INT_SLESSEQUAL => (" s<= ", false),
        _ => ("op", true),
    }
}

/// Ghidra's `Varnode::isHeritageKnown` (varnode.hh):
/// `(flags & (insert|constant|annotation)) != 0`. Replicated locally because
/// rugra's `Varnode` does not yet expose this accessor.
// RUDRA-GLUE: free helper mirroring varnode.hh isHeritageKnown flag check
fn is_heritage_known(vn: &Varnode) -> bool {
    let mask = varnode_flags::INSERT | varnode_flags::CONSTANT | varnode_flags::ANNOTATION;
    (vn.flags & mask) != 0
}

// ===========================================================================
// TraverseConstraint (unify.hh:152-199)
// ===========================================================================

/// Per-constraint iteration state. Each `UnifyConstraint` is assigned a unique
/// traversal slot (its `uniqid`) whose state lives here. Corresponds to
/// Ghidra's `TraverseConstraint` hierarchy (unify.hh:152).
#[derive(Debug)]
pub enum TraverseConstraint {
    /// Single integer counter; used by leaf predicates and `ConstraintOr`.
    /// Faithful to `TraverseCountState` (unify.hh:177-185).
    Count(TraverseCountState),
    /// Iterator over a varnode's descendant ops. Faithful to
    /// `TraverseDescendState` (unify.hh:161-175).
    Descend(TraverseDescendState),
    /// State for `ConstraintGroup`'s nested backtracking. Faithful to
    /// `TraverseGroupState` (unify.hh:187-199).
    Group(TraverseGroupState),
}

/// Counter-based traversal. `step()` returns true while `state < endstate`.
/// Faithful to `TraverseCountState` (unify.hh:177).
#[derive(Debug, Clone)]
pub struct TraverseCountState { state: i32, endstate: i32 }

impl TraverseCountState {
    // Ghidra: unify.hh:181 TraverseCountState::TraverseCountState
    pub fn new(_id: usize) -> Self { Self { state: -1, endstate: 0 } }
    // Ghidra: unify.hh:182 TraverseCountState::getState
    pub fn get_state(&self) -> i32 { self.state }
    /// Faithful to `TraverseCountState::initialize` (unify.hh:183).
    // Ghidra: unify.hh:183 TraverseCountState::initialize
    pub fn initialize(&mut self, end: i32) {
        // unify.hh:183
        self.state = -1; self.endstate = end;
    }
    /// Faithful to `TraverseCountState::step` (unify.hh:184).
    // Ghidra: unify.hh:184 TraverseCountState::step
    pub fn step(&mut self) -> bool {
        // unify.hh:184
        self.state += 1;
        self.state != self.endstate
    }
}

/// Iterator over a varnode's read sites. Faithful to `TraverseDescendState`
/// (unify.hh:161). Ghidra stores a `list<PcodeOp *>::const_iterator`; we
/// collect the live descendants into a `Vec` and advance an index.
#[derive(Debug, Clone)]
pub struct TraverseDescendState {
    onestep: bool,
    descend_list: Vec<OpArc>,
    index: usize,
}

impl TraverseDescendState {
    // Ghidra: unify.hh:166 TraverseDescendState::TraverseDescendState
    pub fn new(_id: usize) -> Self { Self { onestep: false, descend_list: Vec::new(), index: 0 } }
    /// Current descendant op. Faithful to `getCurrentOp` (unify.hh:167).
    // Ghidra: unify.hh:167 TraverseDescendState::getCurrentOp
    pub fn get_current_op(&self) -> OpArc { self.descend_list[self.index].clone() }
    /// Initialize from a varnode's descendant list. Faithful to `initialize`
    /// (unify.hh:168).
    // Ghidra: unify.hh:168 TraverseDescendState::initialize
    pub fn initialize(&mut self, vn: &Varnode) {
        // unify.hh:168
        self.onestep = false;
        self.descend_list = vn.descend_iter().collect();
        self.index = 0;
    }
    /// Advance to the next descendant. Faithful to `step` (unify.hh:169).
    // Ghidra: unify.hh:169 TraverseDescendState::step
    pub fn step(&mut self) -> bool {
        // unify.hh:169
        if self.onestep { self.index += 1; } else { self.onestep = true; }
        self.index < self.descend_list.len()
    }
}

/// Backtracking state for a `ConstraintGroup`. Faithful to
/// `TraverseGroupState` (unify.hh:187-199). The group's `step` drives a small
/// state machine over `currentconstraint` (the active subconstraint index) and
/// `state` (-1 = first entry, 0 = try step, 1 = push/initialize).
#[derive(Debug, Clone)]
pub struct TraverseGroupState { currentconstraint: i32, state: i32 }

impl TraverseGroupState {
    // Ghidra: unify.hh:192 TraverseGroupState::TraverseGroupState
    pub fn new(_id: usize) -> Self { Self { currentconstraint: 0, state: -1 } }
    // Ghidra: unify.hh:195 TraverseGroupState::getCurrentIndex
    pub fn get_current_index(&self) -> i32 { self.currentconstraint }
    // Ghidra: unify.hh:196 TraverseGroupState::setCurrentIndex
    pub fn set_current_index(&mut self, v: i32) { self.currentconstraint = v; }
    // Ghidra: unify.hh:197 TraverseGroupState::getState
    pub fn get_state(&self) -> i32 { self.state }
    // Ghidra: unify.hh:198 TraverseGroupState::setState
    pub fn set_state(&mut self, v: i32) { self.state = v; }
}

// ===========================================================================
// UnifyConstraint trait (unify.hh:201-221)
// ===========================================================================

/// Base trait for every pattern constraint / action.
///
/// Corresponds to Ghidra's abstract `UnifyConstraint` (unify.hh:201). The
/// matcher calls, in order:
///   1. `assign_ids` - assign each node a unique traversal slot;
///   2. `build_traverse_state` - register the per-node iteration state;
///   3. `initialize` - reset iteration state for a fresh match attempt;
///   4. `step` repeatedly - advance to the next candidate binding, returning
///      `false` when exhausted.
pub trait UnifyConstraint: Send + Sync {
    /// This constraint's unique traversal slot id (`uniqid`, unify.hh:204).
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize;
    /// Highest state-slot index this constraint touches (`maxnum`,
    /// unify.hh:205). Used to size the storemap.
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize;
    /// Assign sequential traversal ids, depth-first pre-order. Faithful to
    /// `setId` (unify.hh:215).
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, counter: &mut usize);
    /// Deep-clone into a boxed trait object. Faithful to `clone`
    /// (unify.hh:211).
    // Ghidra: unify.hh:211 UnifyConstraint::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint>;
    /// Reset this constraint's iteration state for a fresh match. Default
    /// initializes a single-state counter (unify.cc:377-382).
    // Ghidra: unify.cc:377 UnifyConstraint::initialize
    fn initialize(&self, state: &mut UnifyState) {
        // unify.cc:377
        state.count_initialize(self.uniqid(), 1);
    }
    /// Advance to the next candidate. Returns `false` when exhausted.
    /// Faithful to `step` (unify.hh:213).
    // Ghidra: unify.hh:213 UnifyConstraint::step
    fn step(&self, state: &mut UnifyState) -> bool;
    /// Register this constraint's `TraverseConstraint` in the state. Default
    /// builds a `TraverseCountState` (unify.cc:384-391).
    // Ghidra: unify.cc:384 UnifyConstraint::buildTraverseState
    fn build_traverse_state(&self, state: &mut UnifyState) {
        // unify.cc:384
        if self.uniqid() != state.num_traverse() {
            panic!("Traverse id does not match index");
        }
        state.register_traverse_constraint(TraverseConstraint::Count(TraverseCountState::new(self.uniqid())));
    }
    /// Declare which state-slot kinds this constraint uses. Default no-op
    /// (unify.hh:216).
    // Ghidra: unify.hh:216 UnifyConstraint::collectTypes
    fn collect_types(&self, _typelist: &mut Vec<UnifyDatatype>) {}
    /// The "primary" slot this constraint produces, or -1 if none (unify.hh:217).
    // Ghidra: unify.hh:217 UnifyConstraint::getBaseIndex
    fn get_base_index(&self) -> i32 { -1 }
    /// True for the placeholder dummy constraints (unify.hh:219).
    // Ghidra: unify.hh:219 UnifyConstraint::isDummy
    fn is_dummy(&self) -> bool { false }
    /// Strip dummy subconstraints (unify.hh:220).
    // Ghidra: unify.hh:220 UnifyConstraint::removeDummy
    fn remove_dummy(&mut self) {}
    /// Emit C source for this constraint. Faithful to `print` (unify.hh:218).
    // Ghidra: unify.hh:218 UnifyConstraint::print
    fn print(&self, s: &mut String, printer: &mut UnifyCPrinter);
}

/// Helper: copy `uniqid`/`maxnum` from another constraint. Faithful to
/// `UnifyConstraint::copyid` (unify.hh:206).
// RUDRA-GLUE: free helper copying (uniqid,maxnum) between constraints (replaces Ghidra UnifyConstraint::copyid)
fn copy_ids(tu: &mut usize, tm: &mut usize, src: &dyn UnifyConstraint) {
    *tu = src.uniqid(); *tm = src.maxnum();
}

// --- Dummy placeholders (unify.hh:223-257). Reserve a state slot; always match.

/// Placeholder reserving an op slot. Faithful to `DummyOpConstraint`
/// (unify.hh:223-233).
#[derive(Debug, Clone)]
pub struct DummyOpConstraint { uniqid: usize, maxnum: usize, opindex: usize }
impl DummyOpConstraint {
    // Ghidra: unify.hh:226 DummyOpConstraint::DummyOpConstraint
    pub fn new(ind: usize) -> Self {
        Self {
            uniqid: 0,
            maxnum: ind,
            opindex: ind,
        }
    }
}
impl UnifyConstraint for DummyOpConstraint {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:227 DummyOpConstraint::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = DummyOpConstraint::new(self.opindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.hh:228 DummyOpConstraint::step
    fn step(&self, _s: &mut UnifyState) -> bool { true }
    // Ghidra: unify.hh:229 DummyOpConstraint::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) { t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType); }
    // Ghidra: unify.hh:230 DummyOpConstraint::getBaseIndex
    fn get_base_index(&self) -> i32 { self.opindex as i32 }
    // Ghidra: unify.hh:232 DummyOpConstraint::isDummy
    fn is_dummy(&self) -> bool { true }
    // Ghidra: unify.hh:231 DummyOpConstraint::print
    fn print(&self, _: &mut String, _: &mut UnifyCPrinter) {}
}

/// Placeholder reserving a varnode slot. Faithful to `DummyVarnodeConstraint`
/// (unify.hh:235-245).
#[derive(Debug, Clone)]
pub struct DummyVarnodeConstraint { uniqid: usize, maxnum: usize, varindex: usize }
impl DummyVarnodeConstraint {
    // Ghidra: unify.hh:238 DummyVarnodeConstraint::DummyVarnodeConstraint
    pub fn new(ind: usize) -> Self {
        Self {
            uniqid: 0,
            maxnum: ind,
            varindex: ind,
        }
    }
}
impl UnifyConstraint for DummyVarnodeConstraint {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:239 DummyVarnodeConstraint::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = DummyVarnodeConstraint::new(self.varindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.hh:240 DummyVarnodeConstraint::step
    fn step(&self, _s: &mut UnifyState) -> bool { true }
    // Ghidra: unify.hh:241 DummyVarnodeConstraint::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) { t[self.varindex] = UnifyDatatype::new(DatatypeKind::VarType); }
    // Ghidra: unify.hh:242 DummyVarnodeConstraint::getBaseIndex
    fn get_base_index(&self) -> i32 { self.varindex as i32 }
    // Ghidra: unify.hh:244 DummyVarnodeConstraint::isDummy
    fn is_dummy(&self) -> bool { true }
    // Ghidra: unify.hh:243 DummyVarnodeConstraint::print
    fn print(&self, _: &mut String, _: &mut UnifyCPrinter) {}
}

/// Placeholder reserving a constant slot. Faithful to `DummyConstConstraint`
/// (unify.hh:247-257).
#[derive(Debug, Clone)]
pub struct DummyConstConstraint { uniqid: usize, maxnum: usize, constindex: usize }
impl DummyConstConstraint {
    // Ghidra: unify.hh:250 DummyConstConstraint::DummyConstConstraint
    pub fn new(ind: usize) -> Self {
        Self {
            uniqid: 0,
            maxnum: ind,
            constindex: ind,
        }
    }
}
impl UnifyConstraint for DummyConstConstraint {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:251 DummyConstConstraint::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = DummyConstConstraint::new(self.constindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.hh:252 DummyConstConstraint::step
    fn step(&self, _s: &mut UnifyState) -> bool { true }
    // Ghidra: unify.hh:253 DummyConstConstraint::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) { t[self.constindex] = UnifyDatatype::new(DatatypeKind::ConstType); }
    // Ghidra: unify.hh:254 DummyConstConstraint::getBaseIndex
    fn get_base_index(&self) -> i32 { self.constindex as i32 }
    // Ghidra: unify.hh:256 DummyConstConstraint::isDummy
    fn is_dummy(&self) -> bool { true }
    // Ghidra: unify.hh:255 DummyConstConstraint::print
    fn print(&self, _: &mut String, _: &mut UnifyCPrinter) {}
}

// --- Predicate / binding constraints ---------------------------------------

/// A boolean RHS expression that must evaluate true (or false). Faithful to
/// `ConstraintBoolean` (unify.hh:259-268, unify.cc:393-416).
pub struct ConstraintBoolean { uniqid: usize, maxnum: usize, istrue: bool, expr: Box<dyn RHSConstant> }
impl ConstraintBoolean {
    // Ghidra: unify.hh:263 ConstraintBoolean::ConstraintBoolean
    pub fn new(ist: bool, ex: Box<dyn RHSConstant>) -> Self { Self { uniqid: 0, maxnum: 0, istrue: ist, expr: ex } }
}
impl Clone for ConstraintBoolean {
    // Ghidra: unify.hh:265 ConstraintBoolean::clone
    fn clone(&self) -> Self { Self { uniqid: self.uniqid, maxnum: self.maxnum, istrue: self.istrue, expr: self.expr.clone_box() } }
}
impl UnifyConstraint for ConstraintBoolean {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:265 ConstraintBoolean::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintBoolean::new(self.istrue, self.expr.clone_box()); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:393 ConstraintBoolean::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:393
        if !state.count_step(self.uniqid) { return false; }
        let v = self.expr.get_constant(state);
        if self.istrue { v != 0 } else { v == 0 }
    }
    // Ghidra: unify.cc:404 ConstraintBoolean::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:404
        p.print_indent(s); s.push_str("if (");
        self.expr.write_expression(s, p);
        s.push_str(if self.istrue { "== 0)" } else { "!= 0)" }); s.push('\n');
        p.print_abort(s);
    }
}

/// Synthesize a new constant varnode. Faithful to `ConstraintVarConst`
/// (unify.hh:270-282, unify.cc:418-463).
pub struct ConstraintVarConst {
    uniqid: usize, maxnum: usize, varindex: usize,
    expr: Box<dyn RHSConstant>, exprsz: Option<Box<dyn RHSConstant>>,
}
impl ConstraintVarConst {
    // Ghidra: unify.hh:275 ConstraintVarConst::ConstraintVarConst
    pub fn new(ind: usize, ex: Box<dyn RHSConstant>, sz: Option<Box<dyn RHSConstant>>) -> Self {
        Self { uniqid: 0, maxnum: ind, varindex: ind, expr: ex, exprsz: sz }
    }
}
impl Clone for ConstraintVarConst {
    // Ghidra: unify.cc:426 ConstraintVarConst::clone
    fn clone(&self) -> Self {
        Self {
            uniqid: self.uniqid, maxnum: self.maxnum, varindex: self.varindex,
            expr: self.expr.clone_box(), exprsz: self.exprsz.as_ref().map(|e| e.clone_box()),
        }
    }
}
impl UnifyConstraint for ConstraintVarConst {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.cc:426 ConstraintVarConst::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let sz = self.exprsz.as_ref().map(|e| e.clone_box());
        let mut n = ConstraintVarConst::new(self.varindex, self.expr.clone_box(), sz);
        copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:437 ConstraintVarConst::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:437
        if !state.count_step(self.uniqid) { return false; }
        let mut ourconst = self.expr.get_constant(state);
        let sz = match &self.exprsz { Some(e) => e.get_constant(state) as usize, None => 8 };
        ourconst &= calc_mask(sz);
        if let Some(fd) = state.get_function_cloned() {
            let vn = fd.write().unwrap().new_constant(sz, ourconst);
            state.data_mut(self.varindex).set_varnode(vn);
        } else {
            let vn = Arc::new(RwLock::new(Varnode::new_constant(ourconst, sz)));
            state.data_mut(self.varindex).set_varnode(vn);
        }
        true
    }
    // Ghidra: unify.cc:455 ConstraintVarConst::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        // unify.cc:455
        t[self.varindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:280 ConstraintVarConst::getBaseIndex
    fn get_base_index(&self) -> i32 { self.varindex as i32 }
    // Ghidra: unify.cc:461 ConstraintVarConst::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:461
        p.print_indent(s); s.push_str(&p.get_name(self.varindex));
        s.push_str(" = data.newConstant(");
        match &self.exprsz { Some(e) => e.write_expression(s, p), None => s.push_str("sizeof(uintb)") }
        s.push(','); self.expr.write_expression(s, p); s.push_str(");\n");
    }
}

/// Bind a named constant slot to an RHS expression. Faithful to
/// `ConstraintNamedExpression` (unify.hh:284-295, unify.cc:477-500).
pub struct ConstraintNamedExpression { uniqid: usize, maxnum: usize, constindex: usize, expr: Box<dyn RHSConstant> }
impl ConstraintNamedExpression {
    // Ghidra: unify.hh:288 ConstraintNamedExpression::ConstraintNamedExpression
    pub fn new(ind: usize, ex: Box<dyn RHSConstant>) -> Self { Self { uniqid: 0, maxnum: ind, constindex: ind, expr: ex } }
}
impl Clone for ConstraintNamedExpression {
    // Ghidra: unify.hh:290 ConstraintNamedExpression::clone
    fn clone(&self) -> Self { Self { uniqid: self.uniqid, maxnum: self.maxnum, constindex: self.constindex, expr: self.expr.clone_box() } }
}
impl UnifyConstraint for ConstraintNamedExpression {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:290 ConstraintNamedExpression::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintNamedExpression::new(self.constindex, self.expr.clone_box());
        copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:477 ConstraintNamedExpression::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:477
        if !state.count_step(self.uniqid) { return false; }
        let val = self.expr.get_constant(state);
        state.data_mut(self.constindex).set_constant(val);
        true
    }
    // Ghidra: unify.cc:487 ConstraintNamedExpression::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        // unify.cc:493
        t[self.constindex] = UnifyDatatype::new(DatatypeKind::ConstType);
    }
    // Ghidra: unify.hh:293 ConstraintNamedExpression::getBaseIndex
    fn get_base_index(&self) -> i32 { self.constindex as i32 }
    // Ghidra: unify.cc:493 ConstraintNamedExpression::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:495
        p.print_indent(s); s.push_str(&p.get_name(self.constindex));
        s.push_str(" = "); self.expr.write_expression(s, p); s.push_str(";\n");
    }
}
/// Copy an op binding from one slot to another. Faithful to `ConstraintOpCopy`
/// (unify.hh:297-307, unify.cc:502-524).
#[derive(Debug, Clone)]
pub struct ConstraintOpCopy { uniqid: usize, maxnum: usize, oldopindex: usize, newopindex: usize }
impl ConstraintOpCopy {
    // Ghidra: unify.hh:301 ConstraintOpCopy::ConstraintOpCopy
    pub fn new(oldind: usize, newind: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, oldind), newind), oldopindex: oldind, newopindex: newind }
    }
}
impl UnifyConstraint for ConstraintOpCopy {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:302 ConstraintOpCopy::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintOpCopy::new(self.oldopindex, self.newopindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:502 ConstraintOpCopy::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:502
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.oldopindex).get_op() {
            Some(o) => { state.data_mut(self.newopindex).set_op(o); true }
            None => false,
        }
    }
    // Ghidra: unify.cc:512 ConstraintOpCopy::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        // unify.cc:512
        t[self.oldopindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.newopindex] = UnifyDatatype::new(DatatypeKind::OpType);
    }
    // Ghidra: unify.hh:305 ConstraintOpCopy::getBaseIndex
    fn get_base_index(&self) -> i32 { self.oldopindex as i32 }
    // Ghidra: unify.cc:519 ConstraintOpCopy::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:519
        p.print_indent(s); s.push_str(&p.get_name(self.newopindex));
        s.push_str(" = "); s.push_str(&p.get_name(self.oldopindex)); s.push_str(";\n");
    }
}

/// Match an op's opcode against a set of accepted opcodes. Faithful to
/// `ConstraintOpcode` (unify.hh:309-320, unify.cc:526-560).
#[derive(Debug, Clone)]
pub struct ConstraintOpcode { uniqid: usize, maxnum: usize, opindex: usize, opcodes: Vec<OpCode> }
impl ConstraintOpcode {
    // Ghidra: unify.hh:313 ConstraintOpcode::ConstraintOpcode
    pub fn new(ind: usize, o: Vec<OpCode>) -> Self { Self { uniqid: 0, maxnum: ind, opindex: ind, opcodes: o } }
    // Ghidra: unify.hh:314 ConstraintOpcode::getOpCodes
    pub fn get_opcodes(&self) -> &[OpCode] { &self.opcodes }
}
impl UnifyConstraint for ConstraintOpcode {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:315 ConstraintOpcode::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintOpcode::new(self.opindex, self.opcodes.clone()); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:526 ConstraintOpcode::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:526
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.opindex).get_op() {
            Some(o) => { let code = o.read().unwrap().opcode; self.opcodes.iter().any(|&c| c == code) }
            None => false,
        }
    }
    // Ghidra: unify.cc:537 ConstraintOpcode::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) { t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType); }
    // Ghidra: unify.hh:318 ConstraintOpcode::getBaseIndex
    fn get_base_index(&self) -> i32 { self.opindex as i32 }
    // Ghidra: unify.cc:543 ConstraintOpcode::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:543
        p.print_indent(s); s.push_str("if (");
        if self.opcodes.len() == 1 {
            s.push_str(&p.get_name(self.opindex)); s.push_str("->code() != CPUI_"); s.push_str(self.opcodes[0].name());
        } else {
            for (i, &oc) in self.opcodes.iter().enumerate() {
                if i > 0 { s.push_str("&&"); }
                s.push('('); s.push_str(&p.get_name(self.opindex)); s.push_str("->code() != CPUI_"); s.push_str(oc.name()); s.push(')');
            }
        }
        s.push_str(")\n"); p.print_abort(s);
    }
}

/// Compare two op slots for (in)equality. Faithful to `ConstraintOpCompare`
/// (unify.hh:322-333, unify.cc:562-590).
#[derive(Debug, Clone)]
pub struct ConstraintOpCompare { uniqid: usize, maxnum: usize, op1index: usize, op2index: usize, istrue: bool }
impl ConstraintOpCompare {
    // Ghidra: unify.hh:327 ConstraintOpCompare::ConstraintOpCompare
    pub fn new(op1ind: usize, op2ind: usize, val: bool) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, op1ind), op2ind), op1index: op1ind, op2index: op2ind, istrue: val }
    }
}
impl UnifyConstraint for ConstraintOpCompare {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:328 ConstraintOpCompare::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintOpCompare::new(self.op1index, self.op2index, self.istrue); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:562 ConstraintOpCompare::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:562
        if !state.count_step(self.uniqid) { return false; }
        let op1 = state.data(self.op1index).get_op();
        let op2 = state.data(self.op2index).get_op();
        let same = match (op1, op2) {
            (Some(a), Some(b)) => Arc::ptr_eq(&a, &b),
            (None, None) => true,
            _ => false,
        };
        same == self.istrue
    }
    // Ghidra: unify.cc:572 ConstraintOpCompare::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.op1index] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.op2index] = UnifyDatatype::new(DatatypeKind::OpType);
    }
    // Ghidra: unify.hh:331 ConstraintOpCompare::getBaseIndex
    fn get_base_index(&self) -> i32 { self.op1index as i32 }
    // Ghidra: unify.cc:579 ConstraintOpCompare::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:579
        p.print_indent(s); s.push_str("if ("); s.push_str(&p.get_name(self.op1index));
        s.push_str(if self.istrue { " != " } else { " == " }); s.push_str(&p.get_name(self.op2index));
        s.push_str(")\n"); p.print_abort(s);
    }
}

/// Bind a specific input slot of an op to a varnode slot. Faithful to
/// `ConstraintOpInput` (unify.hh:335-346, unify.cc:592-616).
#[derive(Debug, Clone)]
pub struct ConstraintOpInput { uniqid: usize, maxnum: usize, opindex: usize, varnodeindex: usize, slot: usize }
impl ConstraintOpInput {
    // Ghidra: unify.hh:340 ConstraintOpInput::ConstraintOpInput
    pub fn new(oind: usize, vind: usize, sl: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, oind), vind), opindex: oind, varnodeindex: vind, slot: sl }
    }
}
impl UnifyConstraint for ConstraintOpInput {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:341 ConstraintOpInput::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintOpInput::new(self.opindex, self.varnodeindex, self.slot); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:592 ConstraintOpInput::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:592
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.opindex).get_op() {
            Some(o) => match o.read().unwrap().get_in(self.slot).cloned() {
                Some(v) => { state.data_mut(self.varnodeindex).set_varnode(v); true }
                None => false,
            },
            None => false,
        }
    }
    // Ghidra: unify.cc:603 ConstraintOpInput::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.varnodeindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:344 ConstraintOpInput::getBaseIndex
    fn get_base_index(&self) -> i32 { self.varnodeindex as i32 }
    // Ghidra: unify.cc:610 ConstraintOpInput::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:610
        p.print_indent(s); s.push_str(&p.get_name(self.varnodeindex)); s.push_str(" = ");
        s.push_str(&p.get_name(self.opindex)); s.push_str("->getIn("); s.push_str(&self.slot.to_string()); s.push_str(");\n");
    }
}

/// Iterate over every input of an op. Faithful to `ConstraintOpInputAny`
/// (unify.hh:348-359, unify.cc:618-654).
#[derive(Debug, Clone)]
pub struct ConstraintOpInputAny { uniqid: usize, maxnum: usize, opindex: usize, varnodeindex: usize }
impl ConstraintOpInputAny {
    // Ghidra: unify.hh:352 ConstraintOpInputAny::ConstraintOpInputAny
    pub fn new(oind: usize, vind: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, oind), vind), opindex: oind, varnodeindex: vind }
    }
}
impl UnifyConstraint for ConstraintOpInputAny {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:353 ConstraintOpInputAny::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintOpInputAny::new(self.opindex, self.varnodeindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:618 ConstraintOpInputAny::initialize
    fn initialize(&self, state: &mut UnifyState) {
        // unify.cc:618 - initialize counter to the op's input count.
        let num = state.data(self.opindex).get_op()
            .map(|o| o.read().unwrap().num_input()).unwrap_or(0) as i32;
        state.count_initialize(self.uniqid(), num);
    }
    // Ghidra: unify.cc:626 ConstraintOpInputAny::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:626
        if !state.count_step(self.uniqid) { return false; }
        let slot = state.count_get_state(self.uniqid) as usize;
        match state.data(self.opindex).get_op() {
            Some(o) => match o.read().unwrap().get_in(slot).cloned() {
                Some(v) => { state.data_mut(self.varnodeindex).set_varnode(v); true }
                None => false,
            },
            None => false,
        }
    }
    // Ghidra: unify.cc:637 ConstraintOpInputAny::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.varnodeindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:357 ConstraintOpInputAny::getBaseIndex
    fn get_base_index(&self) -> i32 { self.varnodeindex as i32 }
    // Ghidra: unify.cc:644 ConstraintOpInputAny::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:644
        let d = p.get_depth();
        p.print_indent(s); s.push_str(&format!("for(int4 i{}=0;i{}<", d, d));
        s.push_str(&p.get_name(self.opindex)); s.push_str(&format!("->numInput();++i{}) {{\n", d));
        p.inc_depth(); p.print_indent(s);
        s.push_str(&p.get_name(self.varnodeindex)); s.push_str(" = "); s.push_str(&p.get_name(self.opindex));
        s.push_str(&format!("->getIn(i{});\n", d));
    }
}

/// Bind an op's output varnode. Faithful to `ConstraintOpOutput`
/// (unify.hh:361-371, unify.cc:656-679).
#[derive(Debug, Clone)]
pub struct ConstraintOpOutput { uniqid: usize, maxnum: usize, opindex: usize, varnodeindex: usize }
impl ConstraintOpOutput {
    // Ghidra: unify.hh:365 ConstraintOpOutput::ConstraintOpOutput
    pub fn new(oind: usize, vind: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, oind), vind), opindex: oind, varnodeindex: vind }
    }
}
impl UnifyConstraint for ConstraintOpOutput {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:366 ConstraintOpOutput::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintOpOutput::new(self.opindex, self.varnodeindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:656 ConstraintOpOutput::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:656
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.opindex).get_op() {
            Some(o) => match o.read().unwrap().get_out().cloned() {
                Some(v) => { state.data_mut(self.varnodeindex).set_varnode(v); true }
                None => false,
            },
            None => false,
        }
    }
    // Ghidra: unify.cc:667 ConstraintOpOutput::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.varnodeindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:369 ConstraintOpOutput::getBaseIndex
    fn get_base_index(&self) -> i32 { self.varnodeindex as i32 }
    // Ghidra: unify.cc:674 ConstraintOpOutput::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:674
        p.print_indent(s); s.push_str(&p.get_name(self.varnodeindex)); s.push_str(" = ");
        s.push_str(&p.get_name(self.opindex)); s.push_str("->getOut();\n");
    }
}

/// Require a specific constant value at an op's input slot. Faithful to
/// `ConstraintParamConstVal` (unify.hh:373-383, unify.cc:681-710).
#[derive(Debug, Clone)]
pub struct ConstraintParamConstVal { uniqid: usize, maxnum: usize, opindex: usize, slot: usize, val: u64 }
impl ConstraintParamConstVal {
    // Ghidra: unify.hh:378 ConstraintParamConstVal::ConstraintParamConstVal
    pub fn new(oind: usize, sl: usize, v: u64) -> Self { Self { uniqid: 0, maxnum: oind, opindex: oind, slot: sl, val: v } }
}
impl UnifyConstraint for ConstraintParamConstVal {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:379 ConstraintParamConstVal::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintParamConstVal::new(self.opindex, self.slot, self.val); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:681 ConstraintParamConstVal::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:681
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.opindex).get_op() {
            Some(o) => match o.read().unwrap().get_in(self.slot).cloned() {
                Some(v) => {
                    let vr = v.read().unwrap();
                    if !vr.is_constant() { return false; }
                    vr.get_offset() == (self.val & calc_mask(vr.get_size()))
                }
                None => false,
            },
            None => false,
        }
    }
    // Ghidra: unify.cc:693 ConstraintParamConstVal::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) { t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType); }
    // Ghidra: unify.cc:699 ConstraintParamConstVal::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:699
        let nm = p.get_name(self.opindex); let sl = self.slot.to_string();
        p.print_indent(s); s.push_str(&format!("if (!{}->getIn({})->isConstant())\n", nm, sl)); p.print_abort(s);
        p.print_indent(s);
        s.push_str(&format!("if ({}->getIn({})->getOffset() != 0x{:x} & calc_mask({}->getIn({})->getSize()))\n", nm, sl, self.val, nm, sl));
        p.print_abort(s);
    }
}

/// Bind an op's constant input at a slot to a named constant. Faithful to
/// `ConstraintParamConst` (unify.hh:385-396, unify.cc:712-740).
#[derive(Debug, Clone)]
pub struct ConstraintParamConst { uniqid: usize, maxnum: usize, opindex: usize, slot: usize, constindex: usize }
impl ConstraintParamConst {
    // Ghidra: unify.hh:390 ConstraintParamConst::ConstraintParamConst
    pub fn new(oind: usize, sl: usize, cind: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, oind), cind), opindex: oind, slot: sl, constindex: cind }
    }
}
impl UnifyConstraint for ConstraintParamConst {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:391 ConstraintParamConst::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintParamConst::new(self.opindex, self.slot, self.constindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:712 ConstraintParamConst::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:712
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.opindex).get_op() {
            Some(o) => match o.read().unwrap().get_in(self.slot).cloned() {
                Some(v) => {
                    let off = { let vr = v.read().unwrap(); if !vr.is_constant() { return false; } vr.get_offset() };
                    state.data_mut(self.constindex).set_constant(off); true
                }
                None => false,
            },
            None => false,
        }
    }
    // Ghidra: unify.cc:724 ConstraintParamConst::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.constindex] = UnifyDatatype::new(DatatypeKind::ConstType);
    }
    // Ghidra: unify.hh:394 ConstraintParamConst::getBaseIndex
    fn get_base_index(&self) -> i32 { self.constindex as i32 }
    // Ghidra: unify.cc:731 ConstraintParamConst::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:731
        let nm = p.get_name(self.opindex); let sl = self.slot.to_string();
        p.print_indent(s); s.push_str(&format!("if (!{}->getIn({})->isConstant())\n", nm, sl)); p.print_abort(s);
        p.print_indent(s); s.push_str(&p.get_name(self.constindex));
        s.push_str(&format!(" = {}->getIn({})->getOffset();\n", nm, sl));
    }
}

/// Copy a varnode binding from one slot to another. Faithful to
/// `ConstraintVarnodeCopy` (unify.hh:398-408, unify.cc:742-764).
#[derive(Debug, Clone)]
pub struct ConstraintVarnodeCopy { uniqid: usize, maxnum: usize, oldvarindex: usize, newvarindex: usize }
impl ConstraintVarnodeCopy {
    // Ghidra: unify.hh:402 ConstraintVarnodeCopy::ConstraintVarnodeCopy
    pub fn new(oldind: usize, newind: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, oldind), newind), oldvarindex: oldind, newvarindex: newind }
    }
}
impl UnifyConstraint for ConstraintVarnodeCopy {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:403 ConstraintVarnodeCopy::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintVarnodeCopy::new(self.oldvarindex, self.newvarindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:742 ConstraintVarnodeCopy::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:742
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.oldvarindex).get_varnode() {
            Some(v) => { state.data_mut(self.newvarindex).set_varnode(v); true }
            None => false,
        }
    }
    // Ghidra: unify.cc:752 ConstraintVarnodeCopy::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.oldvarindex] = UnifyDatatype::new(DatatypeKind::VarType);
        t[self.newvarindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:406 ConstraintVarnodeCopy::getBaseIndex
    fn get_base_index(&self) -> i32 { self.oldvarindex as i32 }
    // Ghidra: unify.cc:759 ConstraintVarnodeCopy::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:759
        p.print_indent(s); s.push_str(&p.get_name(self.newvarindex));
        s.push_str(" = "); s.push_str(&p.get_name(self.oldvarindex)); s.push_str(";\n");
    }
}

/// Compare two varnode slots for (in)equality (pointer identity). Faithful to
/// `ConstraintVarCompare` (unify.hh:410-421, unify.cc:766-794).
#[derive(Debug, Clone)]
pub struct ConstraintVarCompare { uniqid: usize, maxnum: usize, var1index: usize, var2index: usize, istrue: bool }
impl ConstraintVarCompare {
    // Ghidra: unify.hh:415 ConstraintVarCompare::ConstraintVarCompare
    pub fn new(v1: usize, v2: usize, val: bool) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, v1), v2), var1index: v1, var2index: v2, istrue: val }
    }
}
impl UnifyConstraint for ConstraintVarCompare {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:416 ConstraintVarCompare::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintVarCompare::new(self.var1index, self.var2index, self.istrue); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:766 ConstraintVarCompare::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:766
        if !state.count_step(self.uniqid) { return false; }
        let v1 = state.data(self.var1index).get_varnode();
        let v2 = state.data(self.var2index).get_varnode();
        let same = match (v1, v2) {
            (Some(a), Some(b)) => Arc::ptr_eq(&a, &b),
            (None, None) => true,
            _ => false,
        };
        same == self.istrue
    }
    // Ghidra: unify.cc:776 ConstraintVarCompare::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.var1index] = UnifyDatatype::new(DatatypeKind::VarType);
        t[self.var2index] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:419 ConstraintVarCompare::getBaseIndex
    fn get_base_index(&self) -> i32 { self.var1index as i32 }
    // Ghidra: unify.cc:783 ConstraintVarCompare::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:783
        p.print_indent(s); s.push_str("if ("); s.push_str(&p.get_name(self.var1index));
        s.push_str(if self.istrue { " != " } else { " == " }); s.push_str(&p.get_name(self.var2index));
        s.push_str(")\n"); p.print_abort(s);
    }
}

/// Bind the defining op of a written varnode. Faithful to `ConstraintDef`
/// (unify.hh:423-433, unify.cc:796-823).
#[derive(Debug, Clone)]
pub struct ConstraintDef { uniqid: usize, maxnum: usize, opindex: usize, varindex: usize }
impl ConstraintDef {
    // Ghidra: unify.hh:427 ConstraintDef::ConstraintDef
    pub fn new(oind: usize, vind: usize) -> Self { Self { uniqid: 0, maxnum: imax(imax(0, oind), vind), opindex: oind, varindex: vind } }
}
impl UnifyConstraint for ConstraintDef {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:428 ConstraintDef::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintDef::new(self.opindex, self.varindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:796 ConstraintDef::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:796
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.varindex).get_varnode() {
            Some(v) => {
                let def = { let vr = v.read().unwrap(); if !vr.is_written() { return false; } vr.get_def() };
                match def { Some(op) => { state.data_mut(self.opindex).set_op(op); true } None => false }
            }
            None => false,
        }
    }
    // Ghidra: unify.cc:808 ConstraintDef::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.varindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:431 ConstraintDef::getBaseIndex
    fn get_base_index(&self) -> i32 { self.opindex as i32 }
    // Ghidra: unify.cc:815 ConstraintDef::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:815
        p.print_indent(s); s.push_str("if (!"); s.push_str(&p.get_name(self.varindex));
        s.push_str("->isWritten())\n"); p.print_abort(s);
        p.print_indent(s); s.push_str(&p.get_name(self.opindex)); s.push_str(" = ");
        s.push_str(&p.get_name(self.varindex)); s.push_str("->getDef();\n");
    }
}

/// Iterate over the descendant ops of a varnode. Faithful to
/// `ConstraintDescend` (unify.hh:435-447, unify.cc:825-875).
#[derive(Debug, Clone)]
pub struct ConstraintDescend { uniqid: usize, maxnum: usize, opindex: usize, varindex: usize }
impl ConstraintDescend {
    // Ghidra: unify.hh:439 ConstraintDescend::ConstraintDescend
    pub fn new(oind: usize, vind: usize) -> Self { Self { uniqid: 0, maxnum: imax(imax(0, oind), vind), opindex: oind, varindex: vind } }
}
impl UnifyConstraint for ConstraintDescend {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:440 ConstraintDescend::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintDescend::new(self.opindex, self.varindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:825 ConstraintDescend::buildTraverseState
    fn build_traverse_state(&self, state: &mut UnifyState) {
        // unify.cc:825 - Descend uses a Descend traversal, not the Count default.
        if self.uniqid() != state.num_traverse() { panic!("Traverse id does not match index"); }
        state.register_traverse_constraint(TraverseConstraint::Descend(TraverseDescendState::new(self.uniqid())));
    }
    // Ghidra: unify.cc:834 ConstraintDescend::initialize
    fn initialize(&self, state: &mut UnifyState) {
        // unify.cc:834
        match state.data(self.varindex).get_varnode() {
            Some(v) => state.descend_initialize(self.uniqid(), &v.read().unwrap()),
            None => state.descend_initialize_empty(self.uniqid()),
        }
    }
    // Ghidra: unify.cc:842 ConstraintDescend::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:842
        if !state.descend_step(self.uniqid) { return false; }
        let op = state.descend_get_current(self.uniqid);
        state.data_mut(self.opindex).set_op(op); true
    }
    // Ghidra: unify.cc:852 ConstraintDescend::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.varindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:445 ConstraintDescend::getBaseIndex
    fn get_base_index(&self) -> i32 { self.opindex as i32 }
    // Ghidra: unify.cc:859 ConstraintDescend::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:859
        let d = p.get_depth();
        p.print_indent(s); s.push_str(&format!("list<PcodeOp *>::const_iterator iter{},enditer{};\n", d, d));
        p.print_indent(s); s.push_str(&format!("iter{} = ", d)); s.push_str(&p.get_name(self.varindex)); s.push_str("->beginDescend();\n");
        p.print_indent(s); s.push_str(&format!("enditer{} = ", d)); s.push_str(&p.get_name(self.varindex)); s.push_str("->endDescend();\n");
        p.print_indent(s); s.push_str(&format!("while(iter{} != enditer{}) {{\n", d, d));
        p.inc_depth(); p.print_indent(s); s.push_str(&p.get_name(self.opindex));
        s.push_str(&format!(" = *iter{};\n", d)); p.print_indent(s); s.push_str(&format!("++iter{}\n", d));
    }
}

/// Bind the lone descendant of a varnode (fails if zero or many). Faithful to
/// `ConstraintLoneDescend` (unify.hh:449-459, unify.cc:877-904).
#[derive(Debug, Clone)]
pub struct ConstraintLoneDescend { uniqid: usize, maxnum: usize, opindex: usize, varindex: usize }
impl ConstraintLoneDescend {
    // Ghidra: unify.hh:453 ConstraintLoneDescend::ConstraintLoneDescend
    pub fn new(oind: usize, vind: usize) -> Self { Self { uniqid: 0, maxnum: imax(imax(0, oind), vind), opindex: oind, varindex: vind } }
}
impl UnifyConstraint for ConstraintLoneDescend {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:454 ConstraintLoneDescend::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintLoneDescend::new(self.opindex, self.varindex); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:877 ConstraintLoneDescend::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:877
        if !state.count_step(self.uniqid) { return false; }
        match state.data(self.varindex).get_varnode() {
            Some(v) => match v.read().unwrap().lone_descend() {
                Some(op) => { state.data_mut(self.opindex).set_op(op); true } None => false,
            },
            None => false,
        }
    }
    // Ghidra: unify.cc:889 ConstraintLoneDescend::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.varindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:457 ConstraintLoneDescend::getBaseIndex
    fn get_base_index(&self) -> i32 { self.opindex as i32 }
    // Ghidra: unify.cc:896 ConstraintLoneDescend::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:896
        p.print_indent(s); s.push_str(&p.get_name(self.opindex)); s.push_str(" = ");
        s.push_str(&p.get_name(self.varindex)); s.push_str("->loneDescend();\n");
        p.print_indent(s); s.push_str("if ("); s.push_str(&p.get_name(self.opindex));
        s.push_str(" == (PcodeOp *)0)\n"); p.print_abort(s);
    }
}

/// Find the input-slot index holding varnode `vn` on op `op` (pointer
/// identity). Stands in for Ghidra's `PcodeOp::getSlot(Varnode*)` which
/// rugra's `PcodeOp` does not yet expose.
// RUDRA-GLUE: free helper standing in for PcodeOp::getSlot(Varnode*) (op.hh) not yet exposed on rugra PcodeOp
fn find_input_slot(op: &PcodeOp, vn: &VnArc) -> Option<usize> {
    for (i, input) in op.inrefs.iter().enumerate() {
        if Arc::ptr_eq(input, vn) { return Some(i); }
    }
    None
}

/// Bind the "other" input of a binary op, given one input. Faithful to
/// `ConstraintOtherInput` (unify.hh:461-473, unify.cc:906-932).
#[derive(Debug, Clone)]
pub struct ConstraintOtherInput { uniqid: usize, maxnum: usize, opindex: usize, varindex_in: usize, varindex_out: usize }
impl ConstraintOtherInput {
    // Ghidra: unify.hh:466 ConstraintOtherInput::ConstraintOtherInput
    pub fn new(oind: usize, v_in: usize, v_out: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(imax(0, oind), v_in), v_out), opindex: oind, varindex_in: v_in, varindex_out: v_out }
    }
}
impl UnifyConstraint for ConstraintOtherInput {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:468 ConstraintOtherInput::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintOtherInput::new(self.opindex, self.varindex_in, self.varindex_out); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:906 ConstraintOtherInput::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:906
        if !state.count_step(self.uniqid) { return false; }
        let op = state.data(self.opindex).get_op();
        let vn_in = state.data(self.varindex_in).get_varnode();
        match (op, vn_in) {
            (Some(o), Some(vin)) => {
                let other_slot = match find_input_slot(&o.read().unwrap(), &vin) {
                    Some(s) => 1i32 - s as i32, None => return false,
                };
                if other_slot < 0 { return false; }
                match o.read().unwrap().get_in(other_slot as usize).cloned() {
                    Some(v) => { state.data_mut(self.varindex_out).set_varnode(v); true } None => false,
                }
            }
            _ => false,
        }
    }
    // Ghidra: unify.cc:918 ConstraintOtherInput::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.varindex_in] = UnifyDatatype::new(DatatypeKind::VarType);
        t[self.varindex_out] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:469 ConstraintOtherInput::getBaseIndex
    fn get_base_index(&self) -> i32 { self.varindex_out as i32 }
    // Ghidra: unify.cc:926 ConstraintOtherInput::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:926
        p.print_indent(s); s.push_str(&p.get_name(self.varindex_out)); s.push_str(" = ");
        s.push_str(&p.get_name(self.opindex)); s.push_str("->getIn(1 - ");
        s.push_str(&p.get_name(self.opindex)); s.push_str("->getSlot(");
        s.push_str(&p.get_name(self.varindex_in)); s.push_str("));\n");
    }
}

/// Compare two named constants via a boolean opcode. Faithful to
/// `ConstraintConstCompare` (unify.hh:475-487, unify.cc:934-953).
#[derive(Debug, Clone)]
pub struct ConstraintConstCompare { uniqid: usize, maxnum: usize, const1index: usize, const2index: usize, opc: OpCode }
impl ConstraintConstCompare {
    // Ghidra: unify.hh:480 ConstraintConstCompare::ConstraintConstCompare
    pub fn new(c1: usize, c2: usize, oc: OpCode) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, c1), c2), const1index: c1, const2index: c2, opc: oc }
    }
}
impl UnifyConstraint for ConstraintConstCompare {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:482 ConstraintConstCompare::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintConstCompare::new(self.const1index, self.const2index, self.opc); copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:934 ConstraintConstCompare::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:934
        if !state.count_step(self.uniqid) { return false; }
        let c1 = state.data(self.const1index).get_constant();
        let c2 = state.data(self.const2index).get_constant();
        let res = crate::opbehavior::evaluate_binary(self.opc, 1, 8, c1, c2).unwrap_or(0);
        res != 0
    }
    // Ghidra: unify.cc:947 ConstraintConstCompare::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.const1index] = UnifyDatatype::new(DatatypeKind::ConstType);
        t[self.const2index] = UnifyDatatype::new(DatatypeKind::ConstType);
    }
    // Ghidra: unify.hh:485 ConstraintConstCompare::getBaseIndex
    fn get_base_index(&self) -> i32 { self.const1index as i32 }
    // Ghidra: unify.cc:954 ConstraintConstCompare::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:954
        p.print_indent(s); s.push_str("if (");
        match self.opc {
            OpCode::CPUI_INT_EQUAL => {
                s.push_str(&p.get_name(self.const1index)); s.push_str(" != "); s.push_str(&p.get_name(self.const2index));
            }
            OpCode::CPUI_INT_NOTEQUAL => {
                s.push_str(&p.get_name(self.const1index)); s.push_str(" == "); s.push_str(&p.get_name(self.const2index));
            }
            _ => {
                s.push_str(&p.get_name(self.const1index)); s.push_str(" <op> "); s.push_str(&p.get_name(self.const2index));
            }
        }
        s.push_str(")\n"); p.print_abort(s);
    }
}
// -----------------------------------------------------------------------
// Composite constraints: ConstraintGroup (unify.hh:491-511) and ConstraintOr
// (unify.hh:515-523). These carry the backtracking search.
// -----------------------------------------------------------------------

/// A conjunction of subconstraints: ALL must match. Tested first-to-last; a
/// later constraint may assume earlier ones have bound their slots.
/// Faithful to `ConstraintGroup` (unify.hh:491, unify.cc:960-1139).
pub struct ConstraintGroup {
    uniqid: usize,
    maxnum: usize,
    constraintlist: Vec<Box<dyn UnifyConstraint>>,
}

impl Clone for ConstraintGroup {
    // Ghidra: unify.cc:1016 ConstraintGroup::clone
    fn clone(&self) -> Self {
        let mut res = ConstraintGroup::new();
        for c in &self.constraintlist { res.constraintlist.push(c.clone_box()); }
        res.uniqid = self.uniqid; res.maxnum = self.maxnum;
        res
    }
}

impl std::fmt::Debug for ConstraintGroup {
    // RUDRA-GLUE: Rust Debug impl for ConstraintGroup; Ghidra uses print() instead
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConstraintGroup")
            .field("uniqid", &self.uniqid)
            .field("maxnum", &self.maxnum)
            .field("num_constraints", &self.constraintlist.len())
            .finish()
    }
}

impl Default for ConstraintGroup {
    // RUDRA-GLUE: Rust Default delegates to new(); Ghidra has no Default trait,
    // and its constructor at unify.cc:974 sets maxnum=-1 rather than Rust's 0.
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintGroup {
    /// Faithful to `ConstraintGroup::ConstraintGroup` (unify.cc:960-979).
    // Ghidra: unify.cc:974 ConstraintGroup::ConstraintGroup
    pub fn new() -> Self { Self { uniqid: 0, maxnum: 0, constraintlist: Vec::new() } }

    /// Faithful to `addConstraint` (unify.hh:498, unify.cc:988-995).
    // Ghidra: unify.cc:988 ConstraintGroup::addConstraint
    pub fn add_constraint(&mut self, c: Box<dyn UnifyConstraint>) {
        if c.maxnum() > self.maxnum { self.maxnum = c.maxnum(); }
        self.constraintlist.push(c);
    }

    /// Number of subconstraints. Faithful to `numConstraints` (unify.hh:499).
    // Ghidra: unify.hh:499 ConstraintGroup::numConstraints
    pub fn num_constraints(&self) -> usize { self.constraintlist.len() }

    /// Borrow a subconstraint. Faithful to `getConstraint` (unify.hh:497).
    // Ghidra: unify.hh:497 ConstraintGroup::getConstraint
    pub fn get_constraint(&self, slot: usize) -> &dyn UnifyConstraint { self.constraintlist[slot].as_ref() }

    /// Faithful to `deleteConstraint` (unify.hh:500, unify.cc:997-1005).
    // Ghidra: unify.cc:997 ConstraintGroup::deleteConstraint
    pub fn delete_constraint(&mut self, slot: usize) { self.constraintlist.remove(slot); }

    /// Move all subconstraints out of `b` into `self`. Faithful to `mergeIn`
    /// (unify.hh:501, unify.cc:1007-1014).
    // Ghidra: unify.cc:1007 ConstraintGroup::mergeIn
    pub fn merge_in(&mut self, mut b: ConstraintGroup) {
        for c in b.constraintlist.drain(..) { self.add_constraint(c); }
    }

    /// Assign sequential traversal ids to the whole tree. Must be called once
    /// before constructing a `UnifyState`. Faithful to `setId`
    /// (unify.hh:507, unify.cc:1108-1114).
    // Ghidra: unify.cc:1108 ConstraintGroup::setId
    pub fn assign_ids(&mut self) {
        let mut counter = 0usize;
        UnifyConstraint::assign_ids(self, &mut counter);
    }
}

impl UnifyConstraint for ConstraintGroup {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1108 ConstraintGroup::setId
    fn assign_ids(&mut self, counter: &mut usize) {
        // unify.cc:1108
        self.uniqid = *counter; *counter += 1;
        for c in &mut self.constraintlist { c.assign_ids(counter); }
    }
    // Ghidra: unify.cc:1016 ConstraintGroup::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        // unify.cc:1016
        let mut res = ConstraintGroup::new();
        for c in &self.constraintlist { res.constraintlist.push(c.clone_box()); }
        res.uniqid = self.uniqid; res.maxnum = self.maxnum;
        Box::new(res)
    }
    // Ghidra: unify.cc:1028 ConstraintGroup::initialize
    fn initialize(&self, state: &mut UnifyState) {
        // unify.cc:1028
        state.group_set_state(self.uniqid, -1);
    }
    // Ghidra: unify.cc:1035 ConstraintGroup::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:1035 - backtracking depth-first search over the list.
        let max = self.constraintlist.len() as i32;
        if max == 0 {
            // Empty group matches once.
            return state.count_step(self.uniqid);
        }
        let mut subindex: i32;
        loop {
            let stateint = state.group_get_state(self.uniqid);
            let curridx = state.group_get_current_index(self.uniqid);
            if stateint == 0 {
                subindex = curridx;
                if self.constraintlist[subindex as usize].step(state) {
                    subindex += 1;
                    state.group_set(self.uniqid, 1, subindex);
                } else {
                    subindex -= 1;
                    if subindex < 0 { return false; }
                    state.group_set(self.uniqid, 0, subindex);
                }
            } else if stateint == 1 {
                subindex = curridx;
                self.constraintlist[subindex as usize].initialize(state);
                state.group_set_state(self.uniqid, 0);
            } else {
                subindex = 0;
                state.group_set(self.uniqid, 0, 0);
                self.constraintlist[0].initialize(state);
            }
            if !(subindex < max) { break; }
        }
        subindex -= 1;
        state.group_set(self.uniqid, 0, subindex);
        true
    }
    // Ghidra: unify.cc:1085 ConstraintGroup::collectTypes
    fn collect_types(&self, typelist: &mut Vec<UnifyDatatype>) {
        // unify.cc:1085
        for c in &self.constraintlist { c.collect_types(typelist); }
    }
    // Ghidra: unify.cc:1092 ConstraintGroup::buildTraverseState
    fn build_traverse_state(&self, state: &mut UnifyState) {
        // unify.cc:1092
        if self.uniqid != state.num_traverse() { panic!("Traverse id does not match index"); }
        state.register_traverse_constraint(TraverseConstraint::Group(TraverseGroupState::new(self.uniqid)));
        for c in &self.constraintlist { c.build_traverse_state(state); }
    }
    // Ghidra: unify.hh:508 ConstraintGroup::getBaseIndex
    fn get_base_index(&self) -> i32 {
        self.constraintlist.last().map(|c| c.get_base_index()).unwrap_or(-1)
    }
    // Ghidra: unify.cc:1123 ConstraintGroup::removeDummy
    fn remove_dummy(&mut self) {
        // unify.cc:1123
        let mut newlist: Vec<Box<dyn UnifyConstraint>> = Vec::new();
        for mut c in self.constraintlist.drain(..) {
            if c.is_dummy() { continue; }
            c.remove_dummy(); newlist.push(c);
        }
        self.constraintlist = newlist;
    }
    // Ghidra: unify.cc:1116 ConstraintGroup::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:1116
        for c in &self.constraintlist { c.print(s, p); }
    }
}

/// A disjunction: exactly one branch must match. Branches are independent.
/// Faithful to `ConstraintOr` (unify.hh:515-523, unify.cc:1141-1217).
pub struct ConstraintOr {
    uniqid: usize,
    maxnum: usize,
    constraintlist: Vec<Box<dyn UnifyConstraint>>,
}

impl Clone for ConstraintOr {
    // Ghidra: unify.cc:1141 ConstraintOr::clone
    fn clone(&self) -> Self {
        let mut res = ConstraintOr::new();
        for c in &self.constraintlist { res.constraintlist.push(c.clone_box()); }
        res.uniqid = self.uniqid; res.maxnum = self.maxnum;
        res
    }
}

impl std::fmt::Debug for ConstraintOr {
    // RUDRA-GLUE: Rust Debug impl for ConstraintOr; Ghidra uses print() instead
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConstraintOr")
            .field("uniqid", &self.uniqid)
            .field("num_branches", &self.constraintlist.len())
            .finish()
    }
}

impl ConstraintOr {
    // Ghidra: unify.cc:974 ConstraintGroup::ConstraintGroup
    pub fn new() -> Self { Self { uniqid: 0, maxnum: 0, constraintlist: Vec::new() } }
    // Ghidra: unify.cc:988 ConstraintGroup::addConstraint
    pub fn add_constraint(&mut self, c: Box<dyn UnifyConstraint>) {
        if c.maxnum() > self.maxnum { self.maxnum = c.maxnum(); }
        self.constraintlist.push(c);
    }
    // Ghidra: unify.hh:499 ConstraintGroup::numConstraints
    pub fn num_constraints(&self) -> usize { self.constraintlist.len() }
}

impl UnifyConstraint for ConstraintOr {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1108 ConstraintGroup::setId
    fn assign_ids(&mut self, counter: &mut usize) {
        self.uniqid = *counter; *counter += 1;
        for c in &mut self.constraintlist { c.assign_ids(counter); }
    }
    // Ghidra: unify.cc:1141 ConstraintOr::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        // unify.cc:1141
        let mut res = ConstraintOr::new();
        for c in &self.constraintlist { res.constraintlist.push(c.clone_box()); }
        res.uniqid = self.uniqid; res.maxnum = self.maxnum;
        Box::new(res)
    }
    // Ghidra: unify.cc:1153 ConstraintOr::initialize
    fn initialize(&self, state: &mut UnifyState) {
        // unify.cc:1153
        state.count_initialize(self.uniqid, self.constraintlist.len() as i32);
    }
    // Ghidra: unify.cc:1160 ConstraintOr::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:1160
        let mut stateind = state.count_get_state(self.uniqid);
        if stateind == -1 {
            if !state.count_step(self.uniqid) { return false; }
            stateind = state.count_get_state(self.uniqid);
            self.constraintlist[stateind as usize].initialize(state);
        }
        loop {
            if self.constraintlist[stateind as usize].step(state) { return true; }
            if !state.count_step(self.uniqid) { break; }
            stateind = state.count_get_state(self.uniqid);
            self.constraintlist[stateind as usize].initialize(state);
        }
        false
    }
    // Ghidra: unify.cc:1184 ConstraintOr::buildTraverseState
    fn build_traverse_state(&self, state: &mut UnifyState) {
        // unify.cc:1184
        if self.uniqid != state.num_traverse() { panic!("Traverse id does not match index in or"); }
        state.register_traverse_constraint(TraverseConstraint::Count(TraverseCountState::new(self.uniqid)));
        for c in &self.constraintlist { c.build_traverse_state(state); }
    }
    // Ghidra: unify.hh:521 ConstraintOr::getBaseIndex
    fn get_base_index(&self) -> i32 { -1 }
    // Ghidra: unify.cc:1123 ConstraintGroup::removeDummy
    fn remove_dummy(&mut self) { for c in &mut self.constraintlist { c.remove_dummy(); } }
    // Ghidra: unify.cc:1198 ConstraintOr::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:1198
        let d = p.get_depth();
        p.print_indent(s);
        s.push_str(&format!("for(i{}=0;i{}<{};++i{}) {{\n", d, d, self.constraintlist.len(), d));
        p.inc_depth();
        let n = self.constraintlist.len();
        for (i, c) in self.constraintlist.iter().enumerate() {
            p.print_indent(s);
            if i != 0 { s.push_str("else "); }
            if i != n - 1 { s.push_str(&format!("if (i{} == {}) ", d, i)); }
            s.push_str("{\n");
            let olddepth = p.get_depth();
            p.inc_depth();
            c.print(s, p);
            p.pop_depth(s, olddepth);
        }
    }
}
// -----------------------------------------------------------------------
// Action constraints - they always step once (returning true) and mutate the
// Funcdata. Their `step` requires a live Funcdata in the UnifyState.
// -----------------------------------------------------------------------

/// Mint and insert a new op near an existing one. Faithful to `ConstraintNewOp`
/// (unify.hh:527-540, unify.cc:1219-1267).
#[derive(Debug, Clone)]
pub struct ConstraintNewOp {
    uniqid: usize, maxnum: usize,
    newopindex: usize, oldopindex: usize,
    insertafter: bool, opc: OpCode, numparams: usize,
}
impl ConstraintNewOp {
    // Ghidra: unify.cc:1219 ConstraintNewOp::ConstraintNewOp
    pub fn new(newind: usize, oldind: usize, oc: OpCode, iafter: bool, num: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, newind), oldind), newopindex: newind, oldopindex: oldind, insertafter: iafter, opc: oc, numparams: num }
    }
}
impl UnifyConstraint for ConstraintNewOp {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:535 ConstraintNewOp::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintNewOp::new(self.newopindex, self.oldopindex, self.opc, self.insertafter, self.numparams);
        copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:1230 ConstraintNewOp::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:1230
        if !state.count_step(self.uniqid) { return false; }
        let fd = state.get_function_cloned();
        let oldop = state.data(self.oldopindex).get_op();
        match (fd, oldop) {
            (Some(fd), Some(o)) => {
                let addr = o.read().unwrap().get_addr();
                let oldref = PcodeOpRef(o.clone());
                let newref = fd.write().unwrap().new_op(self.numparams, addr);
                fd.write().unwrap().op_set_opcode(&newref, self.opc);
                if self.insertafter { fd.write().unwrap().op_insert_after(&newref, &oldref); }
                else { fd.write().unwrap().op_insert_before(&newref, &oldref); }
                state.data_mut(self.newopindex).set_op(newref.0);
                true
            }
            _ => false,
        }
    }
    // Ghidra: unify.cc:1246 ConstraintNewOp::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.newopindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.oldopindex] = UnifyDatatype::new(DatatypeKind::OpType);
    }
    // Ghidra: unify.hh:536 ConstraintNewOp::getBaseIndex
    fn get_base_index(&self) -> i32 { self.newopindex as i32 }
    // Ghidra: unify.cc:1253 ConstraintNewOp::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:1253
        p.print_indent(s); s.push_str(&p.get_name(self.newopindex));
        s.push_str(&format!(" = data.newOp({},", self.numparams));
        s.push_str(&p.get_name(self.oldopindex)); s.push_str("->getAddr());\n");
        p.print_indent(s); s.push_str("data.opSetOpcode("); s.push_str(&p.get_name(self.newopindex));
        s.push_str(",CPUI_"); s.push_str(self.opc.name()); s.push_str(");\n");
        s.push_str("data.opInsert"); s.push_str(if self.insertafter { "After(" } else { "Before(" });
        s.push_str(&p.get_name(self.newopindex)); s.push(','); s.push_str(&p.get_name(self.oldopindex)); s.push_str(");\n");
    }
}

/// Mint a fresh unique output varnode for an op. Faithful to
/// `ConstraintNewUniqueOut` (unify.hh:542-553, unify.cc:1269-1316).
#[derive(Debug, Clone)]
pub struct ConstraintNewUniqueOut {
    uniqid: usize, maxnum: usize, opindex: usize, newvarindex: usize, sizevarindex: i32,
}
impl ConstraintNewUniqueOut {
    /// `sizeind < 0` denotes a specific byte size; `>= 0` is a varnode slot
    /// whose size is used. Faithful to the constructor (unify.hh:547,
    /// unify.cc:1269-1278).
    // Ghidra: unify.cc:1269 ConstraintNewUniqueOut::ConstraintNewUniqueOut
    pub fn new(oind: usize, newvarind: usize, sizeind: i32) -> Self {
        let mut m = imax(imax(0, oind), newvarind);
        if sizeind >= 0 { m = imax(m, sizeind as usize); }
        Self { uniqid: 0, maxnum: m, opindex: oind, newvarindex: newvarind, sizevarindex: sizeind }
    }
}
impl UnifyConstraint for ConstraintNewUniqueOut {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:548 ConstraintNewUniqueOut::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintNewUniqueOut::new(self.opindex, self.newvarindex, self.sizevarindex);
        copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:1280 ConstraintNewUniqueOut::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:1280
        if !state.count_step(self.uniqid) { return false; }
        let fd = state.get_function_cloned();
        let op = state.data(self.opindex).get_op();
        match (fd, op) {
            (Some(fd), Some(o)) => {
                let sz = if self.sizevarindex < 0 { (-self.sizevarindex) as usize }
                    else {
                        match state.data(self.sizevarindex as usize).get_varnode() {
                            Some(v) => v.read().unwrap().get_size(), None => return false,
                        }
                    };
                let opref = PcodeOpRef(o.clone());
                let newvn = fd.write().unwrap().new_unique_out(sz, &opref);
                state.data_mut(self.newvarindex).set_varnode(newvn);
                true
            }
            _ => false,
        }
    }
    // Ghidra: unify.cc:1299 ConstraintNewUniqueOut::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.newvarindex] = UnifyDatatype::new(DatatypeKind::VarType);
        if self.sizevarindex >= 0 { t[self.sizevarindex as usize] = UnifyDatatype::new(DatatypeKind::VarType); }
    }
    // Ghidra: unify.hh:549 ConstraintNewUniqueOut::getBaseIndex
    fn get_base_index(&self) -> i32 { self.newvarindex as i32 }
    // Ghidra: unify.cc:1308 ConstraintNewUniqueOut::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:1308
        p.print_indent(s); s.push_str(&p.get_name(self.newvarindex)); s.push_str(" = data.newUniqueOut(");
        if self.sizevarindex < 0 { s.push_str(&(-self.sizevarindex).to_string()); }
        else { s.push_str(&p.get_name(self.sizevarindex as usize)); s.push_str("->getSize()"); }
        s.push(','); s.push_str(&p.get_name(self.opindex)); s.push_str(");\n");
    }
}

/// Set an op input to a bound varnode. Faithful to `ConstraintSetInput`
/// (unify.hh:555-567, unify.cc:1320-1348).
pub struct ConstraintSetInput {
    uniqid: usize, maxnum: usize, opindex: usize,
    slot: Box<dyn RHSConstant>, varindex: usize,
}
impl ConstraintSetInput {
    // Ghidra: unify.hh:560 ConstraintSetInput::ConstraintSetInput
    pub fn new(oind: usize, sl: Box<dyn RHSConstant>, varind: usize) -> Self {
        Self { uniqid: 0, maxnum: imax(imax(0, oind), varind), opindex: oind, slot: sl, varindex: varind }
    }
}
impl Clone for ConstraintSetInput {
    // Ghidra: unify.hh:562 ConstraintSetInput::clone
    fn clone(&self) -> Self { Self { uniqid: self.uniqid, maxnum: self.maxnum, opindex: self.opindex, slot: self.slot.clone_box(), varindex: self.varindex } }
}
impl UnifyConstraint for ConstraintSetInput {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:562 ConstraintSetInput::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintSetInput::new(self.opindex, self.slot.clone_box(), self.varindex);
        copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:1320 ConstraintSetInput::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:1320
        if !state.count_step(self.uniqid) { return false; }
        let fd = state.get_function_cloned();
        let op = state.data(self.opindex).get_op();
        let vn = state.data(self.varindex).get_varnode();
        match (fd, op, vn) {
            (Some(fd), Some(o), Some(v)) => {
                let slt = self.slot.get_constant(state) as usize;
                let opref = PcodeOpRef(o.clone());
                fd.write().unwrap().op_set_input(&opref, v, slt); true
            }
            _ => false,
        }
    }
    // Ghidra: unify.cc:1333 ConstraintSetInput::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) {
        t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType);
        t[self.varindex] = UnifyDatatype::new(DatatypeKind::VarType);
    }
    // Ghidra: unify.hh:563 ConstraintSetInput::getBaseIndex
    fn get_base_index(&self) -> i32 { self.varindex as i32 }
    // Ghidra: unify.cc:1340 ConstraintSetInput::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:1340
        p.print_indent(s); s.push_str("data.opSetInput("); s.push_str(&p.get_name(self.opindex)); s.push(',');
        s.push_str(&p.get_name(self.varindex)); s.push(','); self.slot.write_expression(s, p); s.push_str(");\n");
    }
}

/// Set an op input to a synthesized constant. Faithful to
/// `ConstraintSetInputConstVal` (unify.hh:569-581, unify.cc:1350-1414).
pub struct ConstraintSetInputConstVal {
    uniqid: usize, maxnum: usize, opindex: usize,
    slot: Box<dyn RHSConstant>, val: Box<dyn RHSConstant>, exprsz: Option<Box<dyn RHSConstant>>,
}
impl ConstraintSetInputConstVal {
    // Ghidra: unify.hh:575 ConstraintSetInputConstVal::ConstraintSetInputConstVal
    pub fn new(oind: usize, sl: Box<dyn RHSConstant>, v: Box<dyn RHSConstant>, sz: Option<Box<dyn RHSConstant>>) -> Self {
        Self { uniqid: 0, maxnum: oind, opindex: oind, slot: sl, val: v, exprsz: sz }
    }
}
impl Clone for ConstraintSetInputConstVal {
    // Ghidra: unify.cc:1359 ConstraintSetInputConstVal::clone
    fn clone(&self) -> Self {
        Self {
            uniqid: self.uniqid, maxnum: self.maxnum, opindex: self.opindex,
            slot: self.slot.clone_box(), val: self.val.clone_box(),
            exprsz: self.exprsz.as_ref().map(|e| e.clone_box()),
        }
    }
}
impl UnifyConstraint for ConstraintSetInputConstVal {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.cc:1359 ConstraintSetInputConstVal::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let sz = self.exprsz.as_ref().map(|e| e.clone_box());
        let mut n = ConstraintSetInputConstVal::new(self.opindex, self.slot.clone_box(), self.val.clone_box(), sz);
        copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:1370 ConstraintSetInputConstVal::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:1370
        if !state.count_step(self.uniqid) { return false; }
        let fd = state.get_function_cloned();
        let op = state.data(self.opindex).get_op();
        match (fd, op) {
            (Some(fd), Some(o)) => {
                let mut ourconst = self.val.get_constant(state);
                let sz = match &self.exprsz { Some(e) => e.get_constant(state) as usize, None => 8 };
                let slt = self.slot.get_constant(state) as usize;
                ourconst &= calc_mask(sz);
                let opref = PcodeOpRef(o.clone());
                let cn = fd.write().unwrap().new_constant(sz, ourconst);
                fd.write().unwrap().op_set_input(&opref, cn, slt); true
            }
            _ => false,
        }
    }
    // Ghidra: unify.cc:1388 ConstraintSetInputConstVal::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) { t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType); }
    // Ghidra: unify.cc:1395 ConstraintSetInputConstVal::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:1395
        p.print_indent(s); s.push_str("data.opSetInput("); s.push_str(&p.get_name(self.opindex));
        s.push_str(",data.newConstant(");
        match &self.exprsz { Some(e) => e.write_expression(s, p), None => s.push_str("sizeof(uintb)") }
        s.push(','); self.val.write_expression(s, p); s.push_str("),"); self.slot.write_expression(s, p); s.push_str(");\n");
    }
}

/// Remove an input slot from an op. Faithful to `ConstraintRemoveInput`
/// (unify.hh:583-594, unify.cc:1416-1441).
pub struct ConstraintRemoveInput { uniqid: usize, maxnum: usize, opindex: usize, slot: Box<dyn RHSConstant> }
impl ConstraintRemoveInput {
    // Ghidra: unify.hh:587 ConstraintRemoveInput::ConstraintRemoveInput
    pub fn new(oind: usize, sl: Box<dyn RHSConstant>) -> Self { Self { uniqid: 0, maxnum: oind, opindex: oind, slot: sl } }
}
impl Clone for ConstraintRemoveInput {
    // Ghidra: unify.hh:589 ConstraintRemoveInput::clone
    fn clone(&self) -> Self { Self { uniqid: self.uniqid, maxnum: self.maxnum, opindex: self.opindex, slot: self.slot.clone_box() } }
}
impl UnifyConstraint for ConstraintRemoveInput {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:589 ConstraintRemoveInput::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintRemoveInput::new(self.opindex, self.slot.clone_box());
        copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:1416 ConstraintRemoveInput::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:1416
        if !state.count_step(self.uniqid) { return false; }
        let fd = state.get_function_cloned();
        let op = state.data(self.opindex).get_op();
        match (fd, op) {
            (Some(fd), Some(o)) => {
                let slt = self.slot.get_constant(state) as usize;
                let opref = PcodeOpRef(o.clone());
                fd.read().unwrap().op_remove_input(&opref, slt); true
            }
            _ => false,
        }
    }
    // Ghidra: unify.cc:1428 ConstraintRemoveInput::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) { t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType); }
    // Ghidra: unify.hh:590 ConstraintRemoveInput::getBaseIndex
    fn get_base_index(&self) -> i32 { self.opindex as i32 }
    // Ghidra: unify.cc:1434 ConstraintRemoveInput::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:1434
        p.print_indent(s); s.push_str("data.opRemoveInput("); s.push_str(&p.get_name(self.opindex)); s.push(',');
        self.slot.write_expression(s, p); s.push_str(");\n");
    }
}

/// Rewrite an op's opcode. Faithful to `ConstraintSetOpcode`
/// (unify.hh:596-606, unify.cc:1443-1465).
#[derive(Debug, Clone)]
pub struct ConstraintSetOpcode { uniqid: usize, maxnum: usize, opindex: usize, opc: OpCode }
impl ConstraintSetOpcode {
    // Ghidra: unify.hh:600 ConstraintSetOpcode::ConstraintSetOpcode
    pub fn new(oind: usize, oc: OpCode) -> Self { Self { uniqid: 0, maxnum: oind, opindex: oind, opc: oc } }
}
impl UnifyConstraint for ConstraintSetOpcode {
    // Ghidra: unify.hh:209 UnifyConstraint::getId
    fn uniqid(&self) -> usize { self.uniqid }
    // Ghidra: unify.hh:210 UnifyConstraint::getMaxNum
    fn maxnum(&self) -> usize { self.maxnum }
    // Ghidra: unify.cc:1111 UnifyConstraint::setId
    fn assign_ids(&mut self, c: &mut usize) { self.uniqid = *c; *c += 1; }
    // Ghidra: unify.hh:601 ConstraintSetOpcode::clone
    fn clone_box(&self) -> Box<dyn UnifyConstraint> {
        let mut n = ConstraintSetOpcode::new(self.opindex, self.opc);
        copy_ids(&mut n.uniqid, &mut n.maxnum, self); Box::new(n)
    }
    // Ghidra: unify.cc:1443 ConstraintSetOpcode::step
    fn step(&self, state: &mut UnifyState) -> bool {
        // unify.cc:1443
        if !state.count_step(self.uniqid) { return false; }
        let fd = state.get_function_cloned();
        let op = state.data(self.opindex).get_op();
        match (fd, op) {
            (Some(fd), Some(o)) => {
                let opref = PcodeOpRef(o.clone());
                fd.write().unwrap().op_set_opcode(&opref, self.opc); true
            }
            _ => false,
        }
    }
    // Ghidra: unify.cc:1454 ConstraintSetOpcode::collectTypes
    fn collect_types(&self, t: &mut Vec<UnifyDatatype>) { t[self.opindex] = UnifyDatatype::new(DatatypeKind::OpType); }
    // Ghidra: unify.hh:602 ConstraintSetOpcode::getBaseIndex
    fn get_base_index(&self) -> i32 { self.opindex as i32 }
    // Ghidra: unify.cc:1460 ConstraintSetOpcode::print
    fn print(&self, s: &mut String, p: &mut UnifyCPrinter) {
        // unify.cc:1460
        p.print_indent(s); s.push_str("data.opSetOpcode("); s.push_str(&p.get_name(self.opindex));
        s.push_str(",CPUI_"); s.push_str(self.opc.name()); s.push_str(");\n");
    }
}
// ===========================================================================
// UnifyState (unify.hh:608-625, unify.cc:1467-1500)
// ===========================================================================

/// The live match state. Holds the bound op/varnode/constant/block values
/// (`storemap`), the per-constraint iteration state (`traverselist`), and an
/// optional Funcdata used by action constraints.
///
/// Corresponds to Ghidra's `UnifyState` (unify.hh:608).
pub struct UnifyState {
    storemap: Vec<UnifyDatatype>,
    traverselist: Vec<TraverseConstraint>,
    fd: Option<Arc<RwLock<Funcdata>>>,
}

impl UnifyState {
    /// Build a fresh state for the given constraint group. Sizes the storemap,
    /// fills in slot kinds via `collectTypes`, and registers the traversal
    /// state for every constraint. Faithful to `UnifyState::UnifyState`
    /// (unify.cc:1467-1474).
    // Ghidra: unify.cc:1467 UnifyState::UnifyState
    pub fn new(group: &ConstraintGroup) -> Self {
        // unify.cc:1467
        let maxop = group.maxnum();
        let mut storemap: Vec<UnifyDatatype> = (0..=maxop).map(|_| UnifyDatatype::default()).collect();
        group.collect_types(&mut storemap);
        let mut state = Self { storemap, traverselist: Vec::new(), fd: None };
        group.build_traverse_state(&mut state);
        state
    }

    /// Number of registered traversal states. Faithful to `numTraverse`
    /// (unify.hh:616).
    // Ghidra: unify.hh:616 UnifyState::numTraverse
    pub fn num_traverse(&self) -> usize { self.traverselist.len() }

    /// Append a traversal state. Faithful to `registerTraverseConstraint`
    /// (unify.hh:617).
    // Ghidra: unify.hh:617 UnifyState::registerTraverseConstraint
    pub fn register_traverse_constraint(&mut self, t: TraverseConstraint) { self.traverselist.push(t); }

    /// Borrow a slot value. Faithful to `data(int4)` (unify.hh:618).
    // Ghidra: unify.hh:618 UnifyState::data
    pub fn data(&self, slot: usize) -> &UnifyDatatype { &self.storemap[slot] }

    /// Mutably borrow a slot value (for setters).
    // RUDRA-GLUE: Rust mut accessor for storemap slot; complements UnifyState::data(int4) (unify.hh:618) on the mutable path
    pub fn data_mut(&mut self, slot: usize) -> &mut UnifyDatatype { &mut self.storemap[slot] }

    /// Funcdata accessor (for action constraints). Faithful to `getFunction`
    /// (unify.hh:620).
    // Ghidra: unify.hh:620 UnifyState::getFunction
    pub fn get_function(&self) -> Option<&Arc<RwLock<Funcdata>>> { self.fd.as_ref() }

    /// Clone the Funcdata Arc out of the state.
    // RUDRA-GLUE: Rust Arc-cloning accessor for the Funcdata field; complements getFunction (unify.hh:620)
    pub fn get_function_cloned(&self) -> Option<Arc<RwLock<Funcdata>>> { self.fd.clone() }

    /// Faithful to `setFunction` (unify.hh:622).
    // Ghidra: unify.hh:622 UnifyState::setFunction
    pub fn set_function(&mut self, f: Arc<RwLock<Funcdata>>) { self.fd = Some(f); }

    /// Seed a varnode root. Faithful to `initialize(int4,Varnode*)`
    /// (unify.cc:1490-1494).
    // Ghidra: unify.cc:1490 UnifyState::initialize
    pub fn initialize_vn(&mut self, id: usize, vn: VnArc) {
        // unify.cc:1490
        self.storemap[id].set_varnode(vn);
    }

    /// Seed an op root. Faithful to `initialize(int4,PcodeOp*)`
    /// (unify.cc:1496-1500).
    // Ghidra: unify.cc:1496 UnifyState::initialize
    pub fn initialize_op(&mut self, id: usize, op: OpArc) {
        // unify.cc:1496
        self.storemap[id].set_op(op);
    }

    // Typed traversal accessors (downcast the TraverseConstraint enum).

    // Ghidra: unify.hh:183 TraverseCountState::initialize
    pub fn count_initialize(&mut self, id: usize, end: i32) {
        if let TraverseConstraint::Count(t) = &mut self.traverselist[id] { t.initialize(end); }
    }
    // Ghidra: unify.hh:184 TraverseCountState::step
    pub fn count_step(&mut self, id: usize) -> bool {
        if let TraverseConstraint::Count(t) = &mut self.traverselist[id] { t.step() } else { false }
    }
    // Ghidra: unify.hh:182 TraverseCountState::getState
    pub fn count_get_state(&self, id: usize) -> i32 {
        if let TraverseConstraint::Count(t) = &self.traverselist[id] { t.get_state() } else { -1 }
    }
    // Ghidra: unify.hh:168 TraverseDescendState::initialize
    pub fn descend_initialize(&mut self, id: usize, vn: &Varnode) {
        if let TraverseConstraint::Descend(t) = &mut self.traverselist[id] { t.initialize(vn); }
    }
    // RUDRA-GLUE: Rust helper to reset TraverseDescendState (no direct Ghidra counterpart; Ghidra re-creates iterator)
    pub fn descend_initialize_empty(&mut self, id: usize) {
        if let TraverseConstraint::Descend(t) = &mut self.traverselist[id] {
            t.onestep = false; t.descend_list.clear(); t.index = 0;
        }
    }
    // Ghidra: unify.hh:169 TraverseDescendState::step
    pub fn descend_step(&mut self, id: usize) -> bool {
        if let TraverseConstraint::Descend(t) = &mut self.traverselist[id] { t.step() } else { false }
    }
    // Ghidra: unify.hh:167 TraverseDescendState::getCurrentOp
    pub fn descend_get_current(&self, id: usize) -> OpArc {
        if let TraverseConstraint::Descend(t) = &self.traverselist[id] { t.get_current_op() }
        else { panic!("traverse {} is not Descend", id) }
    }
    // Ghidra: unify.hh:197 TraverseGroupState::getState
    pub fn group_get_state(&self, id: usize) -> i32 {
        if let TraverseConstraint::Group(t) = &self.traverselist[id] { t.get_state() }
        else { panic!("traverse {} is not Group", id) }
    }
    // Ghidra: unify.hh:195 TraverseGroupState::getCurrentIndex
    pub fn group_get_current_index(&self, id: usize) -> i32 {
        if let TraverseConstraint::Group(t) = &self.traverselist[id] { t.get_current_index() }
        else { panic!("traverse {} is not Group", id) }
    }
    // Ghidra: unify.hh:198 TraverseGroupState::setState
    pub fn group_set_state(&mut self, id: usize, st: i32) {
        if let TraverseConstraint::Group(t) = &mut self.traverselist[id] { t.set_state(st); }
    }
    // Ghidra: unify.hh:198 TraverseGroupState::setState
    pub fn group_set(&mut self, id: usize, st: i32, ci: i32) {
        if let TraverseConstraint::Group(t) = &mut self.traverselist[id] { t.set_state(st); t.set_current_index(ci); }
    }
}

// ===========================================================================
// UnifyCPrinter (unify.hh:627-655, unify.cc:1502-1644)
// ===========================================================================

/// Emits a C++ `Rule` from a `ConstraintGroup`. Faithful to `UnifyCPrinter`
/// (unify.hh:627). `printingtype` 0 = standard rule (applyOp returning int),
/// 1 = basic boolean matcher.
pub struct UnifyCPrinter {
    storemap: Vec<UnifyDatatype>,
    namemap: Vec<String>,
    depth: i32,
    printingtype: u8,
    classname: String,
    opparam: i32,
    opcodelist: Vec<OpCode>,
    grp: Option<ConstraintGroup>,
}

impl Default for UnifyCPrinter {
    // RUDRA-GLUE: Rust Default trait impl; Ghidra uses default-constructed UnifyDatatype inline (unify.hh:39)
    fn default() -> Self {
        // unify.hh:640
        Self {
            storemap: Vec::new(), namemap: Vec::new(), depth: 0, printingtype: 0,
            classname: String::new(), opparam: -1, opcodelist: Vec::new(), grp: None,
        }
    }
}

impl UnifyCPrinter {
    // Ghidra: unify.hh:641 UnifyCPrinter::getDepth
    pub fn get_depth(&self) -> i32 { self.depth }
    // Ghidra: unify.hh:642 UnifyCPrinter::incDepth
    pub fn inc_depth(&mut self) { self.depth += 1; }
    // Ghidra: unify.hh:643 UnifyCPrinter::decDepth
    pub fn dec_depth(&mut self) { self.depth -= 1; }
    /// Faithful to `printIndent` (unify.hh:644).
    // Ghidra: unify.hh:644 UnifyCPrinter::printIndent
    pub fn print_indent(&self, s: &mut String) {
        for _ in 0..(self.depth + 1) { s.push_str("  "); }
    }
    /// Emit the abort statement (continue / return 0 / return false).
    /// Faithful to `printAbort` (unify.cc:1544-1559).
    // Ghidra: unify.cc:1544 UnifyCPrinter::printAbort
    pub fn print_abort(&mut self, s: &mut String) {
        // unify.cc:1544
        self.depth += 1;
        self.print_indent(s);
        if self.depth > 1 { s.push_str("continue;"); }
        else if self.printingtype == 0 { s.push_str("return 0;"); }
        else { s.push_str("return false;"); }
        self.depth -= 1;
        s.push('\n');
    }
    /// Close nested blocks until `depth == newdepth`. Faithful to `popDepth`
    /// (unify.cc:1561-1569).
    // Ghidra: unify.cc:1561 UnifyCPrinter::popDepth
    pub fn pop_depth(&mut self, s: &mut String, newdepth: i32) {
        // unify.cc:1561
        while self.depth != newdepth {
            self.depth -= 1;
            self.print_indent(s);
            s.push_str("}\n");
        }
    }
    /// Faithful to `getName` (unify.hh:647).
    // Ghidra: unify.hh:647 UnifyCPrinter::getName
    pub fn get_name(&self, id: usize) -> String { self.namemap[id].clone() }
    /// Faithful to `setClassName` (unify.hh:650).
    // Ghidra: unify.hh:650 UnifyCPrinter::setClassName
    pub fn set_classname(&mut self, nm: &str) { self.classname = nm.to_string(); }

    /// Faithful to `initializeBase` (unify.cc:1502-1521).
    // Ghidra: unify.cc:1502 UnifyCPrinter::initializeBase
    fn initialize_base(&mut self, g: ConstraintGroup) {
        // unify.cc:1502
        self.depth = 0;
        self.namemap.clear();
        self.storemap.clear();
        self.opparam = -1;
        self.opcodelist.clear();
        let maxop = g.maxnum();
        self.storemap = (0..=maxop).map(|_| UnifyDatatype::default()).collect();
        g.collect_types(&mut self.storemap);
        for i in 0..=maxop {
            self.namemap.push(format!("{}{}", self.storemap[i].get_type().base_name(), i));
        }
        self.grp = Some(g);
    }
    /// Faithful to `printGetOpList` (unify.cc:1523-1534).
    // Ghidra: unify.cc:1523 UnifyCPrinter::printGetOpList
    fn print_get_op_list(&self, s: &mut String) {
        // unify.cc:1523
        s.push_str(&format!("void {}::getOpList(vector<uint4> &oplist) const\n\n{{\n", self.classname));
        for &oc in &self.opcodelist { s.push_str(&format!("  oplist.push_back(CPUI_{});\n", oc.name())); }
        s.push_str("}\n\n");
    }
    /// Faithful to `printRuleHeader` (unify.cc:1536-1542).
    // Ghidra: unify.cc:1536 UnifyCPrinter::printRuleHeader
    fn print_rule_header(&self, s: &mut String) {
        // unify.cc:1536
        s.push_str(&format!(
            "int {}::applyOp(PcodeOp *{},Funcdata &data)\n\n{{\n",
            self.classname, self.namemap[self.opparam as usize]
        ));
    }
    /// Faithful to `printVarDecls` (unify.cc:1571-1580).
    // Ghidra: unify.cc:1571 UnifyCPrinter::printVarDecls
    fn print_var_decls(&self, s: &mut String) {
        // unify.cc:1571
        for i in 0..self.namemap.len() {
            if i as i32 == self.opparam { continue; }
            self.storemap[i].print_var_decl(s, i, self);
        }
        if !self.namemap.is_empty() { s.push('\n'); }
    }
    /// Faithful to `initializeRuleAction` (unify.cc:1582-1591).
    // Ghidra: unify.cc:1582 UnifyCPrinter::initializeRuleAction
    pub fn initialize_rule_action(&mut self, g: ConstraintGroup, opp: i32, oplist: Vec<OpCode>) {
        // unify.cc:1582
        self.initialize_base(g);
        self.printingtype = 0;
        self.classname = "DummyRule".to_string();
        self.opparam = opp;
        self.opcodelist = oplist;
    }
    /// Faithful to `initializeBasic` (unify.cc:1593-1599).
    // Ghidra: unify.cc:1593 UnifyCPrinter::initializeBasic
    pub fn initialize_basic(&mut self, g: ConstraintGroup) {
        // unify.cc:1593
        self.initialize_base(g);
        self.printingtype = 1;
        self.opparam = -1;
    }
    /// Faithful to `addNames` (unify.hh:651, unify.cc:1601-1612).
    // Ghidra: unify.cc:1601 UnifyCPrinter::addNames
    pub fn add_names(&mut self, nmmap: &[(String, usize)]) {
        // unify.cc:1601
        for (name, slot) in nmmap {
            if self.namemap.len() <= *slot { panic!("Name indices do not match constraint"); }
            self.namemap[*slot] = name.clone();
        }
    }
    /// Faithful to `print` (unify.cc:1614-1644). Produces the full rule body.
    // Ghidra: unify.cc:1614 UnifyCPrinter::print
    pub fn print(&mut self, s: &mut String) {
        // unify.cc:1614
        if self.printingtype == 0 {
            self.print_get_op_list(s);
            s.push('\n');
            self.print_rule_header(s);
            self.print_var_decls(s);
            if let Some(grp) = &self.grp { grp.clone_box().print(s, self); }
            self.print_indent(s); s.push_str("return 1;\n");
            if self.depth != 0 {
                self.pop_depth(s, 0);
                self.print_indent(s); s.push_str("return 0;\n");
            }
            s.push_str("}\n");
        } else if self.printingtype == 1 {
            self.print_var_decls(s);
            if let Some(grp) = &self.grp { grp.clone_box().print(s, self); }
            self.print_indent(s); s.push_str("return true;\n");
            if self.depth != 0 {
                self.pop_depth(s, 0);
                self.print_indent(s); s.push_str("return false;\n");
            }
            s.push_str("}\n");
        }
    }
}

// ===========================================================================
// RuleMatcher - thin driver (Ghidra itself drives the engine inline in
// rulecompile.cc; we expose a small driver here so the engine is usable and
// testable directly). This is the "RuleMatcher" concept referenced by the
// task spec; Ghidra has no class by this name.
// ===========================================================================

/// Driver that runs a `ConstraintGroup` against a root PcodeOp, enumerating
/// every satisfying binding.
pub struct RuleMatcher { group: ConstraintGroup }

impl RuleMatcher {
    /// Build a matcher from a constraint tree. `assign_ids` is applied here.
    // RUDRA-GLUE: Rust constructor for RuleMatcher; Ghidra uses inline constructor
    pub fn new(mut group: ConstraintGroup) -> Self { group.assign_ids(); Self { group } }

    /// Borrow the underlying group.
    // RUDRA-GLUE: Rust convenience method on RuleMatcher; Ghidra has no RuleMatcher class (drives inline)
    pub fn group(&self) -> &ConstraintGroup { &self.group }

    /// Run the matcher with `op` bound to slot `root_slot`. Returns whether at
    /// least one match exists.
    // RUDRA-GLUE: Rust convenience method on RuleMatcher; Ghidra has no RuleMatcher class (drives inline)
    pub fn matches(&self, root_slot: usize, op: OpArc) -> bool {
        let mut state = UnifyState::new(&self.group);
        state.initialize_op(root_slot, op);
        self.group.step(&mut state)
    }

    /// Enumerate up to `limit` distinct matches, calling `f` for each. The
    /// callback receives the state immediately after a match (so bound slots
    /// are readable). Stops early if `f` returns false.
    // RUDRA-GLUE: Rust convenience method on RuleMatcher; Ghidra has no RuleMatcher class (drives inline)
    pub fn enumerate<F: FnMut(&UnifyState) -> bool>(
        &self, root_slot: usize, op: OpArc, limit: usize, mut f: F,
    ) -> usize {
        let mut state = UnifyState::new(&self.group);
        state.initialize_op(root_slot, op);
        let mut count = 0usize;
        while count < limit && self.group.step(&mut state) {
            count += 1;
            if !f(&state) { break; }
        }
        count
    }
}
// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, SeqNum};

    /// Build a `PcodeOp` (uninserted) with the given opcode, inputs, output.
    fn make_op(opcode: OpCode, inputs: &[VnArc], output: Option<VnArc>) -> OpArc {
        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x10), 0), opcode);
        for vn in inputs { op.inrefs.push(vn.clone()); }
        op.output = output;
        Arc::new(RwLock::new(op))
    }

    #[test]
    fn test_unify_datatype_slot_lifecycle() {
        let mut slot = UnifyDatatype::new(DatatypeKind::ConstType);
        assert_eq!(slot.get_type(), DatatypeKind::ConstType);
        slot.set_constant(42);
        assert_eq!(slot.get_constant(), 42);
        slot.set_constant(99);
        assert_eq!(slot.get_constant(), 99);

        let mut op_slot = UnifyDatatype::new(DatatypeKind::OpType);
        assert!(op_slot.get_op().is_none());
        op_slot.set_varnode(Arc::new(RwLock::new(Varnode::new_unique(0x100, 8))));
        assert!(op_slot.get_varnode().is_some());
    }

    #[test]
    fn test_rhs_constant_named_and_absolute() {
        // Bind slot 0 = 7 via NamedExpression, then read it back via
        // ConstantNamed. Absolute returns its literal value.
        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintNamedExpression::new(0, Box::new(ConstantAbsolute::new(7)))));
        grp.assign_ids();
        let mut state = UnifyState::new(&grp);
        assert!(grp.step(&mut state));
        assert_eq!(ConstantNamed::new(0).get_constant(&state), 7);
        assert_eq!(ConstantAbsolute::new(123).get_constant(&state), 123);
    }

    #[test]
    fn test_constraint_opcode_match_and_miss() {
        // Op slot 0 must be INT_ADD; matches an INT_ADD op, rejects COPY.
        let add = make_op(OpCode::CPUI_INT_ADD, &[], None);
        let copy = make_op(OpCode::CPUI_COPY, &[], None);

        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintOpcode::new(0, vec![OpCode::CPUI_INT_ADD])));
        grp.assign_ids();

        let mut s1 = UnifyState::new(&grp);
        s1.initialize_op(0, add);
        assert!(grp.step(&mut s1));

        let mut s2 = UnifyState::new(&grp);
        s2.initialize_op(0, copy);
        assert!(!grp.step(&mut s2));
    }

    #[test]
    fn test_op_input_output_binding() {
        // Group: opcode INT_ADD, bind input[0] -> vn slot 1, output -> slot 2.
        let in0 = Arc::new(RwLock::new(Varnode::new_unique(0x10, 8)));
        let in1 = Arc::new(RwLock::new(Varnode::new_unique(0x20, 8)));
        let out = Arc::new(RwLock::new(Varnode::new_unique(0x30, 8)));
        let add = make_op(OpCode::CPUI_INT_ADD, &[in0.clone(), in1], Some(out.clone()));

        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintOpcode::new(0, vec![OpCode::CPUI_INT_ADD])));
        grp.add_constraint(Box::new(ConstraintOpInput::new(0, 1, 0)));
        grp.add_constraint(Box::new(ConstraintOpOutput::new(0, 2)));
        grp.assign_ids();

        let mut state = UnifyState::new(&grp);
        state.initialize_op(0, add);
        assert!(grp.step(&mut state));
        let bound_in = state.data(1).get_varnode().expect("input bound");
        assert!(Arc::ptr_eq(&bound_in, &in0));
        let bound_out = state.data(2).get_varnode().expect("output bound");
        assert!(Arc::ptr_eq(&bound_out, &out));
    }

    #[test]
    fn test_equal_constraint_on_two_inputs() {
        // INT_ADD with input[0] != input[1]: matches when distinct, fails
        // when both inputs are the same varnode.
        let in_a = Arc::new(RwLock::new(Varnode::new_unique(0x10, 8)));
        let in_b = Arc::new(RwLock::new(Varnode::new_unique(0x20, 8)));
        let add_ab = make_op(OpCode::CPUI_INT_ADD, &[in_a.clone(), in_b.clone()], None);
        let add_aa = make_op(OpCode::CPUI_INT_ADD, &[in_a.clone(), in_a.clone()], None);

        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintOpcode::new(0, vec![OpCode::CPUI_INT_ADD])));
        grp.add_constraint(Box::new(ConstraintOpInput::new(0, 1, 0)));
        grp.add_constraint(Box::new(ConstraintOpInput::new(0, 2, 1)));
        grp.add_constraint(Box::new(ConstraintVarCompare::new(1, 2, false))); // !=
        grp.assign_ids();

        let mut s_ab = UnifyState::new(&grp);
        s_ab.initialize_op(0, add_ab);
        assert!(grp.step(&mut s_ab), "distinct inputs must satisfy v1 != v2");

        let mut s_aa = UnifyState::new(&grp);
        s_aa.initialize_op(0, add_aa);
        assert!(!grp.step(&mut s_aa), "identical inputs must fail v1 != v2");
    }

    #[test]
    fn test_op_input_any_enumerates_all_inputs() {
        // ConstraintOpInputAny should produce one match per input.
        let in0 = Arc::new(RwLock::new(Varnode::new_unique(0x10, 8)));
        let in1 = Arc::new(RwLock::new(Varnode::new_unique(0x20, 8)));
        let in2 = Arc::new(RwLock::new(Varnode::new_unique(0x30, 8)));
        let op = make_op(OpCode::CPUI_STORE, &[in0, in1, in2], None);

        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintOpInputAny::new(0, 1)));
        let matcher = RuleMatcher::new(grp);
        let n = matcher.enumerate(0, op, 100, |_| true);
        assert_eq!(n, 3, "OpInputAny should enumerate exactly 3 inputs");
    }

    #[test]
    fn test_param_const_val_and_param_const() {
        // ParamConstVal requires input[1] == 42; ParamConst binds it to slot 1.
        let c42 = Arc::new(RwLock::new(Varnode::new_constant(42, 4)));
        let c99 = Arc::new(RwLock::new(Varnode::new_constant(99, 4)));
        let nonconst = Arc::new(RwLock::new(Varnode::new_unique(0x10, 8)));
        let op_ok = make_op(OpCode::CPUI_INT_ADD, &[nonconst.clone(), c42.clone()], None);
        let op_bad = make_op(OpCode::CPUI_INT_ADD, &[nonconst.clone(), c99.clone()], None);

        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintParamConstVal::new(0, 1, 42)));
        grp.add_constraint(Box::new(ConstraintParamConst::new(0, 1, 1)));
        grp.assign_ids();

        let mut s_ok = UnifyState::new(&grp);
        s_ok.initialize_op(0, op_ok);
        assert!(grp.step(&mut s_ok));
        assert_eq!(s_ok.data(1).get_constant(), 42);

        let mut s_bad = UnifyState::new(&grp);
        s_bad.initialize_op(0, op_bad);
        assert!(!grp.step(&mut s_bad));
    }

    #[test]
    fn test_const_compare_constraint() {
        // Bind two constants, then compare equal / not-equal.
        let mut grp_eq = ConstraintGroup::new();
        grp_eq.add_constraint(Box::new(ConstraintNamedExpression::new(0, Box::new(ConstantAbsolute::new(5)))));
        grp_eq.add_constraint(Box::new(ConstraintNamedExpression::new(1, Box::new(ConstantAbsolute::new(5)))));
        grp_eq.add_constraint(Box::new(ConstraintConstCompare::new(0, 1, OpCode::CPUI_INT_EQUAL)));
        grp_eq.assign_ids();
        let mut s = UnifyState::new(&grp_eq);
        assert!(grp_eq.step(&mut s), "5 == 5 must satisfy INT_EQUAL");

        let mut grp_ne = ConstraintGroup::new();
        grp_ne.add_constraint(Box::new(ConstraintNamedExpression::new(0, Box::new(ConstantAbsolute::new(5)))));
        grp_ne.add_constraint(Box::new(ConstraintNamedExpression::new(1, Box::new(ConstantAbsolute::new(9)))));
        grp_ne.add_constraint(Box::new(ConstraintConstCompare::new(0, 1, OpCode::CPUI_INT_EQUAL)));
        grp_ne.assign_ids();
        let mut s2 = UnifyState::new(&grp_ne);
        assert!(!grp_ne.step(&mut s2), "5 != 9 must fail INT_EQUAL");
    }

    #[test]
    fn test_constraint_boolean() {
        // ConstraintBoolean(true) requires RHS != 0.
        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintNamedExpression::new(0, Box::new(ConstantAbsolute::new(1)))));
        grp.add_constraint(Box::new(ConstraintBoolean::new(true, Box::new(ConstantNamed::new(0)))));
        grp.assign_ids();
        let mut s = UnifyState::new(&grp);
        assert!(grp.step(&mut s));

        let mut grp2 = ConstraintGroup::new();
        grp2.add_constraint(Box::new(ConstraintNamedExpression::new(0, Box::new(ConstantAbsolute::new(0)))));
        grp2.add_constraint(Box::new(ConstraintBoolean::new(true, Box::new(ConstantNamed::new(0)))));
        grp2.assign_ids();
        let mut s2 = UnifyState::new(&grp2);
        assert!(!grp2.step(&mut s2));
    }

    #[test]
    fn test_constraint_or_disjunction() {
        // Or(Opcode INT_ADD | Opcode INT_SUB) - matches either.
        let add = make_op(OpCode::CPUI_INT_ADD, &[], None);
        let sub = make_op(OpCode::CPUI_INT_SUB, &[], None);
        let copy = make_op(OpCode::CPUI_COPY, &[], None);

        let mut branch_a = ConstraintGroup::new();
        branch_a.add_constraint(Box::new(ConstraintOpcode::new(0, vec![OpCode::CPUI_INT_ADD])));
        let mut branch_b = ConstraintGroup::new();
        branch_b.add_constraint(Box::new(ConstraintOpcode::new(0, vec![OpCode::CPUI_INT_SUB])));

        let mut or = ConstraintOr::new();
        or.add_constraint(Box::new(branch_a));
        or.add_constraint(Box::new(branch_b));
        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(or));
        grp.assign_ids();

        for (op, expect) in [(add, true), (sub, true), (copy, false)] {
            let mut s = UnifyState::new(&grp);
            s.initialize_op(0, op);
            assert_eq!(grp.step(&mut s), expect);
        }
    }

    #[test]
    fn test_rule_matcher_driver() {
        // End-to-end: a small RuleMatcher with opcode + two input bindings.
        let in0 = Arc::new(RwLock::new(Varnode::new_unique(0x10, 8)));
        let in1 = Arc::new(RwLock::new(Varnode::new_unique(0x20, 8)));
        let add = make_op(OpCode::CPUI_INT_ADD, &[in0.clone(), in1.clone()], None);

        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintOpcode::new(0, vec![OpCode::CPUI_INT_ADD])));
        grp.add_constraint(Box::new(ConstraintOpInput::new(0, 1, 0)));
        grp.add_constraint(Box::new(ConstraintOpInput::new(0, 2, 1)));
        let matcher = RuleMatcher::new(grp);

        assert!(matcher.matches(0, add));
    }

    #[test]
    fn test_dummy_constraints_reserve_slots() {
        // Dummy constraints always match but reserve their slot kind.
        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(DummyOpConstraint::new(0)));
        grp.add_constraint(Box::new(DummyVarnodeConstraint::new(1)));
        grp.add_constraint(Box::new(DummyConstConstraint::new(2)));
        grp.assign_ids();
        let state = UnifyState::new(&grp);
        assert_eq!(state.data(0).get_type(), DatatypeKind::OpType);
        assert_eq!(state.data(1).get_type(), DatatypeKind::VarType);
        assert_eq!(state.data(2).get_type(), DatatypeKind::ConstType);
    }

    #[test]
    fn test_remove_dummy_strips_placeholders() {
        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(DummyOpConstraint::new(0)));
        grp.add_constraint(Box::new(ConstraintOpcode::new(1, vec![OpCode::CPUI_COPY])));
        assert_eq!(grp.num_constraints(), 2);
        grp.remove_dummy();
        assert_eq!(grp.num_constraints(), 1, "DummyOpConstraint should be stripped");
    }

    #[test]
    fn test_cprinter_emits_rule_body() {
        // A minimal rule: opcode check + output binding. The printer must
        // produce text containing "getOpList" and "applyOp".
        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintOpcode::new(0, vec![OpCode::CPUI_INT_ADD])));
        grp.add_constraint(Box::new(ConstraintOpOutput::new(0, 1)));
        grp.assign_ids();

        let mut printer = UnifyCPrinter::default();
        printer.initialize_rule_action(grp, 0, vec![OpCode::CPUI_INT_ADD]);
        printer.set_classname("AddRule");
        let mut out = String::new();
        printer.print(&mut out);
        assert!(out.contains("AddRule::getOpList"), "missing getOpList: {}", out);
        assert!(out.contains("AddRule::applyOp"), "missing applyOp: {}", out);
        assert!(out.contains("CPUI_INT_ADD"), "missing opcode literal: {}", out);
    }

    #[test]
    fn test_clone_preserves_ids_and_shape() {
        // Cloning a constraint tree must preserve uniqid/maxnum (copyid).
        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintOpcode::new(0, vec![OpCode::CPUI_INT_ADD])));
        grp.add_constraint(Box::new(ConstraintOpInput::new(0, 1, 0)));
        grp.assign_ids();
        let cloned = grp.clone_box();
        assert_eq!(cloned.uniqid(), grp.uniqid());
        assert_eq!(cloned.maxnum(), grp.maxnum());
    }

    #[test]
    fn test_varnode_copy_and_varnode_size_rhs() {
        // Bind a varnode, copy it to a second slot, then read its size.
        let vn = Arc::new(RwLock::new(Varnode::new_unique(0x10, 4)));
        let mut grp = ConstraintGroup::new();
        grp.add_constraint(Box::new(ConstraintVarnodeCopy::new(0, 1)));
        grp.assign_ids();
        let mut state = UnifyState::new(&grp);
        state.initialize_vn(0, vn);
        assert!(grp.step(&mut state));
        // ConstantVarnodeSize reads slot 1's size.
        assert_eq!(ConstantVarnodeSize::new(1).get_constant(&state), 4);
        assert_eq!(ConstantOffset::new(1).get_constant(&state), 0x10);
    }
}

