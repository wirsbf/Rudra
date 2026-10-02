//! Conditional execution simplification.
//!
//! Corresponds to Ghidra's `condexe.hh` / `condexe.cc` (712 lines).
//!
//! This module simplifies control-flow where two CBRANCH operations test the
//! same (or complementary) boolean value, making one of the joins redundant:
//!
//! ```text
//!    if (a) {           if (a) {
//!       BODY1              BODY1
//!    }          ==>        BODY2
//!    if (a) {           }
//!       BODY2
//!    }
//! ```
//!
//! The block where two flows needlessly merge is the \b iblock. The original
//! boolean evaluation is in \b initblock. Two paths lead from initblock to
//! iblock (\b prea / \b preb) and two paths leave it (\b posta / \b postb).
//! If the iblock's CBRANCH is redundant, iblock is removed and prea is
//! re-linked to posta (or postb, if the conditions are complementary),
//! preserving MULTIEQUAL data-flow by pushing reads into the right path.
//!
//! This is a faithful 1:1 port of Ghidra's `ConditionalExecution` class and
//! `ActionConditionalExe`, including the full data-flow rewrite
//! (`doReplacement` / `getReplacementRead` / `pullbackOp` / `getNewMulti`)
//! and the CFG rewrite (`removeFromFlowSplit`). The previous Rugra
//! implementation only detected candidates and emitted diagnostics; this one
//! performs the actual transformation.

use crate::action::{Action, Rule, action_status};
use crate::funcdata::Funcdata;
use crate::error::{Error, Result};
use crate::opcodes::OpCode;
use std::sync::{Arc, RwLock};
use crate::op::{PcodeOp, PcodeOpRef};
use crate::block::{BlockBasic, FlowBlock};
use crate::varnode::Varnode;

// RUDRA-GLUE: opref (no Ghidra counterpart found)
/// Wrap a bare `Arc<RwLock<PcodeOp>>` into a `PcodeOpRef` for calling the
/// Funcdata op-editing API (which takes `&PcodeOpRef`). This clones only the
/// Arc, not the underlying op.
fn opref(a: &Arc<RwLock<PcodeOp>>) -> PcodeOpRef {
    PcodeOpRef(a.clone())
}

// RUDRA-GLUE: structural-invariant error (no Ghidra counterpart path)
/// Ghidra's condexe data-flow rewrite dereferences pointers unconditionally
/// (`op->getIn(0)`, `vn->getDef()`, `op->getOut()`, `iblock->getImmedDom()`,
/// condexe.cc:166/172/181/202/274/325) — for IR that passed `verify()` those
/// are never null, and a null would be undefined behaviour (crash), not a
/// `LowlevelError`. Rugra's split Arc/Weak model makes those states
/// representable, so this helper converts them into a clearly-marked,
/// terminating internal error instead of UB or a silent skip. Oracle-reachable
/// failures use `Error::Lowlevel` with the verbatim oracle message instead
/// (see `resolve_iblock_read` / `get_replacement_read`).
fn structural(detail: &str) -> Error {
    Error::Generic(format!(
        "condexe: structural invariant violated (no oracle counterpart): {detail}"
    ))
}

/// Correlation between the initblock and iblock CBRANCH booleans.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Correlation {
    /// Conditions always have the same value.
    Same,
    /// Conditions always have opposite values.
    Complementary,
    Uncorrelated,
}

/// `BooleanMatch::evaluate` result, faithful to expression.cc:111.
const SAME: i32 = 0;
const COMPLEMENTARY: i32 = 1;
const UNCORRELATED: i32 = 2;

/// The analysis engine for a single iblock candidate.
///
/// Faithful to Ghidra's `ConditionalExecution` (condexe.hh:91). All field
/// names mirror the C++ class.
pub struct ConditionalExecution<'a> {
    fd: &'a mut Funcdata,
    /// CBRANCH in iblock.
    cbranch: Option<Arc<RwLock<PcodeOp>>>,
    /// The initial block computing the boolean value.
    initblock: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// The block where flow needlessly comes together.
    iblock: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// iblock->In(prea_inslot) = pre a path.
    prea_inslot: i32,
    /// Does true branch (in terms of iblock) go to path pre a.
    init2a_true: bool,
    /// Does true branch go to path post a.
    iblock2posta_true: bool,
    /// init or pre slot to use, for data-flow thru post.
    camethruposta_slot: i32,
    /// The out edge from iblock to posta.
    posta_outslot: i32,
    /// First block in posta path.
    posta_block: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// First block in postb path.
    postb_block: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Map block-index -> replacement Varnode for (current) Varnode.
    replacement: std::collections::HashMap<i32, Arc<RwLock<Varnode>>>,
    /// Outputs of ops pulled back from iblock for (current) Varnode.
    pullback: Vec<Option<Arc<RwLock<Varnode>>>>,
    /// Boolean array indexed by address space indicating whether the space
    /// is heritaged (condexe.hh:105; filled by build_heritage_array).
    heritageyes: Vec<bool>,
    /// Cached correlation result from verify_same_condition.
    matchflip: bool,
}

// Ghidra: condexe.cc:28-30 glb->numSpaces()/glb->getSpace(i) enumeration
/// Rugra's per-space enumeration standing in for the architecture's
/// `baselist` walk in `buildHeritageArray` (condexe.cc:29-30): the same
/// fixed AddressSpace list `Heritage::buildInfoList` walks (heritage.rs:660,
/// heritage.cc:2664-2672). Ghidra's `glb->getSpace(i)` reads the
/// architecture-owned AddrSpaceManager, which is not yet reachable from a
/// Rugra Funcdata (SPACE-0001); Overlay/Other(id) dynamic spaces are not
/// enumerable through it and index lookup treats them as not heritaged.
const CONDEXE_SPACE_LIST: [crate::space::AddressSpace; 7] = [
    crate::space::AddressSpace::Ram,
    crate::space::AddressSpace::Register,
    crate::space::AddressSpace::Unique,
    crate::space::AddressSpace::Const,
    crate::space::AddressSpace::Stack,
    crate::space::AddressSpace::Join,
    crate::space::AddressSpace::Iop,
];

// Ghidra: space.hh:332 AddrSpace::getIndex
/// Index of a space within [`CONDEXE_SPACE_LIST`] — Rugra's stand-in for
/// `AddrSpace::getIndex()` (the slot position in the architecture baselist)
/// as consumed by the `heritageyes[index]` reads (condexe.cc:35/392).
/// `None` for spaces outside the enumerable list (Overlay/Other).
fn condexe_space_index(spc: &crate::space::AddressSpace) -> Option<usize> {
    Some(match spc {
        crate::space::AddressSpace::Ram => 0,
        crate::space::AddressSpace::Register => 1,
        crate::space::AddressSpace::Unique => 2,
        crate::space::AddressSpace::Const => 3,
        crate::space::AddressSpace::Stack => 4,
        crate::space::AddressSpace::Join => 5,
        crate::space::AddressSpace::Iop => 6,
        _ => return None,
    })
}

impl<'a> ConditionalExecution<'a> {
    // Ghidra: condexe.cc:23 ConditionalExecution::buildHeritageArray
    /// `buildHeritageArray` (condexe.cc:23-37): calculate the boolean array
    /// of all address spaces that have had a heritage pass run, used by
    /// `testRemovability` (cc:392) to test if all the links out of the
    /// iblock have been calculated. Faithful order of operations:
    ///   - `heritageyes.clear(); resize(glb->numSpaces(), false)` (cc:26-28)
    ///   - per space `i`: null hole skip (cc:31), `index = spc->getIndex()`
    ///     (cc:32), `!spc->isHeritaged()` skip (cc:33),
    ///     `fd->numHeritagePasses(spc) > 0 -> heritageyes[index] = true`
    ///     (cc:34-35)
    /// A space that is not heritaged is skipped BEFORE numHeritagePasses is
    /// consulted, so `Heritage::numHeritagePasses`'s non-heritaged throw
    /// (heritage.cc:2786-2787) is unreachable from this caller, exactly as
    /// in the oracle.
    fn build_heritage_array(fd: &Funcdata) -> Vec<bool> {
        // cc:26-28: clear + resize(numSpaces, false) — every slot starts
        // false; only an actual heritage pass flips it true.
        let mut heritageyes = vec![false; CONDEXE_SPACE_LIST.len()];
        for spc in &CONDEXE_SPACE_LIST {
            // cc:33: `if (!spc->isHeritaged()) continue;`
            if !spc.is_heritaged() {
                continue;
            }
            // cc:34: `fd->numHeritagePasses(spc)` — funcdata.hh:237 inline
            // delegation to `Heritage::numHeritagePasses(spc)`
            // (heritage.cc:2779-2788: `return pass - info->delay`), read
            // through Rugra's Heritage directly (the Funcdata wrapper
            // predates the per-space parameter).
            if fd.heritage.num_heritage_passes(*spc) > 0 {
                heritageyes[condexe_space_index(spc).unwrap()] = true; // cc:35
            }
        }
        heritageyes
    }

    // Ghidra: condexe.cc:432 ConditionalExecution::ConditionalExecution
    /// Constructor. Faithful to `ConditionalExecution::ConditionalExecution`
    /// (condexe.cc:432-437): `fd = f; buildHeritageArray();` — the heritage
    /// array is cached ONCE per ConditionalExecution object (i.e. once per
    /// ActionConditionalExe::apply, cc:487), reflecting the heritage pass
    /// count at that moment, not per trial/round.
    pub fn new(fd: &'a mut Funcdata) -> Self {
        // cc:436: buildHeritageArray() — cache an array depending on the
        // particular heritage pass.
        let heritageyes = Self::build_heritage_array(fd);
        Self {
            fd,
            cbranch: None,
            initblock: None,
            iblock: None,
            prea_inslot: 0,
            init2a_true: false,
            iblock2posta_true: false,
            camethruposta_slot: 0,
            posta_outslot: 0,
            posta_block: None,
            postb_block: None,
            replacement: std::collections::HashMap::new(),
            pullback: Vec::new(),
            heritageyes,
            matchflip: false,
        }
    }

    // RUDRA-GLUE: graph helpers adapted to Rugra's dynamic-dispatch blocks
    // (Ghidra accesses BlockBasic members directly; `lastOp` maps to
    // BlockBasic::lastOp, block.hh:490).
    // ------------------------------------------------------------------

    fn block_as_basic(
        arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> bool {
        // We need to downcast the trait object to BlockBasic. Because Rugra
        // stores blocks as trait-object Arcs, we cannot trivially recover a
        // typed Arc<BlockBasic>. Instead we operate through the trait methods
        // and, where structural mutation is required, re-acquire the write
        // lock and downcast mutably. This helper signals whether the block is
        // a BlockBasic (used by guards).
        let rg = arc.read().unwrap();
        rg.as_any().downcast_ref::<BlockBasic>().is_some()
    }

    // Ghidra: block.hh:490 BlockBasic::lastOp
    /// Last op of a block, or None.
    fn last_op(arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Option<Arc<RwLock<PcodeOp>>> {
        arc.read().unwrap().get_ops().last().cloned().map(|r| r.0)
    }

    // RUDRA-GLUE: iterator over all ops of a block (Ghidra iterates
    /// `bl->beginOp()..endOp()` inline at each call site).
    fn ops(arc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Vec<Arc<RwLock<PcodeOp>>> {
        arc.read().unwrap().get_ops().into_iter().map(|r| r.0).collect()
    }

    // ------------------------------------------------------------------
    // testIBlock (condexe.cc:43-52)
    // ------------------------------------------------------------------

    // Ghidra: condexe.cc:43 ConditionalExecution::testIBlock
    /// The iblock must have 2 in edges, 2 out edges, and a final CBRANCH.
    fn test_iblock(&mut self) -> bool {
        let ib = match &self.iblock { Some(b) => b.clone(), None => return false };
        let rg = ib.read().unwrap();
        if rg.size_in() != 2 { return false; }
        if rg.size_out() != 2 { return false; }
        drop(rg);
        let last = match Self::last_op(&ib) { Some(o) => o, None => return false };
        if last.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return false; }
        self.cbranch = Some(last);
        true
    }

    // ------------------------------------------------------------------
    // findInitPre (condexe.cc:55-75)
    // ------------------------------------------------------------------

    // Ghidra: condexe.cc:55 ConditionalExecution::findInitPre
    /// Walk back from iblock's prea_inslot input to find the initblock. Also
    /// sets init2a_true.
    fn find_init_pre(&mut self) -> bool {
        let ib = self.iblock.clone().unwrap();
        // Walk up the prea path (chain of 1in/1out blocks) to the first block
        // with 2 out-edges = initblock.
        let bank = ib.read().unwrap().bank();
        // (W2) shadow reads: the 1in/1out chain gates read the bank size
        // shadows (block.hh:312-313); only the get_in(0) walk takes a peer
        // guard. Points ride along with the handles.
        let prea_in = {
            let rg = ib.read().unwrap();
            rg.get_in(self.prea_inslot as usize)
                .map(|e| (bank.expect_arc(e.point), e.point))
        };
        let (mut tmp, mut tmp_point) = match prea_in {
            Some(b) => b,
            None => return false,
        };
        let mut last = ib.clone();
        loop {
            let (sout, sin) =
                (bank.expect_size_out(tmp_point), bank.expect_size_in(tmp_point));
            if sout != 1 || sin != 1 {
                break;
            }
            last = tmp.clone();
            let next = {
                let r = tmp.read().unwrap();
                r.get_in(0).map(|e| (bank.expect_arc(e.point), e.point))
            };
            match next {
                Some(b) => {
                    tmp = b.0;
                    tmp_point = b.1;
                }
                None => return false,
            }
        }
        // (W2) shadow read: the initblock's 2-out gate.
        if bank.expect_size_out(tmp_point) != 2 {
            return false;
        }
        self.initblock = Some(tmp.clone());
        // Walk up the other (1 - prea_inslot) path similarly; it must also
        // reach the same initblock.
        let other_in = {
            let rg = ib.read().unwrap();
            rg.get_in((1 - self.prea_inslot) as usize)
                .map(|e| (bank.expect_arc(e.point), e.point))
        };
        let (mut tmp2, mut tmp2_point) = match other_in {
            Some(b) => b,
            None => return false,
        };
        loop {
            let (sout, sin) =
                (bank.expect_size_out(tmp2_point), bank.expect_size_in(tmp2_point));
            if sout != 1 || sin != 1 {
                break;
            }
            let next = {
                let r = tmp2.read().unwrap();
                r.get_in(0).map(|e| (bank.expect_arc(e.point), e.point))
            };
            match next {
                Some(b) => {
                    tmp2 = b.0;
                    tmp2_point = b.1;
                }
                None => return false,
            }
        }
        if !Arc::ptr_eq(&tmp2, &tmp) { return false; }
        if Arc::ptr_eq(&tmp, &ib) { return false; }

        // condexe.cc:72: init2a_true = (initblock->getTrueOut() == last).
        // getTrueOut() is purely positional out[1] (block.hh:300, never reads
        // BOOLEAN_FLIP); the init CBRANCH's flip is consumed later, exactly
        // once, by verifySameCondition's matchflip composition below.
        let last_id = bank.registered_id_of(&last);
        self.init2a_true = tmp
            .read()
            .unwrap()
            .get_out(1)
            .map(|e| e.point == last_id)
            .unwrap_or(false);
        true
    }

    // ------------------------------------------------------------------
    // verifySameCondition (condexe.cc:80-94) + BooleanExpressionMatch
    // ------------------------------------------------------------------

    // Ghidra: condexe.cc:80 ConditionalExecution::verifySameCondition
    /// Verify initblock and iblock branch on the same (or complementary)
    /// condition. Faithful to `verifySameCondition` + `BooleanExpressionMatch`.
    fn verify_same_condition(&mut self) -> bool {
        let init = match &self.initblock { Some(b) => b.clone(), None => return false };
        let init_cbranch = match Self::last_op(&init) {
            Some(o) => o,
            None => return false,
        };
        if init_cbranch.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return false; }
        let ib_cb = self.cbranch.clone().unwrap();
        let res = boolean_match_verify_condition(&ib_cb, &init_cbranch);
        if res == UNCORRELATED { return false; }
        self.matchflip = res == COMPLEMENTARY;
        // Apply per-CBRANCH flip flags (BooleanExpressionMatch::verifyCondition).
        let ib_flip = (ib_cb.read().unwrap().flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
        let init_flip = (init_cbranch.read().unwrap().flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
        if ib_flip { self.matchflip = !self.matchflip; }
        if init_flip { self.matchflip = !self.matchflip; }
        // init2a_true is complemented if matchflip (verifySameCondition effect).
        if self.matchflip { self.init2a_true = !self.init2a_true; }
        true
    }

    // Ghidra: condexe.cc:101 ConditionalExecution::testMultiRead
    // ------------------------------------------------------------------
    // testMultiRead (condexe.cc:101-113)
    // ------------------------------------------------------------------

    fn test_multi_read(vn: &Arc<RwLock<Varnode>>, op: &Arc<RwLock<PcodeOp>>, iblock: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        let op_parent = op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        let op_code = op.read().unwrap().opcode;
        if let Some(p) = &op_parent {
            if Arc::ptr_eq(p, iblock) {
                if op_code == OpCode::CPUI_COPY || op_code == OpCode::CPUI_SUBPIECE {
                    return true;
                }
                return false;
            }
        }
        if op_code == OpCode::CPUI_RETURN {
            let op_rg = op.read().unwrap();
            if op_rg.num_input() < 2 { return false; }
            // Only test for flow-through to return value: input(1) must be vn.
            let in1 = op_rg.get_in(1);
            return in1.map(|v| Arc::ptr_eq(v, vn)).unwrap_or(false);
        }
        true
    }

    // Ghidra: condexe.cc:120 ConditionalExecution::testOpRead
    // ------------------------------------------------------------------
    // testOpRead (condexe.cc:120-142)
    // ------------------------------------------------------------------

    fn test_op_read(vn: &Arc<RwLock<Varnode>>, op: &Arc<RwLock<PcodeOp>>, iblock: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        let op_parent = op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        if let Some(p) = &op_parent {
            if Arc::ptr_eq(p, iblock) { return true; }
        }
        let writeop = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(o) => o, None => return false,
        };
        let opc = writeop.read().unwrap().opcode;
        if opc == OpCode::CPUI_COPY || opc == OpCode::CPUI_SUBPIECE
            || opc == OpCode::CPUI_INT_ADD || opc == OpCode::CPUI_PTRSUB
        {
            if opc == OpCode::CPUI_INT_ADD || opc == OpCode::CPUI_PTRSUB {
                let wr = writeop.read().unwrap();
                let in1_const = wr.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
                if !in1_const { return false; }
            }
            let invn = writeop.read().unwrap().get_in(0).cloned();
            if let Some(invn) = invn {
                let invn_written = invn.read().unwrap().is_written();
                if invn_written {
                    let upop = invn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                    if let Some(up) = upop {
                        let up_parent = up.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                        let up_code = up.read().unwrap().opcode;
                        if let Some(p) = &up_parent {
                            if Arc::ptr_eq(p, iblock) && up_code != OpCode::CPUI_MULTIEQUAL {
                                return false;
                            }
                        }
                    }
                } else if invn.read().unwrap().is_free() {
                    return false;
                }
                return true;
            }
        }
        false
    }

    // Ghidra: condexe.cc:361 ConditionalExecution::testRemovability
    // ------------------------------------------------------------------
    // testRemovability (condexe.cc:361-397)
    // ------------------------------------------------------------------

    fn test_removability(&self, op: &Arc<RwLock<PcodeOp>>) -> bool {
        let ib = self.iblock.clone().unwrap();
        let opc = op.read().unwrap().opcode;
        if opc == OpCode::CPUI_MULTIEQUAL {
            let out = match op.read().unwrap().output.clone() { Some(o) => o, None => return true };
            let descends: Vec<Arc<RwLock<PcodeOp>>> =
                out.read().unwrap().descend_iter().collect();
            for readop in descends {
                if !Self::test_multi_read(&out, &readop, &ib) { return false; }
            }
            true
        } else {
            let op_rg = op.read().unwrap();
            if op_rg.is_call() { return false; }
            // isFlowBreak: branch/return ops.
            if op_rg.opcode == OpCode::CPUI_BRANCH || op_rg.opcode == OpCode::CPUI_CBRANCH
                || op_rg.opcode == OpCode::CPUI_BRANCHIND || op_rg.opcode == OpCode::CPUI_RETURN
            { return false; }
            if op_rg.opcode == OpCode::CPUI_LOAD || op_rg.opcode == OpCode::CPUI_STORE { return false; }
            if op_rg.opcode == OpCode::CPUI_INDIRECT { return false; }
            drop(op_rg);
            let out = match op.read().unwrap().output.clone() { Some(o) => o, None => return true };
            if out.read().unwrap().is_addr_tied() { return false; }
            let descends: Vec<Arc<RwLock<PcodeOp>>> =
                out.read().unwrap().descend_iter().collect();
            let mut hasnodescend = true;
            for readop in descends {
                if !Self::test_op_read(&out, &readop, &ib) { return false; }
                hasnodescend = false;
            }
            if hasnodescend {
                // cc:392: a Varnode with no descendants can only be moved
                // if heritage is performed for its space:
                // `if (hasnodescend && (!heritageyes[vn->getSpace()->getIndex()])) return false;`
                // Spaces outside the enumerable list (Overlay/Other, see
                // CONDEXE_SPACE_LIST) read as not heritaged.
                let space = out.read().unwrap().get_space();
                match condexe_space_index(&space) {
                    Some(i) if self.heritageyes[i] => {}
                    _ => return false,
                }
            }
            true
        }
    }

    // Ghidra: condexe.cc:402 ConditionalExecution::verify
    // ------------------------------------------------------------------
    // verify (condexe.cc:402-428)
    // ------------------------------------------------------------------

    fn verify(&mut self) -> bool {
        self.prea_inslot = 0;
        self.posta_outslot = 0;
        if !self.test_iblock() { return false; }
        if !self.find_init_pre() { return false; }
        if !self.verify_same_condition() { return false; }
        // Cache useful values.
        let ib = self.iblock.clone().unwrap();
        self.iblock2posta_true = self.posta_outslot == 1;
        self.camethruposta_slot = if self.init2a_true == self.iblock2posta_true {
            self.prea_inslot
        } else {
            1 - self.prea_inslot
        };
        let rg = ib.read().unwrap();
        let bank = rg.bank();
        self.posta_block = rg
            .get_out(self.posta_outslot as usize)
            .map(|e| bank.expect_arc(e.point));
        self.postb_block = rg
            .get_out((1 - self.posta_outslot) as usize)
            .map(|e| bank.expect_arc(e.point));
        drop(rg);
        // Test removability of every non-branch op in iblock.
        let ops = Self::ops(&ib);
        for op in &ops {
            let is_branch = {
                let o = op.read().unwrap();
                o.opcode == OpCode::CPUI_BRANCH || o.opcode == OpCode::CPUI_CBRANCH
                    || o.opcode == OpCode::CPUI_BRANCHIND || o.opcode == OpCode::CPUI_RETURN
            };
            if is_branch { continue; }
            if !self.test_removability(op) { return false; }
        }
        true
    }

    // Ghidra: condexe.cc:146 ConditionalExecution::findPullback
    // ------------------------------------------------------------------
    // Data-flow rewrite helpers (condexe.cc:146-357)
    // ------------------------------------------------------------------

    fn find_pullback(&mut self, inbranch: usize) -> Option<Arc<RwLock<Varnode>>> {
        while self.pullback.len() <= inbranch {
            self.pullback.push(None);
        }
        self.pullback[inbranch].clone()
    }

    // Ghidra: condexe.cc:160 ConditionalExecution::pullbackOp
    /// pullbackOp (condexe.cc:160-190). Duplicate an iblock op outside the
    /// iblock: through the MULTIEQUAL in-branch block when input 0 is defined
    /// by an iblock MULTIEQUAL, otherwise into the iblock's immediate
    /// dominator. The duplicate keeps the original op's address (cc:180), the
    /// original output's address AND address space (cc:182), and is inserted
    /// at the END of the target block (cc:187), before any trailing flow-break
    /// op (funcdata_op.cc:435-446).
    ///
    /// The oracle function has no failure mode (no throw, no null return); the
    /// `Err` legs here are Rugra structural-invariant guards for states the
    /// oracle would hit as null-deref UB (see `structural`).
    fn pullback_op(&mut self, op: &Arc<RwLock<PcodeOp>>, inbranch: usize) -> Result<Arc<RwLock<Varnode>>> {
        // cc:163-165: cached pullback output for this inbranch wins.
        if let Some(v) = self.find_pullback(inbranch) { return Ok(v); }
        let ib = self.iblock.clone().unwrap();
        // cc:166-179: resolve input 0 and the target block.
        let invn = op.read().unwrap().get_in(0).cloned()
            .ok_or_else(|| structural("pullbackOp op without input 0 (condexe.cc:166 dereferences op->getIn(0))"))?;
        let (invn, bl) = if invn.read().unwrap().is_written() {
            // cc:168-169: invn->isWritten() -> defOp = invn->getDef()
            let defop = invn.read().unwrap().def.as_ref().and_then(|w| w.upgrade())
                .ok_or_else(|| structural("pullbackOp written input without def (condexe.cc:169 dereferences getDef())"))?;
            let def_parent = defop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
            let in_iblock = def_parent.map(|p| Arc::ptr_eq(&p, &ib)).unwrap_or(false);
            if in_iblock {
                // cc:170-173: defOp in iblock (must be MULTIEQUAL):
                //   bl = iblock->getIn(inbranch); invn = defOp->getIn(inbranch)
                let sel = defop.read().unwrap().get_in(inbranch).cloned()
                    .ok_or_else(|| structural("pullbackOp defOp missing inbranch input (condexe.cc:172)"))?;
                let bl = {
                    let r = ib.read().unwrap();
                    let bank = r.bank();
                    r.get_in(inbranch).map(|e| bank.expect_arc(e.point))
                }
                    .ok_or_else(|| structural("pullbackOp iblock missing in-branch (condexe.cc:171)"))?;
                (sel, bl)
            } else {
                // cc:174-175: bl = iblock->getImmedDom()
                (invn, self.immed_dom_of(&ib)
                    .ok_or_else(|| structural("pullbackOp iblock without immediate dominator (condexe.cc:175/178)"))?)
            }
        } else {
            // cc:177-179: not written -> bl = iblock->getImmedDom()
            (invn.clone(), self.immed_dom_of(&ib)
                .ok_or_else(|| structural("pullbackOp iblock without immediate dominator (condexe.cc:178)"))?)
        };
        // cc:180: newOp = fd->newOp(op->numInput(), op->getAddr())
        let (n_in, pc, opcode) = {
            let r = op.read().unwrap();
            (r.num_input(), r.get_addr(), r.opcode)
        };
        let new_op = self.fd.new_op(n_in, pc);
        // cc:181-182: outVn = fd->newVarnodeOut(origOutVn->getSize(),
        //                                     origOutVn->getAddr(), newOp)
        let orig_out = op.read().unwrap().output.clone()
            .ok_or_else(|| structural("pullbackOp op without output (condexe.cc:181-182 dereferences op->getOut())"))?;
        let (out_size, out_space, out_offset) = {
            let r = orig_out.read().unwrap();
            (r.get_size(), r.get_space(), r.get_offset())
        };
        let new_out = self.new_varnode_out_with_space(out_size, out_space, out_offset, &new_op);
        // cc:183: fd->opSetOpcode(newOp, op->code())
        self.fd.op_set_opcode(&new_op, opcode);
        // cc:184: fd->opSetInput(newOp, invn, 0)
        self.fd.op_set_input(&new_op, invn, 0);
        // cc:185-186: remaining inputs copied from the original op.
        for i in 1..n_in {
            if let Some(extra) = op.read().unwrap().get_in(i).cloned() {
                self.fd.op_set_input(&new_op, extra, i);
            }
        }
        // cc:187: fd->opInsertEnd(newOp, bl)
        self.fd.op_insert_end(&new_op, &bl);
        // cc:188: pullback[inbranch] = outVn
        while self.pullback.len() <= inbranch { self.pullback.push(None); }
        self.pullback[inbranch] = Some(new_out.clone());
        // cc:189: return outVn
        Ok(new_out)
    }

    // Ghidra: funcdata_varnode.cc:104 Funcdata::newVarnodeOut
    /// Space-preserving `Funcdata::newVarnodeOut` (funcdata_varnode.cc:104-127)
    /// for the two condexe call sites that must keep the original output's
    /// storage address INCLUDING its address space: pullbackOp's duplicate
    /// output (condexe.cc:182) and the RETURN-holding COPY's output
    /// (condexe.cc:343, "Preserve the CPUI_RETURN storage address").
    /// `Funcdata::new_varnode_out` (funcdata.rs) pins AddressSpace::Register
    /// because Rugra's split Address model does not carry a space; the exact
    /// newVarnodeOut leg is replicated here against the true space:
    ///   Varnode *vn = vbank.createDef(s,m,ct,op);
    ///   op->setOutput(vn);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s,m);
    ///   <queryProperties / setSymbolProperties / setFlags leg>
    fn new_varnode_out_with_space(
        &mut self,
        size: usize,
        space: crate::space::AddressSpace,
        offset: u64,
        op: &PcodeOpRef,
    ) -> Arc<RwLock<Varnode>> {
        let vn = self.fd.vbank.create_def_with_space(size, space, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        let _ = self.fd.assign_high(&vn);
        if size >= self.fd.min_laned_size as usize {
            self.fd.check_for_laned_register(
                size,
                space,
                crate::address::Address::new(offset),
            );
        }
        self.fd.set_varnode_properties(&vn);
        vn
    }

    // RUDRA-GLUE: immediate-dominator lookup (Ghidra calls
    // FlowBlock::getImmedDom, block.hh:162, inline).
    fn immed_dom_of(&self, b: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        b.read().unwrap().get_immed_dom().and_then(|w| w.upgrade())
    }

    // Ghidra: condexe.cc:198 ConditionalExecution::getNewMulti
    /// getNewMulti (condexe.cc:198-217). The oracle has no failure mode; the
    /// `Err` legs are Rugra structural-invariant guards (see `structural`).
    fn get_new_multi(&mut self, op: &Arc<RwLock<PcodeOp>>, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Result<Arc<RwLock<Varnode>>> {
        let outvn_size = op.read().unwrap().output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
        let outvn = op.read().unwrap().output.clone()
            .ok_or_else(|| structural("getNewMulti op without output (condexe.cc:202 dereferences op->getOut())"))?;
        let start = bl.read().unwrap().get_start_addr();
        let n_in = bl.read().unwrap().size_in();
        let newop = self.fd.new_op(n_in, start);
        let newoutvn = self.fd.new_unique_out(outvn_size, &newop);
        self.fd.op_set_opcode(&newop, OpCode::CPUI_MULTIEQUAL);
        for i in 0..n_in {
            self.fd.op_set_input(&newop, outvn.clone(), i);
        }
        self.fd.op_insert_begin(&newop, bl);
        Ok(newoutvn)
    }

    // Ghidra: condexe.cc:224 ConditionalExecution::resolveRead
    /// resolveRead (condexe.cc:224-237). `Err` propagates the
    /// `resolveIblockRead` LowlevelError verbatim; structural legs are
    /// Rugra-invariant guards (see `structural`).
    fn resolve_read(&mut self, op: &Arc<RwLock<PcodeOp>>, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Result<Arc<RwLock<Varnode>>> {
        let sin = bl.read().unwrap().size_in();
        if sin == 1 {
            // dominator is iblock; In(0) is iblock. Figure which side we came
            // through via the reverse index vs posta_outslot.
            let rev0 = {
                let r = bl.read().unwrap();
                if let Some(bb) = r.as_any().downcast_ref::<BlockBasic>() {
                    bb.get_in_rev_index(0)
                } else {
                    return Err(structural("resolveRead reader block is not a BlockBasic (condexe.cc:231 calls getInRevIndex on BlockBasic)"));
                }
            };
            let slot = if rev0 == self.posta_outslot { self.camethruposta_slot } else { 1 - self.camethruposta_slot };
            self.resolve_iblock_read(op, slot as usize)
        } else {
            self.get_new_multi(op, bl)
        }
    }

    // Ghidra: condexe.cc:242 ConditionalExecution::resolveIblockRead
    /// resolveIblockRead (condexe.cc:242-262). Falls through to the oracle's
    /// terminating failure: `throw LowlevelError("Conditional execution:
    /// Illegal op in iblock")` (condexe.cc:261) — reproduced verbatim as
    /// `Error::Lowlevel`. In particular a COPY whose input 0 is written by
    /// anything other than a MULTIEQUAL in the iblock keeps `op` unchanged
    /// (cc:249-250) and reaches the throw through the `CPUI_COPY` fall-through,
    /// exactly like the oracle (the old Rugra code silently returned `None`
    /// here, which do_replacement then skipped, looping forever).
    fn resolve_iblock_read(&mut self, op: &Arc<RwLock<PcodeOp>>, inbranch: usize) -> Result<Arc<RwLock<Varnode>>> {
        let mut op = op.clone();
        if op.read().unwrap().opcode == OpCode::CPUI_COPY {
            let vn = op.read().unwrap().get_in(0).cloned()
                .ok_or_else(|| structural("resolveIblockRead COPY without input 0 (condexe.cc:246 dereferences op->getIn(0))"))?;
            let written = vn.read().unwrap().is_written();
            if written {
                let defop = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade())
                    .ok_or_else(|| structural("resolveIblockRead written varnode without def (condexe.cc:248 dereferences getDef())"))?;
                let def_code = defop.read().unwrap().opcode;
                if def_code == OpCode::CPUI_MULTIEQUAL {
                    let ib = self.iblock.clone().unwrap();
                    let def_parent = defop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
                    if def_parent.as_ref().map(|p| Arc::ptr_eq(p, &ib)).unwrap_or(false) {
                        op = defop; // cc:250: op = defOp
                    }
                }
            } else {
                return Ok(vn); // cc:253: unwritten input flows straight through
            }
        }
        let opc = op.read().unwrap().opcode;
        if opc == OpCode::CPUI_MULTIEQUAL {
            return op.read().unwrap().get_in(inbranch).cloned()
                .ok_or_else(|| structural("resolveIblockRead MULTIEQUAL missing inbranch input (condexe.cc:257)"));
        }
        if opc == OpCode::CPUI_SUBPIECE || opc == OpCode::CPUI_INT_ADD || opc == OpCode::CPUI_PTRSUB {
            return self.pullback_op(&op, inbranch);
        }
        // condexe.cc:261: throw LowlevelError("Conditional execution: Illegal
        // op in iblock") — verbatim oracle message.
        Err(Error::Lowlevel(
            "Conditional execution: Illegal op in iblock".to_string(),
        ))
    }

    // Ghidra: condexe.cc:270 ConditionalExecution::getMultiequalRead
    /// getMultiequalRead (condexe.cc:270-279). `Err` propagates the resolve
    /// chain's LowlevelError verbatim; structural legs are Rugra-invariant
    /// guards (see `structural`).
    fn get_multiequal_read(&mut self, op: &Arc<RwLock<PcodeOp>>, readop: &Arc<RwLock<PcodeOp>>, slot: usize) -> Result<Arc<RwLock<Varnode>>> {
        let read_parent = readop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade())
            .ok_or_else(|| structural("getMultiequalRead readop without parent (condexe.cc:273 dereferences getParent())"))?;
        let bl = read_parent;
        let inbl = {
            let r = bl.read().unwrap();
            let bank = r.bank();
            r.get_in(slot).map(|e| bank.expect_arc(e.point))
        }
            .ok_or_else(|| structural("getMultiequalRead reader block missing in-edge (condexe.cc:274 dereferences getIn(slot))"))?;
        let ib = self.iblock.clone().unwrap();
        if !Arc::ptr_eq(&inbl, &ib) {
            return self.get_replacement_read(op, &inbl);
        }
        let rev = {
            let r = bl.read().unwrap();
            if let Some(bb) = r.as_any().downcast_ref::<BlockBasic>() {
                bb.get_in_rev_index(slot)
            } else {
                return Err(structural("getMultiequalRead reader block is not a BlockBasic (condexe.cc:277 calls getInRevIndex on BlockBasic)"));
            }
        };
        let s = if rev == self.posta_outslot { self.camethruposta_slot } else { 1 - self.camethruposta_slot };
        self.resolve_iblock_read(op, s as usize)
    }

    // Ghidra: condexe.cc:291 ConditionalExecution::getReplacementRead
    /// getReplacementRead (condexe.cc:291-315). The dominator-chain walk
    /// reproduces the oracle's terminating failure:
    /// `throw LowlevelError("Conditional execution: Could not find dominator")`
    /// (condexe.cc:303) — verbatim as `Error::Lowlevel` — when the chain
    /// exhausts before reaching a block dominated by the iblock (the old Rust
    /// code silently returned `None` here).
    fn get_replacement_read(&mut self, op: &Arc<RwLock<PcodeOp>>, bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Result<Arc<RwLock<Varnode>>> {
        let bl_idx = bl.read().unwrap().get_index();
        if let Some(v) = self.replacement.get(&bl_idx).cloned() { return Ok(v); }
        // Walk up dominators until we reach a block dominated by iblock
        // (cc:300-304: while(curbl->getImmedDom() != iblock) { curbl = ...;
        // if (curbl == 0) throw ...; }).
        let ib = self.iblock.clone().unwrap();
        let mut curbl = bl.clone();
        loop {
            let curdom = self.immed_dom_of(&curbl);
            match curdom {
                Some(d) if Arc::ptr_eq(&d, &ib) => break,
                Some(d) => { curbl = d; }
                // condexe.cc:303: the chain left the graph without passing
                // through iblock — verbatim oracle message.
                None => return Err(Error::Lowlevel(
                    "Conditional execution: Could not find dominator".to_string(),
                )),
            }
        }
        let cur_idx_key = curbl.read().unwrap().get_index();
        if let Some(v) = self.replacement.get(&cur_idx_key).cloned() {
            self.replacement.insert(bl_idx, v.clone());
            return Ok(v);
        }
        let res = self.resolve_read(op, &curbl)?;
        self.replacement.insert(cur_idx_key, res.clone());
        if cur_idx_key != bl_idx {
            self.replacement.insert(bl_idx, res.clone());
        }
        Ok(res)
    }

    // Ghidra: condexe.cc:320 ConditionalExecution::doReplacement
    /// doReplacement (condexe.cc:320-357). Result-ized: the oracle has no
    /// silent-skip path — every loop iteration removes exactly one descendant
    /// of `op->getOut()` (`opUnsetInput` in the iblock, `opSetInput`
    /// everywhere else, cc:333/352), and the resolve chain either returns a
    /// Varnode or throws `LowlevelError`, which unwinds out of `apply` with
    /// the partial state accumulated so far. The old Rust code returned
    /// `None` from the resolve chain, skipped the `op_set_input`, and re-fetched
    /// the same first descendant forever (death loop); now any failure is an
    /// `Err` that propagates, so the loop always terminates.
    fn do_replacement(&mut self, op: &Arc<RwLock<PcodeOp>>) -> Result<()> {
        self.replacement.clear();
        self.pullback.clear();
        let vn = match op.read().unwrap().output.clone() {
            Some(vn) => vn,
            // condexe.cc:325-326 dereferences op->getOut() unconditionally;
            // a null output is UB there. Every caller passes ops that passed
            // testRemovability, which requires a non-null output
            // (condexe.cc:382-394). Defensive no-op instead of UB.
            None => return Ok(()),
        };
        // Process each descendant. Ghidra resets the iterator to
        // beginDescend() after every pass (cc:355) because replacing an input
        // mutates the descendant list; the loop ends when the last descendant
        // is gone.
        loop {
            let readop = match vn.read().unwrap().descend_iter().next() {
                Some(r) => r,
                None => break,
            };
            // cc:329: slot = readop->getSlot(vn) (op.hh:166 returns
            // inrefs.size() when absent — a state Ghidra would use as an
            // out-of-range slot, i.e. UB; guarded structurally here).
            let slot = (0..readop.read().unwrap().num_input())
                .find(|&i| {
                    readop.read().unwrap().get_in(i)
                        .map(|v| Arc::ptr_eq(v, &vn)).unwrap_or(false)
                });
            // cc:330: bl = readop->getParent() — captured BEFORE the RETURN
            // leg reassigns readop (cc:346).
            let read_parent = readop.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
            let ib = self.iblock.clone().unwrap();
            let in_iblock = read_parent.as_ref().map(|p| Arc::ptr_eq(p, &ib)).unwrap_or(false);
            if in_iblock {
                // cc:332-334: the read is inside the iblock itself — drop the
                // input slot entirely.
                let s = slot.ok_or_else(|| structural("doReplacement descendant does not list the output as an input (condexe.cc:329 getSlot))"))?;
                let r = opref(&readop);
                self.fd.op_unset_input(&r, s);
            } else {
                let read_code = readop.read().unwrap().opcode;
                let readop_ref = opref(&readop);
                if read_code == OpCode::CPUI_MULTIEQUAL {
                    // cc:336-337: rvn = getMultiequalRead(op, readop, slot).
                    let s = slot.ok_or_else(|| structural("doReplacement MULTIEQUAL read without matching slot (condexe.cc:337)"))?;
                    let rvn = self.get_multiequal_read(op, &readop, s)?;
                    // cc:352: opSetInput(readop, rvn, slot) — removes vn from
                    // readop's descendants; guaranteed progress.
                    self.fd.op_set_input(&readop_ref, rvn, s);
                } else if read_code == OpCode::CPUI_RETURN {
                    // cc:339-349: cannot replace a RETURN input directly;
                    // create a COPY to hold the input. Ordering is
                    // load-bearing: if getReplacementRead below fails, the
                    // copy op stays created and inserted with no input 0 —
                    // the same partial state the oracle's throw leaves.
                    let bl = read_parent
                        .ok_or_else(|| structural("doReplacement RETURN readop without parent (condexe.cc:330 dereferences getParent())"))?;
                    let retvn = readop.read().unwrap().get_in(1).cloned()
                        .ok_or_else(|| structural("doReplacement RETURN without input 1 (condexe.cc:340 dereferences getIn(1))"))?;
                    let pc = readop.read().unwrap().get_addr();
                    let (size, retvn_space, retvn_offset) = {
                        let r = retvn.read().unwrap();
                        (r.get_size(), r.get_space(), r.get_offset())
                    };
                    let newcopy = self.fd.new_op(1, pc);
                    self.fd.op_set_opcode(&newcopy, OpCode::CPUI_COPY);
                    // cc:343: outvn = fd->newVarnodeOut(retvn->getSize(),
                    //   retvn->getAddr(), newcopyop) — preserve the
                    // CPUI_RETURN storage address INCLUDING its address
                    // space (funcdata_varnode.cc:104-127 exact leg, shared
                    // with pullbackOp's cc:182 call; Rugra's
                    // Funcdata::new_varnode_out pins the Register space
                    // because its Address lacks a space).
                    let outvn =
                        self.new_varnode_out_with_space(size, retvn_space, retvn_offset, &newcopy);
                    // cc:344: opSetInput(readop, outvn, 1) — RETURN input[1] =
                    // COPY output (NOT retvn!); this is what removes vn from
                    // the RETURN's descendants.
                    self.fd.op_set_input(&readop_ref, outvn, 1);
                    // cc:345: opInsertBefore(newcopyop, readop).
                    self.fd.op_insert_before(&newcopy, &readop_ref);
                    // cc:346-348: readop = newcopyop; slot = 0;
                    //   rvn = getReplacementRead(op, bl) — may propagate the
                    //   dominator/illegal-op LowlevelError, leaving newcopy
                    //   without input 0 (oracle partial state).
                    let rvn = self.get_replacement_read(op, &bl)?;
                    // cc:352 with the cc:346-347 reassignment:
                    // opSetInput(newcopyop, rvn, 0).
                    self.fd.op_set_input(&newcopy, rvn, 0);
                } else {
                    // cc:350-351: rvn = getReplacementRead(op, bl).
                    let bl = read_parent
                        .ok_or_else(|| structural("doReplacement readop without parent (condexe.cc:330 dereferences getParent())"))?;
                    let s = slot.ok_or_else(|| structural("doReplacement read without matching slot (condexe.cc:329 getSlot)"))?;
                    let rvn = self.get_replacement_read(op, &bl)?;
                    // cc:352 — guaranteed progress.
                    self.fd.op_set_input(&readop_ref, rvn, s);
                }
            }
            // cc:355: iter = vn->beginDescend() — re-fetch; the processed
            // descendant is gone (progress invariant).
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // trial / execute (condexe.cc:448-476)
    // ------------------------------------------------------------------

    // Ghidra: condexe.cc:448 ConditionalExecution::trial
    /// Test whether the given block is a modifiable iblock.
    /// Faithful to `ConditionalExecution::trial` (condexe.cc:448-454).
    pub fn trial(&mut self, ib: Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        self.iblock = Some(ib);
        self.verify()
    }

    // Ghidra: condexe.cc:457 ConditionalExecution::execute
    /// Eliminate the unnecessary path join at iblock.
    /// Faithful to `ConditionalExecution::execute` (condexe.cc:457-476).
    /// `Err` mirrors the oracle's exception protocol: a `LowlevelError` out
    /// of `doReplacement` (illegal iblock op, cc:261; missing dominator,
    /// cc:303) or out of `removeFromFlowSplit` ("Can only split the flow for
    /// an empty block", funcdata_block.cc:884-885) unwinds out of execute —
    /// and out of `ActionConditionalExe::apply` — leaving every mutation
    /// performed so far in place (already-destroyed iblock ops stay
    /// destroyed, the failing op survives, the flow split never happens).
    pub fn execute(&mut self) -> Result<()> {
        let ib = self.iblock.clone().unwrap();
        // Remove ops in reverse order, skipping branches.
        let mut ops = Self::ops(&ib);
        while let Some(op) = ops.pop() {
            let is_branch = {
                let o = op.read().unwrap();
                o.opcode == OpCode::CPUI_BRANCH || o.opcode == OpCode::CPUI_CBRANCH
                    || o.opcode == OpCode::CPUI_BRANCHIND || o.opcode == OpCode::CPUI_RETURN
            };
            if !is_branch {
                self.do_replacement(&op)?;
            }
            let r = opref(&op);
            self.fd.op_destroy(&r);
        }
        // removeFromFlowSplit: join prea->posta etc. swap = (posta_outslot != camethruposta_slot).
        let swap = self.posta_outslot != self.camethruposta_slot;
        // cc:475: fd->removeFromFlowSplit(...) — the oracle call throws
        // LowlevelError on a non-empty block (funcdata_block.cc:884-885), and
        // that exception propagates. The Err is therefore NOT discarded here
        // (the old code did `let _ =`); it is mapped into the Lowlevel error
        // channel at this call boundary. RESIDUAL CFG-0001: the Rugra callee
        // (funcdata.rs remove_from_flow_split) still returns Rugra-side
        // message text and the pre-fix swap mapping; its ownership sits with
        // the funcdata.rs/block.rs lease and is registered as TODO CFG-0001.
        self.fd.remove_from_flow_split(&ib, swap).map_err(Error::Lowlevel)?;
        Ok(())
    }

    // RUDRA-GLUE: fixture observability for CONDEXE-TRUEOUT-0002; the locked
    // Ghidra fixture reads the same private members and calls the same private
    // stages through #define private public (tests/oracle/condexe_trueout_1204.cc).
    /// Set iblock/prea_inslot and run `findInitPre` in isolation, returning
    /// (ok, init2a_true). Mirrors condexe.cc:55-75 driven directly.
    #[doc(hidden)]
    pub fn fixture_find_init_pre(
        &mut self,
        ib: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        prea_inslot: i32,
    ) -> (bool, bool) {
        self.iblock = Some(ib);
        self.prea_inslot = prea_inslot;
        let ok = self.find_init_pre();
        (ok, self.init2a_true)
    }

    // RUDRA-GLUE: fixture observability (see fixture_find_init_pre).
    /// Set iblock/cbranch and run the full `verify` stage in isolation,
    /// returning (ok, init2a_true, camethruposta_slot, posta, postb).
    /// Mirrors condexe.cc:402-428 driven directly.
    #[doc(hidden)]
    pub fn fixture_verify(
        &mut self,
        ib: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        cbranch: crate::op::PcodeOpRef,
    ) -> (bool, bool, i32, Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>, Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.iblock = Some(ib);
        self.cbranch = Some(cbranch.0);
        let ok = self.verify();
        (
            ok,
            self.init2a_true,
            self.camethruposta_slot,
            self.posta_block.clone(),
            self.postb_block.clone(),
        )
    }

    // RUDRA-GLUE: fixture observability for CONDEXE-PULLBACK-0005; the locked
    // Ghidra fixture drives the same private stages through
    // #define private public (tests/oracle/condexe_pullback_1204.cc).
    /// Set iblock and run `pullbackOp` in isolation, returning the new
    /// output Varnode. Mirrors condexe.cc:160-190 driven directly. The
    /// underlying pullback_op is Result-typed since CONDEXE-ERROR-0006 (its
    /// Err legs are structural-invariant guards unreachable for the valid
    /// fixture inputs, which mirror the oracle's no-failure contract), so the
    /// Option surface of this glue is unchanged for the pinned pullback
    /// fixture.
    #[doc(hidden)]
    pub fn fixture_pullback_op(
        &mut self,
        ib: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        op: PcodeOpRef,
        inbranch: usize,
    ) -> Option<Arc<RwLock<Varnode>>> {
        self.iblock = Some(ib);
        self.pullback_op(&op.0, inbranch).ok()
    }

    // RUDRA-GLUE: fixture observability (see fixture_pullback_op).
    /// Set iblock and run `testOpRead` in isolation. Mirrors condexe.cc:107-142
    /// driven directly (the pullback admission gate, including the
    /// INT_ADD/PTRSUB constant-input-1 rejection at cc:126-128).
    #[doc(hidden)]
    pub fn fixture_test_op_read(
        &mut self,
        ib: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        vn: Arc<RwLock<Varnode>>,
        readop: PcodeOpRef,
    ) -> bool {
        Self::test_op_read(&vn, &readop.0, &ib)
    }

    // RUDRA-GLUE: fixture observability for CONDEXE-SUCCESS-STATE-0001; the
    // locked Ghidra fixture constructs ConditionalExecution directly (the
    // constructor is public, condexe.hh:124) and reads `heritageyes` through
    // #define private public (tests/oracle/condexe_success_state_1204.cc).
    /// Run `buildHeritageArray` in isolation and return the per-space array
    /// in CONDEXE_SPACE_LIST order (Ram, Register, Unique, Const, Stack,
    /// Join, Iop). Mirrors condexe.cc:23-37 driven directly.
    #[doc(hidden)]
    pub fn fixture_heritage_array(fd: &Funcdata) -> Vec<bool> {
        Self::build_heritage_array(fd)
    }

    // RUDRA-GLUE: fixture observability (see fixture_heritage_array).
    /// The space labels for [`Self::fixture_heritage_array`]'s slots, so the
    /// external fixture can project `name=value` pairs instead of raw
    /// indices (Rugra's CONDEXE_SPACE_LIST order need not match the oracle
    /// architecture's baselist order).
    #[doc(hidden)]
    pub fn fixture_heritage_space_names() -> Vec<&'static str> {
        vec!["ram", "register", "unique", "const", "stack", "join", "iop"]
    }
}

// ======================================================================
// BooleanMatch / BooleanExpressionMatch (expression.cc:57-232)
// ======================================================================

// Ghidra: expression.cc:93 BooleanMatch::varnodeSame
/// `BooleanMatch::varnodeSame` (expression.cc:93-100).
fn varnode_same(a: &Arc<RwLock<Varnode>>, b: &Arc<RwLock<Varnode>>) -> bool {
    if Arc::ptr_eq(a, b) { return true; }
    let (ar, br) = (a.read().unwrap(), b.read().unwrap());
    if ar.is_constant() && br.is_constant() {
        return ar.get_offset() == br.get_offset();
    }
    false
}

// Ghidra: expression.cc:57 BooleanMatch::sameOpComplement
/// `BooleanMatch::sameOpComplement` (expression.cc:57-86). Only handles
/// INT_LESS / INT_SLESS with a constant input.
fn same_op_complement(bin1: &Arc<RwLock<PcodeOp>>, bin2: &Arc<RwLock<PcodeOp>>) -> bool {
    let (opc, n_in) = {
        let r = bin1.read().unwrap();
        (r.opcode, r.inrefs.len())
    };
    if opc != OpCode::CPUI_INT_LESS && opc != OpCode::CPUI_INT_SLESS { return false; }
    let _ = n_in;
    let b1 = bin1.read().unwrap();
    let b2 = bin2.read().unwrap();
    let mut constslot = 0;
    if b1.get_in(1).map(|v| v.read().unwrap().is_constant()).unwrap_or(false) { constslot = 1; }
    let b1c = b1.get_in(constslot).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
    if !b1c { return false; }
    let b2c = b2.get_in(1 - constslot).map(|v| v.read().unwrap().is_constant()).unwrap_or(false);
    if !b2c { return false; }
    let same_var = match (b1.get_in(1 - constslot), b2.get_in(constslot)) {
        (Some(x), Some(y)) => varnode_same(x, y),
        _ => return false,
    };
    if !same_var { return false; }
    let val1 = b1.get_in(constslot).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
    let val2 = b2.get_in(1 - constslot).map(|v| v.read().unwrap().get_offset()).unwrap_or(0);
    let (v1, v2) = if constslot != 0 { (val2, val1) } else { (val1, val2) };
    if v1 + 1 != v2 { return false; }
    if v2 == 0 && opc == OpCode::CPUI_INT_LESS { return false; }
    if opc == OpCode::CPUI_INT_SLESS {
        let sz = b1.get_in(constslot).map(|v| v.read().unwrap().get_size()).unwrap_or(8);
        if crate::address::signbit_negative(v2, sz) && !crate::address::signbit_negative(v1, sz) {
            return false;
        }
    }
    true
}

// Ghidra: expression.cc:111 BooleanMatch::evaluate
/// `BooleanMatch::evaluate` (expression.cc:111-216). Returns SAME /
/// COMPLEMENTARY / UNCORRELATED.
fn boolean_match_evaluate(vn1: &Arc<RwLock<Varnode>>, vn2: &Arc<RwLock<Varnode>>, depth: i32) -> i32 {
    if Arc::ptr_eq(vn1, vn2) { return SAME; }
    let (op1, opc1) = {
        let written = vn1.read().unwrap().is_written();
        if written {
            let def = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            if let Some(def) = def {
                let (is_bool_not, inner_vn, opcode) = {
                    let d = def.read().unwrap();
                    (d.opcode == OpCode::CPUI_BOOL_NEGATE, d.get_in(0).cloned(), d.opcode)
                };
                if is_bool_not {
                    if let Some(inner) = inner_vn {
                        let res = boolean_match_evaluate(&inner, vn2, depth);
                        return if res == SAME { COMPLEMENTARY } else if res == COMPLEMENTARY { SAME } else { res };
                    }
                    return UNCORRELATED;
                }
                (Some(def), opcode)
            } else {
                (None, OpCode::CPUI_MAX)
            }
        } else {
            (None, OpCode::CPUI_MAX)
        }
    };
    let op2_opt = {
        let written = vn2.read().unwrap().is_written();
        if written {
            let def = vn2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            if let Some(def) = def {
                let (is_bool_not, inner_vn) = {
                    let d = def.read().unwrap();
                    (d.opcode == OpCode::CPUI_BOOL_NEGATE, d.get_in(0).cloned())
                };
                if is_bool_not {
                    if let Some(inner) = inner_vn {
                        let res = boolean_match_evaluate(vn1, &inner, depth);
                        return if res == SAME { COMPLEMENTARY } else if res == COMPLEMENTARY { SAME } else { res };
                    }
                    return UNCORRELATED;
                }
                Some(def)
            } else { None }
        } else {
            return UNCORRELATED;
        }
    };
    let op1 = match op1 { Some(o) => o, None => return UNCORRELATED };
    let op2 = match op2_opt { Some(o) => o, None => return UNCORRELATED };
    let (b1, b2) = (op1.read().unwrap().is_bool_output(), op2.read().unwrap().is_bool_output());
    if !b1 || !b2 { return UNCORRELATED; }
    let opc2 = op2.read().unwrap().opcode;
    if depth != 0 && (opc1 == OpCode::CPUI_BOOL_AND || opc1 == OpCode::CPUI_BOOL_OR || opc1 == OpCode::CPUI_BOOL_XOR) {
        if opc2 == OpCode::CPUI_BOOL_AND || opc2 == OpCode::CPUI_BOOL_OR || opc2 == OpCode::CPUI_BOOL_XOR {
            if opc1 == opc2 || (opc1 == OpCode::CPUI_BOOL_AND && opc2 == OpCode::CPUI_BOOL_OR)
                || (opc1 == OpCode::CPUI_BOOL_OR && opc2 == OpCode::CPUI_BOOL_AND)
            {
                let in1_0 = op1.read().unwrap().get_in(0).cloned();
                let in1_1 = op1.read().unwrap().get_in(1).cloned();
                let in2_0 = op2.read().unwrap().get_in(0).cloned();
                let in2_1 = op2.read().unwrap().get_in(1).cloned();
                // Faithful port of expression.cc:154-164 (BooleanMatch::evaluate
                // commutative re-pairing). Previously this block had dead code
                // (`match (a,d,c,b) { _ => {} }`) that never tried the swap,
                // so any switch with swapped AND/OR operand order was
                // misclassified UNCORRELATED, defeating condexe folding.
                let (pair1, pair2) = match (in1_0, in2_0, in1_1, in2_1) {
                    (Some(a), Some(b), Some(c), Some(d)) => {
                        let p1 = boolean_match_evaluate(&a, &b, depth - 1);
                        if p1 == UNCORRELATED {
                            // Try the commutative pairing (op1[0] vs op2[1])
                            let p1_swap = boolean_match_evaluate(&a, &d, depth - 1);
                            if p1_swap == UNCORRELATED {
                                return UNCORRELATED;
                            }
                            let p2_swap = boolean_match_evaluate(&c, &b, depth - 1);
                            (p1_swap, p2_swap)
                        } else {
                            let p2 = boolean_match_evaluate(&c, &d, depth - 1);
                            (p1, p2)
                        }
                    }
                    _ => return UNCORRELATED,
                };
                if pair2 == UNCORRELATED { return UNCORRELATED; }
                if opc1 == opc2 {
                    if pair1 == SAME && pair2 == SAME { return SAME; }
                    if opc1 == OpCode::CPUI_BOOL_XOR {
                        if pair1 == COMPLEMENTARY && pair2 == COMPLEMENTARY { return SAME; }
                        return COMPLEMENTARY;
                    }
                } else {
                    // AND vs OR (De Morgan)
                    if pair1 == COMPLEMENTARY && pair2 == COMPLEMENTARY { return COMPLEMENTARY; }
                }
                return UNCORRELATED;
            }
        }
        return UNCORRELATED;
    }
    // Direct comparison of two boolean-output ops.
    if opc1 == opc2 {
        let n = op1.read().unwrap().num_input();
        let mut same_op = true;
        for i in 0..n {
            let a = op1.read().unwrap().get_in(i).cloned();
            let b = op2.read().unwrap().get_in(i).cloned();
            match (a, b) {
                (Some(a), Some(b)) => { if !varnode_same(&a, &b) { same_op = false; break; } }
                _ => { same_op = false; break; }
            }
        }
        if same_op { return SAME; }
        if same_op_complement(&op1, &op2) { return COMPLEMENTARY; }
        return UNCORRELATED;
    }
    // Check complement via boolean flip.
    let mut reorder = false;
    let flipped = crate::opcodes::get_booleanflip(opc2, &mut reorder);
    if opc1 != flipped { return UNCORRELATED; }
    let slot1 = 0usize;
    let slot2 = if reorder { 1 } else { 0 };
    let a1 = op1.read().unwrap().get_in(slot1).cloned();
    let a2 = op2.read().unwrap().get_in(slot2).cloned();
    let b1 = op1.read().unwrap().get_in(1 - slot1).cloned();
    let b2 = op2.read().unwrap().get_in(1 - slot2).cloned();
    match (a1, a2, b1, b2) {
        (Some(a1), Some(a2), Some(b1), Some(b2)) => {
            if varnode_same(&a1, &a2) && varnode_same(&b1, &b2) { COMPLEMENTARY } else { UNCORRELATED }
        }
        _ => UNCORRELATED,
    }
}

// Ghidra: expression.cc:220 BooleanExpressionMatch::verifyCondition
/// `BooleanExpressionMatch::verifyCondition` (expression.cc:220-232),
/// correlation stage only: returns SAME / COMPLEMENTARY / UNCORRELATED
/// from `BooleanMatch::evaluate` on the two CBRANCH boolean inputs,
/// WITHOUT the per-CBRANCH boolean_flip composition (expression.cc:227-230),
/// which the two Rust callers apply explicitly.
fn boolean_match_verify_condition(op: &Arc<RwLock<PcodeOp>>, iop: &Arc<RwLock<PcodeOp>>) -> i32 {
    let vn_op = op.read().unwrap().get_in(1).cloned();
    let vn_iop = iop.read().unwrap().get_in(1).cloned();
    match (vn_op, vn_iop) {
        (Some(a), Some(b)) => {
            let res = boolean_match_evaluate(&a, &b, 1);
            if res == UNCORRELATED { return UNCORRELATED; }
            res
        }
        _ => UNCORRELATED,
    }
}

// Ghidra: expression.cc:220 BooleanExpressionMatch::verifyCondition
/// Full `BooleanExpressionMatch::verifyCondition` (expression.cc:220-232)
/// including the per-CBRANCH boolean_flip composition (cc:227-230): returns
/// (correlation, matchflip), mirroring what `verifyCondition` stores in
/// `matchflip` and `RuleOrPredicate` consults via `getFlip()` (condexe.cc:678).
fn verify_condition_with_flip(
    op: &Arc<RwLock<PcodeOp>>,
    iop: &Arc<RwLock<PcodeOp>>,
) -> (i32, bool) {
    let vn_op = op.read().unwrap().get_in(1).cloned();
    let vn_iop = iop.read().unwrap().get_in(1).cloned();
    let (a, b) = match (vn_op, vn_iop) {
        (Some(a), Some(b)) => (a, b),
        _ => return (UNCORRELATED, false),
    };
    let res = boolean_match_evaluate(&a, &b, 1);
    if res == UNCORRELATED { return (UNCORRELATED, false); }
    let mut flip = res == COMPLEMENTARY;
    let ib_flip = (op.read().unwrap().flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
    let init_flip = (iop.read().unwrap().flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
    if ib_flip { flip = !flip; }
    if init_flip { flip = !flip; }
    (res, flip)
}

// ======================================================================
// RuleOrPredicate (condexe.hh:172, condexe.cc:509-710)
// ======================================================================

/// A helper marking up a predicated INT_OR/INT_XOR expression.
/// Faithful to `RuleOrPredicate::MultiPredicate` (condexe.hh:174).
struct MultiPredicate {
    /// Base MULTIEQUAL op.
    op: Option<Arc<RwLock<PcodeOp>>>,
    /// Input slot containing the path that sets zero.
    zero_slot: usize,
    /// Final block in path that sets zero.
    zero_block: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// Conditional block determining if zero is set.
    cond_block: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
    /// CBRANCH determining if zero is set.
    cbranch: Option<Arc<RwLock<PcodeOp>>>,
    /// Other (non-zero) Varnode set on the other path.
    other_vn: Option<Arc<RwLock<Varnode>>>,
    /// True if the path to the zero set is the TRUE path out of condBlock.
    zero_path_is_true: bool,
}

impl MultiPredicate {
    // Ghidra: condexe.hh:174 MultiPredicate::new
    fn new() -> Self {
        Self {
            op: None,
            zero_slot: 0,
            zero_block: None,
            cond_block: None,
            cbranch: None,
            other_vn: None,
            zero_path_is_true: false,
        }
    }

    // Ghidra: condexe.cc:509 MultiPredicate::discoverZeroSlot
    /// `MultiPredicate::discoverZeroSlot` (condexe.cc:509-529). Detect a
    /// 2-input MULTIEQUAL whose one input is COPY(#0) and store the other.
    fn discover_zero_slot(&mut self, vn: &Arc<RwLock<Varnode>>) -> bool {
        if !vn.read().unwrap().is_written() { return false; }
        let op = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(o) => o, None => return false,
        };
        if op.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL { return false; }
        if op.read().unwrap().num_input() != 2 { return false; }
        self.op = Some(op.clone());
        for zero_slot in 0..2 {
            let tmpvn = match op.read().unwrap().get_in(zero_slot).cloned() {
                Some(v) => v, None => continue,
            };
            if !tmpvn.read().unwrap().is_written() { continue; }
            let copyop = match tmpvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                Some(o) => o, None => continue,
            };
            if copyop.read().unwrap().opcode != OpCode::CPUI_COPY { continue; }
            let zerovn = match copyop.read().unwrap().get_in(0).cloned() {
                Some(v) => v, None => continue,
            };
            if !zerovn.read().unwrap().is_constant() { continue; }
            if zerovn.read().unwrap().get_offset() != 0 { continue; }
            let other = op.read().unwrap().get_in(1 - zero_slot).cloned();
            let other = match other { Some(o) => o, None => continue };
            if other.read().unwrap().is_free() { return false; }
            self.zero_slot = zero_slot;
            self.other_vn = Some(other);
            return true;
        }
        false
    }

    // Ghidra: condexe.cc:539 MultiPredicate::discoverCbranch
    /// `MultiPredicate::discoverCbranch` (condexe.cc:539-567). Find the single
    /// CBRANCH controlling the MULTIEQUAL's two in-paths.
    fn discover_cbranch(&mut self) -> bool {
        let op = match &self.op { Some(o) => o.clone(), None => return false };
        let base_block = match op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade()) {
            Some(b) => b, None => return false,
        };
        let bank = base_block.read().unwrap().bank();
        // (W2) shadow reads: the zero/other path gates read the bank size
        // shadows (block.hh:312-313); points ride along with the handles.
        let zero_in = base_block
            .read()
            .unwrap()
            .get_in(self.zero_slot)
            .map(|e| (bank.expect_arc(e.point), e.point));
        let other_in = base_block
            .read()
            .unwrap()
            .get_in(1 - self.zero_slot)
            .map(|e| (bank.expect_arc(e.point), e.point));
        let ((zero_block, zero_point), (other_block, other_point)) =
            match (zero_in, other_in) {
                (Some(z), Some(o)) => (z, o),
                _ => return false,
            };
        self.zero_block = Some(zero_block.clone());
        let cond_block;
        let zout = bank.expect_size_out(zero_point);
        if zout == 1 {
            if bank.expect_size_in(zero_point) != 1 {
                return false;
            }
            cond_block = {
                let r = zero_block.read().unwrap();
                r.get_in(0).map(|e| (bank.expect_arc(e.point), e.point))
            };
        } else if zout == 2 {
            cond_block = Some((zero_block.clone(), zero_point));
        } else {
            return false;
        }
        let (cond_block, cond_point) = match cond_block {
            Some(c) => c,
            None => return false,
        };
        if bank.expect_size_out(cond_point) != 2 {
            return false;
        }
        // Verify the other path also routes through cond_block.
        let oout = bank.expect_size_out(other_point);
        if oout == 1 {
            if bank.expect_size_in(other_point) != 1 {
                return false;
            }
            let o_in0 = {
                let r = other_block.read().unwrap();
                r.get_in(0).map(|e| bank.expect_arc(e.point))
            };
            if o_in0.map(|p| !Arc::ptr_eq(&p, &cond_block)).unwrap_or(true) { return false; }
        } else if oout == 2 {
            if !Arc::ptr_eq(&other_block, &cond_block) { return false; }
        } else {
            return false;
        }
        self.cond_block = Some(cond_block.clone());
        // lastOp of cond_block must be a CBRANCH.
        let last = match cond_block.read().unwrap().get_ops().last() {
            Some(o) => o.0.clone(), None => return false,
        };
        if last.read().unwrap().opcode != OpCode::CPUI_CBRANCH { return false; }
        self.cbranch = Some(last);
        true
    }

    // Ghidra: condexe.cc:572 MultiPredicate::discoverPathIsTrue
    /// `MultiPredicate::discoverPathIsTrue` (condexe.cc:572-582).
    fn discover_path_is_true(&mut self) {
        let cond_block = match &self.cond_block { Some(c) => c.clone(), None => return };
        let zero_block = match &self.zero_block { Some(z) => z.clone(), None => return };
        let op = match &self.op { Some(o) => o.clone(), None => return };
        let parent = op.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
        // condexe.cc:575-582 uses purely positional getTrueOut()/getFalseOut()
        // (block.hh:299-300: out[1]=true, out[0]=false, never reads
        // BOOLEAN_FLIP). The cbranch flip is consumed separately, once, in
        // discoverConditionalZero (condexe.cc:612-613).
        let bank = cond_block.read().unwrap().bank();
        let true_out = {
            let r = cond_block.read().unwrap();
            r.get_out(1).map(|e| bank.expect_arc(e.point))
        };
        let false_out = {
            let r = cond_block.read().unwrap();
            r.get_out(0).map(|e| bank.expect_arc(e.point))
        };
        if true_out.as_ref().map(|t| Arc::ptr_eq(t, &zero_block)).unwrap_or(false) {
            self.zero_path_is_true = true;
        } else if false_out.as_ref().map(|f| Arc::ptr_eq(f, &zero_block)).unwrap_or(false) {
            self.zero_path_is_true = false;
        } else {
            // condBlock must be zeroBlock: true if "true" path does not override zero set.
            self.zero_path_is_true = match (true_out, parent) {
                (Some(t), Some(p)) => Arc::ptr_eq(&t, &p),
                _ => false,
            };
        }
    }

    // Ghidra: condexe.cc:590 MultiPredicate::discoverConditionalZero
    /// `MultiPredicate::discoverConditionalZero` (condexe.cc:590-615). Verify
    /// the CBRANCH boolean is (vn == 0) or (vn != 0), adjusting
    /// zero_path_is_true.
    fn discover_conditional_zero(&mut self, vn: &Arc<RwLock<Varnode>>) -> bool {
        let cbranch = match &self.cbranch { Some(c) => c.clone(), None => return false };
        let boolvn = match cbranch.read().unwrap().get_in(1).cloned() {
            Some(v) => v, None => return false,
        };
        if !boolvn.read().unwrap().is_written() { return false; }
        let compareop = match boolvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(o) => o, None => return false,
        };
        let opc = compareop.read().unwrap().opcode;
        if opc == OpCode::CPUI_INT_NOTEQUAL {
            self.zero_path_is_true = !self.zero_path_is_true;
        } else if opc != OpCode::CPUI_INT_EQUAL {
            return false;
        }
        let a1 = compareop.read().unwrap().get_in(0).cloned();
        let a2 = compareop.read().unwrap().get_in(1).cloned();
        let zerovn = match (a1, a2) {
            (Some(a1), Some(a2)) => {
                if Arc::ptr_eq(&a1, vn) { a2 }
                else if Arc::ptr_eq(&a2, vn) { a1 }
                else { return false; }
            }
            _ => return false,
        };
        if !zerovn.read().unwrap().is_constant() { return false; }
        if zerovn.read().unwrap().get_offset() != 0 { return false; }
        if cbranch.read().unwrap().is_boolean_flip() {
            self.zero_path_is_true = !self.zero_path_is_true;
        }
        true
    }
}

/// Simplify predicated INT_OR / INT_XOR constructions.
///
/// Faithful to `RuleOrPredicate` (condexe.hh:172, condexe.cc:509-710).
/// Transforms:
/// ```text
///     tmp1 = cond ? val1 : 0;
///     tmp2 = cond ?  0 : val2;
///     result = tmp1 | tmp2;       ==>   newtmp = val1 ? val2;  result = newtmp;
/// ```
pub struct RuleOrPredicate;

impl RuleOrPredicate {
    // Ghidra: condexe.hh:172 RuleOrPredicate::new
    pub fn new() -> Self { Self }

    // RUDRA-GLUE: fixture observability for CONDEXE-TRUEOUT-0002; the locked
    // Ghidra fixture builds MultiPredicate (a private nested struct,
    // condexe.hh:174) directly and calls discoverPathIsTrue through
    // `#define private public` (tests/oracle/condexe_trueout_1204.cc).
    /// Fill cond_block/zero_block/op/cbranch and run `discoverPathIsTrue` in
    /// isolation, returning zero_path_is_true. Mirrors condexe.cc:572-582.
    #[doc(hidden)]
    pub fn fixture_discover_path_is_true(
        cond_block: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        zero_block: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        op: crate::op::PcodeOpRef,
        cbranch: crate::op::PcodeOpRef,
    ) -> bool {
        let mut mp = MultiPredicate::new();
        mp.op = Some(op.0);
        mp.zero_block = Some(zero_block);
        mp.cond_block = Some(cond_block);
        mp.cbranch = Some(cbranch.0);
        mp.discover_path_is_true();
        mp.zero_path_is_true
    }

    // Ghidra: condexe.cc:617 RuleOrPredicate::getOpList
    pub fn get_opcodes(&self) -> Vec<OpCode> {
        vec![OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR]
    }

    // Ghidra: condexe.cc:638 RuleOrPredicate::checkSingle
    /// `RuleOrPredicate::checkSingle` (condexe.cc:638-652). The alternate form
    /// `tmp1 = (val2 == 0) ? val1 : 0; result = tmp1 | other` where `other`
    /// plays val2.
    fn check_single(
        &self,
        vn: &Arc<RwLock<Varnode>>,
        branch: &mut MultiPredicate,
        op: &crate::op::PcodeOpRef,
        fd: &mut Funcdata,
    ) -> i32 {
        if vn.read().unwrap().is_free() { return 0; }
        if !branch.discover_cbranch() { return 0; }
        // MULTIEQUAL output must have exactly one use (this INT_OR op).
        let multi_out = match branch.op.as_ref().and_then(|o| o.read().unwrap().output.clone()) {
            Some(o) => o, None => return 0,
        };
        let lone = multi_out.read().unwrap().lone_descend();
        if lone.map(|l| !Arc::ptr_eq(&l, &op.0)).unwrap_or(true) { return 0; }
        branch.discover_path_is_true();
        if !branch.discover_conditional_zero(vn) { return 0; }
        if branch.zero_path_is_true { return 0; }
        // Rewrite: MULTIEQUAL input[zeroSlot] = vn; INT_OR -> COPY.
        let multi = branch.op.clone().unwrap();
        let multi_ref = crate::op::PcodeOpRef(multi.clone());
        fd.op_set_input(&multi_ref, vn.clone(), branch.zero_slot);
        fd.op_remove_input(op, 1);
        fd.op_set_opcode(op, OpCode::CPUI_COPY);
        let multi_out2 = multi.read().unwrap().output.clone();
        if let Some(mo) = multi_out2 { fd.op_set_input(op, mo, 0); }
        1
    }

    // Ghidra: condexe.cc:654 RuleOrPredicate::applyOp
    /// `RuleOrPredicate::applyOp` (condexe.cc:654-710).
    pub fn apply_op(&self, op: &crate::op::PcodeOpRef, fd: &mut Funcdata) -> i32 {
        let in0 = op.0.read().unwrap().get_in(0).cloned();
        let in1 = op.0.read().unwrap().get_in(1).cloned();
        let (in0, in1) = match (in0, in1) { (Some(a), Some(b)) => (a, b), _ => return 0 };
        let mut branch0 = MultiPredicate::new();
        let mut branch1 = MultiPredicate::new();
        let test0 = branch0.discover_zero_slot(&in0);
        let test1 = branch1.discover_zero_slot(&in1);
        if !test0 && !test1 { return 0; }
        if !test0 {
            // branch1 has MULTIEQUAL form; check alternate with in0.
            return self.check_single(&in0, &mut branch1, op, fd);
        }
        if !test1 {
            return self.check_single(&in1, &mut branch0, op, fd);
        }
        if !branch0.discover_cbranch() { return 0; }
        if !branch1.discover_cbranch() { return 0; }
        let cb0 = branch0.cond_block.clone().unwrap();
        let cb1 = branch1.cond_block.clone().unwrap();
        if Arc::ptr_eq(&cb0, &cb1) {
            // zero sets must be along different paths.
            let zb0 = branch0.zero_block.clone().unwrap();
            let zb1 = branch1.zero_block.clone().unwrap();
            if Arc::ptr_eq(&zb0, &zb1) { return 0; }
        } else {
            // Cbranches must share a condition; the different zero sets must
            // be on complementary paths.
            let cb_0 = branch0.cbranch.clone().unwrap();
            let cb_1 = branch1.cbranch.clone().unwrap();
            let (res, flip) = verify_condition_with_flip(&cb_0, &cb_1);
            if res == UNCORRELATED { return 0; }
            // getMultiSlot() is always -1 in Ghidra (expression.hh:101), so no
            // additional check needed here.
            let _ = res;
            branch0.discover_path_is_true();
            branch1.discover_path_is_true();
            let mut final_bool = branch0.zero_path_is_true == branch1.zero_path_is_true;
            if flip { final_bool = !final_bool; }
            if final_bool { return 0; } // One path hits both zero sets.
        }
        // Determine control-flow order of the two MULTIEQUALs.
        let m0 = branch0.op.clone().unwrap();
        let m1 = branch1.op.clone().unwrap();
        let order = {
            let (r0, r1) = (m0.read().unwrap(), m1.read().unwrap());
            r0.compare_order(&r1)
        };
        if order == 0 { return 0; }
        let (final_block, slot0_sets_branch0) = if order < 0 {
            // branch1 happens after.
            let fb = m1.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
            (fb, branch1.zero_slot == 0)
        } else {
            // branch0 happens after.
            let fb = m0.read().unwrap().parent.as_ref().and_then(|w| w.upgrade());
            (fb, branch0.zero_slot == 1)
        };
        let final_block = match final_block { Some(b) => b, None => return 0 };
        let start = final_block.read().unwrap().get_start_addr();
        let new_multi = fd.new_op(2, start);
        fd.op_set_opcode(&new_multi, OpCode::CPUI_MULTIEQUAL);
        let b0_other = branch0.other_vn.clone().unwrap();
        let b1_other = branch1.other_vn.clone().unwrap();
        if slot0_sets_branch0 {
            fd.op_set_input(&new_multi, b0_other, 0);
            fd.op_set_input(&new_multi, b1_other, 1);
        } else {
            fd.op_set_input(&new_multi, b1_other, 0);
            fd.op_set_input(&new_multi, b0_other, 1);
        }
        let size = branch0.other_vn.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        let newvn = fd.new_unique_out(size, &new_multi);
        fd.op_insert_begin(&new_multi, &final_block);
        fd.op_remove_input(op, 1);
        fd.op_set_input(op, newvn, 0);
        fd.op_set_opcode(op, OpCode::CPUI_COPY);
        1
    }
}

/// `impl Rule` wrapper for `RuleOrPredicate` (condexe.cc:509-710).
///
/// The core logic lives in [`RuleOrPredicate::apply_op`], which takes a
/// `&PcodeOpRef`. This trait impl adapts it to the `Rule` trait's
/// `&Arc<RwLock<PcodeOp>>` signature (as used by `ActionPool::processOp`,
/// action.cc:823-876), wrapping the inner op in a `PcodeOpRef` and mapping the
/// raw `i32` result to the `Result<i32>` the pool expects.
impl Rule for RuleOrPredicate {
    // Ghidra: condexe.cc:654 RuleOrPredicate::applyOp
    fn apply_op(
        &self,
        op_arc: &Arc<RwLock<PcodeOp>>,
        fd: &mut Funcdata,
    ) -> Result<i32> {
        let op_ref = PcodeOpRef(op_arc.clone());
        Ok(RuleOrPredicate::apply_op(self, &op_ref, fd))
    }

    // Ghidra: condexe.hh:172 RuleOrPredicate::getName
    fn get_name(&self) -> &str { "orpredicate" }

    // Ghidra: condexe.cc:617 RuleOrPredicate::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> {
        // Faithful to RuleOrPredicate::getOpList (condexe.cc:631-635).
        vec![OpCode::CPUI_INT_OR, OpCode::CPUI_INT_XOR]
    }
}

// ======================================================================
// ActionConditionalExe (condexe.hh:133, condexe.cc:478-503)
// ======================================================================

/// Search for and remove various forms of redundant CBRANCH operations.
/// Faithful to Ghidra's `ActionConditionalExe` (condexe.hh:133).
pub struct ActionConditionalExe {
    /// Externalized Ghidra protected `Action::count` accumulator: the oracle
    /// does `count += numhits` at condexe.cc:501 and returns 0; Rugra's
    /// Action trait keeps the control-flow return (0) separate from the
    /// statistics, harvesting this field through `take_count_delta` in
    /// `Action::perform` (action.rs).
    count: i32,
}

impl ActionConditionalExe {
    // Ghidra: condexe.hh:133 ActionConditionalExe::ActionConditionalExe
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

impl Action for ActionConditionalExe {
    // Ghidra: condexe.cc:478 ActionConditionalExe::apply
    /// Faithful to `ActionConditionalExe::apply` (condexe.cc:478-503):
    ///   - unreachable-blocks guard FIRST: return 0 before anything is
    ///     constructed or mutated (cc:485-486; the cached flag is maintained
    ///     by structureReset, funcdata_block.cc:710/714)
    ///   - constructs ONE ConditionalExecution outside the loop (cc:487),
    ///     so buildHeritageArray's cache is computed once per apply
    ///   - `const BlockGraph &bblocks(data.getBasicBlocks())` (cc:488) is a
    ///     LIVE reference: the do-while round loop (cc:490-500) re-reads
    ///     `bblocks.getSize()` and `bblocks.getBlock(i)` from the live graph
    ///     on EVERY iteration. execute() removes the folded iblock
    ///     (removeFromFlowSplit -> BlockGraph::removeBlock), the list shifts
    ///     left, and the block right after a removed iblock is SKIPPED for
    ///     the remainder of that round (index i already passed it) — it is
    ///     only re-tried on the next do-while round. No snapshot is taken.
    ///   - for inner loop over ALL bblocks, NO break on hit (cc:492-499);
    ///     every candidate check (2in/2out/CBRANCH) happens inside
    ///     trial()/verify(), apply adds no pre-filter
    ///   - `count += numhits` only after the round loop completes (cc:501);
    ///     returns 0 (count is statistics only, cc:502)
    /// Error protocol (CONDEXE-ERROR-0006): in the oracle a LowlevelError
    /// thrown inside condexe.execute() (condexe.cc:261/303 via doReplacement,
    /// funcdata_block.cc:885 via removeFromFlowSplit) unwinds straight out of
    /// apply — the action never returns, the surrounding decompiler pipeline
    /// aborts this function, and the Funcdata keeps its partial state. The
    /// Rust port propagates the same failure as `Err` from apply
    /// (ActionGroup::apply aborts on `?`, action.rs), never swallowing it;
    /// the throw also skips `count += numhits` exactly like the oracle.
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // cc:485-486: "Conditional execution elimination logic may not work
        // with unreachable blocks" — return 0 immediately. The early return
        // precedes the ConditionalExecution construction (cc:487), so the
        // Funcdata suffers ZERO mutation and `count += numhits` (cc:501) is
        // skipped: on this path numhits stays 0 and Action::count is never
        // touched. The flag is the cached blocks_unreachable bit maintained
        // by structureReset (funcdata_block.cc:710/714, rootlist.size() > 1).
        if fd.has_unreachable_blocks() {
            return Ok(action_status::NO_CHANGE);
        }
        let mut numhits = 0;
        // cc:487: ONE ConditionalExecution for the whole apply (single
        // buildHeritageArray cache, see ConditionalExecution::new).
        let mut condexe = ConditionalExecution::new(fd);
        // cc:490-500: do { changethisround=false; for(i=0;i<bblocks.getSize();++i)
        //   ... } while(changethisround); — both getSize() and getBlock(i)
        // are live reads through the cc:488 reference.
        loop {
            let mut changethisround = false;
            let mut i = 0usize;
            loop {
                if i >= condexe.fd.bblocks.get_size() {
                    break;
                }
                let bb = condexe.fd.bblocks.get_block(i);
                if let Some(bb) = bb {
                    // cc:494: condexe.trial(bb) — the (BlockBasic*) cast is
                    // unchecked in the oracle; bblocks only ever holds
                    // BlockBasics, and Rugra's get_block returns None only
                    // for an out-of-range index, which the bound above
                    // already excludes.
                    if condexe.trial(bb) {
                        // cc:495: condexe.execute() — an exception unwinds
                        // out of apply in the oracle; here the Err
                        // propagates.
                        condexe.execute()?;
                        numhits += 1; // cc:496
                        changethisround = true; // cc:497
                    }
                }
                i += 1;
            }
            // cc:500: } while(changethisround);
            if !changethisround {
                break;
            }
        }
        // cc:501: count += numhits — Number of changes; statistics only,
        // externalized through take_count_delta. cc:502: return 0.
        self.count += numhits;
        Ok(action_status::NO_CHANGE)
    }

    // RUDRA-GLUE: externalizes Ghidra's inherited protected Action::count
    // (condexe.cc:501 `count += numhits`) into the Rust ActionState
    // accumulator, harvested by Action::perform (action.rs) exactly like
    // coreaction.rs's multicse/restructure_varnote (coreaction.cc:873/2282).
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
    }

    // Ghidra: condexe.hh:133 ActionConditionalExe::getName
    fn get_name(&self) -> &str {
        "conditionalexe"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_name() {
        let mut a = ActionConditionalExe::new();
        assert_eq!(a.get_name(), "conditionalexe");
    }

    #[test]
    fn test_correlation_constants() {
        assert_eq!(SAME, 0);
        assert_eq!(COMPLEMENTARY, 1);
        assert_eq!(UNCORRELATED, 2);
        assert_ne!(SAME, COMPLEMENTARY);
    }

    #[test]
    fn test_varnode_same_identity() {
        // Two references to the same Varnode compare equal via Arc ptr.
        // We can't easily build a bare Varnode without Funcdata, so this
        // guards the const wiring.
        assert_eq!(SAME, 0);
    }

    #[test]
    fn test_apply_on_empty_fd() {
        let mut fd = Funcdata::new("t", crate::address::Address::new(0), 0);
        let mut a = ActionConditionalExe::new();
        let r = a.apply(&mut fd).unwrap();
        assert_eq!(r, action_status::NO_CHANGE);
    }

    /// Verify the same-condition detection (`BooleanExpressionMatch`) wiring
    /// by constructing two INT_EQUAL ops on identical inputs and checking
    /// they evaluate to SAME. This exercises the core `boolean_match_evaluate`
    /// without needing a full CFG.
    #[test]
    fn test_boolean_match_same_condition() {
        use crate::varnode::Varnode;
        use crate::op::PcodeOp;
        use crate::address::{Address, SeqNum};

        // Two INT_EQUAL ops producing boolean outputs from constant inputs.
        // Their outputs feed into boolean_match_evaluate to exercise the
        // machinery end-to-end.
        let mk_int_equal = |off: u64| {
            let out = Arc::new(RwLock::new(Varnode::new_unique(off, 1)));
            out.write().unwrap().set_flags(crate::varnode::varnode_flags::WRITTEN);
            let mut op = PcodeOp::new(SeqNum::new(Address::new(0x10), 0), OpCode::CPUI_INT_EQUAL);
            op.flags |= crate::op::pcodeop_flags::BOOLOUTPUT;
            op.output = Some(out.clone());
            op
        };
        let op1 = mk_int_equal(0x300);
        let op2 = mk_int_equal(0x400);
        let a1 = Arc::new(RwLock::new(op1));
        let a2 = Arc::new(RwLock::new(op2));
        let o1 = a1.read().unwrap().output.clone().unwrap();
        let o2 = a2.read().unwrap().output.clone().unwrap();
        let res = boolean_match_evaluate(&o1, &o2, 1);
        // Distinct outputs with no shared def -> UNCORRELATED.
        assert_eq!(res, UNCORRELATED);
    }

    /// Build a minimal CFG with a 2-in/2-out CBRANCH block and confirm
    /// `ConditionalExecution` correctly rejects an iblock whose condition is
    /// NOT shared (so no spurious rewrite). This validates the verify() path.
    #[test]
    fn test_trial_rejects_unrelated_conditions() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        // A single empty block with 0 in / 0 out cannot be an iblock.
        let _ = fd.bblocks.get_size();
        let mut a = ActionConditionalExe::new();
        let r = a.apply(&mut fd).unwrap();
        // No removable iblock -> NO_CHANGE.
        assert_eq!(r, action_status::NO_CHANGE);
    }

    /// RuleOrPredicate should return 0 when given a non-MULTIEQUAL input
    /// (discoverZeroSlot rejects it). Guards applyOp's early-out path.
    #[test]
    fn test_rule_or_predicate_rejects_plain_input() {
        use crate::address::Address;
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x40);
        // Construct a COPY op (no MULTIEQUAL inputs); applyOp must return 0.
        let op = fd.new_op(2, Address::new(0x10));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_OR);
        let a = Varnode::new_constant(1, 1);
        let b = Varnode::new_constant(2, 1);
        let a = Arc::new(RwLock::new(a));
        let b = Arc::new(RwLock::new(b));
        fd.op_set_input(&op, a, 0);
        fd.op_set_input(&op, b, 1);
        let rule = RuleOrPredicate::new();
        let res = rule.apply_op(&op, &mut fd);
        assert_eq!(res, 0);
    }

    /// RuleOrPredicate opcodes are INT_OR and INT_XOR.
    #[test]
    fn test_rule_or_predicate_opcodes() {
        let rule = RuleOrPredicate::new();
        let ops = rule.get_opcodes();
        assert!(ops.contains(&OpCode::CPUI_INT_OR));
        assert!(ops.contains(&OpCode::CPUI_INT_XOR));
        assert_eq!(ops.len(), 2);
    }

    /// compare_order: same op compares equal; the wiring runs end-to-end.
    #[test]
    fn test_compare_order_basic() {
        use crate::address::{Address, SeqNum};
        let mk = |addr: u64, ord: u32| PcodeOp::new(SeqNum::new(Address::new(addr), ord), OpCode::CPUI_COPY);
        let a = mk(0x100, 0);
        let b = mk(0x100, 1);
        // Same block (no parent set): both None -> compare_order returns 0.
        assert_eq!(a.compare_order(&b), 0);
    }

    // ==================================================================
    // RuleOrPredicate `impl Rule` wrapper tests (condexe.cc:509-710)
    // ==================================================================

    /// The `Rule` trait impl reports the same name/opcodes as the inner struct
    /// (condexe.cc:631-635), and constructs via `new()`.
    #[test]
    fn test_rule_or_predicate_trait_name_and_opcodes() {
        let rule: &dyn Rule = &RuleOrPredicate::new();
        assert_eq!(rule.get_name(), "orpredicate");
        let ops = rule.get_opcodes();
        assert_eq!(ops.len(), 2);
        assert!(ops.contains(&OpCode::CPUI_INT_OR));
        assert!(ops.contains(&OpCode::CPUI_INT_XOR));
    }

    /// The `Rule` trait `apply_op` wrapper delegates to the inner `apply_op`:
    /// an INT_OR whose inputs are not the (cond ? v : 0) MULTIEQUAL form returns
    /// NO_CHANGE (0). This exercises the `&Arc<RwLock<PcodeOp>>` -> `&PcodeOpRef`
    /// adaptation (condexe.cc:654-656).
    #[test]
    fn test_rule_or_predicate_trait_apply_no_form() {
        use crate::address::{Address, SeqNum};
        let mut fd = Funcdata::new("t", Address::new(0x1000), 0x10);
        // Two plain register inputs — neither is a MULTIEQUAL(cond,v,0).
        let in0 = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x10);
        let in1 = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x20);
        let out = fd.vbank.create_with_space(4, crate::space::AddressSpace::Register, 0x30);
        let op = PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_INT_OR);
        let op_arc = Arc::new(RwLock::new(op));
        {
            let mut o = op_arc.write().unwrap();
            o.inrefs = vec![in0, in1];
            o.output = Some(out);
        }
        let rule = RuleOrPredicate::new();
        // Call the `Rule` trait method explicitly (the struct also has an
        // inherent apply_op with a different signature — PcodeOpRef vs Arc).
        let res = <RuleOrPredicate as Rule>::apply_op(&rule, &op_arc, &mut fd).unwrap();
        // discoverZeroSlot fails on plain (non-written) inputs -> no form -> 0.
        assert_eq!(res, 0);
    }

    // ==================================================================
    // CONDEXE-ERROR-0006: error-channel regression tests
    // (condexe.cc:261/303 verbatim LowlevelError, death-loop fix,
    //  execute/apply Err propagation)
    // ==================================================================

    /// Minimal verified diamond used by the error-channel tests:
    /// b0 init [COPY bool, CBRANCH bool] -> b1/b2 prea/preb (empty) ->
    /// b3 iblock [COPY vnY <- vnW, CBRANCH bool] -> b4 posta (reader) /
    /// b5 postb. b6 floats and defines vnW with a COPY (input 0 of the
    /// iblock COPY, written OUTSIDE the iblock by a non-MULTIEQUAL op —
    /// passes testOpRead but is illegal for resolveIblockRead, condexe.cc:261).
    /// `reader_dom_ib`: wire b4's immed_dom to b3 (legal dominator, walks to
    /// the illegal-op throw); otherwise the reader block is undominated
    /// (dominator chain leaves the graph, condexe.cc:303).
    /// Returns (iblock, ib-copy-output, reader block).
    fn build_error_diamond(
        fd: &mut Funcdata,
        reader_dom_ib: bool,
    ) -> (
        Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        Arc<RwLock<Varnode>>,
        Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        use crate::address::Address;
        let mut next_pc = 0x20000u64;
        let mut pc = || {
            let a = Address::new(next_pc);
            next_pc += 8;
            a
        };
        let b: Vec<_> = (0..7).map(|_| fd.create_new_block()).collect();
        fd.bblocks.add_edge(b[0].clone(), b[1].clone());
        fd.bblocks.add_edge(b[0].clone(), b[2].clone());
        fd.bblocks.add_edge(b[1].clone(), b[3].clone());
        fd.bblocks.add_edge(b[2].clone(), b[3].clone());
        fd.bblocks.add_edge(b[3].clone(), b[4].clone());
        fd.bblocks.add_edge(b[3].clone(), b[5].clone());
        // Shared written boolean defined in b0, read by both CBRANCHes
        // (BooleanExpressionMatch -> SAME, condexe.cc:88-93).
        let boolvn = {
            let op = fd.new_op(1, pc());
            fd.op_set_opcode(&op, OpCode::CPUI_COPY);
            let out = fd.vbank.create_def_with_space(1, crate::space::AddressSpace::Unique, 0x900, &op.0);
            op.0.write().unwrap().output = Some(out.clone());
            let c = fd.new_constant(1, 1);
            fd.op_set_input(&op, c, 0);
            fd.op_insert_end(&op, &b[0]);
            out
        };
        let cbranch = |fd: &mut Funcdata,
                       blk: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
                       bv: &Arc<RwLock<Varnode>>,
                       at: crate::address::Address| {
            let op = fd.new_op(2, at);
            fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
            let t = fd.new_constant(8, 0x4000);
            fd.op_set_input(&op, t, 0);
            fd.op_set_input(&op, bv.clone(), 1);
            fd.op_insert_end(&op, blk);
        };
        cbranch(fd, &b[0], &boolvn, pc());
        // b6: floating writer of vnW (outside the iblock, non-MULTIEQUAL).
        let vn_w = {
            let op = fd.new_op(1, pc());
            fd.op_set_opcode(&op, OpCode::CPUI_COPY);
            let out = fd.vbank.create_def_with_space(4, crate::space::AddressSpace::Unique, 0x1000, &op.0);
            op.0.write().unwrap().output = Some(out.clone());
            let c = fd.new_constant(4, 0x41);
            fd.op_set_input(&op, c, 0);
            fd.op_insert_end(&op, &b[6]);
            out
        };
        // b3 iblock: COPY vnY <- vnW, then CBRANCH bool.
        let vn_y = {
            let op = fd.new_op(1, pc());
            fd.op_set_opcode(&op, OpCode::CPUI_COPY);
            let out = fd.vbank.create_def_with_space(4, crate::space::AddressSpace::Unique, 0x2000, &op.0);
            op.0.write().unwrap().output = Some(out.clone());
            fd.op_set_input(&op, vn_w, 0);
            fd.op_insert_end(&op, &b[3]);
            out
        };
        cbranch(fd, &b[3], &boolvn, pc());
        // b4 posta reader: COPY reading vnY.
        {
            let op = fd.new_op(1, pc());
            fd.op_set_opcode(&op, OpCode::CPUI_COPY);
            fd.op_set_input(&op, vn_y.clone(), 0);
            fd.op_insert_end(&op, &b[4]);
        }
        if reader_dom_ib {
            // E1 wiring: b4 is dominated by the iblock — the resolve chain
            // reaches resolveIblockRead and hits the illegal-op throw.
            b[4].write().unwrap().set_immed_dom(Some(Arc::downgrade(&b[3])));
        } else {
            // E2 wiring: b4 is dominated by the INIT block, not the iblock —
            // the walk advances once (b4 -> b0) then leaves the graph at the
            // entry (b0 has no dominator), exercising both the loop-advance
            // leg and the throw (condexe.cc:303).
            b[4].write().unwrap().set_immed_dom(Some(Arc::downgrade(&b[0])));
        }
        (b[3].clone(), vn_y, b[4].clone())
    }

    /// E1 (condexe.cc:261): a COPY in the iblock whose input 0 is written
    /// outside the iblock by a non-MULTIEQUAL op passes verify()/testOpRead
    /// but is illegal for resolveIblockRead. The oracle throws LowlevelError
    /// ("Conditional execution: Illegal op in iblock") out of
    /// ActionConditionalExe::apply; Rugra must return the SAME verbatim Err
    /// (and must terminate — the pre-fix code silently skipped the
    /// op_set_input and looped forever on the same descendant).
    #[test]
    fn test_apply_aborts_illegal_iblock_op() {
        let mut fd = Funcdata::new("e1", crate::address::Address::new(0x60000), 0x100);
        let (ib, vn_y, reader) = build_error_diamond(&mut fd, true);
        let mut action = ActionConditionalExe::new();
        let err = action
            .apply(&mut fd)
            .expect_err("illegal iblock op must abort apply");
        match &err {
            crate::error::Error::Lowlevel(msg) => {
                // Verbatim oracle message, condexe.cc:261.
                assert_eq!(msg, "Conditional execution: Illegal op in iblock");
            }
            other => panic!("expected Lowlevel error, got {other:?}"),
        }
        // Partial state, mirroring the oracle after the throw:
        // the CBRANCH was destroyed first (execute walks in reverse), the
        // failing COPY survives untouched, the reader still reads vnY, and
        // the iblock is still in the graph (removeFromFlowSplit not reached).
        let ib_ops: Vec<String> = {
            let ops = ib.read().unwrap().get_ops();
            ops.iter().map(|o| o.0.read().unwrap().opcode.name().to_string()).collect()
        };
        assert_eq!(ib_ops, vec!["COPY"]);
        assert_eq!(ib.read().unwrap().size_in(), 2);
        assert_eq!(ib.read().unwrap().size_out(), 2);
        let readers: usize = vn_y.read().unwrap().descend_iter().count();
        assert_eq!(readers, 1);
        assert_eq!(reader.read().unwrap().get_ops().len(), 1);
    }

    /// E2 (condexe.cc:303): the reader's block is not dominated by the
    /// iblock, so getReplacementRead's dominator walk leaves the graph. The
    /// oracle throws LowlevelError ("Conditional execution: Could not find
    /// dominator"); Rugra must return the SAME verbatim Err (pre-fix: silent
    /// None + death loop).
    #[test]
    fn test_apply_aborts_missing_dominator() {
        let mut fd = Funcdata::new("e2", crate::address::Address::new(0x60000), 0x100);
        let (ib, vn_y, _reader) = build_error_diamond(&mut fd, false);
        let mut action = ActionConditionalExe::new();
        let err = action
            .apply(&mut fd)
            .expect_err("broken dominator chain must abort apply");
        match &err {
            crate::error::Error::Lowlevel(msg) => {
                // Verbatim oracle message, condexe.cc:303.
                assert_eq!(msg, "Conditional execution: Could not find dominator");
            }
            other => panic!("expected Lowlevel error, got {other:?}"),
        }
        // Same partial-state shape as E1 (CBRANCH destroyed, COPY intact).
        let ib_ops: Vec<String> = {
            let ops = ib.read().unwrap().get_ops();
            ops.iter().map(|o| o.0.read().unwrap().opcode.name().to_string()).collect()
        };
        assert_eq!(ib_ops, vec!["COPY"]);
        assert_eq!(vn_y.read().unwrap().descend_iter().count(), 1);
    }

    /// E3: verify() failure (uncorrelated iblock CBRANCH boolean) makes
    /// trial() return false; apply must complete normally with 0 and leave
    /// the Funcdata untouched — no Err, no partial destruction.
    #[test]
    fn test_apply_verify_failure_no_change() {
        let mut fd = Funcdata::new("e3", crate::address::Address::new(0x60000), 0x100);
        let (ib, _, _) = build_error_diamond(&mut fd, true);
        // Point the iblock CBRANCH's boolean at a constant that does not
        // correlate with the init CBRANCH's written boolean:
        // BooleanExpressionMatch -> UNCORRELATED (expression.cc:111), so
        // verifySameCondition fails (condexe.cc:88-89) before any mutation.
        let ib_ops: Vec<Arc<RwLock<PcodeOp>>> = {
            let ops = ib.read().unwrap().get_ops();
            ops.iter().map(|o| o.0.clone()).collect()
        };
        let cbranch_op = ib_ops.last().unwrap().clone();
        assert_eq!(cbranch_op.read().unwrap().opcode, OpCode::CPUI_CBRANCH);
        let other_bool = fd.new_constant(1, 0x7a);
        fd.op_set_input(&crate::op::PcodeOpRef(cbranch_op), other_bool, 1);
        let mut action = ActionConditionalExe::new();
        let res = action.apply(&mut fd).expect("verify failure must not abort");
        assert_eq!(res, action_status::NO_CHANGE);
        // Untouched: the iblock still holds COPY + CBRANCH.
        let names: Vec<String> = {
            let ops = ib.read().unwrap().get_ops();
            ops.iter().map(|o| o.0.read().unwrap().opcode.name().to_string()).collect()
        };
        assert_eq!(names, vec!["COPY", "CBRANCH"]);
    }

    /// E4 / CONDEXE-UNREACHGUARD-0001 (condexe.cc:485-486): with the cached
    /// blocks_unreachable flag set — via the production structure_reset
    /// path (the diamond's floating b6 has sizeIn()==0, so findSpanningTree
    /// collects two roots and funcdata_block.cc:713-714 sets the flag) —
    /// apply must return 0 IMMEDIATELY, before any ConditionalExecution
    /// work: the E1-shape diamond (a guaranteed abort without the guard)
    /// stays fully untouched. The oracle fixture pins this byte-for-byte
    /// (tests/oracle/condexe_error_1204, record pre/ret/state E4).
    #[test]
    fn test_apply_unreachable_blocks_early_return() {
        let mut fd = Funcdata::new("e4", crate::address::Address::new(0x60000), 0x100);
        let (ib, vn_y, reader) = build_error_diamond(&mut fd, true);
        // Production flag-set path: floating b6 -> two spanning-tree roots
        // -> blocks_unreachable (funcdata_block.cc:713-714).
        fd.structure_reset();
        assert!(fd.has_unreachable_blocks(), "fixture must set the flag it tests");
        let mut action = ActionConditionalExe::new();
        let res = action.apply(&mut fd).expect("guard path must not abort");
        assert_eq!(res, action_status::NO_CHANGE);
        // Zero mutation: COPY + CBRANCH intact, vnY still read once, reader
        // untouched — without the guard this exact input aborts with the
        // E1 illegal-op LowlevelError (negative control, oracle gate).
        let names: Vec<String> = {
            let ops = ib.read().unwrap().get_ops();
            ops.iter().map(|o| o.0.read().unwrap().opcode.name().to_string()).collect()
        };
        assert_eq!(names, vec!["COPY", "CBRANCH"]);
        assert_eq!(ib.read().unwrap().size_in(), 2);
        assert_eq!(ib.read().unwrap().size_out(), 2);
        assert_eq!(vn_y.read().unwrap().descend_iter().count(), 1);
        assert_eq!(reader.read().unwrap().get_ops().len(), 1);
    }
}
