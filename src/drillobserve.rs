//! Read-only per-application modified-op recorder for the stage drill
//! emitter (stage-bisect v2). This is the Rust mirror of Ghidra's
//! `OPACTION_DEBUG` machinery at the SAME hook points:
//!
//!   - `Funcdata::debugModCheck` (funcdata.cc:1010-1022): first-touch
//!     before-caching keyed on the op's `modified` addl-flag, called from
//!     every mutation entry under `#ifdef OPACTION_DEBUG`
//!     (funcdata_op.cc:25-33,52-66,70-87,104-141,150-186,203-221,267-317;
//!     funcdata_varnode.cc:269-292).
//!   - `Action::perform` activate/flush pair (action.cc:316-322).
//!   - `ActionPool::processOp` per-rule activate/flush pair
//!     (action.cc:839-845).
//!   - `Funcdata::debugModPrint` (funcdata.cc:1034-1057): one block per
//!     application — `DEBUG <n>: <leafname>` header (count printed before
//!     increment, so the first native seq is 0), one before/after pair
//!     per first-touched op in modify_list order, count advanced only
//!     when the application actually modified a traced op.
//!
//! Everything is gated on RUDRA_STAGE_DRILL=1: with the env unset every
//! entry point is a no-op and the pipeline behaves byte-identically.
//!
//! RUDRA-GLUE: no single Ghidra counterpart — observation-only recorder
//! mirroring the primitives above; nothing it produces is fed back into
//! the pipeline.

use crate::arch::Architecture;
use crate::op::{op_addl_flags, PcodeOpRef};
use std::cell::RefCell;
use std::sync::Arc;

struct Recorder {
    active: bool,
    count: u64,
    modify_list: Vec<PcodeOpRef>,
    modify_before: Vec<String>,
    blocks: Vec<String>,
    arch: Option<Arc<Architecture>>,
}

impl Default for Recorder {
    // RUDRA-GLUE: Default impl re-initializing recorder scratch state (no Ghidra counterpart; the C++ fields reset in Funcdata ctor funcdata.cc:74-81).
    fn default() -> Self {
        Self {
            active: false,
            count: 0,
            modify_list: Vec::new(),
            modify_before: Vec::new(),
            blocks: Vec::new(),
            arch: None,
        }
    }
}

thread_local! {
    static RECORDER: RefCell<Recorder> = RefCell::new(Recorder::default());
    // Iop-space varnodes encode the referenced PcodeOp as its Arc data
    // pointer (funcdata.rs new_varnode_iop, mirroring Ghidra's
    // `(uintb)(uintp)op`). The drill formatter needs the op back to print
    // the oracle's deterministic IopSpace::printRaw form ('i' + the
    // referenced op's SeqNum, op.cc:41-47), so registrations are kept per
    // thread, gated on the drill env (zero cost when unset).
    static IOP_REGISTRY: RefCell<std::collections::HashMap<usize, std::sync::Weak<std::sync::RwLock<crate::op::PcodeOp>>>> =
        RefCell::new(std::collections::HashMap::new());
}

/// Record the pointer identity of an iop-referenced op (called from
/// Funcdata::new_varnode_iop).
// RUDRA-GLUE: pointer->op registry for iop varnode printing; Ghidra dereferences `(uintb)(uintp)op` directly in IopSpace::printRaw (op.cc:44), Rust cannot.
pub fn register_iop(ptr: usize, op: &std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>) {
    if !is_enabled() {
        return;
    }
    IOP_REGISTRY.with(|reg| {
        reg.borrow_mut().insert(ptr, std::sync::Arc::downgrade(op));
    });
}

/// Resolve an iop varnode offset back to the referenced op's SeqNum raw
/// text (op.cc:41-47 non-branch form). Returns None when the entry is
/// gone (the referenced op was destroyed).
// RUDRA-GLUE: registry lookup backing the IopSpace::printRaw non-branch form (op.cc:41-47).
pub fn resolve_iop_seq(ptr: u64) -> Option<String> {
    if !is_enabled() {
        return None;
    }
    IOP_REGISTRY.with(|reg| {
        reg.borrow()
            .get(&(ptr as usize))
            .and_then(|weak| weak.upgrade())
            .map(|op| {
                let o = op.read().unwrap();
                crate::drillfmt::seqnum_raw(o.get_addr().as_u64(), o.get_time())
            })
    })
}

static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// RUDRA_STAGE_DRILL gate, evaluated once per process.
// RUDRA-GLUE: process env gate standing in for the OPACTION_DEBUG compile-time switch (types.h:82-97); no runtime Ghidra counterpart.
pub fn is_enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var("RUDRA_STAGE_DRILL").is_ok())
}

/// Bind the formatter's Architecture and reset all recorder state. Called
/// once by the drill driver before the run.
// RUDRA-GLUE: driver-side recorder initialization; Ghidra wires debug state in the Funcdata ctor (funcdata.cc:74-81) + debugEnable (funcdata.hh:600-603).
pub fn start(arch: Arc<Architecture>) {
    if !is_enabled() {
        return;
    }
    RECORDER.with(|rec| {
        let mut rec = rec.borrow_mut();
        *rec = Recorder::default();
        rec.arch = Some(arch);
    });
}

/// Mirror of `Action::perform`'s `debugActivate()` (action.cc:316-318 /
/// 839-841): turn on recording for the upcoming application.
// Ghidra: funcdata.hh:600 Funcdata::debugActivate
pub fn activate() {
    if !is_enabled() {
        return;
    }
    RECORDER.with(|rec| {
        rec.borrow_mut().active = true;
    });
}

/// Mirror of `Funcdata::debugModCheck` (funcdata.cc:1012-1022): if the op
/// has not been touched during this application, mark it and cache its
/// before state. Called from the Funcdata mutation entries before the
/// first actual mutation of the op.
// Ghidra: funcdata.cc:1012 Funcdata::debugModCheck
pub fn mod_check(fd_arch: Option<&Arc<Architecture>>, op: &PcodeOpRef) {
    if !is_enabled() {
        return;
    }
    RECORDER.with(|rec| {
        let mut rec = rec.borrow_mut();
        if !rec.active {
            return;
        }
        let arch = rec
            .arch
            .clone()
            .or_else(|| fd_arch.cloned());
        let Some(arch) = arch else { return };
        {
            let mut o = op.0.write().unwrap();
            if (o.addlflags & op_addl_flags::MODIFIED) != 0 {
                return;
            }
            o.addlflags |= op_addl_flags::MODIFIED;
        }
        let before = {
            let o = op.0.read().unwrap();
            crate::drillfmt::DrillFmt { arch }.op_print_debug(&o)
        };
        rec.modify_list.push(op.clone());
        rec.modify_before.push(before);
    });
}

/// Mirror of `Funcdata::debugModPrint` (funcdata.cc:1035-1057): finish the
/// current application; if any traced op was first-touched, append one
/// complete block — `DEBUG <n>: <name>` header, then per op the cached
/// before line, three spaces, and the CURRENT printDebug (dead ops print
/// `<seqnum>: **` at flush time, exactly like the oracle). Returns true
/// when a block was produced.
// Ghidra: funcdata.cc:1035 Funcdata::debugModPrint
pub fn flush(leaf_name: &str) -> bool {
    if !is_enabled() {
        return false;
    }
    let block = RECORDER.with(|rec| {
        let mut rec = rec.borrow_mut();
        if !rec.active {
            return None;
        }
        rec.active = false;
        if rec.modify_list.is_empty() {
            return None;
        }
        let Some(arch) = rec.arch.clone() else {
            rec.modify_list.clear();
            rec.modify_before.clear();
            return None;
        };
        let fmt = crate::drillfmt::DrillFmt { arch };
        let mut block = format!("DEBUG {}: {}\n", rec.count, leaf_name);
        for (op, before) in rec.modify_list.iter().zip(rec.modify_before.iter()) {
            let after = {
                let o = op.0.read().unwrap();
                fmt.op_print_debug(&o)
            };
            op.0.write().unwrap().addlflags &= !op_addl_flags::MODIFIED;
            block.push_str(before);
            block.push('\n');
            block.push_str("   ");
            block.push_str(&after);
            block.push('\n');
        }
        rec.count += 1;
        rec.modify_list.clear();
        rec.modify_before.clear();
        Some(block)
    });
    match block {
        Some(block) => {
            RECORDER.with(|rec| rec.borrow_mut().blocks.push(block));
            true
        }
        None => false,
    }
}

/// Drain completed application blocks (consumed by the drill driver after
/// each pipeline pause).
// RUDRA-GLUE: sink-side block collection; Ghidra flushes straight into the Architecture debug stream (funcdata.cc:1056 glb->printDebug).
pub fn drain() -> Vec<String> {
    if !is_enabled() {
        return Vec::new();
    }
    RECORDER.with(|rec| std::mem::take(&mut rec.borrow_mut().blocks))
}

/// Current native-count value (diagnostics).
// RUDRA-GLUE: read-only opactdbg_count accessor mirror (funcdata.hh:590 field; no public getter in Ghidra).
pub fn count() -> u64 {
    if !is_enabled() {
        return 0;
    }
    RECORDER.with(|rec| rec.borrow().count)
}
