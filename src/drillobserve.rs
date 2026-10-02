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
// Ghidra: op.cc:41 IopSpace::printRaw (non-branch arm; env-gated drill registry lookup)
pub fn resolve_iop_seq(ptr: u64) -> Option<String> {
    if !is_enabled() {
        return None;
    }
    lookup_iop_op(ptr).map(|op| {
        let o = op.read().unwrap();
        crate::drillfmt::seqnum_raw(o.get_addr().as_u64(), o.get_time())
    })
}

/// Shared ungated registry lookup: resolve an iop varnode offset (the
/// referenced op's Arc data pointer) back to the op handle, or None when
/// the entry is gone (the referenced op was destroyed).
// RUDRA-GLUE: registry lookup helper; Ghidra dereferences `(uintb)(uintp)op` directly in IopSpace::printRaw (op.cc:46), Rust cannot.
fn lookup_iop_op(ptr: u64) -> Option<Arc<std::sync::RwLock<crate::op::PcodeOp>>> {
    IOP_REGISTRY.with(|reg| {
        reg.borrow()
            .get(&(ptr as usize))
            .and_then(|weak| weak.upgrade())
    })
}

/// The full `IopSpace::printRaw` dispatch (op.cc:41-59) for the legacy
/// enum print path (`AddressSpace::print_raw_offset_arch`): resolve the
/// offset's registered op, then the non-branch arm prints the op's
/// SeqNum (op.cc:48-50, `s << op->getSeqNum(); return;`), the branch arm
/// prints `code_` + the target block's start shortcut + start printRaw
/// (op.cc:52-58) — with two out edges the printed block is
/// `op->isFallthruTrue() ? bs->getOut(0) : bs->getOut(1))` (the
/// non-fallthru condition), else `bs->getOut(0)`.
///
/// The lookup is ungated by design: registrations stay behind the
/// RUDRA_STAGE_DRILL gate (`register_iop`), so in production runs the
/// registry is empty and this returns None — identical observable
/// behavior to a gated lookup — while unit fixtures can populate the
/// thread-local registry directly without fighting the once-latched env
/// switch. None is also the mapping for the oracle's dangling-deref arm
/// (offset whose referenced op was destroyed — UB in C++), which the
/// caller turns into its deterministic base-form fallback.
// Ghidra: op.cc:41 IopSpace::printRaw
pub fn resolve_iop_printraw(offset: u64) -> Option<String> {
    // PcodeOp *op = (PcodeOp *)(uintp)offset; // Treat offset as op
    let op = lookup_iop_op(offset)?;
    let o = op.read().unwrap();
    // if (!op->isBranch()) { s << op->getSeqNum(); return; }
    if !o.is_branch() {
        return Some(crate::drillfmt::seqnum_raw(o.get_addr().as_u64(), o.get_time()));
    }
    // bs = op->getParent();
    let parent = o.parent.as_ref().and_then(std::sync::Weak::upgrade)?;
    let bs = parent.read().unwrap();
    // if (bs->sizeOut()==2) bl = (BlockBasic *)(op->isFallthruTrue() ?
    //   bs->getOut(0) : bs->getOut(1)); else bl = (BlockBasic
    //   *)bs->getOut(0);
    let slot = if bs.size_out() == 2 {
        usize::from(!o.is_fallthru_true())
    } else {
        0
    };
    let edge = bs.get_out(slot)?;
    let bl_arc = bs.bank().expect_arc(edge.point);
    let bl = bl_arc.read().unwrap();
    // s << "code_" << bl->getStart().getShortcut();
    // bl->getStart().printRaw(s);
    let start = bl.get_start_addr();
    let sa = start.to_space_address();
    let (shortcut, raw) = if sa.is_invalid() {
        // Spaceless legacy code address: the single-arch x86-64 mirror's
        // code space is ram (the same projection as the heritage.rs
        // warnop form — a spaceless code address prints through the ram
        // arm, 'r' + the base padded form).
        (
            crate::space::AddressSpace::Ram.shortcut(),
            crate::space::AddressSpace::Ram.print_raw_offset(start.as_u64()),
        )
    } else {
        (sa.get_shortcut(), sa.print_raw())
    };
    Some(format!("code_{}{}", shortcut, raw))
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

// ---- resolve_iop_printraw 两形单测（op.cc:41-59，VNPRINT-JOINIOP 收口;
// 机制 B2 记录: Rudra 侧回归覆盖，oracle 锚 = Ghidra_12.0.4_build
// e40ed130 op.cc:41-59，本 session 亲读。注册表为 thread_local——测试线程
// 各自独立注册，无跨测污染）----
#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, SeqNum};
    use crate::block::{BlockBasic, BlockGraph};
    use crate::op::{pcodeop_flags, PcodeOp};
    use crate::opcodes::OpCode;
    use std::sync::{Arc, RwLock};

    type BlockArc = Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>;

    /// 以 funcdata new_varnode_iop 同形（Arc 数据指针身份）注入注册表,
    /// 返回该指针作为 iop 偏移。
    fn inject(op: &Arc<RwLock<PcodeOp>>) -> u64 {
        let ptr = Arc::as_ptr(op) as usize;
        IOP_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(ptr, Arc::downgrade(op));
        });
        ptr as u64
    }

    #[test]
    fn test_resolve_iop_printraw_non_branch_seqnum_form() {
        // op.cc:48-50: !isBranch() → `s << op->getSeqNum()` 即
        // `<pc.printRaw>:<uniq-hex>`（address.cc:32-38;pc 基类形 >>32==0
        // → sz4 → `0x00401000`,uniq 5 → `5`）。
        let op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x401000), 5),
            OpCode::CPUI_COPY,
        )));
        let off = inject(&op);
        assert_eq!(resolve_iop_printraw(off).unwrap(), "0x00401000:5");
    }

    #[test]
    fn test_resolve_iop_printraw_unregistered_returns_none() {
        // 生产形（drill env 未设 → 注册表空）与悬空指针臂（oracle UB）
        // 的确定性 None。
        assert!(resolve_iop_printraw(0xdead_beef).is_none());
    }

    /// op.cc:52-58 分支形夹具:父块 0x5000（双出边 out(0)=0x6000 /
    /// out(1)=0x7000 或单出边）+ BRANCH 旗标 op（fallthru_true 可选）。
    /// 返回 (iop 偏移, graph, op Arc)——三者必须由测试持有存活:graph
    /// 撑 op.parent 的 Weak,op Arc 撑注册表 Weak（悬空 = oracle 已删
    /// 对象臂,返回 None）。
    fn branch_fixture(two_out: bool, fallthru_true: bool)
        -> (u64, BlockGraph, Arc<RwLock<PcodeOp>>) {
        let mut graph = BlockGraph::new();
        let a: BlockArc = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
        let b: BlockArc = Arc::new(RwLock::new(BlockBasic::new(1, Address::new(0x6000))));
        let c: BlockArc = Arc::new(RwLock::new(BlockBasic::new(2, Address::new(0x7000))));
        graph.add_block(a.clone());
        graph.add_block(b.clone());
        graph.add_block(c.clone());
        graph.add_edge(a.clone(), b.clone());
        if two_out {
            graph.add_edge(a.clone(), c.clone());
        }
        let mut op = PcodeOp::new(
            SeqNum::new(Address::new(0x5008), 1),
            OpCode::CPUI_CBRANCH,
        );
        op.flags |= pcodeop_flags::BRANCH;
        if fallthru_true {
            op.flags |= pcodeop_flags::FALLTHRU_TRUE;
        }
        op.parent = Some(Arc::downgrade(&a));
        let op = Arc::new(RwLock::new(op));
        (inject(&op), graph, op)
    }

    #[test]
    fn test_resolve_iop_printraw_branch_two_out_fallthru_true_picks_out0() {
        // op.cc:53-54: sizeOut()==2 → isFallthruTrue() ? getOut(0) :
        // getOut(1)——印的是非落穿条件块;fallthru_true → out(0)=0x6000。
        // `code_` + 起始地址 shortcut（镜面码空间=ram,'r'）+ 起始地址
        // printRaw（基类形 `0x00006000`）。
        let (off, _graph, _op) = branch_fixture(true, true);
        assert_eq!(resolve_iop_printraw(off).unwrap(), "code_r0x00006000");
    }

    #[test]
    fn test_resolve_iop_printraw_branch_two_out_not_fallthru_true_picks_out1() {
        // 非 fallthru_true → out(1)=0x7000。
        let (off, _graph, _op) = branch_fixture(true, false);
        assert_eq!(resolve_iop_printraw(off).unwrap(), "code_r0x00007000");
    }

    #[test]
    fn test_resolve_iop_printraw_branch_single_out_picks_out0() {
        // op.cc:55-56: sizeOut()!=2 → getOut(0)。
        let (off, _graph, _op) = branch_fixture(false, false);
        assert_eq!(resolve_iop_printraw(off).unwrap(), "code_r0x00006000");
    }
}
