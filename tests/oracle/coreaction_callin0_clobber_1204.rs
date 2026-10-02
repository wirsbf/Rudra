/*
 * Rudra comparand: CALL in(0) coderef survives ActionDeadCode +
 * ActionVarnodeProps (COREACTION-CALLIN0-CLOBBER-0001).
 *
 * Mirrors the curl E2E inject path (examples/curl_decompile.rs: lift ->
 * inject_raw_ops -> ActionDatabase) on the same function the oracle fixture
 * flows (my_fwrite @0x3460, size 0x62), then runs ActionDeadCode::apply
 * followed by ActionVarnodeProps::apply with heritage pass = 1 — the
 * second-mainloop state in which the clobber fired end-to-end (DECOMPILE
 * prefix 18->19 bisect, w-push88 handoff) and the state Rudra's pass>0 gate
 * in ActionVarnodeProps exposes. Projects the same sorted control-flow
 * target observables as the oracle fixture.
 *
 * The inject path births CPUI_CALL with the static has_callspec flag but no
 * FuncCallSpecs object (the flow-time anchoring gap, CALLSPEC-DRIVER-0001),
 * so the coreaction.cc:3846 "In all cases the first operand is fully
 * consumed" guarantee is provided by ActionDeadCode's spec-less call branch
 * for these calls; with the guarantee, ActionVarnodeProps cc:1327-1341
 * cannot totalReplaceConstant the coderef to const:0 (the FUN_0 clobber).
 */

use rudra::action::Action;
use rudra::address::{calc_mask, Address};
use rudra::coreaction::{ActionDeadCode, ActionDefaultParams, ActionVarnodeProps};
use rudra::disasm::{Disassembler as _, X86Lifter, X86_64Disassembler};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;

/// One control-flow target projection line, sortable by (kind, target) —
/// bank insertion order differs between the flow-driven oracle builder and
/// the inject-driven Rudra builder.
struct Line {
    kind: &'static str,
    target: u64,
    constant: u32,
    consume_full: u32,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: coreaction_callin0_clobber_1204_rudra CURL_BINARY");
        std::process::exit(2);
    }
    let buffer = std::fs::read(&args[1]).expect("read curl binary");
    let obj = goblin::Object::parse(&buffer).expect("parse elf");
    let elf = match &obj {
        goblin::Object::Elf(e) => e,
        _ => {
            eprintln!("not elf");
            std::process::exit(2);
        }
    };

    let target: u64 = 0x3460;
    let size = 0x62usize;
    let mut file_off = 0usize;
    for h in elf.section_headers.iter() {
        if target >= h.sh_addr && target < h.sh_addr + h.sh_size {
            file_off = (h.sh_offset + (target - h.sh_addr)) as usize;
            break;
        }
    }
    let code = &buffer[file_off..file_off + size];

    let mut disasm = X86_64Disassembler::new();
    let instructions = disasm.disassemble(code, Address::new(target)).expect("disassemble");
    let mut lifter = X86Lifter::new();
    let mut raw_ops = Vec::new();
    for inst in &instructions {
        let mut ops = lifter.lift(inst);
        for op in &mut ops {
            op.set_seq_num(rudra::address::SeqNum::new(inst.address, 0));
        }
        raw_ops.extend(ops);
    }

    let mut fd = Funcdata::new("my_fwrite", Address::new(target), size as i32);
    fd.inject_raw_ops(&raw_ops);
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc
        .write()
        .unwrap()
        .set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    // Second-mainloop state: heritage pass 1 opens Rudra's pass>0 gate in
    // ActionVarnodeProps — the exact state the E2E prefix bisect fired in.
    // The oracle fixture runs the same two actions after followFlow, where
    // Ghidra's VarnodeProps has no pass gate (cc:1282-1342).
    {
        let mut fd_write = fd_arc.write().unwrap();
        // Mirror the oracle's base-group ordering: ActionDefaultParams("base")
        // (coreaction.cc:5480) runs before the deadcode group. On the inject
        // path (no FuncCallSpecs) it is a no-op, matching the E2E prefix
        // pipelines where the clobber still fired at prefix 19 pre-fix.
        ActionDefaultParams::new()
            .apply(&mut fd_write)
            .expect("defaultparams apply");
        ActionDeadCode::new().apply(&mut fd_write).expect("deadcode apply");
        fd_write.heritage.pass = 1;
        ActionVarnodeProps::new()
            .apply(&mut fd_write)
            .expect("varnodeprops apply");
    }

    // Collect the control-flow target projections. Inject-path calls carry
    // no FuncCallSpecs: the callee entry address IS the ram-space coderef
    // varnode offset (in(0)), exactly the observable the clobber destroyed.
    // BRANCH/CBRANCH in(0) is the jump target address.
    let fd_read = fd_arc.read().unwrap();
    let mut lines: Vec<Line> = Vec::new();
    for op_ref in fd_read.obank.iter_alive() {
        let op = op_ref.0.read().unwrap();
        let kind = match op.opcode {
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => "call",
            OpCode::CPUI_BRANCH => "branch",
            OpCode::CPUI_CBRANCH => "cbranch",
            _ => continue,
        };
        let Some(in0_arc) = op.inrefs.first() else { continue };
        let in0 = in0_arc.read().unwrap();
        let target = in0.get_offset();
        let full_mask = calc_mask(in0.get_size());
        lines.push(Line {
            kind,
            target,
            constant: if in0.is_constant() { 1 } else { 0 },
            consume_full: if (in0.get_consume() & full_mask) == full_mask {
                1
            } else {
                0
            },
        });
    }
    drop(fd_read);
    lines.sort_by(|a, b| (a.kind, a.target).cmp(&(b.kind, b.target)));
    for line in lines {
        println!(
            "{}:0x{:x} in0_constant={} in0_consume_full={}",
            line.kind, line.target, line.constant, line.consume_full
        );
    }
}
