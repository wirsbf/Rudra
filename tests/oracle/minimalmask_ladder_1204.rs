// MINIMALMASK-LADDER-CONSUMERS-0001: Rugra side of the locked Ghidra 12.0.4
// minimalmask bilateral fixture. Mirrors minimalmask_ladder_1204.cc case for
// case, driving the production code only:
//
//   - `rudra::address::minimalmask` (address.hh:525-534 whole-byte ladder);
//   - `ActionDeadCode::mark_consumed_parameters` (coreaction.cc:3840, the
//     cc:3856 ladder read + autolive bypass + locked full-consume return +
//     inputBytesConsumed AND-gate);
//   - `ActionDeadCode::gather_consumed_return` (coreaction.cc:3871, OR
//     accumulation + dead/slot guards + output-lock return + bytes gate);
//   - `JumpTable::fold_in_normalization` (jumptable.cc:2574, the
//     switch_var_consume ladder read + full-mask SEXT gate + JumpBasic's
//     BRANCHIND in(0) rewrite jumptable.cc:1551).
//
// The runner makes mark_consumed_parameters/gather_consumed_return public in
// an isolated source snapshot only (the action_deadcode_selfloop visibility
// transform precedent); the live crate is untouched.
//
// NZMask seeding is prestate: constants carry their value natively
// (Varnode::new_with_space mirrors varnode.cc:597) and the two written switch
// variables get `nzm` assigned directly — the three consumers only read
// get_nz_mask().

use std::sync::Arc;

use rudra::address::{calc_mask, minimalmask, Address};
use rudra::coreaction::ActionDeadCode;
use rudra::funcdata::Funcdata;
use rudra::fspec::{FuncCallSpecs, FuncProto};
use rudra::jumptable::{JumpBasic, JumpTable};
use rudra::opcodes::OpCode;
use rudra::varnode::Varnode;

type VarnodeRef = Arc<std::sync::RwLock<Varnode>>;

fn hex16(val: u64) -> String {
    format!("{:016x}", val)
}

fn observe_param(nm: &str, vn: &VarnodeRef, worklist: &[VarnodeRef]) {
    let inlist = worklist.iter().any(|v| Arc::ptr_eq(v, vn));
    let rg = vn.read().unwrap();
    println!(
        "param|{}|size={}|nzm={}|mm={}|consume={}|vac={}|lis={}|inwl={}",
        nm,
        rg.get_size(),
        hex16(rg.get_nz_mask()),
        hex16(minimalmask(rg.get_nz_mask())),
        hex16(rg.get_consume()),
        u8::from(rg.is_consume_vacuous()),
        u8::from(rg.is_consume_list()),
        u8::from(inlist),
    );
}

// Per-case prestate reset mirroring ActionDeadCode::apply's reset loop
// (coreaction.cc:3939-3946): Varnodes are born with consume=~0 and production
// zeroes the field before any consumer pushes.
fn reset_consumed(fd: &Funcdata) {
    let all: Vec<VarnodeRef> = fd
        .vbank
        .loc_tree
        .iter()
        .map(|entry| entry.0.clone())
        .collect();
    for vn in all {
        let mut rg = vn.write().unwrap();
        rg.clear_consume_list();
        rg.clear_consume_vacuous();
        rg.set_consume(0);
    }
}

fn main() {
    let mut fd = Funcdata::new("minimalmask", Address::new(0x1000), 0);

    // ---- ladder: the address.hh:525-534 whole-byte boundaries ----
    {
        let vals: [u64; 12] = [
            0x0,
            0x1,
            0xff,
            0x100,
            0x7ff,
            0xffff,
            0x10000,
            0x7fffffff,
            0xffffffff,
            0x100000000,
            0x7fffffffffffffff,
            0xffffffffffffffff,
        ];
        println!("case ladder");
        for val in vals {
            println!("ladder|val={}|mm={}", hex16(val), hex16(minimalmask(val)));
        }
        println!("end");
    }

    // ---- markConsumedParameters, nominal ladder parameters ----
    {
        println!("case callparams_nominal");
        let target = fd.new_constant(8, 0);
        let p1 = fd.new_constant(1, 0x0); // mm 0xff == calc_mask(1)
        let p2 = fd.new_constant(2, 0xff); // boundary >0xff -> 0xffff
        let p3 = fd.new_constant(4, 0x100); // >0xffff -> 0xffffffff
        let p4 = fd.new_constant(4, 0x7ff); // >0xff only -> 0xffff (partial)
        let p5 = fd.new_constant(8, 0xffffffff); // 0xffffffff < full 8-byte
        let p6 = fd.new_constant(8, 0x100000000); // >0xffffffff -> ~0
        let copy = fd.new_op(1, Address::new(0x1100));
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        let p7 = fd.new_unique_out(2, &copy); // written: worklist entry
        p7.write().unwrap().nzm = 0x100;
        let copy_in = fd.new_constant(2, 0x100);
        fd.op_set_input(&copy, copy_in, 0);
        let call = fd.new_op(8, Address::new(0x1200));
        fd.op_set_opcode(&call, OpCode::CPUI_CALL);
        fd.op_set_input(&call, target.clone(), 0);
        fd.op_set_input(&call, p1.clone(), 1);
        fd.op_set_input(&call, p2.clone(), 2);
        fd.op_set_input(&call, p3.clone(), 3);
        fd.op_set_input(&call, p4.clone(), 4);
        fd.op_set_input(&call, p5.clone(), 5);
        fd.op_set_input(&call, p6.clone(), 6);
        fd.op_set_input(&call, p7.clone(), 7);
        let fc = Arc::new(std::sync::RwLock::new(FuncCallSpecs::new_for_op(
            &call,
            default_proto(),
        )));
        reset_consumed(&fd);
        let mut worklist: Vec<VarnodeRef> = Vec::new();
        ActionDeadCode::mark_consumed_parameters(&fd, &fc.read().unwrap(), &mut worklist);
        observe_param("target", &target, &worklist);
        observe_param("p1", &p1, &worklist);
        observe_param("p2", &p2, &worklist);
        observe_param("p3", &p3, &worklist);
        observe_param("p4", &p4, &worklist);
        observe_param("p5", &p5, &worklist);
        observe_param("p6", &p6, &worklist);
        observe_param("p7", &p7, &worklist);
        println!("worklist|size={}", worklist.len());
        println!("end");
    }

    // ---- markConsumedParameters, inputBytesConsumed AND-gate (cc:3857-3859) ----
    {
        println!("case callparams_bytesgate");
        let target = fd.new_constant(8, 0);
        let q1 = fd.new_constant(4, 0x100); // gate 1 byte
        let q2 = fd.new_constant(4, 0x101); // gate 2 bytes (distinct: bank dedups equal constants)
        let q3 = fd.new_constant(2, 0x0); // no hint: ladder only
        let q4 = fd.new_constant(8, 0xffffffff); // gate 8 bytes: caps at ladder
        let call = fd.new_op(5, Address::new(0x1300));
        fd.op_set_opcode(&call, OpCode::CPUI_CALL);
        fd.op_set_input(&call, target, 0);
        fd.op_set_input(&call, q1.clone(), 1);
        fd.op_set_input(&call, q2.clone(), 2);
        fd.op_set_input(&call, q3.clone(), 3);
        fd.op_set_input(&call, q4.clone(), 4);
        let fc = Arc::new(std::sync::RwLock::new(FuncCallSpecs::new_for_op(
            &call,
            default_proto(),
        )));
        fc.write().unwrap().set_input_bytes_consumed(1, 1);
        fc.write().unwrap().set_input_bytes_consumed(2, 2);
        fc.write().unwrap().set_input_bytes_consumed(4, 8);
        reset_consumed(&fd);
        let mut worklist: Vec<VarnodeRef> = Vec::new();
        ActionDeadCode::mark_consumed_parameters(&fd, &fc.read().unwrap(), &mut worklist);
        observe_param("q1", &q1, &worklist);
        observe_param("q2", &q2, &worklist);
        observe_param("q3", &q3, &worklist);
        observe_param("q4", &q4, &worklist);
        println!("end");
    }

    // ---- markConsumedParameters, autolive bypass (cc:3853-3854) ----
    {
        println!("case callparams_autolive");
        let target = fd.new_constant(8, 0);
        let a1 = fd.new_constant(4, 0x100);
        a1.write().unwrap().set_auto_live_hold();
        let call = fd.new_op(2, Address::new(0x1400));
        fd.op_set_opcode(&call, OpCode::CPUI_CALL);
        fd.op_set_input(&call, target, 0);
        fd.op_set_input(&call, a1.clone(), 1);
        let fc = Arc::new(std::sync::RwLock::new(FuncCallSpecs::new_for_op(
            &call,
            default_proto(),
        )));
        reset_consumed(&fd);
        let mut worklist: Vec<VarnodeRef> = Vec::new();
        ActionDeadCode::mark_consumed_parameters(&fd, &fc.read().unwrap(), &mut worklist);
        observe_param("a1", &a1, &worklist);
        println!("end");
    }

    // ---- markConsumedParameters, locked-prototype full consume (cc:3845-3849) ----
    {
        println!("case callparams_inputlock");
        let target = fd.new_constant(8, 0);
        let l1 = fd.new_constant(4, 0x7ff);
        let l2 = fd.new_constant(2, 0xff);
        let call = fd.new_op(3, Address::new(0x1500));
        fd.op_set_opcode(&call, OpCode::CPUI_CALL);
        fd.op_set_input(&call, target, 0);
        fd.op_set_input(&call, l1.clone(), 1);
        fd.op_set_input(&call, l2.clone(), 2);
        let fc = Arc::new(std::sync::RwLock::new(FuncCallSpecs::new_for_op(
            &call,
            default_proto(),
        )));
        fc.write().unwrap().prototype.set_input_lock(true);
        reset_consumed(&fd);
        let mut worklist: Vec<VarnodeRef> = Vec::new();
        ActionDeadCode::mark_consumed_parameters(&fd, &fc.read().unwrap(), &mut worklist);
        observe_param("l1", &l1, &worklist);
        observe_param("l2", &l2, &worklist);
        println!("end");
    }

    // ---- gatherConsumedReturn: OR accumulation + loop guards (cc:3879-3886) ----
    {
        println!("case returns_basic");
        let rblock = fd.create_new_block();
        let r1 = fd.new_op(2, Address::new(0x1600));
        fd.op_set_opcode(&r1, OpCode::CPUI_RETURN);
        let r1_in0 = fd.new_constant(8, 0);
        let r1_in1 = fd.new_constant(2, 0x100); // mm 0xffff
        fd.op_set_input(&r1, r1_in0, 0);
        fd.op_set_input(&r1, r1_in1, 1);
        fd.op_insert_end(&r1, &rblock);
        let r2 = fd.new_op(2, Address::new(0x1700));
        fd.op_set_opcode(&r2, OpCode::CPUI_RETURN);
        let r2_in0 = fd.new_constant(8, 0);
        let r2_in1 = fd.new_constant(4, 0x10000); // mm 0xffffffff
        fd.op_set_input(&r2, r2_in0, 0);
        fd.op_set_input(&r2, r2_in1, 1);
        fd.op_insert_end(&r2, &rblock);
        let r3 = fd.new_op(1, Address::new(0x1800)); // numInput()==1: skipped
        fd.op_set_opcode(&r3, OpCode::CPUI_RETURN);
        let r3_in0 = fd.new_constant(8, 0);
        fd.op_set_input(&r3, r3_in0, 0);
        fd.op_insert_end(&r3, &rblock);
        let r4 = fd.new_op(2, Address::new(0x1900)); // dead: skipped
        fd.op_set_opcode(&r4, OpCode::CPUI_RETURN);
        let r4_in0 = fd.new_constant(8, 0);
        let r4_in1 = fd.new_constant(8, 0x100000000);
        fd.op_set_input(&r4, r4_in0, 0);
        fd.op_set_input(&r4, r4_in1, 1);
        fd.op_insert_end(&r4, &rblock);
        fd.op_destroy(&r4);
        println!(
            "gather|consume={}",
            hex16(ActionDeadCode::gather_consumed_return(&fd))
        );
        println!("end");
    }

    // ---- gatherConsumedReturn: returnBytesConsumed AND-gate (cc:3887-3890).
    // Hints shrink 2 -> 1 (setReturnBytesConsumed keeps the smallest). ----
    {
        println!("case returns_bytes");
        fd.get_func_proto_mut().set_return_bytes_consumed(2);
        println!(
            "gather|bytes=2|consume={}",
            hex16(ActionDeadCode::gather_consumed_return(&fd))
        );
        fd.get_func_proto_mut().set_return_bytes_consumed(1);
        println!(
            "gather|bytes=1|consume={}",
            hex16(ActionDeadCode::gather_consumed_return(&fd))
        );
        println!("end");
    }

    // ---- gatherConsumedReturn: output-lock early return (cc:3874-3875) ----
    {
        println!("case returns_outputlock");
        fd.get_func_proto_mut().set_output_lock(true);
        println!(
            "gather|consume={}",
            hex16(ActionDeadCode::gather_consumed_return(&fd))
        );
        fd.get_func_proto_mut().set_output_lock(false);
        println!("end");
    }

    // ---- foldInNormalization gate forms (jumptable.cc:2574-2591) ----
    {
        println!("case foldin");
        // f1: 1-byte unwritten switchvar — minimalmask >= calc_mask(1) always.
        {
            let sv = fd.new_constant(1, 0x0);
            let bi = fd.new_op(1, Address::new(0x2000));
            fd.op_set_opcode(&bi, OpCode::CPUI_BRANCHIND);
            let bi_in0 = fd.new_constant(1, 0);
            fd.op_set_input(&bi, bi_in0, 0);
            let mut jt = JumpTable::new(Address::new(0x2000));
            let mut model = Box::new(JumpBasic::new());
            model.switchvn = Some(sv.clone());
            jt.jmodel = Some(model);
            jt.indirect = Some(bi.0.clone());
            jt.fold_in_normalization(&mut fd);
            let (size, nzm, consume) = {
                let rg = sv.read().unwrap();
                (rg.get_size(), rg.get_nz_mask(), jt.get_switch_var_consume())
            };
            let in0isswitch = bi
                .0
                .read()
                .unwrap()
                .get_in(0)
                .is_some_and(|v| Arc::ptr_eq(v, &sv));
            println!(
                "foldin|f=unwritten_1byte|size={}|nzm={}|consume={}|gate={}|in0isswitch={}",
                size,
                hex16(nzm),
                hex16(consume),
                u8::from(minimalmask(nzm) >= calc_mask(size)),
                u8::from(in0isswitch),
            );
        }
        // f2: 4-byte switchvar written by SEXT of a 1-byte value — gate
        // fires -> consume truncated to calc_mask(1).
        {
            let sext = fd.new_op(1, Address::new(0x2100));
            fd.op_set_opcode(&sext, OpCode::CPUI_INT_SEXT);
            let sv = fd.new_unique_out(4, &sext);
            sv.write().unwrap().nzm = 0xffffffff;
            let sext_in = fd.new_constant(1, 0x7f);
            fd.op_set_input(&sext, sext_in, 0);
            let bi = fd.new_op(1, Address::new(0x2110));
            fd.op_set_opcode(&bi, OpCode::CPUI_BRANCHIND);
            let bi_in0 = fd.new_constant(4, 0);
            fd.op_set_input(&bi, bi_in0, 0);
            let mut jt = JumpTable::new(Address::new(0x2110));
            let mut model = Box::new(JumpBasic::new());
            model.switchvn = Some(sv.clone());
            jt.jmodel = Some(model);
            jt.indirect = Some(bi.0.clone());
            jt.fold_in_normalization(&mut fd);
            let (size, nzm, consume) = {
                let rg = sv.read().unwrap();
                (rg.get_size(), rg.get_nz_mask(), jt.get_switch_var_consume())
            };
            let in0isswitch = bi
                .0
                .read()
                .unwrap()
                .get_in(0)
                .is_some_and(|v| Arc::ptr_eq(v, &sv));
            println!(
                "foldin|f=sext_4byte|size={}|nzm={}|consume={}|gate={}|in0isswitch={}",
                size,
                hex16(nzm),
                hex16(consume),
                u8::from(minimalmask(nzm) >= calc_mask(size)),
                u8::from(in0isswitch),
            );
        }
        // f3: same shape but written by COPY — the SEXT arm must not fire.
        {
            let cp = fd.new_op(1, Address::new(0x2200));
            fd.op_set_opcode(&cp, OpCode::CPUI_COPY);
            let sv = fd.new_unique_out(4, &cp);
            sv.write().unwrap().nzm = 0xffffffff;
            let cp_in = fd.new_constant(4, 0xffffffff);
            fd.op_set_input(&cp, cp_in, 0);
            let bi = fd.new_op(1, Address::new(0x2210));
            fd.op_set_opcode(&bi, OpCode::CPUI_BRANCHIND);
            let bi_in0 = fd.new_constant(4, 0);
            fd.op_set_input(&bi, bi_in0, 0);
            let mut jt = JumpTable::new(Address::new(0x2210));
            let mut model = Box::new(JumpBasic::new());
            model.switchvn = Some(sv.clone());
            jt.jmodel = Some(model);
            jt.indirect = Some(bi.0.clone());
            jt.fold_in_normalization(&mut fd);
            let (size, nzm, consume) = {
                let rg = sv.read().unwrap();
                (rg.get_size(), rg.get_nz_mask(), jt.get_switch_var_consume())
            };
            let in0isswitch = bi
                .0
                .read()
                .unwrap()
                .get_in(0)
                .is_some_and(|v| Arc::ptr_eq(v, &sv));
            println!(
                "foldin|f=copy_4byte|size={}|nzm={}|consume={}|gate={}|in0isswitch={}",
                size,
                hex16(nzm),
                hex16(consume),
                u8::from(minimalmask(nzm) >= calc_mask(size)),
                u8::from(in0isswitch),
            );
        }
        // f4: 8-byte switchvar by SEXT of 4 bytes — the ladder does NOT
        // cover an 8-byte var: gate stays 0, no SEXT truncation.
        {
            let sext = fd.new_op(1, Address::new(0x2300));
            fd.op_set_opcode(&sext, OpCode::CPUI_INT_SEXT);
            let sv = fd.new_unique_out(8, &sext);
            sv.write().unwrap().nzm = 0xffffffff;
            let sext_in = fd.new_constant(4, 0x7fffffff);
            fd.op_set_input(&sext, sext_in, 0);
            let bi = fd.new_op(1, Address::new(0x2310));
            fd.op_set_opcode(&bi, OpCode::CPUI_BRANCHIND);
            let bi_in0 = fd.new_constant(8, 0);
            fd.op_set_input(&bi, bi_in0, 0);
            let mut jt = JumpTable::new(Address::new(0x2310));
            let mut model = Box::new(JumpBasic::new());
            model.switchvn = Some(sv.clone());
            jt.jmodel = Some(model);
            jt.indirect = Some(bi.0.clone());
            jt.fold_in_normalization(&mut fd);
            let (size, nzm, consume) = {
                let rg = sv.read().unwrap();
                (rg.get_size(), rg.get_nz_mask(), jt.get_switch_var_consume())
            };
            let in0isswitch = bi
                .0
                .read()
                .unwrap()
                .get_in(0)
                .is_some_and(|v| Arc::ptr_eq(v, &sv));
            println!(
                "foldin|f=sext_8byte_partial|size={}|nzm={}|consume={}|gate={}|in0isswitch={}",
                size,
                hex16(nzm),
                hex16(consume),
                u8::from(minimalmask(nzm) >= calc_mask(size)),
                u8::from(in0isswitch),
            );
        }
        // f5: 2-byte switchvar by SEXT of 1 byte — boundary where the ladder
        // (0xffff for nzm 0x100) exactly equals calc_mask(2): gate fires -> 0xff.
        {
            let sext = fd.new_op(1, Address::new(0x2400));
            fd.op_set_opcode(&sext, OpCode::CPUI_INT_SEXT);
            let sv = fd.new_unique_out(2, &sext);
            sv.write().unwrap().nzm = 0x100;
            let sext_in = fd.new_constant(1, 0x7f);
            fd.op_set_input(&sext, sext_in, 0);
            let bi = fd.new_op(1, Address::new(0x2410));
            fd.op_set_opcode(&bi, OpCode::CPUI_BRANCHIND);
            let bi_in0 = fd.new_constant(2, 0);
            fd.op_set_input(&bi, bi_in0, 0);
            let mut jt = JumpTable::new(Address::new(0x2410));
            let mut model = Box::new(JumpBasic::new());
            model.switchvn = Some(sv.clone());
            jt.jmodel = Some(model);
            jt.indirect = Some(bi.0.clone());
            jt.fold_in_normalization(&mut fd);
            let (size, nzm, consume) = {
                let rg = sv.read().unwrap();
                (rg.get_size(), rg.get_nz_mask(), jt.get_switch_var_consume())
            };
            let in0isswitch = bi
                .0
                .read()
                .unwrap()
                .get_in(0)
                .is_some_and(|v| Arc::ptr_eq(v, &sv));
            println!(
                "foldin|f=sext_2byte_from1|size={}|nzm={}|consume={}|gate={}|in0isswitch={}",
                size,
                hex16(nzm),
                hex16(consume),
                u8::from(minimalmask(nzm) >= calc_mask(size)),
                u8::from(in0isswitch),
            );
        }
        println!("end");
    }
}

// The Ghidra FuncCallSpecs ctor base-initializes `: FuncProto()` (fspec.cc
// :4926) — an unlocked, parameter-less prototype. new_for_op ignores its
// caller_funcp argument, so this mirrors the oracle construction.
fn default_proto() -> FuncProto {
    use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
    FuncProto::new(
        String::new(),
        Arc::new(Datatype::Void(TypeBase::new(
            "void".to_string(),
            0,
            TypeMetatype::Void,
        ))),
    )
}
