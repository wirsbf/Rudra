// FUNCDATA-NEWVARNODE-FLAGS-TAIL-0001 (R9-F2 funcdata 租约外两处) fixture —
// Rust side.
//
// Mirrors tests/oracle/funcdata_flags_tail_1204.cc case for case against the
// locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// Funcdata::new_indirect_op (funcdata_op.cc:683-698) and
// Funcdata::new_indirect_creation_in_space (cc:710-728) must apply the
// newVarnode/newVarnodeOut property-flag tail
// (Heritage::apply_new_varnode_flags — funcdata_varnode.cc:148-165/104-127)
// to their in/out varnodes: mapped|addrtied in the ScopeLocal stack window,
// persist inside a Database property band, nothing for out-of-scope unique
// storage.  The free_second_throw case pins the 异常前状态 (pre-exception)
// flags of the stack-window INDIRECT input when the second op_set_input
// panics (Ghidra LowlevelError) inside addDescend.
use std::sync::{Arc, RwLock, RwLockReadGuard};

use rudra::address::{Address, Range};
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::database::Database;
use rudra::funcdata::Funcdata;
use rudra::op::{pcodeop_flags, PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varmap::ScopeLocal;
use rudra::varnode::{varnode_flags, Varnode};

fn read_op(op: &PcodeOpRef) -> RwLockReadGuard<'_, PcodeOp> {
    op.0.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Read a Varnode tolerating lock poisoning: the caught op_set_input panic
/// unwinds through the held write guard, poisoning the RwLock — a Rust
/// unwinding-lock artifact with no Ghidra counterpart; the underlying
/// Varnode state is exactly what the oracle observes after its caught
/// LowlevelError.
fn read_vn(vn: &Arc<RwLock<Varnode>>) -> RwLockReadGuard<'_, Varnode> {
    vn.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn opcode_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_COPY => "COPY",
        OpCode::CPUI_INT_SUB => "INT_SUB",
        // Ghidra's SLEIGH-generated name table aliases CPUI_INDIRECT to
        // its opcode slot's SLEIGH name: "INDIRECT = DELAY_SLOT"
        // (opcodes.cc:26, name row opcodes.cc:45), so get_opname prints
        // DELAY_SLOT for the decompiler's INDIRECT.
        OpCode::CPUI_INDIRECT => "DELAY_SLOT",
        _ => "OTHER",
    }
}

// The C++ comparand's Funcdata ctor creates a real ScopeLocal
// (funcdata.cc:67-73) but leaves FuncProto::localrange/paramrange EMPTY
// (FuncProto::setModel populates neither), so resetLocalWindow installs an
// empty window; the fixture then installs the default-model window
// explicitly via ScopeLocal::addRange — stack params [0,511] plus locals
// [highest-999999, highest] (fspec.cc:2263-2320).  Mirror that state on
// the Rust Funcdata so the constructor's queryProperties sees the same
// input window.
fn install_default_local_scope(fd: &mut Funcdata) {
    let mut scope = ScopeLocal::new();
    scope.space = AddressSpace::Stack;
    scope.local_range = vec![
        (0, 511),
        (0xFFFFFFFFFFFFFFFF - 999999, 0xFFFFFFFFFFFFFFFF),
    ];
    fd.scope = Some(scope);
}

fn catch_set_input_error(
    fd: &mut Funcdata,
    op: &PcodeOpRef,
    vn: &Arc<RwLock<Varnode>>,
    slot: usize,
) -> String {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fd.op_set_input(op, vn.clone(), slot);
    }));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(()) => String::new(),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "non-string panic payload".to_string()),
    }
}

fn main() {
    let mut fd = Funcdata::new("flags_tail", Address::new(0x5000), 0x20);
    install_default_local_scope(&mut fd);
    let b0: Arc<RwLock<BlockBasic>> = Arc::new(RwLock::new(BlockBasic::new(
        0,
        Address::new(0x5000),
    )));
    fd.bblocks.add_block(b0.clone());
    let b0_dyn: Arc<RwLock<dyn FlowBlock + Send + Sync>> = b0.clone();

    let block_order = || -> String {
        let block = b0.read().unwrap();
        block
            .ops
            .iter()
            .map(|op| opcode_name(op.0.read().unwrap().opcode))
            .collect::<Vec<_>>()
            .join(",")
    };

    // case 1: stack-window INDIRECT — in/out both inside [0,511].
    let effect1 = fd.new_op(0, Address::new(0x5010));
    fd.op_set_opcode(&effect1, OpCode::CPUI_INT_SUB);
    fd.op_insert_end(&effect1, &b0_dyn);
    let vn_before = fd.vbank.num_varnodes();
    let ind1 = fd.new_indirect_op(&effect1, AddressSpace::Stack, 0x20, 8, 0);
    let vn_after = fd.vbank.num_varnodes();
    {
        let op = read_op(&ind1);
        let in0 = op.inrefs[0].clone();
        let out = op.output.clone().expect("indirect output");
        println!(
            "case=stack_window_indirect|op={}|opic={}|iss={}|in0={:#x}|in0free={}|in0desc={}|out={:#x}|outwritten={}|outoff={:#x}|outsz={}|vndelta={}|order={}",
            opcode_name(op.opcode),
            u8::from(op.flags & pcodeop_flags::INDIRECT_CREATION != 0),
            u8::from(op.flags & pcodeop_flags::INDIRECT_STORE != 0),
            read_vn(&in0).flags,
            u8::from(read_vn(&in0).is_free()),
            read_vn(&in0).count_descends(),
            read_vn(&out).flags,
            u8::from(read_vn(&out).is_written()),
            read_vn(&out).get_offset(),
            read_vn(&out).get_size(),
            vn_after - vn_before,
            block_order(),
        );
    }

    // Whole-ram persist property band [0x1000,0x2000] (construction-time
    // consultation only — case 1's varnodes must stay un-flagged).
    let mut db = Database::new(false);
    db.set_property_range(
        varnode_flags::PERSIST,
        Range::new(Address::new(0x1000), Address::new(0x2000)).expect("persist range"),
    );
    let mut arch = Architecture::new();
    arch.set_symboltab(Arc::new(RwLock::new(db)));
    fd.set_arch(Arc::new(arch));

    // case 2: persist-band INDIRECT at ram 0x1000.
    let effect2 = fd.new_op(0, Address::new(0x5011));
    fd.op_set_opcode(&effect2, OpCode::CPUI_INT_SUB);
    fd.op_insert_end(&effect2, &b0_dyn);
    let vn_before = fd.vbank.num_varnodes();
    let ind2 = fd.new_indirect_op(&effect2, AddressSpace::Ram, 0x1000, 4, 0);
    let vn_after = fd.vbank.num_varnodes();
    let ind1_in0;
    {
        let op1 = read_op(&ind1);
        ind1_in0 = op1.inrefs[0].clone();
    }
    {
        let op = read_op(&ind2);
        let in0 = op.inrefs[0].clone();
        let out = op.output.clone().expect("indirect output");
        println!(
            "case=persist_band_indirect|in0={:#x}|in0desc={}|out={:#x}|outoff={:#x}|outsz={}|vndelta={}|in0_stable={:#x}|order={}",
            read_vn(&in0).flags,
            read_vn(&in0).count_descends(),
            read_vn(&out).flags,
            read_vn(&out).get_offset(),
            read_vn(&out).get_size(),
            vn_after - vn_before,
            read_vn(&ind1_in0).flags,
            block_order(),
        );
    }

    // case 3: persist-band INDIRECT-creation, possibleout=false.
    let vn_before = fd.vbank.num_varnodes();
    let c1 = fd.new_indirect_creation_in_space(&effect2, AddressSpace::Ram, 0x1008, 4, false);
    let vn_after = fd.vbank.num_varnodes();
    {
        let op = read_op(&c1);
        let in0 = op.inrefs[0].clone();
        let out = op.output.clone().expect("creation output");
        println!(
            "case=persist_band_creation_false|opic={}|in0={:#x}|in0desc={}|out={:#x}|outwritten={}|vndelta={}|order={}",
            u8::from(op.flags & pcodeop_flags::INDIRECT_CREATION != 0),
            read_vn(&in0).flags,
            read_vn(&in0).count_descends(),
            read_vn(&out).flags,
            u8::from(read_vn(&out).is_written()),
            vn_after - vn_before,
            block_order(),
        );
    }

    // case 4: possibleout=true — in0 keeps no indirect_creation.
    let c2 = fd.new_indirect_creation_in_space(&effect2, AddressSpace::Ram, 0x1010, 4, true);
    {
        let op = read_op(&c2);
        let in0 = op.inrefs[0].clone();
        let out = op.output.clone().expect("creation output");
        println!(
            "case=persist_band_creation_true|in0={:#x}|out={:#x}|outsz={}",
            read_vn(&in0).flags,
            read_vn(&out).flags,
            read_vn(&out).get_size(),
        );
    }

    // case 5: control — unique 0x700 is in no scope and no band.
    let c3 = fd.new_indirect_creation_in_space(&effect2, AddressSpace::Unique, 0x700, 4, false);
    {
        let op = read_op(&c3);
        let out = op.output.clone().expect("creation output");
        println!(
            "case=unique_creation_false|out={:#x}|outoff={:#x}",
            read_vn(&out).flags,
            read_vn(&out).get_offset(),
        );
    }

    // case 6: 异常前状态 — second op_set_input of the free stack-window
    // INDIRECT input panics (Ghidra: LowlevelError from addDescend) after
    // the old slot's descend was erased.
    let other = fd.new_op(0, Address::new(0x5020));
    fd.op_set_opcode(&other, OpCode::CPUI_COPY);
    let dummy = fd.new_constant(8, 0x77);
    fd.op_insert_input(&other, dummy.clone(), 0);
    let vn_before = fd.vbank.num_varnodes();
    let throw_error = catch_set_input_error(&mut fd, &other, &ind1_in0, 0);
    let vn_after = fd.vbank.num_varnodes();
    println!(
        "case=free_second_throw|err={throw_error}|in0={:#x}|in0desc={}|dummy_desc={}|vndelta={}",
        read_vn(&ind1_in0).flags,
        read_vn(&ind1_in0).count_descends(),
        read_vn(&dummy).count_descends(),
        vn_after - vn_before,
    );
}
