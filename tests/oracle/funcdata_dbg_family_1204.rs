// FUNCDATA-DBGFAMILY-0001 bilateral fixture — Rust side.
//
// Mirrors tests/oracle/funcdata_dbg_family_1204.cc case for case against a
// locked -DOPACTION_DEBUG oracle build (Ghidra_12.0.4_build
// e40ed13014025f82488b1f8f7bca566894ac376b). The Rust debug members are
// always compiled and gated on opactdbg_on exactly like the oracle's debug
// build; debug_print_range returns the message (the sink is the caller's).
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::{space_flags, AddrSpace, SpaceType};

fn jtcb(_orig: &mut Funcdata, _fd: &mut Funcdata) {}

fn main() {
    // The .cc fixture's ops and debug ranges carry the ram space
    // (Address(ram, ...)); the Rust mirror uses the tagged form so
    // isInvalid() agrees (spaceless = Ghidra's null-base invalid form).
    let ram = AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        3,
        space_flags::HASPHYSICAL,
        0,
        0,
    );
    let ram_addr = |off: u64| Address::with_space(&ram, off);
    let mut fd = Funcdata::new("dbg_family", Address::new(0x5000), 0x20);
    let b0: Arc<RwLock<BlockBasic>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(b0.clone());
    let b0_dyn: Arc<RwLock<dyn FlowBlock + Send + Sync>> = b0.clone();
    let op1 = fd.new_op(1, ram_addr(0x5010));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    fd.op_insert_end(&op1, &b0_dyn);
    let op2 = fd.new_op(1, ram_addr(0x5030));
    fd.op_set_opcode(&op2, OpCode::CPUI_INT_ADD);
    fd.op_insert_end(&op2, &b0_dyn);

    // case=debug_lifecycle: enable/size/clear/disable and the break knobs.
    {
        fd.debug_enable();
        let size_on = fd.debug_size();
        fd.debug_set_range(ram_addr(0x5010), ram_addr(0x5020), u32::MAX, u32::MAX);
        let size_r1 = fd.debug_size();
        fd.debug_clear();
        let size_cleared = fd.debug_size();
        fd.debug_disable();
        let on_after_disable = fd.opactdbg_on as u8;
        fd.debug_set_break(5);
        let breakcount = fd.opactdbg_breakcount;
        fd.debug_handle_break();
        let breakon_after = fd.opactdbg_breakon as u8;
        println!(
            "case=debug_lifecycle|size_on={size_on}|size_r1={size_r1}|size_cleared={size_cleared}|on_after_disable={on_after_disable}|breakcount={breakcount}|breakon_after={breakon_after}"
        );
    }

    // case=debug_range_matrix: two ranges (bounded PC; entire-function with
    // unique window) against ops inside/outside. The entire-function range
    // uses the invalid address form; the Rust Address invalid form is the
    // spaceless null-base address.
    {
        fd.debug_enable();
        fd.debug_set_range(ram_addr(0x5010), ram_addr(0x5020), u32::MAX, u32::MAX);
        fd.debug_set_range(Address::new(0), Address::new(0), 0, 3);
        let r1_hit = fd.debug_check_range(&op1);
        let r1_miss = fd.debug_check_range(&op2);
        print!(
            "case=debug_range_matrix|r1_hit={}|r1_miss={}|",
            r1_hit as u8, r1_miss as u8
        );
        // The oracle routes debugPrintRange through
        // Architecture::printDebug (architecture.hh:256), which appends
        // endl to each message; the Rust twin returns the bare message, so
        // the newline is emitted here.
        print!("{}\n|", fd.debug_print_range(0));
        print!("{}\n", fd.debug_print_range(1));
        print!("\n");
    }

    // case=debug_mod_clear: a traced op takes the modified addl-flag via
    // drillobserve's debugModCheck twin; debug_mod_clear drops it and the
    // lists.
    {
        fd.debug_clear();
        fd.debug_set_range(ram_addr(0x5000), ram_addr(0x6000), u32::MAX, u32::MAX);
        // Funcdata::debugModCheck (funcdata.cc:1010-1022): first-touch
        // caching keyed on the modified addl-flag + the traced range. The
        // Rust twin lives on the drillobserve recorder; the Funcdata-side
        // state transition is driven here through the same observable
        // steps (set the flag, record the before-string).
        {
            let mut o = op1.0.write().unwrap();
            o.addlflags |= rudra::op::op_addl_flags::MODIFIED;
        }
        fd.modify_list.push(op1.clone());
        fd.modify_before.push(String::new());
        let marked = {
            op1.0.read().unwrap().addlflags & rudra::op::op_addl_flags::MODIFIED != 0
        };
        let list_len = fd.modify_list.len();
        fd.debug_mod_clear();
        let marked_after = {
            op1.0.read().unwrap().addlflags & rudra::op::op_addl_flags::MODIFIED != 0
        };
        let list_len_after = fd.modify_list.len();
        let active_after = fd.opactdbg_active;
        println!(
            "case=debug_mod_clear|marked={}|list_len={list_len}|marked_after={}|list_len_after={list_len_after}|active_after={}",
            marked as u8, marked_after as u8, active_after as u8
        );
    }

    // case=debug_activate: activation is gated on debugging being on.
    {
        fd.debug_disable();
        fd.debug_activate();
        let active_off = fd.opactdbg_active;
        fd.debug_enable();
        fd.debug_activate();
        let active_on = fd.opactdbg_active;
        fd.debug_deactivate();
        let active_deactivated = fd.opactdbg_active;
        println!(
            "case=debug_activate|active_off={}|active_on={}|active_deactivated={}",
            active_off as u8, active_on as u8, active_deactivated as u8
        );
    }

    // case=jt_callback: enable/disable stores and clears the fn pointer.
    {
        fd.enable_jt_callback(jtcb);
        let enabled = fd.jtcallback.is_some();
        fd.disable_jt_callback();
        let disabled = fd.jtcallback.is_some();
        println!(
            "case=jt_callback|enabled={}|disabled={}",
            enabled as u8, disabled as u8
        );
    }
}
