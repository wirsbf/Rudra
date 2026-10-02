//! VARNODE-COPYSYMBOL-EQUATE-0001: Rudra side of the locked 12.0.4 oracle
//! fixture for `Varnode::copySymbolIfValid` + `EquateSymbol::isValueClose`.
//!
//! Mirrors `varnode_copysymbol_1204.cc` case-for-case (same names, same
//! observation format) against the pinned rudra source:
//!   vc_*: case|value|op2|size|close
//!   cs_*: case|dst_offset|dst_size|src_symbol|dst_symbol|dst_namelock|
//!         dst_typelock|dst_mapped
//!   op_*: case|apply|opcode|in0_offset|out_size|in0_symbol
//!
//! Equates attach through the public `Varnode::set_symbol_entry` route with
//! `equate_symbol_registry::register_value` marking the symbol as an
//! EquateSymbol carrying its value (the Rust stand-in for the C++ subtype
//! identity that `dynamic_cast<EquateSymbol*>` reads).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::{Address, RangeList};
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::database::{EquateSymbol, Symbol, SymbolEntry};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::ruleaction::RuleCollapseConstants;
use rudra::varnode::{equate_symbol_registry, varnode_flags, Varnode};

static CASE_COUNTER: AtomicU32 = AtomicU32::new(0);

fn next_addr() -> u64 {
    // Ghidra's SeqNum keeps ops distinct at the same address; Rudra assigns
    // distinct addresses to keep new_op bookkeeping deterministic.
    0x5000 + CASE_COUNTER.fetch_add(1, Ordering::SeqCst) as u64
}

// Mirror of the C++ attachEquate: Scope::addEquateSymbol (database.cc:1712)
// builds an EquateSymbol whose dynamic whole-map SymbolEntry is attached via
// Varnode::setSymbolEntry (varnode.cc:429).  Rudra's database::Symbol has no
// equate payload, so the registry records the value the C++ subtype would
// carry.
fn attach_equate(vn: &Arc<RwLock<Varnode>>, value: u64, size: i32) {
    let symbol = Arc::new(RwLock::new(Symbol::new(0, "FIXTURE_EQ", "equ")));
    equate_symbol_registry::register_value(&symbol, value);
    let entry = SymbolEntry::new_dynamic(
        symbol,
        varnode_flags::MAPPED,
        1,
        0,
        size,
        RangeList::default(),
    );
    vn.write().unwrap().set_symbol_entry(Arc::new(RwLock::new(entry)));
}

// Mirror of the C++ plain-symbol route: Scope::addDynamicSymbol
// (database.hh:784) without any equate payload.
fn attach_plain(vn: &Arc<RwLock<Varnode>>, size: i32) {
    let symbol = Arc::new(RwLock::new(Symbol::new(0, "FIXTURE_PLAIN", "unknown")));
    let entry = SymbolEntry::new_dynamic(
        symbol,
        varnode_flags::MAPPED,
        1,
        0,
        size,
        RangeList::default(),
    );
    vn.write().unwrap().set_symbol_entry(Arc::new(RwLock::new(entry)));
}

// Section A: EquateSymbol::isValueClose branch table (database.cc:640-659).
fn run_value_close_table() {
    let cases: &[(&str, u64, u64, usize)] = &[
        ("vc_exact", 0x11223344, 0x11223344, 4),
        ("vc_signext_masked", 0xFFFFFFFF_8899AABB, 0x8899AABB, 4),
        ("vc_masked_non_signext", 0x11223344_55667788, 0x55667788, 4),
        ("vc_op2_wider_masked", 0x55667788, 0x11223344_55667788, 4),
        ("vc_bitnot_close", 0x0F0F, 0xF0F0, 2),
        ("vc_negate_close", 0x0F0F, 0xF0F1, 2),
        ("vc_plus1_close", 0x0F0F, 0x0F0E, 2),
        ("vc_minus1_close", 0x0F0F, 0x0F10, 2),
        ("vc_not_close", 0x1234, 0x5678, 2),
        ("vc_size8_not_close", 0x10, 0x20, 8),
        ("vc_size8_bitnot", 0x10, 0xFFFF_FFFF_FFFF_FFEF, 8),
    ];
    for &(name, value, op2, size) in cases {
        let equ = EquateSymbol::new(0, "VCEQ", 0, value);
        println!(
            "case={name}|value={value}|op2={op2}|size={size}|close={}",
            u8::from(equ.is_value_close(op2, size))
        );
    }
}

// Section B: Varnode::copySymbolIfValid directly on free constant varnodes.
fn run_copy_if_valid_direct(fd: &mut Funcdata) {
    // (name, equate_value, src_val, dst_val, size, plain, no_sym)
    let cases: &[(&str, u64, u64, u64, usize, bool, bool)] = &[
        ("cs_equate_equal", 0x33333333, 0x33333333, 0x33333333, 4, false, false),
        ("cs_equate_not_close", 0x12345678, 0x12345678, 0x33333333, 4, false, false),
        ("cs_equate_negate_close", 0x0F0F, 0xF0F1, 0x0F0F, 2, false, false),
        ("cs_equate_signext", 0xFFFFFFFF_8899AABB, 0x8899AABB, 0x8899AABB, 4, false, false),
        ("cs_plain_symbol", 0, 0x33333333, 0x33333333, 4, true, false),
        ("cs_no_mapentry", 0, 0x33333333, 0x33333333, 4, false, true),
    ];
    for &(name, equate_value, src_val, dst_val, size, plain, no_sym) in cases {
        let src = fd.new_constant(size, src_val);
        let dst = fd.new_constant(size, dst_val);
        if plain {
            attach_plain(&src, size as i32);
        } else if !no_sym {
            attach_equate(&src, equate_value, size as i32);
        }
        dst.write().unwrap().copy_symbol_if_valid(&src.read().unwrap());
        let d = dst.read().unwrap();
        println!(
            "case={name}|dst_offset={}|dst_size={}|src_symbol={}|dst_symbol={}|dst_namelock={}|dst_typelock={}|dst_mapped={}",
            d.get_offset(),
            d.get_size(),
            u8::from(src.read().unwrap().get_symbol_entry().is_some()),
            u8::from(d.get_symbol_entry().is_some()),
            u8::from(d.is_name_lock()),
            u8::from(d.is_type_lock()),
            u8::from(d.is_mapped()),
        );
    }
}

// Section C: op-level integration through RuleCollapseConstants.
fn make_op(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opcode: OpCode,
    values: &[u64],
    sizes: &[usize],
    output_size: usize,
) -> rudra::op::PcodeOpRef {
    let op = fd.new_op(values.len(), Address::new(next_addr()));
    fd.op_set_opcode(&op, opcode);
    for (slot, (&val, &sz)) in values.iter().zip(sizes.iter()).enumerate() {
        let c = fd.new_constant(sz, val);
        fd.op_set_input(&op, c, slot);
    }
    fd.new_unique_out(output_size, &op);
    fd.op_insert_end(&op, block);
    op
}

fn run_op_level(fd: &mut Funcdata) {
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(block.clone());

    let rule = RuleCollapseConstants::new();
    // (name, opcode, values, sizes, output_size, equate_value)
    let cases: &[(&str, OpCode, &[u64], &[usize], usize, u64)] = &[
        (
            "op_add_marked_close",
            OpCode::CPUI_INT_ADD,
            &[0x11111111, 0x22222222],
            &[4, 4],
            4,
            0x33333333,
        ),
        (
            "op_add_marked_not_close",
            OpCode::CPUI_INT_ADD,
            &[1, 2],
            &[4, 4],
            4,
            0xDEADBEEF,
        ),
        (
            "op_subpiece_high_no_propagate",
            OpCode::CPUI_SUBPIECE,
            &[0x1122334455667788, 4],
            &[8, 1],
            4,
            0x11223344,
        ),
    ];
    for &(name, opcode, values, sizes, output_size, equate_value) in cases {
        let op = make_op(fd, &block, opcode, values, sizes, output_size);
        {
            let in0 = op.0.read().unwrap().get_in(0).cloned().unwrap();
            attach_equate(&in0, equate_value, sizes[0] as i32);
        }
        let apply = rule.apply_op(&op.0, fd).expect("apply_op");
        let guard = op.0.read().unwrap();
        let out = guard.output.as_ref();
        let in0 = guard.get_in(0);
        // After a successful collapse the op is COPY(newConst): the
        // propagated markup lands on the new constant, now input 0
        // (ruleaction.cc:3874 opSetInput(op,vn,0)).
        println!(
            "case={name}|apply={apply}|opcode={}|in0_offset={}|out_size={}|in0_symbol={}",
            guard.opcode as i32,
            in0.map(|v| v.read().unwrap().get_offset() as i64).unwrap_or(-1),
            out.map(|v| v.read().unwrap().get_size() as i64).unwrap_or(-1),
            in0.map(|v| u8::from(v.read().unwrap().get_symbol_entry().is_some()))
                .unwrap_or(0),
        );
    }
}

fn main() {
    run_value_close_table();
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    run_copy_if_valid_direct(&mut fd);
    run_op_level(&mut fd);
}
