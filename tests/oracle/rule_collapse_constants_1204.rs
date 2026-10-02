//! RULE-COLLAPSECONSTANTS-0001: Rudra side of the locked 12.0.4 oracle
//! fixture for RuleCollapseConstants.
//!
//! Mirrors `rule_collapse_constants_1204.cc` case-for-case (same names, same
//! observation format) against the pinned `wt/rulefound` rudra source:
//!   case=<name>|apply=<rc>|opcode=<n>|inputs=<n>|in0_const|in0_size|
//!   in0_offset|in0_symbol|out_size|apply2
//!
//! The equate cases attach a `SymbolEntry` to the constant input via
//! `Varnode::set_symbol_entry` (Rudra's public route; Ghidra's fixture uses
//! Scope::addEquateSymbol + Funcdata::remapDynamicVarnode) so the
//! markedInput -> collapseConstantSymbol path is observable on both sides.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::address::RangeList;
use rudra::database::SymbolEntry;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::ruleaction::RuleCollapseConstants;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

static CASE_COUNTER: AtomicU32 = AtomicU32::new(0);

fn next_addr() -> u64 {
    // Ghidra's SeqNum keeps ops distinct at the same address; Rudra assigns
    // distinct addresses to keep new_op bookkeeping deterministic.
    0x5000 + CASE_COUNTER.fetch_add(1, Ordering::SeqCst) as u64
}

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

fn observe(name: &str, op: &rudra::op::PcodeOpRef, fd: &mut Funcdata) {
    let rule = RuleCollapseConstants::new();
    let first = rule.apply_op(&op.0, fd).expect("first apply_op");
    let second = rule.apply_op(&op.0, fd).expect("second apply_op");
    let guard = op.0.read().unwrap();
    let mut line = format!(
        "case={name}|apply={first}|opcode={}|inputs={}",
        guard.opcode as i32,
        guard.num_input()
    );
    if let Some(in0) = guard.get_in(0) {
        let in0 = in0.read().unwrap();
        line += &format!(
            "|in0_const={}|in0_size={}|in0_offset={}|in0_symbol={}",
            u8::from(in0.is_constant()),
            in0.get_size(),
            in0.get_offset(),
            u8::from(in0.get_symbol_entry().is_some())
        );
    } else {
        line += "|in0_const=_|in0_size=_|in0_offset=_|in0_symbol=_";
    }
    let out_size = guard
        .output
        .as_ref()
        .map(|v| v.read().unwrap().get_size() as i64)
        .unwrap_or(-1);
    line += &format!("|out_size={out_size}|apply2={second}");
    println!("{line}");
}

fn attach_equate(vn: &Arc<RwLock<Varnode>>, _value: u64, size: i32) {
    let symbol = Arc::new(RwLock::new(rudra::database::Symbol::new(
        0, "FIXTURE_EQ", "equ",
    )));
    let entry = SymbolEntry::new_dynamic(symbol, 0, 1, 0, size, RangeList::default());
    vn.write().unwrap().set_symbol_entry(Arc::new(RwLock::new(entry)));
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(block.clone());

    // Base Rule::getOpList (action.cc:706-713) — the class does not override
    // it; Rudra enumerates the 72 live opcodes (slots 0/45 unassignable).
    let rule = RuleCollapseConstants::new();
    println!(
        "case=oplist_probe|apply=_|opcode=_|inputs=_|in0_const=_|in0_size=_|in0_offset=_|in0_symbol=_|out_size=_|apply2=_|oplist_live={}",
        rule.get_opcodes().len()
    );

    let cases: &[( &str, OpCode, &[u64], &[usize], usize )] = &[
        ("int_sdiv_neg", OpCode::CPUI_INT_SDIV, &[0xFFFFFF9C, 7], &[4, 4], 4),
        ("int_srem_neg", OpCode::CPUI_INT_SREM, &[0xFFFFFF9C, 7], &[4, 4], 4),
        ("int_div", OpCode::CPUI_INT_DIV, &[0xFFFFFF9C, 7], &[4, 4], 4),
        ("int_rem", OpCode::CPUI_INT_REM, &[0xFFFFFF9C, 7], &[4, 4], 4),
        ("err_div_zero", OpCode::CPUI_INT_DIV, &[5, 0], &[4, 4], 4),
        ("err_srem_zero", OpCode::CPUI_INT_SREM, &[5, 0], &[4, 4], 4),
        ("int_left", OpCode::CPUI_INT_LEFT, &[0x12345678, 5], &[4, 4], 4),
        ("int_left_overlarge", OpCode::CPUI_INT_LEFT, &[0x12345678, 32], &[4, 4], 4),
        ("int_right", OpCode::CPUI_INT_RIGHT, &[0xF1234567, 4], &[4, 4], 4),
        ("int_sright_neg", OpCode::CPUI_INT_SRIGHT, &[0xF1234567, 4], &[4, 4], 4),
        ("int_sright_overlarge", OpCode::CPUI_INT_SRIGHT, &[0x80000000, 33], &[4, 4], 4),
        ("int_piece", OpCode::CPUI_PIECE, &[0x1122, 0x3344], &[2, 2], 4),
        ("int_subpiece_low", OpCode::CPUI_SUBPIECE, &[0x1122334455667788, 0], &[8, 1], 4),
        ("int_subpiece_high", OpCode::CPUI_SUBPIECE, &[0x1122334455667788, 4], &[8, 1], 4),
        ("int_zext", OpCode::CPUI_INT_ZEXT, &[0x80], &[1], 4),
        ("int_sext", OpCode::CPUI_INT_SEXT, &[0x80], &[1], 4),
        ("int_2comp", OpCode::CPUI_INT_2COMP, &[1], &[4], 4),
        ("int_negate", OpCode::CPUI_INT_NEGATE, &[0x0F0F0F0F], &[4], 4),
        ("int_popcount", OpCode::CPUI_POPCOUNT, &[0xFF00FF00], &[4], 4),
        ("int_lzcount", OpCode::CPUI_LZCOUNT, &[0x00010000], &[4], 4),
        ("bool_negate", OpCode::CPUI_BOOL_NEGATE, &[1], &[1], 1),
        ("bool_and", OpCode::CPUI_BOOL_AND, &[1, 0], &[1, 1], 1),
        ("bool_or", OpCode::CPUI_BOOL_OR, &[1, 0], &[1, 1], 1),
        ("bool_xor", OpCode::CPUI_BOOL_XOR, &[1, 1], &[1, 1], 1),
        ("cmp_equal", OpCode::CPUI_INT_EQUAL, &[5, 5], &[4, 4], 1),
        ("cmp_not_equal", OpCode::CPUI_INT_NOTEQUAL, &[5, 5], &[4, 4], 1),
        ("cmp_less", OpCode::CPUI_INT_LESS, &[3, 9], &[4, 4], 1),
        ("cmp_less_equal", OpCode::CPUI_INT_LESSEQUAL, &[9, 9], &[4, 4], 1),
        ("cmp_sless", OpCode::CPUI_INT_SLESS, &[0xFFFFFF80, 1], &[4, 4], 1),
        ("cmp_sless_equal", OpCode::CPUI_INT_SLESSEQUAL, &[0xFFFFFF80, 0xFFFFFF80], &[4, 4], 1),
        ("cmp_carry", OpCode::CPUI_INT_CARRY, &[0xFFFFFFFF, 1], &[4, 4], 1),
        ("cmp_scarry", OpCode::CPUI_INT_SCARRY, &[0x7FFFFFFF, 1], &[4, 4], 1),
        ("cmp_sborrow", OpCode::CPUI_INT_SBORROW, &[0x80000000, 1], &[4, 4], 1),
        ("float_add4", OpCode::CPUI_FLOAT_ADD, &[0x3F800000, 0x40000000], &[4, 4], 4),
        ("float_sub4", OpCode::CPUI_FLOAT_SUB, &[0x40400000, 0x40000000], &[4, 4], 4),
        ("float_mult4", OpCode::CPUI_FLOAT_MULT, &[0x3F800000, 0x40000000], &[4, 4], 4),
        ("float_div4", OpCode::CPUI_FLOAT_DIV, &[0x40400000, 0x40000000], &[4, 4], 4),
        ("float_less4", OpCode::CPUI_FLOAT_LESS, &[0x3F800000, 0x40000000], &[4, 4], 1),
        ("float_less_equal4", OpCode::CPUI_FLOAT_LESSEQUAL, &[0x40000000, 0x40000000], &[4, 4], 1),
        ("float_equal4", OpCode::CPUI_FLOAT_EQUAL, &[0x3F800000, 0x3F800000], &[4, 4], 1),
        ("float_not_equal4", OpCode::CPUI_FLOAT_NOTEQUAL, &[0x3F800000, 0x40000000], &[4, 4], 1),
        ("float_nan4", OpCode::CPUI_FLOAT_NAN, &[0x7FC00000], &[4], 1),
        ("float_neg4", OpCode::CPUI_FLOAT_NEG, &[0x3F800000], &[4], 4),
        ("float_abs4", OpCode::CPUI_FLOAT_ABS, &[0xBF800000], &[4], 4),
        ("float_sqrt4", OpCode::CPUI_FLOAT_SQRT, &[0x40800000], &[4], 4),
        ("float_ceil4", OpCode::CPUI_FLOAT_CEIL, &[0x40200000], &[4], 4),
        ("float_floor4", OpCode::CPUI_FLOAT_FLOOR, &[0x40200000], &[4], 4),
        ("float_round4", OpCode::CPUI_FLOAT_ROUND, &[0x40200000], &[4], 4),
        ("float_int2float4", OpCode::CPUI_FLOAT_INT2FLOAT, &[7], &[4], 4),
        ("float_trunc4", OpCode::CPUI_FLOAT_TRUNC, &[0x40300000], &[4], 4),
        ("float_add8", OpCode::CPUI_FLOAT_ADD, &[0x3FF0000000000000, 0x4000000000000000], &[8, 8], 8),
        ("float_neg8", OpCode::CPUI_FLOAT_NEG, &[0x3FF0000000000000], &[8], 8),
        ("float2float_4to8", OpCode::CPUI_FLOAT_FLOAT2FLOAT, &[0x3FC00000], &[4], 8),
        ("err_insert_ternary", OpCode::CPUI_INSERT, &[0xAB, 0xCD, 0], &[1, 1, 1], 2),
        ("err_float_noformat", OpCode::CPUI_FLOAT_TRUNC, &[0x3C00], &[2], 4),
        ("guard_ptrsub_nocollapse", OpCode::CPUI_PTRSUB, &[0x1000, 8], &[4, 4], 4),
        ("guard_out_too_big", OpCode::CPUI_INT_ADD, &[1, 2], &[16, 16], 16),
    ];
    for (name, opcode, values, sizes, out) in cases {
        let op = make_op(&mut fd, &block, *opcode, values, sizes, *out);
        observe(name, &op, &mut fd);
    }

    // Non-constant input guard (register varnode, op.cc:121-122).
    {
        let op = fd.new_op(2, Address::new(next_addr()));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
        let reg = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x20);
        let reg = fd.set_input_varnode(reg);
        fd.op_set_input(&op, reg, 0);
        let c5 = fd.new_constant(4, 5);
        fd.op_set_input(&op, c5, 1);
        fd.new_unique_out(4, &op);
        fd.op_insert_end(&op, &block);
        observe("guard_nonconst_input", &op, &mut fd);
    }

    // markedInput symbol propagation: INT_ADD picks in0 (op.cc:524-533).
    {
        let op = make_op(&mut fd, &block, OpCode::CPUI_INT_ADD,
            &[0x11111111, 0x22222222], &[4, 4], 4);
        let in0 = op.0.read().unwrap().get_in(0).unwrap().clone();
        attach_equate(&in0, 0x33333333, 4);
        observe("sym_add_marked", &op, &mut fd);
    }
    // SUBPIECE with offset != 0 must NOT propagate (op.cc:508-510).
    {
        let op = make_op(&mut fd, &block, OpCode::CPUI_SUBPIECE,
            &[0x1122334455667788, 4], &[8, 1], 4);
        let in0 = op.0.read().unwrap().get_in(0).unwrap().clone();
        attach_equate(&in0, 0x11223344, 8);
        observe("sym_subpiece_high_no_propagate", &op, &mut fd);
    }
}

fn main() {
    run();
}
