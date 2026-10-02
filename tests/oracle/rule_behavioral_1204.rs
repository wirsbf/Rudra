//! RULE-BEHAVIORAL-FIVE-0001: Rugra side of the locked 12.0.4 oracle
//! fixture for the five behavioral rules.
//!
//! Mirrors `rule_behavioral_1204.cc` case-for-case (same names, same
//! observation format) against the pinned rugra source:
//!   case=<name>|apply=<0/1>|opcode=<n>|inputs=<n>|in0=<tok>|in1=<tok>|
//!   in0def=<int>|defin1=<tok>
//!
//! Dispatch is ActionPool-equivalent: apply_op is invoked only when the op's
//! opcode is in the rule's `get_opcodes()`; the negative dispatch cases pin
//! the opcode sets the oracle refuses (and the old Rugra registrations
//! transformed).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::ruleaction::{RuleShift2Mult, RuleShiftBitops, RuleSignForm, RuleSignNearMult,
                        RuleZextEliminate};
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type Vn = Arc<RwLock<Varnode>>;

static CASE_COUNTER: AtomicU32 = AtomicU32::new(0);

fn next_addr() -> u64 {
    0x5000 + CASE_COUNTER.fetch_add(1, Ordering::SeqCst) as u64
}

fn constant_input(fd: &mut Funcdata, value: u64, size: usize) -> Vn {
    fd.new_constant(size, value)
}

/// Each input varnode gets a fresh, non-overlapping register offset,
/// mirroring the C++ fixture's counter (offsets are semantic-neutral).
static INPUT_OFFSET_COUNTER: AtomicU32 = AtomicU32::new(0);

fn input_varnode(fd: &mut Funcdata, size: usize, _offset: u64) -> Vn {
    let offset = 0x10 + 0x10 * INPUT_OFFSET_COUNTER.fetch_add(1, Ordering::SeqCst) as u64;
    let vn = fd
        .vbank
        .create_with_space(size, AddressSpace::Register, offset);
    fd.set_input_varnode(vn)
}

fn make_op(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opcode: OpCode,
    inputs: &[Vn],
    output_size: usize,
) -> rudra::op::PcodeOpRef {
    let op = fd.new_op(inputs.len(), Address::new(next_addr()));
    fd.op_set_opcode(&op, opcode);
    for (slot, vn) in inputs.iter().enumerate() {
        fd.op_set_input(&op, vn.clone(), slot);
    }
    fd.new_unique_out(output_size, &op);
    fd.op_insert_end(&op, block);
    op
}

/// ActionPool-equivalent dispatch (action.cc:748-750 perop buckets): only
/// ops whose opcode is in the rule's get_opcodes() reach apply_op.
fn dispatch_apply(rule: &dyn Rule, op: &rudra::op::PcodeOpRef, fd: &mut Funcdata) -> i32 {
    let code = op.0.read().unwrap().opcode;
    if rule.get_opcodes().contains(&code) {
        rule.apply_op(&op.0, fd).expect("apply_op")
    } else {
        0
    }
}

fn vn_token(vn: Option<&Vn>) -> String {
    match vn {
        None => "-".to_string(),
        Some(v) => {
            let v = v.read().unwrap();
            if v.is_constant() {
                format!("c{}:{:x}", v.get_size(), v.get_offset())
            } else if v.is_written() {
                format!("w{}", v.get_size())
            } else {
                format!("u{}", v.get_size())
            }
        }
    }
}

fn observe(
    name: &str,
    rule: &dyn Rule,
    op: &rudra::op::PcodeOpRef,
    fd: &mut Funcdata,
) {
    let apply = dispatch_apply(rule, op, fd);
    let guard = op.0.read().unwrap();
    let in0 = guard.get_in(0).cloned();
    let in1 = guard.get_in(1).cloned();
    let mut line = format!(
        "case={name}|apply={apply}|opcode={}|inputs={}|in0={}|in1={}|in0def=",
        guard.opcode as i32,
        guard.num_input(),
        vn_token(in0.as_ref()),
        vn_token(in1.as_ref()),
    );
    if let Some(v) = &in0 {
        if v.read().unwrap().is_written() {
            let def = v.read().unwrap().get_def();
            if let Some(def) = def {
                let d = def.read().unwrap();
                line += &format!("{}", d.opcode as i32);
                // Ghidra prints "_" when the defining op has no input 1.
                let defin1 = if d.num_input() > 1 {
                    vn_token(d.get_in(1))
                } else {
                    "_".to_string()
                };
                line += &format!("|defin1={defin1}");
            } else {
                line += "-1|defin1=_";
            }
            drop(guard);
            println!("{line}");
            return;
        }
    }
    line += "-1|defin1=_";
    drop(guard);
    println!("{line}");
}

fn oplist_probe(tag: &str, rule: &dyn Rule) {
    let ops: Vec<String> = rule
        .get_opcodes()
        .iter()
        .map(|o| format!("{}", *o as i32))
        .collect();
    println!(
        "case=oplist_{tag}|apply=_|opcode=_|inputs=_|in0=_|in1=_|in0def=_|defin1=_|ops={}",
        ops.join(",")
    );
}

/// RuleZextEliminate fixture shape: cmp(zext(V:small->4), c4:cmp_const).
fn make_zext_cmp(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    cmp_opcode: OpCode,
    small_size: usize,
    cmp_const: u64,
    zext_on_slot1: bool,
) -> rudra::op::PcodeOpRef {
    let v = input_varnode(fd, small_size, 0x10);
    let zext_op = make_op(fd, block, OpCode::CPUI_INT_ZEXT, &[v], 4);
    let zext_out = zext_op.0.read().unwrap().output.clone().unwrap();
    let c = constant_input(fd, cmp_const, 4);
    let inputs = if zext_on_slot1 {
        vec![c, zext_out]
    } else {
        vec![zext_out, c]
    };
    make_op(fd, block, cmp_opcode, &inputs, 1)
}

/// RuleSignForm fixture shape: SUBPIECE(ext(V:small->ext), c4:trunc).
fn make_sign_form(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ext_opcode: OpCode,
    small_size: usize,
    ext_out_size: usize,
    out_size: usize,
    trunc_offset: u64,
) -> rudra::op::PcodeOpRef {
    let v = input_varnode(fd, small_size, 0x10);
    let ext_op = make_op(fd, block, ext_opcode, &[v], ext_out_size);
    let ext_out = ext_op.0.read().unwrap().output.clone().unwrap();
    let c = constant_input(fd, trunc_offset, 4);
    make_op(fd, block, OpCode::CPUI_SUBPIECE, &[ext_out, c], out_size)
}

/// RuleSignNearMult fixture shape:
/// AND( x + ((x s>> (8*size-1)) >> k), mask ), shift side on the chosen slot.
fn make_near_mult(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    size: usize,
    k: u64,
    mask: u64,
    shift_on_slot0: bool,
) -> rudra::op::PcodeOpRef {
    let x = input_varnode(fd, size, 0x10);
    let c_ssh = constant_input(fd, (8 * size - 1) as u64, 4);
    let ssh_op = make_op(fd, block, OpCode::CPUI_INT_SRIGHT, &[x.clone(), c_ssh], size);
    let ssh_out = ssh_op.0.read().unwrap().output.clone().unwrap();
    let c_k = constant_input(fd, k, 4);
    let right_op = make_op(fd, block, OpCode::CPUI_INT_RIGHT, &[ssh_out, c_k], size);
    let right_out = right_op.0.read().unwrap().output.clone().unwrap();
    let add_inputs = if shift_on_slot0 {
        vec![right_out, x]
    } else {
        vec![x, right_out]
    };
    let add_op = make_op(fd, block, OpCode::CPUI_INT_ADD, &add_inputs, size);
    let add_out = add_op.0.read().unwrap().output.clone().unwrap();
    let c_mask = constant_input(fd, mask, 4);
    make_op(fd, block, OpCode::CPUI_INT_AND, &[add_out, c_mask], size)
}

/// RuleShiftBitops fixture shape: shiftop( bitop(V, c:bit_const), c:shift_const ).
fn make_bitop_shift(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    bit_opcode: OpCode,
    bit_const: u64,
    shift_opcode: OpCode,
    shift_const: u64,
    size: usize,
    out_size: usize,
) -> rudra::op::PcodeOpRef {
    let v = input_varnode(fd, size, 0x10);
    let c_bit = constant_input(fd, bit_const, 4);
    let bit_op = make_op(fd, block, bit_opcode, &[v, c_bit], size);
    let bit_out = bit_op.0.read().unwrap().output.clone().unwrap();
    let c_shift = constant_input(fd, shift_const, 4);
    make_op(fd, block, shift_opcode, &[bit_out, c_shift], out_size)
}

/// RuleShift2Mult fixture shape: shift(V, c:shift_const) feeding a consumer.
fn make_shift_feed(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    shift_opcode: OpCode,
    shift_const: u64,
    consumer_opcode: OpCode,
) -> rudra::op::PcodeOpRef {
    let v = input_varnode(fd, 4, 0x10);
    let c = constant_input(fd, shift_const, 4);
    let shift_op = make_op(fd, block, shift_opcode, &[v, c], 4);
    let shift_out = shift_op.0.read().unwrap().output.clone().unwrap();
    let w = input_varnode(fd, 4, 0x20);
    make_op(fd, block, consumer_opcode, &[shift_out, w], 4);
    shift_op
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(block.clone());

    let zext_rule = RuleZextEliminate::new();
    let sign_form_rule = RuleSignForm::new();
    let sign_near_rule = RuleSignNearMult::new();
    let bitops_rule = RuleShiftBitops::new();
    let shift2mult_rule = RuleShift2Mult::new();

    // opcode-set probes: the dispatch contract of each rule.
    oplist_probe("zexteliminate", &zext_rule);
    oplist_probe("signform", &sign_form_rule);
    oplist_probe("signnearmult", &sign_near_rule);
    oplist_probe("shiftbitops", &bitops_rule);
    oplist_probe("shift2mult", &shift2mult_rule);

    // --- RuleZextEliminate ---
    observe(
        "zextelim_eq_pos",
        &zext_rule,
        &make_zext_cmp(&mut fd, &block, OpCode::CPUI_INT_EQUAL, 1, 5, false),
        &mut fd,
    );
    observe(
        "zextelim_notequal_slot1_pos",
        &zext_rule,
        &make_zext_cmp(&mut fd, &block, OpCode::CPUI_INT_NOTEQUAL, 1, 5, true),
        &mut fd,
    );
    observe(
        "zextelim_lessequal_pos",
        &zext_rule,
        &make_zext_cmp(&mut fd, &block, OpCode::CPUI_INT_LESSEQUAL, 2, 0x1234, false),
        &mut fd,
    );
    observe(
        "zextelim_less_val_too_big_neg",
        &zext_rule,
        &make_zext_cmp(&mut fd, &block, OpCode::CPUI_INT_LESS, 1, 300, false),
        &mut fd,
    );
    {
        // negative: the zext output feeds a second op -> lone_descend fails
        let v = input_varnode(&mut fd, 1, 0x10);
        let zext_op = make_op(&mut fd, &block, OpCode::CPUI_INT_ZEXT, &[v], 4);
        let zext_out = zext_op.0.read().unwrap().output.clone().unwrap();
        let c = constant_input(&mut fd, 5, 4);
        let cmp_op = make_op(&mut fd, &block, OpCode::CPUI_INT_EQUAL, &[zext_out.clone(), c], 1);
        make_op(&mut fd, &block, OpCode::CPUI_COPY, &[zext_out], 4);
        observe("zextelim_shared_zext_neg", &zext_rule, &cmp_op, &mut fd);
    }
    {
        // negative dispatch: the INT_ZEXT op itself is not in the oplist.
        let v = input_varnode(&mut fd, 4, 0x10);
        let zext_op = make_op(&mut fd, &block, OpCode::CPUI_INT_ZEXT, &[v], 4);
        observe("zextelim_zext_op_dispatch_neg", &zext_rule, &zext_op, &mut fd);
    }
    {
        // negative: other input not constant
        let v = input_varnode(&mut fd, 1, 0x10);
        let zext_op = make_op(&mut fd, &block, OpCode::CPUI_INT_ZEXT, &[v], 4);
        let zext_out = zext_op.0.read().unwrap().output.clone().unwrap();
        let w = input_varnode(&mut fd, 4, 0x30);
        let cmp_op = make_op(&mut fd, &block, OpCode::CPUI_INT_EQUAL, &[zext_out, w], 1);
        observe("zextelim_nonconst_other_neg", &zext_rule, &cmp_op, &mut fd);
    }

    // --- RuleSignForm ---
    observe(
        "signform_subpiece_sext_1b_pos",
        &sign_form_rule,
        &make_sign_form(&mut fd, &block, OpCode::CPUI_INT_SEXT, 1, 4, 1, 2),
        &mut fd,
    );
    observe(
        "signform_subpiece_sext_4b_pos",
        &sign_form_rule,
        &make_sign_form(&mut fd, &block, OpCode::CPUI_INT_SEXT, 4, 8, 4, 4),
        &mut fd,
    );
    observe(
        "signform_offset_below_size_neg",
        &sign_form_rule,
        &make_sign_form(&mut fd, &block, OpCode::CPUI_INT_SEXT, 1, 4, 1, 0),
        &mut fd,
    );
    observe(
        "signform_zext_input_neg",
        &sign_form_rule,
        &make_sign_form(&mut fd, &block, OpCode::CPUI_INT_ZEXT, 1, 4, 1, 2),
        &mut fd,
    );
    {
        // negative dispatch: INT_SRIGHT is not in the oplist.
        let v = input_varnode(&mut fd, 1, 0x10);
        let sext_op = make_op(&mut fd, &block, OpCode::CPUI_INT_SEXT, &[v], 4);
        let sext_out = sext_op.0.read().unwrap().output.clone().unwrap();
        let c = constant_input(&mut fd, 2, 4);
        let sr_op = make_op(&mut fd, &block, OpCode::CPUI_INT_SRIGHT, &[sext_out, c], 1);
        observe("signform_sright_dispatch_neg", &sign_form_rule, &sr_op, &mut fd);
    }

    // --- RuleSignNearMult ---
    observe(
        "signnear_n4_pos",
        &sign_near_rule,
        &make_near_mult(&mut fd, &block, 4, 28, 0xfffffff0, false),
        &mut fd,
    );
    observe(
        "signnear_n8_swap_pos",
        &sign_near_rule,
        &make_near_mult(&mut fd, &block, 4, 24, 0xffffff00, true),
        &mut fd,
    );
    observe(
        "signnear_mask_mismatch_neg",
        &sign_near_rule,
        &make_near_mult(&mut fd, &block, 4, 28, 0xffffff00, false),
        &mut fd,
    );
    {
        // negative: sign shift amount 30 != 31
        let x = input_varnode(&mut fd, 4, 0x10);
        let c_ssh = constant_input(&mut fd, 30, 4);
        let ssh_op = make_op(&mut fd, &block, OpCode::CPUI_INT_SRIGHT, &[x.clone(), c_ssh], 4);
        let ssh_out = ssh_op.0.read().unwrap().output.clone().unwrap();
        let c_k = constant_input(&mut fd, 28, 4);
        let right_op = make_op(&mut fd, &block, OpCode::CPUI_INT_RIGHT, &[ssh_out, c_k], 4);
        let right_out = right_op.0.read().unwrap().output.clone().unwrap();
        let add_op = make_op(&mut fd, &block, OpCode::CPUI_INT_ADD, &[x, right_out], 4);
        let add_out = add_op.0.read().unwrap().output.clone().unwrap();
        let c_mask = constant_input(&mut fd, 0xfffffff0, 4);
        let and_op = make_op(&mut fd, &block, OpCode::CPUI_INT_AND, &[add_out, c_mask], 4);
        observe("signnear_wrong_sshift_neg", &sign_near_rule, &and_op, &mut fd);
    }
    {
        // negative dispatch: INT_MULT is not in the oplist.
        let x = input_varnode(&mut fd, 4, 0x10);
        let c_ssh = constant_input(&mut fd, 31, 4);
        let ssh_op = make_op(&mut fd, &block, OpCode::CPUI_INT_SRIGHT, &[x.clone(), c_ssh], 4);
        let ssh_out = ssh_op.0.read().unwrap().output.clone().unwrap();
        let c_k = constant_input(&mut fd, 28, 4);
        let right_op = make_op(&mut fd, &block, OpCode::CPUI_INT_RIGHT, &[ssh_out, c_k], 4);
        let right_out = right_op.0.read().unwrap().output.clone().unwrap();
        let add_op = make_op(&mut fd, &block, OpCode::CPUI_INT_ADD, &[x, right_out], 4);
        let add_out = add_op.0.read().unwrap().output.clone().unwrap();
        let c_pow = constant_input(&mut fd, 16, 4);
        let mult_op = make_op(&mut fd, &block, OpCode::CPUI_INT_MULT, &[add_out, c_pow], 4);
        observe("signnear_mult_dispatch_neg", &sign_near_rule, &mult_op, &mut fd);
    }

    // --- RuleShiftBitops ---
    observe(
        "bitops_and_left_pos",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_AND, 0xf000, OpCode::CPUI_INT_LEFT, 20, 4, 4),
        &mut fd,
    );
    observe(
        "bitops_add_left_pos",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_ADD, 0xf000, OpCode::CPUI_INT_LEFT, 20, 4, 4),
        &mut fd,
    );
    observe(
        "bitops_or_right_pos",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_OR, 0xff, OpCode::CPUI_INT_RIGHT, 24, 4, 4),
        &mut fd,
    );
    observe(
        "bitops_subpiece_pos",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_AND, 0xff, OpCode::CPUI_SUBPIECE, 1, 4, 3),
        &mut fd,
    );
    observe(
        "bitops_mult_lsb_pos",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_AND, 0xf0000, OpCode::CPUI_INT_MULT, 0x10000, 4, 4),
        &mut fd,
    );
    observe(
        "bitops_no_swallow_neg",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_AND, 0xf0, OpCode::CPUI_INT_LEFT, 4, 4, 4),
        &mut fd,
    );
    observe(
        "bitops_add_right_neg",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_ADD, 0xf000, OpCode::CPUI_INT_RIGHT, 4, 4, 4),
        &mut fd,
    );
    observe(
        "bitops_shift_by_zero_neg",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_AND, 0xf, OpCode::CPUI_INT_LEFT, 0, 4, 4),
        &mut fd,
    );
    observe(
        "bitops_sright_dispatch_neg",
        &bitops_rule,
        &make_bitop_shift(&mut fd, &block, OpCode::CPUI_INT_OR, 0xff, OpCode::CPUI_INT_SRIGHT, 0, 4, 4),
        &mut fd,
    );

    // --- RuleShift2Mult ---
    observe(
        "shift2mult_desc_add_pos",
        &shift2mult_rule,
        &make_shift_feed(&mut fd, &block, OpCode::CPUI_INT_LEFT, 3, OpCode::CPUI_INT_ADD),
        &mut fd,
    );
    {
        // positive: input side defined by INT_ADD
        let v = input_varnode(&mut fd, 4, 0x10);
        let w = input_varnode(&mut fd, 4, 0x20);
        let add_op = make_op(&mut fd, &block, OpCode::CPUI_INT_ADD, &[v, w], 4);
        let add_out = add_op.0.read().unwrap().output.clone().unwrap();
        let c = constant_input(&mut fd, 2, 4);
        let shift_op = make_op(&mut fd, &block, OpCode::CPUI_INT_LEFT, &[add_out, c], 4);
        observe("shift2mult_input_add_pos", &shift2mult_rule, &shift_op, &mut fd);
    }
    observe(
        "shift2mult_desc_sub_pos",
        &shift2mult_rule,
        &make_shift_feed(&mut fd, &block, OpCode::CPUI_INT_LEFT, 3, OpCode::CPUI_INT_SUB),
        &mut fd,
    );
    observe(
        "shift2mult_no_arith_neg",
        &shift2mult_rule,
        &make_shift_feed(&mut fd, &block, OpCode::CPUI_INT_LEFT, 3, OpCode::CPUI_COPY),
        &mut fd,
    );
    observe(
        "shift2mult_big_shift_neg",
        &shift2mult_rule,
        &make_shift_feed(&mut fd, &block, OpCode::CPUI_INT_LEFT, 32, OpCode::CPUI_INT_ADD),
        &mut fd,
    );
    observe(
        "shift2mult_right_dispatch_neg",
        &shift2mult_rule,
        &make_shift_feed(&mut fd, &block, OpCode::CPUI_INT_RIGHT, 3, OpCode::CPUI_INT_ADD),
        &mut fd,
    );

    // --- RuleShiftBitops with PROPAGATED nzm (FUNCDATA-CALCNZM follow-up) ---
    // The main pipeline runs ActionNonzeroMask (coreaction.cc:5507) before
    // the rule pools each mainloop, so ruleaction.cc:541 reads the nzm field
    // that Funcdata::calcNZMask (funcdata_varnode.cc:856-927) propagated
    // through written outputs, not the constructor default. Run calc_nz_mask
    // once here (after all prior observations are printed) and exercise
    // sparse written inputs: without propagation the AND output still
    // reports ~0 and the transforms below cannot fire.
    // Build the chains first, then run calc_nz_mask (after all prior
    // observations are printed), then observe: without propagation the AND
    // output still reports ~0 and the positive transforms cannot fire.
    let prop_add_shift = {
        let w = input_varnode(&mut fd, 1, 0x10);
        let c_mask = constant_input(&mut fd, 0x80, 1);
        let andw_op = make_op(&mut fd, &block, OpCode::CPUI_INT_AND, &[w, c_mask], 1);
        let andw_out = andw_op.0.read().unwrap().output.clone().unwrap();
        let x = input_varnode(&mut fd, 1, 0x10);
        let add_op = make_op(&mut fd, &block, OpCode::CPUI_INT_ADD, &[x, andw_out], 1);
        let add_out = add_op.0.read().unwrap().output.clone().unwrap();
        let c_shift = constant_input(&mut fd, 7, 4);
        make_op(&mut fd, &block, OpCode::CPUI_INT_LEFT, &[add_out, c_shift], 1)
    };
    let prop_sub_sub = {
        let w = input_varnode(&mut fd, 2, 0x10);
        let c_mask = constant_input(&mut fd, 0x8080, 2);
        let andw_op = make_op(&mut fd, &block, OpCode::CPUI_INT_AND, &[w, c_mask], 2);
        let andw_out = andw_op.0.read().unwrap().output.clone().unwrap();
        let c_off = constant_input(&mut fd, 2, 4);
        make_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, &[andw_out, c_off], 1)
    };
    let prop_dense_shift = {
        let w = input_varnode(&mut fd, 1, 0x10);
        let c_mask = constant_input(&mut fd, 0xff, 1);
        let andw_op = make_op(&mut fd, &block, OpCode::CPUI_INT_AND, &[w, c_mask], 1);
        let andw_out = andw_op.0.read().unwrap().output.clone().unwrap();
        let x = input_varnode(&mut fd, 1, 0x10);
        let add_op = make_op(&mut fd, &block, OpCode::CPUI_INT_ADD, &[x, andw_out], 1);
        let add_out = add_op.0.read().unwrap().output.clone().unwrap();
        let c_shift = constant_input(&mut fd, 1, 4);
        make_op(&mut fd, &block, OpCode::CPUI_INT_LEFT, &[add_out, c_shift], 1)
    };
    fd.calc_nz_mask();

    // positive: calcNZMask assigns AND-out nzm = 0x80; 0x80 << 7 loses the
    // 1-byte output mask -> break at i=1 -> ADD keeps the surviving X.
    observe("bitops_propagated_add_pos", &bitops_rule, &prop_add_shift, &mut fd);
    // positive: AND-out nzm = 0x8080; >> 16 (byte offset 2) is zero -> break
    // at i=0 on a WRITTEN input -> AND collapses to #0.
    observe("bitops_propagated_subpiece_pos", &bitops_rule, &prop_sub_sub, &mut fd);
    // negative: 0xff << 1 keeps 0xfe in the 1-byte mask after propagation ->
    // no swallow -> untouched.
    observe("bitops_propagated_dense_neg", &bitops_rule, &prop_dense_shift, &mut fd);
}

fn main() {
    run();
}
