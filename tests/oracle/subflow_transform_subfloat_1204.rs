//! SUBFLOAT-TRANSFORM-RESIDUAL-0001 Rudra comparand.
//!
//! Drives the real `RuleSubfloatConvert::applyOp` (rudra::subflow) — the
//! full SubfloatFlow trace + TransformManager::apply — mirroring the
//! locked-oracle C++ fixture observation for observation: non-constant
//! widen/narrow rewrites, constant-narrow/constant-widen-without-terminator
//! rejections, maxPrecision/exceedsPrecision blocking and pass-through,
//! comparison preexistingGuard, and the repeated-input getRepeatSlot path.

use rudra::action::Rule;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::subflow::RuleSubfloatConvert;
use rudra::varnode::Varnode;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

struct GraphProjection {
    ops: Vec<PcodeOpRef>,
    op_index: HashMap<usize, usize>,
    vars: Vec<VarnodeRef>,
    var_index: HashMap<usize, usize>,
}

impl GraphProjection {
    fn new(block: &Block) -> Self {
        let ops = block.read().unwrap().get_ops();
        let op_index = ops
            .iter()
            .enumerate()
            .map(|(index, op)| (Arc::as_ptr(&op.0) as usize, index))
            .collect();
        let mut result = Self {
            ops,
            op_index,
            vars: Vec::new(),
            var_index: HashMap::new(),
        };
        for op_index in 0..result.ops.len() {
            let (output, inputs) = {
                let op = result.ops[op_index].0.read().unwrap();
                (op.get_out().cloned(), op.inrefs.clone())
            };
            result.touch(output);
            for input in inputs {
                result.touch(Some(input));
            }
        }
        result
    }

    fn touch(&mut self, varnode: Option<VarnodeRef>) {
        let Some(varnode) = varnode else { return };
        let pointer = Arc::as_ptr(&varnode) as usize;
        if self.var_index.contains_key(&pointer) {
            return;
        }
        self.var_index.insert(pointer, self.vars.len());
        self.vars.push(varnode);
    }

    fn var_name(&self, varnode: Option<&VarnodeRef>) -> String {
        let Some(varnode) = varnode else {
            return "_".to_string();
        };
        self.var_index
            .get(&(Arc::as_ptr(varnode) as usize))
            .map_or_else(|| "x".to_string(), |index| format!("v{index}"))
    }

    fn op_name(&self, op: Option<&Arc<RwLock<rudra::op::PcodeOp>>>) -> String {
        let Some(op) = op else {
            return "_".to_string();
        };
        self.op_index
            .get(&(Arc::as_ptr(op) as usize))
            .map_or_else(|| "x".to_string(), |index| format!("o{index}"))
    }

    fn render(&self, fd: &Funcdata, block: &Block) -> String {
        let mut output = String::new();
        output.push_str("ops[");
        for (index, op) in self.ops.iter().enumerate() {
            if index != 0 {
                output.push(';');
            }
            let op = op.0.read().unwrap();
            let parent = op
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .filter(|parent| Arc::ptr_eq(parent, block))
                .map_or(-1, |parent| parent.read().unwrap().get_index());
            write!(
                output,
                "o{index}:{}@{}/t{}/r{}/d{}/p{parent}/o{}/i",
                op.opcode as i32,
                op.get_addr().as_u64(),
                op.start.get_time(),
                op.start.get_order(),
                u8::from(op.is_dead()),
                self.var_name(op.get_out()),
            )
            .unwrap();
            for (slot, input) in op.inrefs.iter().enumerate() {
                if slot != 0 {
                    output.push(',');
                }
                output.push_str(&self.var_name(Some(input)));
            }
        }
        output.push_str("]vars[");
        for (index, varnode) in self.vars.iter().enumerate() {
            if index != 0 {
                output.push(';');
            }
            let varnode = varnode.read().unwrap();
            write!(
                output,
                "v{index}:c{}/s{}/sp{}/k{}",
                varnode.create_index,
                varnode.get_size(),
                varnode.get_space().space_id(),
                u8::from(varnode.is_constant()),
            )
            .unwrap();
            if varnode.is_constant() {
                write!(output, ":{}", varnode.get_offset()).unwrap();
            }
            write!(
                output,
                "/f{}/n{}/w{}/d{}/u",
                u8::from(varnode.is_free()),
                u8::from(varnode.is_input()),
                u8::from(varnode.is_written()),
                self.op_name(varnode.get_def().as_ref()),
            )
            .unwrap();
            for (use_index, descendant) in varnode.descend_iter().enumerate() {
                if use_index != 0 {
                    output.push(',');
                }
                output.push_str(&self.op_name(Some(&descendant)));
            }
        }
        write!(
            output,
            "]count={},{},{},{},{},{}",
            self.ops.len(),
            self.vars.len(),
            fd.obank.alivelist.len(),
            fd.obank.deadlist.len(),
            fd.obank.optree.len(),
            fd.vbank.num_varnodes(),
        )
        .unwrap();
        output
    }
}

fn snapshot(fd: &Funcdata, block: &Block) -> String {
    GraphProjection::new(block).render(fd, block)
}

/// Liveness projection of the fixture-built ops after the rule ran: the
/// block projection drops destroyed ops, so their dead flag is printed
/// separately (original build order).
fn orig_liveness(built: &[PcodeOpRef]) -> String {
    let mut out = String::new();
    for (index, op) in built.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(out, "o{index}:{}", u8::from(op.0.read().unwrap().is_dead())).unwrap();
    }
    out
}

struct Fixture {
    fd: Funcdata,
    block: Block,
    built: Vec<PcodeOpRef>,
}

impl Fixture {
    fn new(architecture: &Arc<Architecture>, name: &str, address: u64) -> Self {
        let mut fd = Funcdata::new(name, Address::new(address), 0);
        fd.set_arch(architecture.clone());
        let block = fd.create_new_block();
        Self {
            fd,
            block,
            built: Vec::new(),
        }
    }

    fn output_op(&mut self, opcode: OpCode, pc: u64, output_size: usize) -> (PcodeOpRef, VarnodeRef) {
        let op = self.fd.new_op(1, Address::new(pc));
        self.fd.op_set_opcode(&op, opcode);
        let output = self.fd.new_unique_out(output_size, &op);
        self.fd.op_insert_end(&op, &self.block);
        self.built.push(op.clone());
        (op, output)
    }

    fn binary_op(&mut self, opcode: OpCode, pc: u64, output_size: usize) -> (PcodeOpRef, VarnodeRef) {
        let op = self.fd.new_op(2, Address::new(pc));
        self.fd.op_set_opcode(&op, opcode);
        let output = self.fd.new_unique_out(output_size, &op);
        self.fd.op_insert_end(&op, &self.block);
        self.built.push(op.clone());
        (op, output)
    }

    fn run(mut self, label: &str, trigger: &PcodeOpRef) {
        let before = snapshot(&self.fd, &self.block);
        let ret = RuleSubfloatConvert::new()
            .apply_op(&trigger.0, &mut self.fd)
            .expect("apply_op");
        let after = snapshot(&self.fd, &self.block);
        println!(
            "{label}|ret={ret}|irSame={}|orig={}|before={before}|after={after}",
            u8::from(before == after),
            orig_liveness(&self.built),
        );
    }
}

fn run_widen(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_widen", 0x1000);
    let (copy, copy_out) = fixture.output_op(OpCode::CPUI_COPY, 0x5000, 4);
    let c4 = fixture.fd.new_constant(4, 0x3F800000);
    fixture.fd.op_set_input(&copy, c4, 0);
    let (widen, widen_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 8);
    fixture.fd.op_set_input(&widen, copy_out, 0);
    let (term, _) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5008, 4);
    fixture.fd.op_set_input(&term, widen_out, 0);
    fixture.run("widen", &widen);
}

fn run_narrow(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_narrow", 0x1100);
    let (int2float, int2float_out) = fixture.output_op(OpCode::CPUI_FLOAT_INT2FLOAT, 0x5000, 8);
    let c8 = fixture.fd.new_constant(8, 0x40000000);
    fixture.fd.op_set_input(&int2float, c8, 0);
    let (narrow, narrow_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 4);
    fixture.fd.op_set_input(&narrow, int2float_out, 0);
    let (trunc, _) = fixture.output_op(OpCode::CPUI_FLOAT_TRUNC, 0x5008, 8);
    fixture.fd.op_set_input(&trunc, narrow_out, 0);
    fixture.run("narrow", &narrow);
}

fn run_const_narrow(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_constnarrow", 0x1200);
    let (narrow, narrow_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 4);
    let c8 = fixture.fd.new_constant(8, 0x3FF0000000000000);
    fixture.fd.op_set_input(&narrow, c8, 0);
    let (trunc, _) = fixture.output_op(OpCode::CPUI_FLOAT_TRUNC, 0x5004, 8);
    fixture.fd.op_set_input(&trunc, narrow_out, 0);
    fixture.run("constNarrow", &narrow);
}

fn run_const_widen_no_term(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_constwiden_noterm", 0x1300);
    let (widen, _) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 8);
    let c4 = fixture.fd.new_constant(4, 0x3F800000);
    fixture.fd.op_set_input(&widen, c4, 0);
    fixture.run("constWidenNoTerm", &widen);
}

fn run_const_widen(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_constwiden", 0x1400);
    let (widen, widen_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 8);
    let c4 = fixture.fd.new_constant(4, 0x3F800000);
    fixture.fd.op_set_input(&widen, c4, 0);
    let (term, _) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 4);
    fixture.fd.op_set_input(&term, widen_out, 0);
    fixture.run("constWiden", &widen);
}

fn run_exceed_block(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_exceed", 0x1500);
    let (left, left_out) = fixture.output_op(OpCode::CPUI_COPY, 0x5000, 8);
    let cl = fixture.fd.new_constant(8, 0x3FF0000000000000);
    fixture.fd.op_set_input(&left, cl, 0);
    let (right, right_out) = fixture.output_op(OpCode::CPUI_COPY, 0x5004, 8);
    let cr = fixture.fd.new_constant(8, 0x4000000000000000);
    fixture.fd.op_set_input(&right, cr, 0);
    let (add, add_out) = fixture.binary_op(OpCode::CPUI_FLOAT_ADD, 0x5008, 8);
    fixture.fd.op_set_input(&add, left_out, 0);
    fixture.fd.op_set_input(&add, right_out, 1);
    let (narrow, narrow_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x500C, 4);
    fixture.fd.op_set_input(&narrow, add_out, 0);
    let (trunc, _) = fixture.output_op(OpCode::CPUI_FLOAT_TRUNC, 0x5010, 8);
    fixture.fd.op_set_input(&trunc, narrow_out, 0);
    fixture.run("exceedBlock", &narrow);
}

fn run_arith_pass(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_arithpass", 0x1600);
    let (leftw, leftw_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 8);
    let cl = fixture.fd.new_constant(4, 0x3F800000);
    fixture.fd.op_set_input(&leftw, cl, 0);
    let (rightw, rightw_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 8);
    let cr = fixture.fd.new_constant(4, 0x40000000);
    fixture.fd.op_set_input(&rightw, cr, 0);
    let (add, add_out) = fixture.binary_op(OpCode::CPUI_FLOAT_ADD, 0x5008, 8);
    fixture.fd.op_set_input(&add, leftw_out, 0);
    fixture.fd.op_set_input(&add, rightw_out, 1);
    let (narrow, narrow_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x500C, 4);
    fixture.fd.op_set_input(&narrow, add_out, 0);
    let (trunc, _) = fixture.output_op(OpCode::CPUI_FLOAT_TRUNC, 0x5010, 8);
    fixture.fd.op_set_input(&trunc, narrow_out, 0);
    fixture.run("arithPass", &narrow);
}

fn run_compare_guard(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_compare", 0x1700);
    let (copy, copy_out) = fixture.output_op(OpCode::CPUI_COPY, 0x5000, 4);
    let c4 = fixture.fd.new_constant(4, 0x3F800000);
    fixture.fd.op_set_input(&copy, c4, 0);
    let (widen, widen_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 8);
    fixture.fd.op_set_input(&widen, copy_out, 0);
    let (otherw, otherw_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5008, 8);
    let cy = fixture.fd.new_constant(4, 0x40400000);
    fixture.fd.op_set_input(&otherw, cy, 0);
    let (less, _) = fixture.binary_op(OpCode::CPUI_FLOAT_LESS, 0x500C, 1);
    fixture.fd.op_set_input(&less, widen_out, 0);
    fixture.fd.op_set_input(&less, otherw_out, 1);
    fixture.run("compareGuard", &widen);
}

fn run_repeat_slot(architecture: &Arc<Architecture>) {
    let mut fixture = Fixture::new(architecture, "subfloat_repeat", 0x1800);
    let (widen, widen_out) = fixture.output_op(OpCode::CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 8);
    let c4 = fixture.fd.new_constant(4, 0x3F800000);
    fixture.fd.op_set_input(&widen, c4, 0);
    let (equal, _) = fixture.binary_op(OpCode::CPUI_FLOAT_EQUAL, 0x5004, 1);
    fixture.fd.op_set_input(&equal, widen_out.clone(), 0);
    fixture.fd.op_set_input(&equal, widen_out, 1);
    fixture.run("repeatSlot", &widen);
}

fn main() {
    let architecture = Arc::new(Architecture::new());
    println!("schema=1|fixture=SUBFLOAT-TRANSFORM-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    run_widen(&architecture);
    run_narrow(&architecture);
    run_const_narrow(&architecture);
    run_const_widen_no_term(&architecture);
    run_const_widen(&architecture);
    run_exceed_block(&architecture);
    run_arith_pass(&architecture);
    run_compare_guard(&architecture);
    run_repeat_slot(&architecture);
}
