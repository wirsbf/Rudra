// RETURNFOLD-GAPB-CONDCONST-0001 Rudra comparand — the CPUI_RETURN special
// case of ActionConditionalConst::propagateConstant (coreaction.cc:4439-4448:
// copyBeforeRet COPY insertion) driven through the production
// ActionConditionalConst::apply + find_const_compare path. Case matrix
// mirrors tests/oracle/returnfold_gapb_1204.cc byte for byte:
//   pre     graph inventory after structure_reset (RPO pinned by creation
//           names), X location + descend order, per-block op orders,
//           return_copy flags on the three RETURNs.
//   ret     dominated RETURNs (b2/b3) read the copyBeforeRet COPY output at
//           slot 1 — never a constant — out at X's exact
//           (space,offset,size), pc equal to the RETURN's pc, no
//           return_copy flag, fresh const input 0; non-dominated b4 keeps X.
//   add     non-RETURN dominated read (INT_ADD in b2) takes the constant
//           directly, no COPY.
//   pass1   count=3, residual descend list, distinct COPY input constants.
//   pass2   reset + re-apply: count=0, IR stable.
//   ruleprop full RulePropagateCopy sweep: hits=0 (cc:3933 isReturnCopy
//           guard on the RETURN targets), `RETURN const` never created.

use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use rudra::action::{Action, Rule};
use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::coreaction::ActionConditionalConst;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::ruleaction::RulePropagateCopy;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

fn space_name(spc: AddressSpace) -> &'static str {
    match spc {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        _ => "other",
    }
}

fn vname(vn: &VarnodeRef) -> String {
    let r = vn.read().unwrap();
    format!("{}:0x{:x}:{}", space_name(r.get_space()), r.get_offset(), r.get_size())
}

fn vdesc(vn: &VarnodeRef) -> String {
    let r = vn.read().unwrap();
    if r.is_constant() {
        format!("const:0x{:x}:{}", r.get_offset(), r.get_size())
    } else {
        vname(vn)
    }
}

fn def_token(vn: &VarnodeRef) -> String {
    let def = vn.read().unwrap().get_def();
    match def {
        None => "input".to_string(),
        Some(d) => d.read().unwrap().opcode.name().to_string(),
    }
}

struct Fixture {
    blocks: Vec<BlockRef>,
    next_pc: u64,
}

impl Fixture {
    fn new() -> Self {
        Fixture { blocks: Vec::new(), next_pc: 0x60000 }
    }

    fn make_block(&mut self, fd: &mut Funcdata) -> BlockRef {
        let b = fd.create_new_block();
        self.blocks.push(b.clone());
        b
    }

    fn edge(&self, fd: &mut Funcdata, from: &BlockRef, to: &BlockRef) {
        fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn alloc_pc(&mut self) -> Address {
        let a = Address::new(self.next_pc);
        self.next_pc += 8;
        a
    }

    /// Written varnode at an explicit address: fixture IR-builder leg
    /// mirroring the C++ fixture's `fd.newVarnodeOut(size,
    /// Address(space, offset), op)` (Rudra's `create_def_with_space` does
    /// not set the op's output field, so it is set here exactly like the
    /// oracle's newVarnodeOut does).
    fn make_out(
        &self,
        fd: &mut Funcdata,
        size: usize,
        space: AddressSpace,
        offset: u64,
        op: &PcodeOpRef,
    ) -> VarnodeRef {
        let vn = fd.vbank.create_def_with_space(size, space, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        vn
    }

    fn make_cbranch_at(
        &mut self,
        fd: &mut Funcdata,
        blk: &BlockRef,
        boolvn: &VarnodeRef,
        at: Address,
    ) {
        let op = fd.new_op(2, at);
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_constant(8, 0x4000);
        fd.op_set_input(&op, target, 0);
        fd.op_set_input(&op, boolvn.clone(), 1);
        fd.op_insert_end(&op, blk);
    }

    fn name_of(&self, blk: &BlockRef) -> String {
        for (i, b) in self.blocks.iter().enumerate() {
            if Arc::ptr_eq(b, blk) {
                return format!("b{i}");
            }
        }
        "x".to_string()
    }

    fn graph_inventory(&self, fd: &Funcdata) -> String {
        let mut parts = Vec::new();
        for i in 0..fd.bblocks.get_size() {
            if let Some(bb) = fd.bblocks.get_block(i) {
                let n = self.name_of(&bb);
                let count = bb.read().unwrap().get_ops().len();
                parts.push(format!("{n}:{count}"));
            }
        }
        parts.join(",")
    }

    fn ops_of(blk: &BlockRef) -> String {
        let ops = blk.read().unwrap().get_ops();
        ops.iter()
            .map(|o| o.0.read().unwrap().opcode.name().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn descend_opcodes(source: &VarnodeRef) -> String {
        source
            .read()
            .unwrap()
            .descend_iter()
            .map(|op| op.read().unwrap().opcode.name().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The first op of the given opcode in the block's op list.
    fn first_of(blk: &BlockRef, opc: OpCode) -> Option<PcodeOpRef> {
        let ops = blk.read().unwrap().get_ops();
        ops.into_iter()
            .find(|o| o.0.read().unwrap().opcode == opc)
    }

    fn is_return_copy(op: &PcodeOpRef) -> bool {
        (op.0.read().unwrap().flags & rudra::op::pcodeop_flags::RETURN_COPY) != 0
    }

    /// Per-RETURN projection: slot-1 descriptor, the feeding COPY's
    /// geometry/flags, and the block's op order.
    fn print_return(&self, label: &str, blk: &BlockRef) {
        let ret = Self::first_of(blk, OpCode::CPUI_RETURN).expect("RETURN in block");
        let ret_r = ret.0.read().unwrap();
        let in1 = ret_r
            .get_in(1)
            .map(|v| v.clone())
            .expect("RETURN in(1)");
        let ret_pc = ret_r.get_addr().as_u64();
        drop(ret_r);
        let mut line = format!(
            "ret|blk={label}|in1_const={}|in1={}|in1_def={}|ret_pc=0x{ret_pc:x}|ret_retflag={}",
            u8::from(in1.read().unwrap().is_constant()),
            vname(&in1),
            def_token(&in1),
            u8::from(Self::is_return_copy(&ret)),
        );
        let def = in1.read().unwrap().get_def();
        if let Some(d) = def {
            let d_r = d.read().unwrap();
            if d_r.opcode == OpCode::CPUI_COPY {
                let copy_pc = d_r.get_addr().as_u64();
                let copy_in0 = d_r.get_in(0).map(|v| vdesc(&v)).unwrap_or_else(|| "-".into());
                let copy_out = d_r
                    .output
                    .as_ref()
                    .map(|o| vname(o))
                    .unwrap_or_else(|| "-".into());
                let copy_retflag =
                    u8::from((d_r.flags & rudra::op::pcodeop_flags::RETURN_COPY) != 0);
                drop(d_r);
                line.push_str(&format!(
                    "|copy_pc=0x{copy_pc:x}|copy_retflag={copy_retflag}|copy_in0={copy_in0}|copy_out={copy_out}"
                ));
            }
        }
        line.push_str(&format!("|blk_ops={}", Self::ops_of(blk)));
        println!("{line}");
    }

    /// Count RETURN ops holding a constant in any value slot (slot >= 1).
    fn returns_with_const_value_slot(&self, fd: &Funcdata) -> usize {
        let mut total = 0;
        for i in 0..fd.bblocks.get_size() {
            let Some(bb) = fd.bblocks.get_block(i) else { continue };
            for op in bb.read().unwrap().get_ops() {
                let r = op.0.read().unwrap();
                if r.opcode != OpCode::CPUI_RETURN {
                    continue;
                }
                for slot in 1..r.num_input() {
                    if let Some(v) = r.get_in(slot) {
                        if v.read().unwrap().is_constant() {
                            total += 1;
                            break;
                        }
                    }
                }
            }
        }
        total
    }

    /// Full RulePropagateCopy sweep: the rule applies to all opcodes
    /// (ruleaction.hh:730), mirroring the C++ fixture's per-block driver.
    fn run_rule_propagate_copy(&mut self, fd: &mut Funcdata) -> Result<usize, String> {
        let rule = RulePropagateCopy::new();
        let mut hits = 0;
        for i in 0..fd.bblocks.get_size() {
            let Some(bb) = fd.bblocks.get_block(i) else { continue };
            let snapshot: Vec<PcodeOpRef> = bb.read().unwrap().get_ops();
            for op in snapshot {
                match rule.apply_op(&op.0, fd) {
                    Ok(v) => hits += v.max(0) as usize,
                    Err(e) => return Err(format!("{e}")),
                }
            }
        }
        Ok(hits)
    }
}

fn run_apply(action: &mut ActionConditionalConst, fd: &mut Funcdata, phase: &str) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| action.apply(fd))) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            println!("exception|phase={phase}|what={error}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("exception|phase={phase}|what=panic");
            std::process::exit(1);
        }
    }
}

fn main() {
    println!(
        "schema=1|fixture=RETURNFOLD-GAPB-CONDCONST-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    let mut fd = Funcdata::new("gapb", Address::new(0x60000), 0x100);
    // Input parity with the C++ fixture: build the heritage info list before
    // apply (the C++ numHeritagePasses dereferences getInfo() unconditionally;
    // Rudra's num_heritage_passes reads the pass counter, but the Funcdata
    // state must match). pass=0 -> use_multiequal=false on both sides.
    fd.heritage.build_info_list();
    let mut f = Fixture::new();
    let b0 = f.make_block(&mut fd); // compare + CBRANCH
    let b1 = f.make_block(&mut fd); // constBlock (b0 true edge)
    let b2 = f.make_block(&mut fd); // INT_ADD + RETURN (dominated)
    let b3 = f.make_block(&mut fd); // RETURN (dominated)
    let b4 = f.make_block(&mut fd); // RETURN (not dominated)

    let x = fd.vbank.create_with_space(4, AddressSpace::Register, 0x0);
    fd.set_input_varnode(x.clone());
    let q = fd.vbank.create_with_space(1, AddressSpace::Register, 0x8);
    fd.set_input_varnode(q.clone());
    let const5 = fd.new_constant(4, 5);

    let eq = fd.new_op(2, f.alloc_pc()); // 0x60000
    fd.op_set_opcode(&eq, OpCode::CPUI_INT_EQUAL);
    let t = f.make_out(&mut fd, 1, AddressSpace::Unique, 0x900, &eq);
    fd.op_set_input(&eq, x.clone(), 0);
    fd.op_set_input(&eq, const5.clone(), 1);
    fd.op_insert_end(&eq, &b0);

    let add = fd.new_op(2, f.alloc_pc()); // 0x60008
    fd.op_set_opcode(&add, OpCode::CPUI_INT_ADD);
    f.make_out(&mut fd, 4, AddressSpace::Unique, 0x904, &add);
    fd.op_set_input(&add, x.clone(), 0);
    let const1 = fd.new_constant(4, 1);
    fd.op_set_input(&add, const1.clone(), 1);
    fd.op_insert_end(&add, &b2);

    let r5 = fd.new_op(2, f.alloc_pc()); // 0x60010
    fd.op_set_opcode(&r5, OpCode::CPUI_RETURN);
    let ret0a = fd.new_constant(1, 0);
    fd.op_set_input(&r5, ret0a, 0);
    fd.op_set_input(&r5, x.clone(), 1);
    fd.op_insert_end(&r5, &b2);

    let r6 = fd.new_op(2, f.alloc_pc()); // 0x60018
    fd.op_set_opcode(&r6, OpCode::CPUI_RETURN);
    let ret0b = fd.new_constant(1, 0);
    fd.op_set_input(&r6, ret0b, 0);
    fd.op_set_input(&r6, x.clone(), 1);
    fd.op_insert_end(&r6, &b3);

    let r3 = fd.new_op(2, f.alloc_pc()); // 0x60020
    fd.op_set_opcode(&r3, OpCode::CPUI_RETURN);
    let ret0c = fd.new_constant(1, 0);
    fd.op_set_input(&r3, ret0c, 0);
    fd.op_set_input(&r3, x.clone(), 1);
    fd.op_insert_end(&r3, &b4);

    let pc_b1_cbranch = f.alloc_pc(); // 0x60028
    f.make_cbranch_at(&mut fd, &b1, &q, pc_b1_cbranch);
    let pc_b0_cbranch = f.alloc_pc(); // 0x60030
    f.make_cbranch_at(&mut fd, &b0, &t, pc_b0_cbranch);
    f.edge(&mut fd, &b0, &b4); // CBRANCH out0 = false path
    f.edge(&mut fd, &b0, &b1); // CBRANCH out1 = true path (X == 5 holds)
    f.edge(&mut fd, &b1, &b2);
    f.edge(&mut fd, &b1, &b3);
    fd.structure_reset();

    println!(
        "pre|blocks={}|x_loc={}|x_desc={}|b0_ops={}|b1_ops={}|b2_ops={}|b3_ops={}|b4_ops={}|retflags=b2:{},b3:{},b4:{}",
        f.graph_inventory(&fd),
        vname(&x),
        Fixture::descend_opcodes(&x),
        Fixture::ops_of(&b0),
        Fixture::ops_of(&b1),
        Fixture::ops_of(&b2),
        Fixture::ops_of(&b3),
        Fixture::ops_of(&b4),
        u8::from(Fixture::is_return_copy(
            &Fixture::first_of(&b2, OpCode::CPUI_RETURN).expect("r5")
        )),
        u8::from(Fixture::is_return_copy(
            &Fixture::first_of(&b3, OpCode::CPUI_RETURN).expect("r6")
        )),
        u8::from(Fixture::is_return_copy(
            &Fixture::first_of(&b4, OpCode::CPUI_RETURN).expect("r3")
        )),
    );
    io::stdout().flush().expect("flush pre-action state");

    let mut action = ActionConditionalConst::new();
    action.reset(&mut fd);
    // Per-apply count zeroing mirrors the C++ fixture's CountProbe::zeroCount
    // (Ghidra zeroes count in Action::perform at status_start, action.cc:306,
    // which the direct apply() calls bypass; Rudra's apply zeroes its count
    // internally — accumulator reset-point asymmetry recorded as
    // CONDCONST-APPLY-RETURN-0001).
    action.count = 0;
    run_apply(&mut action, &mut fd, "after_pre");
    let copy5_in0 = Fixture::first_of(&b2, OpCode::CPUI_COPY)
        .and_then(|c| c.0.read().unwrap().get_in(0).cloned());
    let copy6_in0 = Fixture::first_of(&b3, OpCode::CPUI_COPY)
        .and_then(|c| c.0.read().unwrap().get_in(0).cloned());
    let distinct_copy_in0 = match (&copy5_in0, &copy6_in0) {
        (Some(a), Some(b)) => u8::from(!Arc::ptr_eq(a, b)),
        _ => 0,
    };
    println!(
        "pass1|count={}|x_desc_after={}|returns_const_value_slot={}|distinct_copy_in0={}|copies=b2:{},b3:{},b4:{}",
        action.count,
        Fixture::descend_opcodes(&x),
        f.returns_with_const_value_slot(&fd),
        distinct_copy_in0,
        u8::from(Fixture::first_of(&b2, OpCode::CPUI_COPY).is_some()),
        u8::from(Fixture::first_of(&b3, OpCode::CPUI_COPY).is_some()),
        u8::from(Fixture::first_of(&b4, OpCode::CPUI_COPY).is_some()),
    );
    f.print_return("b2", &b2);
    f.print_return("b3", &b3);
    f.print_return("b4", &b4);
    {
        let add = Fixture::first_of(&b2, OpCode::CPUI_INT_ADD).expect("INT_ADD in b2");
        let add_r = add.0.read().unwrap();
        let in0 = add_r.get_in(0).expect("add in(0)");
        let in1 = add_r.get_in(1).expect("add in(1)");
        println!(
            "add|blk=b2|in0={}|in0_const={}|in1={}",
            vdesc(&in0),
            u8::from(in0.read().unwrap().is_constant()),
            vdesc(&in1),
        );
    }

    action.reset(&mut fd);
    action.count = 0;
    run_apply(&mut action, &mut fd, "after_pass1");
    println!(
        "pass2|count={}|x_desc_after={}|b2_ops={}|b3_ops={}|b4_ops={}|returns_const_value_slot={}",
        action.count,
        Fixture::descend_opcodes(&x),
        Fixture::ops_of(&b2),
        Fixture::ops_of(&b3),
        Fixture::ops_of(&b4),
        f.returns_with_const_value_slot(&fd),
    );

    let hits = match f.run_rule_propagate_copy(&mut fd) {
        Ok(h) => h,
        Err(what) => {
            println!("exception|phase=after_pass2|what={what}");
            std::process::exit(1);
        }
    };
    let in1_def_b2 = Fixture::first_of(&b2, OpCode::CPUI_RETURN)
        .map(|r| def_token(&r.0.read().unwrap().get_in(1).expect("in1")))
        .unwrap_or_else(|| "-".into());
    let in1_def_b3 = Fixture::first_of(&b3, OpCode::CPUI_RETURN)
        .map(|r| def_token(&r.0.read().unwrap().get_in(1).expect("in1")))
        .unwrap_or_else(|| "-".into());
    let in1_const_b2 = Fixture::first_of(&b2, OpCode::CPUI_RETURN)
        .map(|r| {
            u8::from(
                r.0.read()
                    .unwrap()
                    .get_in(1)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false),
            )
        })
        .unwrap_or(0);
    let in1_const_b3 = Fixture::first_of(&b3, OpCode::CPUI_RETURN)
        .map(|r| {
            u8::from(
                r.0.read()
                    .unwrap()
                    .get_in(1)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false),
            )
        })
        .unwrap_or(0);
    println!(
        "ruleprop|hits={hits}|in1_def_b2={in1_def_b2}|in1_def_b3={in1_def_b3}|in1_const_b2={in1_const_b2}|in1_const_b3={in1_const_b3}|b2_ops={}|b3_ops={}",
        Fixture::ops_of(&b2),
        Fixture::ops_of(&b3),
    );

    println!("case_apply_return|status=UNTESTED|note=Ghidra apply returns 0 unconditionally (cc:4545) while Rudra returns count>0; apply return value not projected (CONDCONST-APPLY-RETURN-0001)");
    println!("case_phi_arm|status=UNTESTED|note=MULTIEQUAL phi replacement arm (handlePhiNodes) not exercised; use_multiequal=false on both sides here (CONDCONST-MULTIEQUAL-GUARD-0001)");
    println!("case_implied_bool|status=UNTESTED|note=implied-boolean points require boolVn without lone descendant; fixture boolVn t is read only by its CBRANCH (CONDCONST-IMPLIEDBOOL-0001)");
    println!("case_print_fold|status=UNTESTED|note=return 10 print folding needs MarkExplicit/MarkImplied/PrintC downstream (RETURNFOLD upstream GAP-A/GAP-D); IR-level only here");
}
