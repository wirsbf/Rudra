// RETURNFOLD-GAPA-PROTOTYPES-0001 Rugra comparand — the output-locked
// direct-attach branch of ActionPrototypeTypes::apply (coreaction.cc:4637-
// 4649) driven through the production ActionPrototypeTypes::apply. Case
// matrix mirrors tests/oracle/returnfold_gapa_1204.cc byte for byte:
//   preA/retA  locked int prototype: every live non-halt RETURN gets a fresh
//              free varnode at the locked output storage (register:0x0:4,
//              from the model output entry) APPENDED at slot numInput, then
//              updateType(type, lock=true, override=true); the pre-existing
//              value slot is untouched; halt/dead RETURNs are skipped.
//   preB/postB locked void: metatype gate (cc:4639) skips everything.
//   preC/postC unlocked control: else-branch init_active_output only
//              (cc:4650-4651); no varnode attached.
//   orderA     attach order + varnode distinctness + activeoutput absence.

use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::coreaction::ActionPrototypeTypes;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>;
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

fn mtname(mt: TypeMetatype) -> &'static str {
    match mt {
        TypeMetatype::Void => "void",
        TypeMetatype::Unknown => "unknown",
        TypeMetatype::Int => "int",
        TypeMetatype::Uint => "uint",
        TypeMetatype::Bool => "bool",
        TypeMetatype::Float => "float",
        TypeMetatype::Pointer => "pointer",
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

/// "free" = no def and not a function input (the newVarnode-created
/// locked-output varnode), "input" = marked function input.
fn def_token(vn: &VarnodeRef) -> String {
    let r = vn.read().unwrap();
    if r.get_def().is_some() {
        return "def".to_string();
    }
    if r.is_input() {
        "input".to_string()
    } else {
        "free".to_string()
    }
}

struct Fixture {
    next_pc: u64,
}

impl Fixture {
    fn new(base_pc: u64) -> Self {
        Fixture { next_pc: base_pc }
    }

    fn make_block(&mut self, fd: &mut Funcdata) -> BlockRef {
        fd.create_new_block()
    }

    fn edge(&self, fd: &mut Funcdata, from: &BlockRef, to: &BlockRef) {
        fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn alloc_pc(&mut self) -> Address {
        let a = Address::new(self.next_pc);
        self.next_pc += 8;
        a
    }

    /// The first op of the given opcode in the block's op list.
    fn first_of(blk: &BlockRef, opc: OpCode) -> Option<PcodeOpRef> {
        let ops = blk.read().unwrap().get_ops();
        ops.into_iter().find(|o| o.0.read().unwrap().opcode == opc)
    }

    fn make_return_at(&mut self, fd: &mut Funcdata, blk: &BlockRef, value: Option<&VarnodeRef>) -> PcodeOpRef {
        let op = fd.new_op(if value.is_some() { 2 } else { 1 }, self.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_RETURN);
        let ret0 = fd.new_constant(1, 0);
        fd.op_set_input(&op, ret0, 0);
        if let Some(v) = value {
            fd.op_set_input(&op, v.clone(), 1);
        }
        fd.op_insert_end(&op, blk);
        op
    }

    /// Per-RETURN projection mirroring the C++ fixture byte for byte.
    fn print_return(&self, label: &str, blk: &BlockRef) {
        let ret = Self::first_of(blk, OpCode::CPUI_RETURN).expect("RETURN in block");
        let ret_r = ret.0.read().unwrap();
        let nin = ret_r.num_input();
        let last = ret_r.get_in(nin - 1).cloned().expect("last input");
        let mut line = format!("retA|blk={label}|nin={nin}|in_last={}", vdesc(&last));
        drop(ret_r);
        {
            let r = last.read().unwrap();
            if !r.is_constant() {
                let mt = r.get_type().map(|t| t.get_metatype()).unwrap_or(TypeMetatype::Unknown);
                line.push_str(&format!(
                    "|def={}|typelock={}|mt={}",
                    def_token(&last),
                    u8::from(r.is_type_lock()),
                    mtname(mt),
                ));
            }
        }
        if nin >= 3 {
            let in1 = ret.0.read().unwrap().get_in(1).cloned().expect("in1");
            line.push_str(&format!("|in1={}|in1_def={}", vdesc(&in1), def_token(&in1)));
        }
        println!("{line}");
    }
}

fn run_apply(action: &mut ActionPrototypeTypes, fd: &mut Funcdata, phase: &str) -> i32 {
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
        "schema=1|fixture=RETURNFOLD-GAPA-PROTOTYPES-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---------------- Scenario A: output-locked int ----------------
    // C++ parity: setInternal + setPieces{model, outtype=int4} fills the
    // output ProtoParameter (type int4, storage register:0x0 from the model
    // output entry) and locks output+model. Rugra's flat FuncProto holds the
    // locked return type; the apply-side port derives the storage from the
    // model output entry (ANN-F glue, FSPEC-0001/FSPEC-0002).
    let mut fd_a = Funcdata::new("gapa", Address::new(0x60000), 0x100);
    fd_a.funcp.return_type = Arc::new(Datatype::Base(TypeBase::new(
        "int".to_string(),
        4,
        TypeMetatype::Int,
    )));
    fd_a.funcp.set_output_lock(true);
    let mut f_a = Fixture::new(0x60010);
    let a0 = f_a.make_block(&mut fd_a);
    let a1 = f_a.make_block(&mut fd_a);
    let a2 = f_a.make_block(&mut fd_a);
    let a3 = f_a.make_block(&mut fd_a);
    let a4 = f_a.make_block(&mut fd_a);
    let v = fd_a.vbank.create_with_space(4, AddressSpace::Register, 0x40);
    let v = fd_a.set_input_varnode(v);
    let r_a1 = f_a.make_return_at(&mut fd_a, &a1, None); // 0x60010
    let r_a2 = f_a.make_return_at(&mut fd_a, &a2, Some(&v)); // 0x60018
    let r_h = f_a.make_return_at(&mut fd_a, &a3, None); // 0x60020
    let r_d = f_a.make_return_at(&mut fd_a, &a4, None); // 0x60028
    {
        let mut h = r_h.0.write().unwrap();
        h.flags |= rudra::op::pcodeop_flags::HALT; // cc:4643 skip marker
    }
    {
        let mut d = r_d.0.write().unwrap();
        d.flags |= rudra::op::pcodeop_flags::DEAD; // cc:4642 skip marker
    }
    f_a.edge(&mut fd_a, &a0, &a1);
    f_a.edge(&mut fd_a, &a0, &a2);
    f_a.edge(&mut fd_a, &a0, &a3);
    f_a.edge(&mut fd_a, &a0, &a4);
    println!(
        "preA|locked={}|mt={}",
        u8::from(fd_a.funcp.output_type_locked),
        mtname(fd_a.funcp.return_type.get_metatype()),
    );
    io::stdout().flush().expect("flush preA");

    let mut action_a = ActionPrototypeTypes::new();
    action_a.reset(&mut fd_a);
    let rc_a = run_apply(&mut action_a, &mut fd_a, "scenarioA");
    f_a.print_return("b1", &a1);
    f_a.print_return("b2", &a2);
    f_a.print_return("b3halt", &a3);
    f_a.print_return("b4dead", &a4);
    {
        let v1 = {
            let r = r_a1.0.read().unwrap();
            r.get_in(r.num_input() - 1).cloned().expect("b1 attach")
        };
        let v2 = {
            let r = r_a2.0.read().unwrap();
            r.get_in(r.num_input() - 1).cloned().expect("b2 attach")
        };
        let (idx1, idx2) = {
            let r1 = v1.read().unwrap();
            let r2 = v2.read().unwrap();
            (r1.get_create_index(), r2.get_create_index())
        };
        println!(
            "orderA|b1_lt_b2={}|pair_distinct={}|active={}|rc={rc_a}",
            u8::from(idx1 < idx2),
            u8::from(!Arc::ptr_eq(&v1, &v2)),
            u8::from(fd_a.active_output.is_some()),
        );
    }

    // ---------------- Scenario B: output-locked void ----------------
    let mut fd_b = Funcdata::new("gapb", Address::new(0x61000), 0x100);
    // return_type is already the ctor's void type; lock the output only.
    fd_b.funcp.set_output_lock(true);
    let mut f_b = Fixture::new(0x61010);
    let b0 = f_b.make_block(&mut fd_b);
    let r_b = f_b.make_return_at(&mut fd_b, &b0, None);
    println!(
        "preB|locked={}|mt={}",
        u8::from(fd_b.funcp.output_type_locked),
        mtname(fd_b.funcp.return_type.get_metatype()),
    );
    let mut action_b = ActionPrototypeTypes::new();
    action_b.reset(&mut fd_b);
    let rc_b = run_apply(&mut action_b, &mut fd_b, "scenarioB");
    {
        let r = r_b.0.read().unwrap();
        let last = r.get_in(r.num_input() - 1).cloned().expect("b last input");
        drop(r);
        println!(
            "postB|nin={}|in_last={}|active={}|rc={rc_b}",
            r_b.0.read().unwrap().num_input(),
            vdesc(&last),
            u8::from(fd_b.active_output.is_some()),
        );
    }

    // ---------------- Scenario C: unlocked control ----------------
    let mut fd_c = Funcdata::new("gapc", Address::new(0x62000), 0x100);
    let mut f_c = Fixture::new(0x62010);
    let c0 = f_c.make_block(&mut fd_c);
    let r_c = f_c.make_return_at(&mut fd_c, &c0, None);
    println!(
        "preC|locked={}|mt={}",
        u8::from(fd_c.funcp.output_type_locked),
        mtname(fd_c.funcp.return_type.get_metatype()),
    );
    let mut action_c = ActionPrototypeTypes::new();
    action_c.reset(&mut fd_c);
    let rc_c = run_apply(&mut action_c, &mut fd_c, "scenarioC");
    {
        let r = r_c.0.read().unwrap();
        let last = r.get_in(r.num_input() - 1).cloned().expect("c last input");
        drop(r);
        println!(
            "postC|nin={}|in_last={}|active={}|rc={rc_c}",
            r_c.0.read().unwrap().num_input(),
            vdesc(&last),
            u8::from(fd_c.active_output.is_some()),
        );
    }

    println!("case_model_glue|status=UNTESTED|note=Rugra derives the locked output storage from ProtoModel::default_x86_64 output entry (ANN-F glue, FSPEC-0001/FSPEC-0002) because the flat FuncProto has no output ProtoParameter; fixture pins only the observable address/space identity (RETURNFOLD-GAPA-PROTOTYPES-0001)");
    println!("case_multi_output|status=UNTESTED|note=model output list with >1 entry (multi-register return storage) not projected; default x86-64 model has exactly one output entry on both sides");
    println!("case_e2e_fold|status=UNTESTED|note=end-to-end return-value fold (MarkExplicit/MarkImplied/PrintC) needs GAP-D and print-stage fixtures; IR-level attach only here (RETURNFOLD upstream chain)");
}
