//! RULEACTION-RS0-RELGATE-0001: Rugra side of the locked 12.0.4 oracle
//! fixture for `RuleStructOffset0::applyOp`'s formal relative-pointer branch
//! (ruleaction.cc:6695-6725).
//!
//! Mirrors `rule_structoffset0_relptr_1204.cc` case-for-case (same names,
//! same observation format):
//!   case=<name>|apply=<0/1>
//!     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
//!   endcase
//!
//! Covered arms: field-start PTRSUB(#0) rewire (cc:6721-6722), interior
//! offset INT_ADD back-fill (cc:6716-6720), wordsize scaling via
//! `AddrSpace::byteToAddress` (cc:6709), the STORE form (movesize from
//! in(2), cc:6684-6686), the evaluateThruParent(0) gate rejection
//! (type.cc:2591-2592 → plain path), subtype-too-small (cc:6708) and
//! past-parent gate rejections.

use std::sync::{Arc, RwLock};

use rugra::action::Rule;
use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::block::{BlockBasic, FlowBlock};
use rugra::funcdata::Funcdata;
use rugra::opcodes::OpCode;
use rugra::ruleaction::RuleStructOffset0;
use rugra::varnode::Varnode;

type VnRef = Arc<RwLock<Varnode>>;
type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn vn_class(vn: Option<&VnRef>) -> char {
    match vn {
        None => '_',
        Some(v) => {
            let v = v.read().unwrap();
            if v.is_constant() {
                'c'
            } else if v.is_written() {
                'w'
            } else {
                'o'
            }
        }
    }
}

fn print_op_line(op: &rugra::op::PcodeOpRef) {
    let g = op.0.read().unwrap();
    let addr = g.get_addr().to_space_address().get_offset();
    let mut line = format!("  op={}@0x{:x}|nin={}", g.opcode as i32, addr, g.num_input());
    let sentinel = rugra::op::null_slot_sentinel();
    for i in 0..3 {
        let vn = g.get_in(i).filter(|v| !Arc::ptr_eq(*v, &sentinel));
        match vn {
            Some(v) => {
                let r = v.read().unwrap();
                line += &format!(
                    "|in{}={}|{}|0x{:x}",
                    i,
                    vn_class(Some(v)),
                    r.get_size(),
                    r.get_offset()
                );
            }
            None => {
                line += &format!("|in{}=_|0|0x0", i);
            }
        }
    }
    let out_size = g
        .output
        .as_ref()
        .map(|o| o.read().unwrap().get_size() as i64)
        .unwrap_or(-1);
    line += &format!("|out={}\n", out_size);
    print!("{}", line);
}

fn dump_case_window(fd: &Funcdata, lo: u64, hi: u64) {
    for op in fd.begin_op_all() {
        let a = op.0.read().unwrap().get_addr().to_space_address().get_offset();
        if a < lo || hi < a {
            continue;
        }
        print_op_line(op);
    }
}

struct CaseSpec {
    name: &'static str,
    base: u64,
    is_store: bool,
    rel_off: i64,
    wordsize: usize,
    ptr_to_is_struct: bool,
    move_size: usize,
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    fd.set_type_recovery_started(); // hasTypeRecoveryStarted gate (cc:6680)

    // Shared canvas types: parent struct {a@0 int, b@4 int} (size 8) and the
    // int base — mirrors TypeFactory getBase/getTypeStruct+setFields on the
    // C++ side.
    use rugra::type_system::datatype::{
        type_flags, Datatype, PointerRelState, TypeBase, TypeField, TypeMetatype, TypePointer,
        TypeStruct,
    };
    let int4t: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
        "int".into(),
        4,
        TypeMetatype::Int,
    )));
    let parent_struct: Arc<Datatype> = Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("parent2".into(), 8, TypeMetatype::Struct),
        fields: vec![
            TypeField { name: "a".into(), offset: 0, type_ptr: int4t.clone() },
            TypeField { name: "b".into(), offset: 4, type_ptr: int4t.clone() },
        ],
    }));

    let block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x8000))));
    fd.bblocks.add_block(block.clone());

    let cases: Vec<CaseSpec> = vec![
        CaseSpec { name: "rel_field_start", base: 0x820000, is_store: false, rel_off: 4, wordsize: 1, ptr_to_is_struct: false, move_size: 4 },
        CaseSpec { name: "rel_interior_int_add", base: 0x820100, is_store: false, rel_off: 6, wordsize: 1, ptr_to_is_struct: false, move_size: 4 },
        CaseSpec { name: "rel_wordsize2", base: 0x820200, is_store: false, rel_off: 6, wordsize: 2, ptr_to_is_struct: false, move_size: 4 },
        CaseSpec { name: "rel_store_interior", base: 0x820300, is_store: true, rel_off: 6, wordsize: 1, ptr_to_is_struct: false, move_size: 4 },
        CaseSpec { name: "rel_thru_parent_gate", base: 0x820400, is_store: false, rel_off: 6, wordsize: 1, ptr_to_is_struct: true, move_size: 4 },
        CaseSpec { name: "rel_subtype_too_small", base: 0x820500, is_store: false, rel_off: 0, wordsize: 1, ptr_to_is_struct: false, move_size: 8 },
        CaseSpec { name: "rel_offset_past_parent", base: 0x820600, is_store: false, rel_off: 8, wordsize: 1, ptr_to_is_struct: false, move_size: 4 },
    ];

    let rule = RuleStructOffset0::new();
    for spec in &cases {
        let base = spec.base;
        // Formal rel pointer over the parent struct (IS_PTRREL, no
        // HAS_STRIPPED — isFormalPointerRel true).
        let ptr_to: Arc<Datatype> = if spec.ptr_to_is_struct {
            parent_struct.clone()
        } else {
            int4t.clone()
        };
        let mut tp = TypePointer {
            base: TypeBase::new("relptr".into(), 8, TypeMetatype::Pointer),
            ptr_to,
            wordsize: spec.wordsize,
        };
        tp.base.flags |= type_flags::IS_PTRREL;
        tp.base.pointer_rel = Some(PointerRelState {
            parent: parent_struct.clone(),
            offset: spec.rel_off,
            stripped: None,
        });
        let rel_dt = Arc::new(Datatype::Pointer(tp));

        // COPY @base+0x10: out8 <- #0x100, typed as the rel pointer.
        let writer = fd.new_op(1, Address::new(base + 0x10));
        fd.op_set_opcode(&writer, OpCode::CPUI_COPY);
        let ptr_out = fd.new_unique_out(8, &writer);
        let c = fd.new_constant(8, 0x100);
        fd.op_set_input(&writer, c, 0);
        ptr_out.write().unwrap().update_type(rel_dt);
        fd.op_insert_end(&writer, &block);

        // LOAD/STORE @base+0x40.
        let op = if spec.is_store {
            let op = fd.new_op(3, Address::new(base + 0x40));
            fd.op_set_opcode(&op, OpCode::CPUI_STORE);
            let spc = fd.new_constant(8, 1);
            fd.op_set_input(&op, spc, 0);
            fd.op_set_input(&op, ptr_out, 1);
            let val = fd.new_constant(spec.move_size, 0x5a);
            fd.op_set_input(&op, val, 2);
            op
        } else {
            let op = fd.new_op(2, Address::new(base + 0x40));
            fd.op_set_opcode(&op, OpCode::CPUI_LOAD);
            fd.new_unique_out(spec.move_size, &op);
            let spc = fd.new_constant(8, 1);
            fd.op_set_input(&op, spc, 0);
            fd.op_set_input(&op, ptr_out, 1);
            op
        };
        fd.op_insert_end(&op, &block);

        let apply = rule.apply_op(&op.0, &mut fd).unwrap();
        println!("case={}|apply={}", spec.name, apply);
        dump_case_window(&fd, base, base + 0x80);
        println!("endcase");
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode != "normal" {
        eprintln!("unknown mode: {mode}");
        std::process::exit(2);
    }
    run();
}
