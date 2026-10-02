/* STOP-PTRSUB-WIRE-0001: ActionInferTypes STOP seal + PTRSUB downChain wiring
 * (Rugra comparand). Mirrors tests/oracle/stop_ptrsub_wire_1204.cc case for
 * case; see that file for the graph design commentary.
 */
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::coreaction::ActionInferTypes;
use rudra::funcdata::Funcdata;
use rudra::op::op_addl_flags;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct};
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

fn meta_token(meta: TypeMetatype) -> String {
    match meta {
        TypeMetatype::Void => "void",
        TypeMetatype::Pointer => "ptr",
        TypeMetatype::Array => "array",
        TypeMetatype::Struct => "struct",
        TypeMetatype::Spacebase => "spacebase",
        TypeMetatype::Bool => "bool",
        TypeMetatype::Int => "int",
        TypeMetatype::Uint => "uint",
        _ => "other",
    }
    .to_string()
}

/// Normalized projection shared with the C++ side (no temporary ids, no
/// factory-specific base-type names).
fn type_proj(ct: Option<&Arc<Datatype>>) -> String {
    let Some(ct) = ct else { return "null".to_string() };
    if let Datatype::Pointer(p) = ct.as_ref() {
        let mut res = format!("ptr{}->{}", p.base.size, type_proj(Some(&p.ptr_to)));
        if let Some(rel) = &p.base.pointer_rel {
            res += &format!("|rel={}:{}", rel.parent.get_name(), rel.offset);
        }
        return res;
    }
    format!("{}{}", meta_token(ct.get_metatype()), ct.get_size())
}

struct Cell {
    label: &'static str,
    vn: VarnodeRef,
}

fn snapshot(cells: &[Cell]) -> String {
    cells
        .iter()
        .map(|cell| {
            let vn = cell.vn.read().unwrap();
            format!(
                "{}:{}/stop={}",
                cell.label,
                type_proj(vn.v_type.as_ref()),
                u8::from(vn.stops_up_propagation())
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn main() {
    println!(
        "schema=1|fixture=STOP-PTRSUB-WIRE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    let (progress, progress_pointer) = {
        let mut factory = type_factory.write().unwrap();
        // Mirror the C++ fixture's setupSizes+cacheCoreTypes core-type path:
        // findAdd's alignment gate requires the default map.
        factory.set_default_alignment_map();
        let long_type = factory
            .get_base(8, TypeMetatype::Int)
            .expect("canonical int8");
        let progress = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("ProgressData".into(), 32, TypeMetatype::Struct),
            fields: vec![
                TypeField {
                    name: "total".into(),
                    offset: 0,
                    type_ptr: long_type.clone(),
                },
                TypeField {
                    name: "prev".into(),
                    offset: 8,
                    type_ptr: long_type.clone(),
                },
                TypeField {
                    name: "point".into(),
                    offset: 16,
                    type_ptr: long_type,
                },
            ],
        }));
        let pointer = factory.get_type_pointer(8, progress.clone(), 1);
        (progress, pointer)
    };
    let _ = progress;

    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(type_factory.clone());
    let mut fd = Funcdata::new("stop_ptrsub_wire", Address::new(0x5000), 0x40);
    fd.vbank.set_type_factory(type_factory.clone());
    fd.set_arch(Arc::new(architecture));
    let block = fd.create_new_block();

    let bar = fd.vbank.create_with_space(8, AddressSpace::Register, 0x100);
    let bar = fd.set_input_varnode(bar);
    bar.write()
        .unwrap()
        .update_type_lock(progress_pointer.clone(), true, false);

    let space_const = fd.new_constant(4, AddressSpace::Ram.space_id() as u64);
    let mut cells: Vec<Cell> = Vec::new();
    let mut seq: u64 = 0;

    let make_ptrsub = |fd: &mut Funcdata,
                       seq: &mut u64,
                       block: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
                       in0: &VarnodeRef,
                       off: u64,
                       stop: bool|
     -> VarnodeRef {
        let op = fd.new_op(2, Address::new(0x5000 + *seq));
        *seq += 1;
        fd.op_set_opcode(&op, OpCode::CPUI_PTRSUB);
        fd.op_set_input(&op, in0.clone(), 0);
        let cst = fd.new_constant(8, off);
        fd.op_set_input(&op, cst, 1);
        let out = fd.new_unique_out(8, &op);
        fd.op_insert_end(&op, block);
        if stop {
            // RulePtrArith/RuleStructOffset0's bare `addlflags |= 0x40` idiom
            // (ruleaction.cc:6517); op.rs has no dedicated setter.
            op.0.write().unwrap().addlflags |= op_addl_flags::STOP_TYPE_PROPAGATION;
        }
        out
    };
    let make_load = |fd: &mut Funcdata,
                     seq: &mut u64,
                     block: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
                     space: &VarnodeRef,
                     addr: &VarnodeRef|
     -> VarnodeRef {
        let op = fd.new_op(2, Address::new(0x5000 + *seq));
        *seq += 1;
        fd.op_set_opcode(&op, OpCode::CPUI_LOAD);
        fd.op_set_input(&op, space.clone(), 0);
        fd.op_set_input(&op, addr.clone(), 1);
        let out = fd.new_unique_out(8, &op);
        fd.op_insert_end(&op, block);
        out
    };
    let make_input = |fd: &mut Funcdata, offset: u64| -> VarnodeRef {
        let vn = fd.vbank.create_with_space(8, AddressSpace::Register, offset);
        fd.set_input_varnode(vn)
    };
    let make_equal = |fd: &mut Funcdata,
                      seq: &mut u64,
                      block: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
                      in0: &VarnodeRef,
                      in1: &VarnodeRef|
     -> VarnodeRef {
        let op = fd.new_op(2, Address::new(0x5000 + *seq));
        *seq += 1;
        fd.op_set_opcode(&op, OpCode::CPUI_INT_EQUAL);
        fd.op_set_input(&op, in0.clone(), 0);
        fd.op_set_input(&op, in1.clone(), 1);
        let out = fd.new_unique_out(1, &op);
        fd.op_insert_end(&op, block);
        out
    };

    // A: sealed PTRSUB + LOAD.
    let t_a = make_ptrsub(&mut fd, &mut seq, &block, &bar, 8, true);
    let v_a = make_load(&mut fd, &mut seq, &block, &space_const, &t_a);
    // B: same PTRSUB without the stop flag.
    let t_b = make_ptrsub(&mut fd, &mut seq, &block, &bar, 8, false);
    let v_b = make_load(&mut fd, &mut seq, &block, &space_const, &t_b);
    // C: INT_SUB null arm (typeop.cc:317-321 base returns null).
    let sub_op = fd.new_op(2, Address::new(0x5000 + seq));
    seq += 1;
    fd.op_set_opcode(&sub_op, OpCode::CPUI_INT_SUB);
    fd.op_set_input(&sub_op, bar.clone(), 0);
    let cst8 = fd.new_constant(8, 8);
    fd.op_set_input(&sub_op, cst8, 1);
    let t_c = fd.new_unique_out(8, &sub_op);
    fd.op_insert_end(&sub_op, &block);
    // Consumer that cannot retype tC (a LOAD's reverse edge would mask the
    // null arm — see the C++ side commentary).
    let zero = fd.new_constant(8, 0);
    let v_c = make_equal(&mut fd, &mut seq, &block, &t_c, &zero);
    // D: INT_ADD pointer arm (same propagateAddIn2Out downChain).
    let add_op = fd.new_op(2, Address::new(0x5000 + seq));
    seq += 1;
    fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&add_op, bar.clone(), 0);
    let cst8b = fd.new_constant(8, 8);
    fd.op_set_input(&add_op, cst8b, 1);
    let t_d = fd.new_unique_out(8, &add_op);
    fd.op_insert_end(&add_op, &block);
    let v_d = make_load(&mut fd, &mut seq, &block, &space_const, &t_d);
    // E/F: cc:5093 seal check through the INT_EQUAL across-input arm.
    let z = make_input(&mut fd, 0x140);
    let z2 = make_input(&mut fd, 0x180);
    let q = make_ptrsub(&mut fd, &mut seq, &block, &z, 8, true);
    let q2 = make_ptrsub(&mut fd, &mut seq, &block, &z2, 8, false);
    let c_eq = make_equal(&mut fd, &mut seq, &block, &bar, &q);
    let c_eq2 = make_equal(&mut fd, &mut seq, &block, &bar, &q2);

    for (label, vn) in [
        ("tA", t_a),
        ("tB", t_b),
        ("tC", t_c),
        ("tD", t_d),
        ("vA", v_a),
        ("vB", v_b),
        ("vC", v_c),
        ("vD", v_d),
        ("q", q),
        ("q2", q2),
        ("cEQ", c_eq),
        ("cEQ2", c_eq2),
    ] {
        cells.push(Cell { label, vn });
    }

    println!("pre|{}", snapshot(&cells));

    fd.start_type_recovery();
    let mut action = ActionInferTypes::new();
    action.reset(&mut fd);
    let mut first_types: Vec<Option<Arc<Datatype>>> = cells
        .iter()
        .map(|cell| cell.vn.read().unwrap().v_type.clone())
        .collect();
    for pass in 1..=8 {
        if let Err(error) = action.apply(&mut fd) {
            println!("exception|what={error}");
            std::process::exit(1);
        }
        match pass {
            1 => {
                first_types = cells
                    .iter()
                    .map(|cell| cell.vn.read().unwrap().v_type.clone())
                    .collect();
                println!("pass1|{}", snapshot(&cells));
            }
            2 => println!("pass2|{}", snapshot(&cells)),
            8 => {
                let stable = cells.iter().zip(first_types.iter()).all(|(cell, first)| {
                    let cur = cell.vn.read().unwrap().v_type.clone();
                    match (&cur, first) {
                        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                        (None, None) => true,
                        _ => false,
                    }
                });
                println!(
                    "pass8|{}|types_stable_since_pass1={}",
                    snapshot(&cells),
                    u8::from(stable)
                );
            }
            _ => {}
        }
    }
}
