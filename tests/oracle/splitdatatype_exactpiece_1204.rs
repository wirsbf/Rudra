// SPLITDATATYPE-EXACTPIECE-0001 fixture — Rust side.
//
// Rust twin of tests/oracle/splitdatatype_exactpiece_1204.cc. Every record
// mirrors the Ghidra fixture case-for-case against the locked oracle
// (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b):
//
//   gv records     SplitDatatype::get_value_datatype     (subflow.cc:2910-2938)
//                  via the canonical TypeFactory::get_exact_piece
//   split records  SplitDatatype::split_copy/split_store/split_load gates
//                                                  (subflow.cc:2717/2808/2756)
//   apply records  RuleSplitStore/RuleSplitLoad::applyOp (subflow.cc:2970-3004)
//   stab records   second sweep over every op (rule-repeatapply stability)
//
// Observation planes match the C++ twin:
//   A (gate decisions)  — value-datatype shape and the split gate outcomes
//                         with piece lists, byte-identical both sides.
//   B (structural)      — rule return code, per-store/per-load effective
//                         pointer offset (resolved through the PTRSUB/PTRADD/
//                         INT_ADD constant chain back to the case's root
//                         pointer varnode) and value size, original-op
//                         identity retention, ops-added delta for NO_CHANGE
//                         cases (pre-exception state: nothing is mutated).
//   C (stability)       — a full second sweep over every op reports zero
//                         further changes.
//
// SSA discipline mirrors the C++ twin: every varnode read by more than one
// op is written (defined by a COPY from a constant); free varnodes allow a
// single descendant (varnode.cc:333-336). Observations are alive-only:
// op_destroy marks ops dead, and dead ops keep null inputs/output.

use std::sync::{Arc, RwLock};

use rugra::action::Rule;
use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::funcdata::Funcdata;
use rugra::marshal::{Element, IdRegistry, TreeDecoder};
use rugra::opcodes::OpCode;
use rugra::space::AddressSpace;
use rugra::subflow::{RuleSplitLoad, RuleSplitStore, SplitDatatype};
use rugra::type_system::datatype::{Datatype, TypeField, TypeMetatype};
use rugra::type_system::typefactory::{SizeArchInputs, TypeFactory};

type Dt = Arc<Datatype>;
type Vn = Arc<RwLock<rugra::varnode::Varnode>>;
type OpArc = Arc<RwLock<rugra::op::PcodeOp>>;
type Block = Arc<RwLock<dyn rugra::block::FlowBlock + Send + Sync>>;

fn elem_node(name: &str, attrs: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut el = Element::new();
    el.set_name(name);
    for (k, v) in attrs {
        el.add_attribute(k, v);
    }
    Arc::new(RwLock::new(el))
}

fn entry_node(size: &str, alignment: &str) -> Arc<RwLock<Element>> {
    elem_node("entry", &[("size", size), ("alignment", alignment)])
}

fn decoder_over(root: Arc<RwLock<Element>>) -> TreeDecoder {
    TreeDecoder::new(root, Arc::new(RwLock::new(IdRegistry::new())))
}

fn plain_kind(dt: &Datatype) -> &'static str {
    match dt.get_metatype() {
        TypeMetatype::PartialStruct => "partial_struct",
        TypeMetatype::PartialUnion => "partial_union",
        TypeMetatype::PartialEnum => "partial_enum",
        TypeMetatype::Enum => "enum",
        TypeMetatype::Struct => "struct",
        TypeMetatype::Union => "union",
        TypeMetatype::Array => "array",
        TypeMetatype::Uint => "uint",
        TypeMetatype::Int => "int",
        TypeMetatype::Unknown => "unknown",
        _ => "other",
    }
}

fn short_shape(dt: &Dt) -> String {
    format!("{}:{}", plain_kind(dt), dt.get_size())
}

fn shape(dt: &Dt) -> String {
    match &**dt {
        Datatype::PartialStruct(p) => format!(
            "partial_struct:{}@{}/parent={}",
            dt.get_size(),
            p.offset,
            short_shape(&p.container)
        ),
        Datatype::Array(a) => format!(
            "array:{}x{}/elem={}",
            dt.get_size(),
            a.num_elements,
            short_shape(&a.array_of)
        ),
        _ => short_shape(dt),
    }
}

/// Resolve the byte offset of `vn` relative to the case's root pointer
/// varnode, following PTRSUB/INT_ADD/PTRADD constant chains. COPYs are
/// transparent for offset purposes (they carry no offset), so the chain also
/// walks through the duplicateToTemp COPY root.
fn resolve_offset(vn: &Vn, root: &Vn) -> Option<i64> {
    if Arc::ptr_eq(vn, root) {
        return Some(0);
    }
    let def = vn.read().unwrap().get_def()?;
    if def.read().unwrap().opcode == OpCode::CPUI_COPY {
        let base = def.read().unwrap().get_in(0).cloned()?;
        return resolve_offset(&base, root);
    }
    let (opc, base, off_vn, sz_vn) = {
        let d = def.read().unwrap();
        (
            d.opcode,
            d.get_in(0).cloned()?,
            d.get_in(1).cloned()?,
            d.get_in(2).cloned(),
        )
    };
    if opc != OpCode::CPUI_PTRSUB && opc != OpCode::CPUI_INT_ADD && opc != OpCode::CPUI_PTRADD {
        return None;
    }
    let off = {
        let r = off_vn.read().unwrap();
        if !r.is_constant() {
            return None;
        }
        r.get_offset() as i64
    };
    let base_off = resolve_offset(&base, root)?;
    if opc == OpCode::CPUI_PTRADD {
        let sz = sz_vn.and_then(|s| {
            let r = s.read().unwrap();
            if r.is_constant() {
                Some(r.get_offset() as i64)
            } else {
                None
            }
        })?;
        return Some(base_off + off * sz);
    }
    Some(base_off + off)
}

fn hex16(v: u64) -> String {
    format!("{v:#x}")
}

/// Piece-projection varnode const value: direct constants resolve directly;
/// SUBPIECE-defined pieces resolve by shifting.
fn store_value_projection(vn: &Vn) -> Option<(usize, String)> {
    let (is_const, size, offset) = {
        let r = vn.read().unwrap();
        (r.is_constant(), r.get_size(), r.get_offset())
    };
    if is_const {
        let mask: u64 = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
        return Some((size, hex16(offset & mask)));
    }
    let def = vn.read().unwrap().get_def()?;
    let d = def.read().unwrap();
    if d.opcode != OpCode::CPUI_SUBPIECE {
        return None;
    }
    let base = d.get_in(0).cloned()?;
    let shift_vn = d.get_in(1).cloned()?;
    let (base_val, shift, out_size) = {
        let b = base.read().unwrap();
        let s = shift_vn.read().unwrap();
        if !b.is_constant() || !s.is_constant() {
            return None;
        }
        (b.get_offset(), s.get_offset(), vn.read().unwrap().get_size())
    };
    let mask: u64 = if out_size >= 8 {
        u64::MAX
    } else {
        (1u64 << (out_size * 8)) - 1
    };
    Some((out_size, hex16((base_val >> (shift * 8)) & mask)))
}

fn main() {
    // ---- shared production factory + architecture wiring ------------------
    let mut factory = TypeFactory::new(8);
    let map = elem_node("size_alignment_map", &[]);
    {
        let mut rg = map.write().unwrap();
        rg.add_child(entry_node("0", "1"));
        rg.add_child(entry_node("1", "1"));
        rg.add_child(entry_node("2", "2"));
        rg.add_child(entry_node("3", "2"));
        rg.add_child(entry_node("4", "4"));
        rg.add_child(entry_node("8", "8"));
        rg.add_child(entry_node("16", "8"));
        rg.add_child(entry_node("32", "8"));
    }
    let org = elem_node("data_organization", &[]);
    org.write().unwrap().add_child(map);
    factory.decode_data_organization(&mut decoder_over(org));
    factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });
    let _ = factory.set_core_type_result("undefined1", 1, TypeMetatype::Unknown, false);
    let _ = factory.set_core_type_result("undefined2", 2, TypeMetatype::Unknown, false);
    let _ = factory.set_core_type_result("undefined4", 4, TypeMetatype::Unknown, false);
    let _ = factory.set_core_type_result("undefined8", 8, TypeMetatype::Unknown, false);
    factory.cache_core_types();

    let uint4 = factory.get_base_result(4, TypeMetatype::Uint).expect("uint4");
    let uint8 = factory.get_base_result(8, TypeMetatype::Uint).expect("uint8");
    let uint1 = factory.get_base_result(1, TypeMetatype::Uint).expect("uint1");
    let uint2 = factory.get_base_result(2, TypeMetatype::Uint).expect("uint2");

    // ---- shared production type graph --------------------------------------
    // FILE-like opaque struct: size 8, zero fields.
    factory.create_struct("split_file8");
    factory
        .set_fields_sized("split_file8", vec![], 8, 8)
        .expect("file8 definition");
    // _IO_FILE-like struct: flags uint4@0, hole 4..8, 26 x uint8 @8..216.
    factory.create_struct("split_iofile216");
    let mut iofile_fields = vec![TypeField {
        name: "flags".into(),
        offset: 0,
        type_ptr: uint4.clone(),
    }];
    for i in 0..26 {
        iofile_fields.push(TypeField {
            name: format!("f{i}"),
            offset: 8 + 8 * i,
            type_ptr: uint8.clone(),
        });
    }
    factory
        .set_fields_sized("split_iofile216", iofile_fields, 216, 8)
        .expect("iofile definition");
    // ProgressData-like struct: 4 x uint4 @0..16, uint8 @16.
    factory.create_struct("split_progress24");
    factory
        .set_fields_sized(
            "split_progress24",
            vec![
                TypeField { name: "width".into(), offset: 0, type_ptr: uint4.clone() },
                TypeField { name: "height".into(), offset: 4, type_ptr: uint4.clone() },
                TypeField { name: "total".into(), offset: 8, type_ptr: uint4.clone() },
                TypeField { name: "done".into(), offset: 12, type_ptr: uint4.clone() },
                TypeField { name: "extra".into(), offset: 16, type_ptr: uint8.clone() },
            ],
            24,
            4,
        )
        .expect("progress definition");

    let file8 = factory.find_by_name("split_file8").expect("file8 canonical");
    let iofile = factory.find_by_name("split_iofile216").expect("iofile canonical");
    let progress = factory.find_by_name("split_progress24").expect("progress canonical");
    let uint4_array6 = factory.get_array(uint4.clone(), 6);

    // R15 M-1 verification types.
    // Scalar-field-interior struct: uint8@0, uint4@8 (size 12).
    factory.create_struct("split_interior12");
    factory
        .set_fields_sized(
            "split_interior12",
            vec![
                TypeField { name: "wide".into(), offset: 0, type_ptr: uint8.clone() },
                TypeField { name: "narrow".into(), offset: 8, type_ptr: uint4.clone() },
            ],
            12,
            8,
        )
        .expect("interior definition");
    // Struct with a real field-gap: uint4@0, uint4@8 (padding 4..8).
    factory.create_struct("split_gap12");
    factory
        .set_fields_sized(
            "split_gap12",
            vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: uint4.clone() },
                TypeField { name: "b".into(), offset: 8, type_ptr: uint4.clone() },
            ],
            12,
            4,
        )
        .expect("gap definition");
    // Mismatched-scalar-descent pair.
    factory.create_struct("split_mis5");
    factory
        .set_fields_sized(
            "split_mis5",
            vec![
                TypeField { name: "f0".into(), offset: 0, type_ptr: uint1.clone() },
                TypeField { name: "f1".into(), offset: 1, type_ptr: uint4.clone() },
            ],
            5,
            1,
        )
        .expect("mis5 definition");
    factory.create_struct("split_misout5");
    factory
        .set_fields_sized(
            "split_misout5",
            vec![
                TypeField { name: "f0".into(), offset: 0, type_ptr: uint1.clone() },
                TypeField { name: "f1".into(), offset: 1, type_ptr: uint2.clone() },
                TypeField { name: "f2".into(), offset: 3, type_ptr: uint2.clone() },
            ],
            5,
            1,
        )
        .expect("misout5 definition");

    let interior = factory.find_by_name("split_interior12").expect("interior canonical");
    let gap = factory.find_by_name("split_gap12").expect("gap canonical");
    let mis_in = factory.find_by_name("split_mis5").expect("mis5 canonical");
    let mis_out = factory.find_by_name("split_misout5").expect("misout5 canonical");

    let ptr_file8 = factory.get_type_pointer(8, file8.clone(), 1);
    let ptr_iofile = factory.get_type_pointer(8, iofile.clone(), 1);
    let ptr_progress = factory.get_type_pointer(8, progress.clone(), 1);
    let ptr_array = factory.get_type_pointer(8, uint4_array6.clone(), 1);
    let ptr_uint4 = factory.get_type_pointer(8, uint4.clone(), 1);
    let relptr_progress8 =
        factory.get_type_pointer_rel_ephemeral(ptr_progress.clone(), uint4.clone(), 8);
    let ptr_interior = factory.get_type_pointer(8, interior.clone(), 1);
    let ptr_gap = factory.get_type_pointer(8, gap.clone(), 1);
    let relptr_interior2 =
        factory.get_type_pointer_rel_ephemeral(ptr_interior.clone(), uint4.clone(), 2);

    let factory_arc = Arc::new(RwLock::new(factory));
    let mut arch = Architecture::new();
    arch.types = Some(factory_arc.clone());
    arch.split_datatype_config = rugra::arch::split_datatype::OPTION_STRUCT
        | rugra::arch::split_datatype::OPTION_ARRAY
        | rugra::arch::split_datatype::OPTION_POINTER;
    let arch_arc = Arc::new(arch);

    // Scratch Funcdata for the read-only get_value_datatype stubs: stub LOADs
    // have no output varnode, so they must never be swept by the rule
    // applications (which read the op output).
    let mut fd_stub = Funcdata::new("stubs", Address::new(0x9000), 0x10);
    fd_stub.arch = Some(arch_arc.clone());
    let mut fd = Funcdata::new("fixture", Address::new(0x1000), 0x100);
    fd.arch = Some(arch_arc.clone());
    let block = fd.create_new_block();

    let mut unique_counter: u64 = 0;

    // Build a written pointer varnode (COPY of a constant), SSA-safe for
    // multiple readers.
    let make_ptr = |fd: &mut Funcdata, unique_counter: &mut u64, ptr_type: &Dt| -> Vn {
        let pc = Address::new(0x2000 + 0x10 * *unique_counter);
        let copy = fd.new_op(1, pc);
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        let out = fd.new_unique_out(8, &copy);
        let c = fd.new_constant(8, 0x400000 + *unique_counter);
        fd.op_set_input(&copy, c, 0);
        out.write().unwrap().update_type(ptr_type.clone());
        fd.op_insert_end(&copy, &block);
        *unique_counter += 1;
        out
    };
    // Build a written value varnode (COPY of a constant) of the given size.
    let make_value = |fd: &mut Funcdata, unique_counter: &mut u64, size: usize| -> Vn {
        let pc = Address::new(0x2400 + 0x10 * *unique_counter);
        let copy = fd.new_op(1, pc);
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        let out = fd.new_unique_out(size, &copy);
        let c = fd.new_constant(size, 0x300000 + *unique_counter);
        fd.op_set_input(&copy, c, 0);
        fd.op_insert_end(&copy, &block);
        *unique_counter += 1;
        out
    };
    // Build a detached LOAD stub (in the scratch Funcdata) whose in(1)
    // carries the given pointer type (read-only helper for
    // get_value_datatype).
    let make_load_stub =
        |fd_stub: &mut Funcdata, unique_counter: &mut u64, ptr_type: &Dt| -> OpArc {
            let load = fd_stub.new_op(2, Address::new(0x3000 + 0x10 * *unique_counter));
            fd_stub.op_set_opcode(&load, OpCode::CPUI_LOAD);
            let ptr = fd_stub.vbank.create_with_space(
                8,
                AddressSpace::Unique,
                0x3000 + 0x10 * *unique_counter,
            );
            ptr.write().unwrap().update_type(ptr_type.clone());
            let space_vn = fd_stub.new_varnode_space(AddressSpace::Ram);
            fd_stub.op_set_input(&load, space_vn, 0);
            fd_stub.op_set_input(&load, ptr, 1);
            *unique_counter += 1;
            load.0
        };

    // ---- Plane A: get_value_datatype (subflow.cc:2910-2938) --------------
    let gv_cases: Vec<(&str, &Dt, usize)> = vec![
        ("file_opaque8", &ptr_file8, 8),
        ("iofile8", &ptr_iofile, 8),
        ("progress16", &ptr_progress, 16),
        ("array_window8", &ptr_array, 8),
        ("relptr16", &relptr_progress8, 16),
        ("scalar_array16", &ptr_uint4, 16),
        ("scalar_field_interior", &relptr_interior2, 4),
    ];
    for (id, ptr_type, size) in gv_cases {
        let stub = make_load_stub(&mut fd_stub, &mut unique_counter, ptr_type);
        let result = SplitDatatype::get_value_datatype(&stub, size, &factory_arc);
        let rendered = match result {
            Some(dt) => shape(&dt),
            None => "null".to_string(),
        };
        println!("gv|case={id}|size={size}|result={rendered}");
    }

    let split_store_rule = RuleSplitStore::new();
    let split_load_rule = RuleSplitLoad::new();

    // ---- shared helpers -----------------------------------------------------
    let mut global_second_round_changes: i32 = 0;

    // op_destroy marks ops dead; dead ops keep null inputs/output, so every
    // observation below is alive-only.
    let count_ops = |fd: &Funcdata| -> i64 { fd.obank.alivelist.len() as i64 };
    let op_alive = |fd: &Funcdata, target: &OpArc| -> bool {
        fd.obank
            .iter_alive()
            .any(|op| Arc::ptr_eq(&op.0, target))
    };
    let second_round = |fd: &mut Funcdata| -> i32 {
        let snapshot: Vec<OpArc> = fd
            .obank
            .iter_alive()
            .map(|op| op.0.clone())
            .collect();
        let mut changes = 0;
        for op in snapshot {
            let opc = op.read().unwrap().opcode;
            if opc == OpCode::CPUI_STORE {
                if split_store_rule.apply_op(&op, fd).unwrap_or(0) != 0 {
                    changes += 1;
                }
            } else if opc == OpCode::CPUI_LOAD {
                if split_load_rule.apply_op(&op, fd).unwrap_or(0) != 0 {
                    changes += 1;
                }
            }
        }
        changes
    };
    // Builds a STORE op with the given (already built) pointer and value.
    let make_store = |fd: &mut Funcdata,
                      unique_counter: &mut u64,
                      ptr: &Vn,
                      value: &Vn,
                      block: &Block|
     -> rugra::op::PcodeOpRef {
        let store = fd.new_op(3, Address::new(0x4000 + 0x10 * *unique_counter));
        fd.op_set_opcode(&store, OpCode::CPUI_STORE);
        let space_vn = fd.new_varnode_space(AddressSpace::Ram);
        fd.op_set_input(&store, space_vn, 0);
        fd.op_set_input(&store, ptr.clone(), 1);
        fd.op_set_input(&store, value.clone(), 2);
        fd.op_insert_end(&store, block);
        *unique_counter += 1;
        store
    };
    // Build a PTRSUB off a written root pointer.
    let make_ptrsub = |fd: &mut Funcdata, unique_counter: &mut u64, root: &Vn, off: u64, block: &Block| -> Vn {
        let sub = fd.new_op(2, Address::new(0x4400 + 0x10 * *unique_counter));
        fd.op_set_opcode(&sub, OpCode::CPUI_PTRSUB);
        let out = fd.new_unique_out(8, &sub);
        let c = fd.new_constant(8, off);
        fd.op_set_input(&sub, root.clone(), 0);
        fd.op_set_input(&sub, c, 1);
        fd.op_insert_end(&sub, block);
        *unique_counter += 1;
        out
    };

    // ---- Plane A: gate decisions through the public split entry points ----
    // SplitDatatype's categorize/test_datatype_compatibility members are
    // private by class-default access in the C++ twin (no `private:` label),
    // so #define private public cannot expose them; the gate outcomes are
    // observed through the public splitCopy/splitLoad/splitStore members,
    // which run the exact same gate chain before rewriting.
    let undef16 = factory_arc
        .write()
        .unwrap()
        .get_base_result(16, TypeMetatype::Unknown)
        .expect("undef16");
    let partial_progress16 = factory_arc
        .write()
        .unwrap()
        .get_type_partial_struct(progress.clone(), 0, 16);
    let partial_iofile8 = factory_arc
        .write()
        .unwrap()
        .get_type_partial_struct(iofile.clone(), 0, 8);
    let array2_uint4 = factory_arc.write().unwrap().get_array(uint4.clone(), 2);

    // whole-struct COPY gate: same Arc both sides, non-constant -> reject
    // (subflow.cc:2304-2305).
    {
        let in_vn = make_value(&mut fd, &mut unique_counter, 24);
        in_vn.write().unwrap().update_type(progress.clone());
        let out_vn = make_value(&mut fd, &mut unique_counter, 24);
        out_vn.write().unwrap().update_type(progress.clone());
        let copy = fd.new_op(1, Address::new(0x3400 + 0x10 * unique_counter));
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        fd.op_set_input(&copy, in_vn, 0);
        fd.op_set_output(&copy, out_vn);
        fd.op_insert_end(&copy, &block);
        unique_counter += 1;
        let mut splitter = SplitDatatype::new(&mut fd);
        let ok = splitter.split_copy(&copy.0).unwrap();
        println!("split|case=whole_struct_pd|fn=splitCopy|ok={}", ok as u8);
        if !ok {
            fd.op_destroy(&copy);
        }
    }
    let mut split_store_gate = |fd: &mut Funcdata,
                                unique_counter: &mut u64,
                                id: &str,
                                out_type: &Dt,
                                value: &Vn,
                                ptr_uint4: &Dt,
                                block: &Block| {
        let ptr = make_ptr(fd, unique_counter, ptr_uint4);
        let store = make_store(fd, unique_counter, &ptr, value, block);
        let mut splitter = SplitDatatype::new(fd);
        let ok = splitter.split_store(&store.0, out_type).unwrap();
        let mut pieces = "-".to_string();
        if ok {
            let mut stores: Vec<(i64, usize)> = Vec::new();
            for op in fd.obank.iter_alive() {
                let o = op.0.read().unwrap();
                if o.opcode != OpCode::CPUI_STORE {
                    continue;
                }
                let ptr_in = o.get_in(1).cloned().unwrap();
                if let Some(off) = resolve_offset(&ptr_in, &ptr) {
                    stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
                }
            }
            stores.sort();
            pieces = stores
                .iter()
                .map(|(o, s)| format!("{o}:{s}"))
                .collect::<Vec<_>>()
                .join(",");
        }
        println!("split|case={id}|fn=splitStore|ok={}|pieces={pieces}", ok as u8);
    };
    {
        let value = make_value(&mut fd, &mut unique_counter, 8);
        split_store_gate(&mut fd, &mut unique_counter, "array_window_prim", &array2_uint4, &value, &ptr_uint4, &block);
    }
    {
        let value = fd.vbank.create_constant(8, 0x1122334455667788);
        split_store_gate(&mut fd, &mut unique_counter, "array_window_const", &array2_uint4, &value, &ptr_uint4, &block);
    }
    {
        // iofile partial window: flags + padding hole -> reject (cc:2348-2353)
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_iofile);
        let value = make_value(&mut fd, &mut unique_counter, 8);
        let store = make_store(&mut fd, &mut unique_counter, &ptr, &value, &block);
        let mut splitter = SplitDatatype::new(&mut fd);
        let ok = splitter.split_store(&store.0, &partial_iofile8).unwrap();
        println!("split|case=iofile8_prim|fn=splitStore|ok={}", ok as u8);
    }
    {
        // both primitive -> reject (cc:2303)
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let load = fd.new_op(2, Address::new(0x3800 + 0x10 * unique_counter));
        fd.op_set_opcode(&load, OpCode::CPUI_LOAD);
        let _out = fd.new_unique_out(16, &load);
        let space_vn = fd.new_varnode_space(AddressSpace::Ram);
        fd.op_set_input(&load, space_vn, 0);
        fd.op_set_input(&load, ptr, 1);
        fd.op_insert_end(&load, &block);
        unique_counter += 1;
        let mut splitter = SplitDatatype::new(&mut fd);
        let ok = splitter.split_load(&load.0, &undef16).unwrap();
        println!("split|case=both_primitive|fn=splitLoad|ok={}", ok as u8);
        if !ok {
            fd.op_destroy(&load);
        }
    }
    {
        // progress16 partial window with primitive value -> 4 field pieces
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let value = make_value(&mut fd, &mut unique_counter, 16);
        let store = make_store(&mut fd, &mut unique_counter, &ptr, &value, &block);
        let mut splitter = SplitDatatype::new(&mut fd);
        let ok = splitter.split_store(&store.0, &partial_progress16).unwrap();
        let mut stores: Vec<(i64, usize)> = Vec::new();
        if ok {
            for op in fd.obank.iter_alive() {
                let o = op.0.read().unwrap();
                if o.opcode != OpCode::CPUI_STORE {
                    continue;
                }
                let ptr_in = o.get_in(1).cloned().unwrap();
                if let Some(off) = resolve_offset(&ptr_in, &ptr) {
                    stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
                }
            }
            stores.sort();
        }
        let pieces = if stores.is_empty() {
            "-".to_string()
        } else {
            stores
                .iter()
                .map(|(o, s)| format!("{o}:{s}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        println!("split|case=progress16_prim|fn=splitStore|ok={}|pieces={pieces}", ok as u8);
    }
    {
        // R15 M-1: mismatched scalar descent. in{uint1@0,uint4@1} vs
        // out{uint1@0,uint2@1,uint2@3}: at offset 1 curIn=uint4(4) >
        // curOut and is NOT a hole, so get_component(uint4,0) must return
        // null (scalar get_hole_size = type.hh:256 base 0) and the
        // cc:2363-2364 descent rejects.
        let in_vn = fd.vbank.create_constant(5, 0x11223344);
        in_vn.write().unwrap().update_type(mis_in.clone());
        let out_vn = make_value(&mut fd, &mut unique_counter, 5);
        out_vn.write().unwrap().update_type(mis_out.clone());
        let copy = fd.new_op(1, Address::new(0x3500 + 0x10 * unique_counter));
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        fd.op_set_input(&copy, in_vn, 0);
        fd.op_set_output(&copy, out_vn);
        fd.op_insert_end(&copy, &block);
        unique_counter += 1;
        let mut splitter = SplitDatatype::new(&mut fd);
        let ok = splitter.split_copy(&copy.0).unwrap();
        println!("split|case=mismatched_scalar_desc|fn=splitCopy|ok={}", ok as u8);
        if !ok {
            fd.op_destroy(&copy);
        }
    }
    let mut gap_gate = |fd: &mut Funcdata,
                        unique_counter: &mut u64,
                        id: &str,
                        out_type: &Dt,
                        ptr_gap: &Dt,
                        block: &Block| {
        let ptr = make_ptr(fd, unique_counter, ptr_gap);
        let value = make_value(fd, unique_counter, out_type.get_size());
        let store = make_store(fd, unique_counter, &ptr, &value, block);
        let mut splitter = SplitDatatype::new(fd);
        let ok = splitter.split_store(&store.0, out_type).unwrap();
        let mut stores: Vec<(i64, usize)> = Vec::new();
        if ok {
            for op in fd.obank.iter_alive() {
                let o = op.0.read().unwrap();
                if o.opcode != OpCode::CPUI_STORE {
                    continue;
                }
                let ptr_in = o.get_in(1).cloned().unwrap();
                if let Some(off) = resolve_offset(&ptr_in, &ptr) {
                    stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
                }
            }
            stores.sort();
        }
        let pieces = if stores.is_empty() {
            "-".to_string()
        } else {
            stores
                .iter()
                .map(|(o, s)| format!("{o}:{s}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        println!("split|case={id}|fn=splitStore|ok={}|pieces={pieces}", ok as u8);
    };
    {
        // Window starting on the field gap 4..8: first piece is a hole ->
        // initial-hole rejection (cc:2329-2332).
        let partial = factory_arc
            .write()
            .unwrap()
            .get_type_partial_struct(gap.clone(), 4, 4);
        gap_gate(&mut fd, &mut unique_counter, "initial_hole_window", &partial, &ptr_gap, &block);
    }
    {
        // Window 0..8: uint4 then the padding hole, terminal sizeLeft==0
        // with exactly two pieces -> two-piece padding rejection.
        let partial = factory_arc
            .write()
            .unwrap()
            .get_type_partial_struct(gap.clone(), 0, 8);
        gap_gate(&mut fd, &mut unique_counter, "two_piece_padding", &partial, &ptr_gap, &block);
    }
    {
        // Window 0..12: uint4, middle padding hole (unknown4 filler),
        // uint4 -> three pieces, hole neither initial nor second-and-final
        // -> accepted.
        let partial = factory_arc
            .write()
            .unwrap()
            .get_type_partial_struct(gap.clone(), 0, 12);
        gap_gate(&mut fd, &mut unique_counter, "padding_filler_middle", &partial, &ptr_gap, &block);
    }

    // apply: file_opaque8_store (FILE* + 8 scalar must NOT be split)
    {
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_file8);
        let value = make_value(&mut fd, &mut unique_counter, 8);
        let store = make_store(&mut fd, &mut unique_counter, &ptr, &value, &block);
        let before = count_ops(&fd);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let added = count_ops(&fd) - before;
        println!(
            "apply|case=file_opaque8_store|ret={ret}|ops_added={added}|orig_kept={}",
            op_alive(&fd, &store.0) as u8
        );
    }
    // apply: iofile8_store (window over flags + padding hole must NOT split)
    {
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_iofile);
        let value = make_value(&mut fd, &mut unique_counter, 8);
        let store = make_store(&mut fd, &mut unique_counter, &ptr, &value, &block);
        let before = count_ops(&fd);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let added = count_ops(&fd) - before;
        println!(
            "apply|case=iofile8_store|ret={ret}|ops_added={added}|orig_kept={}",
            op_alive(&fd, &store.0) as u8
        );
    }
    // apply: progress16_store (16-byte store -> 4 field stores)
    {
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let value = make_value(&mut fd, &mut unique_counter, 16);
        let store = make_store(&mut fd, &mut unique_counter, &ptr, &value, &block);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let mut stores: Vec<(i64, usize)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_STORE {
                continue;
            }
            let ptr_in = o.get_in(1).cloned().unwrap();
            if let Some(off) = resolve_offset(&ptr_in, &ptr) {
                stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
            }
        }
        stores.sort();
        let list = stores
            .iter()
            .map(|(o, s)| format!("{o}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!(
            "apply|case=progress16_store|ret={ret}|stores={list}|orig_kept={}|stab={stab}",
            op_alive(&fd, &store.0) as u8
        );
    }
    // applyload: progress16_load (16-byte load -> 4 field loads)
    {
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let load = fd.new_op(2, Address::new(0x4800 + 0x10 * unique_counter));
        fd.op_set_opcode(&load, OpCode::CPUI_LOAD);
        let _out = fd.new_unique_out(16, &load);
        let space_vn = fd.new_varnode_space(AddressSpace::Ram);
        fd.op_set_input(&load, space_vn, 0);
        fd.op_set_input(&load, ptr.clone(), 1);
        fd.op_insert_end(&load, &block);
        unique_counter += 1;
        let ret = split_load_rule.apply_op(&load.0, &mut fd).unwrap();
        let mut loads: Vec<(i64, usize)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_LOAD {
                continue;
            }
            let Some(out_vn) = o.get_out().cloned() else { continue };
            let ptr_in = o.get_in(1).cloned().unwrap();
            if let Some(off) = resolve_offset(&ptr_in, &ptr) {
                loads.push((off, out_vn.read().unwrap().get_size()));
            }
        }
        loads.sort();
        let list = loads
            .iter()
            .map(|(o, s)| format!("{o}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!(
            "applyload|case=progress16_load|ret={ret}|loads={list}|orig_gone={}|stab={stab}",
            (!op_alive(&fd, &load.0)) as u8
        );
    }
    // apply: progress8_ptrsub_store (store through PTRSUB(root,8))
    {
        let root = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let field_ptr = make_ptrsub(&mut fd, &mut unique_counter, &root, 8, &block);
        field_ptr.write().unwrap().update_type(ptr_progress.clone());
        let value = make_value(&mut fd, &mut unique_counter, 8);
        let store = make_store(&mut fd, &mut unique_counter, &field_ptr, &value, &block);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let mut stores: Vec<(i64, usize)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_STORE {
                continue;
            }
            let ptr_in = o.get_in(1).cloned().unwrap();
            if let Some(off) = resolve_offset(&ptr_in, &root) {
                stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
            }
        }
        stores.sort();
        let list = stores
            .iter()
            .map(|(o, s)| format!("{o}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!("apply|case=progress8_ptrsub_store|ret={ret}|stores={list}|stab={stab}");
    }
    // apply: array_window_store (element-pointer non-const -> gate rejects)
    {
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_uint4);
        let value = make_value(&mut fd, &mut unique_counter, 8);
        let store = make_store(&mut fd, &mut unique_counter, &ptr, &value, &block);
        let before = count_ops(&fd);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let added = count_ops(&fd) - before;
        println!(
            "apply|case=array_window_store|ret={ret}|ops_added={added}|orig_kept={}",
            op_alive(&fd, &store.0) as u8
        );
    }
    // apply: array_const_store (element-pointer constant -> 2 element stores)
    {
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_uint4);
        let value = fd.vbank.create_constant(8, 0x1122334455667788);
        let store = make_store(&mut fd, &mut unique_counter, &ptr, &value, &block);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let mut stores: Vec<(i64, usize, String)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_STORE {
                continue;
            }
            let ptr_in = o.get_in(1).cloned().unwrap();
            let Some(off) = resolve_offset(&ptr_in, &ptr) else { continue };
            let val_vn = o.get_in(2).cloned().unwrap();
            if let Some((size, val)) = store_value_projection(&val_vn) {
                stores.push((off, size, val));
            }
        }
        stores.sort_by_key(|(o, _, _)| *o);
        let list = stores
            .iter()
            .map(|(o, s, v)| format!("{o}:{s}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!("apply|case=array_const_store|ret={ret}|stores={list}|stab={stab}");
    }

    // apply: flat_array_pointer_store (uint4[6]* window over a constant —
    // RootPointer::find rejects the implied-array valueType mismatch,
    // subflow.cc:2161-2163: ptrTo=uint4[6] != element uint4 with impliedBase
    // set -> return false, zero ops added, original STORE kept)
    {
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_array);
        let value = fd.vbank.create_constant(8, 0x1122334455667788);
        let store = make_store(&mut fd, &mut unique_counter, &ptr, &value, &block);
        let before = count_ops(&fd);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let added = count_ops(&fd) - before;
        println!(
            "apply|case=flat_array_pointer_store|ret={ret}|ops_added={added}|orig_kept={}",
            op_alive(&fd, &store.0) as u8
        );
    }
    // apply: progress8_twohop_store (2-hop PTRSUB(PTRSUB(root,8),4) chain ->
    // find backs up twice, baseOffset=12; freePointerChain destroys both
    // PTRSUBs after the rewrite)
    {
        let root = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let mid = make_ptrsub(&mut fd, &mut unique_counter, &root, 8, &block);
        mid.write().unwrap().update_type(ptr_progress.clone());
        let field_ptr = make_ptrsub(&mut fd, &mut unique_counter, &mid, 4, &block);
        field_ptr.write().unwrap().update_type(ptr_progress.clone());
        let value = make_value(&mut fd, &mut unique_counter, 8);
        let store = make_store(&mut fd, &mut unique_counter, &field_ptr, &value, &block);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let mut stores: Vec<(i64, usize)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_STORE {
                continue;
            }
            let ptr_in = o.get_in(1).cloned().unwrap();
            if let Some(off) = resolve_offset(&ptr_in, &root) {
                stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
            }
        }
        stores.sort();
        let list = stores
            .iter()
            .map(|(o, s)| format!("{o}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!("apply|case=progress8_twohop_store|ret={ret}|stores={list}|stab={stab}");
    }
    // apply: addrtied_root_store (addr-tied ram-space root pointer ->
    // duplicateToTemp COPIes it into a unique temp before buildPointers,
    // subflow.cc:2874-2875; the projection resolves through that COPY)
    {
        use rugra::varnode::varnode_flags;
        let g = fd.vbank.create_with_space(8, AddressSpace::Ram, 0x7100);
        // addr-tied mapped global; the input flag mirrors the
        // heritage-provided read (free varnodes reject multiple
        // descendants, varnode.cc:334-337)
        g.write().unwrap().set_flags(
            varnode_flags::ADDRTIED | varnode_flags::INSERT | varnode_flags::INPUT,
        );
        g.write().unwrap().update_type(ptr_progress.clone());
        let value = make_value(&mut fd, &mut unique_counter, 16);
        let store = make_store(&mut fd, &mut unique_counter, &g, &value, &block);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let mut stores: Vec<(i64, usize)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_STORE {
                continue;
            }
            let ptr_in = o.get_in(1).cloned().unwrap();
            if let Some(off) = resolve_offset(&ptr_in, &g) {
                stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
            }
        }
        stores.sort();
        let list = stores
            .iter()
            .map(|(o, s)| format!("{o}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!("apply|case=addrtied_root_store|ret={ret}|stores={list}|stab={stab}");
    }
    // apply: load_feed_store (STORE(LOAD) memcpy-style — splitStore LOAD-value
    // trace subflow.cc:2815-2820 re-derives the value type from the feeding
    // LOAD and rewrites per-piece LOADs off the load root, destroying the
    // original LOAD, cc:2892-2894)
    {
        let lptr = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let load = fd.new_op(2, Address::new(0x5000 + 0x10 * unique_counter));
        fd.op_set_opcode(&load, OpCode::CPUI_LOAD);
        let lout = fd.new_unique_out(16, &load);
        let space_vn = fd.new_varnode_space(AddressSpace::Ram);
        fd.op_set_input(&load, space_vn, 0);
        fd.op_set_input(&load, lptr.clone(), 1);
        fd.op_insert_end(&load, &block);
        unique_counter += 1;
        let sptr = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let store = make_store(&mut fd, &mut unique_counter, &sptr, &lout, &block);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let mut stores: Vec<(i64, usize)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_STORE {
                continue;
            }
            let ptr_in = o.get_in(1).cloned().unwrap();
            if let Some(off) = resolve_offset(&ptr_in, &sptr) {
                stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
            }
        }
        stores.sort();
        let list = stores
            .iter()
            .map(|(o, s)| format!("{o}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!(
            "apply|case=load_feed_store|ret={ret}|stores={list}|orig_load_gone={}|stab={stab}",
            (!op_alive(&fd, &load.0)) as u8
        );
    }
    // apply: load_feed_retry_store (LOAD type fails compat — uint8 element
    // array vs uint4 struct fields, cc:2363-2364 scalar descent null — the
    // retry without the LOAD (cc:2825-2832) uses the value's undefined type
    // and splits via SUBPIECEs; the original LOAD is kept because loadOp is
    // cleared by the retry)
    {
        let ptr_uint8 = factory_arc.write().unwrap().get_type_pointer(8, uint8.clone(), 1);
        let lptr = make_ptr(&mut fd, &mut unique_counter, &ptr_uint8);
        let load = fd.new_op(2, Address::new(0x5400 + 0x10 * unique_counter));
        fd.op_set_opcode(&load, OpCode::CPUI_LOAD);
        let lout = fd.new_unique_out(16, &load);
        let space_vn = fd.new_varnode_space(AddressSpace::Ram);
        fd.op_set_input(&load, space_vn, 0);
        fd.op_set_input(&load, lptr, 1);
        fd.op_insert_end(&load, &block);
        unique_counter += 1;
        let sptr = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let store = make_store(&mut fd, &mut unique_counter, &sptr, &lout, &block);
        let ret = split_store_rule.apply_op(&store.0, &mut fd).unwrap();
        let mut stores: Vec<(i64, usize)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_STORE {
                continue;
            }
            let ptr_in = o.get_in(1).cloned().unwrap();
            if let Some(off) = resolve_offset(&ptr_in, &sptr) {
                stores.push((off, o.get_in(2).unwrap().read().unwrap().get_size()));
            }
        }
        stores.sort();
        let list = stores
            .iter()
            .map(|(o, s)| format!("{o}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!(
            "apply|case=load_feed_retry_store|ret={ret}|stores={list}|orig_load_kept={}|stab={stab}",
            op_alive(&fd, &load.0) as u8
        );
    }
    // applyload: copy_follow_load (LOAD output with a lone COPY descendant —
    // splitLoad follows the COPY (cc:2761-2771), splits the COPY's output,
    // inserts the piece LOADs before the COPY, and destroys both the COPY and
    // the original LOAD, cc:2795-2797)
    {
        let ptr = make_ptr(&mut fd, &mut unique_counter, &ptr_progress);
        let load = fd.new_op(2, Address::new(0x5800 + 0x10 * unique_counter));
        fd.op_set_opcode(&load, OpCode::CPUI_LOAD);
        let load_out = fd.new_unique_out(16, &load);
        let space_vn = fd.new_varnode_space(AddressSpace::Ram);
        fd.op_set_input(&load, space_vn, 0);
        fd.op_set_input(&load, ptr.clone(), 1);
        fd.op_insert_end(&load, &block);
        unique_counter += 1;
        let copy = fd.new_op(1, Address::new(0x5900 + 0x10 * unique_counter));
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        let out2 = fd.new_unique_out(16, &copy);
        fd.op_set_input(&copy, load_out, 0);
        fd.op_set_output(&copy, out2.clone());
        fd.op_insert_end(&copy, &block);
        unique_counter += 1;
        // keep out2 live so the reassembly concatenation is required
        let tail = fd.new_op(1, Address::new(0x5a00 + 0x10 * unique_counter));
        fd.op_set_opcode(&tail, OpCode::CPUI_COPY);
        let _tail_out = fd.new_unique_out(16, &tail);
        fd.op_set_input(&tail, out2, 0);
        fd.op_insert_end(&tail, &block);
        unique_counter += 1;
        let ret = split_load_rule.apply_op(&load.0, &mut fd).unwrap();
        let mut loads: Vec<(i64, usize)> = Vec::new();
        for op in fd.obank.iter_alive() {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_LOAD {
                continue;
            }
            let Some(out_vn) = o.get_out().cloned() else { continue };
            let ptr_in = o.get_in(1).cloned().unwrap();
            if let Some(off) = resolve_offset(&ptr_in, &ptr) {
                loads.push((off, out_vn.read().unwrap().get_size()));
            }
        }
        loads.sort();
        let list = loads
            .iter()
            .map(|(o, s)| format!("{o}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        let stab = second_round(&mut fd);
        global_second_round_changes += stab;
        println!(
            "applyload|case=copy_follow_load|ret={ret}|loads={list}|orig_gone={}|copy_gone={}|stab={stab}",
            (!op_alive(&fd, &load.0)) as u8,
            (!op_alive(&fd, &copy.0)) as u8
        );
    }

    println!("stab|global_changes={global_second_round_changes}");
}
