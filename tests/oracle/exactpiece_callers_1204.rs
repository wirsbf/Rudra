// TYPEFACTORY-EXACTPIECE-CALLERS-0001 fixture — Rust side.
//
// Rust twin of tests/oracle/exactpiece_callers_1204.cc. Every record mirrors
// the Ghidra fixture case-for-case against the locked oracle
// (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b):
//
//   entry records    SymbolEntry::get_sized_type       (database.cc:151-162)
//   finalize records HighVariable::finalize_datatype   (variable.cc:551-566)
//   sync records     Funcdata::sync_varnodes_with_symbols
//                    (funcdata_varnode.cc:938-989, ct via cc:957)
//   rule records     RulePieceStructure leaf typing    (ruleaction.cc:7665)
//
// All four caller families reach the SAME Architecture-owned TypeFactory
// (arch.types captured once per caller, exactly like the C++
// symbol->getScope()->getArch()->types / data.getArch()->types chains).
// Identity is projected as Arc::ptr_eq equality bits; shapes use the same
// metatype+size grammar as the C++ side.
//
// Structural mapping notes (registered in the metadata):
//   * Rudra HighVariable::new requires a seed Arc where the C++ constructor
//     starts with a null type; both sides observe before/after identity, so
//     the null cases project "unchanged" bits instead of a null shape.
//   * Varnodes are created via VarnodeBank::create_with_space before any
//     symbol exists, mirroring Ghidra newVarnode against an empty scope
//     (funcdata_varnode.cc:148-169 sees no entry, sets no flags).

use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::{Address, RangeList};
use rudra::arch::Architecture;
use rudra::database::{Symbol, SymbolEntry};
use rudra::funcdata::Funcdata;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::opcodes::OpCode;
use rudra::ruleaction::RulePieceStructure;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeField, TypeMetatype};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::variable::{high_internal_flags, HighVariable};

type Dt = Arc<Datatype>;
type Vn = Arc<RwLock<rudra::varnode::Varnode>>;

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
        Datatype::PartialUnion(p) => format!(
            "partial_union:{}@{}/parent={}",
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

fn shape_opt(dt: &Option<Dt>) -> String {
    match dt {
        Some(t) => shape(t),
        None => "null".to_string(),
    }
}

fn bit(v: bool) -> u8 {
    if v { 1 } else { 0 }
}

fn same_opt(a: &Option<Dt>, b: &Option<Dt>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
        (None, None) => true,
        _ => false,
    }
}

fn make_symbol(dtype: &Dt, name: &str) -> Arc<RwLock<Symbol>> {
    let sym = Arc::new(RwLock::new(Symbol::new(0, name, "fixture")));
    sym.write().unwrap().dtype = Some(dtype.clone());
    sym
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
    let undef4 = factory.get_base_result(4, TypeMetatype::Unknown).expect("undefined4");

    factory.create_struct("caller_inner8");
    let inner = factory
        .set_fields_sized(
            "caller_inner8",
            vec![
                TypeField { name: "lo".into(), offset: 0, type_ptr: uint4.clone() },
                TypeField { name: "hi".into(), offset: 4, type_ptr: uint4.clone() },
            ],
            8,
            4,
        )
        .expect("inner definition");
    factory.create_struct("caller_outer24");
    let outer = factory
        .set_fields_sized(
            "caller_outer24",
            vec![
                TypeField { name: "head".into(), offset: 0, type_ptr: uint4.clone() },
                TypeField { name: "inner".into(), offset: 8, type_ptr: inner.clone() },
                TypeField { name: "tail".into(), offset: 16, type_ptr: uint8.clone() },
            ],
            24,
            8,
        )
        .expect("outer definition");
    factory.get_type_union("caller_union8");
    let union8 = factory
        .set_union_fields_sized(
            "caller_union8",
            vec![
                TypeField { name: "wide".into(), offset: 0, type_ptr: uint8.clone() },
                TypeField { name: "narrow".into(), offset: 0, type_ptr: uint4.clone() },
            ],
            8,
            8,
        )
        .expect("union definition");
    let uint4_array3 = factory.get_array(uint4.clone(), 3);

    let factory_arc = Arc::new(RwLock::new(factory));
    let mut arch = Architecture::new();
    arch.types = Some(factory_arc.clone());
    let arch_arc = Arc::new(arch);

    let mut fd = Funcdata::new("fixture", Address::new(0x1000), 0x100);
    fd.arch = Some(arch_arc.clone());
    fd.scope = Some(rudra::varmap::ScopeLocal::new());

    // All Varnodes are created BEFORE any symbol is mapped (mirrors the C++
    // fixture ordering; newVarnode against an empty scope sets no flags).
    // sync varnodes are written (def COPY from a constant) because
    // syncVarnodesWithSymbol skips free varnodes (cc:1073); finalize
    // varnodes stay free (only instances[0] size is read, variable.cc:559).
    let fin_size: [usize; 5] = [24, 8, 4, 2, 4];
    let mut fin_vn: Vec<Vn> = Vec::new();
    for (i, sz) in fin_size.iter().enumerate() {
        fin_vn.push(
            fd.vbank
                .create_with_space(*sz, AddressSpace::Stack, 0x3000 + 0x10 * i as u64),
        );
    }
    let block = fd.create_new_block();
    let sync_size: [usize; 5] = [8, 24, 4, 4, 8];
    let sync_off: [u64; 5] = [0x2008, 0x2000, 0x2002, 0x2400, 0x2500];
    let mut sync_vn: Vec<Vn> = Vec::new();
    for (i, sz) in sync_size.iter().enumerate() {
        let def = fd.new_op(1, Address::new(0x2800 + 0x10 * i as u64));
        fd.op_set_opcode(&def, OpCode::CPUI_COPY);
        let vn = fd
            .vbank
            .create_def_with_space(*sz, AddressSpace::Stack, sync_off[i], &def.0);
        def.0.write().unwrap().output = Some(vn.clone());
        let c = fd.new_constant(*sz, 0x100 + i as u64);
        fd.op_set_input(&def, c, 0);
        fd.op_insert_end(&def, &block);
        sync_vn.push(vn);
    }

    // ---- entry: SymbolEntry::get_sized_type (database.cc:151-162) --------
    let sym_outer = make_symbol(&outer, "entry_outer");
    let sym_union = make_symbol(&union8, "entry_union");
    let sym_array = make_symbol(&uint4_array3, "entry_array");
    let entry_outer =
        SymbolEntry::new_static(sym_outer.clone(), 0, Address::new(0x1000), 0, 24, RangeList::new());
    let entry_union =
        SymbolEntry::new_static(sym_union.clone(), 0, Address::new(0x1100), 0, 8, RangeList::new());
    let entry_array =
        SymbolEntry::new_static(sym_array.clone(), 0, Address::new(0x1200), 0, 12, RangeList::new());

    struct EntryCase<'a> {
        id: &'static str,
        entry: &'a SymbolEntry,
        addr: u64,
        entry_base: u64,
        sz: i32,
        expected: Option<Dt>,
        direct: Option<Dt>,
    }
    // direct partial constructions happen after factory assembly below.
    let cross_direct = factory_arc
        .write()
        .unwrap()
        .get_type_partial_struct(outer.clone(), 2, 4);
    let wrong_size_direct = factory_arc
        .write()
        .unwrap()
        .get_type_partial_struct(outer.clone(), 0, 16);
    let union_direct = factory_arc
        .write()
        .unwrap()
        .get_type_partial_union(union8.clone(), 1, 4);
    let entry_cases: Vec<EntryCase> = vec![
        EntryCase { id: "entry_whole", entry: &entry_outer, addr: 0x1000, entry_base: 0x1000, sz: 24, expected: Some(outer.clone()), direct: None },
        EntryCase { id: "entry_nested", entry: &entry_outer, addr: 0x1008, entry_base: 0x1000, sz: 8, expected: Some(inner.clone()), direct: None },
        EntryCase { id: "entry_leaf", entry: &entry_outer, addr: 0x100c, entry_base: 0x1000, sz: 4, expected: Some(uint4.clone()), direct: None },
        EntryCase { id: "entry_cross_partial", entry: &entry_outer, addr: 0x1002, entry_base: 0x1000, sz: 4, expected: None, direct: Some(cross_direct) },
        EntryCase { id: "entry_wrong_size_partial", entry: &entry_outer, addr: 0x1000, entry_base: 0x1000, sz: 16, expected: None, direct: Some(wrong_size_direct) },
        EntryCase { id: "entry_beyond", entry: &entry_outer, addr: 0x1016, entry_base: 0x1000, sz: 16, expected: None, direct: None },
        EntryCase { id: "entry_union_partial", entry: &entry_union, addr: 0x1101, entry_base: 0x1100, sz: 4, expected: None, direct: Some(union_direct) },
        EntryCase { id: "entry_array_elem", entry: &entry_array, addr: 0x1204, entry_base: 0x1200, sz: 4, expected: Some(uint4.clone()), direct: None },
    ];
    for c in &entry_cases {
        let mut w = factory_arc.write().unwrap();
        let first = c.entry.get_sized_type(&mut w, Address::new(c.addr), c.sz);
        let repeat = c.entry.get_sized_type(&mut w, Address::new(c.addr), c.sz);
        drop(w);
        let expected: Option<Dt> = c
            .direct
            .clone()
            .or_else(|| c.expected.clone());
        let same_expected = match (&first, &expected) {
            (Some(x), Some(y)) => Arc::ptr_eq(x, y),
            (None, None) => true,
            _ => false,
        };
        let sym_type = match c.id {
            "entry_whole" | "entry_nested" | "entry_leaf" | "entry_cross_partial"
            | "entry_wrong_size_partial" | "entry_beyond" => {
                sym_outer.read().unwrap().dtype.clone()
            }
            "entry_union_partial" => sym_union.read().unwrap().dtype.clone(),
            _ => sym_array.read().unwrap().dtype.clone(),
        };
        let same_symbol = match (&first, &sym_type) {
            (Some(x), Some(y)) => Arc::ptr_eq(x, y),
            (None, None) => true,
            _ => false,
        };
        let repeat_same = match (&first, &repeat) {
            (Some(x), Some(y)) => Arc::ptr_eq(x, y),
            (None, None) => true,
            _ => false,
        };
        print!(
            "entry|case={}|off={}|sz={}|result={}|same_symbol={}|same_expected={}|repeat_same={}|direct_same=",
            c.id,
            (c.addr - c.entry_base) as i64,
            c.sz,
            shape_opt(&first),
            bit(same_symbol),
            bit(same_expected),
            bit(repeat_same),
        );
        match &c.direct {
            Some(d) => {
                let direct_same = match &first {
                    Some(x) => Arc::ptr_eq(x, d),
                    None => false,
                };
                println!("{}", bit(direct_same));
            }
            None => println!("na"),
        }
    }

    // ---- finalize: HighVariable::finalize_datatype (variable.cc:551-566) --
    let sym_fin_undef = make_symbol(&undef4, "fin_undef");
    struct FinalizeCase {
        id: &'static str,
        sym: Arc<RwLock<Symbol>>,
        offset: i32,
        vn_index: usize,
        expected: Option<Dt>, // filled for the three success cases
    }
    let fin_partial_direct = factory_arc
        .write()
        .unwrap()
        .get_type_partial_struct(outer.clone(), 2, 4);
    let fin_cases: Vec<FinalizeCase> = vec![
        FinalizeCase { id: "finalize_whole", sym: sym_outer.clone(), offset: -1, vn_index: 0, expected: Some(outer.clone()) },
        FinalizeCase { id: "finalize_nested", sym: sym_outer.clone(), offset: 8, vn_index: 1, expected: Some(inner.clone()) },
        FinalizeCase { id: "finalize_partial", sym: sym_outer.clone(), offset: 2, vn_index: 2, expected: Some(fin_partial_direct) },
        FinalizeCase { id: "finalize_null", sym: sym_outer.clone(), offset: 9, vn_index: 3, expected: None },
        FinalizeCase { id: "finalize_unknown", sym: sym_fin_undef.clone(), offset: 0, vn_index: 4, expected: None },
    ];
    for c in &fin_cases {
        // C++ `new HighVariable(vn)` starts with a null type; Rudra's glue
        // constructor requires a seed, so the null/unknown cases project
        // before/after identity against the seed.
        let mut high = HighVariable::new(uint4.clone());
        high.instances.push(fin_vn[c.vn_index].clone());
        high.symbol = Some(c.sym.clone());
        high.symbol_offset = c.offset;
        let before = high.v_type.get();
        high.finalize_datatype(&mut factory_arc.write().unwrap());
        let after = high.v_type.get();
        let finalized = (high.highflags & high_internal_flags::TYPE_FINALIZED) != 0;
        let expected: Dt = c.expected.clone().unwrap_or_else(|| before.clone());
        println!(
            "finalize|case={}|off={}|sz={}|finalized={}|same_before={}|same_expected={}",
            c.id,
            c.offset,
            fin_size[c.vn_index],
            bit(finalized),
            bit(Arc::ptr_eq(&after, &before)),
            bit(Arc::ptr_eq(&after, &expected)),
        );
    }

    // ---- sync: Funcdata::sync_varnodes_with_symbols (cc:938-989) ---------
    let sync_before: Vec<Option<Dt>> = sync_vn
        .iter()
        .map(|vn| vn.read().unwrap().get_type())
        .collect();
    {
        let scope = fd.scope.as_mut().expect("scope");
        let mut push = |name: &str, start: u64, size: i32, dtype: &Dt| {
            let mut s = rudra::varmap::LocalSymbol::new(name, start, size, Some(dtype.clone()), -1);
            s.typelock = true;
            scope.symbols.push(s);
        };
        push("sync_outer", 0x2000, 24, &outer);
        push("sync_unk", 0x2400, 4, &undef4);
        push("sync_small", 0x2500, 4, &uint4);
    }
    let updated = fd.sync_varnodes_with_symbols(true, false);
    let sync_partial_direct = factory_arc
        .write()
        .unwrap()
        .get_type_partial_struct(outer.clone(), 2, 4);
    struct SyncCase {
        id: &'static str,
        vn_index: usize,
        expected: Option<Dt>,
    }
    let sync_cases: Vec<SyncCase> = vec![
        SyncCase { id: "sync_nested", vn_index: 0, expected: Some(inner.clone()) },
        SyncCase { id: "sync_whole", vn_index: 1, expected: Some(outer.clone()) },
        SyncCase { id: "sync_partial", vn_index: 2, expected: Some(sync_partial_direct) },
        SyncCase { id: "sync_unknown_drop", vn_index: 3, expected: None },
        SyncCase { id: "sync_small_symbol", vn_index: 4, expected: None },
    ];
    for c in &sync_cases {
        let vn = &sync_vn[c.vn_index];
        let after = vn.read().unwrap().get_type();
        let expected: Option<Dt> = c
            .expected
            .clone()
            .or_else(|| sync_before[c.vn_index].clone());
        let (mapped, addrtied, typelock) = {
            let v = vn.read().unwrap();
            (
                (v.flags & rudra::varnode::varnode_flags::MAPPED) != 0,
                (v.flags & rudra::varnode::varnode_flags::ADDRTIED) != 0,
                (v.flags & rudra::varnode::varnode_flags::TYPELOCK) != 0,
            )
        };
        println!(
            "sync|case={}|off={}|sz={}|updated={}|same_before={}|same_expected={}|mapped={}|addrtied={}|typelock={}",
            c.id,
            sync_off[c.vn_index],
            sync_size[c.vn_index],
            bit(updated),
            bit(same_opt(&after, &sync_before[c.vn_index])),
            bit(same_opt(&after, &expected)),
            bit(mapped),
            bit(addrtied),
            bit(typelock),
        );
    }

    // ---- rule: RulePieceStructure leaf typing (ruleaction.cc:7665) -------
    // Leaves are written by COPY defs: a free varnode cannot take a second
    // reader (Varnode::addDescend varnode.cc:334-336) and the rule inserts a
    // COPY that reads each leaf next to its original reader.
    fn written_unique(
        fd: &mut Funcdata,
        block: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
        size: usize,
        offset: u64,
        op_addr: u64,
        val: u64,
    ) -> Vn {
        let def = fd.new_op(1, Address::new(op_addr));
        fd.op_set_opcode(&def, OpCode::CPUI_COPY);
        let vn = fd
            .vbank
            .create_def_with_space(size, AddressSpace::Unique, offset, &def.0);
        def.0.write().unwrap().output = Some(vn.clone());
        let c = fd.new_constant(size, val);
        fd.op_set_input(&def, c, 0);
        fd.op_insert_end(&def, block);
        vn
    }
    let op_r = fd.new_op(2, Address::new(0x3000));
    fd.op_set_opcode(&op_r, OpCode::CPUI_PIECE);
    let vn_o = fd.new_varnode_out(24, Address::new(0x5000), &op_r);
    vn_o.write().unwrap().update_type(outer.clone());
    let vn_l0 = written_unique(&mut fd, &block, 8, 0x6010, 0x3050, 0x11);
    fd.op_set_input(&op_r, vn_l0.clone(), 1); // least-significant leaf, typeOffset 0
    let op_p = fd.new_op(2, Address::new(0x3010));
    fd.op_set_opcode(&op_p, OpCode::CPUI_PIECE);
    let vn_m = fd.new_varnode_out(16, Address::new(0x5100), &op_p);
    fd.op_set_input(&op_r, vn_m.clone(), 0); // most-significant piece, typeOffset 8
    let vn_l1 = written_unique(&mut fd, &block, 8, 0x6020, 0x3060, 0x22);
    fd.op_set_input(&op_p, vn_l1.clone(), 1); // low of M, typeOffset 8
    let vn_l2 = written_unique(&mut fd, &block, 8, 0x6030, 0x3070, 0x33);
    fd.op_set_input(&op_p, vn_l2.clone(), 0); // high of M, typeOffset 16
    fd.op_insert_end(&op_r, &block);
    fd.op_insert_end(&op_p, &block);
    let piece_rule = RulePieceStructure::new();
    let rc = piece_rule.apply_op(&op_r.0, &mut fd).expect("apply_op");
    let rule_low_partial_direct = factory_arc
        .write()
        .unwrap()
        .get_type_partial_struct(outer.clone(), 0, 8);
    let base = vn_o.read().unwrap().get_offset();
    let (r_low_type, r_low_def, r_low_addr, r_low_proto) = {
        let r = op_r.0.read().unwrap();
        let low = r.inrefs[1].clone();
        let v = low.read().unwrap();
        (
            v.get_type(),
            v.get_def().map(|d| d.read().unwrap().opcode),
            v.get_offset(),
            v.is_proto_partial(),
        )
    };
    println!(
        "rule|case=rule_low_partial|applied={}|low_result={}|low_same_direct={}|low_def={}|low_addr_delta={}|low_proto={}",
        bit(rc != 0),
        shape_opt(&r_low_type),
        bit(r_low_type
            .as_ref()
            .map(|t| Arc::ptr_eq(t, &rule_low_partial_direct))
            .unwrap_or(false)),
        match r_low_def {
            Some(OpCode::CPUI_COPY) => "COPY",
            _ => "OTHER",
        },
        r_low_addr as i64 - base as i64,
        bit(r_low_proto),
    );
    let (p_low_type, p_high_type, r_mid_addr, r_mid_size) = {
        let p = op_p.0.read().unwrap();
        let low = p.inrefs[1].clone();
        let high = p.inrefs[0].clone();
        let r = op_r.0.read().unwrap();
        let mid = r.inrefs[0].clone();
        drop(p);
        drop(r);
        let low_type = low.read().unwrap().get_type();
        let high_type = high.read().unwrap().get_type();
        let mid_v = mid.read().unwrap();
        (low_type, high_type, mid_v.get_offset(), mid_v.get_size())
    };
    println!(
        "rule|case=rule_leaf_identity|inner_result={}|inner_same={}|tail_result={}|tail_same={}|mid_addr_delta={}|mid_size={}",
        shape_opt(&p_low_type),
        bit(p_low_type
            .as_ref()
            .map(|t| Arc::ptr_eq(t, &inner))
            .unwrap_or(false)),
        shape_opt(&p_high_type),
        bit(p_high_type
            .as_ref()
            .map(|t| Arc::ptr_eq(t, &uint8))
            .unwrap_or(false)),
        r_mid_addr as i64 - base as i64,
        r_mid_size,
    );
}
