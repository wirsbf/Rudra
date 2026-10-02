// Locked Ghidra 12.0.4 oracle for PRINTC-SUBPIECE-FIELDEXTRACT-0001
// (Rust side). Mirrors tests/oracle/printc_subpiece_fieldextract_1204.cc
// record-for-record:
//   - piece.*     : Datatype::is_piece_structured sweep (type.hh:929).
//   - cast.*      : CastStrategyC::is_subpiece_cast partial arms + enum
//                   mapping + struct rejection (cast.cc:411-432).
//   - armA/armB   : the two printc.cc:846-871 bodies via the RPN dispatch
//                   (PrintC::op_subpiece_rpn — the twin of Ghidra's public
//                   virtual PrintC::opSubpiece, printc.hh:334):
//                     armA.field     -> "S.hi"   (pushPartialSymbol walk)
//                     armA.array     -> "S.arr[0]" (array getSubEntry walk)
//                     armA.synthetic -> "S._2_4_" (unnamedField, printlanguage.cc:719)
//                     armB.field     -> "S.lo"   (findTruncation/object_member)
//   - arm*.union* : the TypeUnion::findTruncation (type.cc:2185-2199)
//                   (op,slot)-resolution-cache READ side, entries installed
//                   through the real Funcdata::setUnionField write port
//                   (funcdata.cc:937) at the artificial SUBPIECE slot 1:
//                     armB.unionhit  -> "U.b"   (cached field, field-atom arm)
//                     armA.unionhit  -> "V.b"   (cached field, walk descent)
//                     armA.unionmiss -> "W"     (miss: size==sz break)
//                     armA.unionspan -> "X"     (hit but off+sz spans fields)
//                     armA.unionsynth-> "Z._0_2_" (miss: synthetic entry)
//
// The object graph mirrors the C++ fixture: a register-space Varnode typed
// with the fixture struct, a HighVariable whose symbol "S" carries the
// struct type (symbol_offset -1 = perfect match), a SUBPIECE op with
// SPECIAL_PRINT set reading it, and a 4-byte output.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::database::Symbol;
use rudra::op::{op_addl_flags, PcodeOp};
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{
    Datatype, TypeArray, TypeBase, TypeMetatype, TypePartialEnum, TypePartialStruct,
    TypePartialUnion, TypePointer, TypeStruct, TypeUnion,
};
use rudra::variable::HighVariable;
use rudra::varnode::{varnode_flags, Varnode};

type VnRef = Arc<RwLock<Varnode>>;

fn int4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)))
}

fn uint4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new("uint".to_string(), 4, TypeMetatype::Uint)))
}

/// fixture_pair { int lo @0; int hi @4; } (same layout as the C++ fixture).
fn fixture_pair() -> Arc<Datatype> {
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("fixture_pair".to_string(), 8, TypeMetatype::Struct),
        fields: vec![
            rudra::type_system::datatype::TypeField {
                name: "lo".to_string(),
                offset: 0,
                type_ptr: int4(),
            },
            rudra::type_system::datatype::TypeField {
                name: "hi".to_string(),
                offset: 4,
                type_ptr: int4(),
            },
        ],
    }))
}

/// fixture_arr { int arr[2] @0; int tail @8; } — the tail field mirrors the
/// C++ fixture's guard against TypeStruct::setFields' needs_resolution flag
/// (type.cc:1569-1571: field[0] filling the whole struct).
fn fixture_arr() -> Arc<Datatype> {
    let arr2 = Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new("int[2]".to_string(), 8, TypeMetatype::Array),
        array_of: int4(),
        num_elements: 2,
    }));
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("fixture_arr".to_string(), 12, TypeMetatype::Struct),
        fields: vec![
            rudra::type_system::datatype::TypeField {
                name: "arr".to_string(),
                offset: 0,
                type_ptr: arr2,
            },
            rudra::type_system::datatype::TypeField {
                name: "tail".to_string(),
                offset: 8,
                type_ptr: int4(),
            },
        ],
    }))
}

fn fixture_union() -> Arc<Datatype> {
    // Ghidra's TypeUnion ctor ALWAYS sets needs_resolution (type.hh:551);
    // unions never lose the flag through setFields (type.cc:2002-2009). The
    // flag drives the artificial SUBPIECE slot 1 (printc.cc:858) and blocks
    // the pushPartialSymbol loop-top whole-type break (printc.cc:1962).
    let mut base = TypeBase::new("fixture_alt".to_string(), 4, TypeMetatype::Union);
    base.flags |= rudra::type_system::datatype::type_flags::NEEDS_RESOLUTION;
    Arc::new(Datatype::Union(TypeUnion {
        base,
        fields: vec![
            rudra::type_system::datatype::TypeField {
                name: "a".to_string(),
                offset: 0,
                type_ptr: int4(),
            },
            rudra::type_system::datatype::TypeField {
                name: "b".to_string(),
                offset: 0,
                type_ptr: uint4(),
            },
        ],
    }))
}

/// fixture_inner { long x } — single field fills the whole struct. The flag
/// is set MANUALLY here to mirror the REAL TypeFactory::setFields behaviour
/// (type.cc:1569-1871); Rugra's own TypeFactory::set_fields does not yet set
/// it (TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001).
fn fixture_inner() -> Arc<Datatype> {
    let int8 = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(),
        8,
        TypeMetatype::Int,
    )));
    let mut base = TypeBase::new("fixture_inner".to_string(), 8, TypeMetatype::Struct);
    base.flags |= rudra::type_system::datatype::type_flags::NEEDS_RESOLUTION;
    Arc::new(Datatype::Struct(TypeStruct {
        base,
        fields: vec![rudra::type_system::datatype::TypeField {
            name: "x".to_string(),
            offset: 0,
            type_ptr: int8,
        }],
    }))
}

/// fixture_outer { fixture_inner in @0; long tail @8 } — two fields, no
/// needs_resolution (mirrors the C++ fixture construction).
fn fixture_outer() -> Arc<Datatype> {
    let int8 = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(),
        8,
        TypeMetatype::Int,
    )));
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("fixture_outer".to_string(), 16, TypeMetatype::Struct),
        fields: vec![
            rudra::type_system::datatype::TypeField {
                name: "in".to_string(),
                offset: 0,
                type_ptr: fixture_inner(),
            },
            rudra::type_system::datatype::TypeField {
                name: "tail".to_string(),
                offset: 8,
                type_ptr: int8,
            },
        ],
    }))
}

fn fixture_enum() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "fixture_mode".to_string(),
        4,
        TypeMetatype::Enum,
    )))
}

/// Register-space struct-typed Varnode with a HighVariable whose symbol
/// (symbol_offset -1 = perfect whole-map match) carries the same struct
/// type. Mirrors the C++ fixture's type-locked ScopeLocal symbol
/// (addSymbol + setAttribute(typelock)) attached to the varnode via
/// Varnode::setSymbolProperties (varnode.cc:409-421).
fn struct_vn(
    container: Arc<Datatype>,
    symbol_name: &str,
    reg_offset: u64,
    size: usize,
    explicit: bool,
) -> VnRef {
    let mut vn = Varnode::new_with_space(size, AddressSpace::Register, reg_offset);
    vn.v_type = Some(container.clone());
    if explicit {
        vn.set_flags(varnode_flags::EXPLICIT);
    }
    let mut high = HighVariable::new(container.clone());
    high.name = symbol_name.to_string();
    let mut symbol = Symbol::new(0, symbol_name, "fixture_pair");
    symbol.set_dtype(container);
    symbol.display_name = symbol_name.to_string();
    high.symbol = Some(Arc::new(RwLock::new(symbol)));
    high.symbol_offset = -1;
    vn.high = Some(Arc::new(RwLock::new(high)));
    Arc::new(RwLock::new(vn))
}

/// SUBPIECE op: in(0) = struct vn, in(1) = constant lsb, out = `out_size`
/// bytes (optionally typed via `out_type`, which also feeds the output's
/// HighVariable — the allowCast arm reads the OUTPUT high type, printc.cc:859
/// + 2019), SPECIAL_PRINT set (Funcdata::opMarkSpecialPrint, funcdata.hh:483).
/// `time` is the SeqNum creation identity (Ghidra's Funcdata::newOp assigns a
/// unique one per op; the union-cache arms rely on distinct identities so
/// their ResolveEdge keys — (typeId, opTime, slot), unionresolve.cc:64 — do
/// not collide).
fn subpiece_op(
    vn: &VnRef,
    lsb: u64,
    out_size: usize,
    out_type: Option<Arc<Datatype>>,
    pc: u64,
    time: u32,
) -> Arc<RwLock<PcodeOp>> {
    let constant = Arc::new(RwLock::new(Varnode::new_with_space(
        1,
        AddressSpace::Const,
        lsb,
    )));
    let mut out = Varnode::new_with_space(out_size, AddressSpace::Unique, pc);
    if let Some(ref ot) = out_type {
        out.v_type = Some(ot.clone());
    }
    let mut out_high = HighVariable::new(
        out_type.unwrap_or_else(|| {
            Arc::new(Datatype::Base(TypeBase::new(
                "undefined".to_string(),
                out_size,
                TypeMetatype::Unknown,
            )))
        }),
    );
    out_high.name = String::new();
    out.high = Some(Arc::new(RwLock::new(out_high)));
    let out = Arc::new(RwLock::new(out));
    let mut op = PcodeOp::new(
        rudra::address::SeqNum::new(Address::new(pc), time),
        OpCode::CPUI_SUBPIECE,
    );
    op.inrefs.push(vn.clone());
    op.inrefs.push(constant);
    op.output = Some(out);
    op.addlflags |= op_addl_flags::SPECIAL_PRINT;
    Arc::new(RwLock::new(op))
}

fn render(op_arc: &Arc<RwLock<PcodeOp>>) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.op_subpiece_rpn(op_arc);
    let emitter = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture emitter type");
    emitter.get_output()
}

/// Render with the (parent,op,slot)-keyed union-resolution cache snapshot
/// installed from a Funcdata — the fixture twin of the C++ side's REAL
/// `fd->setUnionField` writes feeding TypeUnion::findTruncation's
/// `fd->getUnionField` consults (type.cc:2189-2190). The snapshot is the
/// same doc_function channel the pipeline printer uses.
fn render_with_resolutions(
    op_arc: &Arc<RwLock<PcodeOp>>,
    fd: &rudra::funcdata::Funcdata,
) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.snapshot_union_resolutions(fd);
    printer.op_subpiece_rpn(op_arc);
    let emitter = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture emitter type");
    emitter.get_output()
}

/// The union-resolution cache read-side arms (TYPEUNION-CACHE-READSIDE-0001):
/// TypeUnion::findTruncation (type.cc:2185-2199) does NO scoring — it is a
/// read-only consult of the (parent,op,slot) cache at the ARTIFICIAL SUBPIECE
/// slot 1 (printc.cc:862). Cache entries are installed through the real write
/// side (Funcdata::setUnionField, funcdata.cc:937); the mirror C++ fixture
/// builds the ResolvedUnion with the (parent,fldNum,typegrp) ctor
/// (unionresolve.cc:40: resolve = parent->getDepend(1) = uint4, baseType =
/// altUnion, fieldNum = 1, lock = false), which the struct-literal below
/// reproduces.
fn run_union_cache_arms() {
    use rudra::op::PcodeOpRef;
    use rudra::unionresolve::ResolvedUnion;

    // One Funcdata accumulates the cache entries exactly as the C++ fixture's
    // single GetStr Funcdata does; the distinct SeqNum times keep the
    // ResolveEdge keys apart.
    let mut fd = rudra::funcdata::Funcdata::new("GetStr", Address::new(0x36d0), 0);

    let field_b_of = |union_dt: &Arc<Datatype>| -> Arc<Datatype> {
        match union_dt.as_ref() {
            Datatype::Union(u) => u.fields[1].type_ptr.clone(),
            _ => unreachable!("fixture_union is a union"),
        }
    };

    // armB.unionhit: NON-explicit vn, symbol U over fixture_alt, lsb=0,
    // outsize 4, cached (union,op,slot=1) -> field b: findTruncation(0,4,op,1)
    // hits with offset 0 -> object_member field atom -> U.b.
    {
        let union = fixture_union();
        let vn = struct_vn(union.clone(), "U", 0x70, 4, false);
        let op = subpiece_op(&vn, 0, 4, None, 0xb010, 1);
        fd.set_union_field(
            union.as_ref(),
            &PcodeOpRef(op.clone()),
            1,
            ResolvedUnion {
                resolve: field_b_of(&union),
                base_type: union.clone(),
                field_num: 1,
                lock: false,
            },
        );
        println!("armB.unionhit={}", render_with_resolutions(&op, &fd));
    }
    // armA.unionhit: explicit vn, symbol V, lsb=0, outsize 4, same cached
    // entry -> pushPartialSymbol union arm (printc.cc:2001-2014): no
    // loop-top break (union needsResolution), findTruncation hit descends
    // .b, then at ct=uint4 sz==size -> break -> V.b.
    {
        let union = fixture_union();
        let vn = struct_vn(union.clone(), "V", 0x78, 4, true);
        let op = subpiece_op(&vn, 0, 4, None, 0xc010, 2);
        fd.set_union_field(
            union.as_ref(),
            &PcodeOpRef(op.clone()),
            1,
            ResolvedUnion {
                resolve: field_b_of(&union),
                base_type: union.clone(),
                field_num: 1,
                lock: false,
            },
        );
        println!("armA.unionhit={}", render_with_resolutions(&op, &fd));
    }
    // armA.unionmiss: NO cache entry -> findTruncation null (type.cc:2197-
    // 2198: no scoring, no write), then printc.cc:2015-2016 size==sz -> break
    // -> whole union symbol W.
    {
        let union = fixture_union();
        let vn = struct_vn(union.clone(), "W", 0x80, 4, true);
        let op = subpiece_op(&vn, 0, 4, None, 0xd010, 3);
        println!("armA.unionmiss={}", render_with_resolutions(&op, &fd));
    }
    // armA.unionspan: cached field b (uint4) but lsb=2, outsize 4: newoff=2
    // and 2+4 > 4 -> "Truncation spans more than one field" (type.cc:2194-
    // 2195) -> null -> size==sz break -> whole union symbol X.
    {
        let union = fixture_union();
        let vn = struct_vn(union.clone(), "X", 0x88, 4, true);
        let op = subpiece_op(&vn, 2, 4, None, 0xe010, 4);
        fd.set_union_field(
            union.as_ref(),
            &PcodeOpRef(op.clone()),
            1,
            ResolvedUnion {
                resolve: field_b_of(&union),
                base_type: union.clone(),
                field_num: 1,
                lock: false,
            },
        );
        println!("armA.unionspan={}", render_with_resolutions(&op, &fd));
    }
    // armA.unionsynth: NO cache entry, lsb=0, outsize 2: findTruncation null,
    // size(4) != sz(2) so no break -> synthetic unnamedField(0,2)
    // (printc.cc:2030-2041) -> Z._0_2_.
    {
        let union = fixture_union();
        let vn = struct_vn(union.clone(), "Z", 0x90, 4, true);
        let op = subpiece_op(&vn, 0, 2, None, 0xf010, 5);
        println!("armA.unionsynth={}", render_with_resolutions(&op, &fd));
    }
}

fn run_piece_sweep() {
    let pair = fixture_pair();
    let alt = fixture_union();
    let arr2 = Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new("int[2]".to_string(), 8, TypeMetatype::Array),
        array_of: int4(),
        num_elements: 2,
    }));
    let partial_struct = Arc::new(Datatype::PartialStruct(TypePartialStruct::new(
        pair.clone(),
        4,
        4,
        None,
    )));
    let partial_union = Arc::new(Datatype::PartialUnion(TypePartialUnion::new(
        alt.clone(),
        0,
        2,
        None,
    )));
    let en = fixture_enum();
    let partial_enum = Arc::new(Datatype::PartialEnum(TypePartialEnum::new(
        en.clone(),
        0,
        2,
        None,
    )));
    let ptr = Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
        ptr_to: int4(),
        wordsize: 1,
    }));

    println!("piece.struct={}", pair.is_piece_structured() as u8);
    println!("piece.union={}", alt.is_piece_structured() as u8);
    println!("piece.array={}", arr2.is_piece_structured() as u8);
    println!("piece.partialstruct={}", partial_struct.is_piece_structured() as u8);
    println!("piece.partialunion={}", partial_union.is_piece_structured() as u8);
    // Rugra keeps TypeMetatype::Enum on enum types where Ghidra's TypeEnum
    // ctor normalizes to TYPE_UINT/TYPE_INT (type.hh:489-494) — both sides
    // observe false for is_piece_structured.
    println!("piece.enum={}", en.is_piece_structured() as u8);
    println!("piece.partialenum={}", partial_enum.is_piece_structured() as u8);
    println!("piece.int={}", int4().is_piece_structured() as u8);
    println!("piece.uint={}", uint4().is_piece_structured() as u8);
    println!("piece.pointer={}", ptr.is_piece_structured() as u8);
}

fn run_cast_sweep() {
    let printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    let cs = &printer.cast_strategy;
    let int4 = int4();
    let int8 = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(),
        8,
        TypeMetatype::Int,
    )));
    let pair = fixture_pair();
    let alt = fixture_union();
    let partial_struct = Arc::new(Datatype::PartialStruct(TypePartialStruct::new(
        pair.clone(),
        4,
        4,
        None,
    )));
    let partial_union = Arc::new(Datatype::PartialUnion(TypePartialUnion::new(
        alt.clone(),
        0,
        2,
        None,
    )));
    let en = fixture_enum();
    let partial_enum = Arc::new(Datatype::PartialEnum(TypePartialEnum::new(
        en.clone(),
        0,
        2,
        None,
    )));

    println!("cast.int_int_0={}", cs.is_subpiece_cast(&int4, &int8, 0) as u8);
    println!(
        "cast.int_partialstruct_0={}",
        cs.is_subpiece_cast(&int4, &partial_struct, 0) as u8
    );
    println!(
        "cast.int_partialunion_0={}",
        cs.is_subpiece_cast(&int4, &partial_union, 0) as u8
    );
    println!(
        "cast.int_partialstruct_2={}",
        cs.is_subpiece_cast(&int4, &partial_struct, 2) as u8
    );
    println!("cast.int_struct_0={}", cs.is_subpiece_cast(&int4, &pair, 0) as u8);
    println!("cast.int_enum_0={}", cs.is_subpiece_cast(&int4, &en, 0) as u8);
    println!("cast.enum_int8_0={}", cs.is_subpiece_cast(&en, &int8, 0) as u8);
    // TypePartialEnum delegates to the TypeEnum ctor (type.cc:2255-2262)
    // which normalizes the stored metatype to TYPE_UINT, so a Ghidra
    // partial-enum passes both whitelists like a plain enum.
    println!(
        "cast.int_partialenum_0={}",
        cs.is_subpiece_cast(&int4, &partial_enum, 0) as u8
    );
    println!(
        "cast.partialenum_out_0={}",
        cs.is_subpiece_cast(&partial_enum, &int8, 0) as u8
    );
    println!(
        "cast.partialstruct_out_0={}",
        cs.is_subpiece_cast(&partial_struct, &int8, 0) as u8
    );
}

fn run_subpiece_arms() {
    // armA.field: explicit vn, symbol S over fixture_pair, lsb=4 -> S.hi.
    {
        let vn = struct_vn(fixture_pair(), "S", 0x40, 8, true);
        let op = subpiece_op(&vn, 4, 4, None, 0x5010, 0);
        println!("armA.field={}", render(&op));
    }
    // armA.array: explicit vn, symbol A over fixture_arr, lsb=0 -> A.arr[0].
    {
        let vn = struct_vn(fixture_arr(), "A", 0x48, 8, true);
        let op = subpiece_op(&vn, 0, 4, None, 0x6010, 0);
        println!("armA.array={}", render(&op));
    }
    // armA.synthetic: explicit vn, symbol Y over fixture_pair, lsb=2,
    // outsize 4: findTruncation(2,4) spans past field lo (2+4>4) ->
    // synthetic unnamedField(2,4) -> Y._2_4_.
    {
        let vn = struct_vn(fixture_pair(), "Y", 0x50, 8, true);
        let op = subpiece_op(&vn, 2, 4, None, 0x7010, 0);
        println!("armA.synthetic={}", render(&op));
    }
    // armB.field: NON-explicit vn (high still named/symbolled "B"), lsb=0,
    // outsize 4 -> findTruncation(0,4) -> field lo, offset==0 -> B.lo.
    {
        let vn = struct_vn(fixture_pair(), "B", 0x58, 8, false);
        let op = subpiece_op(&vn, 0, 4, None, 0x8010, 0);
        println!("armB.field={}", render(&op));
    }
    // armA.nested: explicit vn, symbol N over fixture_outer (16 bytes),
    // lsb=0, outsize 8 -> descent .in, then the inner struct's
    // needsResolution findResolve arm: no cached resolution -> field[0].type
    // (long) != inner -> NO break (type.cc:1944-1951 / printc.cc:1969-1971)
    // -> findTruncation descends .x -> N.in.x.
    {
        let vn = struct_vn(fixture_outer(), "N", 0x60, 16, true);
        let op = subpiece_op(&vn, 0, 8, None, 0x9010, 0);
        println!("armA.nested={}", render(&op));
    }
    // armA.allowcast: explicit vn, symbol C over fixture_pair, lsb=0,
    // outsize 2 typed uint2 ("uint2", Ghidra getBase(2,TYPE_UINT) display).
    // Walk: .lo descent, then at ct=int4 the allowCast arm reads outtype
    // from the OUTPUT high (printc.cc:859/2019) ->
    // isSubpieceCastEndian(uint2,int4,0,LE) true -> (uint2)C.lo.
    {
        let vn = struct_vn(fixture_pair(), "C", 0x68, 8, true);
        let uint2 = Arc::new(Datatype::Base(TypeBase::new(
            "uint2".to_string(),
            2,
            TypeMetatype::Uint,
        )));
        let op = subpiece_op(&vn, 0, 2, Some(uint2), 0xa010, 0);
        println!("armA.allowcast={}", render(&op));
    }
}

fn main() {
    run_piece_sweep();
    run_cast_sweep();
    run_subpiece_arms();
    run_union_cache_arms();
}
