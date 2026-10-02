// Locked Ghidra 12.0.4 oracle for PRINTC-SINGLETON-IRFIX-0001 (Rust
// side). Mirrors tests/oracle/printc_checkaddr_impliedfield_1204.cc
// record-for-record — the full-IR bilateral observation of
//   PrintC::checkAddressOfCast (printc.cc:376-418)
//   PrintC::pushImpliedField  (printc.cc:2085-2116)
// driven through the REAL emitExpression port (printc.cc:2465-2494 —
// Rugra's pub emit_expression_rpn twin: assignment push + dispatch +
// rpn_recurse drain):
//   cast.ptrsub_positive       — PTRSUB-def arm positive -> "ca = &sp->x"
//   cast.dtnonptr_reject       — dt1 int (cc:382-383) -> "(int4 (*)[4])ib"
//   cast.nonarray_base0_reject — base0 non-array (cc:386-387) -> "(int *)ic"
//   cast.elem_mismatch_reject  — base1 uint != elem int (cc:394-395)
//                                -> "(int4 (*)[4])id->x"
//   cast.size_mismatch_reject  — int[4] 16 != int[2] 8 (cc:415-417)
//                                -> "(int4 (*)[2])ie->x"
//   cast.symbolentry_positive  — whole-map int[2] entry, symbolOffset -1
//                                (variable.cc:1727-1729), read type int*
//                                (updateType(ct,0,1) twin) -> "&iw"
//   implied.union_proceed      — (U,op,slot 1)->field b (cc:2100-2115)
//                                -> "return 5.b"
//   implied.struct_proceed     — fieldNum 0 -> beginField "x" (cc:2096)
//                                -> "return 5.x"
//   implied.union_nores        — res null -> !proceed (cc:2108-2111)
//                                -> "return 5"
//   implied.plain_parent       — needsResolution gate closed (cc:2091)
//                                -> "return 5"
//
// Object graph mirrors the C++ fixture: type-locked register symbols
// (high.symbol + symbol_offset -1 + vn.symbol_entry — the auto-attach
// twin of Varnode::setSymbolProperties varnode.cc:409-421), implied
// PTRSUB chains (setImplied varnode.hh:309), has_implied_field marks
// (setImpliedField varnode.hh:335), and union resolutions installed
// through the real Funcdata::setUnionField write port (funcdata.cc:937)
// snapshotted by the same doc_function channel the pipeline printer
// uses (snapshot_union_resolutions).

use std::sync::{Arc, RwLock};

use rudra::address::{Address, RangeList, SeqNum};
use rudra::database::{Symbol, SymbolEntry};
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{
    Datatype, TypeArray, TypeBase, TypeField, TypeMetatype, TypePointer, TypeStruct, TypeUnion,
    type_flags,
};
use rudra::unionresolve::ResolvedUnion;
use rudra::variable::HighVariable;
use rudra::varnode::{Varnode, addl_flags, varnode_flags};

type VnRef = Arc<RwLock<Varnode>>;
type OpRef = Arc<RwLock<PcodeOp>>;

fn int4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new("int4".to_string(), 4, TypeMetatype::Int)))
}

fn uint4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new("uint4".to_string(), 4, TypeMetatype::Uint)))
}

fn int8() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new("int8".to_string(), 8, TypeMetatype::Int)))
}

/// fixture_box { int x[4] @0; long tail @16 } — two fields, no
/// needs_resolution (mirrors the C++ fixture construction).
fn box_struct(int_arr4: &Arc<Datatype>) -> Arc<Datatype> {
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("fixture_box".to_string(), 24, TypeMetatype::Struct),
        fields: vec![
            TypeField {
                name: "x".to_string(),
                offset: 0,
                type_ptr: int_arr4.clone(),
            },
            TypeField {
                name: "tail".to_string(),
                offset: 16,
                type_ptr: int8(),
            },
        ],
    }))
}

/// fixture_alt { int a @0; uint b @0 } — TypeUnion always needs
/// resolution (type.hh:551; the flag gate of printc.cc:2091).
fn alt_union() -> Arc<Datatype> {
    let mut base = TypeBase::new("fixture_alt".to_string(), 4, TypeMetatype::Union);
    base.flags |= type_flags::NEEDS_RESOLUTION;
    Arc::new(Datatype::Union(TypeUnion {
        base,
        fields: vec![
            TypeField {
                name: "a".to_string(),
                offset: 0,
                type_ptr: int4(),
            },
            TypeField {
                name: "b".to_string(),
                offset: 0,
                type_ptr: uint4(),
            },
        ],
    }))
}

/// fixture_inner { long x } — single field fills the whole struct, so
/// the REAL TypeFactory::setFields sets needs_resolution (type.cc:
/// 1569-1871); Rugra's factory does not set it yet
/// (TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001), so the flag is applied
/// manually exactly as the subpiece fixture does.
fn inner_struct() -> Arc<Datatype> {
    let mut base = TypeBase::new("fixture_inner".to_string(), 8, TypeMetatype::Struct);
    base.flags |= type_flags::NEEDS_RESOLUTION;
    Arc::new(Datatype::Struct(TypeStruct {
        base,
        fields: vec![TypeField {
            name: "x".to_string(),
            offset: 0,
            type_ptr: int8(),
        }],
    }))
}

fn mk_ptr(pointee: Arc<Datatype>) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(String::new(), 8, TypeMetatype::Pointer),
        ptr_to: pointee,
        wordsize: 1,
    }))
}

fn mk_array(name: &str, elem: Arc<Datatype>, n: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new(name.to_string(), n * elem.get_size(), TypeMetatype::Array),
        array_of: elem,
        num_elements: n,
    }))
}

/// Type-locked register Varnode with a whole-map Symbol: the Rust twin
/// of the C++ fixture's symbolVn (addSymbol + typelock + newVarnode
/// auto-attach). `symbol_dtype` is the Symbol's type (the symbolEntry
/// arm reads it); `vn_type` is the varnode's read-facing type (what the
/// C++ side leaves on the Varnode after SymbolEntry::updateType — or
/// the updateType(ct,0,1) override in the symbolentry arm).
fn sym_vn(symbol_dtype: Arc<Datatype>, vn_type: Arc<Datatype>, name: &str, reg_off: u64, size: usize) -> VnRef {
    let mut vn = Varnode::new_with_space(size, AddressSpace::Register, reg_off);
    vn.v_type = Some(vn_type.clone());
    let mut symbol = Symbol::new(0, name, "fixture");
    symbol.set_dtype(symbol_dtype);
    symbol.display_name = name.to_string();
    let symbol = Arc::new(RwLock::new(symbol));
    let mut high = HighVariable::new(vn_type.clone());
    high.name = name.to_string();
    high.symbol = Some(symbol.clone());
    high.symbol_offset = -1;
    vn.high = Some(Arc::new(RwLock::new(high)));
    vn.set_symbol_entry(Arc::new(RwLock::new(SymbolEntry::new_static(
        symbol,
        0,
        Address::new(reg_off),
        0,
        size as i32,
        RangeList::new(),
    ))));
    Arc::new(RwLock::new(vn))
}

fn mk_op(pc: u64, time: u32, opc: OpCode) -> PcodeOp {
    PcodeOp::new(SeqNum::new(Address::new(pc), time), opc)
}

/// PTRSUB(root, 0) whose output carries `elem_ptr` on the Varnode and
/// the implied mark (varnode.hh:309) — the in0 chain of the cast arms
/// a/d/e. Mirrors impliedPtrsubOut.
fn implied_ptrsub_out(root: &VnRef, elem_ptr: Arc<Datatype>, pc: u64) -> (VnRef, OpRef) {
    let mut in0 = Varnode::new_with_space(8, AddressSpace::Unique, pc);
    in0.v_type = Some(elem_ptr.clone());
    in0.high = Some(Arc::new(RwLock::new(HighVariable::new(elem_ptr))));
    in0.flags |= varnode_flags::WRITTEN | varnode_flags::IMPLIED;
    let in0: VnRef = Arc::new(RwLock::new(in0));
    let off_const: VnRef = Arc::new(RwLock::new(Varnode::new_constant(0, 8)));
    let mut ptrsub = mk_op(pc, 0, OpCode::CPUI_PTRSUB);
    ptrsub.inrefs = vec![root.clone(), off_const];
    ptrsub.output = Some(in0.clone());
    let ptrsub: OpRef = Arc::new(RwLock::new(ptrsub));
    in0.write().unwrap().def = Some(Arc::downgrade(&ptrsub));
    (in0, ptrsub)
}

/// CAST(in0) -> out. Mirrors castOp.
fn cast_op(in0: &VnRef, out: &VnRef, pc: u64) -> OpRef {
    let mut cast = mk_op(pc, 1, OpCode::CPUI_CAST);
    cast.inrefs = vec![in0.clone()];
    cast.output = Some(out.clone());
    Arc::new(RwLock::new(cast))
}

/// RETURN(indeterminate, value): value = implied + has_implied_field vn
/// typed `parent_type`, defined by COPY(const). Mirrors returnOfImplied.
/// The COPY Arc is returned too — the value vn's def is a Weak handle,
/// so the defining op must outlive the render (the C++ fixture keeps it
/// alive in the Funcdata obank).
fn return_of_implied(parent_type: Arc<Datatype>, const_size: usize, const_val: u64, pc: u64) -> (OpRef, OpRef) {
    let mut value = Varnode::new_with_space(parent_type.get_size(), AddressSpace::Unique, pc);
    value.v_type = Some(parent_type.clone());
    value.high = Some(Arc::new(RwLock::new(HighVariable::new(parent_type))));
    value.flags |= varnode_flags::WRITTEN | varnode_flags::IMPLIED;
    value.addlflags |= addl_flags::HAS_IMPLIED_FIELD;
    let value: VnRef = Arc::new(RwLock::new(value));

    let mut const_vn = Varnode::new_constant(const_val, const_size);
    const_vn.v_type = Some(int4());
    let const_vn: VnRef = Arc::new(RwLock::new(const_vn));
    let mut copy = mk_op(pc, 0, OpCode::CPUI_COPY);
    copy.inrefs = vec![const_vn];
    copy.output = Some(value.clone());
    let copy: OpRef = Arc::new(RwLock::new(copy));
    value.write().unwrap().def = Some(Arc::downgrade(&copy));

    let indeterminate: VnRef = Arc::new(RwLock::new(Varnode::new_constant(0, 1)));
    let mut ret = mk_op(pc, 1, OpCode::CPUI_RETURN);
    ret.inrefs = vec![indeterminate, value.clone()];
    let ret: OpRef = Arc::new(RwLock::new(ret));
    (ret, copy)
}

fn drain(printer: PrintC) -> String {
    printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("fixture emitter type")
        .get_output()
}

/// The emitExpression twin (printc.cc:2465-2494) — Rugra's pub
/// emit_expression_rpn: out-assignment push + TypeOp dispatch + the
/// rpn_recurse drain that routes implied+has_implied_field vns into
/// pushImpliedField (printlanguage.cc:527-529).
fn render(op_arc: &OpRef) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    let op = op_arc.read().unwrap();
    printer.emit_expression_rpn(op_arc, &op);
    drop(op);
    drain(printer)
}

/// Same render with the fd's union-resolution map snapshotted (the
/// C++ fixture's Funcdata::setUnionField write port feeding
/// printc.cc:2094 fd->getUnionField).
fn render_with_resolutions(op_arc: &OpRef, fd: &Funcdata) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.snapshot_union_resolutions(fd);
    let op = op_arc.read().unwrap();
    printer.emit_expression_rpn(op_arc, &op);
    drop(op);
    drain(printer)
}

fn run_cast_matrix() {
    let int_arr4 = mk_array("int4[4]", int4(), 4);
    let int_arr2 = mk_array("int4[2]", int4(), 2);
    let ptr_int_arr4 = mk_ptr(int_arr4.clone());
    let ptr_int_arr2 = mk_ptr(int_arr2.clone());
    let ptr_int = mk_ptr(int4());
    let ptr_uint = mk_ptr(uint4());
    let ptr_box = mk_ptr(box_struct(&int_arr4));

    // (a) positive PTRSUB-def arm.
    {
        let sp = sym_vn(ptr_box.clone(), ptr_box.clone(), "sp", 0x100, 8);
        let (in0, _ptrsub) = implied_ptrsub_out(&sp, ptr_int.clone(), 0x5000);
        let out = sym_vn(ptr_int_arr4.clone(), ptr_int_arr4.clone(), "ca", 0x120, 8);
        let op = cast_op(&in0, &out, 0x5010);
        println!("cast.ptrsub_positive={}", render(&op));
    }
    // (b) dt1 non-pointer.
    {
        let ib = sym_vn(int4(), int4(), "ib", 0x128, 4);
        let out = sym_vn(ptr_int_arr4.clone(), ptr_int_arr4.clone(), "cb", 0x130, 8);
        let op = cast_op(&ib, &out, 0x5210);
        println!("cast.dtnonptr_reject={}", render(&op));
    }
    // (c) base0 non-array.
    {
        let ic = sym_vn(ptr_int.clone(), ptr_int.clone(), "ic", 0x138, 8);
        let out = sym_vn(ptr_int.clone(), ptr_int.clone(), "cc", 0x140, 8);
        let op = cast_op(&ic, &out, 0x5410);
        println!("cast.nonarray_base0_reject={}", render(&op));
    }
    // (d) element mismatch.
    {
        let id = sym_vn(ptr_box.clone(), ptr_box.clone(), "id", 0x148, 8);
        let (in0, _ptrsub) = implied_ptrsub_out(&id, ptr_uint.clone(), 0x5600);
        let out = sym_vn(ptr_int_arr4.clone(), ptr_int_arr4.clone(), "cd", 0x150, 8);
        let op = cast_op(&in0, &out, 0x5610);
        println!("cast.elem_mismatch_reject={}", render(&op));
    }
    // (e) symbol-array size mismatch.
    {
        let ie = sym_vn(ptr_box.clone(), ptr_box.clone(), "ie", 0x158, 8);
        let (in0, _ptrsub) = implied_ptrsub_out(&ie, ptr_int.clone(), 0x5800);
        let out = sym_vn(ptr_int_arr2.clone(), ptr_int_arr2.clone(), "ce", 0x160, 8);
        let op = cast_op(&in0, &out, 0x5810);
        println!("cast.size_mismatch_reject={}", render(&op));
    }
    // (f) symbolEntry arm: whole-map int[2] entry (symbol_offset -1) +
    //     the read-facing type overridden to int*.
    {
        let iw = sym_vn(int_arr2.clone(), ptr_int.clone(), "iw", 0x168, 8);
        let out = sym_vn(ptr_int_arr2.clone(), ptr_int_arr2.clone(), "cf", 0x170, 8);
        let op = cast_op(&iw, &out, 0x5a10);
        println!("cast.symbolentry_positive={}", render(&op));
    }
}

fn run_implied_arms() {
    // (u1) union proceed arm.
    {
        let union_u = alt_union();
        let uint_t = uint4();
        let (ret, _copy) = return_of_implied(union_u.clone(), 4, 5, 0x7000);
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        fd.set_union_field(
            union_u.as_ref(),
            &PcodeOpRef(ret.clone()),
            1,
            ResolvedUnion {
                resolve: uint_t,
                base_type: union_u.clone(),
                field_num: 1,
                lock: false,
            },
        );
        println!("implied.union_proceed={}", render_with_resolutions(&ret, &fd));
    }
    // (u4) struct proceed arm: fieldNum 0 -> beginField "x".
    {
        let inner = inner_struct();
        let long_t = int8();
        let (ret, _copy) = return_of_implied(inner.clone(), 8, 5, 0x7200);
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        fd.set_union_field(
            inner.as_ref(),
            &PcodeOpRef(ret.clone()),
            1,
            ResolvedUnion {
                resolve: long_t,
                base_type: inner.clone(),
                field_num: 0,
                lock: false,
            },
        );
        println!("implied.struct_proceed={}", render_with_resolutions(&ret, &fd));
    }
    // (u2) union parent, NO map entry.
    {
        let union_u = alt_union();
        let (ret, _copy) = return_of_implied(union_u, 4, 5, 0x7400);
        let fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        println!("implied.union_nores={}", render_with_resolutions(&ret, &fd));
    }
    // (u3) int parent: gate closed.
    {
        let (ret, _copy) = return_of_implied(int4(), 4, 5, 0x7600);
        let fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        println!("implied.plain_parent={}", render_with_resolutions(&ret, &fd));
    }
}

fn main() {
    run_cast_matrix();
    run_implied_arms();
}
