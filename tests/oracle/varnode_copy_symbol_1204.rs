// VARNODE-COPYSYMBOL-FIELDS-0001 fixture — Rust side.
//
// Mirrors tests/oracle/varnode_copy_symbol_1204.cc case for case against the
// locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// The function under test is Funcdata::opSetInput's constant single-reader
// dedup branch (funcdata_op.cc:104-125) calling Varnode::copySymbol
// (varnode.cc:493-505): the fresh constant copy must inherit the Datatype
// pointer, the mapentry, and exactly the typelock|namelock flag bits.
use std::sync::{Arc, RwLock};

use rudra::address::{Address, RangeList};
use rudra::database::{symbol_flags, Symbol, SymbolEntry};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::TypeMetatype;
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varnode::{varnode_flags, Varnode};

type VnRef = Arc<RwLock<Varnode>>;

fn meta_token(meta: TypeMetatype) -> &'static str {
    match meta {
        TypeMetatype::Unknown => "unknown",
        TypeMetatype::Int => "int",
        _ => "other",
    }
}

fn type_same(a: &Option<Arc<rudra::type_system::datatype::Datatype>>,
             b: &Option<Arc<rudra::type_system::datatype::Datatype>>) -> usize {
    match (a, b) {
        (Some(x), Some(y)) => usize::from(Arc::ptr_eq(x, y)),
        (None, None) => 1,
        _ => 0,
    }
}

// Print the full post-dedup state of one deduplicated consumer pair, in the
// same observation format as the C++ fixture's printCase.
#[allow(clippy::too_many_arguments)]
fn print_case(label: &str, op1: &PcodeOpRef, op2: &PcodeOpRef, src: &VnRef) {
    let (op1_is_src, op2_is_src) = {
        let o1 = op1.0.read().unwrap();
        let o2 = op2.0.read().unwrap();
        (
            usize::from(Arc::ptr_eq(&o1.inrefs[0], src)),
            usize::from(Arc::ptr_eq(&o2.inrefs[0], src)),
        )
    };
    let cvn = op2.0.read().unwrap().inrefs[0].clone();
    let (cvn_flags, cvn_tl, cvn_nl, cvn_type, cvn_mapped, cvn_mapentry, cvn_off, cvn_sz, cvn_descend) = {
        let r = cvn.read().unwrap();
        (
            r.flags,
            usize::from(r.is_type_lock()),
            usize::from(r.is_name_lock()),
            r.v_type.clone(),
            usize::from(r.is_mapped()),
            usize::from(r.mapentry.is_some()),
            r.loc.as_u64(),
            r.size,
            r.count_descends(),
        )
    };
    let (src_flags, src_type, src_descend, src_tl, src_nl) = {
        let r = src.read().unwrap();
        (
            r.flags,
            r.v_type.clone(),
            r.count_descends(),
            usize::from(r.is_type_lock()),
            usize::from(r.is_name_lock()),
        )
    };
    println!(
        "{label}:op1_is_src={op1_is_src},op2_is_src={op2_is_src},cvn_flags={cvn_flags},cvn_tl={cvn_tl},cvn_nl={cvn_nl},type_same={},type_size={},type_meta={},cvn_mapped={cvn_mapped},cvn_mapentry={cvn_mapentry},off={:x},sz={cvn_sz},src_flags={src_flags},src_descend={src_descend},cvn_descend={cvn_descend},src_tl={src_tl},src_nl={src_nl}",
        type_same(&cvn_type, &src_type),
        cvn_type.as_ref().map(|t| t.get_size() as i64).unwrap_or(-1),
        cvn_type
            .as_ref()
            .map(|t| meta_token(t.get_metatype()))
            .unwrap_or("null"),
        cvn_off,
    );
}

fn main() {
    // Same Standalone core-type flavor as the locked oracle fixture so the
    // bank-allocated unknown base types and the int type resolve to stable
    // Arc identities (see varnode_add_descend_1204.rs).
    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    let int4_type = type_factory
        .read()
        .unwrap()
        .get_base(4, TypeMetatype::Int)
        .expect("int4 base type");

    let mut fd = Funcdata::new("fx", Address::new(0x1000), 0x20);
    fd.vbank.set_type_factory(type_factory.clone());
    let mut pc = 0x2000u64;

    // Two fresh single-input COPY ops per case, attached to the same source
    // constant in slot 0: the first opSetInput keeps the source (no
    // descendant yet), the second enters the dedup branch
    // (funcdata_op.cc:108-115).
    let mut make_op = |fd: &mut Funcdata| {
        let op = fd.new_op(1, Address::new(pc));
        pc += 0x10;
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        op
    };

    // locks_type: typelock via update_type_lock(int4,true,false) + namelock
    // flag (varnode.cc:474-489).
    {
        let src = fd.new_constant(4, 0x1234);
        src.write().unwrap().update_type_lock(int4_type.clone(), true, false);
        src.write().unwrap().set_flags(varnode_flags::NAMELOCK);
        let op1 = make_op(&mut fd);
        let op2 = make_op(&mut fd);
        fd.op_set_input(&op1, src.clone(), 0);
        fd.op_set_input(&op2, src.clone(), 0);
        print_case("locks_type", &op1, &op2, &src);
    }

    // no_locks: the constant exactly as new_constant produced it — the
    // bank-allocated unknown base type and no lock bits.
    {
        let src = fd.new_constant(4, 0x5a5a);
        let op1 = make_op(&mut fd);
        let op2 = make_op(&mut fd);
        fd.op_set_input(&op1, src.clone(), 0);
        fd.op_set_input(&op2, src.clone(), 0);
        print_case("no_locks", &op1, &op2, &src);
    }

    // mapentry_symbol: a name-locked Symbol mapped at the constant's own
    // address in the constant space (the shape production equates produce
    // for equate-locked constants), attached with the production
    // Varnode::set_symbol_entry plus a typelock update_type_lock.
    {
        let src = fd.new_constant(4, 0x1234);
        let mut sym = Symbol::new(0x101, "eq0", "");
        sym.dtype = Some(int4_type.clone());
        sym.flags |= symbol_flags::NAMELOCK;
        let sym_arc = Arc::new(RwLock::new(sym));
        let entry_arc = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym_arc,
            0,
            Address::new(0x1234),
            0,
            4,
            RangeList::new(),
        )));
        src.write().unwrap().set_symbol_entry(entry_arc);
        src.write().unwrap().update_type_lock(int4_type.clone(), true, false);
        let op1 = make_op(&mut fd);
        let op2 = make_op(&mut fd);
        fd.op_set_input(&op1, src.clone(), 0);
        fd.op_set_input(&op2, src.clone(), 0);
        print_case("mapentry_symbol", &op1, &op2, &src);
        let cvn = op2.0.read().unwrap().inrefs[0].clone();
        let (name, entry_offset, entry_same) = {
            let r = cvn.read().unwrap();
            let entry = r.mapentry.clone().expect("copied mapentry");
            let e = entry.read().unwrap();
            let src_entry = src.read().unwrap().mapentry.clone().expect("src mapentry");
            (
                e.get_symbol().read().unwrap().get_name().to_string(),
                e.get_offset(),
                usize::from(Arc::ptr_eq(&entry, &src_entry)),
            )
        };
        println!("mapentry_copy:sym_name={name},entry_offset={entry_offset},entry_same={entry_same}");
    }

    // identity_return: the second op_set_input with the SAME varnode and
    // slot returns at cc:107 before any dedup or descend mutation.
    {
        let src = fd.new_constant(4, 0x0d0d);
        let op1 = make_op(&mut fd);
        fd.op_set_input(&op1, src.clone(), 0);
        fd.op_set_input(&op1, src.clone(), 0); // identity early-return
        let (op1_is_src, src_descend, src_flags) = {
            let o1 = op1.0.read().unwrap();
            let r = src.read().unwrap();
            (
                usize::from(Arc::ptr_eq(&o1.inrefs[0], &src)),
                r.count_descends(),
                r.flags,
            )
        };
        println!("identity_return:op1_is_src={op1_is_src},src_descend={src_descend},src_flags={src_flags}");
    }

    // spacebase_exempt: cc:110 `!vn->isSpacebase()` skips the dedup; both
    // ops share the original varnode, which accumulates two descendants.
    {
        let src = fd.new_constant(4, 0x7777);
        src.write().unwrap().set_flags(varnode_flags::SPACEBASE);
        let op1 = make_op(&mut fd);
        let op2 = make_op(&mut fd);
        fd.op_set_input(&op1, src.clone(), 0);
        fd.op_set_input(&op2, src.clone(), 0);
        let (op1_is_src, op2_is_src, src_descend, src_flags) = {
            let o1 = op1.0.read().unwrap();
            let o2 = op2.0.read().unwrap();
            let r = src.read().unwrap();
            (
                usize::from(Arc::ptr_eq(&o1.inrefs[0], &src)),
                usize::from(Arc::ptr_eq(&o2.inrefs[0], &src)),
                r.count_descends(),
                r.flags,
            )
        };
        println!("spacebase_exempt:op1_is_src={op1_is_src},op2_is_src={op2_is_src},src_descend={src_descend},src_flags={src_flags}");
    }
}
