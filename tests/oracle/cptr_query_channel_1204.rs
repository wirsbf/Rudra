// B3-COREACTION-CONSTANTPTR-0001 (a1): Rugra comparand for the locked
// Ghidra 12.0.4 Funcdata symbol query channel oracle.
//
// Mirrors tests/oracle/cptr_query_channel_1204.cc record-for-record. Each
// case installs the same symbol/entry/property table through the
// production Database paths (add_symbol_mapped / add_range / remove_range
// / set_property_range / attach_scope) and issues the same queries through
// the Funcdata channel (query_container_parent_scope /
// query_properties_parent_scope / query_name_parent_scope) — the Rugra
// equivalent of the C++ `data.getScopeLocal()->getParent()` call sites
// (coreaction.cc:1151, funcdata_varnode.cc:1207). Record formats are
// byte-identical to the C++ fixture.
//
// Case semantics (see the .cc header for the full rationale):
//   qc_exact / qc_mid_needexact  the needexacthit input
//                                (entry->getAddr() == rampoint).
//   qc_chararray_mid             TYPE_ARRAY + char base → the middle
//                                exception input (coreaction.cc:1153-1159).
//   qc_intarray_mid              non-char array: no exception.
//   ro_symbol_before_range       install-order: no readonly fold.
//   qc_after_range_fold /
//   ro_symbol_after_range        addMap property fold baked in.
//   ro_scope_only / ro_prop_only the two non-entry queryProperties
//                                branches.
//   trav_child_wins /
//   trav_discovery_shadow        mapScope resolvemap + stackContainer
//                                discovery ordering.
//
// The `arch=x86:LE:64:default:gcc` and `ram=ram` setup fields are the
// locked fixture identity (the C++ side hard-verifies them); the Rust
// hand-built Database/Funcdata emits the same literals. The
// `parent_is_global=1` field is the C++-observed fact that the local
// scope's parent IS the global scope — the documented contract behind the
// Rugra channel's global-scope query point.

use std::sync::{Arc, RwLock};

use rudra::address::{Address, Range};
use rudra::arch::Architecture;
use rudra::database::{symbol_flags, Database};
use rudra::funcdata::Funcdata;
use rudra::type_system::datatype::{
    Datatype, TypeArray, TypeBase, TypeMetatype,
};

fn ghidra_metatype(metatype: TypeMetatype) -> i32 {
    match metatype {
        TypeMetatype::PartialUnion => 0,
        TypeMetatype::PartialStruct => 1,
        TypeMetatype::PartialEnum => 2,
        TypeMetatype::Union => 3,
        TypeMetatype::Struct => 4,
        TypeMetatype::Enum => 5,
        TypeMetatype::Array => 7,
        TypeMetatype::Pointer => 9,
        TypeMetatype::Float => 10,
        TypeMetatype::Code => 11,
        TypeMetatype::Bool => 12,
        TypeMetatype::Uint => 13,
        TypeMetatype::Int => 14,
        TypeMetatype::Unknown => 15,
        TypeMetatype::Spacebase => 16,
        TypeMetatype::Void => 17,
    }
}

fn undefined_type(name: &str, size: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        name.to_string(),
        size,
        TypeMetatype::Unknown,
    )))
}

/// `TypeFactory::getBase(16, TYPE_UNKNOWN)` (type.cc:3631): 16 exceeds
/// `max_basetype_size` (10), so Ghidra builds an ARRAY of sixteen cached
/// 1-byte unknowns (type.cc:3652-3657) — metatype TYPE_ARRAY, base not
/// char-printable. The fixture mirrors that product directly.
fn undefined16_type() -> Arc<Datatype> {
    array_type(undefined_type("undefined1", 1), 16, 16)
}

fn char_type() -> Arc<Datatype> {
    let mut base = TypeBase::new("char".to_string(), 1, TypeMetatype::Int);
    base.flags |= rudra::type_system::datatype::type_flags::CHARTYPE;
    Arc::new(Datatype::Base(base))
}

fn int4_type() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "int4".to_string(),
        4,
        TypeMetatype::Int,
    )))
}

fn array_type(array_of: Arc<Datatype>, num_elements: usize, size: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new(String::new(), size, TypeMetatype::Array),
        array_of,
        num_elements,
    }))
}

fn scope_token(hit_scope_id: u64, hit_scope_name: &str, global_scope_id: u64) -> String {
    if hit_scope_id == global_scope_id {
        "global".to_string()
    } else {
        hit_scope_name.to_string()
    }
}

/// One parent-channel container query, observed exactly as
/// ActionConstantPtr::isPointer would read the result.
fn dump_container_query(case: &str, fd: &Funcdata, global_scope_id: u64, offset: u64) {
    let line = match fd.query_container_parent_scope(Address::new(offset), 1, Address::new(0)) {
        None => format!("case={case}|kind=qc|query={offset:#x}:1|up=inv|result=null"),
        Some(hit) => {
            let exact = hit.entry_addr.as_u64() == offset;
            let meta = ghidra_metatype(hit.type_metatype);
            format!(
                "case={case}|kind=qc|query={offset:#x}:1|up=inv|result={}|first={:#x}|last={:#x}|off={}|sz={}|exact={}|meta={}|charbase={}|flags={:#x}|scope={}",
                hit.symbol_name,
                hit.entry_addr.as_u64(),
                hit.entry_addr.as_u64() + hit.entry_size as u64 - 1,
                hit.entry_offset,
                hit.entry_size,
                exact as i32,
                meta,
                hit.base_is_char_print as i32,
                hit.all_flags,
                scope_token(hit.scope_id, &hit.scope_name, global_scope_id),
            )
        }
    };
    println!("{line}");
}

/// One isReadOnly observation (queryProperties under the hood).
fn dump_read_only(case: &str, fd: &Funcdata, offset: u64) {
    let (entry, flags) = fd
        .query_properties_parent_scope(Address::new(offset), 1, Address::new(0))
        .expect("query channel attached");
    let ro = (flags & symbol_flags::READONLY) != 0;
    let entry_name = match &entry {
        None => "null".to_string(),
        Some(hit) => hit.symbol_name.clone(),
    };
    println!(
        "case={case}|kind=ro|query={offset:#x}:1|ro={}|entry={entry_name}|flags={flags:#x}",
        ro as i32
    );
}

/// One queryByName observation against the parent (global) scope.
fn dump_name_query(case: &str, fd: &Funcdata, nm: &str) {
    let hits = fd
        .query_name_parent_scope(nm)
        .expect("query channel attached");
    let first = hits
        .first()
        .map(|h| h.symbol_name.clone())
        .unwrap_or_else(|| "null".to_string());
    println!("case={case}|kind=name|query={nm}|records={}|first={first}", hits.len());
}

fn main() {
    let db_arc = Arc::new(RwLock::new(Database::new(false)));
    let global_scope_id = db_arc.read().unwrap().global_scope_id;
    let mut arch = Architecture::new();
    arch.symboltab = Some(db_arc.clone());
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    fd.set_arch(Arc::new(arch));

    // Scope ownership window for the deterministic scope-only branch.
    {
        let mut db = db_arc.write().unwrap();
        db.add_range(
            global_scope_id,
            Range::new(Address::new(0x7f200000), Address::new(0x7f200fff)).unwrap(),
        );
    }

    // Symbols mapped BEFORE the property range: no readonly fold.
    {
        let mut db = db_arc.write().unwrap();
        db.add_symbol_mapped(global_scope_id, "DAT_exact", Some(undefined16_type()),
                             Address::new(0x7f200000), 16);
        db.add_symbol_mapped(global_scope_id, "s_lit",
                             Some(array_type(char_type(), 16, 16)),
                             Address::new(0x7f200100), 16);
        db.add_symbol_mapped(global_scope_id, "arr_i",
                             Some(array_type(int4_type(), 4, 16)),
                             Address::new(0x7f200200), 16);
    }

    // Property ranges (the loader/cspec readonly registration channel).
    {
        let mut db = db_arc.write().unwrap();
        db.set_property_range(
            symbol_flags::READONLY,
            Range::new(Address::new(0x7f200000), Address::new(0x7f2000ff)).unwrap(),
        );
        db.set_property_range(
            symbol_flags::READONLY,
            Range::new(Address::new(0x7f300000), Address::new(0x7f3000ff)).unwrap(),
        );
    }
    // Symbol mapped AFTER the range: the addMap fold bakes readonly in.
    {
        let mut db = db_arc.write().unwrap();
        db.add_symbol_mapped(global_scope_id, "DAT_after", Some(undefined_type("undefined8", 8)),
                             Address::new(0x7f200050), 8);
    }

    // Namespace sub-scope owning [0x7f200300,0x7f20030f], its symbol, and
    // a parent symbol shadowed by the child's ownership window.
    let ns_child = {
        let mut db = db_arc.write().unwrap();
        let child = db.attach_scope("ns_child", global_scope_id);
        db.add_range(
            child,
            Range::new(Address::new(0x7f200300), Address::new(0x7f20030f)).unwrap(),
        );
        db.add_symbol_mapped(child, "DAT_nested", Some(undefined_type("undefined4", 4)),
                             Address::new(0x7f200300), 4);
        db.add_symbol_mapped(global_scope_id, "DAT_gshadow", Some(undefined_type("undefined8", 8)),
                             Address::new(0x7f200300), 8);
        db.add_symbol_mapped(global_scope_id, "DAT_plain", Some(undefined_type("undefined4", 4)),
                             Address::new(0x7f200500), 4);
        child
    };

    {
        let mut db = db_arc.write().unwrap();
        // Carve the property-only windows out of the global ownership so
        // the property-only queryProperties branch is observable.
        db.remove_range(
            global_scope_id,
            Range::new(Address::new(0x7f300000), Address::new(0x7f3000ff)).unwrap(),
        );
        db.remove_range(
            global_scope_id,
            Range::new(Address::new(0x7f400000), Address::new(0x7f4000ff)).unwrap(),
        );
    }
    let _ = ns_child;

    println!("case=setup|arch=x86:LE:64:default:gcc|ram=ram|scope=global|parent_is_global=1");

    dump_container_query("qc_exact", &fd, global_scope_id, 0x7f200000);
    dump_container_query("qc_mid_needexact", &fd, global_scope_id, 0x7f200008);
    dump_container_query("qc_miss", &fd, global_scope_id, 0x7f210000);
    dump_container_query("qc_chararray_mid", &fd, global_scope_id, 0x7f200108);
    dump_container_query("qc_intarray_mid", &fd, global_scope_id, 0x7f200202);
    dump_container_query("qc_after_range_fold", &fd, global_scope_id, 0x7f200050);
    dump_read_only("ro_symbol_before_range", &fd, 0x7f200008);
    dump_read_only("ro_symbol_after_range", &fd, 0x7f200050);
    dump_read_only("ro_scope_only", &fd, 0x7f2000c0);
    dump_read_only("ro_prop_only", &fd, 0x7f300010);
    dump_read_only("ro_none", &fd, 0x7f400010);
    dump_name_query("name_hit", &fd, "DAT_exact");
    dump_name_query("name_miss", &fd, "DAT_nosuch");
    dump_name_query("name_child_shadowed", &fd, "DAT_nested");
    dump_container_query("trav_child_wins", &fd, global_scope_id, 0x7f200302);
    dump_container_query("trav_discovery_shadow", &fd, global_scope_id, 0x7f200306);
    dump_container_query("trav_plain_global", &fd, global_scope_id, 0x7f200500);
}
