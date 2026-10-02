//! TYPE-SPACEBASE-SUBTYPE-DISPATCH-0001 Rugra comparand for locked
//! Ghidra 12.0.4 (e40ed130). Mirrors the observation records of
//! `type_spacebase_subtype_1204.cc`: `Datatype::get_sub_type` virtual
//! dispatch on a global `TypeSpacebase` (symbol hit / mid-symbol / miss /
//! end boundary) and the `TypePointer::isPtrsubMatching` SPACEBASE gate
//! (`pointer_is_ptrsub_matching`, type.cc:1123-1137).

use rudra::address::RangeList;
use rudra::database::{symbol_flags, Scope, Symbol, SymbolEntry};
use rudra::type_system::datatype::{
    pointer_is_ptrsub_matching, Datatype, TypeBase, TypeField, TypeMetatype, TypePointer,
    TypeSpacebase, TypeStruct,
};
use rudra::{Address, AddressSpace};
use std::sync::{Arc, RwLock};

fn describe_sub_type(sub_type: Option<&Arc<Datatype>>, newoff: i64) -> String {
    match sub_type {
        None => format!("none:0:{}", newoff),
        Some(t) => {
            let meta = match t.get_metatype() {
                TypeMetatype::Struct => "struct",
                TypeMetatype::Union => "union",
                TypeMetatype::Array => "array",
                TypeMetatype::Unknown => "unknown",
                TypeMetatype::Pointer => "ptr",
                _ => "other",
            };
            format!("{}:{}:{}", meta, t.get_size(), newoff)
        }
    }
}

fn main() {
    // 16-byte struct Conf { lo@0 uint8, hi@8 uint8 } — the global symbol's type.
    let uint8 = Arc::new(Datatype::Base(TypeBase::new(
        "uint8".to_string(),
        8,
        TypeMetatype::Uint,
    )));
    let conf = Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("Conf".to_string(), 16, TypeMetatype::Struct),
        fields: vec![
            TypeField {
                name: "lo".to_string(),
                offset: 0,
                type_ptr: uint8.clone(),
            },
            TypeField {
                name: "hi".to_string(),
                offset: 8,
                type_ptr: uint8.clone(),
            },
        ],
    }));

    // Global scope with one address-tied `config` SymbolEntry at ram 0x1000
    // (the mirror of the cc fixture's ProbeScope::addProbeSymbol).
    let mut sym = Symbol::new(0x202, "config", "Conf");
    sym.dtype = Some(conf.clone());
    sym.flags |= symbol_flags::ADDRTIED;
    let sym = Arc::new(RwLock::new(sym));
    let mut scope = Scope::new(0x202, "", 0);
    scope.entries.push(SymbolEntry::new_static(
        sym,
        0,
        Address::new(0x1000),
        0,
        16,
        RangeList::new(),
    ));

    // Global ram spacebase (localframe invalid), scope attached as the map.
    let spacebase = Datatype::Spacebase(TypeSpacebase {
        base: TypeBase::new(String::new(), 0, TypeMetatype::Spacebase),
        address: Address::new(0),
        fd: None,
        spaceid: Some(AddressSpace::Ram),
        localframe: Address::new(0),
        scope: Some(Arc::new(scope)),
    });

    // --- Datatype::getSubType virtual dispatch (type.cc:174/2947) ---
    let (sub, newoff) = spacebase.get_sub_type(0x1000);
    println!("subtype.hit_start={}", describe_sub_type(sub.as_ref(), newoff));

    let (sub, newoff) = spacebase.get_sub_type(0x1008);
    println!("subtype.hit_mid={}", describe_sub_type(sub.as_ref(), newoff));

    let (sub, newoff) = spacebase.get_sub_type(0x2000);
    println!("subtype.miss_gap={}", describe_sub_type(sub.as_ref(), newoff));

    let (sub, newoff) = spacebase.get_sub_type(0x1010);
    println!(
        "subtype.hit_endboundary={}",
        describe_sub_type(sub.as_ref(), newoff)
    );

    // --- TypePointer::isPtrsubMatching SPACEBASE arm (type.cc:1123) ---
    let ptr = TypePointer::new(8, Arc::new(spacebase), 1);
    let verdict = |off: i64, extra: i64| -> String {
        u8::from(pointer_is_ptrsub_matching(&ptr.ptr_to, 1, off, extra, 0)).to_string()
    };
    println!("gate.hit_extra0={}", verdict(0x1000, 0));
    println!("gate.hit_extra8={}", verdict(0x1000, 8));
    println!("gate.hit_extra16={}", verdict(0x1000, 16));
    println!("gate.midsym={}", verdict(0x1008, 0));
    println!("gate.miss_extra0={}", verdict(0x2000, 0));
    println!("gate.miss_extra8={}", verdict(0x2000, 8));
}
