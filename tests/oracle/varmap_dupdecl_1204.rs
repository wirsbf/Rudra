// VARMAP-DUPDECL-0001: default-name shared-counter fixture (Rust twin of
// tests/oracle/varmap_dupdecl_1204.cc).
//
// Pins the single shared `base` counter of the local-variable default-name
// arm (database.cc:2501-2504): the ActionNameVars namerec loop
// (coreaction.cc:2992-2996) and the trailing assignDefaultNames
// (coreaction.cc:2998) draw from ONE monotonic sequence across every
// printNameBase prefix, so distinct symbols can never share a
// `<prefix>Var<num>` name — the duplicate-declaration (181538f family)
// invariant.
use std::sync::{Arc, RwLock};

use rudra::space::AddressSpace;
use rudra::type_system::datatype::TypeMetatype;
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varmap::ScopeLocal;

fn main() {
    println!(
        "schema=1|fixture=VARMAP-DUPDECL-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));

    // Named atomic types so printNameBase derives the i/u/f/c prefixes
    // exactly like the SLEIGH core types (type.hh:273). The Standalone
    // (SLEIGH) factory pre-registers int4/uint4/float4/char, so fetch those
    // by name; "int8" is fetched the same way. The oracle fixture interns the
    // identical spellings through TypeFactory::getBase(s,m,n) (type.cc:3667).
    let types: Vec<_> = {
        let factory = type_factory.read().unwrap();
        let int_type = factory.find_by_name("int4").expect("core int4");
        let int_for_pointer = int_type.clone();
        vec![
            int_type,
            factory.find_by_name("uint4").expect("core uint4"),
            factory.find_by_name("float4").expect("core float4"),
            factory.find_by_name("char").expect("core char"),
            factory.find_by_name("int8").expect("core int8"),
        ]
    };
    let int_pointer = type_factory
        .write()
        .unwrap()
        .get_ptr(types[0].clone());
    let types = [types[0].clone(), types[1].clone(), types[2].clone(), types[3].clone(), types[4].clone(), int_pointer];

    let mut scope = ScopeLocal::new();
    // Six $$undef symbols mapped with a valid usepoint: buildDefaultName's
    // no-varnode path then takes flags == 0 (the local-variable arm), exactly
    // like the oracle fixture's usepoint-mapped ScopeInternal entries.
    let mut indices = Vec::new();
    for (index, datatype) in types.iter().enumerate() {
        indices.push(scope.add_symbol(
            AddressSpace::Ram,
            "",
            Some(datatype.clone()),
            0x6000 + index as u64 * 8,
            Some(0x7000 + index as u64),
        ));
    }

    // Phase 1: the ActionNameVars namerec loop — the first two
    // still-undefined symbols draw default names from the shared base
    // (coreaction.cc:2992-2996).
    let mut base: i32 = 1;
    for idx in indices.iter().take(2) {
        if scope.symbols[*idx].is_name_undefined() {
            let newname = scope
                .build_default_name(*idx, &mut base, None, None)
                .expect("default name");
            scope.rename_symbol(*idx, &newname);
        }
    }
    // Phase 2: assignDefaultNames continues with the SAME counter
    // (coreaction.cc:2998).
    scope
        .assign_default_names(&mut base)
        .expect("assign default names");

    for (index, idx) in indices.iter().enumerate() {
        println!("name{}={}", index, scope.symbols[*idx].name);
    }
    println!("base={base}");
}
