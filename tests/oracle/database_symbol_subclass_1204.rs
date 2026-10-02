/*
 * Rugra comparand for DATABASE-SYMBOL-SUBCLASS-FIXTURE-0001
 * (MIGW1-DATABASE-0005 phase 2, second fixture), the bilateral twin of
 * tests/oracle/database_symbol_subclass_1204.cc.
 *
 * Exercises the same Symbol-subclass construction surface and the
 * entry/comparator carriers under the same anchors:
 *
 *   FunctionSymbol::buildType / ctors / getBytesConsumed
 *   LabSymbol::buildType / ctors
 *   ExternRefSymbol::buildNameType / ctor / getRefAddr
 *   UnionFacetSymbol ctors / getFieldNumber
 *   Symbol::getBytesConsumed / getMapEntryPosition (cc:309 quirk)
 *   SymbolEntry::getFirstUseAddress / printEntry
 *   SymbolEntry::EntrySubsort ordering
 *   SymbolCompareName / DuplicateFunctionError / Scope::printBounds
 *
 * All projections are id/name/size/message-level; printEntry strings are
 * compared verbatim.  The entry types are base types whose printRaw is
 * the plain name on both sides.  The TypeFactory uses the standalone
 * SLEIGH core table (CoreTypeFlavor::Standalone = sleigh_arch.cc:229),
 * mirroring the oracle's BfdArchitecture environment.
 *
 * Carrier adjudications mirrored here (recorded in docs/api/database.md):
 * - The C++ FunctionSymbol(Scope*,int4) decode ctor's observable state
 *   (empty name, consume size, code type, namelock|typelock) is reached
 *   through the named ctor with an empty name in the Rust value model —
 *   identical fields, construction-path difference only.
 * - The C++ Symbol carries its mapentry list; the Rust
 *   Symbol::get_map_entry_position takes the entry list as a parameter,
 *   so the fixture assembles the same insertion-ordered list.
 */

use rudra::address::{Address, Range, RangeList};
use rudra::database::{
    symbol_flags, DuplicateFunctionError, EntrySubsort, FunctionSymbol, LabSymbol, Scope,
    Symbol, SymbolCompareName, SymbolEntry,
};
use rudra::space::{space_flags, AddrSpace, SpaceType};
use rudra::type_system::datatype::TypeMetatype;
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};

fn hexoff(v: u64) -> String {
    format!("{:x}", v)
}

fn main() {
    let mut types = TypeFactory::new_flavor(8, CoreTypeFlavor::Standalone);
    let int4 = types.get_base(4, TypeMetatype::Int).unwrap();
    let ram = AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        4,
        1,
        3,
        space_flags::HASPHYSICAL,
        -1,
        -1,
    );
    let global_id = 100u64;

    // ---- FunctionSymbol (database.cc:514/534/545/508) ----
    {
        let f = FunctionSymbol::new(global_id, "main", 2, Address::new(0));
        let fs = &f.symbol;
        println!(
            "case=fsym_buildtype|metatype=code|size={}|namelock={}|typelock={}|name={}",
            fs.dtype.as_ref().unwrap().get_size(),
            (fs.flags & symbol_flags::NAMELOCK != 0) as u8,
            (fs.flags & symbol_flags::TYPELOCK != 0) as u8,
            fs.name
        );
        println!("case=fsym_bytes_consumed|{}", f.get_bytes_consumed());
        println!("case=fsym_type_size|{}", fs.dtype.as_ref().unwrap().get_size());
        // The C++ decode ctor FunctionSymbol(Scope*,int4) (database.cc:545)
        // observable state, reached through the named ctor with an empty
        // name in the value model (identical fields).
        let fd = FunctionSymbol::new(global_id, "", 3, Address::new(0));
        println!(
            "case=fsym_decode_ctor|name_empty={}|consume={}",
            (fd.symbol.name.is_empty()) as u8,
            fd.get_bytes_consumed()
        );
    }

    // ---- LabSymbol (database.cc:728/736/745) ----
    {
        let l = LabSymbol::new(global_id, "loop", Address::new(0), &types);
        let dt = l.symbol.dtype.as_ref().unwrap();
        println!(
            "case=lsym_buildtype|typename={}|size={}|name={}",
            dt.get_name(),
            dt.get_size(),
            l.symbol.name
        );
        let ld = LabSymbol::new_decode(global_id, Address::new(0), &types);
        let dt = ld.symbol.dtype.as_ref().unwrap();
        println!(
            "case=lsym_decode_ctor|name_empty={}|typename={}",
            (ld.symbol.name.is_empty()) as u8,
            dt.get_name()
        );
    }

    // ---- ExternRefSymbol (database.cc:768/789; hh:351) ----
    {
        let x = rudra::database::ExternRefSymbol::new(global_id, "", Address::with_space(&ram, 0x6000));
        println!(
            "case=exref_autoname|name={}|externref={}|typelock={}|ptr_size={}|ptr_meta=ptr",
            x.symbol.name,
            (x.symbol.flags & symbol_flags::EXTERNREF != 0) as u8,
            (x.symbol.flags & symbol_flags::TYPELOCK != 0) as u8,
            x.symbol.dtype.as_ref().unwrap().get_size()
        );
        let y = rudra::database::ExternRefSymbol::new(global_id, "printf", Address::with_space(&ram, 0x6010));
        println!("case=exref_named|name={}", y.symbol.name);
        println!("case=exref_ref_addr|{}", hexoff(x.get_ref_addr().as_u64()));
    }

    // ---- UnionFacetSymbol (database.cc:691; hh:323/324) ----
    {
        let udt = types.get_type_union("fixture_union");
        let u = rudra::database::UnionFacetSymbol::new(global_id, "f", Some(udt), 2);
        println!(
            "case=ufacet_ctor|field={}|category={}|typename={}",
            u.get_field_number(),
            u.symbol.category as i32,
            u.symbol.dtype.as_ref().unwrap().get_name()
        );
        let ud = rudra::database::UnionFacetSymbol::new_decode(global_id);
        println!(
            "case=ufacet_decode|field={}|category={}",
            ud.get_field_number(),
            ud.symbol.category as i32
        );
    }

    // ---- Symbol::getBytesConsumed (database.cc:508) ----
    {
        let mut s = Symbol::new(global_id, "s", "int");
        s.dtype = Some(int4.clone());
        println!("case=sym_bytes_consumed|{}", s.get_bytes_consumed());
    }

    // ---- Symbol::getMapEntryPosition (database.cc:301-313) ----
    {
        let sym = std::sync::Arc::new(std::sync::RwLock::new(Symbol::new(global_id, "m", "int")));
        sym.write().unwrap().dtype = Some(int4.clone());
        let empty = RangeList::new();
        // Same insertion order as the C++ mapentry list: three whole
        // entries then a partial piece.
        let e1 = SymbolEntry::new_static(sym.clone(), 0, Address::with_space(&ram, 0x1000), 0, 4, empty.clone());
        let e2 = SymbolEntry::new_static(sym.clone(), 0, Address::with_space(&ram, 0x2000), 0, 4, empty.clone());
        let e3 = SymbolEntry::new_static(sym.clone(), 0, Address::with_space(&ram, 0x3000), 0, 4, empty.clone());
        let piece = SymbolEntry::new_static(sym.clone(), 0, Address::with_space(&ram, 0x4000), 0, 2, empty.clone());
        let entries = vec![e1, e2, e3, piece];
        let sym_r = sym.read().unwrap();
        println!("case=mapentry_whole_sought|{}", sym_r.get_map_entry_position(&entries, &entries[1]));
        println!("case=mapentry_partial_sought|{}", sym_r.get_map_entry_position(&entries, &entries[3]));
        // An entry of a DIFFERENT symbol is absent from the list.
        let other = std::sync::Arc::new(std::sync::RwLock::new(Symbol::new(global_id, "other", "int")));
        other.write().unwrap().dtype = Some(int4.clone());
        let foreign = SymbolEntry::new_static(other, 0, Address::with_space(&ram, 0x8000), 0, 4, empty);
        println!("case=mapentry_absent|{}", sym_r.get_map_entry_position(&entries, &foreign));
    }

    // ---- SymbolEntry::getFirstUseAddress (database.cc:122) ----
    {
        let sym = std::sync::Arc::new(std::sync::RwLock::new(Symbol::new(global_id, "m2", "int")));
        sym.write().unwrap().dtype = Some(int4.clone());
        let mut uselim = RangeList::new();
        uselim.insert_range(
            Range::new(Address::with_space(&ram, 0x4000), Address::with_space(&ram, 0x4fff))
                .unwrap(),
        );
        let e = SymbolEntry::new_static(sym.clone(), 0, Address::with_space(&ram, 0x2000), 0, 4, uselim);
        println!("case=firstuse_present|{}", hexoff(e.get_first_use_address().as_u64()));
        let e2 = SymbolEntry::new_static(sym, 0, Address::with_space(&ram, 0x2100), 0, 4, RangeList::new());
        println!("case=firstuse_empty|{}", e2.get_first_use_address().is_invalid() as u8);
    }

    // ---- SymbolEntry::printEntry (database.cc:166-181) ----
    {
        let sym = std::sync::Arc::new(std::sync::RwLock::new(Symbol::new(global_id, "m", "int")));
        sym.write().unwrap().dtype = Some(int4.clone());
        let e1 = SymbolEntry::new_static(sym.clone(), 0, Address::with_space(&ram, 0x1000), 0, 4, RangeList::new());
        print!("case=printentry_static_all|{}", e1.print_entry());

        let sym2 = std::sync::Arc::new(std::sync::RwLock::new(Symbol::new(global_id, "m2", "int")));
        sym2.write().unwrap().dtype = Some(int4.clone());
        let mut uselim = RangeList::new();
        uselim.insert_range(
            Range::new(Address::with_space(&ram, 0x4000), Address::with_space(&ram, 0x4fff))
                .unwrap(),
        );
        let e2 = SymbolEntry::new_static(sym2, 0, Address::with_space(&ram, 0x2000), 0, 4, uselim);
        print!("case=printentry_uselimit|{}", e2.print_entry());

        let symd = std::sync::Arc::new(std::sync::RwLock::new(Symbol::new(global_id, "d", "int")));
        symd.write().unwrap().dtype = Some(int4.clone());
        let e3 = SymbolEntry::new_dynamic(symd, 0, 0x1234, 0, 4, RangeList::new());
        print!("case=printentry_dynamic|{}", e3.print_entry());
    }

    // ---- SymbolEntry::EntrySubsort (database.hh:107-134) ----
    {
        let earliest = EntrySubsort::earliest();
        let latest = EntrySubsort::from_bool(true);
        println!("case=subsort_earliest_lt_latest|{}", earliest.lt(&latest) as u8);
        println!("case=subsort_latest_gt_earliest|{}", (!latest.lt(&earliest)) as u8);
        let from_a = EntrySubsort::from_parts(3, 0x5000);
        let from_b = EntrySubsort::from_parts(3, 0x6000);
        println!("case=subsort_addr_offset_order|{}", from_a.lt(&from_b) as u8);
        println!("case=subsort_addr_offset_rev|{}", (!from_b.lt(&from_a)) as u8);
        let from_a2 = EntrySubsort::from_parts(3, 0x5000);
        println!("case=subsort_addr_equal|{}", (!from_a.lt(&from_a2)) as u8);
    }

    // ---- SymbolCompareName (database.hh:366) ----
    {
        let mut s1 = Symbol::new(global_id, "apple", "int");
        s1.dtype = Some(int4.clone());
        let mut s2 = Symbol::new(global_id, "banana", "int");
        s2.dtype = Some(int4.clone());
        let cmp = SymbolCompareName;
        println!("case=symcmp_name_order|{}", cmp.is_before(&s1, &s2) as u8);
        println!("case=symcmp_name_rev|{}", (!cmp.is_before(&s2, &s1)) as u8);
        let mut t1 = Symbol::new(global_id, "same", "int");
        t1.dtype = Some(int4.clone());
        t1.name_dedup = 1;
        let mut t2 = Symbol::new(global_id, "same", "int");
        t2.dtype = Some(int4.clone());
        t2.name_dedup = 2;
        println!("case=symcmp_dedup_tiebreak|{}", cmp.is_before(&t1, &t2) as u8);
        println!("case=symcmp_dedup_rev|{}", (!cmp.is_before(&t2, &t1)) as u8);
    }

    // ---- DuplicateFunctionError (database.hh:435) ----
    {
        let err = DuplicateFunctionError::new(Address::with_space(&ram, 0x5000), "foo");
        println!(
            "case=dupfn|msg={}|addr={}|name={}",
            err.message,
            hexoff(err.address.as_u64()),
            err.function_name
        );
    }

    // ---- Scope::printBounds (database.hh:789) ----
    {
        let mut scope = Scope::new(101, "ns", global_id);
        let mut rlist = RangeList::new();
        rlist.insert_range(
            Range::new(Address::with_space(&ram, 0x3000), Address::with_space(&ram, 0x3fff))
                .unwrap(),
        );
        rlist.insert_range(
            Range::new(Address::with_space(&ram, 0x1000), Address::with_space(&ram, 0x1fff))
                .unwrap(),
        );
        for rng in rlist.ranges() {
            scope.rangetree.insert_range(*rng);
        }
        print!("case=scope_printbounds|{}", scope.print_bounds());
    }
}
