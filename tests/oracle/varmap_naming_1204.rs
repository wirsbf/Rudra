// VARMAP-NAMING-0001: Rudra comparand for the locked Ghidra 12.0.4
// authoritative default-naming oracle.  Mirrors
// tests/oracle/varmap_naming_1204.cc case for case: the same ScopeLocal
// states (local windows, parameter boundaries, register table, categories)
// drive ScopeLocal::assign_default_names / build_default_name /
// build_variable_name / make_name_unique, and the complete naming-state
// mutation (SymbolNameTree order, name/displayName, category, category index,
// nameDedup, shared base counter) is printed in the shared observation
// format.

use std::sync::Arc;

use rudra::space::AddressSpace;
use rudra::type_system::datatype::{TypeArray, TypeBase, TypePointer};
use rudra::type_system::{Datatype, TypeMetatype};
use rudra::varmap::{symbol_category, ScopeLocal};
use rudra::varnode::varnode_flags;

struct NamingScope {
    scope: ScopeLocal,
}

impl NamingScope {
    fn new(_name: &str, local_ranges: &[(u64, u64)]) -> Self {
        let mut scope = ScopeLocal::new();
        scope.local_range = local_ranges.to_vec();
        scope.proto_local_range = local_ranges.to_vec();
        NamingScope { scope }
    }

    fn int_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)))
    }
    fn char_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)))
    }
    fn long_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int)))
    }
    fn ptr_array_int() -> Arc<Datatype> {
        let array = Arc::new(Datatype::Array(TypeArray {
            base: TypeBase::new("int[3]".into(), 12, TypeMetatype::Array),
            array_of: Self::int_t(),
            num_elements: 3,
        }));
        Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int[3] *".into(), 8, TypeMetatype::Pointer),
            ptr_to: array,
            wordsize: 0,
        }))
    }

    fn add(&mut self, nm: &str, ct: Arc<Datatype>, offset: u64, has_usepoint: bool,
           cat: i32, catidx: i32) {
        let usepoint = if has_usepoint { Some(0x1000) } else { None };
        let idx = self.scope.add_symbol(AddressSpace::Stack, nm, Some(ct), offset, usepoint);
        if cat >= 0 {
            self.scope.set_category(idx, cat, catidx);
        }
    }

    /// Render the full naming state in SymbolNameTree order:
    /// name:display:category:catindex:nameDedup per symbol, ';' separated.
    fn state_text(&self) -> String {
        let mut out = String::from("[");
        let mut first = true;
        for idx in self.scope.symbols_in_nametree_order() {
            let sym = &self.scope.symbols[idx];
            if !first {
                out.push(';');
            }
            first = false;
            out.push_str(&format!(
                "{}:{}:{}:{}:{}",
                sym.name, sym.display_name, sym.category, sym.cat_index, sym.name_dedup
            ));
        }
        out.push(']');
        out
    }

    fn run(&mut self, case_name: &str, extra: &str) {
        print!("case={}|pre={}", case_name, self.state_text());
        let mut base: i32 = 1;
        self.scope.assign_default_names(&mut base).unwrap();
        print!("|post={}|base={}", self.state_text(), base);
        self.scope.assign_default_names(&mut base).unwrap();
        println!("|post2={}|base2={}|extra=[{}]", self.state_text(), base, extra);
    }
}

// case=cross_category_shared_base
fn run_cross_category() {
    let mut t = NamingScope::new(
        "cross_category",
        &[(0xffffffffffffff00, 0xffffffffffffffff)],
    );
    t.add("", NamingScope::long_t(), 0x10, false, symbol_category::FUNCTION_PARAMETER, 0);
    t.add("", NamingScope::char_t(), 0x20, false, symbol_category::FUNCTION_PARAMETER, 1);
    t.add("", NamingScope::int_t(), 0xffffffffffffff10, false, -1, -1); // iStack_10 (local range)
    t.add("", NamingScope::char_t(), 0xffffffffffffff20, true, -1, -1); // cVar? (default branch)
    t.add("", NamingScope::long_t(), 0xffffffffffffff30, true, -1, -1); // lVar? (default branch)
    t.run("cross_category_shared_base", "");
}

// case=sequential_increment_shared_base
fn run_sequential_increment() {
    let mut t = NamingScope::new("sequential_increment", &[]); // empty local range
    t.add("", NamingScope::int_t(), 0xffffffffffffff10, true, -1, -1);
    t.add("", NamingScope::char_t(), 0xffffffffffffff20, true, -1, -1);
    t.add("", NamingScope::int_t(), 0xffffffffffffff30, true, -1, -1);
    t.add("", NamingScope::long_t(), 0xffffffffffffff40, true, -1, -1);
    t.add("", NamingScope::int_t(), 0x50, false, -1, -1); // iStack<16-digit hex> via addrtied
    t.run("sequential_increment_shared_base", "");
}

// case=typelock_display_and_bump
fn run_typelock_and_bump() {
    let mut t = NamingScope::new("typelock_bump", &[]);
    t.add("cust_lock", NamingScope::long_t(), 0xffffffffffffff10, true,
          symbol_category::FUNCTION_PARAMETER, 5);
    // Mirror of `cust->flags |= typelock|namelock` (read-only observation:
    // assignDefaultNames skips any non-$$undef name regardless of locks).
    t.scope.symbols[0].typelock = true;
    t.scope.symbols[0].namelock = true;
    t.add("iVar1", NamingScope::int_t(), 0xffffffffffffff20, true, -1, -1);
    t.add("iVar1_00", NamingScope::int_t(), 0xffffffffffffff28, true, -1, -1);
    t.add("iVar1_01", NamingScope::int_t(), 0xffffffffffffff30, true, -1, -1);
    t.add("", NamingScope::int_t(), 0xffffffffffffff38, true, -1, -1); // bump past iVar1
    t.add("", NamingScope::int_t(), 0xffffffffffffff40, true, -1, -1); // next shared number
    let extra = format!(
        "{};{};{};{}",
        t.scope.make_name_unique("iVar1").unwrap(),
        t.scope.make_name_unique("iVar1_01").unwrap(),
        t.scope.make_name_unique("iVar9").unwrap(),
        t.scope.make_name_unique("cust_lock").unwrap(),
    );
    t.run("typelock_display_and_bump", &extra);
}

// case=scopelocal_stack_paths
fn run_stack_paths() {
    let mut t = NamingScope::new(
        "stack_paths",
        &[(0xfffffffffffff000, 0xffffffffffffffff), (0x1000000000000000, 0x1fffffffffffffff)],
    );
    t.scope.mark_not_mapped(0xffffffffffffff20, 1, true); // minParamOffset
    t.scope.mark_not_mapped(0xffffffffffffff30, 1, true); // maxParamOffset
    t.add("", NamingScope::int_t(), 0xffffffffffffff10, false, -1, -1); // Y region
    t.add("", NamingScope::int_t(), 0x1000000000000020, false, -1, -1); // X region
    t.add("", NamingScope::int_t(), 0xfffffffffffffff0, false, -1, -1); // plain positive start
    t.add("", NamingScope::long_t(), 0x20, false, symbol_category::FUNCTION_PARAMETER, 2); // param_3
    t.add("", NamingScope::int_t(), 0x1000000000000040, true, -1, -1); // default branch iVar
    t.run("scopelocal_stack_paths", "");
}

// case=direct_flag_paths
fn run_direct_flags() {
    let mut t = NamingScope::new("direct_flags", &[]);
    t.scope.register_names.insert((0x100, 8), "SREG1".to_string());
    t.scope.register_names.insert((0x108, 4), "SREG2".to_string());
    let int_t = NamingScope::int_t();
    let long_t = NamingScope::long_t();
    let pc = None;
    let mut results: Vec<String> = Vec::new();
    let call = |scope: &ScopeLocal, space: AddressSpace, off: u64,
                ct: &Arc<Datatype>, index: i32, flags: u32| -> String {
        let mut idx = index;
        scope
            .build_variable_name(space, off, pc, Some(ct), &mut idx, flags)
            .unwrap()
    };
    results.push(call(&t.scope, AddressSpace::Register, 0x100, &long_t, -1,
                      varnode_flags::UNAFFECTED | varnode_flags::RETURN_ADDRESS));
    results.push(call(&t.scope, AddressSpace::Register, 0x100, &int_t, -1,
                      varnode_flags::UNAFFECTED));
    results.push(call(&t.scope, AddressSpace::Register, 0x100, &long_t, -1,
                      varnode_flags::UNAFFECTED));
    results.push(call(&t.scope, AddressSpace::Register, 0x100, &long_t, -1,
                      varnode_flags::PERSIST));
    results.push(call(&t.scope, AddressSpace::Stack, 0x40, &int_t, -1,
                      varnode_flags::PERSIST));
    results.push(call(&t.scope, AddressSpace::Register, 0x108, &int_t, -1,
                      varnode_flags::INPUT));
    results.push(call(&t.scope, AddressSpace::Stack, 0x20, &int_t, -1,
                      varnode_flags::INPUT));
    results.push(call(&t.scope, AddressSpace::Stack, 0x20, &int_t, 7,
                      varnode_flags::INPUT));
    results.push(call(&t.scope, AddressSpace::Register, 0x100, &long_t, -1,
                      varnode_flags::INDIRECT_CREATION));
    results.push(call(&t.scope, AddressSpace::Stack, 0x0, &int_t, -1,
                      varnode_flags::INDIRECT_CREATION));
    results.push(call(&t.scope, AddressSpace::Stack, 0x20, &int_t, 1, 0));
    results.push(call(&t.scope, AddressSpace::Stack, 0x20, &NamingScope::ptr_array_int(), 1, 0));
    t.run("direct_flag_paths", &results.join(";"));
}

// case=undef_dedup_and_shared_base
fn run_undef_dedup() {
    let mut t = NamingScope::new("undef_dedup", &[]);
    t.add("", NamingScope::int_t(), 0xffffffffffffff10, true, -1, -1);
    t.add("", NamingScope::int_t(), 0xffffffffffffff20, true, -1, -1);
    t.add("", NamingScope::int_t(), 0xffffffffffffff30, true, -1, -1);
    t.add("dup", NamingScope::int_t(), 0xffffffffffffff40, true, -1, -1);
    t.add("dup", NamingScope::int_t(), 0xffffffffffffff50, true, -1, -1);
    t.add("dup", NamingScope::int_t(), 0xffffffffffffff60, true, -1, -1);
    t.run("undef_dedup_and_shared_base", "");
}

fn main() {
    println!("schema=1|fixture=VARMAP-NAMING-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    run_cross_category();
    run_sequential_increment();
    run_typelock_and_bump();
    run_stack_paths();
    run_direct_flags();
    run_undef_dedup();
}
