/*
 * Rugra capability projection for DATABASE-SCOPE-OWNERSHIP-FIXTURE-0001.
 *
 * This intentionally does not construct a parallel Scope/FunctionSymbol
 * shadow graph.  It does exercise the real Database::find_create_scope API,
 * which supports explicit-id creation and repeat lookup.  The narrower gaps
 * are caller-owned Scope identity attachment and its exception ownership,
 * plus the absent concrete buildDatabase/FunctionSymbol/Funcdata ownership
 * chain.
 */

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::database::{Database, Scope};
use rudra::funcdata::Funcdata;

/// Compile-time category binding for the concrete production types consumed
/// below. A return/container value-type change fails to compile until the
/// observation contract is deliberately updated.
trait StorageClass {
    const CLASS: &'static str;
}

impl StorageClass for u64 {
    const CLASS: &'static str = "value";
}

impl StorageClass for Scope {
    const CLASS: &'static str = "value";
}

fn storage_class<T: StorageClass>(_: &T) -> &'static str {
    T::CLASS
}

fn map_value_storage_class<K, V: StorageClass>(
    _: &std::collections::BTreeMap<K, V>,
) -> &'static str {
    V::CLASS
}

fn vec_value_storage_class<T: StorageClass>(_: &Vec<T>) -> &'static str {
    T::CLASS
}

fn main() {
    let mut database = Database::new(true);
    let factory_id = 0x1204_0002;
    let next_scope_id_before = database.next_scope_id;
    let created_id = database.find_create_scope(factory_id, "factory_ns", 0);
    let next_scope_id_after_create = database.next_scope_id;
    let created_ptr = database
        .resolve_scope(created_id)
        .map(|scope| scope as *const _)
        .expect("find_create_scope did not register the created scope");
    let repeated_id = database.find_create_scope(factory_id, "ignored_name", 0);
    let next_scope_id_after_repeat = database.next_scope_id;
    let repeated = database
        .resolve_scope(repeated_id)
        .expect("find_create_scope repeat did not resolve the scope");
    let repeated_ptr = repeated as *const _;
    let resolver_key_present = database.resolve_scope(factory_id).is_some();
    let resolved_slot_stable = database
        .resolve_scope(factory_id)
        .map(|scope| std::ptr::eq(scope, repeated))
        .unwrap_or(false);
    let parent_child_id = database
        .get_global_scope()
        .and_then(|scope| scope.children.iter().find(|&&id| id == factory_id))
        .copied();
    let parent_child_key_resolves = parent_child_id
        .and_then(|id| database.resolve_scope(id))
        .is_some();
    let parent_child_resolved_slot_alias = parent_child_id
        .and_then(|id| database.resolve_scope(id))
        .map(|scope| std::ptr::eq(scope, repeated))
        .unwrap_or(false);
    let parent_child_count = database
        .get_global_scope()
        .map(|scope| scope.children.len())
        .unwrap_or(0);
    let return_class = storage_class(&created_id);
    let scope_storage_class = map_value_storage_class(&database.scopes);
    let parent_child_storage_class = database
        .get_global_scope()
        .map(|scope| vec_value_storage_class(&scope.children))
        .unwrap_or("UNAVAILABLE");
    println!(
        "case=find_create_scope|id_matches={}|resolver_key_present={}|repeat_key_same={}|name_preserved={}|parent_id={}|parent_child_key_resolves={}|parent_child_count={}|return_class={}|resolver_return_alias=UNAVAILABLE|repeat_return_alias=UNAVAILABLE|parent_child_return_alias=UNAVAILABLE|resolved_slot_stable={}|parent_child_resolved_slot_alias={}|scope_storage_class={}|parent_child_storage_class={}|next_scope_id_before={}|next_scope_id_after_create={}|next_scope_id_after_repeat={}",
        u8::from(created_id == factory_id),
        u8::from(resolver_key_present),
        u8::from(created_id == repeated_id),
        u8::from(repeated.get_name() == "factory_ns"),
        repeated.parent_id,
        u8::from(parent_child_key_resolves),
        parent_child_count,
        return_class,
        u8::from(created_ptr == repeated_ptr && resolved_slot_stable),
        u8::from(parent_child_resolved_slot_alias),
        scope_storage_class,
        parent_child_storage_class,
        next_scope_id_before,
        next_scope_id_after_create,
        next_scope_id_after_repeat,
    );

    let architecture = Architecture::new();
    let function = Funcdata::new("fixture_function", Address::new(0x7e12_0400), 0);

    println!(
        "case=rugra_constructor_state|architecture_symboltab_present={}|funcdata_arch_present={}|funcdata_local_scope_present={}",
        u8::from(architecture.symboltab.is_some()),
        u8::from(function.arch.is_some()),
        u8::from(function.scope.is_some()),
    );
    println!(
        "case=missing_capability|build_database=missing_concrete_factory|functionsymbol_funcdata_owner=missing|scope_arch_backref=missing|scope_funcdata_backref=missing|caller_owned_scope_identity_attach=missing|caller_owned_scope_failure_contract=missing|destructor_cascade=missing"
    );
    println!("case=overall|status=MISMATCH");
}
