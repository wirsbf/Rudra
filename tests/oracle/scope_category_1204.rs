use rudra::database::{Scope, Symbol, SymbolCategory};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, Weak};

type SymbolRef = Arc<RwLock<Symbol>>;
type SymbolWeak = Weak<RwLock<Symbol>>;

fn category_value(category: SymbolCategory) -> i32 {
    category as i32
}

fn slot_label(symbol: Option<SymbolRef>, aliases: &BTreeMap<&'static str, SymbolWeak>) -> String {
    let Some(symbol) = symbol else {
        return "-".to_string();
    };
    aliases
        .iter()
        .find_map(|(name, weak)| {
            weak.upgrade()
                .filter(|original| Arc::ptr_eq(original, &symbol))
                .map(|_| (*name).to_string())
        })
        .unwrap_or_else(|| "!foreign".to_string())
}

fn slots(scope: &Scope, aliases: &BTreeMap<&'static str, SymbolWeak>, category: i32) -> String {
    (0..scope.get_category_size(category))
        .map(|index| {
            slot_label(
                scope.get_category_symbol(category, index as i32),
                aliases,
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn symbols(aliases: &BTreeMap<&'static str, SymbolWeak>) -> String {
    aliases
        .iter()
        .filter_map(|(name, weak)| {
            weak.upgrade().map(|symbol| {
                let symbol = symbol.read().expect("symbol read lock");
                format!(
                    "{}:{}/{}",
                    name,
                    category_value(symbol.get_category()),
                    symbol.get_category_index()
                )
            })
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn owned(scope: &Scope, aliases: &BTreeMap<&'static str, SymbolWeak>) -> String {
    aliases
        .keys()
        .map(|name| format!("{}:{}", name, scope.find_by_name(name).len()))
        .collect::<Vec<_>>()
        .join(",")
}

fn destroyed(aliases: &BTreeMap<&'static str, SymbolWeak>) -> usize {
    aliases.values().filter(|weak| weak.upgrade().is_none()).count()
}

fn snapshot(stage: &str, scope: &Scope, aliases: &BTreeMap<&'static str, SymbolWeak>) {
    println!(
        "stage={stage} outer={} sizes=[{},{},{},{},{},{}] cat0=[{}] cat1=[{}] cat2=[{}] invalid=[{},{},{},{}] symbols=[{}] owned=[{}] destroyed={}",
        scope.categories.len(),
        scope.get_category_size(-1),
        scope.get_category_size(0),
        scope.get_category_size(1),
        scope.get_category_size(2),
        scope.get_category_size(3),
        scope.get_category_size(99),
        slots(scope, aliases, 0),
        slots(scope, aliases, 1),
        slots(scope, aliases, 2),
        u8::from(scope.get_category_symbol(-1, 0).is_none()),
        u8::from(scope.get_category_symbol(0, -1).is_none()),
        u8::from(scope.get_category_symbol(99, 0).is_none()),
        u8::from(scope.get_category_symbol(0, 999).is_none()),
        symbols(aliases),
        owned(scope, aliases),
        destroyed(aliases),
    );
}

fn add_alias(
    scope: &mut Scope,
    aliases: &mut BTreeMap<&'static str, SymbolWeak>,
    name: &'static str,
) -> u64 {
    let id = scope.add_symbol(name, "fixture_i32");
    let symbol = scope.symbols.get(&id).expect("new symbol");
    aliases.insert(name, Arc::downgrade(symbol));
    id
}

fn main() {
    let mut aliases: BTreeMap<&'static str, SymbolWeak> = BTreeMap::new();
    {
        let mut scope = Scope::new(0x1234, "fixture", 0);
        let a = add_alias(&mut scope, &mut aliases, "a");
        let b = add_alias(&mut scope, &mut aliases, "b");
        let c = add_alias(&mut scope, &mut aliases, "c");
        let d = add_alias(&mut scope, &mut aliases, "d");
        let e = add_alias(&mut scope, &mut aliases, "e");
        let f = add_alias(&mut scope, &mut aliases, "f");

        snapshot("initial", &scope, &aliases);

        scope.set_category(a, 0, 2);
        scope.set_category(b, 0, 0);
        scope.set_category(c, 0, 5);
        snapshot("cat0_holes", &scope, &aliases);
        let identity = [(0, a), (0, b), (0, c)]
            .iter()
            .zip([2, 0, 5])
            .map(|((category, id), index)| {
                let actual = scope
                    .get_category_symbol(*category, index)
                    .expect("identity slot");
                let expected = scope.symbols.get(id).expect("identity symbol");
                u8::from(Arc::ptr_eq(&actual, expected)).to_string()
            })
            .collect::<String>();
        println!("identity=cat0:{identity}");

        scope.set_category(d, 2, 99);
        scope.set_category(e, 2, 0);
        snapshot("cat2_gap", &scope, &aliases);
        scope.set_category(f, 1, 77);
        snapshot("higher_append", &scope, &aliases);

        scope.set_category(a, 2, 123);
        snapshot("move_a_to_cat2", &scope, &aliases);

        scope.set_category(d, 2, 999);
        snapshot("reappend_d_cat2", &scope, &aliases);

        scope.set_category(e, -1, 444);
        snapshot("uncategorize_e", &scope, &aliases);

        scope.set_category(a, 0, 1);
        snapshot("move_a_to_cat0", &scope, &aliases);

        scope.set_category(b, 0, 4);
        snapshot("move_b_within_cat0", &scope, &aliases);

        scope.remove_symbol(c);
        snapshot("delete_c", &scope, &aliases);

        scope.remove_symbol(b);
        snapshot("delete_b", &scope, &aliases);

        scope.set_category(a, -1, -2);
        snapshot("uncategorize_a", &scope, &aliases);

        scope.remove_symbol(d);
        scope.set_category(f, -1, 7);
        snapshot("empty_all_tables", &scope, &aliases);

        scope.set_category(e, 0, 1);
        scope.set_category(f, 0, 65537);
        snapshot("cat0_replace_wrapped_index", &scope, &aliases);
        let replacement = scope
            .get_category_symbol(0, 1)
            .expect("replacement slot");
        let f_symbol = scope.symbols.get(&f).expect("f symbol");
        let e_symbol = scope.symbols.get(&e).expect("e symbol");
        println!(
            "identity=replace:{}{}",
            u8::from(Arc::ptr_eq(&replacement, f_symbol)),
            u8::from(Arc::ptr_eq(&replacement, e_symbol)),
        );

        scope.set_category(f, -1, 7);
        snapshot("replacement_removed", &scope, &aliases);
    }

    println!("stage=scope_drop destroyed={}", destroyed(&aliases));
}
