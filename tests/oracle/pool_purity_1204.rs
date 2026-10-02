//! PIPE-POOL-LOCAL-RULES-0001 Rust comparand for the pool registration
//! purity oracle.
//!
//! Walks Rugra's real default action database — the production entry
//! `ActionDatabase::set_default_actions` (universalAction + resetDefaults,
//! architecture.cc:582-591) — and prints the identical projection the
//! locked Ghidra fixture emits, for both roots:
//!   - `root=all`: the RAW registered universal tree
//!     (`get_action("universal")`, the object graph `universal_action`
//!     built — the registration site).  The Ghidra fixture reaches the
//!     same full registration sequence through its union-grouplist derive
//!     (setGroup("all") + setCurrent("all"): ActionPool::clone keeps every
//!     rule in allrules order, action.cc:899-914), so the two observations
//!     are the same sequence.
//!   - `root=decompile`: the derived root (`get_current`, action.hh:313)
//!     — the production pipeline that actually runs.
//!
//! Every ActionPool node prints one `pool` line with its ':'-joined tree
//! path, name and rule count, followed by one `rule` line per registered
//! rule in REGISTRATION ORDER with pool name, index and the rule's
//! diagnostic name normalized by deleting '_' (Rugra names rules in
//! snake_case, the oracle mostly does not; the projection is injective on
//! both sides' name sets).  No sorting, no deduplication: the sequence
//! itself is the observable.

use rudra::action::{Action, ActionDatabase};

fn normalize_name(nm: &str) -> String {
    nm.chars().filter(|c| *c != '_').collect()
}

fn dfs(node: &dyn Action, path: &str) {
    let nm = node.get_name();
    let nodepath = if path.is_empty() {
        nm.to_string()
    } else {
        format!("{path}:{nm}")
    };
    if let Some(pool) = node.as_action_pool() {
        let rules = pool.rules();
        println!("pool|path={nodepath}|name={nm}|count={}", rules.len());
        for (index, rule) in rules.iter().enumerate() {
            println!(
                "rule|pool={nm}|index={index}|name={}",
                normalize_name(rule.get_name())
            );
        }
        return;
    }
    if let Some(group) = node.as_action_group() {
        for child in group.child_actions().iter() {
            dfs(child.as_ref(), &nodepath);
        }
    }
}

fn main() {
    println!("schema=1|fixture=PIPE-POOL-LOCAL-RULES-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // Production registration path: raw universal tree, then the default
    // derive (rebuild default grouplists, set_current "decompile" ->
    // grouplist-filtered construction).
    let mut allacts = ActionDatabase::new();
    allacts.set_default_actions();

    // Root 1: the raw registered universal tree — the registration site
    // (equivalent to the Ghidra fixture's union-grouplist derive).
    println!("root=all");
    dfs(allacts.get_action("universal").expect("universal root registered"), "");

    // Root 2: the derived decompile root — the production pipeline that
    // actually runs.
    println!("root=decompile");
    dfs(allacts.get_current(), "");
}
