//! PIPE-DERIVED-TREE-0001 Rust comparand for the derived default pipeline
//! tree.
//!
//! Walks Rudra's real default action database — the production entry
//! `ActionDatabase::set_default_actions` (universalAction + resetDefaults,
//! architecture.cc:582-591) followed by `get_current` (action.hh:313) — and
//! prints the identical depth-first observation the locked Ghidra fixture
//! emits: per node the ':'-joined tree path, global pre-order ordinal, kind
//! (group/pool/leaf), exact name, basegroup and rule flags.  Duplicate
//! names at distinct slots are kept verbatim; no sorting or deduplication.

use rudra::action::{Action, ActionDatabase};

fn dfs(node: &dyn Action, basegroup: &str, path: &str, ordinal: &mut usize) {
    let kind = if node.as_action_group().is_some() {
        "group"
    } else if node.as_action_pool().is_some() {
        "pool"
    } else {
        "leaf"
    };
    println!(
        "node|ordinal={ordinal}|path={path}|kind={kind}|name={}|basegroup={basegroup}|flags={}",
        node.get_name(),
        node.get_flags()
    );
    *ordinal += 1;
    if let Some(group) = node.as_action_group() {
        for (index, child) in group.child_actions().iter().enumerate() {
            let child_path = format!("{path}:{}", child.get_name());
            dfs(child.as_ref(), group.child_group(index), &child_path, ordinal);
        }
    }
}

fn main() {
    println!("schema=1|fixture=PIPE-DERIVED-TREE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // Production derivation path: raw universal tree, then the default
    // derive (keep universal, rebuild default grouplists, set_current
    // "decompile" -> grouplist-filtered construction).
    let mut allacts = ActionDatabase::new();
    allacts.set_default_actions();
    let root: &dyn Action = allacts.get_current();

    println!("root_key={}", allacts.get_current_name());
    println!("root_name={}", root.get_name());
    println!("root_flags={}", root.get_flags());

    let mut ordinal = 0usize;
    let root_name = root.get_name();
    dfs(root, "", root_name, &mut ordinal);
    println!("count={ordinal}");
}
