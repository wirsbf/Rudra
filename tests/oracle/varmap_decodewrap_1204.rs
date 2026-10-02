// Rudra comparand for VARMAP-DECODEWRAP-0001 (handed over from
// MIGW1-DATABASE-0005 phase 3, ruling R5).
//
// Mirrors tests/oracle/varmap_decodewrap_1204.cc case for case through the
// production src/varmap.rs value model:
//
//   ScopeLocal::decode_wrapping_attributes (varmap.cc:479-486 — the only
//       override of Scope::decodeWrappingAttributes, database.hh:719;
//       ATTRIB_LOCK -> rangeLocked, ATTRIB_MAIN -> space)
//   ScopeLocal::reset_local_window's rangeLocked guard (varmap.cc:439:
//       the cc:435-437 refresh runs, the union install is skipped)
//
// The C++ fixture drives its side through the production call point
// Database::decodeScope (database.cc:3385 dispatches the override when the
// opened element is not <scope>). The Rust value model keeps ScopeLocal
// outside Database::scopes (a Funcdata-owned struct), so the comparand
// drives the ported method at the equivalent boundary: the wrapper element
// opened, attributes ingested, then the same reset_local_window
// observation. Every printed field — locked, space, union, min, max,
// growneg, err — projects the identical state.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::fspec::ProtoModelFull;
use rudra::funcdata::Funcdata;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::space::{space_flags, AddrSpace, AddressSpace, SpaceRegistry, SpaceType};
use rudra::varmap::ScopeLocal;

/// The fixture space registry: other (index 1) + ram (index 3) + the
/// 8-byte negative-growth stack (index 5) — the resolve domain of
/// readSpace(ATTRIB_MAIN), the same spaces the C++ FixtureTranslate
/// installs.
fn fixture_registry() -> SpaceRegistry {
    let mut registry = SpaceRegistry::new();
    registry
        .insert_space(AddrSpace::new_space(
            SpaceType::Processor,
            "other",
            false,
            8,
            1,
            1,
            space_flags::HASPHYSICAL,
            0,
            0,
        ))
        .unwrap();
    registry
        .insert_space(AddrSpace::new_space(
            SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            space_flags::HASPHYSICAL,
            0,
            0,
        ))
        .unwrap();
    let ram = registry.get_space_by_name("ram").unwrap();
    registry
        .insert_space(AddrSpace::new_spacebase_space(
            "stack", 5, 8, &ram, 1, true, false,
        ))
        .unwrap();
    registry
}

/// A `<localdb ...>` wrapper element with the given attributes (the shape
/// ScopeLocal::encode writes, varmap.cc:465-467).
fn wrap_element(attrs: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut element = Element::new();
    element.set_name("localdb");
    for (key, value) in attrs {
        element.add_attribute(key, value);
    }
    Arc::new(RwLock::new(element))
}

/// The per-case Funcdata of the C++ fixture (fresh function, default
/// dw_default model binding) — consumed by the reset cases.
fn fixture_fd(name: &str, off: u64) -> Funcdata {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = "dw_default".to_string();
    let model = Arc::new(model);
    let mut arch = Architecture::new();
    let mut proto_models: BTreeMap<String, Arc<ProtoModelFull>> = BTreeMap::new();
    proto_models.insert("dw_default".to_string(), model.clone());
    arch.proto_models = proto_models;
    arch.defaultfp = Some(model.clone());
    let mut fd = Funcdata::new(name, Address::new(off), 0x20);
    fd.set_arch(Arc::new(arch));
    fd.get_func_proto_mut().set_model(Some(model.clone()));
    fd
}

/// One decode case: fresh ScopeLocal (constructor default space = Stack,
/// varmap.cc:341-350), wrapper opened, attributes ingested through the
/// ported override. Prints the same `locked=..|space=..` / `err=..` body.
fn run_decode_case(
    registry: &SpaceRegistry,
    attrs: &[(&str, &str)],
    fd: &Funcdata,
) -> (String, ScopeLocal) {
    use rudra::marshal::Decoder as _;
    let mut scope = ScopeLocal::new();
    // The wrapper element open state Database::decodeScope hands the
    // override (database.cc:3378-3385).
    let registry_ids = Arc::new(RwLock::new(IdRegistry::new()));
    let mut decoder = TreeDecoder::new(wrap_element(attrs), registry_ids);
    assert_ne!(decoder.open_element(), 0, "wrapper element must open");
    let body = match scope.decode_wrapping_attributes(&mut decoder, registry) {
        Ok(()) => format!("locked={}|space={}", scope.range_locked as u8, scope.space.name()),
        Err(message) => format!("err={}", message),
    };
    let _ = fd; // the C++ case binds the model; the decode never reads it
    (body, scope)
}

/// Render the scope's union window as `first-last` hex pairs, ';'-joined,
/// in tree order — the local_range projection of getRangeTree().
fn ranges_text(ranges: &[(u64, u64)]) -> String {
    ranges
        .iter()
        .map(|(first, last)| format!("{:x}-{:x}", first, last))
        .collect::<Vec<_>>()
        .join(";")
}

fn main() {
    let registry = fixture_registry();

    println!(
        "schema=1|fixture=VARMAP-DECODEWRAP-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // decode_lock_true: lock="true" main="stack".
    {
        let fd = fixture_fd("decode_lock_true", 0x9000);
        let (body, _scope) = run_decode_case(
            &registry,
            &[("main", "stack"), ("lock", "true")],
            &fd,
        );
        println!("case=decode_lock_true|{}", body);
    }
    // decode_lock_false: the unconditional reset (varmap.cc:482) clears a
    // stale lock before the read.
    {
        let fd = fixture_fd("decode_lock_false", 0x9020);
        let (body, _scope) = run_decode_case(
            &registry,
            &[("main", "stack"), ("lock", "false")],
            &fd,
        );
        println!("case=decode_lock_false|{}", body);
    }
    // decode_lock_one: xml_readbool's first-char parse (xml.hh:391-396).
    {
        let fd = fixture_fd("decode_lock_one", 0x9040);
        let (body, _scope) =
            run_decode_case(&registry, &[("main", "stack"), ("lock", "1")], &fd);
        println!("case=decode_lock_one|{}", body);
    }
    // decode_lock_yes: xml_readbool's legacy first-char 'y' arm
    // (xml.hh:398, "For backward compatibility"); MARSHAL-READBOOL-0001.
    {
        let fd = fixture_fd("decode_lock_yes", 0x9120);
        let (body, _scope) =
            run_decode_case(&registry, &[("main", "stack"), ("lock", "yes")], &fd);
        println!("case=decode_lock_yes|{}", body);
    }
    // decode_lock_truecap: the first-char parse is case-sensitive — 'T'
    // is not 't' (xml.hh:396), so the lock stays off.
    {
        let fd = fixture_fd("decode_lock_truecap", 0x9140);
        let (body, _scope) =
            run_decode_case(&registry, &[("main", "stack"), ("lock", "True")], &fd);
        println!("case=decode_lock_truecap|{}", body);
    }
    // decode_main_ram: the space is REASSIGNED from the ctor stack.
    {
        let fd = fixture_fd("decode_main_ram", 0x9060);
        let (body, _scope) =
            run_decode_case(&registry, &[("main", "ram"), ("lock", "true")], &fd);
        println!("case=decode_main_ram|{}", body);
    }
    // decode_main_other: a non-canonical space name resolves through the
    // manager and re-points the scope space (the Other(index) fallback
    // arm of the enum mapping; the oracle observation is "other").
    {
        let fd = fixture_fd("decode_main_other", 0x9100);
        let (body, _scope) =
            run_decode_case(&registry, &[("main", "other"), ("lock", "true")], &fd);
        println!("case=decode_main_other|{}", body);
    }
    // decode_main_unknown: the manager lookup rejects unknown names with
    // the oracle's exact message (marshal.cc:421).
    {
        let fd = fixture_fd("decode_main_unknown", 0x9080);
        let (body, _scope) = run_decode_case(
            &registry,
            &[("main", "nosuch"), ("lock", "true")],
            &fd,
        );
        println!("case=decode_main_unknown|{}", body);
    }
    // decode_main_missing: findMatchingAttribute's message (marshal.cc:275).
    {
        let fd = fixture_fd("decode_main_missing", 0x90a0);
        let (body, _scope) = run_decode_case(&registry, &[("lock", "true")], &fd);
        println!("case=decode_main_missing|{}", body);
    }
    // decode_lock_missing: readBool(ATTRIB_LOCK) runs BEFORE the main
    // read (varmap.cc:483), so findMatchingAttribute throws on the lock
    // first (marshal.cc:275-276) — even though main is present;
    // MARSHAL-READBOOL-0001.
    {
        let fd = fixture_fd("decode_lock_missing", 0x9160);
        let (body, _scope) = run_decode_case(&registry, &[("main", "stack")], &fd);
        println!("case=decode_lock_missing|{}", body);
    }
    // reset_locked: cc:435-437 refresh runs, cc:439 guard skips the
    // window install (the empty window survives).
    {
        let fd = fixture_fd("reset_locked", 0x90c0);
        let (_body, mut scope) = run_decode_case(
            &registry,
            &[("main", "stack"), ("lock", "true")],
            &fd,
        );
        scope.min_param_offset = 0x10;
        scope.max_param_offset = 0x20;
        scope.stack_grows_negative = false;
        scope.reset_local_window(&fd);
        println!(
            "case=reset_locked|locked={}|union={}|min={:x}|max={:x}|growneg={}",
            scope.range_locked as u8,
            ranges_text(&scope.local_range),
            scope.min_param_offset,
            scope.max_param_offset,
            scope.stack_grows_negative as u8
        );
    }
    // reset_unlocked: the default union installs ([0,0x1ff] ∪
    // [0xfffffffffff0bdc0,0xffffffffffffffff], ascending by first).
    {
        let fd = fixture_fd("reset_unlocked", 0x90e0);
        let (_body, mut scope) = run_decode_case(
            &registry,
            &[("main", "stack"), ("lock", "false")],
            &fd,
        );
        scope.min_param_offset = 0x10;
        scope.max_param_offset = 0x20;
        scope.stack_grows_negative = false;
        scope.reset_local_window(&fd);
        println!(
            "case=reset_unlocked|locked={}|union={}|min={:x}|max={:x}|growneg={}",
            scope.range_locked as u8,
            ranges_text(&scope.local_range),
            scope.min_param_offset,
            scope.max_param_offset,
            scope.stack_grows_negative as u8
        );
    }
}
