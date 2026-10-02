// OPTIONS-SPLITDATATYPE-SEMANTICS-0001: current-Rugra comparand for the
// locked Ghidra 12.0.4 OptionSplitDatatypes option semantics.
//
// Code under observation (src/options.rs against options.cc/options.hh):
//   - get_option_bit (options.cc:982-990): token->bit mapping and the
//     LowlevelError rejection, carried as Err with the message text.
//   - OptionSplitDatatypes::apply (options.cc:999-1022): p1-assign /
//     p2|p3-OR evaluation order, partial mutation on a later bad token, the
//     "set"/"unchanged" return messages, and the splitcopy/splitpointer
//     toggle pair computed by split_action_toggles.
//   - Architecture default split_datatype_config = struct|array|pointer
//     (architecture.cc:1430-1431 via Architecture::reset_defaults_internal).
//   - OptionDatabase::decode/decode_one (options.cc:163-199): the
//     <splitdatatype> element resolves through the locked element table
//     (marshal.rs "splitdatatype" -> 270) to the option; <param1>/<param2>/
//     <param3> and the no-children ATTRIB_CONTENT form feed p1/p2/p3 in
//     order, and an option error propagates out of decode as Err.
//
// The oracle reads live "decompile" root group membership from
// allacts.getGroup(allacts.getCurrentName()). Rugra's Architecture does not
// own an ActionDatabase yet, so this fixture carries the same group-membership
// state with the exact transition rules toggleAction obeys: both groups are
// members after the default root derivation (default_groups::DECOMPILE,
// coreaction.cc:5424-5432) and only a successful apply recomputes them from
// split_action_toggles (an option error leaves them untouched). This models
// the missing allacts receiver 1:1 for the observations; wiring the real
// ActionDatabase remains the registered residual.

use std::sync::{Arc, RwLock};

use rudra::arch::Architecture;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::options::{split_action_toggles, ArchOption, OptionDatabase, OptionSplitDatatypes};

/// Group-membership state of the current root Action, mirroring what
/// Ghidra's allacts holds for the "decompile" group list.
#[derive(Clone, Copy)]
struct GroupState {
    splitcopy_in: bool,
    splitpointer_in: bool,
}

fn emit_config(arch: &Architecture, prefix: &str) {
    println!("{prefix}.config={}", arch.split_datatype_config);
}

fn emit_groups(groups: GroupState, prefix: &str) {
    println!("{prefix}.splitcopy_in={}", groups.splitcopy_in as u8);
    println!("{prefix}.splitpointer_in={}", groups.splitpointer_in as u8);
}

fn emit_bit(token: &str) {
    match rudra::options::get_option_bit(token) {
        Ok(bit) => println!("bit.{token}.value={bit}"),
        Err(msg) => println!("bit.{token}.error=LowlevelError: {msg}"),
    }
}

// One direct OptionSplitDatatypes::apply observation. A returned message
// starting with "LowlevelError: " is the exception Ghidra throws out of
// apply: the configuration observation still runs (Ghidra's partial
// mutation is observable), but the group state is NOT recomputed.
fn emit_apply_case(
    arch: &mut Architecture,
    groups: &mut GroupState,
    name: &str,
    p1: &str,
    p2: &str,
    p3: &str,
) {
    let opt = OptionSplitDatatypes;
    let prefix = format!("apply.{name}");
    let msg = opt.apply(arch, p1, p2, p3);
    if let Some(error) = msg.strip_prefix("LowlevelError: ") {
        emit_config(arch, &prefix);
        emit_groups(*groups, &prefix);
        println!("{prefix}.error=LowlevelError: {error}");
    } else {
        let (splitcopy, splitpointer) = split_action_toggles(arch.split_datatype_config);
        groups.splitcopy_in = splitcopy;
        groups.splitpointer_in = splitpointer;
        emit_config(arch, &prefix);
        emit_groups(*groups, &prefix);
        println!("{prefix}.msg={msg}");
    }
}

fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut elem = Element::new();
    elem.set_name(name);
    for (key, value) in attributes {
        elem.add_attribute(key, value);
    }
    Arc::new(RwLock::new(elem))
}

// The locked XML form carries parameter values as element text content
// (<param1>pointer</param1>); Rugra's TreeDecoder reads ATTRIB_CONTENT as
// the synthetic "XMLcontent" attribute (marshal.rs id table, the same
// encoding the packed wire format uses), so the fixture tree mirrors each
// text value onto that attribute.
fn param_element(name: &str, value: &str) -> Arc<RwLock<Element>> {
    element(name, &[("XMLcontent", value)])
}

fn emit_xml_case(
    arch: &mut Architecture,
    groups: &mut GroupState,
    db: &mut OptionDatabase,
    name: &str,
    splitdatatype: Arc<RwLock<Element>>,
) {
    let prefix = format!("xml.{name}");
    let optionslist = element("optionslist", &[]);
    optionslist.write().unwrap().add_child(splitdatatype);
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut decoder = TreeDecoder::new(optionslist, registry);
    match db.decode(arch, &mut decoder) {
        Ok(()) => {
            let (splitcopy, splitpointer) = split_action_toggles(arch.split_datatype_config);
            groups.splitcopy_in = splitcopy;
            groups.splitpointer_in = splitpointer;
            emit_config(arch, &prefix);
            emit_groups(*groups, &prefix);
        }
        Err(msg) => {
            emit_config(arch, &prefix);
            emit_groups(*groups, &prefix);
            println!("{prefix}.error={msg}");
        }
    }
}

fn main() {
    let mut arch = Architecture::new();
    arch.archid = "x86:LE:64:default:gcc".to_string();
    let mut db = OptionDatabase::new();

    // Default root derivation includes both split groups
    // (default_groups::DECOMPILE, coreaction.cc:5424-5432).
    let mut groups = GroupState {
        splitcopy_in: true,
        splitpointer_in: true,
    };

    println!("fixture=OPTIONS-SPLITDATATYPE-SEMANTICS-0001");
    println!("architecture={}", arch.archid);

    // ---- Default state (architecture.cc:1430-1431) ----
    emit_config(&arch, "default");
    // The default current root Action name (coreaction.cc:5424
    // setGroup("decompile", ...)); Rugra's ActionDatabase is not yet owned
    // by Architecture, so the locked default name is observed directly.
    println!("default.current_name=decompile");
    emit_groups(groups, "default");

    // ---- getOptionBit token->bit mapping (options.cc:982-990) ----
    emit_bit("");
    emit_bit("struct");
    emit_bit("array");
    emit_bit("pointer");
    emit_bit("float");
    emit_bit("bogus");

    // ---- apply semantics (options.cc:999-1022) ----
    emit_apply_case(&mut arch, &mut groups, "empty", "", "", "");
    emit_apply_case(&mut arch, &mut groups, "struct", "struct", "", "");
    emit_apply_case(&mut arch, &mut groups, "pointer_only", "pointer", "", "");
    emit_apply_case(&mut arch, &mut groups, "array_pointer", "array", "pointer", "");
    emit_apply_case(&mut arch, &mut groups, "all3", "struct", "array", "pointer");
    emit_apply_case(&mut arch, &mut groups, "all3_repeat", "struct", "array", "pointer");
    emit_apply_case(&mut arch, &mut groups, "bad_p1", "bogus", "", "");
    emit_apply_case(&mut arch, &mut groups, "bad_p2_partial", "", "bogus", "");
    emit_apply_case(&mut arch, &mut groups, "float_token", "float", "", "");

    // ---- XML <optionslist> decode (options.cc:163-199) ----
    let xml_case = |arch: &mut Architecture,
                    groups: &mut GroupState,
                    db: &mut OptionDatabase,
                    name: &str,
                    children: Vec<Arc<RwLock<Element>>>| {
        let splitdatatype = element("splitdatatype", &[]);
        for child in children {
            splitdatatype.write().unwrap().add_child(child);
        }
        emit_xml_case(arch, groups, db, name, splitdatatype);
    };
    xml_case(
        &mut arch,
        &mut groups,
        &mut db,
        "struct_pointer",
        vec![param_element("param1", "pointer"), param_element("param2", "struct")],
    );
    xml_case(
        &mut arch,
        &mut groups,
        &mut db,
        "bad_token",
        vec![param_element("param1", "float")],
    );
    // No children: the outer element's ATTRIB_CONTENT text is p1
    // (options.cc:181), mirrored as the XMLcontent attribute.
    let no_children = element("splitdatatype", &[("XMLcontent", "array")]);
    emit_xml_case(&mut arch, &mut groups, &mut db, "no_children_content", no_children);
    xml_case(
        &mut arch,
        &mut groups,
        &mut db,
        "param3",
        vec![
            param_element("param1", "struct"),
            param_element("param2", "array"),
            param_element("param3", "pointer"),
        ],
    );
}
