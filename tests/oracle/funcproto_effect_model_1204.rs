use std::sync::Arc;

use rudra::fspec::{EffectRecord, EffectType, FuncProto, ProtoModelFull};
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

#[derive(Clone, Copy)]
struct Probe {
    label: &'static str,
    space_name: &'static str,
    space: AddressSpace,
    offset: u64,
    size: i32,
}

const PROBES: &[Probe] = &[
    Probe { label: "unique_always", space_name: "unique", space: AddressSpace::Unique, offset: 0x777, size: 4 },
    Probe { label: "same_offset_const", space_name: "const", space: AddressSpace::Const, offset: 0x10, size: 8 },
    Probe { label: "whole_ram_space", space_name: "ram", space: AddressSpace::Ram, offset: 0x777, size: 32 },
    Probe { label: "register_exact", space_name: "register", space: AddressSpace::Register, offset: 0x10, size: 8 },
    Probe { label: "register_contained", space_name: "register", space: AddressSpace::Register, offset: 0x12, size: 2 },
    Probe { label: "register_partial_left", space_name: "register", space: AddressSpace::Register, offset: 0x0e, size: 4 },
    Probe { label: "register_partial_right", space_name: "register", space: AddressSpace::Register, offset: 0x16, size: 4 },
    Probe { label: "register_killed", space_name: "register", space: AddressSpace::Register, offset: 0x20, size: 8 },
    Probe { label: "return_address", space_name: "register", space: AddressSpace::Register, offset: 0x30, size: 8 },
    Probe { label: "same_offset_stack", space_name: "stack", space: AddressSpace::Stack, offset: 0x10, size: 8 },
    Probe { label: "same_offset_register", space_name: "register", space: AddressSpace::Register, offset: 0x10, size: 8 },
    Probe { label: "before_first_register", space_name: "register", space: AddressSpace::Register, offset: 0x08, size: 8 },
];

fn effect_name(effect: EffectType) -> &'static str {
    match effect {
        EffectType::Unaffected => "unaffected",
        EffectType::KilledByCall => "killedbycall",
        EffectType::ReturnAddress => "return_address",
        EffectType::UnknownEffect => "unknown_effect",
    }
}

fn model_effects() -> Vec<EffectRecord> {
    let mut effects = vec![
        EffectRecord::new(AddressSpace::Const, 0x10, 8, EffectType::KilledByCall),
        EffectRecord::new(AddressSpace::Ram, 0, 0, EffectType::Unaffected),
        EffectRecord::new(AddressSpace::Register, 0x10, 8, EffectType::Unaffected),
        EffectRecord::new(AddressSpace::Register, 0x20, 8, EffectType::KilledByCall),
        EffectRecord::new(AddressSpace::Register, 0x30, 8, EffectType::ReturnAddress),
        EffectRecord::new(AddressSpace::Stack, 0x10, 8, EffectType::KilledByCall),
    ];
    effects.sort_by_key(|effect| (effect.space.space_id(), effect.offset));
    effects
}

fn space_name(space: AddressSpace) -> &'static str {
    match space {
        AddressSpace::Const => "const",
        AddressSpace::Unique => "unique",
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Stack => "stack",
        _ => panic!("fixture received an unexpected address space"),
    }
}

fn write_effective_records(out: &mut String, proto: &FuncProto) {
    out.push('[');
    for (index, effect) in proto.effect_iter().iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str("{\"space\":\"");
        out.push_str(space_name(effect.space));
        out.push_str("\",\"offset\":");
        out.push_str(&effect.offset.to_string());
        out.push_str(",\"size\":");
        out.push_str(&effect.size.to_string());
        out.push_str(",\"effect\":\"");
        out.push_str(effect_name(effect.effect_type));
        out.push_str("\"}");
    }
    out.push(']');
}

fn make_model(name: &str, extrapop: i32, has_this: bool, constructor: bool) -> Arc<ProtoModelFull> {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = name.to_string();
    model.extrapop = extrapop;
    model.has_this = has_this;
    model.is_construct = constructor;
    model.output.set_auto_killed_by_call(true);
    model.effectlist = model_effects();
    Arc::new(model)
}

fn make_unknown_model() -> Arc<ProtoModelFull> {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = "fixture_unknown".to_string();
    model.extrapop = 0x8000;
    model.output.set_auto_killed_by_call(true);
    model.effectlist = vec![EffectRecord::new(
        AddressSpace::Register,
        0x40,
        8,
        EffectType::ReturnAddress,
    )];
    Arc::new(model)
}

fn make_replacement_model() -> Arc<ProtoModelFull> {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = "fixture_replacement".to_string();
    model.extrapop = 24;
    model.output.set_auto_killed_by_call(true);
    Arc::new(model)
}

fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

fn write_effects(out: &mut String, proto: &FuncProto) {
    out.push('[');
    for (index, probe) in PROBES.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let effect = proto.has_effect(probe.space, probe.offset, probe.size);
        out.push_str("{\"label\":\"");
        out.push_str(probe.label);
        out.push_str("\",\"space\":\"");
        out.push_str(probe.space_name);
        out.push_str("\",\"offset\":");
        out.push_str(&probe.offset.to_string());
        out.push_str(",\"size\":");
        out.push_str(&probe.size.to_string());
        out.push_str(",\"effect\":\"");
        out.push_str(effect_name(effect));
        out.push_str("\"}");
    }
    out.push(']');
}

fn lookup_record_code(result: Result<Option<usize>, ()>) -> i32 {
    match result {
        Ok(Some(index)) => index as i32,
        Ok(None) => -1,
        Err(()) => -2,
    }
}

fn main() {
    let void_type = void_type();
    let model = make_model("fixture_model", 16, true, true);
    let independent_model = make_model("fixture_model", 16, true, true);
    let unknown_model = make_unknown_model();
    let replacement_model = make_replacement_model();

    let mut model_proto = FuncProto::new(String::new(), void_type.clone());
    model_proto.set_model(Some(model.clone()));
    let mut model_copy = FuncProto::new(String::new(), void_type.clone());
    model_copy.copy_from(&model_proto);
    let mut independent_proto = FuncProto::new(String::new(), void_type.clone());
    independent_proto.set_model(Some(independent_model));

    let mut override_a = FuncProto::new(String::new(), void_type.clone());
    override_a.set_model(Some(model.clone()));
    override_a.effects = vec![
        EffectRecord::new(AddressSpace::Register, 0x10, 8, EffectType::KilledByCall),
    ];
    override_a
        .decode_effect(&model.effectlist)
        .expect("exact override A must merge");
    let mut override_a_copy = FuncProto::new(String::new(), void_type.clone());
    override_a_copy.copy_from(&override_a);

    let mut override_b = FuncProto::new(String::new(), void_type.clone());
    override_b.set_model(Some(model.clone()));
    override_b.effects = vec![
        EffectRecord::new(AddressSpace::Register, 0x30, 8, EffectType::Unaffected),
    ];
    override_b
        .decode_effect(&model.effectlist)
        .expect("exact override B must merge");
    override_a.copy_from(&override_b);

    let lookup_records = vec![EffectRecord::new(
        AddressSpace::Register,
        0x10,
        8,
        EffectType::Unaffected,
    )];
    let before_first_overlap = lookup_record_code(ProtoModelFull::lookup_record(
        &lookup_records,
        1,
        AddressSpace::Register,
        0x08,
        16,
    ));
    let before_first_disjoint = lookup_record_code(ProtoModelFull::lookup_record(
        &lookup_records,
        1,
        AddressSpace::Register,
        0x00,
        8,
    ));

    let mut sticky = FuncProto::new(String::new(), void_type.clone());
    sticky.set_model(Some(model));
    let initial = (
        sticky.get_extra_pop(),
        sticky.has_thisptr(),
        sticky.is_constructor_flag(),
        sticky.is_auto_killed_by_call(),
    );
    sticky.set_model(Some(unknown_model.clone()));
    let switched = (
        sticky.get_extra_pop(),
        sticky.has_thisptr(),
        sticky.is_constructor_flag(),
        sticky.is_auto_killed_by_call(),
    );
    sticky.set_model(Some(replacement_model));
    let replaced = (
        sticky.get_extra_pop(),
        sticky.has_thisptr(),
        sticky.is_constructor_flag(),
        sticky.is_auto_killed_by_call(),
    );
    sticky.set_model(None);
    let mut null_model_print = String::new();
    sticky.print_raw("fixture", &mut null_model_print);
    let null_print_has_no_model = null_model_print.starts_with("(no model) ");

    let mut output_locked = FuncProto::new(String::new(), void_type.clone());
    let output_lock_before = output_locked.is_auto_killed_by_call();
    output_locked.set_output_lock(true);
    let output_lock_after = output_locked.is_auto_killed_by_call();

    let mut copy_hint_source = FuncProto::new(String::new(), void_type.clone());
    copy_hint_source.set_return_bytes_consumed(7);
    let mut copy_hint_destination = FuncProto::new(String::new(), void_type);
    copy_hint_destination.set_return_bytes_consumed(3);
    copy_hint_destination.copy_from(&copy_hint_source);

    let mut out = String::from(
        "{\"schema\":1,\"fixture\":\"PROTO-EFFECT-MODEL-0001\",\"model_effects\":",
    );
    write_effects(&mut out, &model_proto);
    out.push_str(",\"effective_model_records\":");
    write_effective_records(&mut out, &model_proto);
    out.push_str(",\"model_identity\":{\"copy\":");
    out.push(if model_proto.shares_model_with(&model_copy) { '1' } else { '0' });
    out.push_str(",\"independent_same_definition\":");
    out.push(if model_proto.shares_model_with(&independent_proto) { '1' } else { '0' });
    out.push_str("},\"override_a_copy\":");
    write_effects(&mut out, &override_a_copy);
    out.push_str(",\"effective_override_records\":");
    write_effective_records(&mut out, &override_a_copy);
    out.push_str(",\"override_a_after_reassign\":");
    write_effects(&mut out, &override_a);
    out.push_str(",\"lookup_record_before_first\":{\"overlap\":");
    out.push_str(&before_first_overlap.to_string());
    out.push_str(",\"disjoint\":");
    out.push_str(&before_first_disjoint.to_string());
    out.push('}');
    out.push_str(",\"set_model\":{\"initial\":{\"extrapop\":");
    out.push_str(&initial.0.to_string());
    out.push_str(",\"has_this\":");
    out.push(if initial.1 { '1' } else { '0' });
    out.push_str(",\"constructor\":");
    out.push(if initial.2 { '1' } else { '0' });
    out.push_str(",\"auto_killed\":");
    out.push(if initial.3 { '1' } else { '0' });
    out.push_str("},\"unknown_switch\":{\"extrapop\":");
    out.push_str(&switched.0.to_string());
    out.push_str(",\"has_this\":");
    out.push(if switched.1 { '1' } else { '0' });
    out.push_str(",\"constructor\":");
    out.push(if switched.2 { '1' } else { '0' });
    out.push_str(",\"auto_killed\":");
    out.push(if switched.3 { '1' } else { '0' });
    out.push_str("},\"known_switch\":{\"extrapop\":");
    out.push_str(&replaced.0.to_string());
    out.push_str(",\"has_this\":");
    out.push(if replaced.1 { '1' } else { '0' });
    out.push_str(",\"constructor\":");
    out.push(if replaced.2 { '1' } else { '0' });
    out.push_str(",\"auto_killed\":");
    out.push(if replaced.3 { '1' } else { '0' });
    out.push_str("},\"null_switch\":{\"has_model\":");
    out.push(if sticky.has_model() { '1' } else { '0' });
    out.push_str(",\"extrapop\":");
    out.push_str(&sticky.get_extra_pop().to_string());
    out.push_str(",\"has_this\":");
    out.push(if sticky.has_thisptr() { '1' } else { '0' });
    out.push_str(",\"constructor\":");
    out.push(if sticky.is_constructor_flag() { '1' } else { '0' });
    out.push_str(",\"auto_killed\":");
    out.push(if sticky.is_auto_killed_by_call() { '1' } else { '0' });
    out.push_str(",\"print_has_no_model\":");
    out.push(if null_print_has_no_model { '1' } else { '0' });
    out.push_str("}},\"output_lock_auto_killed\":{\"before\":");
    out.push(if output_lock_before { '1' } else { '0' });
    out.push_str(",\"after\":");
    out.push(if output_lock_after { '1' } else { '0' });
    out.push_str("},\"copy_preserves_destination_return_bytes\":");
    out.push_str(&copy_hint_destination.get_return_bytes_consumed().to_string());
    out.push_str("}\n");
    print!("{out}");
}
