use std::sync::Arc;

use rudra::type_system::datatype::{type_flags, Datatype, TypeMetatype};
use rudra::type_system::typefactory::TypeFactory;

fn write_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out.push('"');
}

fn metatype_name(metatype: TypeMetatype) -> &'static str {
    match metatype {
        TypeMetatype::Unknown => "unknown",
        _ => panic!("fixture received a non-unknown type"),
    }
}

fn write_type(out: &mut String, requested_size: usize, datatype: &Datatype) {
    out.push_str("{\"requested_size\":");
    out.push_str(&requested_size.to_string());
    out.push_str(",\"size\":");
    out.push_str(&datatype.get_size().to_string());
    out.push_str(",\"metatype\":");
    write_json_string(out, metatype_name(datatype.get_metatype()));
    out.push_str(",\"name\":");
    write_json_string(out, datatype.get_name());
    out.push_str(",\"id\":");
    out.push_str(&datatype.get_id().to_string());
    out.push_str(",\"flags\":");
    out.push_str(&(datatype.get_flags() & type_flags::CORETYPE).to_string());
    out.push('}');
}

fn write_anonymous_unknown_order(out: &mut String, factory: &TypeFactory) {
    out.push('[');
    let mut first = true;
    let mut ordered = Vec::new();
    factory.dependent_order(&mut ordered);
    for datatype in ordered {
        if datatype.get_metatype() != TypeMetatype::Unknown || !datatype.get_name().is_empty() {
            continue;
        }
        if !first {
            out.push(',');
        }
        out.push_str(&datatype.get_size().to_string());
        first = false;
    }
    out.push(']');
}

fn main() {
    // The locked oracle drives SleighArchitecture's standalone
    // buildCoreTypes (sleigh_arch.cc:229-232), so the Rust comparand
    // constructs the factory with the same registration flavor.
    let mut factory = TypeFactory::new_flavor(8, rudra::type_system::typefactory::CoreTypeFlavor::Standalone);
    let sizes = [8_usize, 1, 4, 2, 3, 5, 6, 7];
    let first: Vec<Arc<Datatype>> = sizes
        .iter()
        .map(|&size| {
            factory
                .get_base(size, TypeMetatype::Unknown)
                .expect("unknown base type must exist")
        })
        .collect();

    let mut out = String::from(
        "{\"schema\":1,\"fixture\":\"TYPE-UNKNOWN-0001\",\"types\":[",
    );
    for (index, (&size, datatype)) in sizes.iter().zip(first.iter()).enumerate() {
        if index != 0 {
            out.push(',');
        }
        write_type(&mut out, size, datatype);
    }

    out.push_str("],\"identity\":{\"repeat\":[");
    for (index, (&size, datatype)) in sizes.iter().zip(first.iter()).enumerate() {
        if index != 0 {
            out.push(',');
        }
        let repeated = factory
            .get_base(size, TypeMetatype::Unknown)
            .expect("repeated unknown base type must exist");
        out.push(if Arc::ptr_eq(datatype, &repeated) { '1' } else { '0' });
    }

    out.push_str("],\"different_size\":[");
    for (index, datatype) in first.iter().enumerate().skip(1) {
        if index != 1 {
            out.push(',');
        }
        out.push(if Arc::ptr_eq(&first[0], datatype) { '1' } else { '0' });
    }
    out.push_str("]},\"named\":");

    let named = factory
        .get_base_named(3, TypeMetatype::Unknown, "fixture_unknown3")
        .expect("named unknown type must be created");
    write_type(&mut out, 3, &named);
    let repeated_named = factory
        .get_base_named(3, TypeMetatype::Unknown, "fixture_unknown3")
        .expect("named unknown type must be canonical");
    out.push_str(",\"named_repeat\":");
    out.push(if Arc::ptr_eq(&named, &repeated_named) {
        '1'
    } else {
        '0'
    });
    out.push_str(",\"collision_error\":");
    let collision = factory
        .get_base_named(4, TypeMetatype::Unknown, "fixture_unknown3")
        .map(|_| "NONE".to_string())
        .unwrap_or_else(|error| error);
    write_json_string(&mut out, &collision);

    out.push_str(",\"anonymous_order_before_clear\":");
    write_anonymous_unknown_order(&mut out, &factory);

    factory.clear_non_core();
    out.push_str(",\"anonymous_order_after_clear\":");
    write_anonymous_unknown_order(&mut out, &factory);
    let after_clear = factory
        .get_base(3, TypeMetatype::Unknown)
        .expect("unknown base must be recreated after clear");
    out.push_str(",\"clear_identity\":{\"new_repeat\":");
    let after_clear_repeat = factory
        .get_base(3, TypeMetatype::Unknown)
        .expect("recreated unknown base must be canonical");
    out.push(if Arc::ptr_eq(&after_clear, &after_clear_repeat) {
        '1'
    } else {
        '0'
    });
    out.push_str("},\"anonymous_order_after_recreate\":");
    write_anonymous_unknown_order(&mut out, &factory);
    out.push_str("}\n");
    print!("{out}");
}
