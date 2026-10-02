use std::sync::Arc;

use rudra::fspec::FuncProto;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

fn dump(label: &str, proto: &FuncProto) {
    println!(
        "{label}:input={},output={},model={},params={}",
        u8::from(proto.is_input_locked()),
        u8::from(proto.is_output_locked()),
        u8::from(proto.is_model_locked()),
        proto.num_params(),
    );
}

fn main() {
    let void_type = void_type();
    let mut proto = FuncProto::new(String::new(), void_type.clone());
    dump("fresh", &proto);

    proto.set_input_lock(true);
    dump("input_locked", &proto);
    proto.clear_unlocked_input();
    dump("clear_unlocked", &proto);

    let mut copied = FuncProto::new(String::new(), void_type.clone());
    copied.copy_from(&proto);
    dump("copied", &copied);
    copied.clear_input();
    dump("clear_input", &copied);

    let mut output = FuncProto::new(String::new(), void_type);
    output.set_output_lock(true);
    dump("output_locked", &output);
    output.set_output_lock(false);
    dump("output_unlocked", &output);
}
