// USEROP-LOCALTYPE-METADATA-0001: Rust comparand for the locked Ghidra
// DatatypeUserOp/UserOpManage fixture.  Every Arc comes directly from one
// TypeFactory; ptr_eq is the Rust observation of Ghidra Datatype* identity.

use std::sync::Arc;

use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::userop::{
    DatatypeUserOp, UserOpManage, UserOpType, UserPcodeOp, BUILTIN_MEMCPY, BUILTIN_STRNCPY,
    BUILTIN_WCSNCPY,
};

fn emit_bool(key: &str, value: bool) {
    println!("{key}={}", if value { 1 } else { 0 });
}

fn local_eq(actual: Option<&Arc<Datatype>>, expected: &Arc<Datatype>) -> bool {
    actual.is_some_and(|datatype| Arc::ptr_eq(datatype, expected))
}

fn emit_datatype_builtin(
    manager: &UserOpManage,
    id: u32,
    key: &str,
    expected_out: &Arc<Datatype>,
    expected_in0: &Arc<Datatype>,
    expected_in1: &Arc<Datatype>,
    expected_in2: &Arc<Datatype>,
) {
    let descriptor = manager.get_op(id as i32).expect("typed builtin descriptor");
    println!("{key}.type={}", descriptor.get_type() as i32);
    println!("{key}.index={}", descriptor.get_index());
    emit_bool(
        &format!("{key}.manager_same"),
        std::ptr::eq(
            descriptor,
            manager
                .get_op(id as i32)
                .expect("same typed builtin descriptor"),
        ),
    );
    emit_bool(
        &format!("{key}.out"),
        local_eq(descriptor.get_output_local(), expected_out),
    );
    emit_bool(
        &format!("{key}.slot0_null"),
        descriptor.get_input_local(0).is_none(),
    );
    emit_bool(
        &format!("{key}.slot1"),
        local_eq(descriptor.get_input_local(1), expected_in0),
    );
    emit_bool(
        &format!("{key}.slot2"),
        local_eq(descriptor.get_input_local(2), expected_in1),
    );
    emit_bool(
        &format!("{key}.slot3"),
        local_eq(descriptor.get_input_local(3), expected_in2),
    );
    emit_bool(
        &format!("{key}.slot4_null"),
        descriptor.get_input_local(4).is_none(),
    );
}

fn main() {
    let mut factory = TypeFactory::new(8);
    factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });

    let void_type = factory.get_type_void();
    let void_pointer = factory.get_type_pointer(8, void_type.clone(), 1);
    let int_type = factory
        .get_base(4, TypeMetatype::Int)
        .expect("canonical int type");
    let char_type = factory.get_type_char(factory.get_size_of_char() as usize);
    let char_pointer = factory.get_type_pointer(8, char_type.clone(), 1);
    let wchar_type = factory.get_type_char(factory.get_size_of_wchar() as usize);
    let wchar_pointer = factory.get_type_pointer(8, wchar_type.clone(), 1);

    let mut builtins = UserOpManage::new();
    builtins
        .register_builtin_with_local_types(
            BUILTIN_MEMCPY,
            Some(void_pointer.clone()),
            vec![
                Some(void_pointer.clone()),
                Some(void_pointer.clone()),
                Some(int_type.clone()),
            ],
        )
        .expect("register memcpy");
    emit_datatype_builtin(
        &builtins,
        BUILTIN_MEMCPY,
        "builtin.memcpy",
        &void_pointer,
        &void_pointer,
        &void_pointer,
        &int_type,
    );
    let memcpy_descriptor = builtins
        .get_op(BUILTIN_MEMCPY as i32)
        .expect("memcpy descriptor") as *const UserPcodeOp;
    builtins
        .register_builtin_with_local_types(
            BUILTIN_MEMCPY,
            Some(int_type.clone()),
            vec![Some(int_type.clone())],
        )
        .expect("repeat memcpy");
    emit_bool(
        "builtin.memcpy.repeat_same",
        std::ptr::eq(
            memcpy_descriptor,
            builtins
                .get_op(BUILTIN_MEMCPY as i32)
                .expect("repeated memcpy descriptor") as *const UserPcodeOp,
        ),
    );
    emit_bool(
        "builtin.memcpy.repeat_out",
        local_eq(
            builtins.get_output_local(BUILTIN_MEMCPY as i32),
            &void_pointer,
        ),
    );

    builtins
        .register_builtin_with_local_types(
            BUILTIN_STRNCPY,
            Some(char_pointer.clone()),
            vec![
                Some(char_pointer.clone()),
                Some(char_pointer.clone()),
                Some(int_type.clone()),
            ],
        )
        .expect("register strncpy");
    emit_datatype_builtin(
        &builtins,
        BUILTIN_STRNCPY,
        "builtin.strncpy",
        &char_pointer,
        &char_pointer,
        &char_pointer,
        &int_type,
    );
    builtins
        .register_builtin_with_local_types(
            BUILTIN_WCSNCPY,
            Some(wchar_pointer.clone()),
            vec![
                Some(wchar_pointer.clone()),
                Some(wchar_pointer.clone()),
                Some(int_type.clone()),
            ],
        )
        .expect("register wcsncpy");
    emit_datatype_builtin(
        &builtins,
        BUILTIN_WCSNCPY,
        "builtin.wcsncpy",
        &wchar_pointer,
        &wchar_pointer,
        &wchar_pointer,
        &int_type,
    );
    emit_bool(
        "builtin.memcpy.stable_after_growth",
        std::ptr::eq(
            memcpy_descriptor,
            builtins
                .get_op(BUILTIN_MEMCPY as i32)
                .expect("stable memcpy descriptor") as *const UserPcodeOp,
        ),
    );

    let bad_id = BUILTIN_WCSNCPY + 1;
    let bad_error = builtins
        .try_register_builtin_by_id(bad_id)
        .expect_err("bad builtin id must fail");
    println!("builtin.bad.error={bad_error}");
    emit_bool(
        "builtin.bad.absent",
        builtins.get_op(bad_id as i32).is_none(),
    );
    emit_bool(
        "builtin.memcpy.stable_after_error",
        std::ptr::eq(
            memcpy_descriptor,
            builtins
                .get_op(BUILTIN_MEMCPY as i32)
                .expect("memcpy after error") as *const UserPcodeOp,
        ),
    );

    let mut manager = UserOpManage::new();
    manager
        .register_user_op(UserPcodeOp::new(
            "typed".to_string(),
            UserOpType::Unspecialized,
            2,
        ))
        .expect("register unspecialized typed op");
    emit_bool("custom.gap0_null", manager.get_op(0).is_none());
    emit_bool("custom.gap1_null", manager.get_op(1).is_none());
    emit_bool(
        "custom.base_out_null",
        manager.get_output_local(2).is_none(),
    );
    emit_bool(
        "custom.base_in_null",
        manager.get_input_local(2, 1).is_none(),
    );

    let typed_result = manager.register_datatype_user_op(DatatypeUserOp::new(
        "typed".to_string(),
        2,
        Some(void_pointer.clone()),
        vec![None, Some(char_type.clone()), None, Some(int_type.clone())],
    ));
    println!(
        "custom.typed.error={}",
        typed_result.err().unwrap_or_else(|| "NO_ERROR".to_string())
    );
    let typed = manager.get_op(2).expect("typed descriptor");
    println!("custom.typed.type={}", typed.get_type() as i32);
    emit_bool(
        "custom.by_name_same",
        std::ptr::eq(
            manager.get_op_by_name("typed").expect("typed name lookup"),
            typed,
        ),
    );
    emit_bool(
        "custom.out",
        local_eq(manager.get_output_local(2), &void_pointer),
    );
    emit_bool("custom.slot0_null", manager.get_input_local(2, 0).is_none());
    emit_bool(
        "custom.slot1_compacted",
        local_eq(manager.get_input_local(2, 1), &char_type),
    );
    emit_bool(
        "custom.slot2_compacted",
        local_eq(manager.get_input_local(2, 2), &int_type),
    );
    emit_bool("custom.slot3_null", manager.get_input_local(2, 3).is_none());

    let replace_result = manager.register_datatype_user_op(DatatypeUserOp::new(
        "typed".to_string(),
        2,
        Some(int_type.clone()),
        vec![Some(void_type.clone())],
    ));
    println!(
        "custom.replace.error={}",
        replace_result
            .err()
            .unwrap_or_else(|| "NO_ERROR".to_string())
    );
    emit_bool(
        "custom.replace.out",
        local_eq(manager.get_output_local(2), &int_type),
    );
    emit_bool(
        "custom.replace.slot1",
        local_eq(manager.get_input_local(2, 1), &void_type),
    );
    emit_bool(
        "custom.replace.slot2_null",
        manager.get_input_local(2, 2).is_none(),
    );

    let same_name_error = manager
        .register_datatype_user_op(DatatypeUserOp::new(
            "typed".to_string(),
            3,
            Some(void_type.clone()),
            vec![Some(int_type.clone())],
        ))
        .expect_err("same name at new index must fail");
    println!("custom.same_name_new_index.error={same_name_error}");
    emit_bool(
        "custom.same_name_new_index.gap_preserved",
        manager.get_op(3).is_none(),
    );
    emit_bool(
        "custom.same_name_new_index.old_preserved",
        local_eq(manager.get_output_local(2), &int_type),
    );

    let same_index_error = manager
        .register_datatype_user_op(DatatypeUserOp::new(
            "other".to_string(),
            2,
            Some(void_type.clone()),
            vec![Some(int_type.clone())],
        ))
        .expect_err("new name at same index must fail");
    println!("custom.same_index_new_name.error={same_index_error}");
    emit_bool(
        "custom.same_index_new_name.absent",
        manager.get_op_by_name("other").is_none(),
    );
    emit_bool(
        "custom.same_index_new_name.old_preserved",
        std::ptr::eq(
            manager
                .get_op_by_name("typed")
                .expect("preserved typed name"),
            manager.get_op(2).expect("preserved typed index"),
        ),
    );

    let negative_error = manager
        .register_datatype_user_op(DatatypeUserOp::new(
            "negative".to_string(),
            -1,
            Some(void_type.clone()),
            vec![Some(int_type.clone())],
        ))
        .expect_err("negative index must fail");
    println!("custom.negative.error={negative_error}");
    emit_bool(
        "custom.negative.absent",
        manager.get_op_by_name("negative").is_none(),
    );

    let missing_result = manager.register_datatype_user_op(DatatypeUserOp::new(
        "missing".to_string(),
        4,
        None,
        Vec::new(),
    ));
    println!(
        "custom.missing.error={}",
        missing_result
            .err()
            .unwrap_or_else(|| "NO_ERROR".to_string())
    );
    emit_bool(
        "custom.missing.out_null",
        manager.get_output_local(4).is_none(),
    );
    emit_bool(
        "custom.missing.in_null",
        manager.get_input_local(4, 1).is_none(),
    );
    emit_bool("custom.error_gap_still_null", manager.get_op(3).is_none());
}
