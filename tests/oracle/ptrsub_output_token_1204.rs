// PTRSUB-OUTPUT-TOKEN-0001 Rust comparand for the locked Ghidra 12.0.4
// fixture.  The selected raw streams are byte-identical.  The enclosing
// evidence remains MISMATCH because substantial mapped-function branches and
// architecture state are explicitly outside this fixture's observation set.
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::coreaction::{ActionInferTypes, ActionSetCasts};
use rudra::funcdata::Funcdata;
use rudra::op::{op_addl_flags, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::{space_flags, AddrSpace, AddressSpace, SpaceType};
use rudra::type_system::datatype::{Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::typeop::{TypeOp, TypeOpPtrsub};
use rudra::varnode::{op_output_type_local, varnode_flags, Varnode};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<RwLock<Varnode>>;

fn meta_token(meta: TypeMetatype) -> &'static str {
    match meta {
        TypeMetatype::Void => "void",
        TypeMetatype::Pointer => "ptr",
        TypeMetatype::Array => "array",
        TypeMetatype::Struct => "struct",
        TypeMetatype::Spacebase => "spacebase",
        TypeMetatype::Bool => "bool",
        TypeMetatype::Int => "int",
        TypeMetatype::Uint => "uint",
        TypeMetatype::Unknown => "unknown",
        _ => "other",
    }
}

fn type_proj(ct: Option<&Arc<Datatype>>) -> String {
    let Some(ct) = ct else {
        return "null".to_string();
    };
    if let Datatype::Pointer(pointer) = ct.as_ref() {
        return format!(
            "ptr{}w{}->{}",
            pointer.base.size,
            pointer.wordsize,
            type_proj(Some(&pointer.ptr_to))
        );
    }
    format!("{}{}", meta_token(ct.get_metatype()), ct.get_size())
}

fn factory_core_state(factory: &TypeFactory) -> String {
    let mut dependent_order = Vec::new();
    factory.dependent_order(&mut dependent_order);
    let order = dependent_order
        .iter()
        .map(|datatype| datatype.get_name())
        .collect::<Vec<_>>()
        .join(",");
    let inventory = [
        "xunknown1",
        "xunknown2",
        "xunknown4",
        "xunknown8",
        "int4",
        "int8",
    ]
    .iter()
    .map(|name| {
        let datatype = factory.find_by_name(name).expect("locked core type");
        format!(
            "{}:{}:{}:0x{:x}:{}:{}:0x{:x}:cache{}",
            datatype.get_name(),
            datatype.get_size(),
            meta_token(datatype.get_metatype()),
            datatype.get_id(),
            datatype.get_alignment(),
            datatype.get_align_size(),
            datatype.get_flags(),
            u8::from(Arc::ptr_eq(
                &datatype,
                &factory
                    .get_base(datatype.get_size(), datatype.get_metatype())
                    .expect("cached locked core type"),
            )),
        )
    })
    .collect::<Vec<_>>()
    .join(",");
    let alignments = (0..=8)
        .map(|size| {
            factory
                .get_alignment(size)
                .expect("locked default alignment map")
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "count:{};order:{};sizes:{},{},{},{},{},{};align:{};types:{}",
        dependent_order.len(),
        order,
        factory.get_size_of_int(),
        factory.get_size_of_long(),
        factory.get_size_of_char(),
        factory.get_size_of_wchar(),
        factory.get_size_of_pointer(),
        factory.get_size_of_alt_pointer(),
        alignments,
        inventory,
    )
}

fn op_token(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_PTRSUB => "ptrsub",
        OpCode::CPUI_CAST => "cast",
        _ => "other",
    }
}

fn print_scale(name: &str, value: u64, wordsize: u32) {
    println!(
        "scale|case={name}|val=0x{value:x}|ws={wordsize}|result=0x{:x}",
        AddrSpace::address_to_byte(value, wordsize)
    );
}

fn fixture_struct(
    name: &str,
    size: usize,
    alignment: usize,
    fields: Vec<TypeField>,
) -> Arc<Datatype> {
    let mut base = TypeBase::new(name.to_string(), size, TypeMetatype::Struct);
    base.alignment = alignment as i32;
    base.align_size = size;
    Arc::new(Datatype::Struct(TypeStruct { base, fields }))
}

fn ram_space() -> AddrSpace {
    AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        3,
        space_flags::HASPHYSICAL,
        0,
        0,
    )
}

fn set_block_range(block: &BlockRef, ram: &AddrSpace, first: u64, last: u64) {
    block
        .write()
        .unwrap()
        .as_any_mut()
        .downcast_mut::<BlockBasic>()
        .expect("fixture basic block")
        .set_initial_range(
            Address::with_space(ram, first),
            Address::with_space(ram, last),
        );
}

fn make_fd(
    name: &str,
    base: u64,
    size: i32,
    ram: &AddrSpace,
    factory: &Arc<RwLock<TypeFactory>>,
    architecture: &Arc<Architecture>,
) -> Funcdata {
    let mut fd = Funcdata::new(name, Address::with_space(ram, base), size);
    fd.vbank.set_type_factory(factory.clone());
    fd.set_arch(architecture.clone());
    fd
}

fn typed_input(fd: &mut Funcdata, offset: u64, datatype: Arc<Datatype>) -> VnRef {
    let vn = fd
        .vbank
        .create_with_space(8, AddressSpace::Register, offset);
    let vn = fd.set_input_varnode(vn);
    vn.write().unwrap().update_type_lock(datatype, true, false);
    vn
}

fn make_ptrsub(
    fd: &mut Funcdata,
    block: &BlockRef,
    base: &VnRef,
    raw_offset: u64,
    pc: u64,
    out_type: Arc<Datatype>,
) -> PcodeOpRef {
    let ram = fd
        .baseaddr
        .get_space()
        .expect("fixture function address must carry ram space");
    let op = fd.new_op(2, Address::with_space(&ram, pc));
    fd.op_set_opcode(&op, OpCode::CPUI_PTRSUB);
    fd.op_set_input(&op, base.clone(), 0);
    let offset = fd.new_constant(8, raw_offset);
    fd.op_set_input(&op, offset, 1);
    let out = fd.new_unique_out(8, &op);
    out.write().unwrap().update_type(out_type);
    fd.op_insert_end(&op, block);
    op
}

fn option_identity(actual: Option<&Arc<Datatype>>, expected: Option<&Arc<Datatype>>) -> bool {
    match (actual, expected) {
        (Some(actual), Some(expected)) => Arc::ptr_eq(actual, expected),
        (None, None) => true,
        _ => false,
    }
}

struct DirectCase {
    name: &'static str,
    op: PcodeOpRef,
    expected_token: Arc<Datatype>,
    expected_pointee: Option<Arc<Datatype>>,
}

fn run_direct(
    architecture: &Arc<Architecture>,
    factory: &Arc<RwLock<TypeFactory>>,
    ram: &AddrSpace,
    progress: Arc<Datatype>,
    outer: Arc<Datatype>,
    int8_type: Arc<Datatype>,
    int4_type: Arc<Datatype>,
    factory_state: &str,
) {
    let mut fd = make_fd(
        "ptrsub_token_direct",
        0x5000,
        0x40,
        ram,
        factory,
        architecture,
    );
    let block = fd.create_new_block();
    set_block_range(&block, ram, 0x5000, 0x5010);

    // Preserve the relevant C++ TypeFactory request order.  Ghidra makes one
    // redundant second int4 lookup that does not change factory state.
    let (
        progress_ptr,
        progress_ptr_w2,
        outer_ptr,
        unknown1,
        unknown_ptr_w1,
        unknown_ptr_w2,
        field_ptr_w1,
        field_ptr_w2,
        field4_ptr_w1,
        scalar_ptr_w1,
    ) = {
        let mut factory = factory.write().unwrap();
        let progress_ptr = factory.get_type_pointer(8, progress.clone(), 1);
        let progress_ptr_w2 = factory.get_type_pointer(8, progress, 2);
        let outer_ptr = factory.get_type_pointer(8, outer, 1);
        let unknown1 = factory
            .get_base(1, TypeMetatype::Unknown)
            .expect("canonical unknown1");
        let unknown_ptr_w1 = factory.get_type_pointer(8, unknown1.clone(), 1);
        let unknown_ptr_w2 = factory.get_type_pointer(8, unknown1.clone(), 2);
        let field_ptr_w1 = factory.get_type_pointer(8, int8_type.clone(), 1);
        let field_ptr_w2 = factory.get_type_pointer(8, int8_type.clone(), 2);
        let field4_ptr_w1 = factory.get_type_pointer(8, int4_type.clone(), 1);
        let scalar_ptr_w1 = factory.get_type_pointer(8, int8_type.clone(), 1);
        (
            progress_ptr,
            progress_ptr_w2,
            outer_ptr,
            unknown1,
            unknown_ptr_w1,
            unknown_ptr_w2,
            field_ptr_w1,
            field_ptr_w2,
            field4_ptr_w1,
            scalar_ptr_w1,
        )
    };

    let progress_in = typed_input(&mut fd, 0x100, progress_ptr);
    let progress_in_w2 = typed_input(&mut fd, 0x108, progress_ptr_w2);
    let outer_in = typed_input(&mut fd, 0x110, outer_ptr);
    let integer_in = typed_input(&mut fd, 0x118, int8_type.clone());
    let scalar_in = typed_input(&mut fd, 0x120, scalar_ptr_w1);

    let cases = vec![
        DirectCase {
            name: "exact0",
            op: make_ptrsub(&mut fd, &block, &progress_in, 0, 0x5000, int8_type.clone()),
            expected_token: field_ptr_w1.clone(),
            expected_pointee: Some(int8_type.clone()),
        },
        DirectCase {
            name: "exact8",
            op: make_ptrsub(&mut fd, &block, &progress_in, 8, 0x5001, int8_type.clone()),
            expected_token: field_ptr_w1,
            expected_pointee: Some(int8_type.clone()),
        },
        DirectCase {
            name: "inside12",
            op: make_ptrsub(&mut fd, &block, &progress_in, 12, 0x5002, int8_type.clone()),
            expected_token: unknown_ptr_w1.clone(),
            expected_pointee: Some(unknown1.clone()),
        },
        DirectCase {
            name: "nested12",
            op: make_ptrsub(&mut fd, &block, &outer_in, 12, 0x5003, int8_type.clone()),
            expected_token: unknown_ptr_w1.clone(),
            expected_pointee: Some(unknown1.clone()),
        },
        DirectCase {
            name: "hole28",
            op: make_ptrsub(&mut fd, &block, &progress_in, 28, 0x5004, int8_type.clone()),
            expected_token: unknown_ptr_w1.clone(),
            expected_pointee: Some(unknown1.clone()),
        },
        DirectCase {
            name: "size32",
            op: make_ptrsub(&mut fd, &block, &progress_in, 32, 0x5005, int8_type.clone()),
            expected_token: unknown_ptr_w1.clone(),
            expected_pointee: Some(unknown1.clone()),
        },
        DirectCase {
            name: "negative1",
            op: make_ptrsub(
                &mut fd,
                &block,
                &progress_in,
                u64::MAX,
                0x5006,
                int8_type.clone(),
            ),
            expected_token: unknown_ptr_w1.clone(),
            expected_pointee: Some(unknown1.clone()),
        },
        DirectCase {
            name: "wordsize2",
            op: make_ptrsub(
                &mut fd,
                &block,
                &progress_in_w2,
                4,
                0x5007,
                int8_type.clone(),
            ),
            expected_token: field_ptr_w2.clone(),
            expected_pointee: Some(int8_type.clone()),
        },
        DirectCase {
            name: "wordsize2_inside",
            op: make_ptrsub(
                &mut fd,
                &block,
                &progress_in_w2,
                6,
                0x5008,
                int8_type.clone(),
            ),
            expected_token: unknown_ptr_w2,
            expected_pointee: Some(unknown1.clone()),
        },
        DirectCase {
            name: "wordsize2_wrap",
            op: make_ptrsub(
                &mut fd,
                &block,
                &progress_in_w2,
                1_u64 << 63,
                0x5009,
                int8_type.clone(),
            ),
            expected_token: field_ptr_w2.clone(),
            expected_pointee: Some(int8_type.clone()),
        },
        DirectCase {
            name: "wordsize2_wrap_nonzero",
            op: make_ptrsub(
                &mut fd,
                &block,
                &progress_in_w2,
                (1_u64 << 63) + 4,
                0x500a,
                int8_type.clone(),
            ),
            expected_token: field_ptr_w2,
            expected_pointee: Some(int8_type.clone()),
        },
        DirectCase {
            name: "exact24",
            op: make_ptrsub(&mut fd, &block, &progress_in, 24, 0x500b, int8_type.clone()),
            expected_token: field4_ptr_w1,
            expected_pointee: Some(int4_type),
        },
        DirectCase {
            name: "scalar0",
            op: make_ptrsub(&mut fd, &block, &scalar_in, 0, 0x500c, int8_type.clone()),
            expected_token: unknown_ptr_w1,
            expected_pointee: Some(unknown1),
        },
        DirectCase {
            name: "nonpointer",
            op: make_ptrsub(&mut fd, &block, &integer_in, 8, 0x500d, int8_type.clone()),
            expected_token: int8_type.clone(),
            expected_pointee: None,
        },
    ];

    fd.set_high_level();
    let ptrsub = TypeOpPtrsub::new(factory.clone());
    for (index, item) in cases.into_iter().enumerate() {
        let (token, repeat, local) = {
            let op = item.op.0.read().unwrap();
            let direct_local = ptrsub
                .get_output_local(&op)
                .expect("direct PTRSUB output local");
            let dispatched_local = op_output_type_local(&op, &factory, None)
                .expect("PcodeOp PTRSUB output local dispatch");
            assert!(
                Arc::ptr_eq(&direct_local, &dispatched_local),
                "PTRSUB direct/dispatch local identity diverged for {}",
                item.name
            );
            (
                ptrsub.get_output_token(&op).expect("PTRSUB output token"),
                ptrsub
                    .get_output_token(&op)
                    .expect("repeat PTRSUB output token"),
                dispatched_local,
            )
        };
        let pointee = match token.as_ref() {
            Datatype::Pointer(pointer) => Some(pointer.ptr_to.clone()),
            _ => None,
        };

        let factory_field = if index == 0 {
            format!("|factory_core={factory_state}")
        } else {
            String::new()
        };
        println!(
            "direct|case={}|token={}|token_identity={}|pointee_present={}|pointee_identity={}|repeat_identity={}|local={}|local_identity={}|local_core={}{}",
            item.name,
            type_proj(Some(&token)),
            u8::from(Arc::ptr_eq(&token, &item.expected_token)),
            u8::from(pointee.is_some()),
            u8::from(option_identity(
                pointee.as_ref(),
                item.expected_pointee.as_ref()
            )),
            u8::from(Arc::ptr_eq(&repeat, &token)),
            type_proj(Some(&local)),
            u8::from(Arc::ptr_eq(&local, &int8_type)),
            u8::from(local.is_coretype()),
            factory_field,
        );
    }
}

fn block_ops(block: &BlockRef) -> String {
    let operations = block.read().unwrap().get_ops();
    let body = operations
        .iter()
        .map(|op| {
            let op = op.0.read().unwrap();
            format!("{}@{:x}", op_token(op.opcode), op.get_addr().as_u64())
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn varnode_type(vn: &VnRef) -> Arc<Datatype> {
    vn.read().unwrap().get_type().expect("fixture varnode type")
}

fn run_action(
    architecture: &Arc<Architecture>,
    factory: &Arc<RwLock<TypeFactory>>,
    ram: &AddrSpace,
    progress: Arc<Datatype>,
    int8_type: Arc<Datatype>,
) {
    let mut fd = make_fd(
        "ptrsub_castoutput",
        0x6000,
        0x20,
        ram,
        factory,
        architecture,
    );
    let block = fd.create_new_block();
    set_block_range(&block, ram, 0x6000, 0x6002);

    let (progress_ptr, field_ptr, other_ptr) = {
        let mut factory = factory.write().unwrap();
        let progress_ptr = factory.get_type_pointer(8, progress, 1);
        let int4_type = factory
            .get_base(4, TypeMetatype::Int)
            .expect("canonical int4");
        let field_ptr = factory.get_type_pointer(8, int8_type.clone(), 1);
        let other_ptr = factory.get_type_pointer(8, int4_type, 1);
        (progress_ptr, field_ptr, other_ptr)
    };

    let base = typed_input(&mut fd, 0x200, progress_ptr);
    let equal_op = make_ptrsub(&mut fd, &block, &base, 8, 0x6000, field_ptr);
    let mismatch_op = make_ptrsub(&mut fd, &block, &base, 8, 0x6001, other_ptr);
    let equal_out = equal_op
        .0
        .read()
        .unwrap()
        .get_out()
        .expect("equal output")
        .clone();
    let mismatch_out = mismatch_op
        .0
        .read()
        .unwrap()
        .get_out()
        .expect("mismatch output")
        .clone();

    fd.set_high_level();

    let equal_pre_def = equal_out
        .read()
        .unwrap()
        .get_def()
        .expect("equal output definition before apply");
    let mismatch_pre_def = mismatch_out
        .read()
        .unwrap()
        .get_def()
        .expect("mismatch output definition before apply");
    println!(
        "action_pre|case=paired|ops={}|equal_def={}|mismatch_def={}|equal_type={}|mismatch_type={}",
        block_ops(&block),
        op_token(equal_pre_def.read().unwrap().opcode),
        op_token(mismatch_pre_def.read().unwrap().opcode),
        type_proj(Some(&varnode_type(&equal_out))),
        type_proj(Some(&varnode_type(&mismatch_out))),
    );

    let mut action = ActionSetCasts::new();
    let result = action.apply(&mut fd).expect("ActionSetCasts::apply");

    let count_before_delta = action.count;
    let delta_first = action.take_count_delta();
    let count_after_delta = action.count;
    let delta_second = action.take_count_delta();

    let mismatch_def = mismatch_out
        .read()
        .unwrap()
        .get_def()
        .expect("mismatch output cast definition");
    let mid = mismatch_op
        .0
        .read()
        .unwrap()
        .get_out()
        .expect("PTRSUB replacement output")
        .clone();
    let mid_use = mid
        .read()
        .unwrap()
        .lone_descend()
        .expect("single CAST consumer");
    let equal_def = equal_out
        .read()
        .unwrap()
        .get_def()
        .expect("equal output definition");
    let mid_def = mid.read().unwrap().get_def().expect("mid definition");

    let cast_count = block
        .read()
        .unwrap()
        .get_ops()
        .iter()
        .filter(|op| op.0.read().unwrap().opcode == OpCode::CPUI_CAST)
        .count();

    let equal_same = equal_op
        .0
        .read()
        .unwrap()
        .get_out()
        .is_some_and(|out| Arc::ptr_eq(out, &equal_out));
    let mismatch_out_same = mismatch_def
        .read()
        .unwrap()
        .get_out()
        .is_some_and(|out| Arc::ptr_eq(out, &mismatch_out));
    let cast_input_mid = mismatch_def
        .read()
        .unwrap()
        .get_in(0)
        .is_some_and(|input| Arc::ptr_eq(input, &mid));

    println!(
        "action_post|case=paired|result={}|count_before_delta={}|delta_first={}|count_after_delta={}|delta_second={}|ops={}|casts={}|equal_same={}|equal_def={}|mismatch_def={}|mismatch_out_same={}|mid_new={}|mid_def={}|mid_use={}|cast_input_mid={}|mid_implied={}|mid_type={}|final_type={}",
        result,
        count_before_delta,
        delta_first,
        count_after_delta,
        delta_second,
        block_ops(&block),
        cast_count,
        u8::from(equal_same),
        op_token(equal_def.read().unwrap().opcode),
        op_token(mismatch_def.read().unwrap().opcode),
        u8::from(mismatch_out_same),
        u8::from(!Arc::ptr_eq(&mid, &mismatch_out)),
        op_token(mid_def.read().unwrap().opcode),
        if Arc::ptr_eq(&mid_use, &mismatch_def) {
            "cast"
        } else {
            "other"
        },
        u8::from(cast_input_mid),
        u8::from(mid.read().unwrap().is_implied()),
        type_proj(Some(&varnode_type(&mid))),
        type_proj(Some(&varnode_type(&mismatch_out))),
    );
}

fn run_infer_local(
    architecture: &Arc<Architecture>,
    factory: &Arc<RwLock<TypeFactory>>,
    ram: &AddrSpace,
    int8_type: Arc<Datatype>,
) {
    let mut fd = make_fd(
        "ptrsub_spacebase_local",
        0x7000,
        0x10,
        ram,
        factory,
        architecture,
    );
    let block = fd.create_new_block();
    set_block_range(&block, ram, 0x7000, 0x7000);
    let base = fd
        .vbank
        .create_with_space(8, AddressSpace::Register, 0x300);
    let base = fd.set_input_varnode(base);
    base.write().unwrap().set_flags(varnode_flags::SPACEBASE);

    let op = fd.new_op(2, Address::with_space(ram, 0x7000));
    fd.op_set_opcode(&op, OpCode::CPUI_PTRSUB);
    fd.op_set_input(&op, base.clone(), 0);
    let offset = fd.new_constant(8, 8);
    fd.op_set_input(&op, offset, 1);
    let out = fd.new_unique_out(8, &op);
    op.0.write().unwrap().addlflags |= op_addl_flags::STOP_TYPE_PROPAGATION;
    fd.op_insert_end(&op, &block);

    println!(
        "infer_pre|case=spacebase_ptrsub_local|base_spacebase={}|base_type={}|out_type={}|out_stop={}|def_stop={}",
        u8::from(base.read().unwrap().is_spacebase()),
        type_proj(Some(&varnode_type(&base))),
        type_proj(Some(&varnode_type(&out))),
        u8::from(out.read().unwrap().stops_up_propagation()),
        u8::from(op.0.read().unwrap().stops_type_propagation()),
    );

    fd.start_type_recovery();
    let mut action = ActionInferTypes::new();
    action.reset(&mut fd);
    let result = action.apply(&mut fd).expect("ActionInferTypes::apply");
    let out_type = varnode_type(&out);
    let def = out
        .read()
        .unwrap()
        .get_def()
        .expect("PTRSUB output definition");
    println!(
        "infer_post|case=spacebase_ptrsub_local|result={}|base_spacebase={}|base_type={}|out_type={}|out_identity={}|out_stop={}|def={}",
        result,
        u8::from(base.read().unwrap().is_spacebase()),
        type_proj(Some(&varnode_type(&base))),
        type_proj(Some(&out_type)),
        u8::from(Arc::ptr_eq(&out_type, &int8_type)),
        u8::from(out.read().unwrap().stops_up_propagation()),
        op_token(def.read().unwrap().opcode),
    );
}

fn main() {
    println!(
        "schema=1|fixture=PTRSUB-OUTPUT-TOKEN-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    print_scale("normal", 5, 2);
    print_scale("wrap_zero", 1_u64 << 63, 2);
    print_scale("wrap_nonzero", (1_u64 << 63) + 4, 2);
    print_scale("max_product", u64::MAX, u32::MAX);
    print_scale("zero_wordsize", u64::MAX, 0);

    // Mirror FixtureArchitecture's raw TypeFactory -> setupSizes -> ordered
    // setCoreType -> cacheCoreTypes bootstrap exactly.  TypeFactory::new_flavor
    // installs additional Rust standalone core types and is not the same
    // observable prestate as this locked synthetic Ghidra architecture.
    let mut raw_factory = TypeFactory::raw();
    raw_factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });
    for (name, size, metatype) in [
        ("xunknown1", 1, TypeMetatype::Unknown),
        ("xunknown2", 2, TypeMetatype::Unknown),
        ("xunknown4", 4, TypeMetatype::Unknown),
        ("xunknown8", 8, TypeMetatype::Unknown),
        ("int4", 4, TypeMetatype::Int),
        ("int8", 8, TypeMetatype::Int),
    ] {
        raw_factory
            .set_core_type_result(name, size, metatype, false)
            .expect("locked core type bootstrap");
    }
    raw_factory.cache_core_types();
    let factory_bootstrap_state = factory_core_state(&raw_factory);
    let factory = Arc::new(RwLock::new(raw_factory));

    let (int8_type, int4_type) = {
        let factory = factory.read().unwrap();
        (
            factory
                .get_base(8, TypeMetatype::Int)
                .expect("canonical int8"),
            factory
                .get_base(4, TypeMetatype::Int)
                .expect("canonical int4"),
        )
    };

    let progress = fixture_struct(
        "ProgressData",
        32,
        8,
        vec![
            TypeField {
                name: "total".into(),
                offset: 0,
                type_ptr: int8_type.clone(),
            },
            TypeField {
                name: "prev".into(),
                offset: 8,
                type_ptr: int8_type.clone(),
            },
            TypeField {
                name: "point".into(),
                offset: 16,
                type_ptr: int8_type.clone(),
            },
            TypeField {
                name: "width".into(),
                offset: 24,
                type_ptr: int4_type.clone(),
            },
        ],
    );
    let inner = fixture_struct(
        "Inner",
        8,
        4,
        vec![
            TypeField {
                name: "head".into(),
                offset: 0,
                type_ptr: int4_type.clone(),
            },
            TypeField {
                name: "leaf".into(),
                offset: 4,
                type_ptr: int4_type.clone(),
            },
        ],
    );
    let outer = fixture_struct(
        "Outer",
        16,
        8,
        vec![
            TypeField {
                name: "prefix".into(),
                offset: 0,
                type_ptr: int8_type.clone(),
            },
            TypeField {
                name: "inner".into(),
                offset: 8,
                type_ptr: inner,
            },
        ],
    );

    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.max_basetype_size = 10;
    architecture.set_types(factory.clone());
    let architecture = Arc::new(architecture);
    let ram = ram_space();

    run_direct(
        &architecture,
        &factory,
        &ram,
        progress.clone(),
        outer,
        int8_type.clone(),
        int4_type,
        &factory_bootstrap_state,
    );
    run_action(&architecture, &factory, &ram, progress, int8_type.clone());
    run_infer_local(&architecture, &factory, &ram, int8_type);
}
