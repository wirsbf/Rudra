//! Rust twin of `rule_addunsigned_typeprecond_1204.cc`.
//!
//! The covered projection invokes the production RuleAddUnsigned directly on
//! three equivalent IR graphs and emits the same record grammar as the locked
//! Ghidra 12.0.4 fixture. Factory-backed `TYPE_UNKNOWN` must reject, while a
//! canonical `TYPE_UINT` is required before the high-quarter value test.

use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::ruleaction::RuleAddUnsigned;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varnode::{varnode_flags, Varnode};

type VarnodeRef = Arc<RwLock<Varnode>>;
type TypeFactoryRef = Arc<RwLock<TypeFactory>>;

fn meta_token(meta: TypeMetatype) -> &'static str {
    match meta {
        TypeMetatype::Unknown => "unknown",
        TypeMetatype::Uint => "uint",
        _ => "other",
    }
}

fn same_type(left: &Arc<Datatype>, right: &Arc<Datatype>) -> usize {
    usize::from(Arc::ptr_eq(left, right))
}

fn same_symbol(left: &Varnode, right: &Varnode) -> usize {
    match (&left.mapentry, &right.mapentry) {
        (Some(left), Some(right)) => usize::from(Arc::ptr_eq(left, right)),
        (None, None) => 1,
        _ => 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_state(
    case_name: &str,
    stage: &str,
    result: &str,
    fd: &Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    op: &PcodeOpRef,
    input0: &VarnodeRef,
    source: &VarnodeRef,
    output: &VarnodeRef,
    uint_type: &Arc<Datatype>,
) {
    let op_guard = op.0.read().unwrap();
    let current = op_guard.inrefs[1].clone();
    let current_guard = current.read().unwrap();
    let source_guard = source.read().unwrap();
    let input0_guard = input0.read().unwrap();
    let output_guard = output.read().unwrap();
    let current_type = current_guard
        .v_type
        .as_ref()
        .expect("factory-backed current type");
    let source_type = source_guard
        .v_type
        .as_ref()
        .expect("factory-backed source type");
    let output_def_is_op = output_guard
        .get_def()
        .is_some_and(|definition| Arc::ptr_eq(&definition, &op.0));
    let parent_is_block = op_guard
        .parent
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
        .is_some_and(|parent| Arc::ptr_eq(&parent, block));
    let alive_has_op = fd
        .obank
        .iter_alive()
        .any(|candidate| Arc::ptr_eq(&candidate.0, &op.0));

    println!(
        "case={case_name}|stage={stage}|result={result}|opcode={}|slot0_same={}|slot1_is_source={}|new_constant={}|output_same={}|value={}|size={}|constant={}|type_meta={}|type_size={}|type_same_source={}|type_is_factory_uint={}|type_lock={}|name_lock={}|symbol_present={}|symbol_same={}|source_desc={}|current_desc={}|input0_desc={}|output_def_is_op={}|current_def_null={}|alive_count={}|alive_has_op={}|dead_count={}|block_count={}|parent_is_block={}|op_dead={}|source_create={}|current_create={}|input0_create={}|output_create={}",
        op_guard.opcode as i32,
        usize::from(Arc::ptr_eq(&op_guard.inrefs[0], input0)),
        usize::from(Arc::ptr_eq(&current, source)),
        usize::from(!Arc::ptr_eq(&current, source)),
        usize::from(op_guard.output.as_ref().is_some_and(|candidate| Arc::ptr_eq(candidate, output))),
        current_guard.get_offset(),
        current_guard.get_size(),
        usize::from(current_guard.is_constant()),
        meta_token(current_type.get_metatype()),
        current_type.get_size(),
        same_type(current_type, source_type),
        same_type(current_type, uint_type),
        usize::from(current_guard.is_type_lock()),
        usize::from(current_guard.is_name_lock()),
        usize::from(current_guard.mapentry.is_some()),
        same_symbol(&current_guard, &source_guard),
        source_guard.count_descends(),
        current_guard.count_descends(),
        input0_guard.count_descends(),
        usize::from(output_def_is_op),
        usize::from(current_guard.get_def().is_none()),
        fd.obank.alivelist.len(),
        usize::from(alive_has_op),
        fd.obank.deadlist.len(),
        block.read().unwrap().get_ops().len(),
        usize::from(parent_is_block),
        usize::from(op_guard.is_dead()),
        source_guard.get_create_index(),
        current_guard.get_create_index(),
        input0_guard.get_create_index(),
        output_guard.get_create_index(),
    );
}

fn run_case(
    type_factory: &TypeFactoryRef,
    case_name: &str,
    value: u64,
    install_uint: bool,
    lock_type_and_name: bool,
) {
    let mut fd = Funcdata::new("fx", Address::new(0x1000), 0x20);
    fd.vbank.set_type_factory(type_factory.clone());
    let block = fd.create_new_block();
    let input0 = fd.vbank.create_with_space(1, AddressSpace::Register, 0x40);
    let input0 = fd.set_input_varnode(input0);
    let source = fd.new_constant(1, value);
    let uint_type = type_factory
        .read()
        .unwrap()
        .get_base(1, TypeMetatype::Uint)
        .expect("canonical uint1");
    if install_uint {
        source
            .write()
            .unwrap()
            .update_type_lock(uint_type.clone(), lock_type_and_name, false);
    }
    if lock_type_and_name {
        source.write().unwrap().set_flags(varnode_flags::NAMELOCK);
    }

    let op = fd.new_op(2, Address::new(0x2000));
    fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
    let output = fd.new_unique_out(1, &op);
    fd.op_set_input(&op, input0.clone(), 0);
    fd.op_set_input(&op, source.clone(), 1);
    fd.op_insert_end(&op, &block);

    emit_state(
        case_name, "before", "na", &fd, &block, &op, &input0, &source, &output, &uint_type,
    );
    let result = RuleAddUnsigned::new()
        .apply_op(&op.0, &mut fd)
        .expect("RuleAddUnsigned apply");
    emit_state(
        case_name,
        "after",
        &result.to_string(),
        &fd,
        &block,
        &op,
        &input0,
        &source,
        &output,
        &uint_type,
    );
}

fn main() {
    let opcodes = RuleAddUnsigned::new().get_opcodes();
    println!(
        "getoplist:count={},opcode={}",
        opcodes.len(),
        opcodes.first().map_or(-1, |opcode| *opcode as i32),
    );

    // One synthetic Architecture-equivalent factory is shared across all
    // cases. Both source and replacement constants therefore resolve inside
    // the same canonical identity domain, matching `glb->types` in Ghidra.
    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    run_case(&type_factory, "unknown_ff", 0xff, false, false);
    run_case(&type_factory, "uint_ff", 0xff, true, true);
    run_case(&type_factory, "uint_7f", 0x7f, true, false);
}
