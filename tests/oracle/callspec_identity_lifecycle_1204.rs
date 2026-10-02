//! Rust counterpart of the locked Ghidra 12.0.4 callspec identity fixture.
//!
//! The C++ side stores qlst owners as raw pointers and embeds an FSPEC-space
//! pointer in CALL input(0).  Rugra stores stable `Arc` owners in qlst and
//! typed `Weak` reverse edges in the operation and annotation.  The printed
//! projection observes identities and owner membership without printing
//! allocation addresses.

use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::flow::FlowInfo;
use rudra::fspec::FuncCallSpecs;
use rudra::funcdata::Funcdata;
use rudra::op::{pcodeop_flags, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use std::env;
use std::error::Error;
use std::sync::{Arc, RwLock, Weak};

type DynBlock = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type CallSpecOwner = Arc<RwLock<FuncCallSpecs>>;

fn parse_address(value: &str) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}

fn make_call(
    fd: &mut Funcdata,
    site: Address,
    entry: Address,
    block: Option<&DynBlock>,
) -> (PcodeOpRef, CallSpecOwner) {
    let prototype = fd.funcp.clone();
    let op = fd.new_op(1, site);
    fd.op_set_opcode(&op, OpCode::CPUI_CALL);
    let code_ref = fd.new_code_ref(entry);
    fd.op_set_input(&op, code_ref, 0);
    let owner = Arc::new(RwLock::new(FuncCallSpecs::new_for_op(&op, prototype)));
    let annotation = fd.new_varnode_call_specs(&owner);
    fd.op_set_input(&op, annotation, 0);
    if let Some(block) = block {
        let index = block.read().expect("block read lock").get_ops().len();
        fd.op_insert(&op, block, Some(index));
    }
    (op, owner)
}

fn owner_ptr(owner: &CallSpecOwner) -> usize {
    Arc::as_ptr(owner) as usize
}

fn label_of(owner: &CallSpecOwner, identities: &[usize; 3]) -> i32 {
    let pointer = owner_ptr(owner);
    identities
        .iter()
        .position(|candidate| *candidate == pointer)
        .map_or(-1, |index| index as i32)
}

fn callspec_labels(fd: &Funcdata, identities: &[usize; 3]) -> String {
    let labels: Vec<_> = fd
        .callspecs
        .iter()
        .map(|owner| label_of(owner, identities).to_string())
        .collect();
    format!("[{}]", labels.join(","))
}

fn annotation_owner(op: &PcodeOpRef) -> Option<CallSpecOwner> {
    let input = op.0.read().expect("op read lock").get_in(0).cloned()?;
    let owner = input.read().expect("annotation read lock").get_call_spec();
    owner
}

fn annotation_weak(op: &PcodeOpRef) -> Option<Weak<RwLock<FuncCallSpecs>>> {
    let input = op.0.read().expect("op read lock").get_in(0).cloned()?;
    let weak = input
        .read()
        .expect("annotation read lock")
        .call_spec
        .clone();
    weak
}

fn flow_state(fd: &mut Funcdata) -> rudra::flow::TruncatedFlowState {
    let mut lifter = SleighLifter::new();
    let flow = FlowInfo::new(fd, &mut lifter, 0, u64::MAX);
    flow.truncated_state()
}

fn run_identity_case(owner_address: u64, callee_address: u64) {
    let site = Address::new(owner_address);
    let entry = Address::new(callee_address);
    let mut fd = Funcdata::new("callspec_identity_owner", site, 1);

    let block0 = fd.create_new_block();
    let block1 = fd.create_new_block();
    block0.write().expect("block0 write lock").set_index(0);
    block1.write().expect("block1 write lock").set_index(1);

    let (call0, spec0) = make_call(&mut fd, site, entry, Some(&block0));
    let (call1, spec1) = make_call(&mut fd, site, entry, Some(&block0));
    let (call2, spec2) = make_call(&mut fd, site, entry, Some(&block1));
    let identities = [owner_ptr(&spec0), owner_ptr(&spec1), owner_ptr(&spec2)];
    let weak0 = Arc::downgrade(&spec0);
    let weak1 = Arc::downgrade(&spec1);
    let weak2 = Arc::downgrade(&spec2);

    // Same reversed qlst order as the C++ fixture.
    fd.add_call_specs_owner(spec2.clone());
    fd.add_call_specs_owner(spec1.clone());
    fd.add_call_specs_owner(spec0.clone());
    drop(spec0);
    drop(spec1);
    drop(spec2);

    let exact = [
        (&call0, identities[0]),
        (&call1, identities[1]),
        (&call2, identities[2]),
    ]
    .map(|(op, expected)| {
        fd.get_call_specs_of_op(op)
            .is_some_and(|owner| owner_ptr(&owner) == expected)
    });
    let address0 = call0.0.read().expect("call0 read lock").get_addr();
    let address1 = call1.0.read().expect("call1 read lock").get_addr();
    println!(
        "case=identity same_addr={} distinct_ops={} distinct_specs={} exact=[{},{},{}] initial_order={}",
        usize::from(address0 == address1),
        usize::from(!Arc::ptr_eq(&call0.0, &call1.0)),
        usize::from(identities[0] != identities[1]),
        usize::from(exact[0]),
        usize::from(exact[1]),
        usize::from(exact[2]),
        callspec_labels(&fd, &identities),
    );

    fd.sort_call_specs();
    let owner_stable = fd.callspecs.len() == 3
        && owner_ptr(&fd.callspecs[0]) == identities[0]
        && owner_ptr(&fd.callspecs[1]) == identities[1]
        && owner_ptr(&fd.callspecs[2]) == identities[2];
    let annotation_stable = annotation_owner(&call0)
        .is_some_and(|owner| owner_ptr(&owner) == identities[0])
        && annotation_owner(&call1).is_some_and(|owner| owner_ptr(&owner) == identities[1])
        && annotation_owner(&call2).is_some_and(|owner| owner_ptr(&owner) == identities[2]);
    let keys = [&call0, &call1, &call2].map(|op| {
        let (parent, order) = {
            let op = op.0.read().expect("call read lock");
            (
                op.parent.as_ref().and_then(Weak::upgrade),
                op.get_seq_num().get_order(),
            )
        };
        let block_index = parent
            .map(|parent| parent.read().expect("parent read lock").get_index())
            .unwrap_or(-1);
        (block_index, order)
    });
    println!(
        "case=sort order={} owner_stable={} annotation_stable={} keys=[{}:{},{}:{},{}:{}]",
        callspec_labels(&fd, &identities),
        usize::from(owner_stable),
        usize::from(annotation_stable),
        keys[0].0,
        keys[0].1,
        keys[1].0,
        keys[1].1,
        keys[2].0,
        keys[2].1,
    );

    let fake = fd.new_op(1, site);
    fd.op_set_opcode(&fake, OpCode::CPUI_CALL);
    let live_annotation = call0
        .0
        .read()
        .expect("call0 read lock")
        .get_in(0)
        .cloned()
        .expect("call0 annotation");
    let live_annotation_offset = live_annotation
        .read()
        .expect("call0 annotation read lock")
        .get_offset();
    let raw = fd.new_constant(std::mem::size_of::<usize>(), live_annotation_offset);
    let same_offset =
        raw.read().expect("raw constant read lock").get_offset() == live_annotation_offset;
    fd.op_set_input(&fake, raw, 0);
    let fake_index = block1.read().expect("block1 read lock").get_ops().len();
    fd.op_insert(&fake, &block1, Some(fake_index));
    println!(
        "case=raw_const same_offset={} resolved={} space=const",
        usize::from(same_offset),
        usize::from(fd.get_call_specs_of_op(&fake).is_some()),
    );
    let real_iop_annotation = fd.new_varnode_iop(&fake);
    let real_iop_exact = fd
        .get_op_from_const(&real_iop_annotation)
        .is_some_and(|resolved| Arc::ptr_eq(&resolved.0, &fake.0));
    println!(
        "case=iop_guard real_iop_exact={} typed_fspec_as_iop={}",
        usize::from(real_iop_exact),
        usize::from(fd.get_op_from_const(&live_annotation).is_some()),
    );

    let deleted_annotation_varnode = call1
        .0
        .read()
        .expect("call1 read lock")
        .get_in(0)
        .cloned()
        .expect("call1 annotation");
    let deleted_annotation = annotation_weak(&call1).expect("typed deleted annotation");
    fd.delete_call_specs(&call1);
    let deleted_expired = deleted_annotation.upgrade().is_none() && weak1.upgrade().is_none();
    let (expired_binding_present, expired_owner_live) = {
        let annotation = deleted_annotation_varnode
            .read()
            .expect("deleted annotation read lock");
        (
            annotation.call_spec.is_some(),
            annotation.get_call_spec().is_some(),
        )
    };
    println!(
        "case=iop_guard_expired binding_present={} owner_live={} typed_fspec_as_iop={}",
        usize::from(expired_binding_present),
        usize::from(expired_owner_live),
        usize::from(fd.get_op_from_const(&deleted_annotation_varnode).is_some()),
    );
    let survivor_exact = fd
        .get_call_specs_of_op(&call2)
        .is_some_and(|owner| owner_ptr(&owner) == identities[2]);
    let shifted_stable = fd.callspecs.len() == 2
        && owner_ptr(&fd.callspecs[1]) == identities[2]
        && weak0
            .upgrade()
            .is_some_and(|owner| owner_ptr(&owner) == identities[0])
        && weak2
            .upgrade()
            .is_some_and(|owner| owner_ptr(&owner) == identities[2]);
    println!(
        "case=delete count={} order={} deleted_annotation_owned={} survivor_exact={} shifted_owner_stable={}",
        fd.callspecs.len(),
        callspec_labels(&fd, &identities),
        usize::from(!deleted_expired),
        usize::from(survivor_exact),
        usize::from(shifted_stable),
    );
}

fn run_clone_case(
    source_address: u64,
    target_address: u64,
    callee_address: u64,
) -> Result<(), Box<dyn Error>> {
    let source_site = Address::new(source_address);
    let mut source = Funcdata::new("callspec_identity_clone_source", source_site, 1);
    let entry_op = source.new_op(0, source_site);
    source.op_set_opcode(&entry_op, OpCode::CPUI_COPY);
    entry_op.0.write().expect("entry op write lock").flags |=
        pcodeop_flags::STARTBASIC | pcodeop_flags::STARTMARK;
    let (old_op, old_owner) =
        make_call(&mut source, source_site, Address::new(callee_address), None);
    old_op.0.write().expect("old call write lock").flags |= pcodeop_flags::STARTMARK;
    let return_op = source.new_op(0, source_site);
    source.op_set_opcode(&return_op, OpCode::CPUI_RETURN);
    return_op.0.write().expect("return op write lock").flags |= pcodeop_flags::STARTMARK;
    {
        let mut old = old_owner.write().expect("old spec write lock");
        old.set_spacebase_offset(0x3456);
        old.init_active_input();
        old.init_active_output();
        old.active_input
            .as_mut()
            .expect("source active input")
            .register_trial_in_space(AddressSpace::Ram, source_site, 1);
        old.active_output
            .as_mut()
            .expect("source active output")
            .register_trial_in_space(AddressSpace::Ram, source_site, 1);
    }
    source.add_call_specs_owner(old_owner.clone());

    let state = flow_state(&mut source);
    let mut target = Funcdata::new(
        "callspec_identity_clone_target",
        Address::new(target_address),
        1,
    );
    target.truncated_flow(&source, &state)?;

    let new_owner = target.callspecs[0].clone();
    let new_op = new_owner
        .read()
        .expect("new spec read lock")
        .op
        .upgrade()
        .map(PcodeOpRef)
        .ok_or("cloned callspec lost its op")?;
    let old_seq = *old_op.0.read().expect("old op read lock").get_seq_num();
    let new_seq = *new_op.0.read().expect("new op read lock").get_seq_num();
    let seq_equal = old_seq == new_seq;
    let old_annotation_old =
        annotation_owner(&old_op).is_some_and(|owner| Arc::ptr_eq(&owner, &old_owner));
    let new_annotation_new =
        annotation_owner(&new_op).is_some_and(|owner| Arc::ptr_eq(&owner, &new_owner));
    let old_new_isolated = annotation_owner(&old_op)
        .zip(annotation_owner(&new_op))
        .is_some_and(|(old, new)| !Arc::ptr_eq(&old, &new));
    let snapshot_state = |owner: &Arc<RwLock<FuncCallSpecs>>| {
        let spec = owner.read().expect("spec read lock");
        (
            spec.is_input_active(),
            spec.is_output_active(),
            spec.active_input
                .as_ref()
                .map_or(0, |active| active.get_num_trials()),
            spec.active_output
                .as_ref()
                .map_or(0, |active| active.get_num_trials()),
            spec.entry_addr,
            spec.get_spacebase_offset(),
        )
    };
    let old_state = snapshot_state(&old_owner);
    let new_state = snapshot_state(&new_owner);
    println!(
        "case=clone source_count={} target_count={} new_owner={} new_op={} seq_equal={} old_annotation_old={} new_annotation_new={} old_new_isolated={} active_source={}/{} active_target={}/{} trials_source={}/{} trials_target={}/{} entry_same={} stack_same={}",
        source.callspecs.len(),
        target.callspecs.len(),
        usize::from(!Arc::ptr_eq(&old_owner, &new_owner)),
        usize::from(!Arc::ptr_eq(&old_op.0, &new_op.0)),
        usize::from(seq_equal),
        usize::from(old_annotation_old),
        usize::from(new_annotation_new),
        usize::from(old_new_isolated),
        usize::from(old_state.0),
        usize::from(old_state.1),
        usize::from(new_state.0),
        usize::from(new_state.1),
        old_state.2,
        old_state.3,
        new_state.2,
        new_state.3,
        usize::from(old_state.4 == new_state.4),
        usize::from(old_state.5 == new_state.5),
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: callspec_identity_lifecycle_1204 OWNER CLONE_SOURCE CLONE_TARGET CALLEE".into(),
        );
    }
    let owner = parse_address(&args[1])?;
    let clone_source = parse_address(&args[2])?;
    let clone_target = parse_address(&args[3])?;
    let callee = parse_address(&args[4])?;
    run_identity_case(owner, callee);
    run_clone_case(clone_source, clone_target, callee)
}
