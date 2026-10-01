//! Rust consumer counterpart of the locked Ghidra 12.0.4
//! `flow_sharedreturn_process_1204.cc` fixture.
//!
//! The runner supplies the exact `.text` bytes and section address from the
//! pinned curl ELF. A direct single-instruction lift observes Arc identity,
//! immutable SeqNum time, and dead-list insertion order around
//! `Funcdata::override_flow`. A fresh `FlowInfo` then observes the production
//! query/lift/rewrite/xref path through block generation.

use rugra::address::Address;
use rugra::disasm::sleigh_lift::SleighLifter;
use rugra::flow::{flow_flags, FlowInfo};
use rugra::funcdata::Funcdata;
use rugra::op::PcodeOpRef;
use rugra::opcodes::OpCode;
use rugra::override_rs::FlowOverride;
use std::env;
use std::error::Error;
use std::fs;
use std::sync::Arc;

#[derive(Clone, Copy)]
struct Probe {
    name: &'static str,
    function_address: u64,
    function_size: usize,
    site: u64,
    map_address: u64,
    map_type: FlowOverride,
}

const PROBES: [Probe; 3] = [
    Probe {
        name: "hugehelp",
        function_address: 0x4a00,
        function_size: 84,
        site: 0x4a4f,
        map_address: 0x4a4f,
        map_type: FlowOverride::CallReturn,
    },
    Probe {
        name: "progressbarinit",
        function_address: 0x49a0,
        function_size: 94,
        site: 0x49e7,
        map_address: 0x49e7,
        map_type: FlowOverride::CallReturn,
    },
    Probe {
        name: "myprogress",
        function_address: 0x34d0,
        function_size: 497,
        site: 0x365e,
        map_address: 0x4a4f,
        map_type: FlowOverride::CallReturn,
    },
];

fn parse_u64(value: &str) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_str_radix(
        value.strip_prefix("0x").unwrap_or(value),
        16,
    )?)
}

fn opcode_token(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_BRANCH => "branch",
        OpCode::CPUI_CALL => "call",
        OpCode::CPUI_RETURN => "return",
        _ => "other",
    }
}

fn override_token(flow_type: FlowOverride) -> &'static str {
    match flow_type {
        FlowOverride::CallReturn => "callreturn",
        FlowOverride::Call => "call",
        FlowOverride::Branch => "branch",
        FlowOverride::Return => "return",
        FlowOverride::None => "none",
    }
}

fn find_site_op(fd: &Funcdata, site: u64, opcode: OpCode) -> Option<PcodeOpRef> {
    fd.obank
        .optree
        .iter()
        .find(|op| {
            let op = op.0.read().expect("op read lock");
            op.get_addr().as_u64() == site && op.opcode == opcode
        })
        .cloned()
}

fn dead_index(fd: &Funcdata, needle: &PcodeOpRef) -> Option<usize> {
    fd.obank
        .iter_dead()
        .position(|op| Arc::ptr_eq(&op.0, &needle.0))
}

fn is_synthetic_return(op: Option<&PcodeOpRef>) -> bool {
    let Some(op) = op else {
        return false;
    };
    let op = op.0.read().expect("return op read lock");
    if op.opcode != OpCode::CPUI_RETURN || op.num_input() != 1 {
        return false;
    }
    let Some(input) = op.get_in(0) else {
        return false;
    };
    let input = input.read().expect("return input read lock");
    input.is_constant() && input.size == 1 && input.get_offset() == 0
}

struct DirectObservation {
    raw_opcode: OpCode,
    site_space: &'static str,
    raw_time: u32,
    raw_dead_index: i32,
    raw_target: u64,
    query: FlowOverride,
    after_opcode: OpCode,
    same_identity: bool,
    same_seq: bool,
    after_dead_index: i32,
    has_synthetic: bool,
    synthetic_time: u32,
    synthetic_dead_index: i32,
    synthetic_constant: bool,
    adjacent: bool,
}

fn observe_direct(
    image: &[u8],
    image_base: u64,
    probe: Probe,
) -> Result<DirectObservation, Box<dyn Error>> {
    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(image, image_base)?;
    let mut fd = Funcdata::new(
        probe.name,
        Address::new(probe.function_address),
        probe.function_size as i32,
    );
    fd.localoverride
        .insert_flow_override(Address::new(probe.map_address), probe.map_type);

    let (_, raw_ops) = lifter.lift_instruction(probe.site)?;
    fd.inject_raw_ops_single(&raw_ops, Address::new(probe.site));
    let raw = find_site_op(&fd, probe.site, OpCode::CPUI_BRANCH)
        .ok_or("direct lane lacks external BRANCH")?;
    let (raw_time, raw_address, raw_target) = {
        let raw_op = raw.0.read().expect("raw op read lock");
        let input = raw_op.get_in(0).ok_or("raw BRANCH lacks input(0)")?;
        let input = input.read().expect("raw target read lock");
        if input.is_constant() {
            return Err("direct lane BRANCH target is unexpectedly constant".into());
        }
        (raw_op.get_time(), raw_op.get_addr(), input.get_offset())
    };
    let raw_dead_index = dead_index(&fd, &raw).ok_or("raw op is not dead")?;
    let query = fd.localoverride.get_flow_override(Address::new(probe.site));
    if query != FlowOverride::None {
        fd.override_flow(Address::new(probe.site), query)?;
    }

    let after_opcode = if query == FlowOverride::None {
        OpCode::CPUI_BRANCH
    } else {
        OpCode::CPUI_CALL
    };
    let after =
        find_site_op(&fd, probe.site, after_opcode).ok_or("direct lane lacks rewritten primary")?;
    let after_dead_index = dead_index(&fd, &after).ok_or("rewritten op is not dead")?;
    let synthetic = fd
        .obank
        .deadlist
        .get(after_dead_index + 1)
        .filter(|op| op.0.read().expect("next op read lock").get_addr().as_u64() == probe.site);
    let has_synthetic = is_synthetic_return(synthetic);
    let synthetic_time = synthetic
        .map(|op| op.0.read().expect("return op read lock").get_time())
        .unwrap_or(0);
    let synthetic_dead_index = synthetic
        .and_then(|op| dead_index(&fd, op))
        .map_or(-1, |index| index as i32);
    let (after_time, after_address) = {
        let op = after.0.read().expect("after op read lock");
        (op.get_time(), op.get_addr())
    };

    Ok(DirectObservation {
        raw_opcode: OpCode::CPUI_BRANCH,
        site_space: if raw_address.get_space().is_some() {
            "tagged"
        } else {
            "null"
        },
        raw_time,
        raw_dead_index: raw_dead_index as i32,
        raw_target,
        query,
        after_opcode,
        same_identity: Arc::ptr_eq(&raw.0, &after.0),
        same_seq: raw_time == after_time && raw_address == after_address,
        after_dead_index: after_dead_index as i32,
        has_synthetic,
        synthetic_time,
        synthetic_dead_index,
        synthetic_constant: has_synthetic,
        adjacent: has_synthetic && synthetic_dead_index == after_dead_index as i32 + 1,
    })
}

struct PipelineObservation {
    map_present: bool,
    query: FlowOverride,
    primary_opcode: OpCode,
    primary_time: u32,
    primary_order: i64,
    has_synthetic: bool,
    synthetic_time: u32,
    synthetic_order: i64,
    dead_adjacent: bool,
    same_block: bool,
    callspec: bool,
    callspec_same_op: bool,
    spec_target: bool,
    raw_target_visited: bool,
    out_of_bounds: bool,
    unprocessed_count: usize,
}

fn observe_pipeline(
    image: &[u8],
    image_base: u64,
    probe: Probe,
    raw_target: u64,
) -> Result<PipelineObservation, Box<dyn Error>> {
    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(image, image_base)?;
    let mut fd = Funcdata::new(
        probe.name,
        Address::new(probe.function_address),
        probe.function_size as i32,
    );
    fd.localoverride
        .insert_flow_override(Address::new(probe.map_address), probe.map_type);

    let query = fd.localoverride.get_flow_override(Address::new(probe.site));
    let wanted = if query == FlowOverride::None {
        OpCode::CPUI_BRANCH
    } else {
        OpCode::CPUI_CALL
    };

    let (snapshot, out_of_bounds, raw_target_visited, dead_adjacent) = {
        let mut flow = FlowInfo::new(
            &mut fd,
            &mut lifter,
            probe.function_address,
            probe.function_address + probe.function_size as u64,
        );
        flow.generate_ops(Address::new(probe.function_address))?;
        let raw_snapshot = flow.snapshot();
        let raw_target_visited = raw_snapshot
            .visited
            .iter()
            .any(|visited| visited.address.as_u64() == raw_target);
        let site_ops: Vec<_> = raw_snapshot
            .operations
            .iter()
            .filter(|operation| {
                operation
                    .op
                    .0
                    .read()
                    .expect("snapshot op read lock")
                    .get_addr()
                    .as_u64()
                    == probe.site
            })
            .collect();
        let primary_pos = site_ops.iter().position(|operation| {
            operation.op.0.read().expect("site op read lock").opcode == wanted
        });
        let dead_adjacent = primary_pos.is_some_and(|position| {
            site_ops
                .get(position + 1)
                .is_some_and(|operation| is_synthetic_return(Some(&operation.op)))
        });
        let out_of_bounds = flow.has_out_of_bounds();
        // Match the oracle projection: the negative myprogress lane stops at
        // generateOps because its unrelated 0x36c1 boundary cannot be
        // materialized with the locked Bfd symbol effects. Positive lanes
        // still complete generateBlocks and expose valid SeqNum::order.
        if query != FlowOverride::None {
            flow.generate_blocks()?;
        }
        (
            flow.snapshot(),
            out_of_bounds,
            raw_target_visited,
            dead_adjacent,
        )
    };

    let primary = find_site_op(&fd, probe.site, wanted).ok_or("pipeline lane lacks primary op")?;
    let synthetic = fd.obank.optree.iter().find(|op| {
        let op = op.0.read().expect("pipeline return read lock");
        op.get_addr().as_u64() == probe.site && op.opcode == OpCode::CPUI_RETURN
    });
    let has_synthetic = is_synthetic_return(synthetic);
    let generated_blocks = query != FlowOverride::None;
    let (primary_time, primary_order, primary_parent) = {
        let op = primary.0.read().expect("pipeline primary read lock");
        (
            op.get_time(),
            if generated_blocks {
                op.get_seq_num().get_order() as i64
            } else {
                -1
            },
            op.parent.as_ref().and_then(|parent| parent.upgrade()),
        )
    };
    let (synthetic_time, synthetic_order, synthetic_parent) =
        synthetic.map_or((0, -1, None), |return_op| {
            let op = return_op.0.read().expect("pipeline return read lock");
            (
                op.get_time(),
                if generated_blocks {
                    op.get_seq_num().get_order() as i64
                } else {
                    -1
                },
                op.parent.as_ref().and_then(|parent| parent.upgrade()),
            )
        });
    let same_block = match (primary_parent, synthetic_parent) {
        (Some(primary), Some(synthetic)) => Arc::ptr_eq(&primary, &synthetic),
        _ => false,
    };

    let spec_owner = if wanted == OpCode::CPUI_CALL {
        fd.get_call_specs_of_op(&primary)
    } else {
        None
    };
    let callspec = spec_owner.is_some();
    // Snapshot the non-owning callspec -> op edge under a short guard, then
    // compare the upgraded Arc with the exact primary PcodeOp allocation.
    let (bound_op, spec_entry) = spec_owner.map_or((None, None), |owner| {
        let spec = owner.read().expect("callspec read lock");
        (spec.op.upgrade(), spec.entry_addr)
    });
    let callspec_same_op = bound_op
        .as_ref()
        .is_some_and(|bound| Arc::ptr_eq(bound, &primary.0));
    let spec_target = spec_entry == Some(Address::new(raw_target));

    Ok(PipelineObservation {
        map_present: fd.localoverride.has_flow_override(),
        query,
        primary_opcode: wanted,
        primary_time,
        primary_order,
        has_synthetic,
        synthetic_time,
        synthetic_order,
        dead_adjacent,
        same_block,
        callspec,
        callspec_same_op,
        spec_target,
        raw_target_visited,
        out_of_bounds,
        unprocessed_count: snapshot.unprocessed_count,
    })
}

fn print_observation(probe: Probe, direct: &DirectObservation, pipeline: &PipelineObservation) {
    println!(
        "case={} site_delta={} site_space={}",
        probe.name,
        probe.site as i64 - probe.function_address as i64,
        direct.site_space
    );
    println!(
        "direct raw={} raw_time={} raw_dead={} target_delta={} query={} after={} same_identity={} same_seq={} after_dead={} synthetic={} synthetic_time={} synthetic_dead={} const1_0={} adjacent={}",
        opcode_token(direct.raw_opcode),
        direct.raw_time,
        direct.raw_dead_index,
        direct.raw_target as i64 - probe.function_address as i64,
        override_token(direct.query),
        opcode_token(direct.after_opcode),
        usize::from(direct.same_identity),
        usize::from(direct.same_seq),
        direct.after_dead_index,
        usize::from(direct.has_synthetic),
        if direct.has_synthetic { direct.synthetic_time as i64 } else { -1 },
        direct.synthetic_dead_index,
        usize::from(direct.synthetic_constant),
        usize::from(direct.adjacent),
    );
    let callspec_binding = if pipeline.callspec {
        format!(
            "callspec_binding=pointer_identity callspec_same_op={}",
            usize::from(pipeline.callspec_same_op)
        )
    } else {
        "callspec_binding=none binding_resolves=0".to_string()
    };
    println!(
        "pipeline map={} query={} primary={} primary_time={} primary_order={} synthetic={} synthetic_time={} synthetic_order={} dead_adjacent={} same_block={} callspec={} {} spec_target={} target_visited={} oob={} unprocessed={}",
        usize::from(pipeline.map_present),
        override_token(pipeline.query),
        opcode_token(pipeline.primary_opcode),
        pipeline.primary_time,
        pipeline.primary_order,
        usize::from(pipeline.has_synthetic),
        if pipeline.has_synthetic { pipeline.synthetic_time as i64 } else { -1 },
        pipeline.synthetic_order,
        usize::from(pipeline.dead_adjacent),
        usize::from(pipeline.same_block),
        usize::from(pipeline.callspec),
        callspec_binding,
        usize::from(pipeline.spec_target),
        usize::from(pipeline.raw_target_visited),
        usize::from(pipeline.out_of_bounds),
        pipeline.unprocessed_count,
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: flow_sharedreturn_process_1204 CURL_TEXT TEXT_BASE".into());
    }
    let image = fs::read(&args[1])?;
    let image_base = parse_u64(&args[2])?;
    for probe in PROBES {
        let direct = observe_direct(&image, image_base, probe)?;
        let pipeline = observe_pipeline(&image, image_base, probe, direct.raw_target)?;
        print_observation(probe, &direct, &pipeline);
    }
    // Keep the imported flag constant live in this external fixture so a
    // bit-number drift is caught at compile time by the same source snapshot.
    let _ = flow_flags::OUTOFBOUNDS_PRESENT;
    Ok(())
}
