use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::disasm::sleigh_lift::{set_sla_path, SleighLifter};
use rudra::flow::{FlowInfo, FlowInfoSnapshot};
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::TypeMetatype;
use rudra::varnode::Varnode;
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::sync::{Arc, RwLock};

const ARCHITECTURE: &str = "x86:LE:64:default";
const COMPILER_SPEC: &str = "gcc";
const LOADED_ARCHID: &str = "x86:LE:64:default:gcc";
const FUNCTION_NAME: &str = "sleigh_flow_relative_probe";
const EXPECTED_IMAGE: [u8; 3] = [0x0f, 0xa2, 0xc3];
const FLOW_FLAGS: u32 = 32;
const MAX_INSTRUCTIONS: u64 = 100_000;

type DynBlock = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character < '\u{20}' || character == '\u{7f}' => {
                write!(&mut escaped, "\\u{:04x}", character as u32).expect("write to String");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn hex_value(value: u64) -> String {
    format!("0x{value:016x}")
}

fn space_fields(space: AddressSpace) -> Result<(u32, u8, &'static str, u32, u32), String> {
    match space {
        AddressSpace::Const => Ok((8, 0, "const", 0, 1)),
        AddressSpace::Other(1) => Ok((8, 1, "OTHER", 1, 1)),
        AddressSpace::Unique => Ok((4, 2, "unique", 3, 1)),
        AddressSpace::Ram => Ok((8, 3, "ram", 1, 1)),
        AddressSpace::Register => Ok((4, 4, "register", 1, 1)),
        other => Err(format!(
            "space {:?} is outside the locked x86 fixture",
            other
        )),
    }
}

fn push_space(output: &mut String, space: AddressSpace) -> Result<(), String> {
    let (addr_size, index, name, type_, word_size) = space_fields(space)?;
    write!(
        output,
        "{{\"addr_size\":{addr_size},\"index\":{index},\"name\":\"{}\",\"type\":{type_},\"word_size\":{word_size}}}",
        json_escape(name),
    )
    .expect("write to String");
    Ok(())
}

fn push_address(output: &mut String, address: Address) -> Result<(), String> {
    write!(
        output,
        "{{\"offset\":\"{}\",\"space\":",
        hex_value(address.as_u64())
    )
    .expect("write to String");
    push_space(output, AddressSpace::Ram)?;
    output.push('}');
    Ok(())
}

fn op_key(op: &PcodeOpRef) -> usize {
    Arc::as_ptr(&op.0) as usize
}

fn varnode_key(varnode: &VarnodeRef) -> usize {
    Arc::as_ptr(varnode) as usize
}

fn op_id(op_ids: &HashMap<usize, usize>, op: &PcodeOpRef) -> Result<usize, String> {
    op_ids
        .get(&op_key(op))
        .copied()
        .ok_or_else(|| "unregistered PcodeOp identity".to_string())
}

fn varnode_id(varnode_ids: &HashMap<usize, usize>, varnode: &VarnodeRef) -> Result<usize, String> {
    varnode_ids
        .get(&varnode_key(varnode))
        .copied()
        .ok_or_else(|| "unregistered Varnode identity".to_string())
}

fn block_ordinal(blocks: &[DynBlock], needle: &DynBlock) -> i32 {
    blocks
        .iter()
        .position(|candidate| Arc::ptr_eq(candidate, needle))
        .map_or(-1, |ordinal| ordinal as i32)
}

fn ghidra_metatype(metatype: TypeMetatype) -> u32 {
    match metatype {
        TypeMetatype::Void => 17,
        TypeMetatype::Spacebase => 16,
        TypeMetatype::Unknown => 15,
        TypeMetatype::Int => 14,
        TypeMetatype::Uint => 13,
        TypeMetatype::Bool => 12,
        TypeMetatype::Code => 11,
        TypeMetatype::Float => 10,
        TypeMetatype::Pointer => 9,
        TypeMetatype::Array => 7,
        TypeMetatype::Enum => 6,
        TypeMetatype::Struct => 4,
        TypeMetatype::Union => 3,
        TypeMetatype::PartialEnum => 2,
        TypeMetatype::PartialStruct => 1,
        TypeMetatype::PartialUnion => 0,
    }
}

fn push_type(output: &mut String, varnode: &Varnode) {
    let Some(datatype) = varnode.v_type.as_ref() else {
        output.push_str("null");
        return;
    };
    write!(
        output,
        "{{\"metatype\":{},\"name\":\"{}\",\"size\":{}}}",
        ghidra_metatype(datatype.get_metatype()),
        json_escape(datatype.get_name()),
        datatype.get_size(),
    )
    .expect("write to String");
}

fn collect_identities(
    snapshot: &FlowInfoSnapshot,
    function: &rudra::funcdata::Funcdata,
) -> (
    Vec<PcodeOpRef>,
    HashMap<usize, usize>,
    Vec<VarnodeRef>,
    HashMap<usize, usize>,
    HashMap<usize, AddressSpace>,
) {
    let ops = snapshot
        .operations
        .iter()
        .map(|operation| operation.op.clone())
        .collect::<Vec<_>>();
    let op_ids = ops
        .iter()
        .enumerate()
        .map(|(identity, op)| (op_key(op), identity))
        .collect::<HashMap<_, _>>();

    let mut varnodes = Vec::new();
    let mut varnode_ids = HashMap::new();
    let mut space_ids = HashMap::new();
    let assign = |varnode: &VarnodeRef,
                  varnodes: &mut Vec<VarnodeRef>,
                  varnode_ids: &mut HashMap<usize, usize>| {
        let key = varnode_key(varnode);
        if varnode_ids.contains_key(&key) {
            return;
        }
        let identity = varnodes.len();
        varnode_ids.insert(key, identity);
        varnodes.push(varnode.clone());
    };

    for op in &ops {
        let op = op.0.read().expect("op read lock");
        if let Some(output) = op.output.as_ref() {
            assign(output, &mut varnodes, &mut varnode_ids);
        }
        for (slot, input) in op.inrefs.iter().enumerate() {
            assign(input, &mut varnodes, &mut varnode_ids);
            if slot == 0 && matches!(op.opcode, OpCode::CPUI_LOAD | OpCode::CPUI_STORE) {
                let input_value = input.read().expect("varnode read lock");
                let target_index = u8::try_from(input_value.get_offset())
                    .expect("normalized LOAD/STORE target-space index must fit u8");
                space_ids.insert(varnode_key(input), AddressSpace::from_id(target_index));
            }
        }
    }
    for location in function.vbank.begin_loc() {
        assign(&location.0, &mut varnodes, &mut varnode_ids);
    }
    (ops, op_ids, varnodes, varnode_ids, space_ids)
}

fn write_header(output: &mut String) {
    writeln!(
        output,
        "{{\"architecture\":\"{ARCHITECTURE}\",\"compiler_spec\":\"{COMPILER_SPEC}\",\"input_hex\":\"0fa2c3\",\"loaded_archid\":\"{LOADED_ARCHID}\",\"record\":\"header\"}}",
    )
    .expect("write to String");
}

fn write_flow_state(
    output: &mut String,
    snapshot: &FlowInfoSnapshot,
    function_size: i32,
) -> Result<(), String> {
    write!(
        output,
        "{{\"addrlist_count\":{},\"baddr\":",
        snapshot.addrlist_count
    )
    .expect("write to String");
    push_address(output, snapshot.baddr)?;
    write!(output, ",\"eaddr\":").expect("write to String");
    push_address(output, snapshot.eaddr)?;
    write!(
        output,
        ",\"flags\":{},\"function_size\":{function_size},\"inject_count\":{},\"instruction_count\":{},\"instruction_max\":{},\"maxaddr\":",
        snapshot.flags,
        snapshot.inject_count,
        snapshot.instruction_count,
        snapshot.instruction_max,
    )
    .expect("write to String");
    push_address(output, snapshot.maxaddr)?;
    write!(output, ",\"minaddr\":").expect("write to String");
    push_address(output, snapshot.minaddr)?;
    writeln!(
        output,
        ",\"phase\":\"post_generate_blocks\",\"record\":\"flow_state\",\"table_count\":{},\"unprocessed_count\":{},\"visited_count\":{}}}",
        snapshot.table_count,
        snapshot.unprocessed_count,
        snapshot.visited.len(),
    )
    .expect("write to String");
    Ok(())
}

fn write_visited(output: &mut String, snapshot: &FlowInfoSnapshot) -> Result<(), String> {
    for visited in &snapshot.visited {
        write!(output, "{{\"address\":").expect("write to String");
        push_address(output, visited.address)?;
        write!(output, ",\"first_seq\":{{\"address\":").expect("write to String");
        push_address(output, visited.first_seq_address)?;
        writeln!(
            output,
            ",\"time\":{}}},\"record\":\"visited\",\"size\":{}}}",
            visited.first_seq_time, visited.size,
        )
        .expect("write to String");
    }
    Ok(())
}

fn write_operations(
    output: &mut String,
    snapshot: &FlowInfoSnapshot,
    blocks: &[DynBlock],
    op_ids: &HashMap<usize, usize>,
    varnode_ids: &HashMap<usize, usize>,
) -> Result<(), String> {
    for operation in &snapshot.operations {
        let op_ref = &operation.op;
        let op = op_ref.0.read().expect("op read lock");
        write!(
            output,
            "{{\"addl_flags\":{},\"flags\":{},\"id\":{},\"inputs\":[",
            op.addlflags,
            op.flags,
            op_id(op_ids, op_ref)?,
        )
        .expect("write to String");
        for (slot, input) in op.inrefs.iter().enumerate() {
            if slot != 0 {
                output.push(',');
            }
            write!(output, "{}", varnode_id(varnode_ids, input)?).expect("write to String");
        }
        write!(
            output,
            "],\"opcode\":{},\"opcode_name\":\"{}\",\"output\":",
            op.opcode as i32,
            op.opcode.name(),
        )
        .expect("write to String");
        match op.output.as_ref() {
            Some(varnode) => {
                write!(output, "{}", varnode_id(varnode_ids, varnode)?).expect("write to String")
            }
            None => output.push_str("null"),
        }
        let parent = op.parent.as_ref().and_then(std::sync::Weak::upgrade);
        let parent_ordinal = parent
            .as_ref()
            .map_or(-1, |parent| block_ordinal(blocks, parent));
        write!(
            output,
            ",\"parent_block\":{parent_ordinal},\"record\":\"op\",\"seq\":{{\"address\":",
        )
        .expect("write to String");
        push_address(output, op.start.addr)?;
        writeln!(
            output,
            ",\"order\":{},\"time\":{}}}}}",
            op.start.order, operation.time,
        )
        .expect("write to String");
    }
    Ok(())
}

fn write_varnodes(
    output: &mut String,
    varnodes: &[VarnodeRef],
    op_ids: &HashMap<usize, usize>,
    varnode_ids: &HashMap<usize, usize>,
    space_ids: &HashMap<usize, AddressSpace>,
) -> Result<(), String> {
    for varnode_ref in varnodes {
        let varnode = varnode_ref.read().expect("varnode read lock");
        let target_space = space_ids.get(&varnode_key(varnode_ref)).copied();
        write!(
            output,
            "{{\"addl_flags\":{},\"consume\":\"{}\",\"cover_present\":{},\"create_index\":{},\"def\":",
            varnode.addlflags,
            hex_value(varnode.consumed),
            varnode.cover.is_some(),
            varnode.create_index,
        )
        .expect("write to String");
        match varnode.def.as_ref().and_then(std::sync::Weak::upgrade) {
            Some(definition) => {
                let definition = PcodeOpRef(definition);
                write!(output, "{}", op_id(op_ids, &definition)?).expect("write to String");
            }
            None => output.push_str("null"),
        }
        output.push_str(",\"descendants\":[");
        let mut first = true;
        for descendant in &varnode.descend {
            let Some(descendant) = descendant.upgrade() else {
                return Err("dangling Varnode descendant".to_string());
            };
            if !first {
                output.push(',');
            }
            first = false;
            let descendant = PcodeOpRef(descendant);
            write!(output, "{}", op_id(op_ids, &descendant)?).expect("write to String");
        }
        write!(
            output,
            "],\"flags\":{},\"high_present\":{},\"id\":{},\"kind\":\"{}\",\"mapentry_present\":{},\"merge_group\":{},\"nzmask\":",
            varnode.flags,
            varnode.high.is_some(),
            varnode_id(varnode_ids, varnode_ref)?,
            if target_space.is_some() { "spaceid" } else { "varnode" },
            varnode.mapentry.is_some(),
            varnode.mergegroup,
        )
        .expect("write to String");
        if target_space.is_some() {
            output.push_str("null,\"offset\":null");
        } else {
            write!(
                output,
                "\"{}\",\"offset\":\"{}\"",
                hex_value(varnode.nzm),
                hex_value(varnode.get_offset()),
            )
            .expect("write to String");
        }
        write!(
            output,
            ",\"record\":\"varnode\",\"size\":{},\"space\":",
            varnode.size,
        )
        .expect("write to String");
        push_space(output, varnode.address_space)?;
        output.push_str(",\"target_space\":");
        match target_space {
            Some(space) => push_space(output, space)?,
            None => output.push_str("null"),
        }
        output.push_str(",\"type\":");
        push_type(output, &varnode);
        output.push_str("}\n");
    }
    Ok(())
}

fn write_relatives(
    output: &mut String,
    snapshot: &FlowInfoSnapshot,
    op_ids: &HashMap<usize, usize>,
) -> Result<(), String> {
    for relative in &snapshot.relatives {
        let offset = relative
            .source
            .0
            .read()
            .expect("op read lock")
            .inrefs
            .first()
            .ok_or_else(|| "relative branch has no input zero".to_string())?
            .read()
            .expect("varnode read lock")
            .get_offset();
        write!(
            output,
            "{{\"computed_target_time\":{},\"kind\":\"{}\",\"offset\":\"{}\",\"record\":\"relative\",\"source\":{},\"target\":",
            relative.computed_target_time,
            if relative.target.is_some() { "internal" } else { "fallthru" },
            hex_value(offset),
            op_id(op_ids, &relative.source)?,
        )
        .expect("write to String");
        match relative.target.as_ref() {
            Some(target) => write!(output, "{}", op_id(op_ids, target)?).expect("write to String"),
            None => output.push_str("null"),
        }
        output.push_str(",\"target_address\":");
        match relative.target_address {
            Some(address) => push_address(output, address)?,
            None => output.push_str("null"),
        }
        output.push_str("}\n");
    }
    Ok(())
}

fn write_raw_edges(
    output: &mut String,
    snapshot: &FlowInfoSnapshot,
    op_ids: &HashMap<usize, usize>,
) -> Result<(), String> {
    for (ordinal, (source, target)) in snapshot.raw_edges.iter().enumerate() {
        writeln!(
            output,
            "{{\"ordinal\":{ordinal},\"record\":\"raw_edge\",\"source\":{},\"target\":{}}}",
            op_id(op_ids, source)?,
            op_id(op_ids, target)?,
        )
        .expect("write to String");
    }
    Ok(())
}

fn write_blocks(
    output: &mut String,
    blocks: &[DynBlock],
    op_ids: &HashMap<usize, usize>,
) -> Result<(), String> {
    for (ordinal, block_ref) in blocks.iter().enumerate() {
        let block = block_ref.read().expect("block read lock");
        let basic = block
            .as_any()
            .downcast_ref::<BlockBasic>()
            .ok_or_else(|| "non-basic block in initial FlowInfo graph".to_string())?;
        write!(
            output,
            "{{\"entry\":{},\"flags\":{},\"id\":{ordinal},\"incoming\":[",
            block.is_entry_point(),
            block.get_flags(),
        )
        .expect("write to String");
        for slot in 0..block.size_in() {
            if slot != 0 {
                output.push(',');
            }
            let edge = block
                .get_in(slot)
                .ok_or_else(|| "missing incoming edge slot".to_string())?;
            write!(
                output,
                "{{\"block\":{},\"flags\":{},\"reverse\":{}}}",
                block_ordinal(blocks, &edge.point),
                edge.flags,
                edge.reverse_index,
            )
            .expect("write to String");
        }
        output.push_str("],\"ops\":[");
        for (slot, op) in basic.ops.iter().enumerate() {
            if slot != 0 {
                output.push(',');
            }
            write!(output, "{}", op_id(op_ids, op)?).expect("write to String");
        }
        output.push_str("],\"outgoing\":[");
        for slot in 0..block.size_out() {
            if slot != 0 {
                output.push(',');
            }
            let edge = block
                .get_out(slot)
                .ok_or_else(|| "missing outgoing edge slot".to_string())?;
            write!(
                output,
                "{{\"block\":{},\"flags\":{},\"reverse\":{}}}",
                block_ordinal(blocks, &edge.point),
                edge.flags,
                edge.reverse_index,
            )
            .expect("write to String");
        }
        output.push_str("],\"record\":\"block\",\"start\":");
        push_address(output, block.get_start_addr())?;
        output.push_str(",\"stop\":");
        push_address(output, basic.get_stop_addr())?;
        output.push_str("}\n");
    }
    Ok(())
}

fn write_summary(
    output: &mut String,
    snapshot: &FlowInfoSnapshot,
    function: &rudra::funcdata::Funcdata,
    blocks: &[DynBlock],
    varnode_count: usize,
) {
    let graph_edges = blocks
        .iter()
        .map(|block| block.read().expect("block read lock").size_out())
        .sum::<usize>();
    let relative_internal = snapshot
        .relatives
        .iter()
        .filter(|relative| relative.target.is_some())
        .count();
    let relative_fallthru = snapshot.relatives.len() - relative_internal;
    let start_block = function
        .bblocks
        .get_start_block()
        .as_ref()
        .map_or(-1, |block| block_ordinal(blocks, block));
    writeln!(
        output,
        "{{\"alive_ops\":{},\"blocks\":{},\"dead_ops\":{},\"graph_edges\":{graph_edges},\"ops\":{},\"raw_edges\":{},\"record\":\"summary\",\"relative_fallthru\":{relative_fallthru},\"relative_internal\":{relative_internal},\"relative_total\":{},\"start_block\":{start_block},\"varnodes\":{varnode_count},\"visited\":{}}}",
        function.obank.alivelist.len(),
        blocks.len(),
        function.obank.deadlist.len(),
        snapshot.operations.len(),
        snapshot.raw_edges.len(),
        snapshot.relatives.len(),
        snapshot.visited.len(),
    )
    .expect("write to String");
}

fn verify_graph_identity(
    snapshot: &FlowInfoSnapshot,
    ops: &[PcodeOpRef],
    varnodes: &[VarnodeRef],
    blocks: &[DynBlock],
    space_ids: &HashMap<usize, AddressSpace>,
) -> Result<(), String> {
    let op_keys = ops.iter().map(op_key).collect::<HashSet<_>>();
    if op_keys.len() != ops.len() {
        return Err("operation snapshot contains duplicate post-emission identities".to_string());
    }
    let varnode_keys = varnodes.iter().map(varnode_key).collect::<HashSet<_>>();
    if varnode_keys.len() != varnodes.len() {
        return Err("varnode snapshot contains duplicate assigned identities".to_string());
    }
    if snapshot
        .operations
        .iter()
        .any(|operation| operation.op.0.read().expect("op read lock").is_dead())
    {
        return Err("valid CPUID/RET fixture unexpectedly retained a dead op".to_string());
    }
    if space_ids.len() != 5 {
        return Err(format!(
            "expected five normalized LOAD/STORE space-id Varnodes, found {}",
            space_ids.len(),
        ));
    }
    if blocks.iter().any(|block| {
        block
            .read()
            .expect("block read lock")
            .as_any()
            .downcast_ref::<BlockBasic>()
            .is_none()
    }) {
        return Err("initial graph contains a non-basic block".to_string());
    }
    Ok(())
}

fn run(sla: &str, image_path: &str) -> Result<String, Box<dyn Error>> {
    let image = fs::read(image_path)?;
    if image != EXPECTED_IMAGE {
        return Err(format!("raw image must be exact x86 bytes 0f a2 c3, got {image:02x?}").into());
    }
    set_sla_path(sla);
    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(&image, 0)?;
    let mut function = rudra::funcdata::Funcdata::new(FUNCTION_NAME, Address::new(0), 0);
    let snapshot = {
        let mut flow = FlowInfo::new(&mut function, &mut lifter, 0, image.len() as u64);
        flow.set_flags(FLOW_FLAGS);
        flow.set_max_instructions(MAX_INSTRUCTIONS);
        flow.generate_ops(Address::new(0));
        flow.generate_blocks();
        flow.snapshot()
    };

    let blocks = function.bblocks.blocks.clone();
    let (ops, op_ids, varnodes, varnode_ids, space_ids) = collect_identities(&snapshot, &function);
    verify_graph_identity(&snapshot, &ops, &varnodes, &blocks, &space_ids)?;

    let mut output = String::new();
    write_header(&mut output);
    write_flow_state(&mut output, &snapshot, function.size)?;
    write_visited(&mut output, &snapshot)?;
    write_operations(&mut output, &snapshot, &blocks, &op_ids, &varnode_ids)?;
    write_varnodes(&mut output, &varnodes, &op_ids, &varnode_ids, &space_ids)?;
    write_relatives(&mut output, &snapshot, &op_ids)?;
    write_raw_edges(&mut output, &snapshot, &op_ids)?;
    write_blocks(&mut output, &blocks, &op_ids)?;
    write_summary(&mut output, &snapshot, &function, &blocks, varnodes.len());
    Ok(output)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: sleigh_flow_relative_1204 SLA RAW_0FA2C3".into());
    }
    let output = run(&args[1], &args[2])?;
    print!("{output}");
    Ok(())
}
