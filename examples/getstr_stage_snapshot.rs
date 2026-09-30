//! Emit layered Rugra pipeline snapshots for `GetStr` in `examples/curl`.
//!
//! The locked Ghidra fixture emits the same JSON schema.  This is diagnostic
//! evidence, not a parity claim: the Heritage stage is explicitly a direct
//! Rugra Action replay because Rugra's Action tree has no observation hook yet.

use goblin::Object;
use rugra::action::{Action, ActionDatabase};
use rugra::address::Address;
use rugra::block::{
    edge_flags, type_to_name, BlockCondition, BlockCopy, BlockDoWhile, BlockGraph, BlockIf,
    BlockInfLoop, BlockList, BlockSwitch, BlockWhileDo, FlowBlock,
};
use rugra::coreaction::ActionHeritage;
use rugra::disasm::sleigh_lift::SleighLifter;
use rugra::funcdata::Funcdata;
use rugra::op::PcodeOpRef;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printc::PrintC;
use rugra::printlanguage::PrintLanguage;
use rugra::type_system::datatype::metatype2string;
use rugra::varnode::Varnode;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const FUNCTION_NAME: &str = "GetStr";

#[derive(Clone)]
struct FunctionInput {
    name: String,
    address: u64,
    size: usize,
    image_base: u64,
    image: Vec<u8>,
    symbols: HashMap<u64, String>,
}

struct SnapshotIds {
    ops: Vec<PcodeOpRef>,
    op_ids: HashMap<usize, u64>,
    varnodes: Vec<Arc<RwLock<Varnode>>>,
    varnode_ids: HashMap<usize, u64>,
}

impl SnapshotIds {
    fn from_funcdata(fd: &Funcdata) -> Self {
        let ops = fd.obank.optree.iter().cloned().collect::<Vec<_>>();
        let op_ids = ops
            .iter()
            .enumerate()
            .map(|(index, op)| (Arc::as_ptr(&op.0) as usize, index as u64))
            .collect::<HashMap<_, _>>();
        let mut ids = Self {
            ops,
            op_ids,
            varnodes: Vec::new(),
            varnode_ids: HashMap::new(),
        };
        let ordered_ops = ids.ops.clone();
        for op in ordered_ops {
            let (output, inputs) = {
                let op_read = op.0.read().expect("PcodeOp read lock");
                (op_read.output.clone(), op_read.inrefs.clone())
            };
            if let Some(output) = output {
                ids.add_varnode(output);
            }
            for input in inputs {
                ids.add_varnode(input);
            }
        }
        for entry in &fd.vbank.loc_tree {
            ids.add_varnode(entry.0.clone());
        }
        ids
    }

    fn add_varnode(&mut self, varnode: Arc<RwLock<Varnode>>) {
        let key = Arc::as_ptr(&varnode) as usize;
        if self.varnode_ids.contains_key(&key) {
            return;
        }
        let id = self.varnodes.len() as u64;
        self.varnode_ids.insert(key, id);
        self.varnodes.push(varnode);
    }

    fn op_id(&self, op: &Arc<RwLock<rugra::op::PcodeOp>>) -> i64 {
        self.op_ids
            .get(&(Arc::as_ptr(op) as usize))
            .copied()
            .map_or(-1, |id| id as i64)
    }

    fn varnode_id(&self, varnode: &Arc<RwLock<Varnode>>) -> i64 {
        self.varnode_ids
            .get(&(Arc::as_ptr(varnode) as usize))
            .copied()
            .map_or(-1, |id| id as i64)
    }
}

fn address_value(space: rugra::space::AddressSpace, offset: u64) -> Value {
    json!({
        "space": space.space_id(),
        "space_name": space.name(),
        "offset": offset,
    })
}

fn op_values(ids: &SnapshotIds, include_high_read_types: bool) -> Vec<Value> {
    ids.ops
        .iter()
        .enumerate()
        .map(|(index, op)| {
            let op = op.0.read().expect("PcodeOp read lock");
            let parent_block = op
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .map(|parent| parent.read().expect("parent block read lock").get_index());
            let input_high_read_types = op
                .inrefs
                .iter()
                .enumerate()
                .map(|(slot, varnode)| {
                    let varnode = varnode.read().expect("Varnode read lock");
                    if !include_high_read_types || varnode.is_annotation() {
                        None
                    } else {
                        varnode
                            .get_high_type_read_facing(&op, slot as i32)
                            .map(|data_type| {
                                json!({
                                    "name": data_type.get_name(),
                                    "size": data_type.get_size(),
                                    "metatype": metatype2string(data_type.get_metatype()),
                                })
                            })
                    }
                })
                .collect::<Vec<_>>();
            json!({
                "id": index,
                "address": address_value(rugra::space::AddressSpace::Ram, op.start.addr.as_u64()),
                // Rugra currently collapses Ghidra SeqNum::uniq/time and mutable order.
                // Recording the same field twice exposes this structural mismatch.
                "time": op.start.order,
                "order": op.start.order,
                "opcode": op.opcode as i32,
                "opcode_name": op.opcode.name(),
                "parent_block": parent_block,
                "output": op.output.as_ref().map(|varnode| ids.varnode_id(varnode)),
                "inputs": op.inrefs.iter().map(|varnode| ids.varnode_id(varnode)).collect::<Vec<_>>(),
                "input_high_read_types": input_high_read_types,
                "properties": {
                    "dead": op.is_dead(),
                    "call": op.is_call(),
                    "marker": op.is_marker(),
                    "branch": op.is_branch(),
                    "bool_output": op.is_bool_output(),
                    "boolean_flip": op.is_boolean_flip(),
                    "instruction_start": op.is_instruction_start(),
                    "indirect_source": op.is_indirect_source(),
                    "ptr_flow": op.is_ptr_flow(),
                },
            })
        })
        .collect()
}

fn varnode_values(fd: &Funcdata, ids: &SnapshotIds) -> Vec<Value> {
    ids.varnodes
        .iter()
        .enumerate()
        .map(|(index, varnode_ref)| {
            let varnode = varnode_ref.read().expect("Varnode read lock");
            let address_space = varnode.address_space;
            let raw_offset = varnode.loc.as_u64();
            let defining_op = varnode
                .def
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .map(|op| ids.op_id(&op));
            let descend_ops = varnode
                .descend
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .collect::<Vec<_>>();
            let has_call_spec_binding = varnode.call_spec.is_some();
            let typed_call_spec = varnode.get_call_spec();
            let is_constant = varnode.is_constant();
            let size = varnode.size;
            let flags = varnode.flags;
            let create_index = varnode.create_index;
            let data_type = varnode.v_type.as_ref().map(|data_type| {
                json!({
                    "name": data_type.get_name(),
                    "size": data_type.get_size(),
                    "metatype": metatype2string(data_type.get_metatype()),
                })
            });
            drop(varnode);

            let uses = descend_ops
                .iter()
                .map(|op| ids.op_id(op))
                .collect::<Vec<_>>();
            let is_space_reference = is_constant
                && descend_ops.iter().any(|op| {
                    let op = op.read().expect("PcodeOp space-input read lock");
                    matches!(
                        op.opcode,
                        rugra::opcodes::OpCode::CPUI_LOAD | rugra::opcodes::OpCode::CPUI_STORE
                    ) && op
                        .inrefs
                        .first()
                        .is_some_and(|input| Arc::ptr_eq(input, varnode_ref))
                });
            let space_reference = is_space_reference.then_some(raw_offset);
            let call_target = (address_space == rugra::space::AddressSpace::Iop)
                .then(|| {
                    descend_ops.iter().find_map(|op| {
                        let operation = op.read().expect("PcodeOp call-spec read lock");
                        let is_target = operation.opcode == rugra::opcodes::OpCode::CPUI_CALL
                            && operation
                                .inrefs
                                .first()
                                .is_some_and(|input| Arc::ptr_eq(input, varnode_ref));
                        is_target.then(|| op.clone())
                    })
                })
                .flatten();
            let typed_call_spec = call_target.as_ref().and(typed_call_spec);
            let fspec_owner = typed_call_spec.filter(|owner| {
                let owned = fd
                    .callspecs
                    .iter()
                    .any(|candidate| Arc::ptr_eq(candidate, owner));
                let same_op = call_target.as_ref().is_some_and(|target| {
                    owner
                        .read()
                        .expect("FuncCallSpecs read lock")
                        .op
                        .upgrade()
                        .is_some_and(|bound| Arc::ptr_eq(&bound, target))
                });
                owned && same_op
            });
            let fspec_reference = fspec_owner
                .as_ref()
                .and_then(|owner| owner.read().expect("FuncCallSpecs read lock").entry_addr)
                .map(|address| address.as_u64());
            // A CALL input(0) that fails exact typed-owner validation is an
            // unresolved callspec annotation, never a numeric PcodeOp key.
            // Ordinary Iop annotations may still resolve through the op-id
            // map, but a stale key is represented explicitly instead of
            // panicking.
            let iop_reference = (address_space == rugra::space::AddressSpace::Iop
                && !has_call_spec_binding
                && call_target.is_none())
            .then(|| ids.op_ids.get(&(raw_offset as usize)).copied())
            .flatten();
            let normalized_offset = space_reference
                .or(fspec_reference)
                .or(iop_reference)
                .unwrap_or(raw_offset);
            let pointer_ref_kind = if space_reference.is_some() {
                Some("space")
            } else if fspec_owner.is_some() {
                Some("fspec")
            } else if iop_reference.is_some() {
                Some("iop")
            } else if has_call_spec_binding || call_target.is_some() {
                Some("fspec_unresolved")
            } else if address_space == rugra::space::AddressSpace::Iop {
                Some("iop_unresolved")
            } else {
                None
            };
            json!({
                "id": index,
                "space": address_space.space_id(),
                "space_name": address_space.name(),
                "offset": normalized_offset,
                "space_ref_index": space_reference,
                "pointer_ref_kind": pointer_ref_kind,
                "size": size,
                "flags": flags,
                "create_index": create_index,
                "def": defining_op,
                "uses": uses,
                "type": data_type,
            })
        })
        .collect()
}

fn out_edge_values(block: &dyn FlowBlock) -> Vec<Value> {
    // ARENAFLIP-(e): edge points are bank ids — resolve the peer index
    // through the owning bank (block.bank() per the owner-bank back-pointer).
    let bank = block.bank();
    (0..block.size_out())
        .filter_map(|slot| {
            block.get_out(slot).map(|edge| {
                let flags = edge.flags;
                json!({
                    "slot": slot,
                    "target": bank.expect_index(edge.point),
                    "reverse": edge.reverse_index,
                    "loop": flags & edge_flags::F_LOOP_EDGE != 0,
                    "default": flags & edge_flags::F_DEFAULTSWITCH_EDGE != 0,
                    "back": flags & edge_flags::F_BACK_EDGE != 0,
                    "irreducible": flags & edge_flags::F_IRREDUCIBLE_EDGE != 0,
                    "goto": flags & edge_flags::F_GOTO_EDGE != 0,
                })
            })
        })
        .collect()
}

fn in_edge_values(block: &dyn FlowBlock) -> Vec<Value> {
    // ARENAFLIP-(e): edge points are bank ids — resolve the peer index
    // through the owning bank (block.bank() per the owner-bank back-pointer).
    let bank = block.bank();
    (0..block.size_in())
        .filter_map(|slot| {
            block.get_in(slot).map(|edge| {
                let flags = edge.flags;
                json!({
                    "slot": slot,
                    "source": bank.expect_index(edge.point),
                    "reverse": edge.reverse_index,
                    "loop": flags & edge_flags::F_LOOP_EDGE != 0,
                    "tree": flags & edge_flags::F_TREE_EDGE != 0,
                    "back": flags & edge_flags::F_BACK_EDGE != 0,
                    "irreducible": flags & edge_flags::F_IRREDUCIBLE_EDGE != 0,
                    "goto": flags & edge_flags::F_GOTO_EDGE != 0,
                })
            })
        })
        .collect()
}

fn block_values(fd: &Funcdata, ids: &SnapshotIds) -> Vec<Value> {
    fd.bblocks
        .blocks
        .iter()
        .map(|block| {
            let block = block.read().expect("basic block read lock");
            let (start, stop) = block
                .as_any()
                .downcast_ref::<rugra::block::BlockBasic>()
                .map_or((Value::Null, Value::Null), |basic| {
                    (
                        address_value(rugra::space::AddressSpace::Ram, basic.start_addr.as_u64()),
                        address_value(
                            rugra::space::AddressSpace::Ram,
                            basic.get_stop_addr().as_u64(),
                        ),
                    )
                });
            json!({
                "index": block.get_index(),
                "type": type_to_name(block.get_type()),
                "flags": block.get_flags(),
                "start": start,
                "stop": stop,
                "ops": block.get_ops().iter().map(|op| ids.op_id(&op.0)).collect::<Vec<_>>(),
                "out_edges": out_edge_values(&*block),
                "in_edges": in_edge_values(&*block),
            })
        })
        .collect()
}

fn structure_node_arc(block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> Value {
    let block = block.read().expect("structure block read lock");
    structure_node(&*block)
}

fn structure_node(block: &dyn FlowBlock) -> Value {
    let mut children = Vec::new();
    if let Some(copy) = block.as_any().downcast_ref::<BlockCopy>() {
        let original = copy.original.read().expect("BlockCopy original read lock");
        children.push(structure_node(&*original));
    } else if let Some(if_block) = block.as_any().downcast_ref::<BlockIf>() {
        children.push(structure_node_arc(&if_block.condition));
        children.push(structure_node_arc(&if_block.if_body));
        if let Some(else_body) = &if_block.else_body {
            children.push(structure_node_arc(else_body));
        }
    } else if let Some(while_block) = block.as_any().downcast_ref::<BlockWhileDo>() {
        children.push(structure_node_arc(&while_block.condition));
        children.push(structure_node_arc(&while_block.body));
    } else if let Some(do_while) = block.as_any().downcast_ref::<BlockDoWhile>() {
        children.push(structure_node_arc(&do_while.condition));
    } else if let Some(infinite) = block.as_any().downcast_ref::<BlockInfLoop>() {
        children.push(structure_node_arc(&infinite.body));
    } else if let Some(list) = block.as_any().downcast_ref::<BlockList>() {
        children.extend(list.children.iter().map(structure_node_arc));
    } else if let Some(condition) = block.as_any().downcast_ref::<BlockCondition>() {
        children.push(structure_node_arc(&condition.first));
        children.push(structure_node_arc(&condition.second));
    } else if let Some(switch) = block.as_any().downcast_ref::<BlockSwitch>() {
        children.push(structure_node_arc(&switch.control));
        children.extend(switch.cases.iter().map(structure_node_arc));
        if let Some(default_case) = &switch.default_case {
            children.push(structure_node_arc(default_case));
        }
    }
    json!({
        "index": block.get_index(),
        "type": type_to_name(block.get_type()),
        "flags": block.get_flags(),
        "children": children,
    })
}

fn structure_graph(graph: &BlockGraph) -> Value {
    json!({
        "index": graph.index,
        "type": "graph",
        "flags": graph.flags,
        "children": graph.blocks.iter().map(structure_node_arc).collect::<Vec<_>>(),
    })
}

#[allow(clippy::too_many_arguments)]
fn snapshot(
    stage: &str,
    fd: &Funcdata,
    include_ops: bool,
    include_varnodes: bool,
    include_blocks: bool,
    include_structure: bool,
    text: Option<&str>,
) -> Value {
    let ids = SnapshotIds::from_funcdata(fd);
    json!({
        "schema": 1,
        "state": "OK",
        "stage": stage,
        "function": {
            "name": fd.name,
            "entry": address_value(rugra::space::AddressSpace::Ram, fd.baseaddr.as_u64()),
            "size": fd.size,
        },
        "ops": if include_ops { op_values(&ids, stage == "03_action_ir") } else { Vec::new() },
        "varnodes": if include_varnodes { varnode_values(fd, &ids) } else { Vec::new() },
        "blocks": if include_blocks { block_values(fd, &ids) } else { Vec::new() },
        "structure": if include_structure { structure_graph(&fd.sblocks) } else { Value::Null },
        "text": text,
    })
}

fn write_snapshot(
    output_directory: &Path,
    name: &str,
    value: &Value,
) -> Result<(), Box<dyn Error>> {
    let path = output_directory.join(name);
    let bytes = serde_json::to_vec(value)?;
    fs::write(path, [bytes.as_slice(), b"\n"].concat())?;
    Ok(())
}

// FUNCPROTO-MODEL-BIND-0001 mirror of examples/curl_decompile.rs: locked
// x86-64 address-space facts + spec host for the worker-side compiler-spec
// parse. The production driver binds this Architecture to every Funcdata
// before analysis (fd.set_arch), so the production-path heritage
// observation below must run with the same real-cspec default model.
const SPEC_SPACES: [(&str, u64); 9] = [
    ("const", u64::MAX),
    ("OTHER", u64::MAX),
    ("unique", 0xffff_ffff),
    ("ram", u64::MAX),
    ("register", 0xffff_ffff),
    ("fspec", u64::MAX),
    ("iop", u64::MAX),
    ("join", 0xffff_ffff),
    ("stack", u64::MAX),
];

const SPEC_UNIQUE_INJECT_BASE: u64 = 0x364_400;

struct WorkerSpecHost {
    registers: HashMap<String, rugra::fspec::VarnodeData>,
}

fn spec_space_by_name(name: &str) -> Option<rugra::space::AddressSpace> {
    use rugra::space::AddressSpace;
    match name {
        "ram" => Some(AddressSpace::Ram),
        "stack" => Some(AddressSpace::Stack),
        "register" => Some(AddressSpace::Register),
        "OTHER" | "other" => Some(AddressSpace::Other(1)),
        "unique" => Some(AddressSpace::Unique),
        "const" => Some(AddressSpace::Const),
        _ => None,
    }
}

impl rugra::arch::SpecQuery for WorkerSpecHost {
    fn get_register(&self, name: &str) -> Option<rugra::fspec::VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<rugra::space::AddressSpace> {
        spec_space_by_name(name)
    }
    fn space_highest(&self, spc: rugra::space::AddressSpace) -> u64 {
        let name = match spc {
            rugra::space::AddressSpace::Const => "const",
            rugra::space::AddressSpace::Other(_) => "OTHER",
            rugra::space::AddressSpace::Unique => "unique",
            rugra::space::AddressSpace::Ram => "ram",
            rugra::space::AddressSpace::Register => "register",
            rugra::space::AddressSpace::Stack => "stack",
            rugra::space::AddressSpace::Iop => "iop",
            rugra::space::AddressSpace::Join => "join",
            rugra::space::AddressSpace::Overlay => "OTHER",
        };
        SPEC_SPACES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        SPEC_UNIQUE_INJECT_BASE
    }
}

impl rugra::pcodeparse::SleighSymbolLookup for WorkerSpecHost {
    fn find_symbol(&self, name: &str) -> Option<rugra::pcodeparse::SleighSymbol> {
        self.registers
            .get(name)
            .map(|vd| rugra::pcodeparse::SleighSymbol {
            name: name.to_string(),
            kind: rugra::pcodeparse::SleightSymbolKind::Varnode(rugra::varnode::VarnodeData {
                space: vd.space,
                offset: vd.offset,
                size: vd.size.max(0) as usize,
            }),
        })
    }
}

fn worker_architecture() -> Result<Arc<rugra::arch::Architecture>, String> {
    static CACHE: std::sync::OnceLock<Result<Arc<rugra::arch::Architecture>, String>> =
        std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
                .map_err(|error| format!("unable to read compiler spec: {error}"))?;
            let sleigh = rugra::sleigh_ffi::SleighCtx::new()
                .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
            let mut registers = HashMap::new();
            for index in 0..sleigh.num_registers() {
                let Some((name, space, offset, size)) = sleigh.register_info(index) else {
                    continue;
                };
                let Ok(space_id) = u8::try_from(space) else {
                    continue;
                };
                registers.insert(
                    name.to_string(),
                    rugra::fspec::VarnodeData {
                        space: rugra::space::AddressSpace::from_id(space_id),
                        offset,
                        size,
                    },
                );
            }
            let host = Arc::new(WorkerSpecHost { registers });
            let mut store = rugra::marshal::DocumentStorage::new();
            let doc = store
                .parse_document(&cspec_bytes)
                .map_err(|error| format!("compiler spec parse failed: {error}"))?;
            let root = doc
                .root
                .clone()
                .ok_or_else(|| "compiler spec has no root element".to_string())?;
            if root
                .read()
                .map_err(|_| "compiler spec element lock poisoned".to_string())?
                .name
                != "compiler_spec"
            {
                return Err("compiler spec root is not compiler_spec".to_string());
            }
            store.register_tag(&root);
            let mut arch = rugra::arch::Architecture::new();
            arch.archid = "x86:LE:64:default".to_string();
            // The bilateral oracle is BfdArchitecture, which inherits
            // SleighArchitecture.  Its locked cspec has no <coretypes>, so
            // buildCoreTypes must run the standalone fallback after compiler
            // data-organization parsing, not the Java-client DataOrg table.
            arch.set_types(Arc::new(std::sync::RwLock::new(
                rugra::type_system::typefactory::TypeFactory::raw(),
            )));
            arch.set_commentdb(std::sync::Arc::new(std::sync::RwLock::new(
                rugra::comment::CommentDatabaseInternal::new(),
            )));
            let mut inject_lib =
                rugra::pcodeinject::PcodeInjectLibrary::new(SPEC_UNIQUE_INJECT_BASE);
            inject_lib.set_sleigh_lookup(host.clone());
            arch.pcodeinjectlib = Some(Arc::new(std::sync::RwLock::new(inject_lib)));
            arch.userops = Some(Arc::new(std::sync::RwLock::new(
                rugra::userop::UserOpManage::new(),
            )));
            // ARCH-CONTEXT-TRACKED-0001 mirror of examples/curl_decompile.rs:
            // Architecture::restoreFromSpec runs parseProcessorConfig BEFORE
            // parseCompilerConfig (architecture.cc:639->641); its
            // ELEM_CONTEXT_DATA arm (architecture.cc:1190) feeds
            // ContextInternal::decodeFromSpec.  Minimal wiring (ARCH-0001
            // residual): the locked x86-64.pspec bytes parsed with the
            // worker's DocumentStorage, every <context_data> child handed to
            // the mapped Architecture::decode_context_data, so the tracked
            // DF=0 register drives ActionConstbase's entry COPY
            // (coreaction.cc:692-704) exactly as in the oracle's
            // getstr_pipeline_1204 observation boundary.
            let pspec_bytes = fs::read("sleigh_specs/x86-64.pspec")
                .map_err(|error| format!("unable to read processor spec: {error}"))?;
            let pspec_doc = store
                .parse_document(&pspec_bytes)
                .map_err(|error| format!("processor spec parse failed: {error}"))?;
            let pspec_root = pspec_doc
                .root
                .clone()
                .ok_or_else(|| "processor spec has no root element".to_string())?;
            if pspec_root
                .read()
                .map_err(|_| "processor spec element lock poisoned".to_string())?
                .name
                != "processor_spec"
            {
                return Err("processor spec root is not processor_spec".to_string());
            }
            let pspec_children: Vec<_> = pspec_root
                .read()
                .map_err(|_| "processor spec element lock poisoned".to_string())?
                .children
                .clone();
            let pspec_registry =
                Arc::new(std::sync::RwLock::new(rugra::marshal::IdRegistry::new()));
            for child in pspec_children {
                let child_name = child
                    .read()
                    .map_err(|_| "processor spec element lock poisoned".to_string())?
                    .name
                    .clone();
                if child_name != "context_data" {
                    continue;
                }
                let mut decoder =
                    rugra::marshal::TreeDecoder::new(child, pspec_registry.clone());
                arch.decode_context_data(&mut decoder, host.as_ref())
                    .map_err(|error| {
                        format!("processor spec context_data decode failed: {error}")
                    })?;
            }
            arch.parse_compiler_config(&mut store, host.as_ref(), 8)
                .map_err(|error| format!("compiler spec parse failed: {error}"))?;
            arch.types
                .as_ref()
                .expect("Bfd TypeFactory installed before compiler-spec parse")
                .write()
                .map_err(|_| "type factory lock poisoned".to_string())?
                .build_core_types_flavor(
                    rugra::type_system::typefactory::CoreTypeFlavor::Standalone,
                );
            if arch.defaultfp.is_none() {
                return Err("No default prototype specified".to_string());
            }
            Ok(Arc::new(arch))
        })
        .clone()
}

fn build_funcdata(input: &FunctionInput) -> Result<Funcdata, Box<dyn Error>> {
    let mut fd = Funcdata::new(&input.name, Address::new(input.address), input.size as i32);
    // Production binding (examples/curl_decompile.rs decompile_request):
    // the worker Architecture — carrying the locked x86-64-gcc cspec
    // default model — is attached before any analysis so callspec
    // effect lookups resolve against the real effect list.
    fd.set_arch(worker_architecture()?);
    for (&address, name) in &input.symbols {
        fd.add_symbol(address, name.clone());
    }
    let mut lifter = SleighLifter::new();
    lifter
        .configure_x86_64(&input.image, input.image_base)
        .expect("configure GetStr SLEIGH translator");
    // GetStr has no known no-return callees (no canary/exit paths), so the
    // callee table is intentionally empty; this keeps the call site on the
    // FLOW-NORETURN-DATA-0001 entry without pulling the curl_decompile mirror.
    rugra::flow::follow_flow_with_callee_protos(
        &mut fd,
        &mut lifter,
        Address::new(input.address),
        u64::MAX,
        &std::collections::BTreeMap::new(),
    );
    Ok(fd)
}

fn load_input(binary: &Path) -> Result<FunctionInput, Box<dyn Error>> {
    let bytes = fs::read(binary)?;
    let object = Object::parse(&bytes)?;
    let Object::Elf(elf) = object else {
        return Err("GetStr snapshot currently requires an ELF input".into());
    };
    let mut symbols = HashMap::new();
    for symbol in &elf.syms {
        if symbol.st_value == 0 {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(symbol.st_name) {
            if !name.is_empty() {
                symbols.insert(symbol.st_value, name.to_string());
            }
        }
    }
    for symbol in &elf.dynsyms {
        if symbol.st_value == 0 {
            continue;
        }
        if let Some(name) = elf.dynstrtab.get_at(symbol.st_name) {
            if !name.is_empty() {
                symbols.insert(symbol.st_value, name.to_string());
            }
        }
    }
    let symbol = elf
        .syms
        .iter()
        .find(|symbol| {
            symbol.is_function()
                && symbol.st_size > 0
                && elf.strtab.get_at(symbol.st_name) == Some(FUNCTION_NAME)
        })
        .ok_or("GetStr was not found in the ELF symbol table")?;
    let section = elf
        .section_headers
        .iter()
        .find(|section| {
            symbol.st_value >= section.sh_addr
                && symbol.st_value < section.sh_addr.saturating_add(section.sh_size)
        })
        .ok_or("GetStr does not belong to a file-backed ELF section")?;
    let image_start = section.sh_offset as usize;
    let image_end = section
        .sh_offset
        .checked_add(section.sh_size)
        .ok_or("GetStr section file range overflow")? as usize;
    let image = bytes
        .get(image_start..image_end)
        .ok_or("GetStr section file range lies outside the ELF bytes")?
        .to_vec();

    Ok(FunctionInput {
        name: FUNCTION_NAME.to_string(),
        address: symbol.st_value,
        size: symbol.st_size as usize,
        image_base: section.sh_addr,
        image,
        symbols,
    })
}

/// Per-object projection of the INDIRECT call guards created by the
/// production-path `guardCalls` (HERITAGE-CALLGUARD-0001 observation):
/// for every alive INDIRECT op in block/position order print the parent
/// block index and position, the iop-aliased causing op (resolved through
/// the same Funcdata::get_op_from_const boundary Ghidra's
/// PcodeOp::getOpFromConst uses), the input[0] form (indirectly-created
/// constant zero vs prior storage value), and the output storage + flags.
fn report_production_call_guards(fd: &Funcdata) {
    let mut guard_count = 0usize;
    eprintln!("[CALLGUARD] production heritage guards:");
    for block in &fd.bblocks.blocks {
        let block_read = block.read().expect("guard block read lock");
        let Some(basic) = block_read
            .as_any()
            .downcast_ref::<rugra::block::BlockBasic>()
        else {
            continue;
        };
        for (position, op_ref) in basic.ops.iter().enumerate() {
            let op = op_ref.0.read().expect("guard op read lock");
            if op.opcode != rugra::opcodes::OpCode::CPUI_INDIRECT {
                continue;
            }
            let Some(in1) = op.get_in(1) else {
                continue;
            };
            if in1.read().expect("guard iop read lock").address_space
                != rugra::space::AddressSpace::Iop
            {
                continue;
            }
            let causing = fd
                .get_op_from_const(in1)
                .map(|target| {
                    target
                        .0
                        .read()
                        .expect("guard target read lock")
                        .start
                        .addr
                        .as_u64()
                })
                .unwrap_or(0);
            let form = op.is_indirect_creation();
            let describe = |vn: &Arc<RwLock<Varnode>>| -> String {
                let v = vn.read().expect("guard varnode read lock");
                let mut flags = String::new();
                if v.is_written() {
                    flags.push('W');
                }
                if v.is_input() {
                    flags.push('I');
                }
                if v.is_active_heritage() {
                    flags.push('h');
                }
                if (v.flags & rugra::varnode::varnode_flags::INDIRECT_CREATION) != 0 {
                    flags.push('c');
                }
                if (v.flags & rugra::varnode::varnode_flags::RETURN_ADDRESS) != 0 {
                    flags.push('r');
                }
                if v.is_constant() {
                    format!("const:{}:{}", v.size, flags)
                } else {
                    format!(
                        "{}:{:x}:{}:{}",
                        v.address_space.name(),
                        v.loc.as_u64(),
                        v.size,
                        flags
                    )
                }
            };
            let in0 = op
                .get_in(0)
                .map(describe)
                .unwrap_or_else(|| "none".to_string());
            let out = op
                .output
                .as_ref()
                .map(describe)
                .unwrap_or_else(|| "none".to_string());
            eprintln!(
                "[CALLGUARD] block={}.{} ind{} call@0x{:x} in0={} out={}",
                basic.index, position, if form { "+ic" } else { "" }, causing, in0, out
            );
            guard_count += 1;
        }
    }
    eprintln!("[CALLGUARD] total INDIRECT call guards = {guard_count}");
}

fn run(binary: &Path, output_directory: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_directory)?;
    let input = load_input(binary)?;

    let raw_fd = build_funcdata(&input)?;
    write_snapshot(
        output_directory,
        "00_raw_pcode.json",
        &snapshot("00_raw_pcode", &raw_fd, true, true, false, false, None),
    )?;
    write_snapshot(
        output_directory,
        "01_cfg.json",
        &snapshot("01_cfg", &raw_fd, false, false, true, false, None),
    )?;

    let mut heritage_fd = build_funcdata(&input)?;
    let mut heritage = ActionHeritage::new();
    heritage.apply(&mut heritage_fd)?;
    write_snapshot(
        output_directory,
        "02_heritage_ssa.json",
        &snapshot(
            "02_heritage_ssa",
            &heritage_fd,
            true,
            true,
            true,
            false,
            None,
        ),
    )?;

    // 02b: the production-path heritage moment. Ghidra's locked fixture
    // observes the same instant through a post-heritage breakpoint in the
    // universal action list (getstr_pipeline_1204.cc). Rugra's action.rs has
    // no breakpoint table yet, so this diagnostic replays the exact pre-
    // heritage action sequence from build_default_pipeline (universal
    // children before fullloop, then mainloop's varnodeprops) and snapshots
    // immediately after the production ActionHeritage — the guardCalls
    // boundary HERITAGE-CALLGUARD-0001 observes per-object.
    let production_fd = Arc::new(RwLock::new(build_funcdata(&input)?));
    production_fd
        .write()
        .expect("Funcdata write lock")
        .set_self_ref(Arc::downgrade(&production_fd));
    {
        let mut fd = production_fd
            .write()
            .expect("Funcdata production-prefix write lock");
        let mut prefix: Vec<Box<dyn rugra::action::Action>> = vec![
            Box::new(rugra::coreaction::ActionStart::new()),
            Box::new(rugra::coreaction::ActionConstbase::new()),
            Box::new(rugra::coreaction::ActionDefaultParams::new()),
            Box::new(rugra::coreaction::ActionExtraPopSetup::new()),
            Box::new(rugra::coreaction::ActionPrototypeTypes::new()),
            Box::new(rugra::coreaction::ActionFuncLink::new()),
            Box::new(rugra::coreaction::ActionFuncLinkOutOnly::new()),
            Box::new(rugra::coreaction::ActionSegmentize::new()),
            Box::new(rugra::coreaction::ActionInternalStorage::new()),
            Box::new(rugra::coreaction::ActionMultiCse::new()),
            Box::new(rugra::coreaction::ActionShadowVar::new()),
            Box::new(rugra::coreaction::ActionDeindirect::new()),
            Box::new(rugra::coreaction::ActionVarnodeProps::new()),
        ];
        for action in prefix.iter_mut() {
            action
                .apply(&mut fd)
                .map_err(|e| format!("production prefix action failed: {e}"))?;
        }
        rugra::coreaction::ActionHeritage::new()
            .apply(&mut fd)
            .map_err(|e| format!("production ActionHeritage failed: {e}"))?;
    }
    {
        let fd = production_fd
            .read()
            .expect("Funcdata production-heritage read lock");
        write_snapshot(
            output_directory,
            "02b_production_heritage.json",
            &snapshot(
                "02b_production_heritage",
                &fd,
                true,
                true,
                true,
                false,
                None,
            ),
        )?;
        report_production_call_guards(&fd);
    }

    let action_fd = Arc::new(RwLock::new(build_funcdata(&input)?));
    action_fd
        .write()
        .expect("Funcdata write lock")
        .set_self_ref(Arc::downgrade(&action_fd));
    let mut actions = ActionDatabase::new();
    actions.set_default_actions();
    if actions
        .perform_action(
            "decompile",
            &mut action_fd.write().expect("Funcdata action write lock"),
        )?
        .is_none()
    {
        return Err("Rugra did not configure the decompile action".into());
    }
    let action_read = action_fd.read().expect("Funcdata snapshot read lock");
    write_snapshot(
        output_directory,
        "03_action_ir.json",
        &snapshot("03_action_ir", &action_read, true, true, true, false, None),
    )?;
    write_snapshot(
        output_directory,
        "04_structure.json",
        &snapshot(
            "04_structure",
            &action_read,
            false,
            false,
            false,
            true,
            None,
        ),
    )?;

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.set_rpn_enabled(true);
    printer.doc_function(&action_read);
    let output = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .map_err(|_| "PrintC returned an unexpected emitter type")?;
    let c_text = output.get_output();
    write_snapshot(
        output_directory,
        "05_c.json",
        &snapshot(
            "05_c",
            &action_read,
            false,
            false,
            false,
            false,
            Some(&c_text),
        ),
    )?;
    eprintln!(
        "getstr_stage_snapshot: raw_ops={} action_ops={} output={}",
        raw_fd.obank.optree.len(),
        action_read.obank.optree.len(),
        output_directory.display()
    );
    Ok(())
}

fn main() {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let binary = arguments
        .get(1)
        .map_or_else(|| PathBuf::from("examples/curl"), PathBuf::from);
    let output_directory = arguments.get(2).map_or_else(
        || PathBuf::from("result/pipeline_snapshots/getstr/rugra"),
        PathBuf::from,
    );
    if let Err(error) = run(&binary, &output_directory) {
        eprintln!("getstr_stage_snapshot: {error}");
        std::process::exit(1);
    }
}
