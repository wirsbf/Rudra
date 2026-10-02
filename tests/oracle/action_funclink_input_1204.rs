//! Rust comparand for GETSTR-FUNCLINK-SPACE-0001.
//!
//! The compiler specification and register table come from the same locked
//! x86-64 GCC `.cspec`/`.sla` bytes as the C++ oracle.  Prototype storage is
//! assigned by `ProtoModelFull::assign_parameter_storage`; no parameter
//! register or stack offset is hand-written in this fixture.

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::{Architecture, SpecQuery};
use rudra::coreaction::ActionFuncLink;
use rudra::fspec::{FuncCallSpecs, FuncProto, ParamActive, ProtoModelFull, VarnodeData};
use rudra::funcdata::Funcdata;
use rudra::grammar::PrototypePieces;
use rudra::marshal::DocumentStorage;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::pcodeinject::PcodeInjectLibrary;
use rudra::pcodeparse::{SleighSymbol, SleighSymbolLookup, SleightSymbolKind};
use rudra::sleigh_ffi::{set_sla_path, SleighCtx};
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::userop::{UserOpManage, UserOpType};
use rudra::varnode::Varnode;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

const UNIQUE_INJECT_BASE: u64 = 0x364_400;

struct Host {
    registers: BTreeMap<String, VarnodeData>,
}

impl SpecQuery for Host {
    fn get_register(&self, name: &str) -> Option<VarnodeData> {
        self.registers.get(name).copied()
    }

    fn space_by_name(&self, name: &str) -> Option<AddressSpace> {
        match name {
            "ram" => Some(AddressSpace::Ram),
            "register" => Some(AddressSpace::Register),
            "stack" => Some(AddressSpace::Stack),
            "OTHER" | "other" => Some(AddressSpace::Other(1)),
            "unique" => Some(AddressSpace::Unique),
            "const" => Some(AddressSpace::Const),
            _ => None,
        }
    }

    fn space_highest(&self, space: AddressSpace) -> u64 {
        match space {
            AddressSpace::Unique | AddressSpace::Register | AddressSpace::Join => 0xffff_ffff,
            _ => u64::MAX,
        }
    }

    fn unique_inject_base(&self) -> u64 {
        UNIQUE_INJECT_BASE
    }
}

impl SleighSymbolLookup for Host {
    fn find_symbol(&self, name: &str) -> Option<SleighSymbol> {
        self.registers.get(name).map(|data| SleighSymbol {
            name: name.to_string(),
            kind: SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                space: data.space,
                offset: data.offset,
                size: data.size.max(0) as usize,
            }),
        })
    }
}

fn void_type() -> Arc<Datatype> {
    Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )))
}

fn int8_type() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "int8".to_string(),
        8,
        TypeMetatype::Int,
    )))
}

fn space_type_name(space: AddressSpace) -> &'static str {
    match space {
        AddressSpace::Const => "constant",
        AddressSpace::Ram | AddressSpace::Register | AddressSpace::Other(_) => "processor",
        AddressSpace::Stack => "spacebase",
        AddressSpace::Unique => "internal",
        AddressSpace::Iop => "iop",
        AddressSpace::Join => "join",
        AddressSpace::Overlay => "other",
    }
}

fn address_descriptor(space: AddressSpace, address: Address) -> String {
    format!(
        "{}@{}:{}:0x{:x}",
        space.name(),
        space.get_index(),
        space_type_name(space),
        address.as_u64(),
    )
}

fn op_name(vn: &Varnode) -> &'static str {
    let Some(def) = vn.get_def() else {
        return "-";
    };
    let name = def.read().expect("def read lock").opcode.name();
    name
}

fn dump_input(out: &mut String, label: &str, slot: usize, vn: &Arc<RwLock<Varnode>>) {
    let vn = vn.read().expect("input read lock");
    out.push_str(&format!(
        "input|{}|{}|addr={}|size={}|annotation={}|input={}|written={}|placeholder={}|def={}\n",
        label,
        slot,
        address_descriptor(vn.get_space(), *vn.get_addr()),
        vn.get_size(),
        i32::from(vn.is_annotation()),
        i32::from(vn.is_input()),
        i32::from(vn.is_written()),
        i32::from(vn.is_spacebase_placeholder()),
        op_name(&vn),
    ));
}

struct CaseState {
    fd: Funcdata,
    op: PcodeOpRef,
    preexisting: Option<Arc<RwLock<Varnode>>>,
}

fn locked_proto(
    default_model: Arc<ProtoModelFull>,
    label: &str,
    varargs: bool,
    param_count: usize,
) -> FuncProto {
    let mut proto = FuncProto::new(label.to_string(), void_type());
    proto.set_internal(Some(default_model.clone()), void_type());
    let pieces = PrototypePieces {
        model: Some(default_model.get_name().to_string()),
        name: label.to_string(),
        out_type: Some(void_type()),
        in_types: (0..param_count).map(|_| int8_type()).collect(),
        in_names: (0..param_count).map(|index| format!("p{index}")).collect(),
        first_var_arg_slot: if varargs { 2 } else { -1 },
    };
    proto.set_pieces(&pieces);
    proto
}

fn make_case(
    architecture: Arc<Architecture>,
    label: &str,
    function_offset: u64,
    call_offset: u64,
    locked: bool,
    varargs: bool,
    param_count: usize,
) -> Result<CaseState, String> {
    let default_model = architecture
        .get_default_model()
        .cloned()
        .ok_or_else(|| "missing default prototype model".to_string())?;
    let prototype = if locked {
        locked_proto(default_model, label, varargs, param_count)
    } else {
        let mut proto = FuncProto::new(label.to_string(), void_type());
        proto.set_internal(Some(default_model), void_type());
        proto
    };

    let mut fd = Funcdata::new(label, Address::new(function_offset), 1);
    fd.set_arch(architecture);
    let op = fd.new_op(1, Address::new(call_offset));
    fd.op_set_opcode(&op, OpCode::CPUI_CALL);
    let target = fd.new_code_ref(Address::new(0x710000));
    fd.op_set_input(&op, target, 0);
    let block = fd.create_new_block();
    fd.op_insert(&op, &block, None);

    let mut spec = FuncCallSpecs::new_for_op(&op, fd.funcp.clone());
    spec.prototype = prototype;
    let preexisting = if locked {
        let first = spec
            .prototype
            .get_param(0)
            .ok_or_else(|| "locked prototype has no first parameter".to_string())?;
        // Deliberately use the ordinary explicit-space VarnodeBank path,
        // not the prototype's Address object.  This catches a split between
        // lifted `(Register, 0x38)` storage and Action-created parameter
        // storage even if each individual path is internally self-consistent.
        Some(fd.vbank.create_with_space(
            first.data_type.get_size(),
            first.get_address_space(),
            first.address.as_u64(),
        ))
    } else {
        None
    };
    fd.add_call_specs_owner(Arc::new(RwLock::new(spec)));
    Ok(CaseState {
        fd,
        op,
        preexisting,
    })
}

fn trial_index(active: &ParamActive, needle: *const rudra::fspec::ParamTrial) -> i32 {
    (0..active.get_num_trials())
        .find(|&index| std::ptr::eq(active.get_trial(index), needle))
        .map_or(-1, |index| index as i32)
}

fn dump_case(out: &mut String, label: &str, state: &CaseState) {
    let owner = state.fd.callspecs[0].read().expect("callspec read lock");
    let active = &owner.active_input;
    let input_count = state.op.0.read().expect("call read lock").num_input();
    out.push_str(&format!(
        "case|{}|model={}|locked={}|varargs={}|input_active={}|output_active={}|trials={}|passes={}|maxpass={}|fully_checked={}|needs_final={}|recover_subcall={}|join_reverse={}|callspec_placeholder={}|active_placeholder={}|inputs={}\n",
        label,
        owner.prototype.get_model_name(),
        i32::from(owner.is_input_locked()),
        i32::from(owner.is_dotdotdot()),
        i32::from(owner.is_input_active()),
        i32::from(owner.is_output_active()),
        active.get_num_trials(),
        active.get_num_passes(),
        active.get_max_pass(),
        i32::from(active.is_fully_checked()),
        i32::from(active.needs_final_check()),
        i32::from(active.is_recover_subcall()),
        i32::from(active.is_join_reverse()),
        owner.stack_placeholder_slot,
        active.get_stack_placeholder_slot(),
        input_count,
    ));

    for index in 0..active.get_num_trials() {
        let trial = active.get_trial(index);
        out.push_str(&format!(
            "trial|{}|{}|addr={}|size={}|slot={}|flags=0x{:x}|fixed={}\n",
            label,
            index,
            address_descriptor(trial.get_space(), trial.get_address()),
            trial.get_size(),
            trial.get_slot(),
            trial.get_flags(),
            trial.get_fixed_position(),
        ));
    }

    let inputs = state.op.0.read().expect("call read lock").inrefs.clone();
    for (slot, input) in inputs.iter().enumerate() {
        dump_input(out, label, slot, input);
    }

    for index in 0..owner.prototype.num_params() {
        let formal = owner.prototype.get_param(index).expect("formal parameter");
        let trial = active.get_trial(index);
        let call = inputs[index + 1]
            .read()
            .expect("formal call input read lock");
        out.push_str(&format!(
            "formal|{}|{}|addr={}|size={}\n",
            label,
            index,
            address_descriptor(formal.get_address_space(), formal.address),
            formal.data_type.get_size(),
        ));
        out.push_str(&format!(
            "alias|{}|{}|formal_trial_space={}|formal_trial_addr={}|formal_call_space={}|formal_call_addr={}\n",
            label,
            index,
            i32::from(formal.get_address_space() == trial.get_space()),
            i32::from(formal.address == trial.get_address()),
            i32::from(formal.get_address_space() == call.get_space()),
            i32::from(
                formal.get_address_space() == call.get_space()
                    && formal.address.as_u64() == call.get_offset()
            ),
        ));
    }

    if let Some(preexisting) = state.preexisting.as_ref() {
        let call_input = inputs[1].clone();
        let (space, address, size) = {
            let pre = preexisting.read().expect("preexisting read lock");
            (pre.get_space(), *pre.get_addr(), pre.get_size())
        };
        let exact: Vec<_> = state
            .fd
            .vbank
            .begin_loc()
            .filter(|entry| {
                let value = entry.0.read().expect("bank entry read lock");
                value.get_space() == space
                    && value.get_offset() == address.as_u64()
                    && value.get_size() == size
            })
            .map(|entry| entry.0.clone())
            .collect();
        let (call_space, call_address) = {
            let call = call_input.read().expect("call input read lock");
            (call.get_space(), *call.get_addr())
        };
        out.push_str(&format!(
            "bank|{}|addr={}|size={}|pre_call_object={}|pre_call_space={}|pre_call_addr={}|exact_count={}|first_pre={}|latest_call={}\n",
            label,
            address_descriptor(space, address),
            size,
            i32::from(Arc::ptr_eq(preexisting, &call_input)),
            i32::from(space == call_space),
            i32::from(space == call_space && address.as_u64() == call_address.as_u64()),
            exact.len(),
            i32::from(exact.first().is_some_and(|value| Arc::ptr_eq(value, preexisting))),
            i32::from(exact.last().is_some_and(|value| Arc::ptr_eq(value, &call_input))),
        ));
    }

    out.push_str(&format!("mapping|{}|", label));
    for slot in 1..=active.get_num_trials() {
        if slot != 1 {
            out.push(',');
        }
        let mapped = active.get_trial_for_input_varnode(slot as i32);
        out.push_str(&format!(
            "{}->{}",
            slot,
            trial_index(active, mapped as *const _),
        ));
    }
    out.push('\n');
}

fn dump_after_placeholder_mapping(out: &mut String, locked: &CaseState) {
    let owner = locked.fd.callspecs[0]
        .read()
        .expect("locked callspec read lock");
    let first = owner.prototype.get_param(0).expect("first locked formal");
    let second = owner.prototype.get_param(1).expect("second locked formal");
    let mut active = ParamActive::new(true);
    active.register_trial_in_space(first.get_address_space(), first.address, 8);
    active.set_placeholder_slot();
    active.register_trial_in_space(second.get_address_space(), second.address, 8);
    let before = active.get_trial_for_input_varnode(1) as *const _;
    let after = active.get_trial_for_input_varnode(3) as *const _;
    out.push_str(&format!(
        "mapping_after_placeholder|placeholder={}|slot1={}|slot3={}|trial_slots={},{}\n",
        active.get_stack_placeholder_slot(),
        trial_index(&active, before),
        trial_index(&active, after),
        active.get_trial(0).get_slot(),
        active.get_trial(1).get_slot(),
    ));
}

fn load_architecture(cspec_path: &str, sla_path: &str) -> Result<Arc<Architecture>, String> {
    let cspec =
        fs::read(cspec_path).map_err(|error| format!("failed to read {cspec_path}: {error}"))?;
    let mut documents = DocumentStorage::new();
    let document = documents
        .parse_document(&cspec)
        .map_err(|error| format!("cspec parse failed: {error}"))?;
    let root = document
        .root
        .clone()
        .ok_or_else(|| "cspec has no root element".to_string())?;
    documents.register_tag(&root);

    set_sla_path(sla_path);
    let sleigh = SleighCtx::new().ok_or_else(|| "SleighCtx::new failed".to_string())?;
    let mut registers = BTreeMap::new();
    for index in 0..sleigh.num_registers() {
        if let Some((name, space, offset, size)) = sleigh.register_info(index) {
            let Ok(space_id) = u8::try_from(space) else {
                continue;
            };
            registers.insert(
                name,
                VarnodeData {
                    space: AddressSpace::from_id(space_id),
                    offset,
                    size,
                },
            );
        }
    }
    let host = Arc::new(Host { registers });
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default".to_string();
    let mut inject = PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
    inject.set_sleigh_lookup(host.clone());
    architecture.pcodeinjectlib = Some(Arc::new(RwLock::new(inject)));
    let mut userops = UserOpManage::new();
    userops.register_op("segment".to_string(), UserOpType::Unspecialized);
    architecture.userops = Some(Arc::new(RwLock::new(userops)));
    architecture
        .parse_compiler_config(&mut documents, host.as_ref(), 8)
        .map_err(|error| format!("parse_compiler_config failed: {error}"))?;
    Ok(Arc::new(architecture))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: action_funclink_input_1204 CSPEC SLA".to_string());
    }
    let architecture = load_architecture(&args[1], &args[2])?;
    let mut locked = make_case(
        architecture.clone(),
        "locked",
        0x700000,
        0x700100,
        true,
        false,
        7,
    )?;
    let mut register_only = make_case(
        architecture.clone(),
        "register_only",
        0x700600,
        0x700700,
        true,
        false,
        6,
    )?;
    let mut varargs = make_case(
        architecture.clone(),
        "varargs",
        0x700200,
        0x700300,
        true,
        true,
        7,
    )?;
    let mut unlocked = make_case(
        architecture,
        "unlocked",
        0x700400,
        0x700500,
        false,
        false,
        0,
    )?;

    ActionFuncLink::new()
        .apply(&mut locked.fd)
        .map_err(|error| error.to_string())?;
    ActionFuncLink::new()
        .apply(&mut register_only.fd)
        .map_err(|error| error.to_string())?;
    ActionFuncLink::new()
        .apply(&mut varargs.fd)
        .map_err(|error| error.to_string())?;
    ActionFuncLink::new()
        .apply(&mut unlocked.fd)
        .map_err(|error| error.to_string())?;

    let mut out = String::new();
    out.push_str("schema=1|fixture=ACTION-FUNCLINK-INPUT-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n");
    dump_case(&mut out, "locked", &locked);
    dump_case(&mut out, "register_only", &register_only);
    dump_case(&mut out, "varargs", &varargs);
    dump_case(&mut out, "unlocked", &unlocked);
    dump_after_placeholder_mapping(&mut out, &locked);
    out.push_str("done\n");
    std::io::stdout()
        .write_all(out.as_bytes())
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
