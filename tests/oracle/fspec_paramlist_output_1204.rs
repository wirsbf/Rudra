//! Rust comparand for the locked Ghidra 12.0.4 output-ParamList fixture.
//! It ingests the production x86-64-gcc.cspec and x86-64.sla, then drives
//! `ProtoModelFull::derive_output_map` over the same trial states.

use rudra::address::Address;
use rudra::arch::{Architecture, SpecQuery};
use rudra::fspec::{ParamActive, ProtoModelFull, VarnodeData};
use rudra::marshal::DocumentStorage;
use rudra::pcodeparse::{SleighSymbol, SleighSymbolLookup, SleightSymbolKind};
use rudra::sleigh_ffi::{set_sla_path, SleighCtx};
use rudra::space::AddressSpace;
use rudra::userop::{UserOpManage, UserOpType};

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

const SPACES: [(&str, u64); 9] = [
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

const UNIQUE_INJECT_BASE: u64 = 0x364_400;

fn space_name(space: AddressSpace) -> &'static str {
    match space {
        AddressSpace::Const => "const",
        AddressSpace::Other(_) => "OTHER",
        AddressSpace::Unique => "unique",
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Stack => "stack",
        AddressSpace::Iop => "iop",
        AddressSpace::Join => "join",
        AddressSpace::Overlay => "overlay",
    }
}

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
            "stack" => Some(AddressSpace::Stack),
            "register" => Some(AddressSpace::Register),
            "OTHER" | "other" => Some(AddressSpace::Other(1)),
            "unique" => Some(AddressSpace::Unique),
            "const" => Some(AddressSpace::Const),
            _ => None,
        }
    }

    fn space_highest(&self, space: AddressSpace) -> u64 {
        let name = space_name(space);
        SPACES
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }

    fn unique_inject_base(&self) -> u64 {
        UNIQUE_INJECT_BASE
    }
}

impl SleighSymbolLookup for Host {
    fn find_symbol(&self, name: &str) -> Option<SleighSymbol> {
        self.registers.get(name).map(|storage| SleighSymbol {
            name: name.to_string(),
            kind: SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                space: storage.space,
                offset: storage.offset,
                size: storage.size.max(0) as usize,
            }),
        })
    }
}

fn dump_active(output: &mut String, phase: &str, active: &ParamActive, model: &ProtoModelFull) {
    output.push_str(&format!(
        "{}|count={}|used={}|passes={}|maxpass={}|fully={}|final={}|recover_subcall={}|join_reverse={}\n",
        phase,
        active.get_num_trials(),
        active.get_num_used(),
        active.get_num_passes(),
        active.get_max_pass(),
        i32::from(active.is_fully_checked()),
        i32::from(active.needs_final_check()),
        i32::from(active.is_recover_subcall()),
        i32::from(active.is_join_reverse()),
    ));
    for index in 0..active.get_num_trials() {
        let trial = active.get_trial(index);
        let entry_group = trial
            .get_entry_index()
            .and_then(|entry| model.output_entries().get(entry))
            .map(|entry| entry.get_group())
            .unwrap_or(-1);
        output.push_str(&format!(
            "{}_TRIAL|index={}|space={}|offset=0x{:x}|size={}|slot={}|entry_group={}|entry_offset={}|flags=0x{:x}\n",
            phase,
            index,
            space_name(trial.get_space()),
            trial.get_address().as_u64(),
            trial.get_size(),
            trial.get_slot(),
            entry_group,
            trial.get_offset(),
            trial.get_flags(),
        ));
    }
}

fn run_case(
    output: &mut String,
    model: &ProtoModelFull,
    host: &Host,
    name: &str,
    active_registers: &[&str],
    inactive_registers: &[&str],
) -> Result<(), String> {
    let mut active = ParamActive::new(false);
    output.push_str(&format!("CASE|{}\n", name));
    for register in active_registers {
        let storage = host
            .get_register(register)
            .ok_or_else(|| format!("missing register {}", register))?;
        active.register_trial_in_space(
            storage.space,
            Address::new(storage.offset),
            storage.size,
        );
        let index = active.get_num_trials() - 1;
        active.get_trial_mut(index).mark_active();
    }
    for register in inactive_registers {
        let storage = host
            .get_register(register)
            .ok_or_else(|| format!("missing register {}", register))?;
        active.register_trial_in_space(
            storage.space,
            Address::new(storage.offset),
            storage.size,
        );
        let index = active.get_num_trials() - 1;
        active.get_trial_mut(index).mark_inactive();
    }
    dump_active(output, "BEFORE", &active, model);
    model.derive_output_map(&mut active);
    dump_active(output, "AFTER", &active, model);
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: fspec_paramlist_output_1204 <cspec> <sla>".to_string());
    }

    let cspec = fs::read(&args[1])
        .map_err(|error| format!("failed to read {}: {}", args[1], error))?;
    let mut documents = DocumentStorage::new();
    let document = documents
        .parse_document(&cspec)
        .map_err(|error| format!("cspec parse failed: {}", error))?;
    let root = document
        .root
        .clone()
        .ok_or_else(|| "cspec has no root element".to_string())?;
    if root.read().map_err(|_| "poisoned lock")?.name != "compiler_spec" {
        return Err("cspec root is not compiler_spec".to_string());
    }
    documents.register_tag(&root);

    set_sla_path(&args[2]);
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

    let mut arch = Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    let mut inject = rudra::pcodeinject::PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
    inject.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(Arc::new(RwLock::new(inject)));
    let mut userops = UserOpManage::new();
    userops.register_op("segment".to_string(), UserOpType::Unspecialized);
    arch.userops = Some(Arc::new(RwLock::new(userops)));
    arch.parse_compiler_config(&mut documents, host.as_ref(), 8)
        .map_err(|error| format!("parse_compiler_config failed: {}", error))?;
    let model = arch
        .defaultfp
        .as_ref()
        .ok_or_else(|| "No default prototype specified".to_string())?;

    let xmm0 = host.get_register("XMM0_Qa").ok_or("missing XMM0_Qa")?;
    let rax = host.get_register("RAX").ok_or("missing RAX")?;
    let rcx = host.get_register("RCX").ok_or("missing RCX")?;

    let mut output = String::new();
    output.push_str("SCHEMA|1\n");
    output.push_str("ORACLE|e40ed13014025f82488b1f8f7bca566894ac376b\n");
    output.push_str(&format!("MODEL|{}|extrapop={}\n", model.name, model.extrapop));
    output.push_str(&format!(
        "OUTPUT_STATE|auto_killed_by_call={}\n",
        i32::from(model.output.is_auto_killed_by_call()),
    ));
    for (name, storage) in [("XMM0_Qa", xmm0), ("RAX", rax), ("RCX", rcx)] {
        output.push_str(&format!(
            "POSSIBLE|{}|{}\n",
            name,
            i32::from(model.possible_output_param(
                storage.space,
                storage.offset,
                storage.size,
            )),
        ));
    }
    run_case(&mut output, model, host.as_ref(), "float_only", &["XMM0_Qa"], &[])?;
    run_case(
        &mut output,
        model,
        host.as_ref(),
        "float_second_only",
        &["XMM1_Qa"],
        &[],
    )?;
    run_case(&mut output, model, host.as_ref(), "general_only", &["RAX"], &[])?;
    run_case(
        &mut output,
        model,
        host.as_ref(),
        "general_second_only",
        &["RDX"],
        &[],
    )?;
    run_case(
        &mut output,
        model,
        host.as_ref(),
        "general_beats_float",
        &["RAX"],
        &["XMM0_Qa"],
    )?;
    run_case(&mut output, model, host.as_ref(), "invalid_output", &["RCX"], &[])?;
    output.push_str("DONE\n");

    let mut stdout = std::io::stdout();
    stdout
        .write_all(output.as_bytes())
        .map_err(|error| error.to_string())?;
    stdout.flush().map_err(|error| error.to_string())?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error);
            ExitCode::FAILURE
        }
    }
}
