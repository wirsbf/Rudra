//! HTTPD-STACKSLOT-FOLD-0001 diagnostic: decompile ap_parse_vhost_addrs via
//! the standard pipeline, then dump every surviving LOAD/STORE with its
//! pointer def chain, checking the RuleLoadVarnode/RuleStoreVarnode
//! (ruleaction.cc:4165-4341) firing conditions.

use std::collections::HashMap;

use rugra::action::ActionDatabase;
use rugra::address::Address;
use rugra::funcdata::Funcdata;
use rugra::opcodes::OpCode;

// STACKFOLD-FIXTURE-F6DC-BREAK-0001: language host + canonical cspec-bearing
// Architecture factory, mirroring the canon httpd driver
// (examples/httpd_decompile.rs tracked_context_architecture, SB-CONSTBASE-0001
// + HTTPD-CSPEC-ARCH-0001): registers enumerated from the real locked .sla
// through SleighCtx, spaces from the locked table. Only the SpecQuery legs
// Architecture::decode_context_data reaches are implemented (get_register
// for `<set name="DF">`, space_by_name for the `<tracked_set space="ram">`
// range, space_highest for the range's open last address).
const SPEC_UNIQUE_INJECT_BASE: u64 = 0x364_400;

struct TrackedSpecHost {
    registers: HashMap<String, rugra::fspec::VarnodeData>,
}

const TRACKED_SPEC_SPACES: [(&str, u64); 9] = [
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

fn tracked_spec_space_by_name(name: &str) -> Option<rugra::space::AddressSpace> {
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

// Callfixup snippet parsing needs the symbol lookup (canon httpd driver
// parity, HTTPD-CSPEC-ARCH-0001).
impl rugra::pcodeparse::SleighSymbolLookup for TrackedSpecHost {
    fn find_symbol(&self, name: &str) -> Option<rugra::pcodeparse::SleighSymbol> {
        self.registers.get(name).map(|vd| {
            rugra::pcodeparse::SleighSymbol {
                name: name.to_string(),
                kind: rugra::pcodeparse::SleightSymbolKind::Varnode(
                    rugra::varnode::VarnodeData {
                        space: vd.space,
                        offset: vd.offset,
                        size: vd.size.max(0) as usize,
                    },
                ),
            }
        })
    }
}

impl rugra::arch::SpecQuery for TrackedSpecHost {
    fn get_register(&self, name: &str) -> Option<rugra::fspec::VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<rugra::space::AddressSpace> {
        tracked_spec_space_by_name(name)
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
        TRACKED_SPEC_SPACES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        SPEC_UNIQUE_INJECT_BASE
    }
}

// STACKFOLD-FIXTURE-F6DC-BREAK-0001: the fixture's original attach was a
// bare `Architecture::new()` (cspec-less, defaultfp=None). f6dcbed0's
// faithful ActionRestrictLocal loop-2 port (coreaction.cc:1983-1985:
// effectBegin/effectEnd with model fallback, fspec.cc:4243-4247 — the
// oracle dereferences the ctor-bound defaultfp unconditionally via
// funcdata.cc:69 -> fspec.cc:3884 `setModel(s->getArch()->defaultfp)`,
// no model-less path exists) turned that construction into the fspec.rs:574
// panic. The repair is the canon httpd cspec form: parse the locked
// x86-64.pspec tracked context + the locked x86-64-gcc.cspec through
// Architecture::parse_compiler_config so defaultfp is resolved exactly the
// way every BfdArchitecture serving the headless oracle was, and
// fd.set_arch's setScope tail (funcdata.cc:69 -> fspec.cc:3884) binds it
// into funcp. funcp.effects stays empty: ap_parse_vhost_addrs was an
// analysis-time prototype in the oracle (no local effect records), so loop-2
// walks the model-fallback list — the same surface f6dcbed0 fixed.
fn model_bearing_architecture() -> Result<rugra::arch::Architecture, String> {
    let mut arch = rugra::arch::Architecture::new();
    // SLEIGH register catalog (no image needed for the spec query legs).
    let sleigh = rugra::sleigh_ffi::SleighCtx::new()
        .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
    let mut registers = HashMap::new();
    // Same enumeration as the canon httpd driver: the SLEIGH register
    // catalog also feeds the Architecture register_xref (SleighBase::
    // getAllRegisters -> varnode_xref, sleighbase.cc:182-186) that
    // Architecture::get_register_name (sleighbase.cc:144-168) walks.
    let mut register_xref: Vec<(i32, u64, i32, String)> = Vec::new();
    for index in 0..sleigh.num_registers() {
        let Some((name, space, offset, size)) = sleigh.register_info(index) else {
            continue;
        };
        let Ok(space_id) = u8::try_from(space) else {
            continue;
        };
        register_xref.push((space, offset, size, name.to_string()));
        registers.insert(
            name.to_string(),
            rugra::fspec::VarnodeData {
                space: rugra::space::AddressSpace::from_id(space_id),
                offset,
                size,
            },
        );
    }
    let host = std::sync::Arc::new(TrackedSpecHost { registers });
    // Parse the locked pspec and hand every <context_data>/<register_data>
    // child to the mapped decode (same DOM extraction model as the canon
    // httpd driver).
    let pspec_bytes = std::fs::read("sleigh_specs/x86-64.pspec")
        .map_err(|error| format!("unable to read processor spec: {error}"))?;
    let mut store = rugra::marshal::DocumentStorage::new();
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
        std::sync::Arc::new(std::sync::RwLock::new(rugra::marshal::IdRegistry::new()));
    for child in pspec_children {
        let child_name = child
            .read()
            .map_err(|_| "processor spec element lock poisoned".to_string())?
            .name
            .clone();
        match child_name.as_str() {
            "context_data" => {
                let mut decoder =
                    rugra::marshal::TreeDecoder::new(child, pspec_registry.clone());
                arch.decode_context_data(&mut decoder, host.as_ref())
                    .map_err(|error| format!("processor spec context_data decode failed: {error}"))?;
            }
            "register_data" => {
                let mut decoder =
                    rugra::marshal::TreeDecoder::new(child, pspec_registry.clone());
                arch.decode_register_data(&mut decoder, host.as_ref())
                    .map_err(|error| format!("processor spec register_data decode failed: {error}"))?;
            }
            _ => {}
        }
    }

    // Parse the locked production compiler spec into the same
    // DocumentStorage and establish the Architecture init chain the canon
    // httpd driver builds: archid + register_xref + commentdb + TypeFactory
    // (data_organization decode + setup_sizes mirror parseCompilerConfig's
    // ELEM_DATA_ORGANIZATION arm, architecture.cc:1269, and its trailing
    // types->setupSizes() at cc:1350) + PcodeInjectLibrary/UserOpManage +
    // the final parse_compiler_config (architecture.cc:1239-1351) which
    // establishes `defaultfp`.
    let cspec_bytes = std::fs::read("sleigh_specs/x86-64-gcc.cspec")
        .map_err(|error| format!("unable to read compiler spec: {error}"))?;
    let cspec_doc = store
        .parse_document(&cspec_bytes)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    let cspec_root = cspec_doc
        .root
        .clone()
        .ok_or_else(|| "compiler spec has no root element".to_string())?;
    if cspec_root
        .read()
        .map_err(|_| "compiler spec element lock poisoned".to_string())?
        .name
        != "compiler_spec"
    {
        return Err("compiler spec root is not compiler_spec".to_string());
    }
    store.register_tag(&cspec_root);
    arch.archid = "x86:LE:64:default".to_string();
    arch.set_register_xref(register_xref);
    arch.set_commentdb(std::sync::Arc::new(std::sync::RwLock::new(
        rugra::comment::CommentDatabaseInternal::new(),
    )));
    {
        let mut types = rugra::type_system::typefactory::TypeFactory::new(8);
        let data_org = cspec_root
            .read()
            .map_err(|_| "compiler spec element lock poisoned".to_string())?
            .children
            .iter()
            .find(|child| {
                child
                    .read()
                    .map(|element| element.name == "data_organization")
                    .unwrap_or(false)
            })
            .cloned()
            .ok_or_else(|| "compiler spec has no data_organization".to_string())?;
        let registry =
            std::sync::Arc::new(std::sync::RwLock::new(rugra::marshal::IdRegistry::new()));
        let mut decoder = rugra::marshal::TreeDecoder::new(data_org, registry);
        types.decode_data_organization(&mut decoder);
        types.setup_sizes(&rugra::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        arch.set_types(std::sync::Arc::new(std::sync::RwLock::new(types)));
    }
    let mut inject_lib =
        rugra::pcodeinject::PcodeInjectLibrary::new(SPEC_UNIQUE_INJECT_BASE);
    inject_lib.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(std::sync::Arc::new(std::sync::RwLock::new(inject_lib)));
    arch.userops = Some(std::sync::Arc::new(std::sync::RwLock::new(
        rugra::userop::UserOpManage::new(),
    )));
    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    if arch.defaultfp.is_none() {
        return Err("No default prototype specified".to_string());
    }
    Ok(arch)
}

fn vn_desc(vn: &std::sync::Arc<std::sync::RwLock<rugra::varnode::Varnode>>, depth: usize) -> String {
    let v = vn.read().unwrap();
    let mut s = format!(
        "[{}:0x{:x}:{} const={} input={} written={} spacebase={:?}]",
        v.get_space(),
        v.get_offset(),
        v.get_size(),
        v.is_constant(),
        v.is_input(),
        v.is_written(),
        v.is_spacebase()
    );
    if depth < 8 {
        if let Some(def_w) = v.def.as_ref().and_then(|w| w.upgrade()) {
            let d = def_w.read().unwrap();
            s.push_str(&format!(
                " = {:?}(",
                d.opcode
            ));
            let parts: Vec<String> = d
                .inrefs
                .iter()
                .map(|inv| vn_desc(inv, depth + 1))
                .collect();
            s.push_str(&parts.join(", "));
            s.push(')');
        }
    }
    s
}

/// Walk the def chain of vn looking for Register:offset. Depth-limited.
fn chain_has_reg(vn: &std::sync::Arc<std::sync::RwLock<rugra::varnode::Varnode>>, reg_off: u64, depth: usize) -> bool {
    if depth > 8 { return false; }
    let v = vn.read().unwrap();
    if v.get_space() == rugra::space::AddressSpace::Register && v.get_offset() == reg_off {
        return true;
    }
    if let Some(def_w) = v.def.as_ref().and_then(|w| w.upgrade()) {
        let d = def_w.read().unwrap();
        for inv in d.inrefs.iter() {
            if chain_has_reg(inv, reg_off, depth + 1) { return true; }
        }
    }
    false
}

fn main() -> anyhow::Result<()> {
    let buffer = std::fs::read("examples/httpd")?;
    let obj = goblin::Object::parse(&buffer)?;
    let elf = match &obj {
        goblin::Object::Elf(e) => e,
        _ => anyhow::bail!("not elf"),
    };

    let target: u64 = 0x2cf30;
    let size: usize = 203;
    let mut file_off = 0usize;
    for h in elf.section_headers.iter() {
        if target >= h.sh_addr && target < h.sh_addr + h.sh_size {
            file_off = (h.sh_offset + (target - h.sh_addr)) as usize;
            break;
        }
    }
    let code = &buffer[file_off..file_off + size];

    // SLEIGH-RUSTIFY-PHASE3-0001: canon-contract linear walk (the httpd
    // driver's lift_instruction_skip_nops padding filter) — the 203-byte
    // symbol window ends in a 7-byte `0f 1f 80` alignment NOP whose engine
    // operand pcode the canon path never injects.
    let raw_ops = rugra::disasm::sleigh_lift::sleigh_raw_ops_skip_nops(code, target);

    eprintln!("== raw lifted STORE/LOAD ops:");
    for op in raw_ops.iter() {
        let opc = OpCode::from_i32(op.get_opcode()).unwrap();
        if opc == OpCode::CPUI_STORE || opc == OpCode::CPUI_LOAD {
            let inputs = op
                .inputs()
                .iter()
                .map(|v| format!("{}:0x{:x}:{}", v.space, v.offset, v.size))
                .collect::<Vec<_>>()
                .join(",");
            eprintln!("  {:?} in=({inputs})", opc);
        }
    }

    let mut fd = Funcdata::new("ap_parse_vhost_addrs", Address::new(target), size as i32);
    // HTTPD-STACKSLOT-FOLD-0001 fixture runner: the shipped httpd runner
    // attaches the canonical Architecture (mirroring `glb =
    // scope->getArch()`, funcdata.cc:48) before the pipeline.
    // STACKFOLD-FIXTURE-F6DC-BREAK-0001: the original bare
    // Architecture::new() attach was cspec-less (defaultfp=None -> funcp
    // model-less), which f6dcbed0's faithful ActionRestrictLocal loop-2
    // port (coreaction.cc:1983-1985) turns into the fspec.rs:574 panic —
    // the oracle has no model-less path either (fspec.cc:4243-4247
    // dereferences the ctor-bound defaultfp unconditionally, so the
    // arch-less configuration segfaults there). Attach the canon httpd
    // cspec-bearing form instead (see model_bearing_architecture).
    // STACKFOLD_ARCH=0 keeps the model-less differential mode: under loop-2
    // it now stops at that same panic (the loop-1-era census-7 observation
    // is a pre-f6dcbed0 artifact and no longer reachable).
    if std::env::var("STACKFOLD_ARCH").map(|v| v != "0").unwrap_or(true) {
        let arch = model_bearing_architecture().map_err(anyhow::Error::msg)?;
        fd.set_arch(std::sync::Arc::new(arch));
    }
    fd.add_symbol(0x2ec00, "ap_getword_conf".into());
    fd.add_symbol(0x2c960, "FUN_0012c960".into());
    fd.inject_raw_ops(&raw_ops);

    {
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        db.apply_all(&mut fd)?;
    }

    eprintln!("\n== surviving STORE/LOAD ops after full pipeline:");
    let fdg = &fd;
    let mut n = 0;
    for op_ref in fdg.obank.iter_alive() {
        let op = op_ref.0.read().unwrap();
        if op.opcode == OpCode::CPUI_STORE || op.opcode == OpCode::CPUI_LOAD {
            n += 1;
            eprintln!("\n--- #{n} {:?} @ 0x{:x}", op.opcode, op.get_addr());
            if let Some(addr_vn) = op.inrefs.get(1) {
                eprintln!("  ptr chain: {}", vn_desc(addr_vn, 0));
            }
        }
    }
    eprintln!("\ntotal surviving LOAD/STORE: {n}");

    // HTTPD-STACKSLOT-FOLD-0001 regression assertion: with the canonical
    // Architecture attached, every spacebase-relative STORE/LOAD of
    // ap_parse_vhost_addrs folds into stack-space COPYs; the surviving
    // LOAD/STORE set must contain zero in_RSP(RSP=register:0x20)-chained
    // pointer. STACKFOLD-FIXTURE-F6DC-BREAK-0001 re-observation under the
    // canon cspec-bearing arch (loop-2 active): surviving=9 — the pinned
    // "surviving=1" was a loop-1-era, bare-Architecture observation
    // (no TypeFactory/casts, no effect walk); under the canonical
    // configuration the survivors are the param-register pointer chains
    // (in_RDX +0x30/+0x60, in_RSI +0x28 — the *param_1 + 0xNN deref forms
    // of the pinned rugra excerpt) plus RBP-derived stack-address values,
    // none RSP-chained. Pre-fix (arch-less) census was 7 with 7/7 in_RSP
    // chains (loop-1 era; arch-less is now the fspec.rs:574 model-less
    // panic under loop-2, mirroring the oracle's unconditional
    // effectBegin deref).
    if std::env::var("STACKFOLD_ARCH").map(|v| v != "0").unwrap_or(true) {
        let leak = fdg
            .obank
            .iter_alive()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_STORE || op.opcode == OpCode::CPUI_LOAD {
                    op.inrefs.get(1).cloned()
                } else {
                    None
                }
            })
            .filter(|addr_vn| chain_has_reg(addr_vn, 0x20, 0))
            .count();
        if n != 9 || leak != 0 {
            eprintln!(
                "STACKFOLD FIXTURE FAIL: surviving={n} in_RSP-chained={leak} (expected 9/0)"
            );
            std::process::exit(1);
        }
        eprintln!("STACKFOLD FIXTURE PASS: surviving={n} in_RSP-chained={leak}");
    }

    // Does an input RSP exist and is it spacebase-marked?
    for entry in fdg.vbank.loc_tree.iter() {
        let v = entry.0.read().unwrap();
        if v.get_space() == rugra::space::AddressSpace::Register
            && v.get_offset() == 0x20
            && v.get_size() == 8
        {
            eprintln!(
                "RSP vn: input={} spacebase={:?} written={} ndesc={}",
                v.is_input(),
                v.is_spacebase(),
                v.is_written(),
                v.descend.len()
            );
        }
    }
    Ok(())
}
