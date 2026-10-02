//! HERMIT lane probe (PAREVAL-DETERM-HERMETICITY-0001): in-process
//! predecessor-dose driver for the sqlite3 shell_exec two-variant defect.
//!
//! Modes:
//!   --dose            Reproduce the PAREVAL dose ladder: for k in 0..=5
//!                     decompile predecessors {k..5} then shell_exec (f006)
//!                     in ONE process, print shell_exec's hash + variant.
//!                     Expect (archived evidence): k5=B k4=A k3=A k2=B
//!                     k1=A k0=A (A=9e5bc8ea B=afc7f416, 38491 bytes).
//!   --trace K         Dose-K run, then re-decompile shell_exec under a
//!                     breakpoint ladder over the top-level children of
//!                     the "decompile" action group. After each ladder
//!                     step the op fingerprint of the affected region
//!                     (SeqNum addr in [TRACE_LO, TRACE_HI]) is dumped:
//!                     block index, position in the block's op list,
//!                     SeqNum (addr, uniq), opcode, op Arc address and
//!                     output varnode identity. Diffing two traces
//!                     localizes the action where the two adjacent COPYs
//!                     swap order.
//!
//! The function selection replicates pareval_poc.rs verbatim (largest
//! first, ties by address, truncate to 8, then address order) so that
//! f006 == shell_exec of the archived evidence.

use goblin::Object;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use rudra::action::{break_flags, Action, ActionDatabase, ActionState};
use rudra::address::Address;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::funcdata::Funcdata;
use rudra::printc::PrintC;
use rudra::printlanguage::PrintLanguage;
use rudra::prettyprint::EmitPrettyPrint;

const R_X86_64_GLOB_DAT: u32 = 1;
const R_X86_64_JUMP_SLOT: u32 = 7;
const PT_LOAD: u32 = 1;
const STACK_BYTES: usize = 256 * 1024 * 1024;
const SHELL_EXEC_JOB: usize = 6;
const LAST_PREDECESSOR: usize = 5;
/// Region of the swapped zero-COPY statements (the `if (param_2 == 0)`
/// branch feeding `goto code_r0x00033e71`).
const TRACE_LO: u64 = 0x33e40;
const TRACE_HI: u64 = 0x33e80;

// ===========================================================================
// Function discovery + memory image — pareval_poc.rs verbatim
// ===========================================================================

#[derive(Clone)]
struct GenFunction {
    vaddr: u64,
    name: String,
    size: usize,
}

fn discover_functions(elf: &goblin::elf::Elf) -> Vec<GenFunction> {
    let mut by_addr: HashMap<u64, GenFunction> = HashMap::new();
    let mut register = |vaddr: u64, name: String, size: usize| {
        by_addr.entry(vaddr).or_insert_with(|| GenFunction {
            vaddr,
            name,
            size,
        });
    };
    for sym in elf.syms.iter() {
        if sym.st_shndx == 0 || !sym.is_function() {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                register(sym.st_value, name.to_string(), sym.st_size as usize);
            }
        }
    }
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx == 0 || !sym.is_function() {
            continue;
        }
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if !name.is_empty() {
                register(sym.st_value, name.to_string(), sym.st_size as usize);
            }
        }
    }
    let mut plt_sec_base = 0u64;
    let mut plt_sec_size = 0u64;
    let mut plt_base = 0u64;
    let mut plt_size = 0u64;
    for header in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
            if name == ".plt.sec" {
                plt_sec_base = header.sh_addr;
                plt_sec_size = header.sh_size;
            } else if name == ".plt" {
                plt_base = header.sh_addr;
                plt_size = header.sh_size;
            }
        }
    }
    for (index, reloc) in elf.pltrelocs.iter().enumerate() {
        if reloc.r_type != R_X86_64_JUMP_SLOT {
            continue;
        }
        let stub = if plt_sec_base != 0 && plt_sec_size >= (index as u64 + 1) * 16 {
            plt_sec_base + 16 * index as u64
        } else if plt_base != 0 && plt_size >= (index as u64 + 2) * 16 {
            plt_base + 16 * (index as u64 + 1)
        } else {
            continue;
        };
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() && !name.starts_with('_') {
                    register(stub, name.to_string(), 16);
                }
            }
        }
    }
    let mut functions: Vec<GenFunction> = by_addr.into_values().collect();
    functions.sort_by(|a, b| a.vaddr.cmp(&b.vaddr));
    functions
}

fn memory_image_bytes(elf: &goblin::elf::Elf, buffer: &[u8]) -> Vec<u8> {
    let mut top = 0usize;
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD {
            top = top.max((ph.p_vaddr as usize).saturating_add(ph.p_memsz as usize));
        }
    }
    let mut image = vec![0u8; top];
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD {
            let vaddr = ph.p_vaddr as usize;
            let src = buffer
                .get(
                    ph.p_offset as usize
                        ..(ph.p_offset as usize).saturating_add(ph.p_filesz as usize),
                )
                .unwrap_or(&[]);
            let dst_end = vaddr.saturating_add(src.len()).min(top);
            if vaddr < dst_end {
                image[vaddr..dst_end].copy_from_slice(&src[..dst_end - vaddr]);
            }
        }
    }
    const SHF_ALLOC: u64 = 0x2;
    let external_base = elf
        .section_headers
        .iter()
        .filter(|header| (header.sh_flags & SHF_ALLOC) != 0)
        .map(|header| header.sh_addr.saturating_add(header.sh_size))
        .max()
        .unwrap_or(0)
        .div_ceil(0x1000)
        * 0x1000;
    let mut external_slot_of: HashMap<&str, u64> = HashMap::new();
    for (index, sym) in elf.dynsyms.iter().enumerate() {
        if sym.st_shndx == 0 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    external_slot_of.insert(name, external_base + 8 * index as u64);
                }
            }
        }
    }
    let apply_import_reloc = |image: &mut [u8],
                              reloc_type: u32,
                              reloc_sym: usize,
                              reloc_offset: u64| {
        if reloc_type != R_X86_64_GLOB_DAT && reloc_type != R_X86_64_JUMP_SLOT {
            return;
        }
        let Some(sym) = elf.dynsyms.get(reloc_sym) else {
            return;
        };
        if sym.st_shndx != 0 {
            return; // Defined symbols keep their file values.
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            return;
        };
        let Some(&slot) = external_slot_of.get(name) else {
            return;
        };
        let offset = reloc_offset as usize;
        if let Some(bytes) = image.get_mut(offset..offset + 8) {
            bytes.copy_from_slice(&slot.to_le_bytes());
        }
    };
    for reloc in elf.pltrelocs.iter() {
        apply_import_reloc(&mut image, reloc.r_type, reloc.r_sym, reloc.r_offset);
    }
    for reloc in elf.dynrelas.iter() {
        apply_import_reloc(&mut image, reloc.r_type, reloc.r_sym, reloc.r_offset);
    }
    image
}

// ===========================================================================
// Spec host + architecture — pareval_poc.rs verbatim (isolated mode)
// ===========================================================================

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

fn spec_space_by_name(name: &str) -> Option<rudra::space::AddressSpace> {
    use rudra::space::AddressSpace;
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

struct SweepSpecHost {
    registers: HashMap<String, rudra::fspec::VarnodeData>,
}

impl rudra::arch::SpecQuery for SweepSpecHost {
    fn get_register(&self, name: &str) -> Option<rudra::fspec::VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<rudra::space::AddressSpace> {
        spec_space_by_name(name)
    }
    fn space_highest(&self, spc: rudra::space::AddressSpace) -> u64 {
        let name = match spc {
            rudra::space::AddressSpace::Const => "const",
            rudra::space::AddressSpace::Other(_) => "OTHER",
            rudra::space::AddressSpace::Unique => "unique",
            rudra::space::AddressSpace::Ram => "ram",
            rudra::space::AddressSpace::Register => "register",
            rudra::space::AddressSpace::Stack => "stack",
            rudra::space::AddressSpace::Iop => "iop",
            rudra::space::AddressSpace::Join => "join",
            rudra::space::AddressSpace::Overlay => "OTHER",
        };
        SPEC_SPACES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        0x364_400
    }
}

impl rudra::pcodeparse::SleighSymbolLookup for SweepSpecHost {
    fn find_symbol(&self, name: &str) -> Option<rudra::pcodeparse::SleighSymbol> {
        self.registers
            .get(name)
            .map(|vd| rudra::pcodeparse::SleighSymbol {
                name: name.to_string(),
                kind: rudra::pcodeparse::SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                    space: vd.space,
                    offset: vd.offset,
                    size: vd.size.max(0) as usize,
                }),
            })
    }
}

// PERF-DUAL-SLEIGH-INIT-0001: also returns the register-catalog engine so
// prepare_fd's lifter adopts it (SleighLifter::from_ctx) — the oracle's ONE
// translator per Architecture (sleigh_arch.cc:174 buildTranslator reuse),
// not a second x86-64.sla deserialization.
fn build_architecture(
    loader: Option<std::sync::Arc<dyn rudra::loadimage::LoadImage>>,
) -> Result<
    (
        std::sync::Arc<rudra::arch::Architecture>,
        rudra::sleigh_ffi::SleighCtx,
    ),
    String,
> {
    use std::sync::Arc;
    let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
        .map_err(|error| format!("unable to read compiler spec: {error}"))?;
    let sleigh = rudra::sleigh_ffi::SleighCtx::new()
        .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
    let mut registers: HashMap<String, rudra::fspec::VarnodeData> = HashMap::new();
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
            rudra::fspec::VarnodeData {
                space: rudra::space::AddressSpace::from_id(space_id),
                offset,
                size,
            },
        );
    }
    let host = Arc::new(SweepSpecHost { registers });
    let mut store = rudra::marshal::DocumentStorage::new();
    let doc = store
        .parse_document(&cspec_bytes)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    let root = doc
        .root
        .clone()
        .ok_or_else(|| "compiler spec has no root element".to_string())?;
    if root
        .read()
        .map_err(|_| "cspec element lock poisoned".to_string())?
        .name
        != "compiler_spec"
    {
        return Err("compiler spec root is not compiler_spec".to_string());
    }
    store.register_tag(&root);
    let mut arch = rudra::arch::Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    arch.set_register_xref(register_xref);
    arch.set_commentdb(Arc::new(std::sync::RwLock::new(
        rudra::comment::CommentDatabaseInternal::new(),
    )));
    // isolated factory mode (rugra_decompile_func shape) — the archived
    // dose evidence was collected in this mode.
    let types = Arc::new(std::sync::RwLock::new(
        rudra::type_system::typefactory::TypeFactory::new(8),
    ));
    let data_org = root
        .read()
        .map_err(|_| "cspec element lock poisoned".to_string())?
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
    let registry = Arc::new(std::sync::RwLock::new(rudra::marshal::IdRegistry::new()));
    let mut decoder = rudra::marshal::TreeDecoder::new(data_org, registry);
    types
        .write()
        .map_err(|_| "cspec factory lock poisoned".to_string())?
        .decode_data_organization(&mut decoder);
    types
        .write()
        .map_err(|_| "cspec factory lock poisoned".to_string())?
        .setup_sizes(&rudra::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
    arch.set_types(Arc::clone(&types));
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(0x364_400);
    inject_lib.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(Arc::new(std::sync::RwLock::new(inject_lib)));
    arch.userops = Some(Arc::new(std::sync::RwLock::new(
        rudra::userop::UserOpManage::new(),
    )));
    let pspec_bytes = fs::read("sleigh_specs/x86-64.pspec")
        .map_err(|error| format!("unable to read processor spec: {error}"))?;
    let pspec_doc = store
        .parse_document(&pspec_bytes)
        .map_err(|error| format!("processor spec parse failed: {error}"))?;
    let pspec_root = pspec_doc
        .root
        .clone()
        .ok_or_else(|| "processor spec has no root element".to_string())?;
    {
        let children: Vec<_> = pspec_root
            .read()
            .map_err(|_| "pspec element lock poisoned".to_string())?
            .children
            .iter()
            .map(|child| {
                child
                    .read()
                    .map(|element| element.name.clone())
                    .unwrap_or_default()
            })
            .collect();
        for (position, name) in children.iter().enumerate() {
            let child = pspec_root
                .read()
                .map_err(|_| "pspec element lock poisoned".to_string())?
                .children
                .get(position)
                .cloned()
                .ok_or_else(|| "processor spec child vanished".to_string())?;
            match name.as_str() {
                "context_data" => {
                    let pspec_registry =
                        Arc::new(std::sync::RwLock::new(rudra::marshal::IdRegistry::new()));
                    let mut decoder = rudra::marshal::TreeDecoder::new(child, pspec_registry);
                    arch.decode_context_data(&mut decoder, host.as_ref())
                        .map_err(|error| format!("processor spec context_data decode failed: {error}"))?;
                }
                "register_data" => {
                    let pspec_registry =
                        Arc::new(std::sync::RwLock::new(rudra::marshal::IdRegistry::new()));
                    let mut decoder = rudra::marshal::TreeDecoder::new(child, pspec_registry);
                    arch.decode_register_data(&mut decoder, host.as_ref())
                        .map_err(|error| format!("processor spec register_data decode failed: {error}"))?;
                }
                _ => {}
            }
        }
    }
    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    if arch.defaultfp.is_none() {
        return Err("No default prototype specified".to_string());
    }
    if let Some(loader) = loader {
        arch.loader = Some(loader);
        arch.build_string_manager();
    }
    Ok((Arc::new(arch), sleigh))
}

// ===========================================================================
// Per-function decompile — pareval_poc.rs decompile_one (isolated mode),
// plus an IR-building entry that stops before the action pipeline.
// ===========================================================================

fn prepare_fd(
    image: &[u8],
    image_name: &str,
    target: &GenFunction,
    functions: &[GenFunction],
) -> Result<Funcdata, String> {
    let loader: std::sync::Arc<dyn rudra::loadimage::LoadImage> =
        std::sync::Arc::new(rudra::loadimage::RawLoadImage::from_bytes(
            image_name,
            0,
            image.to_vec(),
        ));
    let (arch, sleigh_ctx) = build_architecture(Some(loader))?;
    let func_size = i32::try_from(target.size).map_err(|_| "function too large".to_string())?;
    let mut fd = Funcdata::new(&target.name, Address::new(target.vaddr), func_size);
    fd.set_arch(arch);
    for function in functions {
        fd.add_symbol(function.vaddr, function.name.clone());
    }
    // PERF-DUAL-SLEIGH-INIT-0001: adopt the register-catalog engine
    // (single .sla load; oracle sleigh_arch.cc:174 buildTranslator reuses
    // the one translator per languageindex). Catalog leg was read-only.
    let mut sleigh = SleighLifter::from_ctx(sleigh_ctx);
    sleigh
        .configure_x86_64(image, 0)
        .map_err(|error| format!("failed to configure SLEIGH: {error}"))?;
    let empty_protos = std::collections::BTreeMap::new();
    rudra::flow::follow_flow_range(&mut fd, &mut sleigh, 0, u64::MAX, &empty_protos)
        .map_err(|error| format!("flow generation failed for {}: {error}", target.name))?;
    Ok(fd)
}

fn decompile_one(image: &[u8], image_name: &str, target: &GenFunction, functions: &[GenFunction]) -> Result<String, String> {
    let mut fd = prepare_fd(image, image_name, target, functions)?;
    let mut db = ActionDatabase::new();
    db.set_default_actions();
    db.perform_action("decompile", &mut fd)
        .map_err(|error| format!("action pipeline failed for {}: {error}", target.name))?;
    let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
    printer.set_rpn_enabled(true);
    printer.doc_function(&fd);
    let output_buffer = printer
        .take_emit()
        .into_any()
        .downcast::<EmitPrettyPrint>()
        .expect("PrintC returned an unexpected emitter type");
    Ok(output_buffer.get_output().trim_end().to_string())
}

fn hash_text(text: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for byte in text.as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ===========================================================================
// Dump mode: the --dose ladder on the MAIN thread (the protocol that
// reliably reproduces the two variants), but the shell_exec decompile
// returns its Funcdata and the FULL final state of the SAME fd that
// produced the text is dumped: basic-block graph (indices, edges, ops
// with SeqNum/inputs/output) + structured tree (all ops, leaf order).
// No ladder re-runs, no thread spawn — zero perturbation of the run
// under observation (the dump allocations happen after each text is
// captured and affect only later doses, deterministically).
// ===========================================================================

fn decompile_shell_with_fd(
    image: &[u8],
    image_name: &str,
    target: &GenFunction,
    functions: &[GenFunction],
) -> Result<(String, Funcdata), String> {
    let mut fd = prepare_fd(image, image_name, target, functions)?;
    let mut db = ActionDatabase::new();
    db.set_default_actions();
    db.perform_action("decompile", &mut fd)
        .map_err(|error| format!("action pipeline failed for {}: {error}", target.name))?;
    let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
    printer.set_rpn_enabled(true);
    printer.doc_function(&fd);
    let output_buffer = printer
        .take_emit()
        .into_any()
        .downcast::<EmitPrettyPrint>()
        .expect("PrintC returned an unexpected emitter type");
    Ok((output_buffer.get_output().trim_end().to_string(), fd))
}

fn varnode_desc(vn: &Arc<std::sync::RwLock<rudra::varnode::Varnode>>) -> String {
    let v = vn.read().unwrap();
    format!("{:?}:{:x}:{}", v.get_space(), v.get_offset(), v.get_size())
}

fn dump_full_state(fd: &Funcdata, out_dir: &PathBuf, tag: &str) {
    let mut ir = String::new();
    let blocks = fd.get_basic_blocks();
    for (bi, block_arc) in blocks.blocks.iter().enumerate() {
        let guard = block_arc.read().unwrap();
        let idx = guard.get_index();
        let mut outs = Vec::new();
        for slot in 0..guard.size_out() {
            match guard.get_out(slot) {
                Some(e) => {
                    // ARENAFLIP-(e): edge points are bank ids — resolve the
                    // peer index through the owning graph's bank.
                    outs.push(format!(
                        "{}:f{}/r{}",
                        fd.bblocks.bank.expect_index(e.point),
                        e.flags,
                        e.reverse_index
                    ));
                }
                None => outs.push("NONE".to_string()),
            }
        }
        let ops = guard.get_ops();
        ir.push_str(&format!(
            "blk {:03} idx={} outs=[{}] nops={}\n",
            bi,
            idx,
            outs.join(","),
            ops.len()
        ));
        for (pos, op_ref) in ops.iter().enumerate() {
            let op = op_ref.0.read().unwrap();
            let seq = op.get_seq_num();
            let ins: Vec<String> = (0..op.num_input())
                .map(|i| {
                    op.get_in(i)
                        .map(varnode_desc)
                        .unwrap_or_else(|| "-".to_string())
                })
                .collect();
            let out = op
                .get_out()
                .map(varnode_desc)
                .unwrap_or_else(|| "-".to_string());
            ir.push_str(&format!(
                "  [{:03}] seq={:x}/{} {} out={} in=[{}]\n",
                pos,
                seq.get_addr().as_u64(),
                seq.get_time(),
                opcode_name(op.get_opcode()),
                out,
                ins.join(",")
            ));
        }
    }
    fs::write(out_dir.join(format!("dump-{tag}-ir.txt")), ir).ok();

    let mut sb: Vec<String> = Vec::new();
    structured_full_dump(fd, &mut sb);
    fs::write(
        out_dir.join(format!("dump-{tag}-sblocks.txt")),
        sb.join("\n"),
    )
    .ok();
}

/// Full structured-tree dump: every node type, every leaf's ops, in the
/// exact order the print dispatcher reaches them.
fn structured_full_dump(fd: &Funcdata, out: &mut Vec<String>) {
    fn walk(
        bl: &Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
        path: &str,
        out: &mut Vec<String>,
    ) {
        use rudra::block::BlockType;
        let rg = bl.read().unwrap();
        match rg.get_type() {
            BlockType::Graph | BlockType::List => {
                let children: Vec<_> = rg
                    .as_any()
                    .downcast_ref::<rudra::block::BlockGraph>()
                    .map(|g| g.blocks.clone())
                    .or_else(|| {
                        rg.as_any()
                            .downcast_ref::<rudra::block::BlockList>()
                            .map(|l| l.children.clone())
                    })
                    .unwrap_or_default();
                out.push(format!(
                    "{} {} nchild={}",
                    path,
                    if matches!(rg.get_type(), BlockType::Graph) {
                        "graph"
                    } else {
                        "list"
                    },
                    children.len()
                ));
                for (i, c) in children.iter().enumerate() {
                    walk(c, &format!("{}.{:02}", path, i), out);
                }
            }
            BlockType::If => {
                if let Some(bif) = rg.as_any().downcast_ref::<rudra::block::BlockIf>() {
                    out.push(format!("{path} if"));
                    walk(&bif.condition, &format!("{path}.c"), out);
                    walk(&bif.if_body, &format!("{path}.t"), out);
                    if let Some(eb) = &bif.else_body {
                        walk(eb, &format!("{path}.e"), out);
                    }
                }
            }
            BlockType::Goto | BlockType::MultiGoto => {
                if let Some(g) = rg.as_any().downcast_ref::<rudra::block::BlockGoto>() {
                    out.push(format!("{path} goto"));
                    if let Some(w) = &g.wrapped {
                        walk(w, &format!("{path}.w"), out);
                    }
                }
            }
            BlockType::DoWhile => {
                if let Some(dw) = rg.as_any().downcast_ref::<rudra::block::BlockDoWhile>() {
                    out.push(format!("{path} dowhile"));
                    walk(&dw.condition, &format!("{path}.c"), out);
                }
            }
            BlockType::WhileDo => {
                if let Some(wd) = rg.as_any().downcast_ref::<rudra::block::BlockWhileDo>() {
                    out.push(format!("{path} whiledo"));
                    walk(&wd.condition, &format!("{path}.c"), out);
                    walk(&wd.body, &format!("{path}.b"), out);
                }
            }
            BlockType::Switch => {
                if let Some(sw) = rg.as_any().downcast_ref::<rudra::block::BlockSwitch>() {
                    out.push(format!("{path} switch ncase={}", sw.cases.len()));
                    walk(&sw.control, &format!("{path}.k"), out);
                    for (i, c) in sw.cases.iter().enumerate() {
                        walk(c, &format!("{path}.s{:02}", i), out);
                    }
                }
            }
            BlockType::Basic | BlockType::Copy | BlockType::Plain | BlockType::Condition
            | BlockType::InfLoop => {
                let idx = rg.get_index();
                let ops = rg.get_ops();
                out.push(format!(
                    "{} leaf idx={} type={:?} nops={}",
                    path,
                    idx,
                    rg.get_type(),
                    ops.len()
                ));
                for (pos, op_ref) in ops.iter().enumerate() {
                    let op = op_ref.0.read().unwrap();
                    let seq = op.get_seq_num();
                    let ins: Vec<String> = (0..op.num_input())
                        .map(|i| {
                            op.get_in(i)
                                .map(varnode_desc)
                                .unwrap_or_else(|| "-".to_string())
                        })
                        .collect();
                    let out_vn = op
                        .get_out()
                        .map(varnode_desc)
                        .unwrap_or_else(|| "-".to_string());
                    out.push(format!(
                        "{}   [{:03}] seq={:x}/{} {} out={} in=[{}]",
                        path,
                        pos,
                        seq.get_addr().as_u64(),
                        seq.get_time(),
                        opcode_name(op.get_opcode()),
                        out_vn,
                        ins.join(",")
                    ));
                }
            }
        }
    }
    for (i, root) in fd.sblocks.blocks.iter().enumerate() {
        walk(root, &format!("r{:02}", i), out);
    }
}

// ===========================================================================
// Trace mode: breakpoint ladder over the top-level children of the
// "decompile" action group + region fingerprint.
// ===========================================================================

fn opcode_name(opc: rudra::opcodes::OpCode) -> String {
    format!("{:?}", opc)
}

/// `--at 12.3` → descend into top child 12, sub child 3 (empty = root).
fn trace_path() -> Vec<usize> {
    let argv: Vec<String> = std::env::args().collect();
    let mut path = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        if argv[i] == "--at" {
            i += 1;
            if let Some(spec) = argv.get(i) {
                for part in spec.split('.') {
                    if let Ok(v) = part.parse() {
                        path.push(v);
                    }
                }
            }
        }
        i += 1;
    }
    path
}

/// Compact fingerprint of every op whose SeqNum addr is in [TRACE_LO,
/// TRACE_HI): where does it live (block index + position in the block's op
/// list), its SeqNum (addr, uniq), its opcode, its Arc address and output
/// varnode Arc address.
fn region_fingerprint(fd: &Funcdata) -> Vec<String> {
    let mut lines = Vec::new();
    let blocks = fd.get_basic_blocks();
    for (bi, block_arc) in blocks.blocks.iter().enumerate() {
        let guard = block_arc.read().unwrap();
        let ops = guard.get_ops();
        for (pos, op_ref) in ops.iter().enumerate() {
            let op = op_ref.0.read().unwrap();
            let seq = op.get_seq_num();
            let addr = seq.get_addr().as_u64();
            if addr < TRACE_LO || addr >= TRACE_HI {
                continue;
            }
            let out = op
                .get_out()
                .map(|vn| {
                    let v = vn.read().unwrap();
                    format!(
                        "{:?}:{:x}:{}@{:p}",
                        v.get_space(),
                        v.get_offset(),
                        v.get_size(),
                        Arc::as_ptr(vn)
                    )
                })
                .unwrap_or_else(|| "-".to_string());
            lines.push(format!(
                "blk{:03}[{:02}] seq={:x}/{} opc={} op@{:p} out={}",
                bi,
                pos,
                addr,
                seq.get_time(),
                opcode_name(op.get_opcode()),
                Arc::as_ptr(&op_ref.0),
                out
            ));
        }
    }
    lines
}

/// Structured-tree region fingerprint: walk fd.sblocks the way the print
/// dispatcher does (Graph/List children, If cond/body/else, Goto wrapped,
/// WhileDo cond/body, DoWhile cond, Switch control/cases) and print the
/// region ops in the order the leaves are reached. This is the order the
/// printer actually emits statements in.
fn structured_region_fingerprint(fd: &Funcdata, out: &mut Vec<String>) {
    fn walk(
        bl: &std::sync::Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
        path: &str,
        out: &mut Vec<String>,
    ) {
        use rudra::block::BlockType;
        let rg = bl.read().unwrap();
        match rg.get_type() {
            BlockType::Graph | BlockType::List => {
                let children: Vec<_> = rg
                    .as_any()
                    .downcast_ref::<rudra::block::BlockGraph>()
                    .map(|g| g.blocks.clone())
                    .or_else(|| {
                        rg.as_any()
                            .downcast_ref::<rudra::block::BlockList>()
                            .map(|l| l.children.clone())
                    })
                    .unwrap_or_default();
                for (i, c) in children.iter().enumerate() {
                    walk(c, &format!("{}.{:02}", path, i), out);
                }
            }
            BlockType::If => {
                if let Some(bif) = rg.as_any().downcast_ref::<rudra::block::BlockIf>() {
                    walk(&bif.condition, &format!("{}.c", path), out);
                    walk(&bif.if_body, &format!("{}.t", path), out);
                    if let Some(eb) = &bif.else_body {
                        walk(eb, &format!("{}.e", path), out);
                    }
                }
            }
            BlockType::Goto => {
                if let Some(g) = rg.as_any().downcast_ref::<rudra::block::BlockGoto>() {
                    if let Some(w) = &g.wrapped {
                        walk(w, &format!("{}.w", path), out);
                    }
                }
            }
            BlockType::DoWhile => {
                if let Some(dw) = rg.as_any().downcast_ref::<rudra::block::BlockDoWhile>() {
                    walk(&dw.condition, &format!("{}.c", path), out);
                }
            }
            BlockType::WhileDo => {
                if let Some(wd) = rg.as_any().downcast_ref::<rudra::block::BlockWhileDo>() {
                    walk(&wd.condition, &format!("{}.c", path), out);
                    walk(&wd.body, &format!("{}.b", path), out);
                }
            }
            BlockType::Switch => {
                if let Some(sw) = rg.as_any().downcast_ref::<rudra::block::BlockSwitch>() {
                    walk(&sw.control, &format!("{}.k", path), out);
                    for (i, c) in sw.cases.iter().enumerate() {
                        walk(c, &format!("{}.s{:02}", path, i), out);
                    }
                }
            }
            BlockType::Basic | BlockType::Copy => {
                for (pos, op_ref) in rg.get_ops().iter().enumerate() {
                    let op = op_ref.0.read().unwrap();
                    let seq = op.get_seq_num();
                    let addr = seq.get_addr().as_u64();
                    if addr < TRACE_LO || addr >= TRACE_HI {
                        continue;
                    }
                    let out_desc = op
                        .get_out()
                        .map(|vn| {
                            let v = vn.read().unwrap();
                            format!("{:?}:{:x}:{}", v.get_space(), v.get_offset(), v.get_size())
                        })
                        .unwrap_or_else(|| "-".to_string());
                    out.push(format!(
                        "struct{}[{:02}] seq={:x}/{} opc={} out={}",
                        path,
                        pos,
                        addr,
                        seq.get_time(),
                        opcode_name(op.get_opcode()),
                        out_desc
                    ));
                }
            }
            _ => {}
        }
    }
    for (i, root) in fd.sblocks.blocks.iter().enumerate() {
        walk(root, &format!("r{:02}", i), out);
    }
}

fn run_trace(
    image: &[u8],
    image_name: &str,
    functions: &[GenFunction],
    dose_k: usize,
    out_dir: &PathBuf,
    at: Vec<usize>,
) {
    // Replay the FULL cumulative --dose ladder prefix (j = 6 down to
    // dose_k+1, each dose = predecessors {j..5} then shell_exec) so the
    // trace history is byte-identical to the dose run that reproduces the
    // two variants. A bare {k..5} prefix does NOT reproduce the flip.
    for j in (dose_k + 1..=6).rev() {
        if j <= LAST_PREDECESSOR {
            for idx in j..=LAST_PREDECESSOR {
                let text = decompile_one(image, image_name, &functions[idx], functions)
                    .unwrap_or_else(|error| panic!("history predecessor f{idx} failed: {error}"));
                eprintln!(
                    "[TRACE] history dose j={} pred f{:03} {} fnv={:016x}",
                    j,
                    idx,
                    functions[idx].name,
                    hash_text(&text)
                );
            }
        }
        let text = decompile_one(image, image_name, &functions[SHELL_EXEC_JOB], functions)
            .unwrap_or_else(|error| panic!("history shell_exec failed: {error}"));
        eprintln!("[TRACE] history dose j={} shell_exec fnv={:016x}", j, hash_text(&text));
    }
    // Dose predecessors for the target k.
    for idx in dose_k..=LAST_PREDECESSOR {
        let text = decompile_one(image, image_name, &functions[idx], functions)
            .unwrap_or_else(|error| panic!("predecessor f{idx} failed: {error}"));
        eprintln!("[TRACE] dose predecessor f{:03} {} -> fnv {:016x}", idx, functions[idx].name, hash_text(&text));
    }
    // Full pipeline reference run.
    let text = decompile_one(image, image_name, &functions[SHELL_EXEC_JOB], functions)
        .unwrap_or_else(|error| panic!("shell_exec failed: {error}"));
    fs::write(out_dir.join(format!("trace-k{}-final.c", dose_k)), &text).ok();
    eprintln!(
        "[TRACE] k={} shell_exec fnv={:016x} len={}",
        dose_k,
        hash_text(&text),
        text.len()
    );

    // Ladder: break at start of child i of the node selected by `at`
    // (empty path = the decompile root), run until the break fires (all
    // earlier children completed), dump region state.
    let mut db = ActionDatabase::new();
    db.set_default_actions();
    let root = db.get_action_mut("decompile").expect("decompile action");
    let mut node = root.as_action_group_mut().expect("root group");
    for &step in &at {
        node = node.child_actions_mut()[step]
            .as_action_group_mut()
            .expect("sub node is not an ActionGroup");
    }
    let num_children = node.num_actions();
    eprintln!(
        "[TRACE] selected node (path={:?}) has {} children {:?}",
        at,
        num_children,
        node.child_names()
    );
    for child in 0..num_children {
        let mut fd = prepare_fd(image, image_name, &functions[SHELL_EXEC_JOB], functions)
            .unwrap_or_else(|error| panic!("prepare failed: {error}"));
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let root = db.get_action_mut("decompile").expect("decompile action");
        let mut node = root.as_action_group_mut().expect("root group");
        for &step in &at {
            node = node.child_actions_mut()[step]
                .as_action_group_mut()
                .expect("sub node is not an ActionGroup");
        }
        // Sticky start breakpoint ONLY on child `child` (survives reset).
        node.child_state_mut(child)
            .expect("child state")
            .set_break(break_flags::BREAK_START);
        drop(node);
        let root = db.get_action_mut("decompile").expect("decompile action");
        root.reset(&mut fd);
        let mut state = ActionState::new(root.get_flags());
        let result = root.perform(&mut fd, &mut state);
        let region = region_fingerprint(&fd);
        // Print the C text AT THIS LADDER STOP (fresh PrintC, same face as
        // the reference run) so text-level divergence localizes the child
        // even when the bblocks fingerprint is blind to it (structured-tree
        // or print-time state).
        let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
        printer.set_rpn_enabled(true);
        printer.doc_function(&fd);
        let ladder_text = printer
            .take_emit()
            .into_any()
            .downcast::<EmitPrettyPrint>()
            .expect("PrintC returned an unexpected emitter type")
            .get_output()
            .trim_end()
            .to_string();
        eprintln!(
            "[TRACE] ladder {:02} result={:?} ops_in_region={} blocks={} text_fnv={:016x} len={}",
            child,
            result,
            region.len(),
            fd.get_basic_blocks().blocks.len(),
            hash_text(&ladder_text),
            ladder_text.len()
        );
        fs::write(out_dir.join(format!("ladder-k{:02}-s{:02}.c", dose_k, child)), &ladder_text).ok();
        for line in &region {
            eprintln!("[TRACE]   {}", line);
        }
        let mut struct_lines = Vec::new();
        structured_region_fingerprint(&fd, &mut struct_lines);
        eprintln!("[TRACE] structured region ops={}", struct_lines.len());
        for line in &struct_lines {
            eprintln!("[TRACE]  S {}", line);
        }
    }
}

// ===========================================================================
// main
// ===========================================================================

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut mode_dose = false;
    let mut mode_dump = false;
    let mut trace_k: Option<usize> = None;
    let mut out_dir = PathBuf::from("/dev/shm/rugra-tests/hermit");
    let mut binary = String::new();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--dose" => mode_dose = true,
            "--dump" => mode_dump = true,
            "--trace" => {
                i += 1;
                trace_k = Some(
                    argv.get(i)
                        .and_then(|v| v.parse().ok())
                        .expect("--trace needs a dose k"),
                );
            }
            "--at" => {
                i += 1; // value consumed by trace_path()
            }
            "--out-dir" => {
                i += 1;
                out_dir = PathBuf::from(argv.get(i).expect("--out-dir needs a path"));
            }
            other => binary = other.to_string(),
        }
        i += 1;
    }
    if std::env::args().any(|a| a == "--tree") {
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let root = db.get_action_mut("decompile").expect("decompile action");
        let group = root.as_action_group().expect("root group");
        for (i, name) in group.child_names().iter().enumerate() {
            println!("child {:02} {}", i, name);
        }
        return;
    }
    if binary.is_empty() || (!mode_dose && !mode_dump && trace_k.is_none()) {
        eprintln!(
            "usage: hermit_probe <binary> --dose | --dump | --trace K [--out-dir DIR] | --tree"
        );
        std::process::exit(2);
    }
    fs::create_dir_all(&out_dir).ok();

    let buffer = fs::read(&binary).expect("read binary");
    let obj = Object::parse(&buffer).expect("parse binary");
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => panic!("not an ELF binary"),
    };
    let image = memory_image_bytes(elf, &buffer);
    let image_name = binary.rsplit('/').next().unwrap_or("corpus").to_string();
    let mut functions = discover_functions(elf);
    functions.sort_by(|a, b| {
        b.size
            .cmp(&a.size)
            .then(a.vaddr.cmp(&b.vaddr))
            .then(a.name.cmp(&b.name))
    });
    functions.truncate(48);
    // Drop the pathological indexes in the POST-SELECTION index space
    // (pareval_poc --skip 8,24,30: do_meta_command, sqlite3VdbeExec,
    // sqlite3Parser), then execute in address order.
    let mut kept: Vec<GenFunction> = Vec::new();
    for (idx, f) in functions.into_iter().enumerate() {
        if idx == 8 || idx == 24 || idx == 30 {
            continue;
        }
        kept.push(f);
    }
    let mut functions = kept;
    functions.sort_by(|a, b| a.vaddr.cmp(&b.vaddr).then(a.name.cmp(&b.name)));
    for (idx, f) in functions.iter().enumerate() {
        eprintln!("[HERMIT] f{:03} {} @ {:x} ({} B)", idx, f.name, f.vaddr, f.size);
    }
    assert_eq!(functions[SHELL_EXEC_JOB].name, "shell_exec", "f006 must be shell_exec");

    if std::env::args().any(|a| a == "--tree") {
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let root = db.get_action_mut("decompile").expect("decompile action");
        let group = root.as_action_group().expect("root group");
        for (i, name) in group.child_names().iter().enumerate() {
            println!("child {:02} {}", i, name);
        }
        return;
    }

    if mode_dose || mode_dump {
        // Dose ladder, each dose in this ONE process (the hermeticity
        // violation surface). k = first predecessor index ({k..5} then
        // shell_exec); k = 6 -> no predecessors.
        for k in (0..=6).rev() {
            if k <= LAST_PREDECESSOR {
                for idx in k..=LAST_PREDECESSOR {
                    let text = decompile_one(&image, &image_name, &functions[idx], &functions)
                        .unwrap_or_else(|error| panic!("predecessor f{idx} failed: {error}"));
                    eprintln!(
                        "[DOSE] k={} pred f{:03} {} fnv={:016x} len={}",
                        k,
                        idx,
                        functions[idx].name,
                        hash_text(&text),
                        text.len()
                    );
                }
            }
            if mode_dump {
                let (text, fd) =
                    decompile_shell_with_fd(&image, &image_name, &functions[SHELL_EXEC_JOB], &functions)
                        .expect("shell_exec decompile");
                let h = hash_text(&text);
                fs::write(out_dir.join(format!("dose-k{k}-hermit.c")), &text).ok();
                dump_full_state(&fd, &out_dir, &format!("k{k}"));
                eprintln!("[DOSE] k={} shell_exec fnv={:016x} len={}", k, h, text.len());
                println!("k={} fnv={:016x} len={}", k, h, text.len());
            } else {
                let text = decompile_one(&image, &image_name, &functions[SHELL_EXEC_JOB], &functions)
                    .expect("shell_exec decompile");
                let h = hash_text(&text);
                fs::write(out_dir.join(format!("dose-k{}-hermit.c", k)), &text).ok();
                eprintln!("[DOSE] k={} shell_exec fnv={:016x} len={}", k, h, text.len());
                println!("k={} fnv={:016x} len={}", k, h, text.len());
            }
        }
        return;
    }

    if let Some(k) = trace_k {
        let child = thread::Builder::new()
            .stack_size(STACK_BYTES)
            .spawn(move || run_trace(&image, &image_name, &functions, k, &out_dir, trace_path()))
            .expect("spawn trace thread");
        child.join().expect("trace thread panicked");
    }
}
