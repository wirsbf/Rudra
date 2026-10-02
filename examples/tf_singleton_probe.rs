//! tf_singleton_probe — TF-SINGLETON-WIRING-0001 第一步实证探针
//! （双二进制单进程 TypeFactory 泄漏 A/B）。
//!
//! 目的：在**同一进程**内顺序反编译两个二进制的函数，隔离
//! `TypeFactory::shared_default()` 进程单例（修复前形态）与
//! per-Architecture 工厂（修复后形态，`TypeFactory::fresh_canonical` +
//! `Architecture::set_types` 发布）的可观察差异：
//!
//!   - `--factory shared`：bin#1 与 bin#2 的所有 Architecture 共享一个
//!     进程级工厂（历史 bin_sweep/curl/httpd 驱动形态）。
//!   - `--factory fresh` ：每个函数一个 Architecture，各持**自己的**工厂
//!     （oracle 形态：sleigh_arch.cc:201 `types = new TypeFactory(this);`，
//!     生命周期 = Architecture 生命周期，architecture.cc:211-212）。
//!
//! 其余路径（函数发现/内存镜像/Architecture 构建/cspec dataorg decode/
//! 流/action/打印）两种模式逐字节同构——唯一轴 = 工厂来源。每个函数的
//! C 文本落盘 `f<b>_f<i>_<name>.c`，`summary.jsonl` 记录 sha256/字节/
//! 状态，供外部跨运行对比：
//!
//!   泄漏实证（修复前形态）: shared 模式 [bin1,bin2] 的 bin2 输出
//!     vs shared 模式 [bin2] 的 bin2 输出 —— 不同即跨二进制污染实证。
//!   闭合亲证（修复后形态）: fresh 模式 [bin1,bin2] 的 bin2 输出
//!     vs fresh 模式 [bin2] 的 bin2 输出 —— 必须恒等。
//!
//! 用法（repo 根运行，sleigh_specs/ 为 CWD 相对）：
//!   cargo run --profile fast-release --example tf_singleton_probe -- \
//!       --factory fresh --binaries examples/curl examples/httpd \
//!       --max-funcs 24 --out-dir /dev/shm/rudra-tests/tfsingle/probe-run

use goblin::Object;
use rudra::action::ActionDatabase;
use rudra::address::Address;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::funcdata::Funcdata;
use rudra::printc::PrintC;
use rudra::printlanguage::PrintLanguage;
use rudra::prettyprint::EmitPrettyPrint;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

const R_X86_64_GLOB_DAT: u32 = 1;
const R_X86_64_JUMP_SLOT: u32 = 7;
const PT_LOAD: u32 = 1;
const DEFAULT_MAX_FUNCS: usize = 24;
/// FUNCPROTO-MODEL-BIND-0001 (sweep-driver copy): locked x86-64
/// address-space facts for the spec host.
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
/// FUNCPROTO-MODEL-BIND-0001 (sweep-driver copy): Translate::getUniqueStart
/// for the locked x86-64 .sla (bin_sweep value).
const SPEC_UNIQUE_INJECT_BASE: u64 = 0x364_400;

// RUDRA-GLUE: one discovered decompilable unit (bin_sweep shape verbatim).
#[derive(Clone)]
struct GenFunction {
    vaddr: u64,
    name: String,
    size: usize,
}

// RUDRA-GLUE: probe row (out-dir summary.jsonl record).
#[derive(Serialize)]
struct ProbeRow {
    binary_index: usize,
    binary: String,
    func_index: usize,
    name: String,
    status: String, // ok | panic | error
    c_bytes: usize,
    sha256: String,
    ms: u64,
    panic_msg: String,
    err_msg: String,
}

// RUDRA-GLUE: BFD static/dynamic FUNC symbols + PLT JUMP_SLOT stubs,
// dedup by address, (offset, name) order (bin_sweep discover_functions
// verbatim — the gen_decompile bare-face contract).
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
                if !name.is_empty() {
                    register(stub, name.to_string(), 16);
                }
            }
        }
    }
    let mut functions: Vec<GenFunction> = by_addr.into_values().collect();
    functions.sort_by(|left, right| {
        left.vaddr
            .cmp(&right.vaddr)
            .then_with(|| left.name.cmp(&right.name))
    });
    functions
}

// RUDRA-GLUE: PT_LOAD vaddr-keyed memory image with import relocations
// applied (bin_sweep memory_image_bytes verbatim).
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

// FUNCPROTO-MODEL-BIND-0001 (sweep-driver copy): language host for the
// driver-side compiler-spec parse.
struct ProbeSpecHost {
    registers: HashMap<String, rudra::fspec::VarnodeData>,
}

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

impl rudra::arch::SpecQuery for ProbeSpecHost {
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
        SPEC_UNIQUE_INJECT_BASE
    }
}

impl rudra::pcodeparse::SleighSymbolLookup for ProbeSpecHost {
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

/// 工厂来源轴——本探针唯一参数化维度。
#[derive(Clone, Copy, PartialEq, Eq)]
enum FactoryMode {
    /// 修复前形态：进程级共享单例（历史驱动形态）。
    Shared,
    /// 修复后形态：每 Architecture 自己的工厂（oracle 形态）。
    Fresh,
}

// bin_sweep build_architecture 逐字同构，唯二差异：①工厂来源按
// FactoryMode 选择；②工厂取件后**立即** decode dataorg（保持两模式
// 工厂内容装配一致——差异只剩"是否跨 Architecture 共享"）。
// PERF-DUAL-SLEIGH-INIT-0001: also returns the register-catalog engine so
// decompile_to_text's lifter adopts it (SleighLifter::from_ctx) — the
// oracle's ONE translator per Architecture (sleigh_arch.cc:174
// buildTranslator reuse), not a second x86-64.sla deserialization.
fn build_architecture(
    loader: Option<Arc<dyn rudra::loadimage::LoadImage>>,
    mode: FactoryMode,
) -> Result<(Arc<rudra::arch::Architecture>, rudra::sleigh_ffi::SleighCtx), String> {
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
    let host = Arc::new(ProbeSpecHost { registers });
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
        .map_err(|_| "compiler spec element lock poisoned".to_string())?
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
    // ── 唯一轴:工厂来源 ──────────────────────────────────────────
    let types = match mode {
        FactoryMode::Shared => rudra::type_system::typefactory::TypeFactory::shared_default(),
        FactoryMode::Fresh => rudra::type_system::typefactory::TypeFactory::fresh_canonical(),
    };
    // ─────────────────────────────────────────────────────────────
    let data_org = root
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
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(SPEC_UNIQUE_INJECT_BASE);
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
            .map_err(|_| "processor spec element lock poisoned".to_string())?
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
                .map_err(|_| "processor spec element lock poisoned".to_string())?
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

// bin_sweep run_one 的文本产出形态（返回完整 C 文本而非长度）。
fn decompile_to_text(
    binary_path: &str,
    image: &[u8],
    functions: &[GenFunction],
    index: usize,
    mode: FactoryMode,
) -> Result<String, String> {
    let target = &functions[index];
    let loader: Arc<dyn rudra::loadimage::LoadImage> = Arc::new(
        rudra::loadimage::RawLoadImage::from_bytes(
            binary_path.rsplit('/').next().unwrap_or("probe"),
            0,
            image.to_vec(),
        ),
    );
    let (arch, sleigh_ctx) = build_architecture(Some(loader), mode)?;
    let func_size =
        i32::try_from(target.size).map_err(|_| format!("function {} is too large", target.name))?;
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
    let fd_arc = Arc::new(std::sync::RwLock::new(fd));
    fd_arc
        .write()
        .map_err(|_| "Funcdata write lock poisoned".to_string())?
        .set_self_ref(Arc::downgrade(&fd_arc));
    let mut db = ActionDatabase::new();
    db.set_default_actions();
    {
        let mut fd_write = fd_arc
            .write()
            .map_err(|_| "Funcdata write lock poisoned during analysis".to_string())?;
        db.perform_action("decompile", &mut fd_write)
            .map_err(|error| format!("action pipeline failed for {}: {error}", target.name))?;
    }
    let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
    printer.set_rpn_enabled(true);
    {
        let fd_read = fd_arc
            .read()
            .map_err(|_| "Funcdata read lock poisoned".to_string())?;
        printer.doc_function(&fd_read);
    }
    let output_buffer = printer
        .take_emit()
        .into_any()
        .downcast::<EmitPrettyPrint>()
        .map_err(|_| "PrintC returned an unexpected emitter type".to_string())?;
    Ok(output_buffer.get_output())
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let flag_value = |flag: &str| -> Option<String> {
        args.iter().position(|arg| arg == flag).map(|position| {
            args.get(position + 1)
                .cloned()
                .unwrap_or_default()
        })
    };
    let mode = match flag_value("--factory").as_deref() {
        Some("shared") => FactoryMode::Shared,
        Some("fresh") => FactoryMode::Fresh,
        other => {
            eprintln!("usage: tf_singleton_probe --factory shared|fresh --binaries <p1> [p2...] [--max-funcs N] --out-dir DIR");
            eprintln!("  (got --factory {other:?})");
            std::process::exit(2);
        }
    };
    let Some(out_dir) = flag_value("--out-dir") else {
        eprintln!("--out-dir is required");
        std::process::exit(2);
    };
    let max_funcs: usize = flag_value("--max-funcs")
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MAX_FUNCS);
    let Some(binaries_pos) = args.iter().position(|arg| arg == "--binaries") else {
        eprintln!("--binaries is required");
        std::process::exit(2);
    };
    let binaries: Vec<String> = args[binaries_pos + 1..]
        .iter()
        .take_while(|arg| !arg.starts_with("--"))
        .cloned()
        .collect();
    if binaries.is_empty() {
        eprintln!("--binaries needs at least one path");
        std::process::exit(2);
    }
    fs::create_dir_all(&out_dir).expect("create out-dir");

    // 256MB 大栈线程承载全部反编译（sweep_one 同款）；探针本体串行确定性。
    let out_dir_display = out_dir.clone();
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || run_probe(mode, &binaries, max_funcs, &out_dir))
        .expect("spawn probe thread");
    match handle.join() {
        Ok(count) => {
            eprintln!("[TFPROBE] {count} rows written to {out_dir_display}/summary.jsonl");
        }
        Err(payload) => {
            eprintln!("[TFPROBE] probe thread panicked: {payload:?}");
            std::process::exit(70);
        }
    }
}

fn run_probe(mode: FactoryMode, binaries: &[String], max_funcs: usize, out_dir: &str) -> usize {
    let mut rows: Vec<ProbeRow> = Vec::new();
    for (binary_index, binary_path) in binaries.iter().enumerate() {
        let buffer = match fs::read(binary_path) {
            Ok(buffer) => buffer,
            Err(error) => {
                eprintln!("[TFPROBE] cannot read {binary_path}: {error}");
                std::process::exit(64);
            }
        };
        let obj = match Object::parse(&buffer) {
            Ok(obj) => obj,
            Err(error) => {
                eprintln!("[TFPROBE] cannot parse {binary_path}: {error}");
                std::process::exit(64);
            }
        };
        let Object::Elf(elf) = &obj else {
            eprintln!("[TFPROBE] {binary_path} is not an ELF binary");
            std::process::exit(64);
        };
        let functions = discover_functions(elf);
        let image = memory_image_bytes(elf, &buffer);
        let selected = functions.len().min(max_funcs);
        eprintln!(
            "[TFPROBE] binary {binary_index} {} — {} functions discovered, first {selected} selected",
            binary_path.rsplit('/').next().unwrap_or(binary_path),
            functions.len()
        );
        for func_index in 0..selected {
            let started = std::time::Instant::now();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decompile_to_text(binary_path, &image, &functions, func_index, mode)
            }));
            let ms = started.elapsed().as_millis() as u64;
            let target = &functions[func_index];
            let mut row = ProbeRow {
                binary_index,
                binary: binary_path.clone(),
                func_index,
                name: target.name.clone(),
                status: "ok".to_string(),
                c_bytes: 0,
                sha256: String::new(),
                ms,
                panic_msg: String::new(),
                err_msg: String::new(),
            };
            match outcome {
                Ok(Ok(c_text)) => {
                    let trimmed = c_text.trim_end();
                    row.c_bytes = trimmed.len();
                    let file_name = format!(
                        "f{binary_index}_f{func_index}_{}.c",
                        sanitize_name(&target.name)
                    );
                    let file_path = format!("{out_dir}/{file_name}");
                    fs::write(&file_path, trimmed).expect("write probe output");
                    row.sha256 = sha256_hex(&file_path);
                }
                Ok(Err(error)) => {
                    row.status = "error".to_string();
                    row.err_msg = error.chars().take(240).collect();
                }
                Err(payload) => {
                    row.status = "panic".to_string();
                    row.panic_msg = panic_message(&payload).chars().take(240).collect();
                }
            }
            eprintln!(
                "[TFPROBE]   f{binary_index}/{func_index:03} {} [{}] {} bytes {}ms",
                target.name, row.status, row.c_bytes, row.ms
            );
            rows.push(row);
        }
    }
    let mut summary = String::new();
    for row in &rows {
        summary.push_str(&serde_json::to_string(row).unwrap_or_default());
        summary.push('\n');
    }
    fs::write(format!("{out_dir}/summary.jsonl"), summary).expect("write summary");
    rows.len()
}

// RUDRA-GLUE: panic payload to string (sweep_one payload_str shape).
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

// RUDRA-GLUE: sha256 via coreutils (bin_sweep sha256_of precedent — the
// sweep already shells out for cross-verification hashes).
fn sha256_hex(path: &str) -> String {
    std::process::Command::new("sha256sum")
        .arg(path)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .unwrap_or_default()
}
