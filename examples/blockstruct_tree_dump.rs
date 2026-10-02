//! Structure-tree dumper for BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001 diagnosis.
//!
//! Decompile ONE function (same setup as rugra_decompile_func.rs) and dump the
//! final structured tree (fd.sblocks) recursively to stderr: node index, block
//! type, address range, and for unstructured nodes (BlockGoto / if-goto) the
//! target address + goto_type + precomputed prints flag.
//!
//! Usage:
//!   cargo run --profile fast-release --example blockstruct_tree_dump -- <binary> <name_or_addr>

use goblin::Object;
use std::collections::HashMap;
use std::fs;

use rudra::action::ActionDatabase;
use rudra::address::Address;
use rudra::block::{BlockGraph, BlockType, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::printc::PrintC;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printlanguage::PrintLanguage;

type DynBlock = std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;

fn resolve_target(
    elf: &goblin::elf::Elf,
    spec: &str,
) -> Option<(u64, usize, u64, String)> {
    let as_addr = spec
        .strip_prefix("0x")
        .or_else(|| spec.strip_prefix("0X"))
        .unwrap_or(spec);
    if let Ok(addr) = u64::from_str_radix(as_addr, 16) {
        for sym in elf.syms.iter() {
            if sym.st_value == addr && sym.st_size != 0 {
                if let Some(off) = file_offset_for(elf, sym.st_value) {
                    return Some((addr, sym.st_size as usize, off, spec.to_string()));
                }
            }
        }
    }
    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .or_else(|| elf.dynstrtab.get_at(sym.st_name));
        if let Some(n) = name {
            if n == spec {
                if let Some(off) = file_offset_for(elf, sym.st_value) {
                    return Some((sym.st_value, sym.st_size as usize, off, n.to_string()));
                }
            }
        }
    }
    None
}

fn file_offset_for(elf: &goblin::elf::Elf, vaddr: u64) -> Option<u64> {
    for header in elf.section_headers.iter() {
        if vaddr >= header.sh_addr && vaddr < header.sh_addr + header.sh_size {
            return Some(header.sh_offset + (vaddr - header.sh_addr));
        }
    }
    None
}

fn build_tables(
    elf: &goblin::elf::Elf,
    buffer: &[u8],
) -> (HashMap<u64, String>, HashMap<u64, String>) {
    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();
    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sym.st_value != 0 {
            if let Some(name) = elf
                .strtab
                .get_at(sym.st_name)
                .or_else(|| elf.dynstrtab.get_at(sym.st_name))
            {
                if !name.is_empty() {
                    symbol_table.insert(sym.st_value, name.to_string());
                }
            }
        }
    }
    let mut plt_sec_base = 0u64;
    let mut plt_base = 0u64;
    for header in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
            if name == ".plt" {
                plt_base = header.sh_addr;
            } else if name == ".plt.sec" {
                plt_sec_base = header.sh_addr;
            }
        }
    }
    let (base, offset_start) = if plt_sec_base != 0 {
        (plt_sec_base, 0u64)
    } else if plt_base != 0 {
        (plt_base, 1u64)
    } else {
        (0, 0)
    };
    if base != 0 {
        for (i, reloc) in elf.pltrelocs.iter().enumerate() {
            let plt_addr = base + 16 * (i as u64 + offset_start);
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(plt_addr, name.to_string());
                    }
                }
            }
        }
    }
    for header in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
            if name == ".rodata" {
                let start = header.sh_offset as usize;
                let end = std::cmp::min(start + header.sh_size as usize, buffer.len());
                let rodata = &buffer[start..end];
                let base_vaddr = header.sh_addr;
                let mut i = 0;
                while i < rodata.len() {
                    if rodata[i].is_ascii_graphic() || rodata[i] == b' ' || rodata[i] == b'\n' {
                        let str_start = i;
                        while i < rodata.len() && rodata[i] != 0 {
                            i += 1;
                        }
                        let str_len = i - str_start;
                        let va = base_vaddr + str_start as u64;
                        if str_len >= 4 {
                            let s = String::from_utf8_lossy(&rodata[str_start..str_start + str_len]);
                            let clean: String = s.chars().filter(|c| c.is_ascii()).collect();
                            if !clean.is_empty() {
                                string_table.insert(va, clean);
                            }
                        }
                    }
                    i += 1;
                }
                break;
            }
        }
    }
    (symbol_table, string_table)
}

fn addr_of(bl: &DynBlock) -> String {
    // Composite nodes carry no start address of their own; report the front
    // leaf's start (the first basic block in flow), descending through
    // BlockCopy wrappers into the wrapped original, which is what correlates
    // with code_r0x labels.
    let descend_copies = |mut cur: DynBlock| -> DynBlock {
        for _ in 0..8 {
            let next = {
                let rg = cur.read().unwrap();
                if let Some(copy) = rg.as_any().downcast_ref::<rudra::block::BlockCopy>() {
                    Some(copy.original.clone())
                } else {
                    None
                }
            };
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        cur
    };
    let mut cur = descend_copies(bl.clone());
    if let Some(leaf) = rudra::block::front_leaf(&cur) {
        cur = descend_copies(leaf);
    }
    let s = cur.read().unwrap().get_start_addr();
    if s.is_null() {
        "?".to_string()
    } else {
        format!("{:#x}", s.as_u64())
    }
}

fn dump_node(bl: &DynBlock, depth: usize, out: &mut String) {
    let rg = bl.read().unwrap();
    let indent = "  ".repeat(depth);
    let idx = rg.get_index();
    let bt = rg.get_type();
    let name = format!("{:?}", bt);
    match bt {
        BlockType::Graph | BlockType::List => {
            let children: Vec<DynBlock> = rg
                .as_any()
                .downcast_ref::<BlockGraph>()
                .map(|g| g.blocks.clone())
                .or_else(|| {
                    rg.as_any()
                        .downcast_ref::<rudra::block::BlockList>()
                        .map(|l| l.children.clone())
                })
                .unwrap_or_default();
            out.push_str(&format!("{}#{} {} [{}..]\n", indent, idx, name, addr_of(bl)));
            for c in &children {
                dump_node(c, depth + 1, out);
            }
        }
        BlockType::If => {
            if let Some(bif) = rg.as_any().downcast_ref::<rudra::block::BlockIf>() {
                if let Some(gt) = &bif.goto_target {
                    out.push_str(&format!(
                        "{}#{} IFGOTO cond=#{} target={}({}) goto_type={} prints?\n",
                        indent,
                        idx,
                        bif.condition.read().unwrap().get_index(),
                        addr_of(gt),
                        gt.read().unwrap().get_index(),
                        bif.goto_type
                    ));
                    dump_node(&bif.condition, depth + 1, out);
                } else {
                    out.push_str(&format!(
                        "{}#{} If cond=#{}\n",
                        indent,
                        idx,
                        bif.condition.read().unwrap().get_index()
                    ));
                    dump_node(&bif.condition, depth + 1, out);
                    out.push_str(&format!("{}  then:\n", indent));
                    dump_node(&bif.if_body, depth + 1, out);
                    if let Some(eb) = &bif.else_body {
                        out.push_str(&format!("{}  else:\n", indent));
                        dump_node(eb, depth + 1, out);
                    }
                }
            }
        }
        BlockType::Goto => {
            if let Some(g) = rg.as_any().downcast_ref::<rudra::block::BlockGoto>() {
                let tgt = g
                    .target_dyn
                    .as_ref()
                    .map(|t| format!("{}(#{} c#{})", addr_of(t), t.read().unwrap().get_index(), g.wrapped.as_ref().map(|w| w.read().unwrap().get_index()).unwrap_or(-1)))
                    .unwrap_or_else(|| "none".into());
                out.push_str(&format!(
                    "{}#{} Goto target={} goto_type={} prints={}\n",
                    indent,
                    idx,
                    tgt,
                    g.goto_type,
                    g.prints_precomputed
                ));
                if let Some(w) = &g.wrapped {
                    dump_node(w, depth + 1, out);
                }
            }
        }
        BlockType::DoWhile => {
            if let Some(dw) = rg.as_any().downcast_ref::<rudra::block::BlockDoWhile>() {
                out.push_str(&format!(
                    "{}#{} DoWhile cond=#{}\n",
                    indent,
                    idx,
                    dw.condition.read().unwrap().get_index()
                ));
                dump_node(&dw.condition, depth + 1, out);
            }
        }
        BlockType::WhileDo => {
            if let Some(wd) = rg.as_any().downcast_ref::<rudra::block::BlockWhileDo>() {
                out.push_str(&format!(
                    "{}#{} WhileDo cond=#{} body=#{}\n",
                    indent,
                    idx,
                    wd.condition.read().unwrap().get_index(),
                    wd.body.read().unwrap().get_index()
                ));
                dump_node(&wd.condition, depth + 1, out);
                dump_node(&wd.body, depth + 1, out);
            }
        }
        BlockType::Switch => {
            if let Some(sw) = rg.as_any().downcast_ref::<rudra::block::BlockSwitch>() {
                out.push_str(&format!(
                    "{}#{} Switch control=#{} numcases={}\n",
                    indent,
                    idx,
                    sw.control.read().unwrap().get_index(),
                    sw.cases.len()
                ));
                dump_node(&sw.control, depth + 1, out);
                for c in &sw.cases {
                    dump_node(c, depth + 1, out);
                }
            }
        }
        BlockType::Basic | BlockType::Copy => {
            out.push_str(&format!(
                "{}#{} {} @{}\n",
                indent,
                idx,
                name,
                addr_of(bl)
            ));
        }
        other => {
            out.push_str(&format!(
                "{}#{} {:?} @{}\n",
                indent, idx, other, addr_of(bl)
            ));
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <binary> <name_or_addr>", args[0]);
        std::process::exit(1);
    }
    let binary_path = args[1].clone();
    let target_spec = args[2].clone();
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || run_main(&binary_path, &target_spec))
        .expect("Failed to spawn stack thread");
    match child.join().expect("Worker thread panicked") {
        Ok(()) => Ok(()),
        Err(msg) => Err(format!("{}", msg).into()),
    }
}

fn run_main(binary_path: &str, target_spec: &str) -> Result<(), String> {
    let buffer = fs::read(binary_path).map_err(|e| e.to_string())?;
    let obj = Object::parse(&buffer).map_err(|e| e.to_string())?;
    let elf = match &obj {
        Object::Elf(e) => e,
        _ => return Err("not an ELF binary".into()),
    };

    let (target_addr, func_size, file_offset, func_name) =
        match resolve_target(elf, target_spec) {
            Some(t) => t,
            None => return Err(format!("function '{}' not found", target_spec)),
        };

    let (symbol_table, string_table) = build_tables(elf, &buffer);
    let code_bytes = &buffer[file_offset as usize..file_offset as usize + func_size];

    // SLEIGH-RUSTIFY-PHASE3-0001: canon-contract linear walk (padding NOP
    // filter); lift_instruction stamps SeqNum(addr, 0) itself.
    let raw_ops = rudra::disasm::sleigh_lift::sleigh_raw_ops_skip_nops(code_bytes, target_addr);

    // FUNCPROTO-MODEL-BIND-0001: the pipeline's call-effect actions read
    // FuncProto::effect_iter, which delegates to the Architecture's default
    // prototype model — the gen mirror driver wires this via
    // Funcdata::set_arch (fspec.cc:3884 model-binding tail). Build the
    // minimal Architecture with the shared default model here so the
    // decompile pipeline runs without the effect_iter panic.
    let model = rudra::fspec::ProtoModelFull::new(None, 8);
    let mut arch = rudra::arch::Architecture::new();
    arch.defaultfp = Some(std::sync::Arc::new(model));
    let mut fd = Funcdata::new(&func_name, Address::new(target_addr), func_size as i32);
    fd.set_arch(std::sync::Arc::new(arch));
    for (&addr, n) in &symbol_table {
        fd.add_symbol(addr, n.clone());
    }
    for (&addr, s) in &string_table {
        fd.add_string(addr, s.clone());
    }
    fd.inject_raw_ops(&raw_ops);
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc
        .write()
        .unwrap()
        .set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();
    {
        let mut fdw = fd_arc.write().unwrap();
        let _ = db.perform_action("decompile", &mut fdw);
    }

    // Structure tree dump.
    {
        let fdr = fd_arc.read().unwrap();
        let mut out = String::new();
        out.push_str(&format!(
            "=== structure tree for {} @ {:#x} ({} bblocks) ===\n",
            func_name,
            target_addr,
            fdr.bblocks.get_size()
        ));
        for blk in &fdr.sblocks.blocks {
            dump_node(blk, 0, &mut out);
        }
        eprintln!("{}", out);
    }

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    {
        let fdr = fd_arc.read().unwrap();
        printer.doc_function(&fdr);
    }
    let buf = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .unwrap();
    let body = buf.get_output();
    println!("{}", body);
    Ok(())
}
