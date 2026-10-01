//! Diagnostic: dump P-code, HighVariables, and final output for one function.
//! Usage: cargo run --release --example debug_my_fwrite

use goblin::Object;
use std::collections::HashMap;
use std::fs;

use rugra::action::{Action, ActionDatabase};
use rugra::address::Address;
use rugra::disasm::sleigh_lift::SleighLifter;
use rugra::funcdata::Funcdata;
use rugra::opcodes::OpCode;
use rugra::printc::PrintC;
use rugra::prettyprint::EmitNoMarkup;
use rugra::printlanguage::PrintLanguage;
use rugra::space::AddressSpace;
use rugra::varnode::Varnode;

const TARGET_ADDR: u64 = 0x3460; // my_fwrite

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let target_addr = args
        .get(1)
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(TARGET_ADDR);

    let buffer = fs::read("examples/curl")?;
    let obj = Object::parse(&buffer)?;

    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();
    let mut plt_symbols: HashMap<u64, String> = HashMap::new();

    if let Object::Elf(elf) = &obj {
        for sym in elf.syms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(sym.st_value, name.to_string());
                    }
                }
            }
        }
        for sym in elf.dynsyms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
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
                            plt_symbols.insert(plt_addr, name.to_string());
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
    }

    // Find target function bytes
    let mut file_offset = 0u64;
    let mut func_size = 0usize;
    if let Object::Elf(elf) = &obj {
        for sym in elf.syms.iter() {
            if sym.st_value == target_addr {
                func_size = sym.st_size as usize;
                for header in elf.section_headers.iter() {
                    if sym.st_value >= header.sh_addr
                        && sym.st_value < header.sh_addr + header.sh_size
                    {
                        file_offset = header.sh_offset + (sym.st_value - header.sh_addr);
                        break;
                    }
                }
                break;
            }
        }
    }
    if func_size == 0 {
        eprintln!("Function @ 0x{:x} not found", target_addr);
        return Ok(());
    }
    let code_bytes = &buffer[file_offset as usize..file_offset as usize + func_size];

    // SLEIGH-RUSTIFY-PHASE3-0001: canon-contract linear walk (padding NOP
    // filter). The retired iced full-text listing becomes a mnemonic
    // listing (Translate::printAssembly contract, translate.hh:442).
    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(code_bytes, target_addr)?;

    eprintln!("=== Instructions ===");
    let mut raw_ops = Vec::new();
    let mut addr = target_addr;
    let limit = target_addr + code_bytes.len() as u64;
    while addr < limit {
        let mnemonic = lifter
            .assembly_mnemonic(addr)
            .unwrap_or_else(|| "?".to_string());
        match lifter.lift_instruction_skip_nops(addr) {
            Ok((step, ops)) => {
                eprintln!("  0x{:x}: [{}] ({} ops)", addr, mnemonic, ops.len());
                raw_ops.extend(ops);
                addr += step as u64;
            }
            Err(_) => {
                eprintln!("  0x{:x}: [undecodable]", addr);
                addr += 1;
            }
        }
    }

    eprintln!("\n=== RAW OPS (before inject): {} ===", raw_ops.len());
    for (i, raw) in raw_ops.iter().enumerate() {
        let out_str = if let Some(o) = raw.output() {
            let marker = if o.space == AddressSpace::Register && o.offset == 0x10 {
                " <<< RDX-OUTPUT"
            } else {
                ""
            };
            format!("{:?}(0x{:x}:{}) ={} ", o.space, o.offset, o.size, marker)
        } else {
            String::new()
        };
        let in_str: Vec<String> = raw
            .inputs()
            .iter()
            .map(|v| format!("{:?}(0x{:x}:{})", v.space, v.offset, v.size))
            .collect();
        eprintln!(
            "  [{}] op{} {}{}",
            i,
            raw.get_opcode(),
            out_str,
            in_str.join(", ")
        );
    }

    let mut fd = Funcdata::new("target", Address::new(target_addr), func_size as i32);
    for (&addr, n) in &symbol_table {
        fd.add_symbol(addr, n.clone());
    }
    for (&addr, s) in &string_table {
        fd.add_string(addr, s.clone());
    }
    fd.inject_raw_ops(&raw_ops);
    fd.run_heritage_direct();

    eprintln!("\n=== P-code after heritage (alive ops: {}) ===", fd.obank.alivelist.len());
    for op_ref in fd.obank.iter_alive() {
        let op = op_ref.0.read().unwrap();
        let out_str = if let Some(o) = &op.output {
            let v = o.read().unwrap();
            format!("{} = ", dump_vn(&v))
        } else {
            String::new()
        };
        let in_str: Vec<String> = op
            .inrefs
            .iter()
            .map(|a| {
                let v = a.read().unwrap();
                dump_vn(&v)
            })
            .collect();
        eprintln!(
            "  [{}] @0x{:x} {}{}",
            op.start.order,
            op.start.addr.as_u64(),
            out_str,
            format_op(&op.opcode, &in_str)
        );
    }

    // Apply full pipeline
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();
    {
        let mut fdw = fd_arc.write().unwrap();
        let _ = db.perform_action("decompile", &mut fdw);
    }

    eprintln!("\n=== After full pipeline: loc_tree varnodes ({}) ===", {
        let fd = fd_arc.read().unwrap();
        fd.vbank.loc_tree.len()
    });
    {
        let fd = fd_arc.read().unwrap();
        for vn_ref in &fd.vbank.loc_tree {
            let vn = vn_ref.0.read().unwrap();
            let high_name = vn
                .high
                .as_ref()
                .map(|h| {
                    let h = h.read().unwrap();
                    h.get_name().to_string()
                })
                .unwrap_or_else(|| "<none>".to_string());
            let typ = vn
                .v_type
                .as_ref()
                .map(|t| t.get_name().to_string())
                .unwrap_or_else(|| "<none>".to_string());
            let def_str = vn
                .def
                .as_ref()
                .and_then(|d| d.upgrade())
                .map(|x| {
                    let op = x.read().unwrap();
                    format!("op@{:x}/{}", op.start.addr.as_u64(), op.start.order)
                })
                .unwrap_or_else(|| "INPUT".to_string());
            eprintln!(
                "  {:?} off=0x{:x} size={} def={} high='{}' type={}",
                vn.get_space(),
                vn.get_offset(),
                vn.get_size(),
                def_str,
                high_name,
                typ
            );
        }
    }

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    {
        let fd = fd_arc.read().unwrap();
        printer.doc_function(&fd);
    }
    let buf = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .unwrap();
    println!("\n=== Output ===\n{}", buf.get_output());

    Ok(())
}

fn dump_vn(v: &Varnode) -> String {
    match v.get_space() {
        AddressSpace::Register => {
            let n = reg_name(v.get_offset(), v.get_size());
            format!("Reg({}/0x{:x}:{})", n, v.get_offset(), v.get_size())
        }
        AddressSpace::Const => format!("Const(0x{:x})", v.get_offset()),
        AddressSpace::Unique => format!("Unique(0x{:x}:{})", v.get_offset(), v.get_size()),
        AddressSpace::Stack => format!("Stack(0x{:x}:{})", v.get_offset(), v.get_size()),
        AddressSpace::Ram => format!("Ram(0x{:x})", v.get_offset()),
        s => format!("{:?}(0x{:x})", s, v.get_offset()),
    }
}

fn reg_name(off: u64, size: usize) -> &'static str {
    match (off, size) {
        (0x0, 8) => "RAX",
        (0x0, 4) => "EAX",
        (0x0, 2) => "AX",
        (0x0, 1) => "AL",
        (0x8, 8) => "RCX",
        (0x10, 8) => "RDX",
        (0x18, 8) => "RBX",
        (0x20, 8) => "RSP",
        (0x28, 8) => "RBP",
        (0x30, 8) => "RSI",
        (0x38, 8) => "RDI",
        (0x40, 8) => "R8",
        (0x48, 8) => "R9",
        (0x50, 8) => "R10",
        (0x58, 8) => "R11",
        (0x60, 8) => "R12",
        (0x68, 8) => "R13",
        (0x70, 8) => "R14",
        (0x78, 8) => "R15",
        _ => "reg?",
    }
}

#[allow(non_snake_case)]
fn format_op(op: &OpCode, ins: &[String]) -> String {
    match op {
        OpCode::CPUI_COPY => format!("COPY {}", ins[0]),
        OpCode::CPUI_LOAD => format!(
            "LOAD space={} addr={}",
            ins.get(0).cloned().unwrap_or_default(),
            ins.get(1).cloned().unwrap_or_default()
        ),
        OpCode::CPUI_STORE => format!(
            "STORE space={} addr={} val={}",
            ins.get(0).cloned().unwrap_or_default(),
            ins.get(1).cloned().unwrap_or_default(),
            ins.get(2).cloned().unwrap_or_default()
        ),
        OpCode::CPUI_INT_ADD => format!("INT_ADD {} + {}", ins[0], ins[1]),
        OpCode::CPUI_INT_SUB => format!("INT_SUB {} - {}", ins[0], ins[1]),
        OpCode::CPUI_INT_MULT => format!("INT_MULT {} * {}", ins[0], ins[1]),
        OpCode::CPUI_INT_EQUAL => format!("INT_EQUAL {} == {}", ins[0], ins[1]),
        OpCode::CPUI_INT_NOTEQUAL => format!("INT_NOTEQUAL {} != {}", ins[0], ins[1]),
        OpCode::CPUI_INT_LESS => format!("INT_LESS {} < {}", ins[0], ins[1]),
        OpCode::CPUI_INT_SLESS => format!("INT_SLESS {} < {}", ins[0], ins[1]),
        OpCode::CPUI_CBRANCH => format!(
            "CBRANCH target={} cond={}",
            ins.get(1).cloned().unwrap_or_default(),
            ins.get(0).cloned().unwrap_or_default()
        ),
        OpCode::CPUI_BRANCH => format!("BRANCH {}", ins[0]),
        OpCode::CPUI_BRANCHIND => format!("BRANCHIND {}", ins[0]),
        OpCode::CPUI_CALL => format!("CALL {}", ins[0]),
        OpCode::CPUI_RETURN => "RETURN".to_string(),
        _ => format!("{:?}({})", op, ins.join(", ")),
    }
}
