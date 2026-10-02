use goblin::Object;
use std::fs;
use std::collections::HashMap;
use std::path::Path;

use rudra::action::{Action, ActionDatabase};
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::funcdata::Funcdata;
use rudra::printc::PrintC;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printlanguage::PrintLanguage;
use rudra::address::Address;

// RUDRA-GLUE: main (no Ghidra counterpart found)
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: rudra <binary> [max_functions] [--symbols-only]");
        eprintln!("  binary          ELF/PE binary to decompile");
        eprintln!("  max_functions   Limit number of functions (default: all)");
        eprintln!("  --symbols-only  Only decompile functions with symbols (skip stripped)");
        return;
    }

    let binary_path = &args[1];
    let max_functions = args.get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(usize::MAX);

    let buffer = match fs::read(binary_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: cannot read {}: {}", binary_path, e);
            std::process::exit(1);
        }
    };

    let obj = match Object::parse(&buffer) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: cannot parse binary: {}", e);
            std::process::exit(1);
        }
    };

    let elf = match &obj {
        Object::Elf(e) => e,
        _ => {
            eprintln!("Error: only ELF binaries are supported");
            std::process::exit(1);
        }
    };

    let mut functions: Vec<(u64, usize, u64, String)> = Vec::new();
    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();

    for sym in elf.syms.iter() {
        if sym.st_value != 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    symbol_table.insert(sym.st_value, name.to_string());
                }
                if sym.is_function() {
                    let mut file_off = 0u64;
                    for header in elf.section_headers.iter() {
                        if sym.st_value >= header.sh_addr && sym.st_value < header.sh_addr + header.sh_size {
                            file_off = header.sh_offset + (sym.st_value - header.sh_addr);
                            break;
                        }
                    }
                    if file_off > 0 {
                        let size = if sym.st_size > 0 { sym.st_size as usize } else { 512 };
                        functions.push((sym.st_value, size, file_off, name.to_string()));
                    }
                }
            }
        }
    }

    for sym in elf.dynsyms.iter() {
        if sym.is_function() && sym.st_value != 0 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                symbol_table.entry(sym.st_value).or_insert_with(|| name.to_string());
                let mut file_off = 0u64;
                for header in elf.section_headers.iter() {
                    if sym.st_value >= header.sh_addr && sym.st_value < header.sh_addr + header.sh_size {
                        file_off = header.sh_offset + (sym.st_value - header.sh_addr);
                        break;
                    }
                }
                if file_off > 0 && !functions.iter().any(|f| f.0 == sym.st_value) {
                    let size = if sym.st_size > 0 { sym.st_size as usize } else { 512 };
                    functions.push((sym.st_value, size, file_off, name.to_string()));
                }
            }
        }
    }

    for header in elf.section_headers.iter() {
        let is_rodata = header.sh_type == 1
            && header.sh_size > 0
            && (header.sh_flags & 0x2) != 0
            && (header.sh_flags & 0x1) == 0
            && (header.sh_flags & 0x4) == 0;
        if !is_rodata { continue; }
        let start = header.sh_offset as usize;
        let end = std::cmp::min(start + header.sh_size as usize, buffer.len());
        if start >= end { continue; }
        let data = &buffer[start..end];
        let mut i = 0;
        while i < data.len() {
            let s_start = i;
            while i < data.len() && data[i] >= 0x20 && data[i] < 0x7f { i += 1; }
            let len = i - s_start;
            if len >= 4 {
                let s = String::from_utf8_lossy(&data[s_start..i]).to_string();
                string_table.insert(header.sh_addr + s_start as u64, s);
            }
            i += 1;
        }
    }

    functions.sort_by_key(|f| f.0);

    eprintln!("[INFO] {} — {} functions, {} symbols, {} strings",
        Path::new(binary_path).file_name().unwrap_or_default().to_string_lossy(),
        functions.len(), symbol_table.len(), string_table.len());

    let take_count = max_functions.min(functions.len()) + 50;

    let mut prototype_db: HashMap<u64, usize> = HashMap::new();
    let mut call_targets: std::collections::HashSet<u64> = std::collections::HashSet::new();

    let addr_to_fileoff = |addr: u64| -> Option<(usize, usize)> {
        for header in elf.section_headers.iter() {
            if addr >= header.sh_addr && addr < header.sh_addr + header.sh_size {
                let off = (header.sh_offset + (addr - header.sh_addr)) as usize;
                let end = std::cmp::min(off + 512, buffer.len());
                return Some((off, end));
            }
        }
        None
    };

    // SLEIGH-RUSTIFY-PHASE3-0001: the prototype pre-pass decodes through the
    // production SLEIGH engine (one full-PT_LOAD-image lifter at the
    // ELF-relative base 0, the same contract the main loop's flow lifters
    // use per section). A decode error skips one byte with zero ops — the
    // retired iced walk's "Unimplemented" fallback contract.
    let prepass_image = {
        const PT_LOAD: u32 = 1;
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
                    .get(ph.p_offset as usize..(ph.p_offset as usize).saturating_add(ph.p_filesz as usize))
                    .unwrap_or(&[]);
                let dst_end = vaddr.saturating_add(src.len()).min(top);
                if vaddr < dst_end {
                    image[vaddr..dst_end].copy_from_slice(&src[..dst_end - vaddr]);
                }
            }
        }
        image
    };
    let mut prepass_sleigh = SleighLifter::new();
    if let Err(error) = prepass_sleigh.configure_x86_64(&prepass_image, 0) {
        eprintln!("[PREPASS] SLEIGH setup failed: {:?} — prototype pre-pass skipped", error);
        return;
    }
    for &(vaddr, size, _file_offset, ref name) in functions.iter().take(take_count) {
        if size < 5 { continue; }
        let range_len = std::cmp::min(size, 4096);
        let mut raw_ops = Vec::new();
        let mut addr = vaddr;
        let limit = vaddr + range_len as u64;
        while addr < limit {
            match prepass_sleigh.lift_instruction(addr) {
                Ok((step, ops)) => {
                    for op in &ops {
                        if rudra::opcodes::OpCode::from_i32(op.get_opcode())
                            == Some(rudra::opcodes::OpCode::CPUI_CALL)
                        {
                            if let Some(target_vn) = op.inputs().first() {
                                if target_vn.space == rudra::space::AddressSpace::Ram {
                                    call_targets.insert(target_vn.offset);
                                }
                            }
                        }
                    }
                    raw_ops.extend(ops);
                    addr += step as u64;
                }
                Err(_) => { addr += 1; }
            }
        }
        let mut fd = Funcdata::new(name, Address::new(vaddr), size as i32);
        fd.inject_raw_ops(&raw_ops);
        fd.run_heritage_direct();
        let mut infer = rudra::coreaction::ActionInferParams::new();
        let _ = infer.apply(&mut fd);
        prototype_db.insert(vaddr, fd.funcp.num_params());
    }

    for &target in &call_targets {
        if prototype_db.contains_key(&target) { continue; }
        let Some((foff, fend)) = addr_to_fileoff(target) else { continue; };
        if foff >= buffer.len() { continue; }
        let range_len = fend - foff;
        let mut raw_ops = Vec::new();
        let mut addr = target;
        let limit = target + range_len as u64;
        while addr < limit {
            match prepass_sleigh.lift_instruction(addr) {
                Ok((step, ops)) => {
                    raw_ops.extend(ops);
                    addr += step as u64;
                }
                Err(_) => { addr += 1; }
            }
        }
        let name = symbol_table.get(&target).cloned().unwrap_or_else(|| format!("sub_{:x}", target));
        let mut fd = Funcdata::new(&name, Address::new(target), 512);
        fd.inject_raw_ops(&raw_ops);
        fd.run_heritage_direct();
        let mut infer = rudra::coreaction::ActionInferParams::new();
        let _ = infer.apply(&mut fd);
        prototype_db.insert(target, fd.funcp.num_params());
    }

    let mut success = 0u32;
    let mut failed = 0u32;

    for (idx, &(vaddr, size, file_offset, ref name)) in functions.iter().enumerate() {
        if idx >= max_functions { break; }
        if size < 5 || name == "_start" || name == "register_tm_clones" || name == "deregister_tm_clones"
            || name == "frame_dummy" { continue; }

        if file_offset as usize >= buffer.len() { continue; }

        // Use one long-lived SLEIGH translator and follow only reachable code.
        let Some(section) = elf.section_headers.iter().find(|section| {
            vaddr >= section.sh_addr && vaddr < section.sh_addr.saturating_add(section.sh_size)
        }) else {
            failed += 1;
            continue;
        };
        let section_start = section.sh_offset as usize;
        let section_end = section
            .sh_offset
            .saturating_add(section.sh_size)
            .min(buffer.len() as u64) as usize;
        let Some(section_image) = buffer.get(section_start..section_end) else {
            failed += 1;
            continue;
        };
        let mut lifter = SleighLifter::new();
        if let Err(error) = lifter.configure_x86_64(section_image, section.sh_addr) {
            eprintln!("[FLOW] {}: failed to configure SLEIGH: {}", name, error);
            failed += 1;
            continue;
        }
        let mut fd = Funcdata::new(name, Address::new(vaddr), size as i32);
        fd.external_prototypes = prototype_db.clone();
        for (&addr, n) in &symbol_table { fd.add_symbol(addr, n.clone()); }
        for (&addr, s) in &string_table { fd.add_string(addr, s.clone()); }
        rudra::flow::follow_flow(
            &mut fd,
            &mut lifter,
            Address::new(vaddr),
            u64::MAX,
        );
        let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
        fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

        let handle = std::thread::spawn(move || -> Option<String> {

            let mut db = ActionDatabase::new();
            db.set_default_actions();
            {
                let mut fd_write = fd_arc.write().unwrap();
                let _ = db.perform_action("decompile", &mut fd_write);
            }

            let fd_read = fd_arc.read().unwrap();
            let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
            printer.doc_function(&fd_read);
            let output = printer.take_emit();
            let text = output.into_any().downcast::<EmitNoMarkup>().unwrap();
            Some(text.get_output())
        });

        match handle.join() {
            Ok(Some(output)) => {
                println!("/* ---- 0x{:x}: {} ({} bytes) ---- */", vaddr, name, size);
                println!("{}", output);
                println!();
                success += 1;
            }
            _ => { failed += 1; }
        }
    }

    eprintln!("[INFO] {} functions decompiled, {} failed", success, failed);
}
