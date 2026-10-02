use goblin::Object;
use std::fs;

use rudra::action::ActionDatabase;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::funcdata::Funcdata;
use rudra::block::BlockGraph;

fn dump_blocks(prefix: &str, graph: &BlockGraph) {
    println!("{} Graph: {} blocks", prefix, graph.get_size());
    for i in 0..graph.get_size() {
        if let Some(block) = graph.get_block(i) {
            let b = block.read().unwrap();
            print!("  Block {}: Type={:?}, In={}", b.get_index(), b.get_type(), b.size_in());
            print!(", Out={} (", b.size_out());
            for j in 0..b.size_out() {
                if let Some(edge) = b.get_out(j) {
                    // ARENAFLIP-(e): edge points are bank ids — resolve the
                    // peer index through the owning graph's bank.
                    print!("{} ", graph.bank.expect_index(edge.point));
                }
            }
            println!(")");
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buffer = fs::read("examples/curl")?;
    let obj = Object::parse(&buffer)?;
    let mut main_vaddr = 0;
    let mut main_size = 0;
    let mut main_offset = 0;

    if let Object::Elf(elf) = obj {
        for sym in elf.syms.iter() {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name == "main" {
                    main_vaddr = sym.st_value;
                    main_size = sym.st_size as usize;
                    break;
                }
            }
        }
        for header in elf.section_headers.iter() {
            if main_vaddr >= header.sh_addr && main_vaddr < header.sh_addr + header.sh_size {
                main_offset = header.sh_offset + (main_vaddr - header.sh_addr);
                break;
            }
        }
    }

    let size = if main_size > 0 { std::cmp::min(main_size, 512) } else { 128 };
    let end_offset = std::cmp::min(main_offset as usize + size, buffer.len());
    let code_bytes = &buffer[main_offset as usize..end_offset];

    // SLEIGH-RUSTIFY-PHASE3-0001: canon-contract linear walk (padding NOP
    // filter). The retired iced full-text listing becomes a mnemonic
    // listing — the SLEIGH bridge exposes the Translate::printAssembly
    // contract (translate.hh:442), not iced's formatter.
    let mut lifter = SleighLifter::new();
    lifter
        .configure_x86_64(code_bytes, main_vaddr)
        .map_err(|e| e.to_string())?;

    println!("--- Disassembly (SLEIGH mnemonics) ---");
    let mut raw_ops = Vec::new();
    let mut addr = main_vaddr;
    let limit = main_vaddr + code_bytes.len() as u64;
    while addr < limit {
        let mnemonic = lifter
            .assembly_mnemonic(addr)
            .unwrap_or_else(|| "?".to_string());
        match lifter.lift_instruction_skip_nops(addr) {
            Ok((step, ops)) => {
                println!("0x{:x}: [{}] ({} ops)", addr, mnemonic, ops.len());
                raw_ops.extend(ops);
                addr += step as u64;
            }
            Err(_) => {
                println!("0x{:x}: [undecodable]", addr);
                addr += 1;
            }
        }
    }
    println!("-------------------");

    let mut fd = Funcdata::new("main", rudra::address::Address::new(main_vaddr), main_size as i32);
    
    // Quick debug: how many branches?
    let mut num_branches = 0;
    for op in &raw_ops {
        if op.get_opcode() == rudra::opcodes::OpCode::CPUI_CBRANCH as i32 || op.get_opcode() == rudra::opcodes::OpCode::CPUI_BRANCH as i32 {
            num_branches += 1;
            println!("Found branch op at {:?}", op.seq_num().unwrap().get_addr());
        }
    }
    println!("Total branch ops: {}", num_branches);

    fd.inject_raw_ops(&raw_ops);
    
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();
    
    {
        let mut fd_write = fd_arc.write().unwrap();
        
        println!("=== BEFORE ACTION DATABASE ===");
        dump_blocks("Basic", &fd_write.bblocks);
        
        let _ = db.perform_action("decompile", &mut fd_write);
        
        println!("=== AFTER ACTION DATABASE ===");
        dump_blocks("Basic", &fd_write.bblocks);
        dump_blocks("Struct", &fd_write.sblocks);
    }

    Ok(())
}
