//! Utility to inspect the curl binary sections and address mappings
//! Run with: cargo run --example inspect_curl

use goblin::Object;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Rudra Binary Inspector: examples/curl ===\n");

    // Read the binary file
    let buffer = match fs::read("examples/curl") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: Could not read examples/curl: {}", e);
            eprintln!("Make sure you are running from the rudra project root.");
            return Ok(());
        }
    };

    // Parse the binary using goblin
    let obj = Object::parse(&buffer)?;

    match obj {
        Object::Elf(elf) => {
            println!("Format: ELF 64-bit");
            println!("Entry Point: 0x{:x}", elf.entry);
            println!("\nSection Headers:");
            println!("{:<3} {:<18} {:<12} {:<12} {:<12}", "Idx", "Name", "Addr", "Offset", "Size");
            println!("{}", "-".repeat(60));

            for (i, header) in elf.section_headers.iter().enumerate() {
                let name = elf.shdr_strtab.get_at(header.sh_name).unwrap_or("?");
                println!("[{:2}] {:<18} 0x{:08x}   0x{:08x}   0x{:x}",
                    i, name, header.sh_addr, header.sh_offset, header.sh_size);
            }

            println!("\nSearching for 'main' symbol and mapping to file offset...");
            let mut found = false;
            for sym in elf.syms.iter() {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                if name == "main" {
                    let vaddr = sym.st_value;
                    println!("-------------------------------------------");
                    println!("Symbol: {}", name);
                    println!("Virtual Address: 0x{:x}", vaddr);
                    println!("Size: {} bytes", sym.st_size);

                    // Map VAddr to File Offset
                    let mut mapped = false;
                    for header in elf.section_headers.iter() {
                        if vaddr >= header.sh_addr && vaddr < header.sh_addr + header.sh_size {
                            let offset = header.sh_offset + (vaddr - header.sh_addr);
                            println!("Mapped to Section: {}", elf.shdr_strtab.get_at(header.sh_name).unwrap_or("?"));
                            println!("Calculated File Offset: 0x{:x}", offset);

                            // Verify bytes if possible
                            if (offset as usize) < buffer.len() {
                                let end = std::cmp::min(offset as usize + 16, buffer.len());
                                let preview = &buffer[offset as usize..end];
                                print!("Hex Preview at Offset: ");
                                for b in preview {
                                    print!("{:02x} ", b);
                                }
                                println!();
                            }
                            mapped = true;
                            break;
                        }
                    }
                    if !mapped {
                        println!("Warning: Could not map virtual address to any section offset.");
                    }
                    println!("-------------------------------------------");
                    found = true;
                    break;
                }
            }

            if !found {
                println!("'main' symbol not found.");
            }
        }
        _ => {
            println!("Not an ELF file or unsupported format.");
        }
    }

    Ok(())
}
