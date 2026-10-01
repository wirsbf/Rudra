//! One-shot diagnostic: dump LOAD/STORE ops and their address-varnode def
//! chains for a function, to understand why varmap's gather_spacebase
//! returns 0 hints. Run: cargo run --release --example diag_stack

use goblin::Object;
use rugra::funcdata::Funcdata;
use rugra::address::Address;
use rugra::opcodes::OpCode;

fn dump_def_chain(vn: &std::sync::Arc<std::sync::RwLock<rugra::varnode::Varnode>>, depth: usize) {
    let v = vn.read().unwrap();
    let indent = "  ".repeat(depth);
    let sp = v.get_space();
    let off = v.get_offset();
    let sz = v.get_size();
    eprintln!("{indent}VN[{:?} off=0x{:x} sz={} const={} written={}]", sp, off, sz, v.is_constant(), v.is_written());
    if depth > 6 { return; }
    if let Some(def_w) = v.def.as_ref().and_then(|w| w.upgrade()) {
        let d = def_w.read().unwrap();
        eprintln!("{indent}  def=OPCODE({:?}) n_in={}", d.opcode, d.inrefs.len());
        for (i, inv) in d.inrefs.iter().enumerate() {
            eprintln!("{indent}  in[{}]:", i);
            dump_def_chain(inv, depth + 2);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let buffer = std::fs::read("examples/curl")?;
    let obj = Object::parse(&buffer)?;
    let elf = match obj { Object::Elf(e) => e, _ => unreachable!() };

    // Find my_fwrite (0x3460) and getparameter (0x3f00) by address.
    let targets: &[(&str, u64, usize)] = &[
        ("my_fwrite", 0x3460, 98),
        ("myprogress", 0x34d0, 497),
        ("helpf", 0x3980, 267),
    ];

    for &(name, vaddr, size) in targets {
        // Find file offset via section headers.
        let mut file_off = 0u64;
        for h in elf.section_headers.iter() {
            if vaddr >= h.sh_addr && vaddr < h.sh_addr + h.sh_size {
                file_off = h.sh_offset + (vaddr - h.sh_addr);
                break;
            }
        }
        let end = std::cmp::min(file_off as usize + size, buffer.len());
        let code = &buffer[file_off as usize..end];

        // SLEIGH-RUSTIFY-PHASE3-0001: canon-contract linear walk (padding
        // NOP filter) over each function window.
        let raw = rugra::disasm::sleigh_lift::sleigh_raw_ops_skip_nops(code, vaddr);

        let mut fd = Funcdata::new(name, Address::new(vaddr), size as i32);
        fd.inject_raw_ops(&raw);
        fd.run_heritage_direct();

        eprintln!("\n===== {} @ 0x{:x}: {} ops, {} bblocks =====", name, vaddr, fd.obank.alivelist.len(), fd.bblocks.get_size());
        let mut count = 0;
        for op_ref in fd.obank.iter_alive() {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_LOAD || op.opcode == OpCode::CPUI_STORE {
                count += 1;
                if count > 8 { continue; } // cap output
                eprintln!("\n--- {:?} @ 0x{:x} (in={}) ---", op.opcode, op.get_addr(), op.inrefs.len());
                // LOAD: in[0]=spaceid, in[1]=addr; STORE: in[0]=spaceid, in[1]=addr, in[2]=val
                let addr_idx = 1;
                if let Some(addr_vn) = op.inrefs.get(addr_idx) {
                    eprintln!("  addr varnode def chain:");
                    dump_def_chain(addr_vn, 1);
                    // Test if varmap's resolve_rsp_offset would catch it.
                    // We replicate the check inline (resolve is private).
                    // Instead, build a ScopeLocal and see if this offset maps.
                    let resolved = {
                        // resolve_rsp_offset walks def chain from RSP(0x20).
                        // Quick check: does the chain contain Register:0x20?
                        chain_has_reg(addr_vn, 0x20, 0)
                    };
                    eprintln!("  -> chain reaches RSP(0x20)? {}", resolved);
                }
            }
        }
        eprintln!("\n[{}] total LOAD/STORE ops: {}", name, count);

        // Now actually run restructure_varnode and report scope symbol count.
        let mut scope = rugra::varmap::ScopeLocal::new();
        // Diag harness stands in for a post-first-pass inspection, so pass
        // aliasyes=true (ActionRestructureVarnode cc:2279 numpass!=0 form).
        scope.restructure_varnode(&mut fd, true);
        eprintln!("[{}] scope symbols: {}", name, scope.symbols.len());
        for s in &scope.symbols {
            eprintln!("    sym: name={} start={} size={}", s.name, s.start, s.size);
        }
    }
    Ok(())
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
