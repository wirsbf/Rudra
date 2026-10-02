//! End-to-end decompilation example using the new concurrent pipeline
//!
//! This example demonstrates the full decompilation pipeline:
//! 1. Manually construct P-code operations for a simple function
//! 2. Inject them into a Funcdata container
//! 3. Run the ActionDatabase analysis pipeline
//! 4. Print C output via PrintC

use rudra::{
    Address,
    Funcdata,
    action::ActionDatabase,
    opcodes::OpCode,
    pcoderaw::{PcodeOpRaw, VarnodeRaw},
    prettyprint::EmitNoMarkup,
    printc::PrintC,
    printlanguage::PrintLanguage,
    space::AddressSpace,
};

fn main() {
    println!("=== Rudra Decompilation Demo (End-to-End Pipeline) ===\n");

    // Example 1: Simple addition function
    println!("Example 1: Simple Addition Function");
    println!("-----------------------------------");
    decompile_addition_function();

    println!();

    // Example 2: Conditional function
    println!("Example 2: Conditional Function");
    println!("-------------------------------");
    decompile_conditional_function();
}

/// Decompile a simple `int64_t add(int64_t a, int64_t b) { return a + b; }`
fn decompile_addition_function() {
    // x86-64 System V ABI:
    //   RDI = first param  (offset 0x38 in Ghidra register space)
    //   RSI = second param (offset 0x30)
    //   RAX = return value (offset 0x00)
    //
    // P-code equivalent:
    //   COPY  RAX <- RDI       ; move first arg to return register
    //   INT_ADD RAX <- RAX, RSI ; add second arg
    //   RETURN (RAX)           ; return

    let mut ops = Vec::new();

    // Op 0: RAX = COPY(RDI)
    let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
    op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
    op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));  // RDI
    ops.push(op0);

    // Op 1: RAX = INT_ADD(RAX, RSI)
    let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
    op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
    op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));  // RAX
    op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8));  // RSI
    ops.push(op1);

    // Op 2: RETURN(RAX)
    let mut op2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
    op2.add_input(VarnodeRaw::new(AddressSpace::Const, 0x1000, 8));   // return target
    op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));  // RAX (return value)
    ops.push(op2);

    // Step 1: Create Funcdata and inject P-code
    let mut fd = Funcdata::new("add", Address::new(0x1000), 7);
    fd.inject_raw_ops(&ops);

    println!("Injected {} P-code ops into Funcdata", fd.obank.alivelist.len());
    println!("Created {} basic blocks", fd.bblocks.get_size());
    println!("Created {} varnodes", fd.vbank.num_varnodes());
    println!();

    // Step 2: Setup self-ref and run ActionDatabase
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();

    {
        let mut fd_write = fd_arc.write().unwrap();
        match db.perform_action("decompile", &mut fd_write) {
            Ok(Some(changes)) => println!("ActionDatabase pipeline completed. Changes: {}", changes),
            Ok(None) => println!("Pipeline error: missing decompile action"),
            Err(e) => println!("Pipeline error: {}", e),
        }
    }
    println!();

    // Step 3: Emit C code via PrintC
    println!("Generated C output:");
    println!("--------------------");
    let emit = Box::new(EmitNoMarkup::new());
    let mut printer = PrintC::new(emit);
    let fd_read = fd_arc.read().unwrap();
    printer.doc_function(&fd_read);
    drop(fd_read);

    // Retrieve the buffered output via downcast
    let emit_box = printer.take_emit();
    let emit_any: Box<dyn std::any::Any> = emit_box.into_any();
    if let Ok(emit_no_markup) = emit_any.downcast::<EmitNoMarkup>() {
        println!("{}", emit_no_markup.get_output());
    }
}

/// Decompile a conditional function:
/// ```c
/// int64_t abs_val(int64_t x) {
///     if (x < 0) return -x;
///     return x;
/// }
/// ```
fn decompile_conditional_function() {
    let mut ops = Vec::new();

    // Block 0: Compare and branch
    // Op 0: uVar = INT_SLESS(RDI, 0)
    let mut op0 = PcodeOpRaw::new(OpCode::CPUI_INT_SLESS as i32);
    op0.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
    op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));  // RDI
    op0.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));        // 0
    ops.push(op0);

    // Op 1: CBRANCH(target=block2_addr, uVar)
    let mut op1 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
    op1.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1030, 8));     // branch target = block 2 start (op3 addr)
    op1.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));   // condition
    ops.push(op1);

    // Block 1 (fallthrough, x >= 0): RETURN(RDI)
    let mut op2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
    op2.add_input(VarnodeRaw::new(AddressSpace::Const, 0x1010, 8));   // return target
    op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));  // RDI
    ops.push(op2);

    // Block 2 (branch target, x < 0): RAX = INT_NEGATE(RDI); RETURN(RAX)
    let mut op3 = PcodeOpRaw::new(OpCode::CPUI_INT_NEGATE as i32);
    op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
    op3.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));  // RDI
    ops.push(op3);

    let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
    op4.add_input(VarnodeRaw::new(AddressSpace::Const, 0x1020, 8));   // return target
    op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));  // RAX
    ops.push(op4);

    // Create Funcdata and inject
    let mut fd = Funcdata::new("abs_val", Address::new(0x1000), 32);
    fd.inject_raw_ops(&ops);

    println!("Injected {} P-code ops into Funcdata", fd.obank.alivelist.len());
    println!("Created {} basic blocks", fd.bblocks.get_size());
    println!();

    // Run ActionDatabase
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc.write().unwrap().set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();

    {
        let mut fd_write = fd_arc.write().unwrap();
        match db.perform_action("decompile", &mut fd_write) {
            Ok(Some(changes)) => println!("ActionDatabase pipeline completed. Changes: {}", changes),
            Ok(None) => println!("Pipeline error: missing decompile action"),
            Err(e) => println!("Pipeline error: {}", e),
        }
    }
    println!();

    // Emit C code
    println!("Generated C output:");
    println!("--------------------");
    let emit = Box::new(EmitNoMarkup::new());
    let mut printer = PrintC::new(emit);
    let fd_read = fd_arc.read().unwrap();
    printer.doc_function(&fd_read);
    drop(fd_read);

    // Retrieve the buffered output via downcast
    let emit_box = printer.take_emit();
    let emit_any: Box<dyn std::any::Any> = emit_box.into_any();
    if let Ok(emit_no_markup) = emit_any.downcast::<EmitNoMarkup>() {
        println!("{}", emit_no_markup.get_output());
    }
}
