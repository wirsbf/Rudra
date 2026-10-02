//! Minimal smoke test for Rugra's direct Ghidra SLEIGH FFI.

use anyhow::{ensure, Context, Result};
use rudra::sleigh_ffi::SleighCtx;

fn main() -> Result<()> {
    let mut ctx = SleighCtx::new().context("failed to load sleigh_specs/x86-64.sla")?;

    // Keep this raw ABI smoke independent of the temporary pspec string
    // scanner. SLEIGH-0002C will replace these explicit defaults with the
    // real ContextInternal::decodeFromSpec path.
    for (name, value) in [
        ("addrsize", 2),
        ("opsize", 1),
        ("rexprefix", 0),
        ("longMode", 1),
    ] {
        ctx.try_set_context(name, value)
            .with_context(|| format!("failed to set SLEIGH context {name}"))?;
    }

    // MOV RAX,RDI; RET.  In x86-64 context the first instruction is three
    // bytes and produces a COPY.  Without pspec defaults it decodes as a
    // one-byte instruction, so this also checks context initialization.
    let code = [0x48, 0x89, 0xf8, 0xc3];
    ctx.try_set_image(&code, 0)
        .context("failed to copy the SLEIGH image")?;
    let decoded = ctx
        .one_instruction(0)
        .context("SLEIGH rejected the first instruction")?;
    let step = decoded.step;
    let ops = decoded.ops;

    ensure!(
        step == 3,
        "expected x86-64 oneInstruction step 3, got {step}"
    );
    ensure!(!ops.is_empty(), "expected MOV RAX,RDI to emit p-code");

    println!("sleigh.context=x86:LE:64:default");
    println!("sleigh.spaces={}", ctx.num_spaces());
    println!("sleigh.registers={}", ctx.num_registers());
    println!("instruction.step={step}");
    for (index, op) in ops.iter().enumerate() {
        println!(
            "op[{index}].opcode={}:inputs={}:output={}",
            op.opcode, op.num_inputs, op.has_output
        );
    }
    Ok(())
}
