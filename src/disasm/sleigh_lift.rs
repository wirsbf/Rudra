use crate::address::{Address, SeqNum};
use crate::opcodes::OpCode;
use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
use crate::space::AddressSpace;
use crate::sleigh_ffi::{
    PcodeOpC, SleighCtx, SleighDecodeError, SleighErrorKind, VarnodeC,
};

// RUDRA-GLUE: set_sla_path
pub fn set_sla_path(path: &str) {
    crate::sleigh_ffi::set_sla_path(path);
}

// RUDRA-GLUE: map_space
fn map_space(space_idx: i32) -> AddressSpace {
    AddressSpace::from_id(space_idx as u8)
}

// RUDRA-GLUE: map_vn
fn map_vn(vn: &VarnodeC) -> VarnodeRaw {
    VarnodeRaw::new(map_space(vn.space), vn.offset, vn.size as usize)
}

pub struct SleighLifter {
    ctx: Option<SleighCtx>,
}

impl SleighLifter {
    // RUDRA-GLUE: new
    pub fn new() -> Self {
        Self {
            ctx: SleighCtx::new(),
        }
    }

    // Ghidra: sleigh_arch.cc:174 SleighArchitecture::buildTranslator
    /// PERF-DUAL-SLEIGH-INIT-0001: adopt an already-initialized engine (the
    /// register-catalog instance a driver's architecture build enumerated)
    /// instead of deserializing the same `.sla` a second time. The oracle
    /// keeps ONE `Sleigh` translator per languageindex in a static map
    /// (`translators`, sleigh_arch.hh:109) and `buildTranslator` hands that
    /// SAME instance to every consumer — the register catalog
    /// (`SleighBase::getAllRegisters`, sleighbase.cc:182, reading the
    /// translator's `varnode_xref`) and all instruction decoding
    /// (`Architecture::restoreFromSpec`, architecture.cc:627-641,
    /// `buildTranslator` + one `initialize` + `translate = newtrans`).
    /// Rugra's two per-leg `SleighCtx::new()` calls deserialized
    /// `x86-64.sla` twice per hermetic child; this constructor restores the
    /// single-instance oracle shape by ownership transfer (Arc sharing is
    /// unnecessary: the single-threaded engine lifecycle
    /// —created, used, dropped on one thread— matches the driver's
    /// same-thread build+lift sequence). The adopted engine must be in the
    /// same never-decoded, no-image, no-context-default state a fresh
    /// construction has (true for every register-catalog leg: they only
    /// call `num_registers`/`register_info`), so a subsequent
    /// `configure_x86_64` observes byte-identical engine state.
    pub fn from_ctx(ctx: SleighCtx) -> Self {
        Self { ctx: Some(ctx) }
    }

    // RUDRA-GLUE: configure one owned SLEIGH translator before following a function
    pub fn configure_x86_64(
        &mut self,
        image: &[u8],
        image_base: u64,
    ) -> Result<(), SleighDecodeError> {
        let ctx = self.ctx.as_mut().ok_or_else(Self::unavailable_error)?;
        let pspec = std::path::Path::new("sleigh_specs/x86-64.pspec");
        if pspec.exists() {
            ctx.load_pspec(pspec.to_str().unwrap_or_default());
        }
        ctx.try_set_image(image, image_base)
    }

    // RUDRA-GLUE: SLEIGH printAssembly mnemonic probe (translate.hh:442),
    // SleighCtx::assembly_mnemonic passthrough. Driver disassembly listings
    // (debug_cfg / debug_my_fwrite) print it per decode boundary; the canon
    // drivers use the same probe internally via lift_instruction_skip_nops.
    pub fn assembly_mnemonic(&self, address: u64) -> Option<String> {
        self.ctx
            .as_ref()
            .and_then(|ctx| ctx.assembly_mnemonic(address))
    }

    // RUDRA-GLUE: atomically consume Sleigh::oneInstruction step and emitted ops
    pub fn lift_instruction(
        &mut self,
        address: u64,
    ) -> Result<(usize, Vec<PcodeOpRaw>), SleighDecodeError> {
        let ctx = self.ctx.as_mut().ok_or_else(Self::unavailable_error)?;
        let decoded = ctx.one_instruction(address)?;
        let step = usize::try_from(decoded.step)
            .ok()
            .filter(|step| *step != 0)
            .ok_or_else(|| SleighDecodeError {
                kind: SleighErrorKind::Bridge,
                message: format!("SLEIGH returned invalid step {}", decoded.step).into_bytes(),
                instruction_length: None,
            })?;
        let seq = SeqNum::new(Address::new(address), 0);
        let ops = decoded
            .ops
            .iter()
            .map(|op| Self::convert(op, seq))
            .collect();
        Ok((step, ops))
    }

    // RUDRA-GLUE: lift one instruction, dropping the ops of no-effect
    // padding classified as NOP by the .sla's own constructor table
    // (SLEIGH-RUSTIFY-PHASE3-0001). The :NOP rm32 constructors carry
    // empty templates but their rm operands' attached address semantics
    // make the ENGINE emit operand pcode (ia.sinc:4136-4137; both C++
    // SLEIGH and kuna emit it — Phase2 op-for-op zero-diff). Ghidra's
    // flow-following pipeline never lifts unreachable padding, so the
    // oracle IR never contains those ops; a LINEAR walk filters them by
    // the oracle's own mnemonic to keep the same effective IR.
    pub fn lift_instruction_skip_nops(
        &mut self,
        address: u64,
    ) -> Result<(usize, Vec<PcodeOpRaw>), SleighDecodeError> {
        let is_nop = self
            .ctx
            .as_ref()
            .and_then(|ctx| ctx.assembly_mnemonic(address))
            .map(|mnemonic| mnemonic == "NOP")
            .unwrap_or(false);
        let (step, ops) = self.lift_instruction(address)?;
        if is_nop {
            return Ok((step, Vec::new()));
        }
        Ok((step, ops))
    }

    // RUDRA-GLUE: construct the typed failure used when the C++ engine could not be created
    fn unavailable_error() -> SleighDecodeError {
        SleighDecodeError {
            kind: SleighErrorKind::Bridge,
            message: b"unable to create the SLEIGH translator".to_vec(),
            instruction_length: None,
        }
    }

    // RUDRA-GLUE: lift_function
    pub fn lift_function(func_code: &[u8], func_base: u64, inst_offsets: &[(u64, usize)]) -> Vec<(u64, Vec<PcodeOpRaw>)> {
        let mut lifter = Self::new();
        if lifter.configure_x86_64(func_code, func_base).is_err() {
            return Vec::new();
        }

        let mut result = Vec::new();
        for &(rel_offset, _len) in inst_offsets {
            let off = rel_offset as usize;
            if off + 4 <= func_code.len() && func_code[off..off+4] == [0xf3, 0x0f, 0x1e, 0xfa] {
                continue;
            }
            let abs_addr = func_base + rel_offset;
            let Ok((_step, ops)) = lifter.lift_instruction(abs_addr) else {
                continue;
            };
            if !ops.is_empty() {
                result.push((abs_addr, ops));
            }
        }
        result
    }

    // Ghidra: funcdata.cc:878 PcodeEmitFd::dump (callback adapter)
    /// Convert one FFI op record into a `PcodeOpRaw`.
    ///
    /// Faithful to `PcodeEmitFd::dump` (funcdata.cc:878-908): every input
    /// varnode's SLEIGH-reported `(space, offset, size)` tuple is passed
    /// through unchanged. In particular the input(0) of a CODEREF op
    /// (BRANCH/CBRANCH/CALL) is handed to `Funcdata::newCodeRef` as
    /// `Address(vars[0].space, vars[0].offset)`: a Const-space relative label
    /// offset stays in the constant space (`resolveRelatives`, sleigh.cc:120
    /// leaves `(labels[id] - calling_index) & calc_mask(size)` in the Const
    /// space), while x86 machine `jmp/call rel` export a `*[ram]` operand
    /// (ia.sinc:1149-1151 `export *[ram]:$(SIZE) reloc`) so their input(0)
    /// arrives in the ram space with the absolute target. The const/ram
    /// distinction is exactly what `FlowInfo::branchTarget`
    /// (flow.cc:190 `addr.isConstant()`) dispatches on, so this adapter must
    /// never rewrite one into the other.
    pub fn convert(opc: &PcodeOpC, seq: SeqNum) -> PcodeOpRaw {
        let opcode = OpCode::from_i32(opc.opcode).unwrap_or(OpCode::CPUI_COPY);
        let mut raw = PcodeOpRaw::new(opcode as i32);
        raw.set_seq_num(seq);

        if opc.has_output != 0 {
            raw.set_output(map_vn(&opc.output));
        }
        for vn in &opc.inputs {
            raw.add_input(map_vn(vn));
        }
        raw
    }

    // RUDRA-GLUE: lift_from_func
    pub fn lift_from_func(func_code: &[u8], func_base: u64, addr: u64) -> Vec<PcodeOpRaw> {
        let mut lifter = Self::new();
        if lifter.configure_x86_64(func_code, func_base).is_err() {
            return Vec::new();
        }
        lifter
            .lift_instruction(addr)
            .map(|(_, ops)| ops)
            .unwrap_or_default()
    }

}

// RUDRA-GLUE: linear SLEIGH decode over a byte window (driver/test raw-op
// construction). Ghidra itself has no linear decoder — its only contract is
// flow-following through Translate::oneInstruction (flow.cc:421) — so this
// walk is pure Rugra glue: decode each boundary in [base, base+len), and on
// an undecodable byte skip one byte with zero ops (the retired iced walk's
// "Unimplemented" fallback contract).
pub fn sleigh_raw_ops(code: &[u8], base: u64) -> Vec<PcodeOpRaw> {
    let mut lifter = SleighLifter::new();
    if lifter.configure_x86_64(code, base).is_err() {
        return Vec::new();
    }
    let mut ops = Vec::new();
    let mut addr = base;
    let limit = base + code.len() as u64;
    while addr < limit {
        match lifter.lift_instruction(addr) {
            Ok((step, decoded)) => {
                ops.extend(decoded);
                addr += step as u64;
            }
            Err(_) => {
                addr += 1;
            }
        }
    }
    ops
}

// RUDRA-GLUE: canon-contract linear walk — sleigh_raw_ops with the httpd
// driver's lift_instruction_skip_nops padding filter (SLEIGH-RUSTIFY-
// PHASE3-0001). Function windows cut at symbol size can include trailing
// alignment padding; the engine emits operand pcode for multi-byte `:NOP`
// constructors (ia.sinc:4136-4137) that Ghidra's flow-following pipeline
// never lifts, so a debugger walk over a function window must drop them to
// observe the same effective IR the canon driver builds.
pub fn sleigh_raw_ops_skip_nops(code: &[u8], base: u64) -> Vec<PcodeOpRaw> {
    let mut lifter = SleighLifter::new();
    if lifter.configure_x86_64(code, base).is_err() {
        return Vec::new();
    }
    let mut ops = Vec::new();
    let mut addr = base;
    let limit = base + code.len() as u64;
    while addr < limit {
        match lifter.lift_instruction_skip_nops(addr) {
            Ok((step, decoded)) => {
                ops.extend(decoded);
                addr += step as u64;
            }
            Err(_) => {
                addr += 1;
            }
        }
    }
    ops
}
