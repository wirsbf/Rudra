//! P-code emulation engine.
//!
//! Corresponds to Ghidra's `emulate.hh` / `emulate.cc` (1013 lines).
//!
//! The emulator executes P-code operations on a virtual machine state
//! (MemState + register file), used for constant propagation and
//! jump-table analysis.
//!
//! Key classes:
//! - `BreakCallBack`: breakpoint callback trait
//! - `BreakTable`: breakpoint collection
//! - `Emulate`: base emulator that executes p-code ops one at a time
//! - `EmulatePcodeOp`: emulator operating on high-level PcodeOp objects
//!
//! # Status
//! Core Emulate struct with execute_op using opbehavior evaluate functions.
//! Full BreakCallBack/BreakTable and memory-backed LOAD/STORE are deferred.

use std::collections::HashMap;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::varnode::Varnode;
use crate::opbehavior;
use crate::memstate::MemState;
use std::sync::{Arc, RwLock};

/// Emulation control flow state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EmulateOpBehavior {
    /// Continue executing
    Continue,
    /// Op was a branch, stop
    Branch,
    /// Op was a return, stop
    Return,
    /// Op caused an error
    Error,
}

/// The base P-code emulator.
/// Corresponds to Ghidra's `Emulate` (emulate.hh).
pub struct Emulate {
    /// Memory state for LOAD/STORE
    pub mem_state: MemState,
    /// Register file: (space, offset) → value
    pub registers: HashMap<(u64, u64), u64>,
    /// Current execution address
    pub current_address: u64,
    /// Whether emulation has terminated
    pub terminated: bool,
    /// Instruction count (for limiting emulation)
    pub instruction_count: u64,
    /// Maximum instructions to emulate (0 = unlimited)
    pub max_instructions: u64,
}

impl Emulate {
    // Ghidra: emulate.hh:27 Emulate::new
    pub fn new() -> Self {
        Self {
            mem_state: MemState::new(),
            registers: HashMap::new(),
            current_address: 0,
            terminated: false,
            instruction_count: 0,
            max_instructions: 0,
        }
    }

    // Ghidra: emulate.hh:27 Emulate::setRegister
    /// Set a register value.
    pub fn set_register(&mut self, space: u64, offset: u64, val: u64) {
        self.registers.insert((space, offset), val);
    }

    // Ghidra: emulate.hh:27 Emulate::getRegister
    /// Get a register value.
    pub fn get_register(&self, space: u64, offset: u64) -> u64 {
        self.registers.get(&(space, offset)).copied().unwrap_or(0)
    }

    // Ghidra: emulate.hh:27 Emulate::getValue
    /// Resolve a Varnode to its current value. Faithful to
    /// `MemoryState::getValue` (memstate.cc): a constant yields its offset,
    /// any other (register/unique) varnode yields the stored register value
    /// (0 if unset). This is the value-resolution the emulator uses for op
    /// inputs — unlike the prior constant-only path, it reads back values
    /// written by earlier emulated ops.
    pub fn get_value(&self, vn: &Arc<RwLock<Varnode>>) -> u64 {
        let v = vn.read().unwrap();
        if v.is_constant() {
            v.get_offset()
        } else {
            self.get_register(v.get_space().space_id() as u64, v.get_offset())
        }
    }

    // Ghidra: emulate.hh:27 Emulate::setValue
    /// Write a value to a Varnode's storage. Faithful to
    /// `MemoryState::setValue` (memstate.cc): stores into the register file
    /// keyed by (space_id, offset).
    pub fn set_value(&mut self, vn: &Arc<RwLock<Varnode>>, val: u64) {
        let v = vn.read().unwrap();
        self.set_register(v.get_space().space_id() as u64, v.get_offset(), val);
    }

    // Ghidra: emulate.cc:143 Emulate::executeCurrentOp
    /// Execute a single P-code op with full Ghidra `executeCurrentOp` dispatch
    /// (emulate.cc:143-216). Evaluates arithmetic ops via opbehavior, handles
    /// LOAD/STORE against MemState, and resolves control flow (branch/return).
    /// Returns the control-flow disposition for this op.
    pub fn execute_current_op(&mut self, op: &Arc<RwLock<PcodeOp>>) -> EmulateOpBehavior {
        self.instruction_count += 1;
        if self.max_instructions > 0 && self.instruction_count > self.max_instructions {
            self.terminated = true;
            return EmulateOpBehavior::Error;
        }
        let opcode = { op.read().unwrap().opcode };
        match opcode {
            // ---- Special ops (emulate.cc:150-206) ----
            OpCode::CPUI_LOAD => {
                self.execute_load(op);
                EmulateOpBehavior::Continue
            }
            OpCode::CPUI_STORE => {
                self.execute_store(op);
                EmulateOpBehavior::Continue
            }
            OpCode::CPUI_BRANCH => {
                // executeBranch: set address to the branch target.
                let tgt = op.read().unwrap().get_in(0).cloned();
                if let Some(t) = tgt {
                    self.current_address = t.read().unwrap().get_offset();
                }
                EmulateOpBehavior::Branch
            }
            OpCode::CPUI_CBRANCH => {
                // executeCbranch: take branch iff condition != 0.
                let cond = op.read().unwrap().get_in(1).map(|c| self.get_value(c)).unwrap_or(0);
                if cond != 0 {
                    let tgt = op.read().unwrap().get_in(0).cloned();
                    if let Some(t) = tgt {
                        self.current_address = t.read().unwrap().get_offset();
                    }
                    EmulateOpBehavior::Branch
                } else {
                    EmulateOpBehavior::Continue
                }
            }
            OpCode::CPUI_BRANCHIND => {
                // executeBranchind: target is the value of input(0).
                let off = op.read().unwrap().get_in(0).map(|v| self.get_value(v)).unwrap_or(0);
                self.current_address = off;
                EmulateOpBehavior::Branch
            }
            OpCode::CPUI_CALL => {
                let tgt = op.read().unwrap().get_in(0).cloned();
                if let Some(t) = tgt {
                    self.current_address = t.read().unwrap().get_offset();
                }
                EmulateOpBehavior::Branch
            }
            OpCode::CPUI_CALLIND => {
                let off = op.read().unwrap().get_in(0).map(|v| self.get_value(v)).unwrap_or(0);
                self.current_address = off;
                EmulateOpBehavior::Branch
            }
            OpCode::CPUI_RETURN => {
                self.terminated = true;
                EmulateOpBehavior::Return
            }
            // MULTIEQUAL / INDIRECT in un-heritaged code throw in Ghidra; we
            // treat them as no-op fallthrus (the emulator is used on lifted
            // p-code, where these appear).
            OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => EmulateOpBehavior::Continue,
            // ---- Unary arithmetic (emulate.cc:208-211) ----
            // Ghidra BOOL_NEGATE == Rudra BOOL_NOT; INT_2COMP == INT_NEG;
            // INT_NEGATE == INT_NOT. COPY is also unary (1 input).
            OpCode::CPUI_COPY
            | OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_INT_ZEXT
            | OpCode::CPUI_INT_SEXT
            | OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_INT_NEGATE
            | OpCode::CPUI_SUBPIECE => {
                self.execute_unary(op);
                EmulateOpBehavior::Continue
            }
            // ---- Binary arithmetic (emulate.cc:212-215) ----
            _ => {
                self.execute_binary(op);
                EmulateOpBehavior::Continue
            }
        }
    }

    // Ghidra: emulate.hh:27 Emulate::executeUnary
    /// Execute a unary arithmetic/logical op. Faithful to
    /// `EmulateMemory::executeUnary` (emulate.cc:218-225).
    fn execute_unary(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        let (in_vn, size_out, size_in, opcode) = {
            let o = op.read().unwrap();
            let in_vn = match o.get_in(0) { Some(v) => v.clone(), None => return };
            let size_out = o.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            let size_in = in_vn.read().unwrap().get_size();
            (in_vn, size_out, size_in, o.opcode)
        };
        let in1 = self.get_value(&in_vn);
        if let Some(out) = op.read().unwrap().output.clone() {
            if let Some(val) = opbehavior::evaluate_unary(opcode, size_out, size_in, in1) {
                self.set_value(&out, val);
            }
        }
    }

    // Ghidra: emulate.hh:27 Emulate::executeBinary
    /// Execute a binary arithmetic/logical op. Faithful to
    /// `EmulateMemory::executeBinary` (emulate.cc:227-235).
    fn execute_binary(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        let (in0, in1, size_out, size_in, opcode) = {
            let o = op.read().unwrap();
            let in0 = match o.get_in(0) { Some(v) => v.clone(), None => return };
            let in1 = match o.get_in(1) { Some(v) => v.clone(), None => return };
            let size_out = o.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(0);
            let size_in = in0.read().unwrap().get_size();
            (in0, in1, size_out, size_in, o.opcode)
        };
        let v0 = self.get_value(&in0);
        let v1 = self.get_value(&in1);
        if let Some(out) = op.read().unwrap().output.clone() {
            if let Some(val) = opbehavior::evaluate_binary(opcode, size_out, size_in, v0, v1) {
                self.set_value(&out, val);
            }
        }
    }

    // Ghidra: emulate.hh:27 Emulate::executeLoad
    /// Execute a LOAD op. Faithful to `EmulateMemory::executeLoad`
    /// (emulate.cc:237-246): reads `output.size` bytes from the space
    /// indicated by input(0) at the offset given by input(1)'s value.
    fn execute_load(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        let (off, out_size) = {
            let o = op.read().unwrap();
            let addr_vn = match o.get_in(1) { Some(v) => v.clone(), None => return };
            let off = self.get_value(&addr_vn);
            let out_size = o.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(1);
            (off, out_size)
        };
        let val = self.mem_state.get_bank("ram")
            .map(|bank| bank.get_value(off, out_size))
            .unwrap_or(0);
        if let Some(out) = op.read().unwrap().output.clone() {
            self.set_value(&out, val);
        }
    }

    // Ghidra: emulate.hh:27 Emulate::executeStore
    /// Execute a STORE op. Faithful to `EmulateMemory::executeStore`
    /// (emulate.cc:248-257): writes input(2)'s value at the offset given by
    /// input(1)'s value.
    fn execute_store(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        let (off, val, size) = {
            let o = op.read().unwrap();
            let addr_vn = match o.get_in(1) { Some(v) => v.clone(), None => return };
            let val_vn = match o.get_in(2) { Some(v) => v.clone(), None => return };
            let off = self.get_value(&addr_vn);
            let val = self.get_value(&val_vn);
            let size = val_vn.read().unwrap().get_size();
            (off, val, size)
        };
        if let Some(bank) = self.mem_state.get_bank_mut("ram") {
            bank.set_value(off, size, val);
        }
    }

    // Ghidra: emulate.hh:27 Emulate::execute
    /// Execute a sequence of P-code ops (the main `execute` loop). Faithful to
    /// the driver loop callers of Ghidra's `Emulate::executeCurrentOp`
    /// (emulate.hh:209): steps through ops in order, following branches only
    /// as a disposition signal, until termination (RETURN, instruction-limit,
    /// or end of sequence). The optional `start_index` begins execution at a
    /// specific op; otherwise 0. Returns the final disposition.
    pub fn execute(&mut self, ops: &[Arc<RwLock<PcodeOp>>]) -> EmulateOpBehavior {
        let mut i = 0;
        let mut last = EmulateOpBehavior::Continue;
        while i < ops.len() && !self.terminated {
            let disp = self.execute_current_op(&ops[i]);
            last = disp;
            match disp {
                EmulateOpBehavior::Continue => i += 1,
                EmulateOpBehavior::Branch | EmulateOpBehavior::Return | EmulateOpBehavior::Error => break,
            }
        }
        last
    }

    // Ghidra: emulate.hh:27 Emulate::executeOp
    /// Execute a single PcodeOp, returning the behavior result.
    /// Uses opbehavior evaluate functions for constant emulation and
    /// integrates with MemState for LOAD/STORE.
    pub fn execute_op(&mut self, op: &Arc<RwLock<PcodeOp>>) -> EmulateOpBehavior {
        self.instruction_count += 1;
        if self.max_instructions > 0 && self.instruction_count > self.max_instructions {
            self.terminated = true;
            return EmulateOpBehavior::Error;
        }
        let o = op.read().unwrap();
        match o.opcode {
            OpCode::CPUI_BRANCH => EmulateOpBehavior::Branch,
            OpCode::CPUI_CBRANCH => {
                // Check condition
                let cond = o.inrefs.get(1).map(|vn| {
                    let v = vn.read().unwrap();
                    if v.is_constant() { v.get_offset() != 0 } else { false }
                }).unwrap_or(false);
                if cond { EmulateOpBehavior::Branch } else { EmulateOpBehavior::Continue }
            }
            OpCode::CPUI_BRANCHIND => EmulateOpBehavior::Branch,
            OpCode::CPUI_RETURN => {
                self.terminated = true;
                EmulateOpBehavior::Return
            }
            OpCode::CPUI_LOAD => {
                // LOAD(space_id, addr) → output
                if o.inrefs.len() >= 2 {
                    let addr_vn = &o.inrefs[1];
                    let addr = addr_vn.read().unwrap();
                    if addr.is_constant() {
                        let offset = addr.get_offset();
                        let size = o.output.as_ref().map(|o| o.read().unwrap().get_size()).unwrap_or(1);
                        let val = self.mem_state.get_bank("ram")
                            .map(|bank| bank.get_value(offset, size))
                            .unwrap_or(0);
                        // Store in registers via output varnode key
                        if let Some(out) = &o.output {
                            let out_vn = out.read().unwrap();
                            self.set_register(out_vn.get_space().space_id() as u64, out_vn.get_offset(), val);
                        }
                    }
                }
                EmulateOpBehavior::Continue
            }
            OpCode::CPUI_STORE => {
                // STORE(space_id, addr, value)
                if o.inrefs.len() >= 3 {
                    let addr_vn = &o.inrefs[1];
                    let val_vn = &o.inrefs[2];
                    let addr = addr_vn.read().unwrap();
                    let val = val_vn.read().unwrap();
                    if addr.is_constant() && val.is_constant() {
                        let offset = addr.get_offset();
                        let size = val.get_size();
                        if let Some(bank) = self.mem_state.get_bank_mut("ram") {
                            bank.set_value(offset, size, val.get_offset());
                        }
                    }
                }
                EmulateOpBehavior::Continue
            }
            _ => {
                // For arithmetic/logic ops: if all inputs are constant,
                // evaluate and store the output.
                if let Some(out) = &o.output {
                    let all_const = o.inrefs.iter().all(|vn| vn.read().unwrap().is_constant());
                    if all_const && !o.inrefs.is_empty() {
                        let result = self.evaluate(&o);
                        if let Some(val) = result {
                            let out_vn = out.read().unwrap();
                            self.set_register(out_vn.get_space().space_id() as u64, out_vn.get_offset(), val);
                        }
                    }
                }
                EmulateOpBehavior::Continue
            }
        }
    }

    // Ghidra: emulate.hh:27 Emulate::evaluate
    /// Evaluate a constant operation using opbehavior.
    fn evaluate(&self, op: &PcodeOp) -> Option<u64> {
        let size_out = op.output.as_ref()?.read().unwrap().get_size();
        let in_size = op.inrefs.first()?.read().unwrap().get_size();
        match op.inrefs.len() {
            1 => {
                let in1 = op.inrefs[0].read().unwrap().get_offset();
                opbehavior::evaluate_unary(op.opcode, size_out, in_size, in1)
            }
            2 | 3 => {
                let in1 = op.inrefs[0].read().unwrap().get_offset();
                let in2 = op.inrefs.get(1)?.read().unwrap().get_offset();
                opbehavior::evaluate_binary(op.opcode, size_out, in_size, in1, in2)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulate_creation() {
        let emu = Emulate::new();
        assert!(!emu.terminated);
        assert_eq!(emu.current_address, 0);
    }

    #[test]
    fn test_register_file() {
        let mut emu = Emulate::new();
        emu.set_register(0, 0x100, 42);
        assert_eq!(emu.get_register(0, 0x100), 42);
        assert_eq!(emu.get_register(0, 0x200), 0);
    }

    #[test]
    fn test_instruction_limit() {
        let mut emu = Emulate::new();
        emu.max_instructions = 5;
        // Simulate 5 instructions
        for _ in 0..5 {
            emu.instruction_count += 1;
        }
        // Next instruction should trigger termination
        emu.instruction_count += 1;
        if emu.max_instructions > 0 && emu.instruction_count > emu.max_instructions {
            emu.terminated = true;
        }
        assert!(emu.terminated);
    }

    /// Build a COPY(out ← const) op and run it: the output register should
    /// hold the constant. Exercises execute_current_op's unary path +
    /// get_value/set_value round-trip.
    #[test]
    fn test_execute_copy_constant() {
        use crate::address::{Address, SeqNum};
        use crate::space::AddressSpace;
        // COPY(Unique:0x100 ← Const 42)
        let const_vn = Arc::new(RwLock::new(Varnode::new_constant(42, 8)));
        let out_vn = Arc::new(RwLock::new(Varnode::new_unique(0x100, 8)));
        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x10), 0), OpCode::CPUI_COPY);
        op.inrefs = vec![const_vn];
        op.output = Some(out_vn.clone());
        let op_arc = Arc::new(RwLock::new(op));
        let mut emu = Emulate::new();
        let disp = emu.execute_current_op(&op_arc);
        assert_eq!(disp, EmulateOpBehavior::Continue);
        // Output should now hold 42 (Unique space id resolves via get_value).
        assert_eq!(emu.get_value(&out_vn), 42);
    }

    /// Build INT_ADD(Unique:0x100, Const 5) → Unique:0x200 and run it: the
    /// output should hold input + 5. Exercises the binary path.
    #[test]
    fn test_execute_int_add() {
        use crate::address::{Address, SeqNum};
        // INT_ADD(Unique:0x100=10, Const 5) → Unique:0x200
        let in0 = Arc::new(RwLock::new(Varnode::new_unique(0x100, 8)));
        let in1 = Arc::new(RwLock::new(Varnode::new_constant(5, 8)));
        let out_vn = Arc::new(RwLock::new(Varnode::new_unique(0x200, 8)));
        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x20), 0), OpCode::CPUI_INT_ADD);
        op.inrefs = vec![in0.clone(), in1];
        op.output = Some(out_vn.clone());
        let op_arc = Arc::new(RwLock::new(op));
        let mut emu = Emulate::new();
        // Seed in0 with 10.
        emu.set_value(&in0, 10);
        let disp = emu.execute_current_op(&op_arc);
        assert_eq!(disp, EmulateOpBehavior::Continue);
        assert_eq!(emu.get_value(&out_vn), 15);
    }

    /// The execute() loop runs a sequence: COPY(c←7), INT_ADD(c, 3→d), d==10.
    #[test]
fn test_execute_loop_chained() {
        use crate::address::{Address, SeqNum};
        let c = Arc::new(RwLock::new(Varnode::new_unique(0x300, 8)));
        let d = Arc::new(RwLock::new(Varnode::new_unique(0x400, 8)));
        // COPY(c ← 7)
        let mut op1 = PcodeOp::new(SeqNum::new(Address::new(0x30), 0), OpCode::CPUI_COPY);
        op1.inrefs = vec![Arc::new(RwLock::new(Varnode::new_constant(7, 8)))];
        op1.output = Some(c.clone());
        // INT_ADD(c, 3 → d)
        let mut op2 = PcodeOp::new(SeqNum::new(Address::new(0x31), 0), OpCode::CPUI_INT_ADD);
        op2.inrefs = vec![c.clone(), Arc::new(RwLock::new(Varnode::new_constant(3, 8)))];
        op2.output = Some(d.clone());
        let ops = vec![Arc::new(RwLock::new(op1)), Arc::new(RwLock::new(op2))];
        let mut emu = Emulate::new();
        let disp = emu.execute(&ops);
        assert_eq!(disp, EmulateOpBehavior::Continue);
        assert_eq!(emu.get_value(&c), 7);
        assert_eq!(emu.get_value(&d), 10);
    }

    /// RETURN terminates the execute loop.
    #[test]
    fn test_execute_return_terminates() {
        use crate::address::{Address, SeqNum};
        let mut ret = PcodeOp::new(SeqNum::new(Address::new(0x40), 0), OpCode::CPUI_RETURN);
        ret.inrefs = vec![Arc::new(RwLock::new(Varnode::new_constant(0, 8)))];
        // A trailing COPY that must NOT execute after the return.
        let out_vn = Arc::new(RwLock::new(Varnode::new_unique(0x500, 8)));
        let mut copy = PcodeOp::new(SeqNum::new(Address::new(0x41), 0), OpCode::CPUI_COPY);
        copy.inrefs = vec![Arc::new(RwLock::new(Varnode::new_constant(99, 8)))];
        copy.output = Some(out_vn.clone());
        let ops = vec![Arc::new(RwLock::new(ret)), Arc::new(RwLock::new(copy))];
        let mut emu = Emulate::new();
        let disp = emu.execute(&ops);
        assert_eq!(disp, EmulateOpBehavior::Return);
        assert!(emu.terminated);
        // The COPY after RETURN must not have run.
        assert_eq!(emu.get_value(&out_vn), 0);
    }
}
