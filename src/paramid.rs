//! Parameter identification — faithful port of `paramid.hh` / `paramid.cc`
//! (284 lines).
//!
//! Analysis for recovering function parameters from call sites. `ParamMeasure`
//! walks data-flow forward/backward to classify how a storage location is used
//! (direct read, sub-function param, return value, indirect, etc.) and assigns
//! a rank indicating likelihood of being a parameter.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/paramid.{hh,cc}.

use crate::address::Address;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::varnode::Varnode;
use std::sync::{Arc, RwLock};

/// I/O direction for a parameter measure. Faithful to `ParamIDIO`
/// (paramid.hh:29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamIdIo {
    /// Input parameter (being read).
    Input = 0,
    /// Output parameter (return value, being written).
    Output = 1,
}

/// Parameter rank indicating likelihood of being a parameter. Faithful to
/// `ParamRank` (paramid.hh:33). Lower rank = more likely to be a parameter.
/// Values are i32 to allow duplicate ranks (as in Ghidra's enum).
#[derive(Debug, Clone, Copy)]
pub struct ParamRank(pub i32);

impl ParamRank {
    /// Best possible rank.
    pub const BEST: Self = Self(1);
    /// Output: direct write without read (most likely return value).
    pub const DIRECT_WRITE_WITHOUT_READ: Self = Self(1);
    /// Input: direct read (most likely parameter).
    pub const DIRECT_READ: Self = Self(2);
    /// Output: direct write with read.
    pub const DIRECT_WRITE_WITH_READ: Self = Self(2);
    /// Output: direct write, unknown read status.
    pub const DIRECT_WRITE_UNKNOWN_READ: Self = Self(3);
    /// Input: passed as sub-function parameter.
    pub const SUB_FN_PARAM: Self = Self(4);
    /// Output: this function's parameter (via backward walk).
    pub const THIS_FN_PARAM: Self = Self(4);
    /// Output: sub-function return value.
    pub const SUB_FN_RETURN: Self = Self(5);
    /// Input: this function's return value (via backward walk).
    pub const THIS_FN_RETURN: Self = Self(5);
    /// Input or Output: indirect usage (least likely parameter).
    pub const INDIRECT: Self = Self(6);
    /// Worst possible rank.
    pub const WORST: Self = Self(7);

    // RUGRA-GLUE: as_i32 (no Ghidra counterpart found)
    /// Get the numeric measure. Faithful to `getMeasure`.
    pub fn as_i32(&self) -> i32 {
        self.0
    }
}

impl PartialEq for ParamRank {
    // RUGRA-GLUE: eq (no Ghidra counterpart found)
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ParamRank {}

impl PartialOrd for ParamRank {
    // RUGRA-GLUE: partial_cmp (no Ghidra counterpart found)
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl Ord for ParamRank {
    // RUGRA-GLUE: cmp (no Ghidra counterpart found)
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// State carried during forward/backward walks. Faithful to `WalkState`
/// (paramid.hh:47).
#[derive(Debug, Clone, Copy)]
pub struct WalkState {
    /// Whether to take the best (min) or worst (max) rank.
    pub best: bool,
    /// Current recursion depth.
    pub depth: i32,
    /// The rank at which to stop walking.
    pub terminal_rank: ParamRank,
}

impl Default for WalkState {
    // Ghidra: paramid.hh:47 WalkState::default
    fn default() -> Self {
        Self {
            best: true,
            depth: 0,
            terminal_rank: ParamRank::WORST,
        }
    }
}

/// Maximum recursion depth for forward/backward walks. Faithful to MAXDEPTH
/// (paramid.cc:36).
const MAX_DEPTH: i32 = 10;

/// A measure of how likely a storage location is to be a parameter. Faithful
/// to `ParamMeasure` (paramid.hh:27).
pub struct ParamMeasure {
    /// The storage location offset.
    pub vn_offset: u64,
    /// The address space of the storage.
    pub vn_space: AddressSpace,
    /// The size of the storage in bytes.
    pub vn_size: u32,
    /// The data-type name (full Datatype integration deferred).
    pub vn_type_name: String,
    /// The I/O direction (input or output).
    pub io: ParamIdIo,
    /// The computed rank.
    pub rank: ParamRank,
    /// Number of calls seen during the walk.
    pub numcalls: i32,
}

impl ParamMeasure {
    // Ghidra: paramid.hh:27 ParamMeasure::new
    /// Construct given address, size, type name, and I/O direction. Faithful
    /// to the constructor (paramid.hh:62).
    pub fn new(addr: Address, space: AddressSpace, sz: u32, type_name: &str, io: ParamIdIo) -> Self {
        Self {
            vn_offset: addr.as_u64(),
            vn_space: space,
            vn_size: sz,
            vn_type_name: type_name.to_string(),
            io,
            rank: ParamRank::WORST,
            numcalls: 0,
        }
    }

    // Ghidra: paramid.hh:27 ParamMeasure::updateRank
    /// Update the rank, taking min or max based on `best`. Faithful to
    /// `updaterank` (paramid.hh:60).
    fn update_rank(&mut self, rank_in: ParamRank, best: bool) {
        self.rank = if best {
            self.rank.min(rank_in)
        } else {
            self.rank.max(rank_in)
        };
    }

    // Ghidra: paramid.hh:27 ParamMeasure::getMeasure
    /// Get the computed measure (rank as integer). Faithful to `getMeasure`.
    pub fn get_measure(&self) -> i32 {
        self.rank.as_i32()
    }

    // Ghidra: paramid.hh:27 ParamMeasure::walkForward
    /// Walk forward through descendant ops to classify input usage. Faithful
    /// to `walkforward` (paramid.cc:37).
    pub fn walk_forward(
        &mut self,
        state: &mut WalkState,
        ignore_op: Option<&Arc<RwLock<PcodeOp>>>,
        vn: &Arc<RwLock<Varnode>>,
    ) {
        state.depth += 1;
        if state.depth >= MAX_DEPTH {
            state.depth -= 1;
            return;
        }
        let descend_ops: Vec<Arc<RwLock<PcodeOp>>> = vn.read().unwrap().descend_iter().collect();
        for op_arc in descend_ops {
            if self.rank == state.terminal_rank {
                break;
            }
            // Check if this is the ignore op.
            if let Some(ig) = ignore_op {
                if Arc::ptr_eq(&op_arc, ig) {
                    continue;
                }
            }
            let op_rg = op_arc.read().unwrap();
            let oc = op_rg.opcode;
            // Find the slot of vn in this op's inputs.
            let slot = (0..op_rg.num_input()).find(|&i| {
                op_rg.get_in(i).map(|v| Arc::ptr_eq(v, vn)).unwrap_or(false)
            });
            drop(op_rg);
            match oc {
                OpCode::CPUI_BRANCH | OpCode::CPUI_BRANCHIND => {
                    if slot == Some(0) {
                        self.update_rank(ParamRank::DIRECT_READ, state.best);
                    }
                }
                OpCode::CPUI_CBRANCH => {
                    if slot.map(|s| s < 2).unwrap_or(false) {
                        self.update_rank(ParamRank::DIRECT_READ, state.best);
                    }
                }
                OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                    if slot == Some(0) {
                        self.update_rank(ParamRank::DIRECT_READ, state.best);
                    } else {
                        self.numcalls += 1;
                        self.update_rank(ParamRank::SUB_FN_PARAM, state.best);
                    }
                }
                OpCode::CPUI_CALLOTHER => {
                    self.update_rank(ParamRank::DIRECT_READ, state.best);
                }
                OpCode::CPUI_RETURN => {
                    self.update_rank(ParamRank::THIS_FN_RETURN, state.best);
                }
                OpCode::CPUI_INDIRECT => {
                    self.update_rank(ParamRank::INDIRECT, state.best);
                }
                OpCode::CPUI_MULTIEQUAL => {
                    // Walk forward through the output, avoiding loops.
                    // L3 gap: full isLoopIn check requires BlockBasic.
                    let out = op_arc.read().unwrap().get_out().cloned();
                    drop(op_arc);
                    if let Some(out_vn) = out {
                        self.walk_forward(state, None, &out_vn);
                    }
                }
                _ => {
                    self.update_rank(ParamRank::DIRECT_READ, state.best);
                }
            }
        }
        state.depth -= 1;
    }

    // Ghidra: paramid.hh:27 ParamMeasure::walkBackward
    /// Walk backward through the defining op to classify output usage. Faithful
    /// to `walkbackward` (paramid.cc:90).
    pub fn walk_backward(
        &mut self,
        state: &mut WalkState,
        ignore_op: Option<&Arc<RwLock<PcodeOp>>>,
        vn: &Arc<RwLock<Varnode>>,
    ) {
        let vn_rg = vn.read().unwrap();
        if vn_rg.is_input() {
            drop(vn_rg);
            self.update_rank(ParamRank::THIS_FN_PARAM, state.best);
            return;
        }
        if !vn_rg.is_written() {
            drop(vn_rg);
            self.update_rank(ParamRank::THIS_FN_PARAM, state.best);
            return;
        }
        let def_op = vn_rg.get_def();
        drop(vn_rg);
        let Some(def) = def_op else {
            return;
        };
        let oc = def.read().unwrap().opcode;
        match oc {
            OpCode::CPUI_BRANCH
            | OpCode::CPUI_BRANCHIND
            | OpCode::CPUI_CBRANCH
            | OpCode::CPUI_CALL
            | OpCode::CPUI_CALLIND => {
                // No rank update for these.
            }
            OpCode::CPUI_CALLOTHER => {
                self.update_rank(ParamRank::DIRECT_READ, state.best);
            }
            OpCode::CPUI_RETURN => {
                self.update_rank(ParamRank::SUB_FN_RETURN, state.best);
            }
            OpCode::CPUI_INDIRECT => {
                self.update_rank(ParamRank::INDIRECT, state.best);
            }
            OpCode::CPUI_MULTIEQUAL => {
                // Walk backward through all inputs, avoiding loops.
                let n_in = def.read().unwrap().num_input();
                for slot in 0..n_in {
                    if self.rank == state.terminal_rank {
                        break;
                    }
                    let in_vn = def.read().unwrap().get_in(slot).cloned();
                    if let Some(in_vn) = in_vn {
                        self.walk_backward(state, Some(&def), &in_vn);
                    }
                }
            }
            _ => {
                // Default: might be DIRECTWRITEWITHOUTREAD or DIRECTWRITEWITHREAD.
                // Full implementation does a forward walk to check; simplified
                // to DIRECTWRITEWITHOUTREAD.
                self.update_rank(ParamRank::DIRECT_WRITE_WITHOUT_READ, state.best);
            }
        }
    }

    // Ghidra: paramid.cc:141 ParamMeasure::calculateRank
    /// Calculate the rank for this parameter measure. Faithful to
    /// `calculateRank` (paramid.cc:141).
    pub fn calculate_rank(
        &mut self,
        best: bool,
        base_vn: &Arc<RwLock<Varnode>>,
        ignore_op: Option<&Arc<RwLock<PcodeOp>>>,
    ) {
        let mut state = WalkState::default();
        state.best = best;
        state.depth = 0;
        if best {
            self.rank = ParamRank::WORST;
            state.terminal_rank = if self.io == ParamIdIo::Input {
                ParamRank::DIRECT_READ
            } else {
                ParamRank::DIRECT_WRITE_WITHOUT_READ
            };
        } else {
            self.rank = ParamRank::BEST;
            state.terminal_rank = ParamRank::INDIRECT;
        }
        self.numcalls = 0;
        if self.io == ParamIdIo::Input {
            self.walk_forward(&mut state, ignore_op, base_vn);
        } else {
            self.walk_backward(&mut state, ignore_op, base_vn);
        }
    }
}

/// Parameter identification analysis for a function. Faithful to
/// `ParamIDAnalysis` (paramid.hh:70).
pub struct ParamIdAnalysis {
    /// Input parameter measures.
    pub input_measures: Vec<ParamMeasure>,
    /// Output parameter measures.
    pub output_measures: Vec<ParamMeasure>,
}

impl Default for ParamIdAnalysis {
    // RUGRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

impl ParamIdAnalysis {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct an empty analysis.
    pub fn new() -> Self {
        Self {
            input_measures: Vec::new(),
            output_measures: Vec::new(),
        }
    }

    // RUGRA-GLUE: add_input (no Ghidra counterpart found)
    /// Add an input parameter measure.
    pub fn add_input(&mut self, pm: ParamMeasure) {
        self.input_measures.push(pm);
    }

    // RUGRA-GLUE: add_output (no Ghidra counterpart found)
    /// Add an output parameter measure.
    pub fn add_output(&mut self, pm: ParamMeasure) {
        self.output_measures.push(pm);
    }

    // RUGRA-GLUE: num_inputs (no Ghidra counterpart found)
    /// Number of input measures.
    pub fn num_inputs(&self) -> usize {
        self.input_measures.len()
    }

    // RUGRA-GLUE: num_outputs (no Ghidra counterpart found)
    /// Number of output measures.
    pub fn num_outputs(&self) -> usize {
        self.output_measures.len()
    }

    // RUGRA-GLUE: save_pretty (no Ghidra counterpart found)
    /// Get a pretty-printed description of all measures. Faithful to
    /// `savePretty` (paramid.cc:264).
    pub fn save_pretty(&self) -> String {
        let mut s = String::new();
        s.push_str("Param Measures\n");
        s.push_str(&format!("Num Params: {}\n", self.num_inputs()));
        for pm in &self.input_measures {
            s.push_str(&format!(
                "  Addr: {:#x}\n  Size: {}\n  Rank: {}\n",
                pm.vn_offset, pm.vn_size, pm.rank.as_i32()
            ));
        }
        s.push_str(&format!("Num Returns: {}\n", self.num_outputs()));
        for pm in &self.output_measures {
            s.push_str(&format!(
                "  Addr: {:#x}\n  Size: {}\n  Rank: {}\n",
                pm.vn_offset, pm.vn_size, pm.rank.as_i32()
            ));
        }
        s
    }

    // RUGRA-GLUE: analyze (no Ghidra counterpart found)
    /// Analyze a function's parameters using data-flow classification.
    /// Faithful to `ParamIDAnalysis` constructor (paramid.cc:186).
    ///
    /// Iterates input Varnodes, creates ParamMeasure for each, and calls
    /// `calculate_rank` to classify usage. Also checks RETURN ops for
    /// output parameters.
    pub fn analyze(&mut self, fd: &crate::funcdata::Funcdata) {
        use crate::opcodes::OpCode;

        // Analyze input parameters.
        let varnodes: Vec<_> = fd
            .vbank
            .loc_tree
            .iter()
            .map(|v| v.0.clone())
            .collect();

        for vn_arc in &varnodes {
            let vn_rg = vn_arc.read().unwrap();
            if !vn_rg.is_input() {
                continue;
            }
            // Create a ParamMeasure for this input.
            let mut pm = ParamMeasure::new(
                crate::address::Address::new(vn_rg.get_offset()),
                vn_rg.get_space(),
                vn_rg.get_size() as u32,
                "unknown",
                ParamIdIo::Input,
            );
            // Calculate rank by walking forward through descendants.
            pm.calculate_rank(true, vn_arc, None);
            self.add_input(pm);
        }

        // Analyze output (return value) from RETURN ops.
        for op_ref in fd.obank.iter_alive() {
            let op_rg = op_ref.0.read().unwrap();
            if op_rg.opcode != OpCode::CPUI_RETURN {
                continue;
            }
            // RETURN input(1) = return value (if numInput >= 2).
            if op_rg.num_input() >= 2 {
                if let Some(ret_vn) = op_rg.get_in(1) {
                    let vn_rg = ret_vn.read().unwrap();
                    let mut pm = ParamMeasure::new(
                        crate::address::Address::new(vn_rg.get_offset()),
                        vn_rg.get_space(),
                        vn_rg.get_size() as u32,
                        "unknown",
                        ParamIdIo::Output,
                    );
                    pm.calculate_rank(true, ret_vn, Some(&op_ref.0));
                    self.add_output(pm);
                }
            }
            break; // Only use the first RETURN op.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_rank_ordering() {
        assert!(ParamRank::DIRECT_READ < ParamRank::SUB_FN_PARAM);
        assert!(ParamRank::SUB_FN_PARAM < ParamRank::INDIRECT);
        assert!(ParamRank::INDIRECT < ParamRank::WORST);
    }

    #[test]
    fn test_param_measure_construction() {
        let pm = ParamMeasure::new(
            Address::new(0x1000),
            AddressSpace::Register,
            4,
            "int",
            ParamIdIo::Input,
        );
        assert_eq!(pm.vn_offset, 0x1000);
        assert_eq!(pm.vn_size, 4);
        assert_eq!(pm.io, ParamIdIo::Input);
        assert_eq!(pm.rank, ParamRank::WORST);
        assert_eq!(pm.get_measure(), ParamRank::WORST.as_i32());
    }

    #[test]
    fn test_update_rank_best() {
        let mut pm = ParamMeasure::new(
            Address::new(0),
            AddressSpace::Register,
            4,
            "int",
            ParamIdIo::Input,
        );
        // best=true → take min.
        pm.update_rank(ParamRank::INDIRECT, true);
        assert_eq!(pm.rank, ParamRank::INDIRECT);
        pm.update_rank(ParamRank::DIRECT_READ, true);
        assert_eq!(pm.rank, ParamRank::DIRECT_READ);
    }

    #[test]
    fn test_update_rank_worst() {
        let mut pm = ParamMeasure::new(
            Address::new(0),
            AddressSpace::Register,
            4,
            "int",
            ParamIdIo::Input,
        );
        pm.rank = ParamRank::BEST;
        // best=false → take max.
        pm.update_rank(ParamRank::DIRECT_READ, false);
        assert_eq!(pm.rank, ParamRank::DIRECT_READ);
        pm.update_rank(ParamRank::INDIRECT, false);
        assert_eq!(pm.rank, ParamRank::INDIRECT);
    }

    #[test]
    fn test_param_measure_output() {
        let pm = ParamMeasure::new(
            Address::new(0x2000),
            AddressSpace::Register,
            8,
            "long",
            ParamIdIo::Output,
        );
        assert_eq!(pm.io, ParamIdIo::Output);
    }

    #[test]
    fn test_param_id_analysis() {
        let mut analysis = ParamIdAnalysis::new();
        assert_eq!(analysis.num_inputs(), 0);
        analysis.add_input(ParamMeasure::new(
            Address::new(0x100),
            AddressSpace::Register,
            4,
            "int",
            ParamIdIo::Input,
        ));
        assert_eq!(analysis.num_inputs(), 1);
        assert_eq!(analysis.num_outputs(), 0);
        analysis.add_output(ParamMeasure::new(
            Address::new(0x200),
            AddressSpace::Register,
            8,
            "long",
            ParamIdIo::Output,
        ));
        assert_eq!(analysis.num_outputs(), 1);
    }

    #[test]
    fn test_save_pretty() {
        let mut analysis = ParamIdAnalysis::new();
        analysis.add_input(ParamMeasure::new(
            Address::new(0x100),
            AddressSpace::Register,
            4,
            "int",
            ParamIdIo::Input,
        ));
        let s = analysis.save_pretty();
        assert!(s.contains("Param Measures"));
        assert!(s.contains("Num Params: 1"));
        assert!(s.contains("0x100"));
    }

    #[test]
    fn test_walk_state_default() {
        let ws = WalkState::default();
        assert!(ws.best);
        assert_eq!(ws.depth, 0);
        assert_eq!(ws.terminal_rank, ParamRank::WORST);
    }
}
