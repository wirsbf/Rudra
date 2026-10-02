//! # Rugra - Rust Ghidra-inspired Decompiler
//!
//! A high-performance, memory-safe decompiler for C/C++ binaries written in Rust.
//! Rugra aims to provide production-quality decompilation with a focus on correctness,
//! performance, and extensibility.
//!
//! ## Architecture
//!
//! ```text
//! Binary → Loader → Disassembler → P-code IR → Analysis → AST → C Code
//!    ↓                   ↓             ↓          ↓        ↓       ↓
//!   ELF              x86/ARM        SSA Form    CFG      Types   Output
//!   PE               MIPS           Optimizer   DFA
//!   Mach-O
//! ```
//!
//! ## Modules
//!
//! - [`binary`] - Binary parsing and loading (ELF, PE, Mach-O)
//! - [`pcode`] - P-code intermediate representation
//! - [`analysis`] - Control flow, data flow, and type analysis
//! - [`codegen`] - C code generation
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use rudra::Funcdata;
//! use rudra::action::ActionDatabase;
//!
//! // Create a Funcdata for the target function
//! let mut fd = Funcdata::new("main", rudra::Address::new(0x401000));
//!
//! // Inject raw P-code operations (from a lifter)
//! // fd.inject_raw_ops(&raw_ops);
//!
//! // Run the analysis pipeline
//! let db = ActionDatabase::build_default();
//! db.apply(&mut fd).expect("analysis pipeline");
//!
//! // Generate C output via PrintC
//! ```

#![allow(missing_docs)] // Re-enable when approaching stable release
#![warn(clippy::all)]
#![allow(dead_code)] // During development

// Core Ghidra-aligned modules
pub mod action; // ← action.hh
pub mod address; // ← address.hh
pub mod analysis; // ← type propagation
pub mod arch; // ← architecture.hh (Ghidra Architecture config container)
pub mod arena; // ← Rust-side arena core (no Ghidra counterpart; see docs/api/arena.md — PERF-ARENA-CORE-0001)
pub mod block; // ← block.hh
pub mod blockaction;
pub mod callgraph; // ← callgraph.hh
pub mod capability; // ← capability.hh
pub mod coreaction; // ← coreaction.hh
pub mod condexe; // ← condexe.hh
pub mod comment; // ← comment.hh
pub mod compression; // ← compression.hh
pub mod constseq; // ← constseq.hh
pub mod context; // ← globalcontext.hh
pub mod cpool; // ← cpool.hh
pub mod cover; // ← cover.hh
pub mod crc32; // ← crc32.hh
pub mod database; // ← database.hh (Symbol/Scope/Database)
pub mod debugproto; // native DWARF → locked FuncProto front-end boundary
pub mod frontend; // native ELF front-end boundary: symbols/discovery/memory map/demangle
pub mod double_precis; // ← double.cc (SplitVarnode double-precision merge)
pub mod fspec; // ← fspec.hh
pub mod funcdata; // ← funcdata.hh
pub mod grammar; // ← grammar.hh
pub mod graph; // ← graph.hh
pub mod heritage; // ← heritage.hh
pub mod jumptable; // ← jumptable.hh
pub mod expression; // ← expression.hh
pub mod loadimage; // ← loadimage.hh
pub mod marshal; // ← marshal.hh + xml.hh (serialization)
pub mod emulate; // ← emulate.hh
pub mod float_emulate; // ← float.hh
pub mod merge; // ← merge.hh
pub mod memstate; // ← memstate.hh
pub mod modelrules; // ← modelrules.hh
pub mod op; // ← op.hh
pub mod drillfmt; // ← drill emitter raw formatters (RUGRA-GLUE)
pub mod drillobserve; // ← drill emitter recorder (RUGRA-GLUE)
pub mod opcodes; // ← opcodes.hh
pub mod opbehavior; // ← opbehavior.hh
pub mod options; // ← options.hh
pub mod override_rs; // ← override.hh (Override commands)
pub mod paramid; // ← paramid.hh
pub mod pcoderaw; // ← pcoderaw.hh
pub mod prefersplit; // ← prefersplit.hh
pub mod prettyprint; // ← prettyprint.hh
pub mod printc; // ← printc.hh
pub mod printlanguage; // ← printlanguage.hh
pub mod pcodeinject; // ← pcodeinject.hh
pub mod pcodeparse; // ← pcodeparse.hh + pcodecompile.hh
pub mod rangeutil; // ← rangeutil.hh
pub mod rangemap; // ← rangemap.hh + partmap.hh
pub mod ruleaction; // ← ruleaction.hh
pub mod sailr; // ← ENHANCEMENT domain: SAILR structuring layer (no Ghidra counterpart)
pub mod signature; // ← signature.hh
pub mod space; // ← space.hh
pub mod stringmanage; // ← stringmanage.hh
pub mod subflow; // ← subflow.hh
pub mod transform; // ← transform.hh
pub mod translate; // ← translate.hh
pub mod type_system; // ← type.hh
pub mod typeop; // ← typeop.hh
pub mod unionresolve; // ← unionresolve.hh
pub mod unify; // ← unify.hh
pub mod dynamic; // ← dynamic.hh
pub mod userop; // ← userop.hh
pub mod variable; // ← variable.hh
pub mod varnode; // ← varnode.hh // ← blockaction.hh

// Temporarily disabled - legacy modules using old Program API
// TODO: Update these to use new Arc<RwLock<>> architecture
pub mod align;
pub mod binary;
pub mod disasm;
pub mod sleigh_ffi;
pub mod ffi;
pub mod tracedag;
pub mod varmap;
pub mod flow; // ← flow.hh (FlowInfo reachability-based flow tracking)

mod error;
mod types;
mod utils;

// Re-exports
pub use address::{Address, Range, RangeList, RangeProperties, SeqNum};
pub use block::{BlockBasic, BlockEdge, BlockRef};
pub use error::{Error, Result};
pub use fspec::{FuncProto, ProtoParameter};
pub use funcdata::Funcdata;
pub use opcodes::OpCode;
pub use space::AddressSpace;
pub use type_system::{Datatype, TypeMetatype};
pub use types::Architecture;

// use std::collections::HashMap;

// Temporarily disabled - Decompiler uses old Program API
// TODO: Reimplement using new VarnodeBank/PcodeOpBank architecture
/*
/// Main decompiler interface
///
/// This is the primary entry point for using Rugra. It orchestrates the entire
/// decompilation pipeline from binary loading to C code generation.
///
/// # Example
///
/// ```rust,no_run
/// use rudra::{Decompiler, Architecture};
///
/// # fn main() -> anyhow::Result<()> {
/// let mut dec = Decompiler::new(Architecture::X86_64)?;
/// dec.load_binary(&std::fs::read("binary")?)?;
/// let code = dec.decompile_function(0x1000)?;
/// # Ok(())
/// # }
/// ```
pub struct Decompiler {
    /// Target architecture
    arch: Architecture,

    /// Loaded binary
    binary: Option<binary::Binary>,

    /// P-code programs for each function
    pcode_cache: HashMap<Address, pcode::Program>,

    /// Analysis results cache
    analysis_cache: HashMap<Address, analysis::FunctionAnalysis>,
}

impl Decompiler {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Create a new decompiler for the specified architecture
    ///
    /// # Arguments
    ///
    /// * `arch` - Target architecture (X86_64, ARM64, etc.)
    ///
    /// # Returns
    ///
    /// A new decompiler instance
    pub fn new(arch: Architecture) -> Result<Self> {
        Ok(Self {
            arch,
            binary: None,
            pcode_cache: HashMap::new(),
            analysis_cache: HashMap::new(),
        })
    }

    // RUGRA-GLUE: load_binary (no Ghidra counterpart found)
    /// Load a binary file for analysis
    ///
    /// # Arguments
    ///
    /// * `data` - Raw binary data
    ///
    /// # Returns
    ///
    /// Result indicating success or failure
    pub fn load_binary(&mut self, data: &[u8]) -> Result<()> {
        let binary = binary::Binary::parse(data)?;
        self.binary = Some(binary);
        Ok(())
    }

    // RUGRA-GLUE: decompile_function (no Ghidra counterpart found)
    /// Decompile a function at the given address
    ///
    /// # Arguments
    ///
    /// * `address` - Virtual address of the function entry point
    ///
    /// # Returns
    ///
    /// Decompiled C code as a string
    pub fn decompile_function(&mut self, address: u64) -> Result<String> {
        let addr = Address::new(address);

        // Ensure binary is loaded
        let binary = self.binary.as_ref()
            .ok_or(Error::NoBinaryLoaded)?;

        // Get or generate P-code
        if !self.pcode_cache.contains_key(&addr) {
            let pcode = self.generate_pcode(binary, addr)?;
            self.pcode_cache.insert(addr, pcode);
        }

        // Get or perform analysis
        if !self.analysis_cache.contains_key(&addr) {
            let pcode = self.pcode_cache.get_mut(&addr).expect("P-code not found");
            let analysis = analysis::analyze_function(pcode, Some(binary))?;
            self.analysis_cache.insert(addr, analysis);
        }

        // Generate C code
        let analysis = &self.analysis_cache[&addr];
        let pcode = self.pcode_cache.get(&addr).expect("P-code not found");
        let c_code = codegen::generate_c_code(analysis, pcode, self.binary.as_ref())?;

        Ok(c_code)
    }

    // RUGRA-GLUE: get_functions (no Ghidra counterpart found)
    /// Get list of all functions in the binary
    ///
    /// # Returns
    ///
    /// Vector of function entry point addresses
    pub fn get_functions(&self) -> Result<Vec<Address>> {
        let binary = self.binary.as_ref()
            .ok_or(Error::NoBinaryLoaded)?;
        Ok(binary.get_functions())
    }

    // RUGRA-GLUE: get_function_name (no Ghidra counterpart found)
    /// Get the name of a function at the given address
    pub fn get_function_name(&self, addr: Address) -> Option<String> {
        self.binary.as_ref()?.get_function_name(addr).cloned()
    }

    // RUGRA-GLUE: architecture (no Ghidra counterpart found)
    /// Get the target architecture
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    // RUGRA-GLUE: clear_cache (no Ghidra counterpart found)
    /// Clear all caches
    pub fn clear_cache(&mut self) {
        self.pcode_cache.clear();
        self.analysis_cache.clear();
    }

    // RUGRA-GLUE: generate_pcode (no Ghidra counterpart found)
    // Private helper methods

    fn generate_pcode(&self, binary: &binary::Binary, addr: Address) -> Result<pcode::Program> {
        use crate::translator::Translator;

        let instructions = binary.disassemble_function(addr, self.arch)?;

        // Create translator for architecture
        // Currently we primary support X86_64
        let translator = crate::translator::X86_64Translator::new();

        let mut program = pcode::Program::with_entry_point(addr);

        for instr in instructions {
            match translator.translate(&instr) {
                Ok(ops) => {
                    for op in ops {
                        program.add_operation(op);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to translate instruction at {}: {}", instr.address, e);
                }
            }
        }

        Ok(program)
    }
}
*/

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// RUGRA-GLUE: version (no Ghidra counterpart found)
/// Get the version string
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    // Temporarily disabled - Decompiler is commented out
    // #[test]
    // fn test_decompiler_creation() {
    //     let dec = Decompiler::new(Architecture::X86_64);
    //     assert!(dec.is_ok());
    // }

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
    }
}
