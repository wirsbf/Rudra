# Pipeline Migration Plan: Monolithic `Program` to Concurrent `Funcdata`

## 1. Context & Motivation

Currently, Rudra's decompilation pipeline has two distinct paradigms coexisting:
1. **The Old Pipeline**: Centered around `src/pcode/program.rs` (`Program` structure) and `src/analysis/mod.rs` (`analyze_function`). This pipeline is monolithic, running sequential passes (CFG -> Variables -> Type Inference -> SSA -> Optimization). It relies on flat `Vec<PcodeOperation>`.
2. **The New Pipeline (Ghidra-Aligned)**: Centered around `src/funcdata.rs` (`Funcdata`) and `src/action.rs` (`Action` & `ActionDatabase`). This matches Ghidra's C++ design, using `VarnodeBank` and `PcodeOpBank` for efficient graph manipulations, and modular `Action` passes that can be dynamically grouped and run until fixed points.

The goal is to **completely deprecate the Old Pipeline** and migrate all logic to the New Pipeline to achieve 1:1 alignment with Ghidra's decompiler architecture and enable concurrent/modular analysis.

## 2. Structural Mapping

| Old Abstraction (`src/`) | New Ghidra-Aligned Abstraction (`src/`) | Migration Action |
| --- | --- | --- |
| `pcode::Program` | `Funcdata` | Replace. `Funcdata` acts as the root container. |
| `pcode::PcodeOperation` (Flat Vec) | `op::PcodeOpBank` + `PcodeOp` | Ops are now double-linked through `Varnode` use-def chains. |
| `pcode::Varnode` (Standalone) | `varnode::VarnodeBank` | Varnodes are centrally managed and deduplicated. |
| `analysis::cfg::ControlFlowGraph` | `block::BlockGraph` | Migrate graph algorithms; blocks natively own their P-code ops. |

## 3. Pipeline Pass Migration Strategy

The monolithic `analyze_function` in `src/analysis/mod.rs` must be split into independent `Action` implementations that implement `fn apply(&self, fd: &mut Funcdata) -> Result<i32>`.

1. **CFG Construction (`analysis::cfg`)**:
   - *Target*: Move to function initialization or a specific `ActionBlockStructure`.
   - *Change*: `BlockGraph` should be built directly when populating `Funcdata` from raw P-code.
2. **SSA Construction (`analysis::ssa`)**:
   - *Target*: `ActionHeritage` in `src/coreaction.rs`.
   - *Change*: `Funcdata::heritage` already exists. Need to ensure Phi placement algorithm aligns with Ghidra's `heritage.cc`.
3. **Variable Recovery (`analysis::variables`)**:
   - *Target*: `ActionMergeRequired` / `VarnodeBank::merge` logic.
   - *Change*: High variables in Ghidra are managed by merging varnodes that share the same storage and don't destructively interfere.
4. **Type Propagation (`analysis::type_propagation`)**:
   - *Target*: Implement an `ActionTypeProp` or integrate into the `ActionDatabase`.
   - *Change*: Leverage `Datatype` attachments directly on `Varnode` via use-def chaining rather than separate solver maps.
5. **Optimization (`analysis::optimization`)**:
   - *Target*: Break down into `Rule`s in `ruleaction.rs` (e.g., `RuleAddConstant`, `RuleCopyPropagation`) and apply them via pool actions like `ActionDeadCode` and `ActionCse`.

## 4. Phase Execution Plan

### Phase 1: Dual-Boot Support
- Keep the old `Program` pipeline intact for existing users.
- Plumb FFI/CLI adapters to optionally construct `Funcdata` and run the `ActionDatabase` for testing (`ActionStart`, `ActionHeritage`, `ActionDeadCode`).

### Phase 2: Action Ports
- Port individual passes from `src/analysis/*` to independent `Action` or `Rule` structs.
- Validate each ported action functionally matches the old pass logic or improves upon it via Ghidra alignment.

### Phase 3: Replacement & Cleanup
- Switch the main CLI/FFI entry point to exclusively build `Funcdata` and execute the `ActionDatabase`.
- Delete `src/pcode/program.rs` and the legacy code in `src/analysis/mod.rs`.
- Update `docs/api` to reflect the removed modules.

## 5. Verification Plan

1. **Unit Tests**: Modify `cargo test` to execute both old and new pipelines on synthetic P-code and compare the semantic equivalence of the final `HighVariable` states.
2. **FFI Alignment**: Run `cargo test --features ffi-test runtime_verify::` to ensure the new `Funcdata`-based execution precisely matches Ghidra C++ `DecompileProcess` output for given binaries.
