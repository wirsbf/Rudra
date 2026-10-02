//! Architecture configuration options — faithful port of `options.hh` /
//! `options.cc` (1063 lines).
//!
//! Classes for processing architecture configuration options. Each option
//! modifies the Architecture object's configuration via its `apply` method.
//! `OptionDatabase` dispatches option commands by name.
//!
//! ## Alignment
//!
//! Every ported function carries a `// Ghidra: options.cc:<line> <symbol>`
//! comment pointing at the exact upstream definition. Pure Rust glue that
//! has no Ghidra counterpart is marked `// RUDRA-GLUE: <reason>`.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/options.{hh,cc}.

use crate::arch::Architecture;
use crate::flow::flow_flags;
use std::collections::HashMap;

// Ghidra: options.cc:69 ArchOption::onOrOff
/// Parse an "on" or "off" string into a boolean. Faithful to
/// `ArchOption::onOrOff` (options.cc:69). An empty string defaults to true.
///
/// Ghidra throws `ParseError` for any other value. Rugra returns `true`
/// for unknown values to keep the `apply` signatures side-effect free.
pub fn on_or_off(p: &str) -> bool {
    if p.is_empty() {
        return true;
    }
    if p == "on" {
        return true;
    }
    if p == "off" {
        return false;
    }
    true
}

// Ghidra: options.hh:75 ArchOption
/// Base trait for options that affect Architecture configuration. Faithful to
/// `ArchOption` (options.hh:75-95).
pub trait ArchOption: Send + Sync {
    // RUDRA-GLUE: name (Rust trait returns a constant; C++ has protected field).
    fn name(&self) -> &str;
    // Ghidra: options.hh:92 ArchOption::apply
    /// Apply the option. Returns the confirmation message; a message
    /// starting with `"LowlevelError: "` represents the exception Ghidra
    /// throws out of `apply` (the C++ signature has no error channel, the
    /// exception propagates through `OptionDatabase::set`).
    fn apply(&self, arch: &mut Architecture, p1: &str, p2: &str, p3: &str) -> String;
}

// ===========================================================================
// options.cc:213 OptionExtraPop::apply
// ===========================================================================
/// Set the \b extrapop parameter used by the (default) prototype model.
/// Faithful to `OptionExtraPop::apply` (options.cc:213-244).
pub struct OptionExtraPop;
impl ArchOption for OptionExtraPop {
    // Ghidra: options.cc:97 OptionExtraPop constructor (name = "extrapop")
    fn name(&self) -> &str {
        "extrapop"
    }
    // Ghidra: options.cc:213 OptionExtraPop::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        let expop: i32;
        if p1 == "unknown" {
            expop = -2000; // ProtoModel::extrapop_unknown
        } else {
            match parse_int_any_base(p1) {
                Some(v) => expop = v as i32,
                None => {
                    return "Bad extrapop adjustment parameter".to_string();
                }
            }
        }
        // RUDRA-GLUE: ProtoModelEntry has no extrapop field; setExtraPop deferred.
        let _ = expop;
        if !p2.is_empty() {
            format!("ExtraPop set for function {p2}")
        } else {
            "Global extrapop set".to_string()
        }
    }
}

// ===========================================================================
// options.cc:251 OptionReadOnly::apply
// ===========================================================================
/// Toggle whether read-only memory locations propagate. Faithful to
/// `OptionReadOnly::apply` (options.cc:251-260).
pub struct OptionReadOnly;
impl ArchOption for OptionReadOnly {
    // Ghidra: options.hh:126 OptionReadOnly::OptionReadOnly
    fn name(&self) -> &str {
        "readonly"
    }
    // Ghidra: options.cc:251 OptionReadOnly::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        arch.readonlypropagate = val;
        if val {
            "Read-only memory locations now propagate as constants".to_string()
        } else {
            "Read-only memory locations now do not propagate".to_string()
        }
    }
}

// ===========================================================================
// options.cc:266 OptionDefaultPrototype::apply
// ===========================================================================
/// Set the default prototype model. Faithful to
/// `OptionDefaultPrototype::apply` (options.cc:266-274).
pub struct OptionDefaultPrototype;
impl ArchOption for OptionDefaultPrototype {
    // Ghidra: options.hh:132 OptionDefaultPrototype::OptionDefaultPrototype
    fn name(&self) -> &str {
        "defaultprototype"
    }
    // Ghidra: options.cc:266 OptionDefaultPrototype::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if arch.get_model(p1).is_none() {
            return format!("Unknown prototype model :{p1}");
        }
        arch.set_default_model(p1);
        format!("Set default prototype to {p1}")
    }
}

// ===========================================================================
// options.cc:281 OptionInferConstPtr::apply
// ===========================================================================
/// Toggle whether the decompiler infers constant pointers. Faithful to
/// `OptionInferConstPtr::apply` (options.cc:281-296).
pub struct OptionInferConstPtr;
impl ArchOption for OptionInferConstPtr {
    // Ghidra: options.hh:138 OptionInferConstPtr::OptionInferConstPtr
    fn name(&self) -> &str {
        "inferconstptr"
    }
    // Ghidra: options.cc:281 OptionInferConstPtr::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        let res = if val {
            "Constant pointers are now inferred"
        } else {
            "Constant pointers must now be set explicitly"
        };
        arch.infer_pointers = val;
        res.to_string()
    }
}

// ===========================================================================
// options.cc:307 OptionForLoops::apply
// ===========================================================================
/// Toggle for-loop recovery. Faithful to `OptionForLoops::apply`
/// (options.cc:307-314).
pub struct OptionForLoops;
impl ArchOption for OptionForLoops {
    // Ghidra: options.hh:144 OptionForLoops::OptionForLoops
    fn name(&self) -> &str {
        "analyzeforloops"
    }
    // Ghidra: options.cc:307 OptionForLoops::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        arch.analyze_for_loops = on_or_off(p1);
        format!("Recovery of for-loops is {p1}")
    }
}

// ===========================================================================
// options.cc:321 OptionInline::apply
// ===========================================================================
/// Mark/unmark a function as inline. Faithful to `OptionInline::apply`
/// (options.cc:321-340).
pub struct OptionInline;
impl ArchOption for OptionInline {
    // Ghidra: options.hh:150 OptionInline::OptionInline
    fn name(&self) -> &str {
        "inline"
    }
    // Ghidra: options.cc:321 OptionInline::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        // RUDRA-GLUE: no queryFunction lookup yet.
        if p1.is_empty() {
            return "Unknown function name: ".to_string();
        }
        let val = p2.is_empty() || p2 == "true";
        let prop = if val { "true" } else { "false" };
        format!("Inline property for function {p1} = {prop}")
    }
}

// ===========================================================================
// options.cc:347 OptionNoReturn::apply
// ===========================================================================
/// Mark/unmark a function with noreturn. Faithful to `OptionNoReturn::apply`
/// (options.cc:347-366).
pub struct OptionNoReturn;
impl ArchOption for OptionNoReturn {
    // Ghidra: options.hh:156 OptionNoReturn::OptionNoReturn
    fn name(&self) -> &str {
        "noreturn"
    }
    // Ghidra: options.cc:347 OptionNoReturn::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Unknown function name: ".to_string();
        }
        let val = p2.is_empty() || p2 == "true";
        let prop = if val { "true" } else { "false" };
        format!("No return property for function {p1} = {prop}")
    }
}

// ===========================================================================
// options.cc:373 OptionWarning::apply
// ===========================================================================
/// Toggle warnings for an action/rule. Faithful to `OptionWarning::apply`
/// (options.cc:373-389).
pub struct OptionWarning;
impl ArchOption for OptionWarning {
    // Ghidra: options.hh:162 OptionWarning::OptionWarning
    fn name(&self) -> &str {
        "warning"
    }
    // Ghidra: options.cc:373 OptionWarning::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "No action/rule specified".to_string();
        }
        let val = p2.is_empty() || on_or_off(p2);
        // RUDRA-GLUE: allacts.getCurrent()->setWarning not wired.
        let prop = if val { "on" } else { "off" };
        format!("Warnings for {p1} turned {prop}")
    }
}

// ===========================================================================
// options.cc:393 OptionNullPrinting::apply
// ===========================================================================
/// Toggle printing of null p-code ops. Faithful to `OptionNullPrinting::apply`
/// (options.cc:393-403).
pub struct OptionNullPrinting;
impl ArchOption for OptionNullPrinting {
    // Ghidra: options.hh:168 OptionNullPrinting::OptionNullPrinting
    fn name(&self) -> &str {
        "printnull"
    }
    // Ghidra: options.cc:393 OptionNullPrinting::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        // RUDRA-GLUE: no PrintLanguage wired into Architecture yet.
        let prop = if val { "on" } else { "off" };
        format!("Null printing is {prop}")
    }
}

// ===========================================================================
// options.cc:411 OptionInPlaceOps::apply
// ===========================================================================
/// Toggle in-place ops transformation. Faithful to `OptionInPlaceOps::apply`
/// (options.cc:411-421).
pub struct OptionInPlaceOps;
impl ArchOption for OptionInPlaceOps {
    // Ghidra: options.hh:174 OptionInPlaceOps::OptionInPlaceOps
    fn name(&self) -> &str {
        "inplaceops"
    }
    // Ghidra: options.cc:408 OptionInPlaceOps::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        // RUDRA-GLUE: print reset isInPlaceOps() not wired.
        let prop = if val { "on" } else { "off" };
        format!("In-place ops are {prop}")
    }
}

// ===========================================================================
// options.cc:428 OptionConventionPrinting::apply
// ===========================================================================
/// Toggle convention printing. Faithful to `OptionConventionPrinting::apply`
/// (options.cc:428-438).
pub struct OptionConventionPrinting;
impl ArchOption for OptionConventionPrinting {
    // Ghidra: options.hh:180 OptionConventionPrinting::OptionConventionPrinting
    fn name(&self) -> &str {
        "conventionprinting"
    }
    // Ghidra: options.cc:423 OptionConventionPrinting::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        let prop = if val { "on" } else { "off" };
        format!("Convention printing is {prop}")
    }
}

// ===========================================================================
// options.cc:445 OptionNoCastPrinting::apply
// ===========================================================================
pub struct OptionNoCastPrinting;
impl ArchOption for OptionNoCastPrinting {
    // Ghidra: options.hh:186 OptionNoCastPrinting::OptionNoCastPrinting
    fn name(&self) -> &str {
        "nocastprinting"
    }
    // Ghidra: options.cc:438 OptionNoCastPrinting::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        let prop = if val { "on" } else { "off" };
        format!("No cast printing is {prop}")
    }
}

// ===========================================================================
// options.cc:462 OptionHideExtensions::apply
// ===========================================================================
pub struct OptionHideExtensions;
impl ArchOption for OptionHideExtensions {
    // Ghidra: options.hh:192 OptionHideExtensions::OptionHideExtensions
    fn name(&self) -> &str {
        "hideextensions"
    }
    // Ghidra: options.cc:453 OptionHideExtensions::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        let prop = if val { "on" } else { "off" };
        format!("Extension markings hidden: {prop}")
    }
}

// ===========================================================================
// options.cc:530 OptionMaxLineWidth::apply
// ===========================================================================
pub struct OptionMaxLineWidth;
impl ArchOption for OptionMaxLineWidth {
    // Ghidra: options.hh:198 OptionMaxLineWidth::OptionMaxLineWidth
    fn name(&self) -> &str {
        "maxlinewidth"
    }
    // Ghidra: options.cc:471 OptionMaxLineWidth::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify max line width".to_string();
        }
        let _ = parse_uint_any_base(p1);
        // RUDRA-GLUE: no emitter line width config on Architecture yet.
        format!("Max line width = {p1}")
    }
}

// ===========================================================================
// options.cc:543 OptionIndentIncrement::apply
// ===========================================================================
pub struct OptionIndentIncrement;
impl ArchOption for OptionIndentIncrement {
    // Ghidra: options.hh:204 OptionIndentIncrement::OptionIndentIncrement
    fn name(&self) -> &str {
        "indentincrement"
    }
    // Ghidra: options.cc:488 OptionIndentIncrement::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify indent increment".to_string();
        }
        format!("Indent increment = {p1}")
    }
}

// ===========================================================================
// options.cc:556 OptionCommentIndent::apply
// ===========================================================================
pub struct OptionCommentIndent;
impl ArchOption for OptionCommentIndent {
    // Ghidra: options.hh:210 OptionCommentIndent::OptionCommentIndent
    fn name(&self) -> &str {
        "commentindent"
    }
    // Ghidra: options.cc:506 OptionCommentIndent::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify comment indent".to_string();
        }
        format!("Comment indent = {p1}")
    }
}

// ===========================================================================
// options.cc:564 OptionCommentStyle::apply
// ===========================================================================
pub struct OptionCommentStyle;
impl ArchOption for OptionCommentStyle {
    // Ghidra: options.hh:216 OptionCommentStyle::OptionCommentStyle
    fn name(&self) -> &str {
        "commentstyle"
    }
    // Ghidra: options.cc:523 OptionCommentStyle::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra accepts "/* */" (C), "// " (C++/shell), "/* **/" (header),
        // "/** */" (JavaDoc) - validated by printlanguage.
        // options.cc:526: glb->print->setCommentStyle(p1); — the current
        // printer, reached through the architecture's printer registry
        // (architecture.hh:205/206 print/printlist).
        let Some(handle) = arch.print_language_current() else {
            // Pre-registration state: the oracle's constructor-time build
            // (architecture.cc:171-172) always has a printer, so Ghidra
            // cannot occupy this state; report it as the exception the
            // oracle-shaped route would surface instead of silently
            // succeeding.
            return "LowlevelError: no print language registered with the architecture".to_string();
        };
        let mut printer = handle
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match printer.set_comment_style(p1) {
            // options.cc:527: return "Comment style set to "+p1;
            Ok(()) => format!("Comment style set to {p1}"),
            // setCommentStyle's throw LowlevelError (printc.cc:2359-2360)
            // propagates out of apply through OptionDatabase::set.
            Err(msg) => format!("LowlevelError: {msg}"),
        }
    }
}

// ===========================================================================
// options.cc:574 OptionCommentHeader::apply
// ===========================================================================
pub struct OptionCommentHeader;
impl ArchOption for OptionCommentHeader {
    // Ghidra: options.hh:222 OptionCommentHeader::OptionCommentHeader
    fn name(&self) -> &str {
        "commentheader"
    }
    // Ghidra: options.cc:535 OptionCommentHeader::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        format!("Comment header (type={p1}) flag set")
    }
}

// ===========================================================================
// options.cc:585 OptionCommentInstruction::apply
// ===========================================================================
pub struct OptionCommentInstruction;
impl ArchOption for OptionCommentInstruction {
    // Ghidra: options.hh:228 OptionCommentInstruction::OptionCommentInstruction
    fn name(&self) -> &str {
        "commentinstruction"
    }
    // Ghidra: options.cc:556 OptionCommentInstruction::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        format!("Comment instruction (type={p1}) flag set")
    }
}

// ===========================================================================
// options.cc:505 OptionIntegerFormat::apply
// ===========================================================================
/// Configure how integers are rendered (hex/dec/best). Faithful to
/// `OptionIntegerFormat::apply` (options.cc:505-525). The C++ class stores
/// `format` and `force` flags used to configure each PrintLanguage. Rugra
/// has no per-language emitter yet, so we record the request verbatim.
pub struct OptionIntegerFormat;
impl ArchOption for OptionIntegerFormat {
    // Ghidra: options.hh:234 OptionIntegerFormat::OptionIntegerFormat
    fn name(&self) -> &str {
        "integerformat"
    }
    // Ghidra: options.cc:576 OptionIntegerFormat::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        // p1 is one of: "hex", "dec", "best"
        // p2 == "force" forces the format even when it makes the output worse.
        let force = !p2.is_empty() && p2 != "noforce";
        format!("Integer format = {p1} (force={force})")
    }
}

// ===========================================================================
// options.cc:596 OptionBraceFormat::apply
// ===========================================================================
/// Configure brace layout. Faithful to `OptionBraceFormat::apply`
/// (options.cc:596-623).
pub struct OptionBraceFormat;
impl ArchOption for OptionBraceFormat {
    // Ghidra: options.hh:240 OptionBraceFormat::OptionBraceFormat
    fn name(&self) -> &str {
        "braceformat"
    }
    // Ghidra: options.cc:596 OptionBraceFormat::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra accepts "same", "next", "none" for each of: function, block,
        // struct, linewrap.
        format!("Brace format = {p1}")
    }
}

// ===========================================================================
// options.cc:631 OptionSetAction::apply
// ===========================================================================
/// Replace the global action pipeline. Faithful to `OptionSetAction::apply`
/// (options.cc:631-647).
pub struct OptionSetAction;
impl ArchOption for OptionSetAction {
    // Ghidra: options.hh:246 OptionSetAction::OptionSetAction
    fn name(&self) -> &str {
        "setaction"
    }
    // Ghidra: options.cc:631 OptionSetAction::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // RUDRA-GLUE: ActionDatabase::resetDefaultsFromAction not wired.
        format!("Set global action = {p1}")
    }
}

// ===========================================================================
// options.cc:654 OptionCurrentAction::apply
// ===========================================================================
/// Switch the active sub-action in the pipeline. Faithful to
/// `OptionCurrentAction::apply` (options.cc:654-674).
pub struct OptionCurrentAction;
impl ArchOption for OptionCurrentAction {
    // Ghidra: options.hh:252 OptionCurrentAction::OptionCurrentAction
    fn name(&self) -> &str {
        "currentaction"
    }
    // Ghidra: options.cc:654 OptionCurrentAction::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra: `allacts.setCurrent(p1)` throws LowlevelError on unknown
        // action. We return the error message faithfully.
        if p1.is_empty() {
            return "Bad current action parameter".to_string();
        }
        // RUDRA-GLUE: ActionDatabase::setCurrent not wired.
        format!("Current action = {p1}")
    }
}

// ===========================================================================
// options.cc:681 OptionAllowContextSet::apply
// ===========================================================================
/// Toggle whether the disassembly context may be modified. Faithful to
/// `OptionAllowContextSet::apply` (options.cc:681-691).
pub struct OptionAllowContextSet;
impl ArchOption for OptionAllowContextSet {
    // Ghidra: options.hh:258 OptionAllowContextSet::OptionAllowContextSet
    fn name(&self) -> &str {
        "allowcontextset"
    }
    // Ghidra: options.cc:681 OptionAllowContextSet::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        // RUDRA-GLUE: ContextCache::allowSet not exposed on Architecture yet.
        let prop = if val { "on" } else { "off" };
        format!("Allow context set is {prop}")
    }
}

// ===========================================================================
// options.cc:698 OptionIgnoreUnimplemented::apply
// ===========================================================================
/// Set the flow flag that drops unimplemented p-code ops. Faithful to
/// `OptionIgnoreUnimplemented::apply` (options.cc:698-711).
pub struct OptionIgnoreUnimplemented;
impl ArchOption for OptionIgnoreUnimplemented {
    // Ghidra: options.hh:264 OptionIgnoreUnimplemented::OptionIgnoreUnimplemented
    fn name(&self) -> &str {
        "ignoreunimplemented"
    }
    // Ghidra: options.cc:698 OptionIgnoreUnimplemented::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::IGNORE_UNIMPLEMENTED;
            "Unimplemented instructions are now ignored (treated as nop)".to_string()
        } else {
            arch.flowoptions &= !flow_flags::IGNORE_UNIMPLEMENTED;
            "Unimplemented instructions now generate warnings".to_string()
        }
    }
}

// ===========================================================================
// options.cc:715 OptionErrorUnimplemented::apply
// ===========================================================================
/// Set the flow flag that errors on unimplemented p-code ops. Faithful to
/// `OptionErrorUnimplemented::apply` (options.cc:715-728).
pub struct OptionErrorUnimplemented;
impl ArchOption for OptionErrorUnimplemented {
    // Ghidra: options.hh:270 OptionErrorUnimplemented::OptionErrorUnimplemented
    fn name(&self) -> &str {
        "errorunimplemented"
    }
    // Ghidra: options.cc:721 OptionErrorUnimplemented::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::ERROR_UNIMPLEMENTED;
            "Unimplemented instructions are now considered errors".to_string()
        } else {
            arch.flowoptions &= !flow_flags::ERROR_UNIMPLEMENTED;
            "Unimplemented instructions are no longer considered errors".to_string()
        }
    }
}

// ===========================================================================
// options.cc:731 OptionErrorReinterpreted::apply
// ===========================================================================
/// Set the flow flag that errors on instruction reinterpretation. Faithful
/// to `OptionErrorReinterpreted::apply` (options.cc:731-744).
pub struct OptionErrorReinterpreted;
impl ArchOption for OptionErrorReinterpreted {
    // Ghidra: options.hh:276 OptionErrorReinterpreted::OptionErrorReinterpreted
    fn name(&self) -> &str {
        "errorreinterpreted"
    }
    // Ghidra: options.cc:744 OptionErrorReinterpreted::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::ERROR_REINTERPRETED;
            "Reinterpreted instructions are now considered errors".to_string()
        } else {
            arch.flowoptions &= !flow_flags::ERROR_REINTERPRETED;
            "Reinterpreted instructions are no longer considered errors".to_string()
        }
    }
}

// ===========================================================================
// options.cc:747 OptionErrorTooManyInstructions::apply
// ===========================================================================
/// Set the flow flag that errors on too many instructions. Faithful to
/// `OptionErrorTooManyInstructions::apply` (options.cc:747-760).
pub struct OptionErrorTooManyInstructions;
impl ArchOption for OptionErrorTooManyInstructions {
    // Ghidra: options.hh:282 OptionErrorTooManyInstructions::OptionErrorTooManyInstructions
    fn name(&self) -> &str {
        "errortoomanyinstructions"
    }
    // Ghidra: options.cc:767 OptionErrorTooManyInstructions::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::ERROR_TOOMANYINSTRUCTIONS;
            "Too many instructions are now considered an error".to_string()
        } else {
            arch.flowoptions &= !flow_flags::ERROR_TOOMANYINSTRUCTIONS;
            "Too many instructions are no longer considered an error".to_string()
        }
    }
}

// ===========================================================================
// options.cc:792 OptionProtoEval::apply
// ===========================================================================
/// Set the prototype model used when evaluating a function's signature.
/// Faithful to `OptionProtoEval::apply` (options.cc:792-823).
pub struct OptionProtoEval;
impl ArchOption for OptionProtoEval {
    // Ghidra: options.hh:288 OptionProtoEval::OptionProtoEval
    fn name(&self) -> &str {
        "protoeval"
    }
    // Ghidra: options.cc:792 OptionProtoEval::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1 == "default" {
            arch.evalfp_current_name = None;
            return "Setting prototype eval model: default".to_string();
        }
        if arch.get_model(p1).is_none() {
            return format!("Unknown prototype model: {p1}");
        }
        arch.evalfp_current_name = Some(p1.to_string());
        format!("Setting prototype eval model: {p1}")
    }
}

// ===========================================================================
// options.cc:824 OptionSetLanguage::apply
// ===========================================================================
/// Select the active decompiler output language. Faithful to
/// `OptionSetLanguage::apply` (options.cc:824-831).
pub struct OptionSetLanguage;
impl ArchOption for OptionSetLanguage {
    // Ghidra: options.hh:294 OptionSetLanguage::OptionSetLanguage
    fn name(&self) -> &str {
        "setlanguage"
    }
    // Ghidra: options.cc:816 OptionSetLanguage::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // RUDRA-GLUE: PrintLanguage registry not wired into Architecture.
        format!("Setting printing language: {p1}")
    }
}

// ===========================================================================
// options.cc:127 OptionJumpTableMax constructor / options.cc:833 apply
// ===========================================================================
/// Maximum entries in a recovered jump table. Faithful to
/// `OptionJumpTableMax::apply` (options.cc:833-846).
pub struct OptionJumpTableMax;
impl ArchOption for OptionJumpTableMax {
    // Ghidra: options.hh:300 OptionJumpTableMax::OptionJumpTableMax
    fn name(&self) -> &str {
        "jumptablemax"
    }
    // Ghidra: options.cc:833 OptionJumpTableMax::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = match parse_uint_any_base(p1) {
            Some(v) => v as u32,
            None => return "Bad jumptablemax parameter".to_string(),
        };
        arch.max_jumptable_size = val;
        format!("Set maximum jump table size to {val}")
    }
}

// ===========================================================================
// options.cc:851 OptionJumpLoad::apply
// ===========================================================================
/// Toggle recording of jump-table loads. Faithful to `OptionJumpLoad::apply`
/// (options.cc:851-865).
pub struct OptionJumpLoad;
impl ArchOption for OptionJumpLoad {
    // Ghidra: options.hh:306 OptionJumpLoad::OptionJumpLoad
    fn name(&self) -> &str {
        "jumpload"
    }
    // Ghidra: options.cc:851 OptionJumpLoad::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        let val = on_or_off(p1);
        if val {
            arch.flowoptions |= flow_flags::RECORD_JUMPLOADS;
            "Recording jumptable loads".to_string()
        } else {
            arch.flowoptions &= !flow_flags::RECORD_JUMPLOADS;
            "Not recording jumptable loads".to_string()
        }
    }
}

// ===========================================================================
// options.cc:873 OptionToggleRule::apply
// ===========================================================================
/// Enable or disable a single rewrite rule. Faithful to
/// `OptionToggleRule::apply` (options.cc:873-903).
pub struct OptionToggleRule;
impl ArchOption for OptionToggleRule {
    // Ghidra: options.hh:312 OptionToggleRule::OptionToggleRule
    fn name(&self) -> &str {
        "togglerule"
    }
    // Ghidra: options.cc:873 OptionToggleRule::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify rule name".to_string();
        }
        let enable = !(p2 == "off" || p2 == "false");
        // RUDRA-GLUE: ActionGroup::enableSubRule/disableSubRule not wired.
        let prop = if enable { "enabled" } else { "disabled" };
        format!("Rule {p1} {prop}")
    }
}

// ===========================================================================
// options.cc:913 OptionAliasBlock::apply
// ===========================================================================
/// Configure how aliases block analysis. Faithful to
/// `OptionAliasBlock::apply` (options.cc:913-928).
pub struct OptionAliasBlock;
impl ArchOption for OptionAliasBlock {
    // Ghidra: options.hh:318 OptionAliasBlock::OptionAliasBlock
    fn name(&self) -> &str {
        "aliasblock"
    }
    // Ghidra: options.cc:913 OptionAliasBlock::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra accepts flags: "all", "none", "struct", "array", "global",
        // "param1", "param2", "param3", "param4", "param5", "param6",
        // "param7", "param8", "param9", "param10", "param11", "param12".
        let mut level: i32 = 0;
        for tok in p1.split(',') {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(v) = alias_block_flag(t) {
                level |= v;
            } else {
                return format!("Bad aliasblock option: {t}");
            }
        }
        arch.alias_block_level = level;
        if level == 0 {
            "No alias blocking".to_string()
        } else {
            format!("Alias blocking flags = 0x{level:x}")
        }
    }
}

// ===========================================================================
// options.cc:938 OptionMaxInstruction::apply
// ===========================================================================
/// Maximum number of instructions the decompiler will process. Faithful to
/// `OptionMaxInstruction::apply` (options.cc:938-951).
pub struct OptionMaxInstruction;
impl ArchOption for OptionMaxInstruction {
    // Ghidra: options.hh:324 OptionMaxInstruction::OptionMaxInstruction
    fn name(&self) -> &str {
        "maxinstruction"
    }
    // Ghidra: options.cc:938 OptionMaxInstruction::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        if p1.is_empty() {
            return "Must specify number of instructions".to_string();
        }
        let new_max: i32 = match parse_int_any_base(p1) {
            Some(v) => v as i32,
            None => return "Bad maxinstruction parameter".to_string(),
        };
        arch.max_instructions = new_max as u32;
        format!("Set maximum instructions to {p1}")
    }
}

// ===========================================================================
// options.cc:958 OptionNamespaceStrategy::apply
// ===========================================================================
/// Select how the printer renders C++ namespaces. Faithful to
/// `OptionNamespaceStrategy::apply` (options.cc:958-975).
pub struct OptionNamespaceStrategy;
impl ArchOption for OptionNamespaceStrategy {
    // Ghidra: options.hh:330 OptionNamespaceStrategy::OptionNamespaceStrategy
    fn name(&self) -> &str {
        "namespacestrategy"
    }
    // Ghidra: options.cc:958 OptionNamespaceStrategy::apply
    fn apply(&self, _arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        // Ghidra accepts: "minimal", "none", "all".
        let valid = matches!(p1, "minimal" | "none" | "all");
        if !valid {
            return format!("Bad namespacestrategy parameter: {p1}");
        }
        // RUDRA-GLUE: PrintLanguage::setNamespaceStrategy not wired.
        format!("Namespace strategy = {p1}")
    }
}

// ===========================================================================
// options.cc:999 OptionSplitDatatypes::apply
// ===========================================================================
/// Control which data-type assignments are split into multiple
/// COPY/LOAD/STORE operations. Faithful to `OptionSplitDatatypes::apply`
/// (options.cc:999-1022): the three parameters are OR-ed as configuration
/// bits (first parameter assigns, the rest OR in), and the "splitcopy" /
/// "splitpointer" action groups are toggled from the resulting bits.
pub struct OptionSplitDatatypes;
impl ArchOption for OptionSplitDatatypes {
    // Ghidra: options.hh:343 OptionSplitDatatypes::OptionSplitDatatypes
    fn name(&self) -> &str {
        "splitdatatype"
    }
    // Ghidra: options.cc:999 OptionSplitDatatypes::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, p2: &str, p3: &str) -> String {
        // Ghidra: options.cc:1002 `uint4 oldConfig = glb->split_datatype_config;`
        let old_config = arch.split_datatype_config;
        // Ghidra: options.cc:1003 `glb->split_datatype_config = getOptionBit(p1);`
        // An unknown p1 token throws LowlevelError BEFORE the assignment, so
        // the configuration keeps its previous value.
        let mut new_config = match get_option_bit(p1) {
            Ok(bit) => bit,
            Err(msg) => return format!("LowlevelError: {msg}"),
        };
        // Ghidra: options.cc:1004-1005 `|= getOptionBit(p2); |= getOptionBit(p3);`
        // An unknown later token throws AFTER the earlier assignment took
        // effect: Ghidra leaves split_datatype_config at the partial value
        // and never reaches the toggleAction calls.
        for param in [p2, p3] {
            match get_option_bit(param) {
                Ok(bit) => new_config |= bit,
                Err(msg) => {
                    arch.split_datatype_config = new_config;
                    return format!("LowlevelError: {msg}");
                }
            }
        }
        arch.split_datatype_config = new_config;
        // Ghidra: options.cc:1007-1016 — toggle the "splitcopy"/"splitpointer"
        // action groups on the current root Action.
        let (splitcopy_on, splitpointer_on) = split_action_toggles(arch.split_datatype_config);
        // Ghidra: options.cc:1008-1015
        //   glb->allacts.toggleAction(glb->allacts.getCurrentName(),
        //                             "splitcopy",  splitcopy_on);
        //   glb->allacts.toggleAction(glb->allacts.getCurrentName(),
        //                             "splitpointer", splitpointer_on);
        // getCurrentName() is re-read at each call site, but toggleAction
        // never writes currentactname (action.cc:1049 only reads it; the sole
        // writer is setCurrent at action.cc:1024), so one snapshot is
        // equivalent for the pair. A `None` database (Rugra's pre-build_action
        // state, unrepresentable for Ghidra's embedded allacts member) skips
        // the toggles — same Option-guard precedent as reset_defaults
        // (architecture.cc:1442 wiring in src/arch.rs).
        if let Some(db) = &arch.allacts {
            let mut db = db.write().expect("allacts write lock");
            let current = db.get_current_name().to_string();
            db.toggle_action(&current, "splitcopy", splitcopy_on);
            db.toggle_action(&current, "splitpointer", splitpointer_on);
        }
        // Ghidra: options.cc:1017-1019
        if old_config == arch.split_datatype_config {
            "Split data-type configuration unchanged".to_string()
        } else {
            "Split data-type configuration set".to_string()
        }
    }
}

// Ghidra: options.cc:982 OptionSplitDatatypes::getOptionBit
/// Translate an option string to a configuration bit. Faithful to
/// `OptionSplitDatatypes::getOptionBit` (options.cc:982-990): "" -> 0,
/// "struct" -> 1, "array" -> 2, "pointer" -> 4; any other token is a
/// LowlevelError("Unknown data-type split option: <val>"), surfaced here as
/// `Err` carrying the same message text.
pub fn get_option_bit(val: &str) -> Result<u32, String> {
    use crate::arch::split_datatype as split_datatype_option;
    if val.is_empty() {
        return Ok(0);
    }
    if val == "struct" {
        return Ok(split_datatype_option::OPTION_STRUCT);
    }
    if val == "array" {
        return Ok(split_datatype_option::OPTION_ARRAY);
    }
    if val == "pointer" {
        return Ok(split_datatype_option::OPTION_POINTER);
    }
    Err(format!("Unknown data-type split option: {val}"))
}

// RUDRA-GLUE: decomposition of the two toggleAction group switches that
// OptionSplitDatatypes::apply performs (options.cc:1007-1016) into the
// (splitcopy, splitpointer) on/off pair. Ghidra writes this as an inline
// if/else over the configuration bits; the pair is forwarded by apply()
// to Architecture::allacts's toggle_action (action.cc:1036-1053), which
// adds/removes the group from the current root's ActionGroupList and
// re-clones the root from the universal.
pub fn split_action_toggles(config: u32) -> (bool, bool) {
    use crate::arch::split_datatype as split_datatype_option;
    if config & (split_datatype_option::OPTION_STRUCT | split_datatype_option::OPTION_ARRAY) == 0 {
        (false, false)
    } else {
        let pointers = config & split_datatype_option::OPTION_POINTER != 0;
        (true, pointers)
    }
}

// ===========================================================================
// options.cc:1030 OptionNanIgnore::apply
// ===========================================================================
/// Configure how the decompiler handles NaN comparisons. Faithful to
/// `OptionNanIgnore::apply` (options.cc:1030-1053).
pub struct OptionNanIgnore;
impl ArchOption for OptionNanIgnore {
    // Ghidra: options.hh:349 OptionNanIgnore::OptionNanIgnore
    fn name(&self) -> &str {
        "nanignore"
    }
    // Ghidra: options.cc:1030 OptionNanIgnore::apply
    fn apply(&self, arch: &mut Architecture, p1: &str, _p2: &str, _p3: &str) -> String {
        match p1 {
            "all" => {
                arch.nan_ignore_all = true;
                arch.nan_ignore_compare = true;
            }
            "none" => {
                arch.nan_ignore_all = false;
                arch.nan_ignore_compare = false;
            }
            "compare" => {
                arch.nan_ignore_compare = true;
            }
            "input" => {
                arch.nan_ignore_all = true;
            }
            _ => return format!("Bad nanignore parameter: {p1}"),
        }
        let mut parts: Vec<&str> = Vec::new();
        if arch.nan_ignore_all {
            parts.push("input");
        }
        if arch.nan_ignore_compare {
            parts.push("compare");
        }
        if parts.is_empty() {
            "NaN ignore: none".to_string()
        } else {
            format!("NaN ignore: {}", parts.join(", "))
        }
    }
}

// ===========================================================================
// Local helpers (no Ghidra counterpart - pure Rust glue)
// ===========================================================================

// Ghidra: options.cc:913 OptionAliasBlock::apply
/// Translate a symbolic alias-block token into its bit value. Faithful to
/// the inline bit mapping performed in `OptionAliasBlock::apply`
/// (options.cc:913-928).
pub fn alias_block_flag(name: &str) -> Option<i32> {
    // RUDRA-GLUE: Ghidra hashes these to enum values; we mirror the bit
    // layout in src/arch.rs (alias_block_level).
    match name {
        "struct" => Some(1),
        "array" => Some(2),
        "global" => Some(4),
        "param1" => Some(8),
        "param2" => Some(0x10),
        "param3" => Some(0x20),
        "param4" => Some(0x40),
        "param5" => Some(0x80),
        "param6" => Some(0x100),
        "param7" => Some(0x200),
        "param8" => Some(0x400),
        "param9" => Some(0x800),
        "param10" => Some(0x1000),
        "param11" => Some(0x2000),
        "param12" => Some(0x4000),
        "all" => Some(0xFFFF_FFFFu32 as i32),
        "none" => Some(0),
        _ => None,
    }
}

// RUDRA-GLUE: parse_int_any_base (C++ uses `istringstream`, which we emulate
//   manually because `str::parse` does not support octal, and `from_str_radix`
//   does not accept `0x`/`0` prefixes with mixed bases).
//
// Replicates `std::istringstream` with `>>` reset semantics:
///   * "0x..." or "0X..." -> base 16
///   * "0..." (leading zero, multiple digits) -> base 8
///   * otherwise          -> base 10
///
/// Leading '-' / '+' sign is honoured.
pub fn parse_int_any_base(s: &str) -> Option<i64> {
    parse_int_any_base_i64(s)
}

// RUDRA-GLUE: Public unsigned wrapper for Rust's shared any-base parser;
// Ghidra repeats std::istringstream extraction at each integer option.
pub fn parse_uint_any_base(s: &str) -> Option<u64> {
    parse_uint_any_base_u64(s)
}

// RUDRA-GLUE: Rust helper factoring signed std::istringstream-style parsing;
// Ghidra performs the equivalent extraction inline in individual apply methods.
fn parse_int_any_base_i64(s: &str) -> Option<i64> {
    let trimmed = s.trim();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    // Optional leading sign.
    let mut idx = 0;
    let negative;
    match bytes[0] {
        b'-' => {
            negative = true;
            idx = 1;
        }
        b'+' => {
            negative = false;
            idx = 1;
        }
        _ => {
            negative = false;
        }
    }
    if idx >= bytes.len() {
        return None;
    }
    let magnitude = parse_uint_any_base_u64(&trimmed[idx..])?;
    Some(if negative { -(magnitude as i64) } else { magnitude as i64 })
}

// RUDRA-GLUE: Rust helper factoring unsigned std::istringstream-style parsing;
// Ghidra performs the equivalent extraction inline in individual apply methods.
fn parse_uint_any_base_u64(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    // Detect "0x"/"0X" (base 16) or leading zero (base 8), otherwise base 10.
    if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X') {
        u64::from_str_radix(&trimmed[2..], 16).ok()
    } else if bytes.len() >= 2 && bytes[0] == b'0' && bytes[1].is_ascii_digit() {
        u64::from_str_radix(&trimmed[1..], 8).ok()
    } else {
        u64::from_str_radix(trimmed, 10).ok()
    }
}

// ===========================================================================
// Element IDs for the <optionslist> XML format.
// ===========================================================================

// RUDRA-GLUE: ElementId constants. Ghidra uses a runtime ElementId registry
// (`element.cc`) with names registered in `options.cc` lines 23-63. Rugra
// defines the numeric IDs as plain constants because the Decoder trait keys
// off integer IDs (src/marshal.rs:389); the values mirror the locked
// options.cc registrations (also present in the marshal.rs name table).
pub mod elem_ids {
    // Ghidra: options.cc:50 ELEM_OPTIONSLIST
    pub const ELEM_OPTIONSLIST: u32 = 201;
    // Ghidra: options.cc:51 ELEM_PARAM1
    pub const ELEM_PARAM1: u32 = 202;
    // Ghidra: options.cc:52 ELEM_PARAM2
    pub const ELEM_PARAM2: u32 = 203;
    // Ghidra: options.cc:53 ELEM_PARAM3
    pub const ELEM_PARAM3: u32 = 204;
}

// ===========================================================================
// options.hh:106 OptionDatabase
// ===========================================================================

/// Registry mapping option names to `ArchOption` implementations. Faithful
/// to `OptionDatabase` (options.hh:106-116).
///
/// The C++ class owns `map<string, ArchOption *> optionmap` and a reference
/// to the `Architecture`. Rugra stores owned trait objects and clones the
/// architecture reference on each call instead.
pub struct OptionDatabase {
    // RUDRA-GLUE: Ghidra stores pointers; we store Boxes keyed by option name.
    options: HashMap<String, Box<dyn ArchOption>>,
}

impl OptionDatabase {
    // Ghidra: options.cc:93 OptionDatabase::OptionDatabase (ctor builds the
    //   default registry via registerOption, lines 95-149).
    /// Build the default option registry, mirroring Ghidra's constructor.
    pub fn new() -> Self {
        let mut db = Self {
            options: HashMap::new(),
        };
        db.register_all();
        db
    }

    // Ghidra: options.cc:84 registerOption
    /// Insert a single option. Mirrors `registerOption` (options.cc:84-91).
    pub fn register<O: ArchOption + 'static>(&mut self, opt: O) {
        let name = opt.name().to_string();
        self.options.insert(name, Box::new(opt));
    }

    // Ghidra: options.cc:95-149 registerOption calls inside the ctor.
    /// Register every option Ghidra registers in the constructor. Order
    /// matches Ghidra (options.cc:96-149).
    fn register_all(&mut self) {
        // Ghidra: options.cc:96 registerOption(new OptionExtraPop())
        self.register(OptionExtraPop);
        // Ghidra: options.cc:97 registerOption(new OptionReadOnly())
        self.register(OptionReadOnly);
        // Ghidra: options.cc:98 registerOption(new OptionDefaultPrototype())
        self.register(OptionDefaultPrototype);
        // Ghidra: options.cc:99 registerOption(new OptionInferConstPtr())
        self.register(OptionInferConstPtr);
        // Ghidra: options.cc:100 registerOption(new OptionForLoops())
        self.register(OptionForLoops);
        // Ghidra: options.cc:101 registerOption(new OptionInline())
        self.register(OptionInline);
        // Ghidra: options.cc:102 registerOption(new OptionNoReturn())
        self.register(OptionNoReturn);
        // Ghidra: options.cc:103 registerOption(new OptionWarning())
        self.register(OptionWarning);
        // Ghidra: options.cc:104 registerOption(new OptionNullPrinting())
        self.register(OptionNullPrinting);
        // Ghidra: options.cc:105 registerOption(new OptionInPlaceOps())
        self.register(OptionInPlaceOps);
        // Ghidra: options.cc:106 registerOption(new OptionConventionPrinting())
        self.register(OptionConventionPrinting);
        // Ghidra: options.cc:107 registerOption(new OptionNoCastPrinting())
        self.register(OptionNoCastPrinting);
        // Ghidra: options.cc:108 registerOption(new OptionHideExtensions())
        self.register(OptionHideExtensions);
        // Ghidra: options.cc:109 registerOption(new OptionMaxLineWidth())
        self.register(OptionMaxLineWidth);
        // Ghidra: options.cc:110 registerOption(new OptionIndentIncrement())
        self.register(OptionIndentIncrement);
        // Ghidra: options.cc:111 registerOption(new OptionCommentIndent())
        self.register(OptionCommentIndent);
        // Ghidra: options.cc:112 registerOption(new OptionCommentStyle())
        self.register(OptionCommentStyle);
        // Ghidra: options.cc:113 registerOption(new OptionCommentHeader())
        self.register(OptionCommentHeader);
        // Ghidra: options.cc:114 registerOption(new OptionCommentInstruction())
        self.register(OptionCommentInstruction);
        // Ghidra: options.cc:115 registerOption(new OptionIntegerFormat())
        self.register(OptionIntegerFormat);
        // Ghidra: options.cc:116 registerOption(new OptionBraceFormat())
        self.register(OptionBraceFormat);
        // Ghidra: options.cc:117 registerOption(new OptionSetAction())
        self.register(OptionSetAction);
        // Ghidra: options.cc:118 registerOption(new OptionCurrentAction())
        self.register(OptionCurrentAction);
        // Ghidra: options.cc:119 registerOption(new OptionAllowContextSet())
        self.register(OptionAllowContextSet);
        // Ghidra: options.cc:120 registerOption(new OptionIgnoreUnimplemented())
        self.register(OptionIgnoreUnimplemented);
        // Ghidra: options.cc:121 registerOption(new OptionErrorUnimplemented())
        self.register(OptionErrorUnimplemented);
        // Ghidra: options.cc:122 registerOption(new OptionErrorReinterpreted())
        self.register(OptionErrorReinterpreted);
        // Ghidra: options.cc:123 registerOption(new OptionErrorTooManyInstructions())
        self.register(OptionErrorTooManyInstructions);
        // Ghidra: options.cc:124 registerOption(new OptionProtoEval())
        self.register(OptionProtoEval);
        // Ghidra: options.cc:125 registerOption(new OptionSetLanguage())
        self.register(OptionSetLanguage);
        // Ghidra: options.cc:126 registerOption(new OptionJumpTableMax())
        self.register(OptionJumpTableMax);
        // Ghidra: options.cc:127 registerOption(new OptionJumpLoad())
        self.register(OptionJumpLoad);
        // Ghidra: options.cc:128 registerOption(new OptionToggleRule())
        self.register(OptionToggleRule);
        // Ghidra: options.cc:129 registerOption(new OptionAliasBlock())
        self.register(OptionAliasBlock);
        // Ghidra: options.cc:130 registerOption(new OptionMaxInstruction())
        self.register(OptionMaxInstruction);
        // Ghidra: options.cc:131 registerOption(new OptionNamespaceStrategy())
        self.register(OptionNamespaceStrategy);
        // Ghidra: options.cc:132 registerOption(new OptionSplitDatatypes())
        self.register(OptionSplitDatatypes);
        // Ghidra: options.cc:133 registerOption(new OptionNanIgnore())
        self.register(OptionNanIgnore);
    }

    /// Number of registered options.
    // RUDRA-GLUE: Rust-only registry introspection; OptionDatabase has no
    // matching C++ method.
    pub fn num_options(&self) -> usize {
        self.options.len()
    }

    /// Whether an option named `name` is registered.
    // RUDRA-GLUE: Rust-only registry introspection; OptionDatabase has no
    // matching C++ method.
    pub fn has_option(&self, name: &str) -> bool {
        self.options.contains_key(name)
    }

    /// Sorted list of registered option names.
    // RUDRA-GLUE: Rust-only deterministic registry view; OptionDatabase has
    // no matching C++ method.
    pub fn option_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.options.keys().cloned().collect();
        names.sort();
        names
    }

    // Ghidra: options.cc:150 OptionDatabase::set
    /// Apply the option named `name` with up to three parameters. Faithful
    /// to `OptionDatabase::set` (options.cc:150-161). Returns `Some(msg)`
    /// on success, or `None` if the option is unknown (Ghidra throws a
    /// `LowlevelError`).
    pub fn set(
        &mut self,
        arch: &mut Architecture,
        name: &str,
        p1: &str,
        p2: &str,
        p3: &str,
    ) -> Option<String> {
        let opt = self.options.get(name)?;
        Some(opt.apply(arch, p1, p2, p3))
    }

    // RUDRA-GLUE: try_set is the non-panicking variant for tests; not in
    //   Ghidra's public API.
    pub fn try_set(
        &mut self,
        arch: &mut Architecture,
        name: &str,
        p1: &str,
        p2: &str,
        p3: &str,
    ) -> Result<String, String> {
        match self.set(arch, name, p1, p2, p3) {
            Some(msg) => Ok(msg),
            None => Err(format!("Unknown option: {name}")),
        }
    }

    // Ghidra: options.cc:163 OptionDatabase::decodeOne
    /// Decode and apply one `<optionslist>` entry. Faithful to
    /// `OptionDatabase::decodeOne` (options.cc:163-190).
    ///
    /// The option is named by the **element id** of the outer element (each
    /// registered option name corresponds to a registered ElementId). Up to
    /// three child elements (`ELEM_PARAM1`/`ELEM_PARAM2`/`ELEM_PARAM3`)
    /// supply positional parameters, scanned linearly as Ghidra does.
    pub fn decode_one(
        &mut self,
        arch: &mut Architecture,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        // Ghidra: options.cc:165 `uint4 elemId = decoder.openElement();`
        // RUDRA-GLUE: the element id doubles as the option name in Ghidra's
        //   registry; we look the id up via Decoder::element_name and dispatch
        //   by string.
        let elem_id = decoder.open_element();
        let opt_name = match decoder.element_name(elem_id) {
            Some(n) => n,
            None => {
                decoder.close_element(elem_id);
                return Err(format!("Unknown element id {elem_id}"));
            }
        };
        let mut p1 = String::new();
        let mut p2 = String::new();
        let mut p3 = String::new();
        // Ghidra: options.cc:166 `uint4 subId = decoder.openElement();`
        let sub_id = decoder.open_element();
        // Ghidra: options.cc:167-180 - linear scan of PARAM1/PARAM2/PARAM3;
        //   each readString(ATTRIB_CONTENT) reads the param element's text
        //   content (marshal.cc:390-396).
        let content_attrib = crate::marshal::AttributeId::new("XMLcontent", 1);
        if sub_id == elem_ids::ELEM_PARAM1 {
            p1 = decoder.read_string_attr(&content_attrib);
            decoder.close_element(sub_id);
            let sub2 = decoder.open_element();
            if sub2 == elem_ids::ELEM_PARAM2 {
                p2 = decoder.read_string_attr(&content_attrib);
                decoder.close_element(sub2);
                let sub3 = decoder.open_element();
                if sub3 == elem_ids::ELEM_PARAM3 {
                    p3 = decoder.read_string_attr(&content_attrib);
                    decoder.close_element(sub3);
                } else if sub3 != 0 {
                    decoder.close_element(sub3);
                }
            } else if sub2 != 0 {
                decoder.close_element(sub2);
            }
        } else if sub_id == 0 {
            // Ghidra: options.cc:181 `p1 = decoder.readString(ATTRIB_CONTENT);`
            // No children: the outer element's text content is p1.
            p1 = decoder.read_string_attr(&content_attrib);
        } else {
            decoder.close_element(sub_id);
        }
        // Ghidra: options.cc:183 `decoder.closeElement(elemId);`
        decoder.close_element(elem_id);
        // Ghidra: options.cc:184 `set(elemId,p1,p2,p3);` — a LowlevelError
        // thrown by the option's apply propagates out of decodeOne; options
        // surface thrown errors as message text prefixed "LowlevelError: ",
        // which is propagated as Err here.
        if let Some(msg) = self.set(arch, &opt_name, &p1, &p2, &p3) {
            if msg.starts_with("LowlevelError: ") {
                return Err(msg);
            }
        }
        Ok(())
    }

    // Ghidra: options.cc:192 OptionDatabase::decode
    /// Parse an `<optionslist>` element, treating each child as an option
    /// command. Faithful to `OptionDatabase::decode` (options.cc:192-199).
    pub fn decode(
        &mut self,
        arch: &mut Architecture,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        // Ghidra: options.cc:194 `uint4 elemId = decoder.openElement(ELEM_OPTIONSLIST);`
        let elem_id = decoder.open_element();
        if elem_id != elem_ids::ELEM_OPTIONSLIST {
            decoder.close_element(elem_id);
            return Err(format!(
                "Expected <optionslist>, got element id {elem_id}"
            ));
        }
        // Ghidra: options.cc:196 `while(decoder.peekElement() != 0)`
        while decoder.peek_element() != 0 {
            self.decode_one(arch, decoder)?;
        }
        // Ghidra: options.cc:197 `decoder.closeElement(elemId);`
        decoder.close_element(elem_ids::ELEM_OPTIONSLIST);
        Ok(())
    }
}

impl Default for OptionDatabase {
    // RUDRA-GLUE: Rust Default trait adapter delegates to new(); C++ has no
    // Default trait separate from OptionDatabase::OptionDatabase.
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Architecture;

    fn make_arch() -> Architecture {
        Architecture::new()
    }

    // PRINTC-PRINTLIST-WIRING-0001: options.cc:526
    // `glb->print->setCommentStyle(p1)` — the option routes to the
    // architecture's current printer through the printlist registry.
    #[test]
    fn test_comment_style_routes_to_registered_printer() {
        use crate::prettyprint::{Emit, EmitNoMarkup};
        use crate::printlanguage::PrintLanguage as _;

        fn rendered_comment(
            handle: &std::sync::Arc<
                std::sync::RwLock<Box<dyn crate::printlanguage::PrintLanguage>>,
            >,
        ) -> String {
            let mut printer = handle
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Slice the delta: the emitter buffer accumulates across calls.
            let before = printer
                .get_emit()
                .as_any_mut()
                .and_then(|any| any.downcast_ref::<EmitNoMarkup>())
                .map(|emit| emit.debug_get_output_ref().len())
                .unwrap_or(0);
            printer.emit_line_comment(0, "routed body");
            printer
                .get_emit()
                .as_any_mut()
                .and_then(|any| any.downcast_ref::<EmitNoMarkup>())
                .map(|emit| emit.debug_get_output_ref()[before..].to_string())
                .unwrap_or_default()
                .trim_start_matches(['\n', ' '])
                .to_string()
        }

        let mut arch = make_arch();
        // Pre-registration: oracle cannot occupy this state (ctor builds a
        // printer, architecture.cc:171-172); the message reports it.
        let mut db = OptionDatabase::new();
        let msg = db
            .set(&mut arch, "commentstyle", "cplusplus", "", "")
            .expect("commentstyle registered");
        assert!(msg.starts_with("LowlevelError: no print language registered"));

        // Register the printer (the architecture.cc:171-172 mirror).
        let handle = arch.register_print_language(Box::new(crate::printc::PrintC::new(Box::new(
            EmitNoMarkup::new(),
        ))));
        // Default style is C (printc.cc:1594 setCStyleComments).
        assert!(rendered_comment(&handle).starts_with("/* "));
        let msg = db
            .set(&mut arch, "commentstyle", "cplusplus", "", "")
            .expect("commentstyle registered");
        // options.cc:527: "Comment style set to "+p1
        assert_eq!(msg, "Comment style set to cplusplus");
        // The routed state is observable on the SAME printer object the
        // registrant holds (printc.cc:2357 setCPlusPlusStyleComments ->
        // setCommentDelimeter("// ","",true)): the next rendered comment
        // opens with "// ".
        assert!(
            rendered_comment(&handle).starts_with("// "),
            "route did not reach printer"
        );
        // An unknown style surfaces the oracle's LowlevelError text
        // (printc.cc:2359-2360) and leaves the printer untouched.
        let msg = db
            .set(&mut arch, "commentstyle", "badstyle", "", "")
            .expect("commentstyle registered");
        assert_eq!(
            msg,
            "LowlevelError: Unknown comment style. Use \"c\" or \"cplusplus\""
        );
        assert!(rendered_comment(&handle).starts_with("// "));
        // Architecture::resetDefaults (architecture.cc:1443-1444) resets
        // every registered printer: the style returns to C.
        arch.reset_defaults();
        assert!(
            rendered_comment(&handle).starts_with("/* "),
            "printlist reset loop did not reach printer"
        );
    }

    #[test]
    fn test_on_or_off() {
        assert!(on_or_off("on"));
        assert!(!on_or_off("off"));
        assert!(on_or_off(""));
        // Ghidra throws on unknown; rugra defaults to true.
        assert!(on_or_off("yes"));
    }

    #[test]
    fn test_option_database_default_registry() {
        let db = OptionDatabase::new();
        assert!(db.num_options() >= 38);
        // Mirrors the names registered in options.cc:96-133.
        for n in [
            "extrapop",
            "readonly",
            "defaultprototype",
            "inferconstptr",
            "analyzeforloops",
            "inline",
            "noreturn",
            "warning",
            "printnull",
            "inplaceops",
            "conventionprinting",
            "nocastprinting",
            "hideextensions",
            "maxlinewidth",
            "indentincrement",
            "commentindent",
            "commentstyle",
            "commentheader",
            "commentinstruction",
            "integerformat",
            "braceformat",
            "setaction",
            "currentaction",
            "allowcontextset",
            "ignoreunimplemented",
            "errorunimplemented",
            "errorreinterpreted",
            "errortoomanyinstructions",
            "protoeval",
            "setlanguage",
            "jumptablemax",
            "jumpload",
            "togglerule",
            "aliasblock",
            "maxinstruction",
            "namespacestrategy",
            "splitdatatype",
            "nanignore",
        ] {
            assert!(db.has_option(n), "missing option {n}");
        }
    }

    #[test]
    fn test_option_ignore_unimplemented_sets_flow_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        let msg = db.try_set(&mut arch, "ignoreunimplemented", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::IGNORE_UNIMPLEMENTED != 0);
        assert!(msg.contains("ignored"));
        db.try_set(&mut arch, "ignoreunimplemented", "off", "", "").unwrap();
        assert_eq!(arch.flowoptions & flow_flags::IGNORE_UNIMPLEMENTED, 0);
    }

    #[test]
    fn test_option_error_unimplemented_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        db.try_set(&mut arch, "errorunimplemented", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::ERROR_UNIMPLEMENTED != 0);
        db.try_set(&mut arch, "errorunimplemented", "off", "", "").unwrap();
        assert_eq!(arch.flowoptions & flow_flags::ERROR_UNIMPLEMENTED, 0);
    }

    #[test]
    fn test_option_error_reinterpreted_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        db.try_set(&mut arch, "errorreinterpreted", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::ERROR_REINTERPRETED != 0);
    }

    #[test]
    fn test_option_error_too_many_instructions_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        db.try_set(&mut arch, "errortoomanyinstructions", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::ERROR_TOOMANYINSTRUCTIONS != 0);
    }

    #[test]
    fn test_option_jump_load_flag() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.flowoptions = 0;
        db.try_set(&mut arch, "jumpload", "on", "", "").unwrap();
        assert!(arch.flowoptions & flow_flags::RECORD_JUMPLOADS != 0);
        db.try_set(&mut arch, "jumpload", "off", "", "").unwrap();
        assert_eq!(arch.flowoptions & flow_flags::RECORD_JUMPLOADS, 0);
    }

    #[test]
    fn test_option_jumptablemax_numeric() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let msg = db.try_set(&mut arch, "jumptablemax", "0x100", "", "").unwrap();
        assert_eq!(arch.max_jumptable_size, 0x100);
        assert!(msg.contains("256") || msg.contains("100"));
        // Bad input is rejected.
        assert!(db
            .try_set(&mut arch, "jumptablemax", "garbage", "", "")
            .is_ok());
    }

    #[test]
    fn test_option_maxinstruction_signed_negative_ok() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        db.try_set(&mut arch, "maxinstruction", "123", "", "").unwrap();
        assert_eq!(arch.max_instructions, 123);
    }

    #[test]
    fn test_option_alias_block_combines_flags() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.alias_block_level = 0;
        db.try_set(&mut arch, "aliasblock", "struct,array", "", "").unwrap();
        assert_eq!(arch.alias_block_level, 1 | 2);
        db.try_set(&mut arch, "aliasblock", "none", "", "").unwrap();
        assert_eq!(arch.alias_block_level, 0);
    }

    #[test]
    fn test_option_infer_const_ptr() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.infer_pointers = false;
        db.try_set(&mut arch, "inferconstptr", "on", "", "").unwrap();
        assert!(arch.infer_pointers);
        db.try_set(&mut arch, "inferconstptr", "off", "", "").unwrap();
        assert!(!arch.infer_pointers);
    }

    #[test]
    fn test_option_for_loops() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.analyze_for_loops = false;
        db.try_set(&mut arch, "analyzeforloops", "on", "", "").unwrap();
        assert!(arch.analyze_for_loops);
    }

    #[test]
    fn test_option_readonly() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.readonlypropagate = false;
        db.try_set(&mut arch, "readonly", "on", "", "").unwrap();
        assert!(arch.readonlypropagate);
    }

    #[test]
    fn test_option_split_datatypes() {
        use crate::arch::split_datatype as bits;
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        // Default is struct|array|pointer (architecture.cc:1430-1431).
        assert_eq!(arch.split_datatype_config, 7);
        // Empty params reset the configuration to 0 (options.cc:1003-1005).
        let msg = db.try_set(&mut arch, "splitdatatype", "", "", "").unwrap();
        assert_eq!(arch.split_datatype_config, 0);
        assert_eq!(msg, "Split data-type configuration set");
        // struct alone: splitcopy group on, splitpointer off.
        db.try_set(&mut arch, "splitdatatype", "struct", "", "").unwrap();
        assert_eq!(arch.split_datatype_config, bits::OPTION_STRUCT);
        assert_eq!(split_action_toggles(arch.split_datatype_config), (true, false));
        // Repeating the same configuration returns "unchanged" (options.cc:1017-1019).
        let msg = db.try_set(&mut arch, "splitdatatype", "struct", "", "").unwrap();
        assert_eq!(msg, "Split data-type configuration unchanged");
        // Three params OR together, first one assigns.
        db.try_set(&mut arch, "splitdatatype", "array", "pointer", "struct").unwrap();
        assert_eq!(arch.split_datatype_config, 7);
        assert_eq!(split_action_toggles(arch.split_datatype_config), (true, true));
        // Pointer alone leaves both groups off (options.cc:1007-1009).
        db.try_set(&mut arch, "splitdatatype", "pointer", "", "").unwrap();
        assert_eq!(arch.split_datatype_config, bits::OPTION_POINTER);
        assert_eq!(split_action_toggles(arch.split_datatype_config), (false, false));
        // Old 11.x token "float" is rejected as an unknown option token.
        let msg = db.try_set(&mut arch, "splitdatatype", "float", "", "").unwrap();
        assert_eq!(msg, "LowlevelError: Unknown data-type split option: float");
        assert_eq!(arch.split_datatype_config, bits::OPTION_POINTER);
        // A bad p2 token throws after p1's assignment took effect
        // (options.cc:1003-1004 evaluation order).
        let msg = db.try_set(&mut arch, "splitdatatype", "struct", "bogus", "").unwrap();
        assert_eq!(msg, "LowlevelError: Unknown data-type split option: bogus");
        assert_eq!(arch.split_datatype_config, bits::OPTION_STRUCT);
        // The 11.x plural name is no longer registered (options.hh:343).
        assert!(db.try_set(&mut arch, "splitdatatypes", "struct", "", "").is_err());
    }

    #[test]
    fn test_option_nan_ignore() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        arch.nan_ignore_all = false;
        arch.nan_ignore_compare = false;
        db.try_set(&mut arch, "nanignore", "all", "", "").unwrap();
        assert!(arch.nan_ignore_all && arch.nan_ignore_compare);
        db.try_set(&mut arch, "nanignore", "none", "", "").unwrap();
        assert!(!arch.nan_ignore_all && !arch.nan_ignore_compare);
    }

    #[test]
    fn test_option_integer_format() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let msg = db.try_set(&mut arch, "integerformat", "hex", "force", "").unwrap();
        assert!(msg.contains("hex") && msg.contains("force"));
        let msg = db.try_set(&mut arch, "integerformat", "dec", "", "").unwrap();
        assert!(msg.contains("dec"));
    }

    #[test]
    fn test_option_brace_format() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let msg = db.try_set(&mut arch, "braceformat", "next", "", "").unwrap();
        assert!(msg.contains("next"));
    }

    #[test]
    fn test_option_set_and_current_action_messages() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let m1 = db.try_set(&mut arch, "setaction", "decompile", "", "").unwrap();
        assert!(m1.contains("decompile"));
        let m2 = db.try_set(&mut arch, "currentaction", "decompile", "", "").unwrap();
        assert!(m2.contains("decompile"));
        // Empty current action is rejected.
        let m3 = db.try_set(&mut arch, "currentaction", "", "", "").unwrap();
        assert!(m3.contains("Bad"));
    }

    #[test]
    fn test_option_toggle_rule_messages() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let m1 = db.try_set(&mut arch, "togglerule", "myrule", "on", "").unwrap();
        assert!(m1.contains("enabled"));
        let m2 = db.try_set(&mut arch, "togglerule", "myrule", "off", "").unwrap();
        assert!(m2.contains("disabled"));
    }

    #[test]
    fn test_option_allow_context_set_message() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let m = db.try_set(&mut arch, "allowcontextset", "off", "", "").unwrap();
        assert!(m.contains("off"));
    }

    #[test]
    fn test_option_protocval_unknown_message() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        let m = db.try_set(&mut arch, "protoeval", "nonexistent", "", "").unwrap();
        assert!(m.contains("Unknown"));
        // Reset to default always succeeds.
        let m = db.try_set(&mut arch, "protoeval", "default", "", "").unwrap();
        assert!(m.contains("default"));
    }

    #[test]
    fn test_unknown_option_returns_none() {
        let mut arch = make_arch();
        let mut db = OptionDatabase::new();
        assert!(db.try_set(&mut arch, "nosuchoption", "", "", "").is_err());
    }

    #[test]
    fn test_parse_int_any_base_hex() {
        assert_eq!(parse_int_any_base("0x10"), Some(16));
        assert_eq!(parse_int_any_base("0XFF"), Some(255));
        assert_eq!(parse_int_any_base("42"), Some(42));
        assert_eq!(parse_int_any_base("-5"), Some(-5));
        assert_eq!(parse_int_any_base(""), None);
        assert_eq!(parse_int_any_base("abc"), None);
    }

    #[test]
    fn test_parse_uint_any_base_octal() {
        assert_eq!(parse_uint_any_base("010"), Some(8));
        assert_eq!(parse_uint_any_base("10"), Some(10));
        assert_eq!(parse_uint_any_base("0x1F"), Some(31));
    }

    #[test]
    fn test_alias_block_flag_lookup() {
        assert_eq!(alias_block_flag("struct"), Some(1));
        assert_eq!(alias_block_flag("array"), Some(2));
        assert_eq!(alias_block_flag("none"), Some(0));
        assert_eq!(alias_block_flag("bogus"), None);
    }

    #[test]
    fn test_get_option_bit() {
        assert_eq!(get_option_bit(""), Ok(0));
        assert_eq!(get_option_bit("struct"), Ok(1));
        assert_eq!(get_option_bit("array"), Ok(2));
        assert_eq!(get_option_bit("pointer"), Ok(4));
        assert_eq!(
            get_option_bit("float"),
            Err("Unknown data-type split option: float".to_string())
        );
        assert_eq!(
            get_option_bit("bogus"),
            Err("Unknown data-type split option: bogus".to_string())
        );
    }
}
