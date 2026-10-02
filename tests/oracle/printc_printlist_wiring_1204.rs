//! PRINTC-PRINTLIST-WIRING-0001 Rust comparand — the option-to-printer
//! wiring hop, the architecture printlist structure, and the emitter half
//! of the resetDefaults chain, against locked Ghidra 12.0.4.
//!
//! Mirrors `tests/oracle/printc_printlist_wiring_1204.cc` case-for-case:
//!   - `OptionCommentStyle::apply` (options.cc:523-527) reached through
//!     the production `OptionDatabase::set` route;
//!   - the architecture-side printlist registry (the architecture.hh:
//!     205-206 storage mirror) — structure count and the current
//!     printer's name;
//!   - `Architecture::reset_defaults`' printlist loop
//!     (architecture.cc:1443-1444) restoring both the comment style and
//!     the pretty emitter's max line size (the emitter half,
//!     printlanguage.cc:674 -> prettyprint.cc:1237-1242).
//!
//! The registered printer is the production `PrintC` over the production
//! `EmitPrettyPrint` (the oracle PrintLanguage ctor's emitter,
//! printlanguage.cc:69); renders go through `emit_line_comment` + `flush`
//! exactly like the oracle fixture's `render` helper, observed as the
//! low-level stream delta. No hand-written expected output is embedded.

use std::sync::{Arc, RwLock};

use rudra::action::{Action, ActionDatabase, ActionGroupList, ActionRestartGroup};
use rudra::arch::Architecture;
use rudra::options::{ArchOption, OptionCommentStyle, OptionDatabase};
use rudra::prettyprint::{Emit, EmitPrettyPrint};
use rudra::printc::PrintC;
use rudra::printlanguage::{self, PrintLanguage as _};

// The inherited flags word carries this leaf's construction ordinal (same
// allocator-independent identity convention as the oracle fixture's
// ScriptAction).
static NEXT_SCRIPT_ORDINAL: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(100);

struct ScriptAction {
    group: &'static str,
    name: &'static str,
    ordinal: u32,
}

impl ScriptAction {
    fn new(group: &'static str, name: &'static str) -> Self {
        Self {
            group,
            name,
            ordinal: NEXT_SCRIPT_ORDINAL.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        }
    }
}

impl Action for ScriptAction {
    fn apply(&mut self, _fd: &mut rudra::funcdata::Funcdata) -> rudra::Result<i32> {
        Ok(0)
    }
    fn get_name(&self) -> &str {
        self.name
    }
    fn get_flags(&self) -> u32 {
        self.ordinal
    }
    fn clone_for_groups(&self, grouplist: &ActionGroupList) -> Option<Box<dyn Action>> {
        if !grouplist.contains(self.group) {
            return None;
        }
        Some(Box::new(Self::new(self.group, self.name)))
    }
}

type PrinterHandle = Arc<RwLock<Box<dyn printlanguage::PrintLanguage>>>;

// The oracle render helper: one line comment through the current printer,
// bytes committed to the low-level stream since the previous render.
fn render(handle: &PrinterHandle) -> String {
    let mut printer = handle
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let before = printer
        .get_emit()
        .as_any_mut()
        .and_then(|any| any.downcast_ref::<EmitPrettyPrint>())
        .map(|emit| emit.debug_lowlevel_output_ref().len())
        .unwrap_or(0);
    printer.emit_line_comment(0, "fixture body");
    printer.get_emit().flush();
    printer
        .get_emit()
        .as_any_mut()
        .and_then(|any| any.downcast_ref::<EmitPrettyPrint>())
        .map(|emit| emit.debug_lowlevel_output_ref()[before..].to_string())
        .unwrap_or_default()
}

fn emit_width(handle: &PrinterHandle) -> i32 {
    let mut printer = handle
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    printer.get_emit().get_max_line_size()
}

fn set_width(handle: &PrinterHandle, val: i32) {
    let mut printer = handle
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(pretty) = printer
        .get_emit()
        .as_any_mut()
        .and_then(|any| any.downcast_mut::<EmitPrettyPrint>())
    {
        pretty.set_max_line_size(val);
    }
}

fn main() {
    let mut arch = Architecture::new();

    // Minimal synthetic allacts root (the oracle fixture's shape) so the
    // allacts half of Architecture::reset_defaults finds its root.
    let mut universal = ActionRestartGroup::new(
        "universal",
        rudra::action::action_flags::RULE_ONCEPERFUNC,
        1,
    );
    universal.add_action_in_group(
        Box::new(ScriptAction::new("base", "start")),
        "base",
    );
    let mut db = ActionDatabase::new();
    db.register_action(Box::new(universal));
    db.set_group("decompile", &["base"]);
    db.set_current("decompile");
    arch.allacts = Some(Arc::new(RwLock::new(db)));

    // architecture.cc:171-172 mirror: register the default printer and
    // make it current.
    let handle = arch.register_print_language(Box::new(PrintC::new(Box::new(
        EmitPrettyPrint::new(),
    ))));
    println!(
        "case=structure|count={}|name={}",
        printlanguage::printlist_len(arch.print_registry_key),
        arch.print_language_current()
            .expect("registered printer")
            .read()
            .unwrap()
            .get_name()
    );

    // ---- the option route (options.cc:523-527) ----
    let routes: [(&str, &str); 5] = [
        ("cplusplus", "cplusplus"),
        ("c", "c"),
        ("blockslash", "/*custom"),
        ("lineslash", "//custom"),
        ("bad", "badstyle"),
    ];
    let option = OptionCommentStyle;
    for (tag, style) in routes {
        // The oracle fixture calls OptionCommentStyle::apply directly;
        // this drives the same production apply body, echoing the
        // LowlevelError's `explain` (no "LowlevelError: " prefix — that
        // prefix is Rudra's exception-channel convention inside apply's
        // return string) for the byte parity.
        let (threw, msg) = apply_option(&option, &mut arch, style);
        println!("case=route.{tag}|threw={threw}|msg={msg}|text={}", render(&handle));
    }

    // ---- the emitter half of resetDefaults (prettyprint.cc:1237-1242) ----
    set_width(&handle, 60);
    apply_option(&option, &mut arch, "cplusplus");
    println!("case=emit.before|width={}|text={}", emit_width(&handle), render(&handle));
    arch.reset_defaults();
    println!(
        "case=reset|count={}|width={}|text={}",
        printlanguage::printlist_len(arch.print_registry_key),
        emit_width(&handle),
        render(&handle)
    );
}

// options.cc:150-161 OptionDatabase::set for a directly constructed option
// object: apply with three parameters (the registry route is exercised in
// the unit test; the fixture pins the apply body itself, same as the
// oracle fixture's direct `option.apply(&arch, ...)`). Returns the threw
// flag plus the message as the oracle fixture echoes it (LowlevelError
// explain without Rudra's prefix convention).
fn apply_option(
    option: &OptionCommentStyle,
    arch: &mut Architecture,
    p1: &str,
) -> (i32, String) {
    let msg = option.apply(arch, p1, "", "");
    if let Some(explain) = msg.strip_prefix("LowlevelError: ") {
        (1, explain.to_string())
    } else {
        (0, msg)
    }
}
