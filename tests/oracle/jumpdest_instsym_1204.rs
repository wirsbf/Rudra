//! CSPEC-JUMPDEST-INSTSYM-0001: Rust side of the locked Ghidra 12.0.4
//! JUMPSYM snippet-compiler oracle.  Compiles the same ten snippets as the
//! C++ fixture (tests/oracle/jumpdest_instsym_1204.cc) through
//! `PcodeSnippet` + `PredefinedJumpSymbols`, printing the same projections
//! byte for byte:
//!   - `SYM|` — for each probed name, the `symbol_type` ordinal
//!     (slghsymbol.hh:28-32) the language lookup resolves it to.  The three
//!     predefined JUMPSYM symbols are folded into the language-side wrapper
//!     (`PredefinedJumpSymbols`, standing in for the .sla-serialized
//!     StartSymbol/EndSymbol/Next2Symbol of slgh_compile.cc:1986-1991);
//!     `inst_dest`/`inst_ref`/`epsilon` are ABSENT from the language table
//!     exactly like the locked oracle (inst_dest/inst_ref live only in the
//!     snippet-local tree, pcodeparse.y:693-694; EpsilonSymbol is dropped by
//!     SymbolTable::purge, slghsymbol.cc:248-255).
//!   - `SNIP|i|OK|<xml>` / `SNIP|i|ERR|<msg>` — the compiled template
//!     through the same XmlEncode formatting the C++ fixture's
//!     `ConstructTpl::encode(encoder,-1)` produces.
//!
//! Snippet temporaries start at unique offset 0 (PcodeSnippet default
//! tempbase, pcodeparse.y:681) matching the C++ side.

use rudra::pcodeparse::{
    ConstTpl, ConstructTpl, OpTpl, PcodeSnippet, PredefinedJumpSymbols, SleighSymbol,
    SleighSymbolLookup, SleightSymbolKind, VarnodeTpl,
};

use std::process::ExitCode;
use std::sync::Arc;

/// symbol_type ordinals (slghsymbol.hh:28-32) for the wrapper-provided
/// language symbols, matching the locked oracle's `findSymbol` result.
fn symbol_type_ordinal(sym: &SleighSymbol) -> Option<i32> {
    match &sym.kind {
        // space_symbol=0, token_symbol=1, userop_symbol=2, value_symbol=3,
        // valuemap_symbol=4, name_symbol=5, varnode_symbol=6,
        // varnodelist_symbol=7, operand_symbol=8, start_symbol=9,
        // end_symbol=10, next2_symbol=11, ...
        SleightSymbolKind::Space(_) => Some(0),
        SleightSymbolKind::UserOp(_) => Some(2),
        SleightSymbolKind::Varnode(_) => Some(6),
        SleightSymbolKind::Operand(_, _) => Some(8),
        SleightSymbolKind::JumpTarget(kind) => match kind {
            rudra::pcodeparse::JumpTargetKind::InstStart => Some(9),
            rudra::pcodeparse::JumpTargetKind::InstNext => Some(10),
            rudra::pcodeparse::JumpTargetKind::InstNext2 => Some(11),
            // flowdest_symbol=19, flowref_symbol=20 (language lookup never
            // returns these: they are snippet-local only).
            rudra::pcodeparse::JumpTargetKind::InstDest => Some(19),
            rudra::pcodeparse::JumpTargetKind::InstRef => Some(20),
        },
        // epsilon_symbol=17, label_symbol=18 — not reachable through the
        // language wrapper.
        SleightSymbolKind::Label(_, _) => Some(18),
    }
}

/// The XmlEncode-style mini writer used to print compiled templates with
/// byte-identical formatting to Ghidra's `ConstructTpl::encode`
/// (marshal.cc XmlEncode).
struct TplWriter {
    out: String,
    depth: usize,
    tag_open: bool,
}

impl TplWriter {
    fn new() -> Self {
        Self {
            out: String::new(),
            depth: 0,
            tag_open: false,
        }
    }
    fn newline_indent(&mut self) {
        self.out.push('\n');
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
    }
    fn begin(&mut self, name: &str, attrs: &[(&str, String)]) {
        if self.tag_open {
            self.out.push('>');
            self.tag_open = false;
        }
        self.newline_indent();
        self.out.push('<');
        self.out.push_str(name);
        for (key, value) in attrs {
            self.out.push_str(&format!(" {}=\"{}\"", key, value));
        }
        self.depth += 1;
        self.tag_open = true;
    }
    fn end(&mut self, name: &str) {
        self.depth -= 1;
        if self.tag_open {
            self.out.push_str("/>");
            self.tag_open = false;
            return;
        }
        self.newline_indent();
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push('>');
    }
}

fn write_const_tpl(writer: &mut TplWriter, ct: &ConstTpl) {
    // ConstTpl::encode element names (semantics.cc:300-365, slaformat.cc).
    let (name, attrs): (&str, Vec<(&str, String)>) = match ct {
        ConstTpl::Real(v) => ("const_real", vec![("val", format!("0x{:x}", v))]),
        ConstTpl::SpaceId(_) => ("const_spaceid", Vec::new()), // space filled by caller
        ConstTpl::JCurSpace => ("const_curspace", Vec::new()),
        ConstTpl::JCurSpaceSize => ("const_curspace_size", Vec::new()),
        ConstTpl::JRelative(i) => ("const_relative", vec![("val", format!("0x{:x}", i))]),
        ConstTpl::JStart => ("const_start", Vec::new()),
        ConstTpl::JNext => ("const_next", Vec::new()),
        ConstTpl::JNext2 => ("const_next2", Vec::new()),
        ConstTpl::JFlowRef => ("const_flowref", Vec::new()),
        ConstTpl::JFlowDest => ("const_flowdest", Vec::new()),
        ConstTpl::Handle { index, select, plus } => {
            // ConstTpl::encode handle case (semantics.cc:309-316): val =
            // handle index, s = select, plus only for v_offset_plus.
            let s = match select {
                rudra::pcodeparse::HandleSelect::Space => 0,
                rudra::pcodeparse::HandleSelect::Offset => 1,
                rudra::pcodeparse::HandleSelect::Size => 2,
                rudra::pcodeparse::HandleSelect::OffsetPlus => 3,
            };
            if matches!(select, rudra::pcodeparse::HandleSelect::OffsetPlus) {
                (
                    "const_handle",
                    vec![
                        ("val", format!("{}", index)),
                        ("s", format!("{}", s)),
                        ("plus", format!("0x{:x}", plus)),
                    ],
                )
            } else {
                ("const_handle", vec![("val", format!("{}", index)), ("s", format!("{}", s))])
            }
        }
    };
    if name == "const_spaceid" {
        // writeSpace emits the space name (locked x86-64 names).
        let spc = match ct {
            ConstTpl::SpaceId(s) => *s,
            _ => unreachable!(),
        };
        let spc_name = match spc {
            rudra::space::AddressSpace::Const => "const",
            rudra::space::AddressSpace::Unique => "unique",
            rudra::space::AddressSpace::Ram => "ram",
            rudra::space::AddressSpace::Register => "register",
            rudra::space::AddressSpace::Stack => "stack",
            rudra::space::AddressSpace::Iop => "iop",
            rudra::space::AddressSpace::Join => "join",
            rudra::space::AddressSpace::Other(_) => "OTHER",
            rudra::space::AddressSpace::Overlay => "OTHER",
        };
        writer.begin(name, &[("space", spc_name.to_string())]);
    } else {
        writer.begin(name, &attrs);
    }
    writer.end(name);
}

fn write_varnode_tpl(writer: &mut TplWriter, vn: &VarnodeTpl) {
    writer.begin("varnode_tpl", &[]);
    write_const_tpl(writer, &vn.get_space());
    write_const_tpl(writer, &vn.get_offset());
    write_const_tpl(writer, &vn.get_size());
    writer.end("varnode_tpl");
}

/// Byte-identical mirror of the C++ fixture's `tpl->encode(encoder, -1)`
/// (ConstructTpl::encode, semantics.cc: the <construct_tpl> header with a
/// <null/> result handle then one <op_tpl> per op).
fn write_template(tpl: &ConstructTpl) -> String {
    let mut writer = TplWriter::new();
    writer.begin("construct_tpl", &[]);
    // Snippet templates carry no result handle: <null/>.
    writer.begin("null", &[]);
    writer.end("null");
    for op in tpl.get_opvec() {
        write_op_tpl(&mut writer, op);
    }
    writer.end("construct_tpl");
    writer.out
}

fn write_op_tpl(writer: &mut TplWriter, op: &OpTpl) {
    writer.begin("op_tpl", &[("code", op.opc.name().to_string())]);
    match &op.out {
        Some(out) => write_varnode_tpl(writer, out),
        None => {
            writer.begin("null", &[]);
            writer.end("null");
        }
    }
    for input in &op.inputs {
        write_varnode_tpl(writer, input);
    }
    writer.end("op_tpl");
}

fn escape_newlines(value: &str) -> String {
    value.replace('\n', "\\n")
}

/// The language-side host: only the three predefined JUMPSYM symbols
/// (everything else resolves through the inner empty lookup, i.e. ABSENT,
/// exactly like the locked x86-64.sla for inst_dest/inst_ref/epsilon).
struct EmptyLanguage;

impl SleighSymbolLookup for EmptyLanguage {
    fn find_symbol(&self, _name: &str) -> Option<SleighSymbol> {
        None
    }
}

fn run_snippet(index: usize, snippet: &str, out: &mut String) {
    // parseInject lifecycle (inject_sleigh.cc:387-416): fresh compiler per
    // snippet, language lookup installed, default tempbase.
    let mut compiler = PcodeSnippet::new();
    compiler.set_sleigh_lookup(Arc::new(PredefinedJumpSymbols::new(EmptyLanguage)));
    if compiler.parse_stream(snippet) && !compiler.has_errors() {
        if let Some(tpl) = compiler.release_result() {
            out.push_str(&format!(
                "SNIP|{}|OK|{}\n",
                index,
                escape_newlines(&write_template(&tpl))
            ));
            return;
        }
        out.push_str(&format!("SNIP|{}|ERR|no result\n", index));
        return;
    }
    out.push_str(&format!(
        "SNIP|{}|ERR|{}\n",
        index,
        escape_newlines(compiler.get_error_message())
    ));
}

fn run() -> Result<(), String> {
    let language = PredefinedJumpSymbols::new(EmptyLanguage);

    let mut out = String::new();
    out.push_str("SCHEMA|1\n");

    // SleighBase::findSymbol observations.  inst_dest/inst_ref/epsilon are
    // absent from the language table (the C++ oracle prints ABSENT; the
    // local snippet tree provides inst_dest/inst_ref separately).
    let probe_names = ["inst_start", "inst_next", "inst_next2", "inst_dest", "inst_ref", "epsilon"];
    for name in probe_names {
        match language.find_symbol(name) {
            None => out.push_str(&format!("SYM|{}|ABSENT\n", name)),
            Some(sym) => match symbol_type_ordinal(&sym) {
                Some(ordinal) => out.push_str(&format!("SYM|{}|{}\n", name, ordinal)),
                None => return Err(format!("symbol {} has no type ordinal", name)),
            },
        }
    }

    // The same ten snippets as the C++ fixture.
    let snippets = [
        "goto inst_dest;",        // 0: jumpdest x local flowdest symbol
        "goto inst_ref;",         // 1: jumpdest x local flowref symbol
        "goto inst_next;",        // 2: jumpdest x language EndSymbol
        "goto inst_start;",       // 3: jumpdest x language StartSymbol
        "goto inst_next2;",       // 4: jumpdest x language Next2Symbol
        "local x:8 = inst_ref;",  // 5: varnode x local flowref (size propagation)
        "local y:8 = inst_dest;", // 6: varnode x local flowdest
        "local z:8 = inst_next;", // 7: varnode x language EndSymbol
        "goto nosuchsym;",        // 8: unknown jump destination (y:200)
        "local w:8 = epsilon;",   // 9: predefined-but-purged name -> STRING
    ];
    for (index, snippet) in snippets.iter().enumerate() {
        run_snippet(index, snippet, &mut out);
    }

    out.push_str("DONE\n");
    print!("{}", out);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("jumpdest_instsym_1204: {}", message);
            ExitCode::FAILURE
        }
    }
}
