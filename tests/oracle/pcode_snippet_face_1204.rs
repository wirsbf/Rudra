//! PARSEADJ-PARSEFACE-PCODE-0001: current-Rudra comparand for the locked
//! Ghidra 12.0.4 pcode-snippet parser whole-face fixture
//! (pcode_snippet_face_1204.cc).  Compiles the same case matrix through
//! `PcodeSnippet` and prints the identical records byte for byte.
//!
//! ## Language-side host
//!
//! The C++ fixture boots a real `SleighBase` on the production x86-64.sla;
//! Rudra links no SLEIGH engine, so the language symbol table arrives
//! through the `SleighSymbolLookup` hook exactly like production callers
//! install it (`set_sleigh_lookup`).  `FaceLanguage` mirrors the
//! x86-64.sla facts the locked-oracle fixture itself observes in its SYM
//! section: the register varnode symbols (RAX..RIP/SF/ZF/AL with their
//! register-space offsets and sizes), the one user-defined op (`cpuid`,
//! index 44), and nothing else — `ram`/`OTHER`/`stack` are ABSENT from the
//! language table on both sides (the address-space symbols are seeded by
//! the `PcodeSnippet` constructor itself, pcodeparse.y:686-692), and the
//! three predefined JUMPSYM symbols (`inst_start`/`inst_next`/
//! `inst_next2`) are provided by `PredefinedJumpSymbols`, standing in for
//! their .sla serialization (slgh_compile.cc:1986-1991).
//!
//! ## Projection normalisations (fixture-writer channel, not parse facts)
//!
//! - Opcode names in `<op_tpl code=...>` are rendered by the production
//!   `OpCode::name()` (the `get_opname` port, opcodes.cc:29-48) — since
//!   PCODE-OPNAME-TABLE-0001 aligned the src table 1:1 with the locked
//!   oracle, the twin's former local `ghidra_op_name` mirror was retired;
//!   the `<op_tpl code=...>` bytes are produced by the very src function
//!   under alignment (PTRADD→LABEL, INT2FLOAT/FLOAT2FLOAT, TRUNC/CEIL/
//!   FLOOR/ROUND verified against the oracle encode channel).
//! - `construct_tpl` carries the `labels="N"` attribute when the template
//!   placed labels (ConstructTpl::addOp counting LABELBUILD ops,
//!   semantics.cc:748-749, encoded at semantics.cc:875-876).

use rudra::opcodes::OpCode;
use rudra::pcodeparse::{
    ConstTpl, ConstructTpl, HandleSelect, PcodeSnippet, PredefinedJumpSymbols,
    SleighSymbol, SleighSymbolLookup, SleightSymbolKind, VarnodeTpl,
};
use rudra::space::AddressSpace;

use std::process::ExitCode;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Language-side host: x86-64.sla facts (oracle SYM section)
// ---------------------------------------------------------------------------

/// (name, offset, size) of the register varnode symbols the x86-64.sla
/// exposes, exactly as the locked-oracle fixture's SYM probes observe them.
const REGISTERS: [(&str, u64, usize); 13] = [
    ("RAX", 0x0, 8),
    ("EAX", 0x0, 4),
    ("AL", 0x0, 1),
    ("RCX", 0x8, 8),
    ("RDX", 0x10, 8),
    ("RBX", 0x18, 8),
    ("RSP", 0x20, 8),
    ("RBP", 0x28, 8),
    ("RSI", 0x30, 8),
    ("RDI", 0x38, 8),
    ("RIP", 0x288, 8),
    ("SF", 0x207, 1),
    ("ZF", 0x206, 1),
];

/// The one user-defined pcode op of the x86-64.sla.
const USEROPS: [(&str, u32); 1] = [("cpuid", 44)];

struct FaceLanguage;

impl SleighSymbolLookup for FaceLanguage {
    fn find_symbol(&self, name: &str) -> Option<SleighSymbol> {
        if let Some((_, off, size)) = REGISTERS.iter().find(|(n, _, _)| *n == name) {
            return Some(SleighSymbol {
                name: name.to_string(),
                kind: SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                    space: AddressSpace::Register,
                    offset: *off,
                    size: *size,
                }),
            });
        }
        if let Some((_, index)) = USEROPS.iter().find(|(n, _)| *n == name) {
            return Some(SleighSymbol {
                name: name.to_string(),
                kind: SleightSymbolKind::UserOp(*index),
            });
        }
        None
    }
}

/// symbol_type ordinals (slghsymbol.hh:28-32) for the SYM section.
fn symbol_type_ordinal(sym: &SleighSymbol) -> Option<i32> {
    match &sym.kind {
        SleightSymbolKind::Space(_) => Some(0),
        SleightSymbolKind::UserOp(_) => Some(2),
        SleightSymbolKind::Varnode(_) => Some(6),
        SleightSymbolKind::Operand(_, _) => Some(8),
        SleightSymbolKind::JumpTarget(kind) => match kind {
            rudra::pcodeparse::JumpTargetKind::InstStart => Some(9),
            rudra::pcodeparse::JumpTargetKind::InstNext => Some(10),
            rudra::pcodeparse::JumpTargetKind::InstNext2 => Some(11),
            rudra::pcodeparse::JumpTargetKind::InstDest => Some(19),
            rudra::pcodeparse::JumpTargetKind::InstRef => Some(20),
        },
        SleightSymbolKind::Label(_, _) => Some(18),
    }
}

// ---------------------------------------------------------------------------
// XML projection: byte-identical mirror of XmlEncode + ConstructTpl::encode
// ---------------------------------------------------------------------------

// NOTE(PCODE-OPNAME-TABLE-0001): the former local `ghidra_op_name` mirror of
// the get_opname table was retired — `OpCode::name()` itself is now the 1:1
// port of opcodes.cc:29-48, and every `<op_tpl code=...>` attribute below is
// rendered straight from the production src function.

fn space_name(spc: &AddressSpace) -> &'static str {
    match spc {
        AddressSpace::Const => "const",
        AddressSpace::Unique => "unique",
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Stack => "stack",
        AddressSpace::Iop => "iop",
        AddressSpace::Join => "join",
        AddressSpace::Other(_) => "OTHER",
        AddressSpace::Overlay => "OTHER",
    }
}

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

/// a_v_u (xml.hh:363-369): unsigned attributes print as 0x + lowercase hex.
fn hex_val(v: u64) -> String {
    format!("0x{:x}", v)
}

fn write_const_tpl(writer: &mut TplWriter, ct: &ConstTpl) {
    match ct {
        ConstTpl::Real(v) => {
            writer.begin("const_real", &[("val", hex_val(*v))]);
            writer.end("const_real");
        }
        ConstTpl::SpaceId(spc) => {
            writer.begin("const_spaceid", &[("space", space_name(spc).to_string())]);
            writer.end("const_spaceid");
        }
        ConstTpl::JCurSpace => {
            writer.begin("const_curspace", &[]);
            writer.end("const_curspace");
        }
        ConstTpl::JCurSpaceSize => {
            writer.begin("const_curspace_size", &[]);
            writer.end("const_curspace_size");
        }
        ConstTpl::JRelative(i) => {
            writer.begin("const_relative", &[("val", hex_val(u64::from(*i)))]);
            writer.end("const_relative");
        }
        ConstTpl::JStart => {
            writer.begin("const_start", &[]);
            writer.end("const_start");
        }
        ConstTpl::JNext => {
            writer.begin("const_next", &[]);
            writer.end("const_next");
        }
        ConstTpl::JNext2 => {
            writer.begin("const_next2", &[]);
            writer.end("const_next2");
        }
        ConstTpl::JFlowRef => {
            writer.begin("const_flowref", &[]);
            writer.end("const_flowref");
        }
        ConstTpl::JFlowDest => {
            writer.begin("const_flowdest", &[]);
            writer.end("const_flowdest");
        }
        ConstTpl::Handle {
            index,
            select,
            plus,
        } => {
            // ConstTpl::encode handle case (semantics.cc:309-316): val and
            // s are signed decimals; plus (only for v_offset_plus) is an
            // unsigned hex attribute.
            let s: i32 = match select {
                HandleSelect::Space => 0,
                HandleSelect::Offset => 1,
                HandleSelect::Size => 2,
                HandleSelect::OffsetPlus => 3,
            };
            if matches!(select, HandleSelect::OffsetPlus) {
                writer.begin(
                    "const_handle",
                    &[
                        ("val", format!("{}", index)),
                        ("s", format!("{}", s)),
                        ("plus", hex_val(*plus)),
                    ],
                );
            } else {
                writer.begin(
                    "const_handle",
                    &[("val", format!("{}", index)), ("s", format!("{}", s))],
                );
            }
            writer.end("const_handle");
        }
    }
}

fn write_varnode_tpl(writer: &mut TplWriter, vn: &VarnodeTpl) {
    writer.begin("varnode_tpl", &[]);
    write_const_tpl(writer, &vn.get_space());
    write_const_tpl(writer, &vn.get_offset());
    write_const_tpl(writer, &vn.get_size());
    writer.end("varnode_tpl");
}

/// Byte-identical mirror of `ConstructTpl::encode(encoder, -1)`
/// (semantics.cc:867-883): the `labels` attribute when labels were placed
/// (signed decimal), the `<null/>` result handle, then one `<op_tpl>` per op.
fn write_template(tpl: &ConstructTpl) -> String {
    let mut writer = TplWriter::new();
    let attrs: Vec<(&str, String)> = if tpl.num_labels != 0 {
        vec![("labels", format!("{}", tpl.num_labels))]
    } else {
        Vec::new()
    };
    writer.begin("construct_tpl", &attrs);
    writer.begin("null", &[]);
    writer.end("null");
    for op in tpl.get_opvec() {
        writer.begin("op_tpl", &[("code", op.opc.name().to_string())]);
        match &op.out {
            Some(out) => write_varnode_tpl(&mut writer, out),
            None => {
                writer.begin("null", &[]);
                writer.end("null");
            }
        }
        for input in &op.inputs {
            write_varnode_tpl(&mut writer, input);
        }
        writer.end("op_tpl");
    }
    writer.end("construct_tpl");
    writer.out
}

fn escape_newlines(value: &str) -> String {
    value.replace('\n', "\\n")
}

// ---------------------------------------------------------------------------
// Case runner
// ---------------------------------------------------------------------------

fn fresh_compiler() -> PcodeSnippet {
    let mut compiler = PcodeSnippet::new();
    compiler.set_sleigh_lookup(Arc::new(PredefinedJumpSymbols::new(FaceLanguage)));
    compiler
}

fn encode_result(compiler: &mut PcodeSnippet, id: &str, out: &mut String) {
    match compiler.release_result() {
        Some(tpl) => out.push_str(&format!(
            "SNIP|{}|OK|{}\n",
            id,
            escape_newlines(&write_template(&tpl))
        )),
        None => out.push_str(&format!("SNIP|{}|ERR|no result\n", id)),
    }
}

fn run_snippet(id: &str, snippet: &str, out: &mut String) {
    // parseInject lifecycle (inject_sleigh.cc:387-416): fresh compiler per
    // snippet, language lookup installed, default tempbase.
    let mut compiler = fresh_compiler();
    let ok = compiler.parse_stream(snippet);
    // SleighError escape (pcodecompile.cc:580 throw out of parseStream):
    // observe the hard-error channel first, exactly like the C++ fixture's
    // catch clause.
    if let Some(exc) = compiler.get_hard_error() {
        out.push_str(&format!("SNIP|{}|EXC|{}\n", id, escape_newlines(exc)));
        return;
    }
    if ok && !compiler.has_errors() {
        encode_result(&mut compiler, id, out);
        return;
    }
    out.push_str(&format!(
        "SNIP|{}|ERR|{}\n",
        id,
        escape_newlines(compiler.get_error_message())
    ));
}

fn run() -> Result<(), String> {
    let language = PredefinedJumpSymbols::new(FaceLanguage);

    let mut out = String::new();
    out.push_str("SCHEMA|1\n");

    // --- SYM probes (SleighBase::findSymbol face, pcodeparse.cc:3223) ------
    let probe_names = [
        "RAX", "EAX", "AL", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "RIP", "SF", "ZF",
        "cpuid", "inst_start", "inst_next", "inst_next2", "ram", "OTHER", "stack",
    ];
    for name in probe_names {
        match language.find_symbol(name) {
            None => out.push_str(&format!("SYM|{}|ABSENT\n", name)),
            Some(sym) => {
                out.push_str(&format!(
                    "SYM|{}|type={}",
                    name,
                    symbol_type_ordinal(&sym).ok_or_else(|| format!("symbol {} has no ordinal", name))?
                ));
                if let SleightSymbolKind::Varnode(vd) = &sym.kind {
                    out.push_str(&format!(
                        "|space={}|off=0x{:x}|size={}",
                        space_name(&vd.space),
                        vd.offset,
                        vd.size
                    ));
                }
                if let SleightSymbolKind::UserOp(index) = &sym.kind {
                    out.push_str(&format!("|index={}", index));
                }
                out.push('\n');
            }
        }
    }

    // --- SNIP: address-space seeding face ----------------------------------
    run_snippet("sp01", "*[ram]:8 RAX = RBX;", &mut out);
    run_snippet("sp02", "*[register]:8 RAX = RBX;", &mut out);
    run_snippet("sp03", "*[unique]:8 RAX = RBX;", &mut out);
    run_snippet("sp04", "*[const]:8 RAX = RBX;", &mut out);
    run_snippet("sp05", "*[OTHER]:8 RAX = RBX;", &mut out);
    run_snippet("sp06", "*[stack]:8 RAX = RBX;", &mut out);
    run_snippet("sp07", "*[iop]:8 RAX = RBX;", &mut out);
    run_snippet("sp08", "*:8 RAX = RBX;", &mut out);
    run_snippet("sp09", "local v:8 = *:8 RAX;", &mut out);
    run_snippet("sp10", "local w:8 = * RAX;", &mut out);

    // --- SNIP: statement forms ---------------------------------------------
    run_snippet("st01", "RAX = RAX + 1;", &mut out);
    run_snippet("st02", "local t = EAX;", &mut out);
    run_snippet("st03", "local t:8 = 0x10;", &mut out);
    run_snippet("st04", "q = RAX;", &mut out);
    run_snippet("st05", "q:4 = 5;", &mut out);
    run_snippet("st06", "local d:8 = inst_ref;", &mut out);
    run_snippet("st07", "cpuid();", &mut out);
    run_snippet("st08", "cpuid(RAX,RBX);", &mut out);
    run_snippet("st09", "RAX[0,16] = RCX;", &mut out);
    run_snippet("st10", "RAX[4,8] = 0x1;", &mut out);
    run_snippet("st11", "RAX:4 = RAX;", &mut out);
    run_snippet("st12", "RAX(2);", &mut out);
    run_snippet("st13", "return;", &mut out);
    run_snippet("st14", "return [RAX];", &mut out);
    run_snippet("st15", "local RAX = 1;", &mut out);
    run_snippet("st16", "goto 0x1000;", &mut out);
    run_snippet("st17", "goto 0x1000[ram];", &mut out);
    run_snippet("st18", "goto 0x20[register];", &mut out);
    run_snippet("st19", "goto inst_next;", &mut out);
    run_snippet("st20", "<lab> RAX = RBX; goto <lab>;", &mut out);
    run_snippet("st21", "goto nosuch;", &mut out);
    run_snippet("st22", "if (RAX == 0) goto 0x40;", &mut out);
    run_snippet("st23", "call 0x1000;", &mut out);
    run_snippet("st24", "call [RBX];", &mut out);
    run_snippet("st25", "goto [RAX + 0x8];", &mut out);
    run_snippet("st26", "local q:8 = 1; local q:4 = 2;", &mut out);
    run_snippet("st27", "<a> RAX = 1; <a> RBX = 2;", &mut out);
    run_snippet("st28", "zz;", &mut out);
    run_snippet("st29", "RAX = zzz + 1;", &mut out);
    run_snippet("st30", "RAX = = 1;", &mut out);
    run_snippet("st31", "goto 18446744073709551616;", &mut out);
    run_snippet("st32", "local t:8 = 0x10000000000000000;", &mut out);
    run_snippet("st33", "local t = RAX f+ RBX;", &mut out);
    run_snippet("st34", "RAX[0,0] = 1;", &mut out);
    run_snippet("st35", "AL[0,16] = 1;", &mut out);
    run_snippet("st36", "RAX[0,64] = RBX;", &mut out);
    run_snippet("st37", "local t = RAX:8;", &mut out);
    run_snippet("st38", "local t = AL[0,16];", &mut out);
    run_snippet("st39", "local q; local r; q = r; r = RBX;", &mut out);
    run_snippet("st40", "local q; RAX = q;", &mut out);

    // --- SNIP: expression operator face ------------------------------------
    run_snippet("ex01", "local t:8 = RAX + RBX * 2 - RCX / 3 % 4;", &mut out);
    run_snippet("ex02", "local t:8 = RAX - RBX - RCX;", &mut out);
    run_snippet("ex03", "local t:8 = RAX - (RBX - RCX);", &mut out);
    run_snippet("ex04", "local a:1 = RAX > RBX; local b:1 = RAX >= RBX;", &mut out);
    run_snippet("ex05", "local a:1 = RAX s> RBX; local b:1 = RAX s>= RBX;", &mut out);
    run_snippet(
        "ex06",
        "local a:8 = RAX f+ RBX; local b:8 = RAX f- RBX; local c:8 = RAX f* RBX; local d:8 = RAX f/ RBX;",
        &mut out,
    );
    run_snippet(
        "ex07",
        "local a:1 = RAX f> RBX; local b:1 = RAX f>= RBX; local c:1 = RAX f== RBX; local d:1 = RAX f!= RBX;",
        &mut out,
    );
    run_snippet(
        "ex08",
        "local a:8 = -RAX; local b:8 = ~RAX; local c:1 = !(RAX == RBX); local d:8 = f- RAX;",
        &mut out,
    );
    run_snippet(
        "ex09",
        "local a:1 = RAX && RBX; local b:1 = RAX || RBX; local c:1 = RAX ^^ RBX;",
        &mut out,
    );
    run_snippet(
        "ex10",
        "local a:8 = RAX << RBX; local b:8 = RAX >> RBX; local c:8 = RAX s>> RBX;",
        &mut out,
    );
    run_snippet(
        "ex11",
        "local a:8 = zext(EAX); local b:8 = sext(EAX); local c:1 = carry(RAX,RBX); local d:1 = scarry(RAX,RBX); local e:1 = sborrow(RAX,RBX);",
        &mut out,
    );
    run_snippet(
        "ex12",
        "local a:8 = abs(RAX); local b:8 = sqrt(RAX); local c:8 = ceil(RAX); local d:8 = floor(RAX); local e:8 = round(RAX);",
        &mut out,
    );
    run_snippet(
        "ex13",
        "local a:1 = nan(RAX); local b:8 = trunc(RAX); local c:8 = int2float(EAX); local d:8 = float2float(RAX);",
        &mut out,
    );
    run_snippet("ex14", "local t = EAX(1);", &mut out);
    run_snippet("ex15", "local a = EAX:2; local b = RAX[0,16]; local c = EAX[4,4];", &mut out);
    run_snippet("ex16", "local t:8 = cpuid(RAX);", &mut out);
    run_snippet("ex17", "local p = &RAX; local q = &:8 RBX; local r = &inst_start;", &mut out);
    run_snippet("ex18", "local t:4 = 0xdeadbeef:4;", &mut out);
    run_snippet("ex19", "local v:8 = *[ram]:8 RAX + 0x8;", &mut out);
    run_snippet("ex20", "local n:8 = new(RAX); local m:8 = new(RAX,RBX);", &mut out);

    // --- SNIP: lexer face ---------------------------------------------------
    run_snippet("lx01", "# lead comment\n\tRAX = RAX;\nRAX = RBX; # tail comment\n", &mut out);
    run_snippet(
        "lx02",
        "local a:1 = EAX s<= EAX; local b:1 = EAX s>= EAX; local c:8 = EAX s>> EAX; local d:1 = EAX f== EAX; local e:1 = EAX f!= EAX;",
        &mut out,
    );
    run_snippet("lx03", "local a_b.c:1 = 1; local size1:1 = 2; local floorx:1 = 3;", &mut out);
    run_snippet("lx04", "local a:8 = 0xff + 255;", &mut out);
    run_snippet("lx05", "local t:8 = 0xffffffffffffffff;", &mut out);
    run_snippet("lx06", "RAX = RAX $ 1;", &mut out);

    // --- LF: lifecycle member probes ---------------------------------------
    // lf1: set_unique_base / get_unique_base / allocate_temp offsets.
    {
        let mut compiler = fresh_compiler();
        compiler.set_unique_base(0x1234);
        out.push_str(&format!("LF|ub|{:x}\n", compiler.get_unique_base()));
        encode_lf(&mut compiler, "ubparse", "local q:8 = 1;", &mut out);
    }
    // lf2: clear() drops non-space symbols — the defined local q becomes
    // unknown after clear.
    {
        let mut compiler = fresh_compiler();
        let oka = compiler.parse_stream("local q:8 = 1; q = q + 1;");
        out.push_str(&format!(
            "LF|clr1|{}\n",
            if oka && !compiler.has_errors() { "OK" } else { "ERR" }
        ));
        compiler.clear();
        compiler.parse_stream("q = q + 1;");
        out.push_str(&format!(
            "LF|clr2|{}\n",
            escape_newlines(compiler.get_error_message())
        ));
    }
    // lf3: clear() does NOT reset tempbase — the second parse's local lands
    // at offset 16.
    {
        let mut compiler = fresh_compiler();
        compiler.parse_stream("local a:8 = 1;");
        compiler.clear();
        encode_lf(&mut compiler, "clrtb", "local b:8 = 2;", &mut out);
    }
    // lf4: clear() resets the label counter — the label index after clear
    // starts from 0 again.
    {
        let mut compiler = fresh_compiler();
        compiler.parse_stream("<x> goto <x>;");
        compiler.clear();
        encode_lf(&mut compiler, "clrlbl", "<y> goto <y>;", &mut out);
    }
    // lf5: clear() resets the error state.
    {
        let mut compiler = fresh_compiler();
        compiler.parse_stream("return;");
        out.push_str(&format!(
            "LF|clrerr1|{}\n",
            escape_newlines(compiler.get_error_message())
        ));
        compiler.clear();
        let okb = compiler.parse_stream("RAX = RAX;");
        out.push_str(&format!(
            "LF|clrerr2|{}\n",
            if okb && !compiler.has_errors() { "OK" } else { "ERR" }
        ));
    }
    // lf6: add_symbol duplicate detection reached through the public
    // add_operand — "ram" collides with the ctor-seeded space symbol.
    {
        let mut compiler = fresh_compiler();
        compiler.add_operand("ram", 0);
        out.push_str(&format!(
            "LF|dup|{}\n",
            if compiler.has_errors() {
                escape_newlines(compiler.get_error_message())
            } else {
                "noerr".to_string()
            }
        ));
        compiler.clear();
        let okb = compiler.parse_stream("RAX = RBX;");
        out.push_str(&format!(
            "LF|duprec|{}\n",
            if okb && !compiler.has_errors() { "OK" } else { "ERR" }
        ));
    }
    // lf7: add_operand handles — operand symbols feed the OPERANDSYM
    // varnode/handle forms.
    {
        let mut compiler = fresh_compiler();
        compiler.add_operand("in0", 0);
        compiler.add_operand("in1", 1);
        encode_lf(&mut compiler, "ops", "local o:8 = in0 + in1; local p:4 = in0(2);", &mut out);
    }
    // lf8: release_result ownership — the second release returns None.
    {
        let mut compiler = fresh_compiler();
        compiler.parse_stream("RAX = RBX;");
        drop(compiler.release_result());
        let second = compiler.release_result();
        out.push_str(&format!(
            "LF|release2|{}\n",
            if second.is_none() { "null" } else { "some" }
        ));
    }

    out.push_str("DONE\n");
    print!("{}", out);
    Ok(())
}

/// Parse one snippet on the given compiler and emit the `LF|id|...` record
/// (same encoding channel as the SNIP records).
fn encode_lf(compiler: &mut PcodeSnippet, id: &str, snippet: &str, out: &mut String) {
    let ok = compiler.parse_stream(snippet);
    if let Some(exc) = compiler.get_hard_error() {
        out.push_str(&format!("LF|{}|EXC|{}\n", id, escape_newlines(exc)));
        return;
    }
    if ok && !compiler.has_errors() {
        match compiler.release_result() {
            Some(tpl) => out.push_str(&format!(
                "LF|{}|OK|{}\n",
                id,
                escape_newlines(&write_template(&tpl))
            )),
            None => out.push_str(&format!("LF|{}|ERR|no result\n", id)),
        }
        return;
    }
    out.push_str(&format!(
        "LF|{}|ERR|{}\n",
        id,
        escape_newlines(compiler.get_error_message())
    ));
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("pcode_snippet_face_1204: {}", message);
            ExitCode::FAILURE
        }
    }
}
