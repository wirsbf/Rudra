// PRINTC-UNMAP-SINGLETON-0001 fixture — Rust side. The bilateral
// counterpart of printc_singleton_emission_1204.cc (locked oracle
// e40ed13014025f82488b1f8f7bca566894ac376b): same case lines, byte-for-byte
// stdout equality is the MATCH gate (runner tools/run_printc_singleton_
// emission_oracle.sh).
//
// Rudra-side notes: push_float runs through the default FloatFormats the
// oracle's Translate registers (translate.cc:962-970 setDefaultFloatFormats);
// the comment-style delimiters render through emit_line_comment (the
// printlanguage.cc:589 port); genericFunctionName takes the ram-space dims
// (addrsize 8, wordsize 1) the oracle fixture's Address(ram, ...) carries;
// emitSymbolScope observes the depth-0 global-scope fast path; the mismatch
// arms run through the pushMismatchSymbol text form; pushTypePointerRel
// observes the same incomplete "(ADJ" token pair the oracle's pushOp/
// pushAtom machinery leaves after flush.
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::{display_format, PrintC};
use rudra::printlanguage::PrintLanguage as _;

fn fresh() -> PrintC {
    PrintC::new(Box::new(EmitNoMarkup::new()))
}

fn drain(printer: PrintC) -> String {
    printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("fixture emitter type")
        .get_output()
}

fn push_float(val: u64, sz: i32) -> String {
    let mut printer = fresh();
    let text = printer.push_float_text(val, sz);
    drop(printer);
    text
}

fn push_float_scinote(val: u64, sz: i32) -> String {
    let mut printer = fresh();
    printer.push_mod();
    printer.set_mod(rudra::printlanguage::modifiers::FORCE_SCINOTE);
    let text = printer.push_float_text(val, sz);
    printer.pop_mod();
    text
}

fn render_comment(style: &str) -> (String, bool) {
    let mut printer = fresh();
    match printer.set_comment_style(style) {
        Ok(()) => {
            printer.emit_line_comment(0, "fixture body");
            (drain(printer), false)
        }
        Err(_) => (String::new(), true),
    }
}

fn main() {
    // ---- push_float (printc.cc:1380-1424) ----
    println!("case=float4.zero|out={}", push_float(0x00000000, 4));
    println!("case=float4.negzero|out={}", push_float(0x80000000, 4));
    println!("case=float4.one|out={}", push_float(0x3f800000, 4));
    println!("case=float4.negone|out={}", push_float(0xbf800000, 4));
    println!("case=float4.half|out={}", push_float(0x3f000000, 4));
    println!("case=float4.two_integral|out={}", push_float(0x40000000, 4));
    println!(
        "case=float4.hundred_integral|out={}",
        push_float(0x42c80000, 4)
    );
    println!("case=float4.pi|out={}", push_float(0x40490fdb, 4));
    println!("case=float4.inf|out={}", push_float(0x7f800000, 4));
    println!("case=float4.neginf|out={}", push_float(0xff800000, 4));
    println!("case=float4.nan|out={}", push_float(0x7fc00000, 4));
    println!("case=float4.negnan|out={}", push_float(0xffc00000, 4));
    println!("case=float4.subnormal|out={}", push_float(0x00000001, 4));
    println!(
        "case=float4.scinote_pi|out={}",
        push_float_scinote(0x40490fdb, 4)
    );
    println!("case=float8.one|out={}", push_float(0x3ff0000000000000, 8));
    println!("case=float8.tenth|out={}", push_float(0x3fb999999999999a, 8));
    println!(
        "case=float8.integral64|out={}",
        push_float(0x4059000000000000, 8)
    );
    println!("case=float8.inf|out={}", push_float(0x7ff0000000000000, 8));
    println!("case=float8.negnan|out={}", push_float(0xfff8000000000000, 8));
    println!(
        "case=float8.scinote_tenth|out={}",
        push_float_scinote(0x3fb999999999999a, 8)
    );
    println!("case=float2.unknown|out={}", push_float(0x3f80, 2));

    // ---- setCommentStyle (printc.cc:2350-2361) ----
    let (out, threw) = render_comment("c");
    println!("case=commentstyle.c|out={out}|threw={}", if threw { 1 } else { 0 });
    let (out, threw) = render_comment("cplusplus");
    println!("case=commentstyle.cplusplus|out={out}|threw={}", if threw { 1 } else { 0 });
    let (out, threw) = render_comment("/*custom");
    println!("case=commentstyle.blockslash|out={out}|threw={}", if threw { 1 } else { 0 });
    let (out, threw) = render_comment("//custom");
    println!("case=commentstyle.lineslash|out={out}|threw={}", if threw { 1 } else { 0 });
    let (_, threw) = render_comment("badstyle");
    println!("case=commentstyle.bad|threw={}", if threw { 1 } else { 0 });

    // ---- genericFunctionName (printc.cc:3359-3366) ----
    // The oracle fixture's Address(ram, off): addrsize 8, wordsize 1.
    println!(
        "case=genericname.plt|out={}",
        PrintC::generic_function_name(8, 1, 0x22e0)
    );
    println!(
        "case=genericname.low|out={}",
        PrintC::generic_function_name(8, 1, 0x3190)
    );
    println!(
        "case=genericname.high32|out={}",
        PrintC::generic_function_name(8, 1, 0x123456789)
    );

    // ---- emitSymbolScope (printc.cc:233-259) ----
    // The BFD function symbols live in the global scope; the fixture
    // printer's scope stack is empty (curscope null), so
    // getResolutionDepth answers 0 (database.cc:326-332 null branch,
    // count-1 for a global-scope symbol) and nothing prints.
    {
        let mut printer = fresh();
        printer.emit_symbol_scope("main");
        println!("case=emitsymbolscope.main|out=[{}]", drain(printer));
    }
    {
        let mut printer = fresh();
        printer.emit_symbol_scope("GetStr");
        println!("case=emitsymbolscope.getstr|out=[{}]", drain(printer));
    }

    // ---- pushMismatchSymbol (printc.cc:2067-2083) ----
    {
        let printer = fresh();
        println!(
            "case=mismatch.off0|out={}",
            printer.push_mismatch_symbol_text("mismatched", 0, None)
        );
    }
    {
        let printer = fresh();
        // The off!=0 arm: pushUnnamedLocation of the Varnode's own
        // address (ram0x10 in the oracle fixture's data-space varnode).
        let vn = rudra::varnode::Varnode::new(
            1,
            rudra::address::Address::new(0x10),
        );
        println!(
            "case=mismatch.offpos|out={}",
            printer.push_mismatch_symbol_text("mismatched", 4, Some(&vn))
        );
    }

    // ---- pushTypePointerRel (printc.hh:365-370) ----
    {
        let mut printer = fresh();
        printer.rpn_push_type_pointer_rel();
        // The completing operand atoms (base + index), mirroring the
        // oracle fixture's pushAtom/push_integer tail.
        use rudra::printlanguage::{Atom, SyntaxHighlight, TagType};
        printer.rpn_push_atom(&Atom::with_type(
            "base",
            TagType::VarToken,
            SyntaxHighlight::NoColor,
            0,
        ));
        let index_text = printer.integer_text(0, 4, false, display_format::DEFAULT);
        printer.rpn_push_atom(&Atom::with_type(
            &index_text,
            TagType::Syntax,
            SyntaxHighlight::ConstColor,
            0,
        ));
        println!("case=ptrrel.adj|out={}", drain(printer));
    }

    // ---- doEmitWideCharPrefix via pushCharConstant (printc.cc:1504/1606) ----
    {
        let mut printer = fresh();
        printer.push_char_constant_fmt(0x1234, 2, true, display_format::DEFAULT);
        println!("case=widechar.ascii|out={}", drain(printer));
    }
    {
        let mut printer = fresh();
        printer.push_char_constant_fmt(0x0a, 2, true, display_format::DEFAULT);
        println!("case=widechar.escape|out={}", drain(printer));
    }
}
