// PRINTC-FORMAT-0001: Rudra comparand for the locked Ghidra 12.0.4
// PrintC::docFunction pure-format oracle (function-header brace layout,
// parameter join spacing, comma spacing, body indent policy).
//
// Mirrors tests/oracle/printc_format_1204.cc case-for-case: each case builds
// the same synthetic Funcdata state (return type, parameter list, optional
// RETURN statement) and drives the production emission sequence that
// docFunction performs (printc.cc:2641-2676): leading tagLine,
// emitFunctionDeclaration, openBraceIndent(OPEN_CURLY, option_brace_func =
// skip_line), local-var decls (none in these cases), emitBlockGraph (flat),
// closeBraceIndent(CLOSE_CURLY), trailing tagLine.

use rudra::address::{Address, SeqNum};
use rudra::block::BlockBasic;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::printc::PrintC;
use rudra::printlanguage::PrintLanguage;
use rudra::prettyprint::{BraceStyle, EmitNoMarkup};
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
use std::sync::{Arc, RwLock};

fn base_type(name: &str, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, metatype)))
}

// Pointer names mirror the TypeFactory spelling the Rust comparand renders
// (`format!("{} *", pointee.get_name())`, typefactory.rs:282): `char *`,
// `char **` (the second level concatenates without an extra space).
fn types_by_name(name: &str) -> Arc<Datatype> {
    match name {
        "char" => base_type("char", 1, TypeMetatype::Int),
        "char*" => Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("char *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: base_type("char", 1, TypeMetatype::Int),
            wordsize: 1,
        })),
        "char**" => Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("char**".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: types_by_name("char*"),
            wordsize: 1,
        })),
        "int" => base_type("int", 4, TypeMetatype::Int),
        "long" => base_type("long", 8, TypeMetatype::Int),
        _ => panic!("unknown fixture type: {name}"),
    }
}

fn render(
    ret: &str,
    params: &[(&str, &str)],
    with_return: bool,
    dotdotdot: bool,
) -> String {
    let mut fd = Funcdata::new("fxn", Address::new(0x1000), 0x20);
    fd.funcp.return_type = if ret == "void" {
        base_type("void", 0, TypeMetatype::Void)
    } else {
        types_by_name(ret)
    };
    for (slot, (pname, ptype)) in params.iter().enumerate() {
        fd.funcp.parameters.push(rudra::fspec::ProtoParameter {
            name: pname.to_string(),
            data_type: types_by_name(ptype),
            address: Address::new(8 * (slot as u64 + 1)),
            flags: 0,
        });
    }
    fd.funcp.is_dotdotdot = dotdotdot;

    if with_return {
        let mut op = PcodeOp::new(SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_RETURN);
        op.set_opcode_flags(OpCode::CPUI_RETURN);
        let op_arc: rudra::op::PcodeOpRef = rudra::op::PcodeOpRef(Arc::new(RwLock::new(op)));
        let mut block = BlockBasic::new(0, Address::new(0x1000));
        block.ops.push(op_arc);
        fd.bblocks.add_block(Arc::new(RwLock::new(block)));
    }

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    // docFunction sequence (printc.cc:2641-2676). Rudra's full doc_function
    // drives the two-pass pipeline with naming/typedef side effects, so the
    // fixture issues the same production emission calls directly.
    // printc.cc:2653 emit->tagLine() — the leading function break.
    printer.get_emit().tag_line(0);
    // printc.cc:2654 emitFunctionDeclaration(fd)
    printer.emit_function_declaration(&fd);
    // printc.cc:2655 openBraceIndent(OPEN_CURLY, option_brace_func)
    // option_brace_func = skip_line (printc.cc:1590)
    printer.get_emit().open_brace_indent("{", BraceStyle::SkipLine);
    // printc.cc:2656 emitLocalVarDecls — no scope symbols in these cases.
    // printc.cc:2657-2660 flat emitBlockGraph over the basic-block graph
    printer.emit_block_graph(&fd.bblocks);
    // printc.cc:2662 closeBraceIndent(CLOSE_CURLY, id)
    printer.get_emit().close_brace_indent("}");
    // printc.cc:2663 emit->tagLine()
    printer.get_emit().tag_line(0);

    let emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("fixture must retain EmitNoMarkup");
    emit.debug_get_output_ref().to_owned()
}

fn to_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn main() {
    let raw = std::env::args().nth(1).as_deref() == Some("--raw");
    let cases: Vec<(&str, &str, Vec<(&str, &str)>, bool, bool)> = vec![
        ("void_empty", "void", vec![], false, false),
        ("void_return_body", "void", vec![], true, false),
        (
            "ptr_int_params",
            "int",
            vec![("pattern", "char*"), ("pos", "int")],
            true,
            false,
        ),
        (
            "int_char2_params",
            "int",
            vec![("argc", "int"), ("argv", "char**")],
            true,
            false,
        ),
        ("dotdotdot_param", "void", vec![("fmt", "char*")], true, true),
        ("base_join_param", "long", vec![("x", "long")], true, false),
    ];

    for (name, ret, params, with_return, dotdotdot) in cases {
        let out = render(ret, &params, with_return, dotdotdot);
        if raw {
            println!("{name}={}", to_hex(&out));
        } else {
            println!("{name}={}", out.len());
        }
    }
}
