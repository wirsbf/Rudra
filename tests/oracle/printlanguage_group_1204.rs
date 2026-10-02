use rudra::prettyprint::EmitNoMarkup;
use rudra::printlanguage::{
    rpn_push_atom, rpn_push_op, Atom, NodePending, OpToken, ReversePolish,
    SyntaxHighlight, TagType,
};

fn atom(name: &str) -> Atom {
    Atom::new(name, TagType::Syntax, SyntaxHighlight::VarColor)
}

fn render(callback: impl FnOnce(
    &mut Vec<ReversePolish>,
    &mut Vec<NodePending>,
    &mut usize,
    &[OpToken],
    &mut EmitNoMarkup,
)) -> String {
    let tokens = vec![
        OpToken::unary_prefix("!", 62, 0, 0),
        OpToken::binary("+", 50, true, 1, 0, -1),
        OpToken::binary("*", 54, true, 1, 0, -1),
    ];
    let mut revpol = Vec::new();
    let mut nodepend = Vec::new();
    let mut pending = 0;
    let mut emit = EmitNoMarkup::new();
    callback(
        &mut revpol,
        &mut nodepend,
        &mut pending,
        &tokens,
        &mut emit,
    );
    assert!(revpol.is_empty(), "fixture must completely drain the RPN stack");
    emit.get_output()
}

fn main() {
    let root_unary = render(|revpol, nodepend, pending, tokens, emit| {
        rpn_push_op(revpol, nodepend, pending, tokens, emit, 0, -1);
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("x"));
    });
    println!("root_unary={root_unary}");

    let root_binary = render(|revpol, nodepend, pending, tokens, emit| {
        rpn_push_op(revpol, nodepend, pending, tokens, emit, 1, -1);
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("a"));
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("b"));
    });
    println!("root_binary={root_binary}");

    let nested_invisible = render(|revpol, nodepend, pending, tokens, emit| {
        rpn_push_op(revpol, nodepend, pending, tokens, emit, 1, -1);
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("a"));
        rpn_push_op(revpol, nodepend, pending, tokens, emit, 2, -1);
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("b"));
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("c"));
    });
    println!("nested_invisible={nested_invisible}");

    let nested_parenthesized = render(|revpol, nodepend, pending, tokens, emit| {
        rpn_push_op(revpol, nodepend, pending, tokens, emit, 2, -1);
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("a"));
        rpn_push_op(revpol, nodepend, pending, tokens, emit, 1, -1);
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("b"));
        rpn_push_atom(revpol, nodepend, pending, tokens, emit, &atom("c"));
    });
    println!("nested_parenthesized={nested_parenthesized}");
}
