//! PRINTLANGUAGE-ATOM-METADATA-0001 Rugra comparand.
//!
//! The IDs below are fixture creation-order identities corresponding to the
//! native-pointer normalization performed by the locked C++ oracle.

use rudra::prettyprint::Emit;
use rudra::printlanguage::{
    rpn_push_atom, rpn_push_op, Atom, NodePending, OpToken, ReversePolish, SyntaxHighlight,
    TagType, TokenType,
};

struct RecordingEmit {
    events: Vec<String>,
    next_group: i32,
}

impl Default for RecordingEmit {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            next_group: 0,
        }
    }
}

fn hex_text(text: &str) -> String {
    text.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn color_name(highlight: SyntaxHighlight) -> &'static str {
    match highlight {
        SyntaxHighlight::ConstColor => "const",
        SyntaxHighlight::NoColor => "none",
        _ => panic!("unexpected fixture highlight: {highlight:?}"),
    }
}

fn varnode_id(identity: i64) -> &'static str {
    match identity {
        -1 => "none",
        0 => "obj0",
        _ => panic!("unregistered fixture Varnode identity: {identity}"),
    }
}

fn op_id(identity: i64) -> &'static str {
    match identity {
        -1 => "none",
        1 => "obj1",
        _ => panic!("unregistered fixture PcodeOp identity: {identity}"),
    }
}

impl RecordingEmit {
    fn append(
        &mut self,
        kind: &str,
        text: &str,
        highlight: SyntaxHighlight,
        varnode_identity: i64,
        op_identity: i64,
        group: &str,
    ) {
        self.events.push(format!(
            "event={}|kind={kind}|text_hex={}|highlight={}|vn={}|op={}|group={group}",
            self.events.len(),
            hex_text(text),
            color_name(highlight),
            varnode_id(varnode_identity),
            op_id(op_identity),
        ));
    }
}

impl Emit for RecordingEmit {
    fn print(&mut self, text: &str) {
        self.append("syntax", text, SyntaxHighlight::NoColor, -1, -1, "none");
    }

    fn open_group(&mut self) -> i32 {
        let id = self.next_group;
        self.next_group += 1;
        self.append(
            "open_group",
            "",
            SyntaxHighlight::NoColor,
            -1,
            -1,
            &format!("g{id}"),
        );
        id
    }

    fn close_group(&mut self, id: i32) {
        assert!(
            (0..self.next_group).contains(&id),
            "unknown fixture group id"
        );
        self.append(
            "close_group",
            "",
            SyntaxHighlight::NoColor,
            -1,
            -1,
            &format!("g{id}"),
        );
    }

    fn begin_block(&mut self) {}
    fn end_block(&mut self) {}
    fn begin_function(&mut self) {}
    fn end_function(&mut self) {}
    fn tag_type(&mut self, _text: &str, _id: u64) {}
    fn tag_variable(&mut self, _text: &str, _id: u64) {
        panic!("metadata-aware variable bridge was bypassed");
    }

    fn tag_variable_with_metadata(
        &mut self,
        text: &str,
        highlight: SyntaxHighlight,
        varnode_identity: i64,
        op_identity: i64,
    ) {
        self.append(
            "variable",
            text,
            highlight,
            varnode_identity,
            op_identity,
            "none",
        );
    }

    fn tag_op(&mut self, _text: &str) {}
    fn tag_field(&mut self, _text: &str, _id: u64) {}
    fn tag_func_name(&mut self, _text: &str, _id: u64) {}
    fn tag_comment(&mut self, _text: &str) {}
    fn tag_label(&mut self, _text: &str) {}
    fn tag_case_label(&mut self, _text: &str) {}
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

fn push_hidden_atom(
    revpol: &mut Vec<ReversePolish>,
    nodepend: &mut Vec<NodePending>,
    pending: &mut usize,
    tokens: &[OpToken],
    emit: &mut RecordingEmit,
    atom: &Atom,
    consuming_op_identity: i64,
) {
    rpn_push_op(
        revpol,
        nodepend,
        pending,
        tokens,
        emit,
        0,
        consuming_op_identity,
    );
    rpn_push_atom(revpol, nodepend, pending, tokens, emit, atom);
}

fn main() {
    // A single global creation-order namespace distinguishes the two metadata
    // domains and catches accidental vn/op field interchange.
    const VARNODE_CREATION_ID: i64 = 0;
    const CONSUMING_OP_CREATION_ID: i64 = 1;
    struct IdentityGraph {
        varnode: i64,
        consuming_op: i64,
        consuming_op_input0: i64,
    }
    let graph = IdentityGraph {
        varnode: VARNODE_CREATION_ID,
        consuming_op: CONSUMING_OP_CREATION_ID,
        consuming_op_input0: VARNODE_CREATION_ID,
    };
    assert_ne!(graph.varnode, graph.consuming_op);
    assert_eq!(graph.consuming_op_input0, graph.varnode);

    // Exact counterpart of Ghidra PrintC::hidden at printc.cc:23.  Construct
    // the fixture input explicitly so this projection is independent of
    // convenience-constructor coverage.
    let tokens = vec![OpToken {
        print1: String::new(),
        print2: String::new(),
        stage: 1,
        precedence: 70,
        associative: false,
        type_: TokenType::HiddenFunction,
        spacing: 0,
        bump: 0,
        negate: -1,
    }];
    let atom = Atom::with_op_vn_int(
        "'\\0'",
        TagType::VarToken,
        SyntaxHighlight::ConstColor,
        CONSUMING_OP_CREATION_ID,
        VARNODE_CREATION_ID,
        0,
    );
    let syntax = Atom::new(";", TagType::Syntax, SyntaxHighlight::NoColor);

    let mut revpol = Vec::new();
    let mut nodepend = Vec::new();
    let mut pending = 0;
    let mut emit = RecordingEmit::default();

    push_hidden_atom(
        &mut revpol,
        &mut nodepend,
        &mut pending,
        &tokens,
        &mut emit,
        &atom,
        graph.consuming_op,
    );
    push_hidden_atom(
        &mut revpol,
        &mut nodepend,
        &mut pending,
        &tokens,
        &mut emit,
        &atom,
        graph.consuming_op,
    );
    rpn_push_atom(
        &mut revpol,
        &mut nodepend,
        &mut pending,
        &tokens,
        &mut emit,
        &syntax,
    );

    assert!(
        revpol.is_empty(),
        "fixture must completely drain the RPN stack"
    );
    assert!(nodepend.is_empty(), "fixture does not use pending Varnodes");
    assert_eq!(pending, 0);

    println!(
        "schema=1|fixture=PRINTLANGUAGE-ATOM-METADATA-0001|\
         oracle=e40ed13014025f82488b1f8f7bca566894ac376b|\
         covered_projection=MATCH|overall=MISMATCH"
    );
    for event in emit.events {
        println!("{event}");
    }
}
