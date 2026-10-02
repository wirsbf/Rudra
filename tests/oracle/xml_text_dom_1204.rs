//! XML text ingestion oracle fixture (MARSHAL-XML-TEXT-0001).
//!
//! Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//! Mirrors `xml_text_dom_1204.cc` record for record: parse the same XML byte
//! inputs through `rudra::marshal::{xml_tree, DocumentStorage}` and print the
//! same canonical DOM / DocumentStorage / error projection. The runner diffs
//! both outputs byte for byte.

use rudra::marshal::{xml_tree, DocumentStorage};
use std::io::Write;
use std::sync::{Arc, RwLock};

use rudra::marshal::Element;

fn dump_element(out: &mut dyn Write, el: &Arc<RwLock<Element>>, depth: usize) {
    let el = el.read().unwrap();
    let _ = writeln!(
        out,
        "E|{}|{}|{}|{}|{}",
        depth,
        el.get_name(),
        el.get_content(),
        el.get_num_attributes(),
        el.get_children().len()
    );
    for i in 0..el.get_num_attributes() {
        let _ = writeln!(
            out,
            "A|{}|{}|{}={}",
            depth,
            i,
            el.get_attribute_name(i),
            el.get_attribute_value_at(i)
        );
    }
    for child in el.get_children() {
        dump_element(out, child, depth + 1);
    }
}

fn try_parse(label: &str, text: &[u8]) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    match xml_tree(text) {
        Ok(doc) => {
            let _ = writeln!(lock, "P|{}|OK", label);
            let mut buf = Vec::new();
            if let Some(root) = doc.get_root() {
                dump_element(&mut buf, root, 0);
            }
            let _ = lock.write_all(&buf);
            let _ = lock.flush();
        }
        Err(e) => {
            let _ = writeln!(lock, "P|{}|ERR|{}", label, e.explain);
            let _ = lock.flush();
        }
    }
}

fn main() {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // -- successful parses: tree shape, ordered attributes, content rules --
    try_parse(
                "basic_tree",
        b"<compiler_spec><stackpointer register=\"rsp\" space=\"ram\" growth=\"down\"/></compiler_spec>",
    );
    try_parse("content_ws_only", b"<data>  \n\t  </data>");
    try_parse("content_split", b"<data>keep <b/> this</data>");
    try_parse("cdata_ws_only", b"<data><![CDATA[   ]]></data>");
    try_parse("cdata_markup", b"<d><![CDATA[x<y & z]]></d>");
    try_parse("cdata_split", b"<d>a<![CDATA[b]]>c</d>");
    try_parse(
                "entity_attr_content",
        b"<r a=\"&lt;&amp;&quot;\">&#65;&#x42;&amp;</r>",
    );
    try_parse("single_quote", b"<r a='it&quot;s'/>");
    try_parse("dup_attr", b"<r a=\"1\" a=\"2\"/>");
    try_parse("empty_attr", b"<r a=\"\"/>");
    try_parse("attr_ws_eq", b"<r a = \"1\" />");
    try_parse("etag_ws", b"<r>x</r >");
    try_parse("etag_nl", b"<r>x</r\n>");
    try_parse("mismatch_etag", b"<r>x</q>");
    try_parse("prolog_comment", b"<!--c--><a/>");
    try_parse("prolog_multi_misc", b"<!--a--> <!--b-->\n<a/>");
    try_parse(
                "xmldecl_full",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><r/>",
    );
    try_parse("xmldecl_sp", b"<?xml version = \"1.0\" ?><r/>");
    try_parse(
                "xmldecl_comment",
        b"<?xml version=\"1.0\"?><!--c--><a/>",
    );
    try_parse("inner_comment", b"<a> <!-- i --> <c/></a>");
    try_parse("empty_comment", b"<a><!----></a>");
    try_parse("deep", b"<a><b><c>t</c></b></a>");
    try_parse("trailing_ws", b"<a/>  ");
    try_parse("charref_attr", b"<r a=\"&#65;&#x42;\"/>");
    try_parse("amp_ref_attr", b"<r a=\"a&amp;b\"/>");
    try_parse("raw_cdata_end_text", b"<r>]]&gt;</r>");

    // -- parse failures with exact error messages --
    try_parse("trailing_comment", b"<r/><!--c-->");
    try_parse("trailing_two_comments", b"<r/><!--c--><!--d-->");
    try_parse("nested_mismatch", b"<r><b></r>");
    try_parse("unclosed", b"<r>");
    try_parse("unclosed_content", b"<a>x");
    try_parse("pi_first", b"<?php ?>");
    try_parse("pi_after_comment", b"<!--c--><?php ?>");
    try_parse("pi_in_content", b"<r><?php ?></r>");
    try_parse("dtd_first", b"<!DOCTYPE x>");
    try_parse("dtd_after_comment", b"<!--c--><!DOCTYPE x>");
    try_parse("dtd_after_ws", b" <!DOCTYPE x>");
    try_parse(
                "dtd_after_xmldecl",
        b"<?xml version=\"1.0\"?><!DOCTYPE x>",
    );
    try_parse("two_roots", b"<r/><r/>");
    try_parse("empty_input", b"");
    try_parse("missing_gt_stag", b"<r <s/>");
    try_parse("lt_in_attr", b"<r a=\"<\"/>");
    try_parse("comment_dashdash", b"<a><!-- x -- y --></a>");
    try_parse("charref_hex_upper", b"<r>&#x41;&#X42;</r>");
    try_parse("charref_nodigits", b"<r>&#;</r>");

    // -- DocumentStorage: register/getTag, same-name overwrite, null-slot --
    let mut store = DocumentStorage::new();
    let d1 = store
        .parse_document(b"<colors><red/></colors>")
        .expect("colors parse");
    let red1 = d1.get_root().expect("colors root").read().unwrap().children[0].clone();
    store.register_tag(&red1);
    let _ = writeln!(out, "T|getTag_red|{}", store.get_tag("red").is_some() as u8);
    let _ = writeln!(out, "T|getTag_blue|{}", store.get_tag("blue").is_some() as u8);
    let d2 = store
        .parse_document(b"<other><red x=\"1\"/></other>")
        .expect("other parse");
    let red2 = d2.get_root().expect("other root").read().unwrap().children[0].clone();
    store.register_tag(&red2);
    let _ = writeln!(
        out,
        "T|overwrite|{}",
        store
            .get_tag("red")
            .and_then(|el| el.read().unwrap().get_attribute_value("x").map(str::to_string))
            .expect("overwritten red registered")
    );
    match store.parse_document(b"<broken>") {
        Ok(_) => {
            let _ = writeln!(out, "X|broken|UNEXPECTED_OK");
        }
        Err(e) => {
            let _ = writeln!(out, "X|broken|{}", e.explain);
        }
    }
    // State-parity invariant: the failed parse leaves a null slot behind.
    assert_eq!(store.doclist_len(), 3);
    let d4 = store.parse_document(b"<ok/>").expect("storage usable");
    let _ = writeln!(
        out,
        "X|afterfail|{}",
        d4.get_root().expect("ok root").read().unwrap().get_name()
    );
    match store.open_document("/nonexistent/xml/text/dom/fixture.xml") {
        Ok(_) => {
            let _ = writeln!(out, "X|openfail|UNEXPECTED_OK");
        }
        Err(e) => {
            let _ = writeln!(out, "X|openfail|{}", e.explain);
        }
    }
    let _ = writeln!(out, "S|DONE");
}
