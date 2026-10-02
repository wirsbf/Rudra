// COMMENT-WARNING-CODEC-0001: Rugra comparand for the locked Ghidra 12.0.4
// Comment and CommentDatabaseInternal codec/order/dedup/filter oracle.

use std::error::Error;
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::comment::{comment_type, Comment, CommentDatabaseInternal};
use rudra::marshal::{AttributeId, ElementId, Encoder, IdRegistry, TreeDecoder, TreeEncoder};
use rudra::space::{space_flags, AddrSpace, SpaceType};

fn ram_space() -> AddrSpace {
    AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        3,
        space_flags::HASPHYSICAL,
        0,
        0,
    )
}

fn registry() -> Arc<RwLock<IdRegistry>> {
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    {
        let mut ids = registry.write().unwrap();
        for name in ["type", "space", "offset", "XMLcontent"] {
            ids.register_attribute(name);
        }
        for name in ["comment", "commentdb", "addr", "text"] {
            ids.register_element(name);
        }
    }
    registry
}

fn render_function(db: &CommentDatabaseInternal, fad: Address) {
    print!("[");
    for (index, comment) in db.comments_for_function(fad).enumerate() {
        if index != 0 {
            print!(";");
        }
        print!(
            "{}:{}:{}:{}:{}",
            comment.get_type(),
            comment.get_func_addr().as_u64(),
            comment.get_addr().as_u64(),
            comment.get_uniq(),
            comment.get_text()
        );
    }
    print!("]");
}

fn encoded_schema_ok(root: &Arc<RwLock<rudra::marshal::Element>>) -> bool {
    let root = root.read().unwrap();
    let mut saw_1000 = false;
    let mut saw_2000 = false;
    let mut saw_warning_text = false;
    for comment in root.get_children() {
        let comment = comment.read().unwrap();
        for child in comment.get_children() {
            let child = child.read().unwrap();
            if child.get_name() == "addr" && child.get_attribute_value("space") == Some("ram") {
                saw_1000 |= child.get_attribute_value("offset") == Some("4096");
                saw_2000 |= child.get_attribute_value("offset") == Some("8192");
            }
            if child.get_name() == "text"
                && child.get_attribute_value("XMLcontent") == Some("Test warning")
            {
                saw_warning_text = true;
            }
        }
    }
    saw_1000 && saw_2000 && saw_warning_text
}

fn run_roundtrip(ram: &AddrSpace) -> Result<(), Box<dyn Error>> {
    let fad = Address::with_space(ram, 0x1000);
    let mut source = CommentDatabaseInternal::new();
    source.add_comment(comment_type::HEADER, fad, fad, "Header");
    source.add_comment(
        comment_type::WARNING,
        fad,
        Address::with_space(ram, 0x2000),
        "Test warning",
    );
    source.add_comment(
        comment_type::WARNING,
        fad,
        Address::with_space(ram, 0x2000),
        "Second warning",
    );
    let duplicate = source.add_comment_no_duplicate(
        comment_type::USER2,
        fad,
        Address::with_space(ram, 0x2000),
        "Test warning",
    );
    let inserted = source.add_comment_no_duplicate(
        comment_type::USER2,
        fad,
        Address::with_space(ram, 0x2000),
        "User note",
    );

    let ids = registry();
    let mut encoder = TreeEncoder::new(ids.clone());
    source.encode(&mut encoder)?;
    let document = encoder.into_document();
    let root = document.get_root().unwrap().clone();
    let schema_ok = encoded_schema_ok(&root);
    let mut decoder = TreeDecoder::new(root, ids);
    let mut decoded = CommentDatabaseInternal::new();
    decoded.decode(&mut decoder)?;

    print!(
        "case=roundtrip|schema={}|duplicate={}|inserted={}|comments=",
        if schema_ok { 1 } else { 0 },
        if duplicate { 1 } else { 0 },
        if inserted { 1 } else { 0 }
    );
    // The current Decoder trait does not carry an AddrSpaceManager. The
    // decoded projection is therefore the complete ordered offset state.
    render_function(&decoded, Address::new(0x1000));
    println!();
    Ok(())
}

fn run_filter(ram: &AddrSpace) {
    let fad = Address::with_space(ram, 0x1000);
    let other_fad = Address::with_space(ram, 0x5000);
    let mut db = CommentDatabaseInternal::new();
    db.add_comment(comment_type::WARNINGHEADER, fad, fad, "Warning header");
    db.add_comment(comment_type::HEADER, fad, fad, "Header");
    db.add_comment(
        comment_type::WARNING,
        fad,
        Address::with_space(ram, 0x2000),
        "Inline warning",
    );
    db.add_comment(
        comment_type::USER2,
        fad,
        Address::with_space(ram, 0x3000),
        "User note",
    );
    db.add_comment(
        comment_type::WARNING,
        other_fad,
        Address::with_space(ram, 0x6000),
        "Other warning",
    );
    db.clear_type(fad, comment_type::WARNING | comment_type::WARNINGHEADER);

    print!("case=filter|f1000=");
    render_function(&db, fad);
    print!("|f5000=");
    render_function(&db, other_fad);
    println!();
}

fn run_unknown_type_partial() {
    let ids = registry();
    let comment_element = ElementId::new("comment", 0);
    let mut encoder = TreeEncoder::new(ids.clone());
    encoder.open_element(&comment_element);
    encoder.write_string(&AttributeId::new("type", 0), "bogus");
    encoder.close_element(&comment_element);
    let root = encoder.into_document().get_root().unwrap().clone();

    let mut comment = Comment::new(
        comment_type::HEADER,
        Address::new(0xaaaa),
        Address::new(0xbbbb),
        7,
        "sentinel",
    );
    comment.set_emitted(true);
    let mut decoder = TreeDecoder::new(root, ids);
    let error = comment.decode(&mut decoder).unwrap_err().to_string();
    println!(
        "case=unknown_type|error={}|type={}|emitted={}|func={}|addr={}|uniq={}|text={}",
        error,
        comment.get_type(),
        if comment.is_emitted() { 1 } else { 0 },
        comment.get_func_addr().as_u64(),
        comment.get_addr().as_u64(),
        comment.get_uniq(),
        comment.get_text()
    );
}

fn run_missing_offset_partial() {
    let ids = registry();
    let comment_element = ElementId::new("comment", 0);
    let addr_element = ElementId::new("addr", 0);
    let mut encoder = TreeEncoder::new(ids.clone());
    encoder.open_element(&comment_element);
    encoder.write_string(&AttributeId::new("type", 0), "warning");
    encoder.open_element(&addr_element);
    encoder.write_string(&AttributeId::new("space", 0), "ram");
    encoder.close_element(&addr_element);
    encoder.close_element(&comment_element);
    let root = encoder.into_document().get_root().unwrap().clone();

    let mut comment = Comment::new(
        comment_type::HEADER,
        Address::new(0xaaaa),
        Address::new(0xbbbb),
        7,
        "sentinel",
    );
    comment.set_emitted(true);
    let mut decoder = TreeDecoder::new(root, ids);
    let error = comment.decode(&mut decoder).unwrap_err().to_string();
    println!(
        "case=missing_offset|error={}|type={}|emitted={}|func={}|addr={}|uniq={}|text={}",
        error,
        comment.get_type(),
        if comment.is_emitted() { 1 } else { 0 },
        comment.get_func_addr().as_u64(),
        comment.get_addr().as_u64(),
        comment.get_uniq(),
        comment.get_text()
    );
}

fn run_unknown_property_encode(ram: &AddrSpace) {
    let mut comment = Comment::new(
        64,
        Address::with_space(ram, 0xaaaa),
        Address::with_space(ram, 0xbbbb),
        7,
        "sentinel",
    );
    comment.set_emitted(true);
    let mut encoder = TreeEncoder::new(registry());
    let error = comment.encode(&mut encoder).unwrap_err().to_string();
    println!(
        "case=unknown_property_encode|error={}|stream_empty={}|type={}|emitted={}|func={}|addr={}|uniq={}|text={}",
        error,
        if encoder.root().is_none() { 1 } else { 0 },
        comment.get_type(),
        if comment.is_emitted() { 1 } else { 0 },
        comment.get_func_addr().as_u64(),
        comment.get_addr().as_u64(),
        comment.get_uniq(),
        comment.get_text()
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    let ram = ram_space();
    println!(
        "schema=1|fixture=COMMENT-WARNING-CODEC-0001|oracle=\
         e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    run_roundtrip(&ram)?;
    run_filter(&ram);
    run_unknown_type_partial();
    run_missing_offset_partial();
    run_unknown_property_encode(&ram);
    Ok(())
}
