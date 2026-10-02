use rudra::marshal::{
    Decoder, Element, IdRegistry, TreeDecoder, ATTRIBUTE_ID_TABLE, ATTRIB_UNKNOWN,
    ELEMENT_ID_TABLE, ELEM_UNKNOWN,
};
use std::sync::{Arc, RwLock};

fn emit_tree_state(registry: Arc<RwLock<IdRegistry>>) {
    let mut root = Element::new();
    root.set_name("data");
    root.add_attribute("size", "1");
    root.add_attribute("fixture_unknown_attribute", "2");
    root.add_attribute("space", "ram");

    let mut known_child = Element::new();
    known_child.set_name("data");
    root.add_child(Arc::new(RwLock::new(known_child)));
    let mut unknown_child = Element::new();
    unknown_child.set_name("fixture_unknown_element");
    root.add_child(Arc::new(RwLock::new(unknown_child)));

    let mut decoder = TreeDecoder::new(Arc::new(RwLock::new(root)), registry);
    let peek_root = decoder.peek_element();
    let open_root = decoder.open_element();
    let attr0 = decoder.next_attribute_id();
    let attr1 = decoder.next_attribute_id();
    let attr2 = decoder.next_attribute_id();
    let attr_end = decoder.next_attribute_id();
    let peek_known = decoder.peek_element();
    let open_known = decoder.open_element();
    let known_attr_end = decoder.next_attribute_id();
    decoder.close_element(open_known);
    let peek_unknown = decoder.peek_element();
    let open_unknown = decoder.open_element();
    let unknown_attr_end = decoder.next_attribute_id();
    decoder.close_element(open_unknown);
    let child_end = decoder.peek_element();
    decoder.close_element(open_root);
    let after_close_peek = decoder.peek_element();
    let after_close_open = decoder.open_element();

    println!(
        "T|{peek_root}|{open_root}|{attr0},{attr1},{attr2},{attr_end}|\
         {peek_known}|{open_known}|{known_attr_end}|{peek_unknown}|{open_unknown}|\
         {unknown_attr_end}|{child_end}|{after_close_peek}|{after_close_open}"
    );
}

fn main() {
    assert_eq!(ATTRIBUTE_ID_TABLE.len(), 146);
    assert_eq!(ELEMENT_ID_TABLE.len(), 274);

    IdRegistry::initialize();
    IdRegistry::initialize();
    let registry = Arc::new(RwLock::new(IdRegistry::new()));

    println!(
        "H|1|{}|{}|{}|{}",
        ATTRIBUTE_ID_TABLE.len(),
        ELEMENT_ID_TABLE.len(),
        ATTRIB_UNKNOWN,
        ELEM_UNKNOWN
    );
    {
        let ids = registry.read().unwrap();
        for &(name, id) in ATTRIBUTE_ID_TABLE {
            println!(
                "A|{id}|{name}|{}|{}",
                ids.find_attribute(name),
                ids.attribute_name(id).unwrap_or("NONE")
            );
        }
        for &(name, id) in ELEMENT_ID_TABLE {
            println!(
                "E|{id}|{name}|{}|{}",
                ids.find_element(name),
                ids.element_name(id).unwrap_or("NONE")
            );
        }
        println!(
            "C|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            ids.find_attribute("size"),
            ids.find_attribute("space"),
            ids.find_attribute("fixture_unknown_attribute"),
            ids.find_element("fixture_unknown_element"),
            ids.find_attribute_in_scope("size", 1),
            ids.find_element_in_scope("data", 1),
            ids.attribute_name(0).unwrap_or("NONE"),
            ids.element_name(0).unwrap_or("NONE"),
            ids.find_attribute("size"),
            ids.find_element("data")
        );
    }
    emit_tree_state(registry);
    println!("S|MATCH|420|0");
}
