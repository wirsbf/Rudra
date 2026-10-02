// COMMENT-SORTER-ITERATORS-0001: Rugra comparand for the locked Ghidra 12.0.4
// CommentSorter shared-iterator oracle (setupBlockList/setupOpList/setupHeader
// + findPosition + setupFunctionList + hasNext/getNext interleaving).
//
// Mirrors tests/oracle/comment_sorter_iterators_1204.cc construction
// step-for-step: same block graph (reverse-post-order indexes from
// find_spanning_tree over the bb_a->bb_b->bb_c->bb_d->bb_e chain), same op
// creation/insertion order (fixing SeqNum::uniq and the BlockBasic::insert
// order ladder), same comment database insertion order, same walk protocol.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, BlockGraph, FlowBlock};
use rudra::comment::{
    comment_type, header_type, CommentDatabaseInternal, CommentSorter,
};
use rudra::space::{space_flags, AddrSpace, SpaceType};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

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

fn drain_walk(sorter: &CommentSorter, case_id: &str, ev: &str) {
    let mut count = 0;
    while sorter.has_next() {
        let comm = sorter.get_next();
        count += 1;
        println!(
            "case={case_id}|ev={ev}|n={count}|type={}|emitted={}|text={}",
            comm.get_type(),
            if comm.is_emitted() { 1 } else { 0 },
            comm.get_text()
        );
    }
    println!("case={case_id}|ev={ev}|drained={count}");
}

fn main() {
    println!("schema=1|fixture=COMMENT-SORTER-ITERATORS-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    let ram = ram_space();
    let addr = |off: u64| Address::with_space(&ram, off);
    let fad = addr(0x1000);
    let mut fd = rudra::funcdata::Funcdata::new("sorter", fad, 0x20);

    let mut graph = BlockGraph::new();
    let mk_block = |graph: &mut BlockGraph, start: u64| -> BlockRef {
        let bb: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, addr(start))));
        graph.add_block(bb.clone());
        bb
    };
    // Install each block's instruction cover the same way the C++ fixture
    // does through Funcdata::setBasicBlockRange (funcdata.hh:556 ->
    // BlockBasic::setInitialRange, block.cc:2625): same ranges, same position
    // in the construction order (blocks -> ranges -> edges -> spanning tree
    // -> ops). A manually built block without a cover is an incomplete state:
    // Ghidra's contains/getStop read only the cover (block.hh:476,
    // block.cc:2328-2335), with no last-op fallback.
    let set_range = |bb: &BlockRef, beg: u64, end: u64| {
        bb.write()
            .unwrap()
            .as_any_mut()
            .downcast_mut::<BlockBasic>()
            .expect("basic block")
            .set_initial_range(addr(beg), addr(end));
    };
    let bb_a = mk_block(&mut graph, 0x1000);
    let bb_b = mk_block(&mut graph, 0x1009);
    let bb_c = mk_block(&mut graph, 0x1012);
    let bb_d = mk_block(&mut graph, 0x2000);
    let bb_e = mk_block(&mut graph, 0x3000);
    set_range(&bb_a, 0x1000, 0x100a);
    set_range(&bb_b, 0x1009, 0x100e);
    set_range(&bb_c, 0x1012, 0x1012);
    set_range(&bb_d, 0x2000, 0x2005);
    set_range(&bb_e, 0x3000, 0x3010);
    graph.add_edge(bb_a.clone(), bb_b.clone());
    graph.add_edge(bb_b.clone(), bb_c.clone());
    graph.add_edge(bb_c.clone(), bb_d.clone());
    graph.add_edge(bb_d.clone(), bb_e.clone());
    let mut preorder = Vec::new();
    let mut rootlist = Vec::new();
    graph.find_spanning_tree(&mut preorder, &mut rootlist).unwrap();
    let idx = |bb: &BlockRef| bb.read().unwrap().get_index();

    let mut new_insert =
        |fd: &mut rudra::funcdata::Funcdata, off: u64, bb: &BlockRef| -> rudra::op::PcodeOpRef {
            let op = fd.new_op(0, addr(off));
            fd.op_insert_end(&op, bb);
            op
        };
    let op_a = new_insert(&mut fd, 0x1000, &bb_a);
    let op_b = new_insert(&mut fd, 0x100a, &bb_a);
    let op_m1 = new_insert(&mut fd, 0x1015, &bb_d);
    let op_m2 = new_insert(&mut fd, 0x1012, &bb_d);
    let op_c = new_insert(&mut fd, 0x2000, &bb_d);
    let op_d = new_insert(&mut fd, 0x2005, &bb_d);
    let op_e = new_insert(&mut fd, 0x3000, &bb_e);
    let op_f = new_insert(&mut fd, 0x3005, &bb_e);
    let op_g = new_insert(&mut fd, 0x3010, &bb_e);
    let op_h = new_insert(&mut fd, 0x1009, &bb_b);
    let _op_i = new_insert(&mut fd, 0x100e, &bb_b);
    let _ = (op_m2, op_h);

    let mut db = CommentDatabaseInternal::new();
    db.add_comment(comment_type::HEADER, fad, fad, "hdr-basic");
    db.add_comment(comment_type::WARNINGHEADER, fad, fad, "warn-hdr");
    db.add_comment(comment_type::WARNING, fad, fad, "inline-entry");
    db.add_comment(comment_type::WARNING, fad, addr(0x1008), "tail-a");
    db.add_comment(comment_type::USER1, fad, addr(0x100a), "at-b");
    db.add_comment(comment_type::USER2, fad, addr(0x1013), "unplaced");
    db.add_comment(comment_type::USER2, fad, addr(0x1015), "migrated");
    db.add_comment(comment_type::WARNING, fad, addr(0x2003), "mid-d");
    db.add_comment(comment_type::HEADER, fad, addr(0x3000), "hdr-away");
    db.add_comment(comment_type::WARNING, fad, addr(0x3002), "between-ef");
    db.add_comment(comment_type::WARNING, fad, addr(0x3005), "at-f");
    db.add_comment(comment_type::WARNING, fad, addr(0x3008), "between-fg");
    db.add_comment(0, fad, addr(0x3000), "zerotype");

    let tp = comment_type::HEADER | comment_type::WARNING | comment_type::WARNINGHEADER;

    let mut sorter1 = CommentSorter::new();
    sorter1.setup_function_list(tp, &fd, &db, true).unwrap();
    sorter1.setup_header(header_type::HEADER_BASIC);
    drain_walk(&sorter1, "placed", "hdr-basic");
    sorter1.setup_header(header_type::HEADER_UNPLACED);
    drain_walk(&sorter1, "placed", "hdr-unplaced");

    sorter1.setup_block_bounds(idx(&bb_a));
    sorter1.setup_op_stop(Some(&op_a));
    drain_walk(&sorter1, "placed", "bbA-atA");
    sorter1.setup_op_stop(Some(&op_b));
    drain_walk(&sorter1, "placed", "bbA-atB");
    sorter1.setup_op_stop(None);
    drain_walk(&sorter1, "placed", "bbA-null");

    sorter1.setup_block_bounds(idx(&bb_d));
    sorter1.setup_op_stop(Some(&op_m1));
    drain_walk(&sorter1, "placed", "bbD-atM1");
    sorter1.setup_op_stop(Some(&op_c));
    drain_walk(&sorter1, "placed", "bbD-atC");
    sorter1.setup_op_stop(Some(&op_d));
    drain_walk(&sorter1, "placed", "bbD-atD");
    sorter1.setup_op_stop(None);
    drain_walk(&sorter1, "placed", "bbD-null");

    sorter1.setup_block_bounds(idx(&bb_e));
    sorter1.setup_op_stop(Some(&op_e));
    drain_walk(&sorter1, "placed", "bbE-atE");
    sorter1.setup_op_stop(Some(&op_f));
    drain_walk(&sorter1, "placed", "bbE-atF");
    sorter1.setup_op_stop(Some(&op_g));
    drain_walk(&sorter1, "placed", "bbE-atG");
    sorter1.setup_op_stop(None);
    drain_walk(&sorter1, "placed", "bbE-null");

    sorter1.setup_block_bounds(idx(&bb_c));
    sorter1.setup_op_stop(None);
    drain_walk(&sorter1, "placed", "bbC-null");

    let mut sorter2 = CommentSorter::new();
    sorter2.setup_function_list(tp, &fd, &db, false).unwrap();
    sorter2.setup_header(header_type::HEADER_BASIC);
    drain_walk(&sorter2, "nounsplaced", "hdr-basic");
    sorter2.setup_header(header_type::HEADER_UNPLACED);
    drain_walk(&sorter2, "nounsplaced", "hdr-unplaced");
    sorter2.setup_block_bounds(idx(&bb_a));
    sorter2.setup_op_stop(None);
    drain_walk(&sorter2, "nounsplaced", "bbA-null");

    // Dead op: created (in the optree) but never inserted into a block.
    {
        let mut fd2 = rudra::funcdata::Funcdata::new("dead", addr(0x4000), 0x10);
        let _dead = fd2.new_op(0, addr(0x6000));
        let mut db2 = CommentDatabaseInternal::new();
        db2.add_comment(comment_type::WARNING, addr(0x4000), addr(0x6000), "doomed");
        let mut sorter3 = CommentSorter::new();
        let error = sorter3
            .setup_function_list(0xffff, &fd2, &db2, true)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        println!("case=deadop|error={error}");
    }

    // Op-less function: every placeable comment lands at block 0 order 0.
    {
        let fd_addr3 = addr(0x5000);
        let mut fd3 = rudra::funcdata::Funcdata::new("noops", fd_addr3, 0x10);
        let mut graph3 = BlockGraph::new();
        let bb_f: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, addr(0x5000))));
        graph3.add_block(bb_f.clone());
        // Degenerate cover [0x5000, 0x5000], matching the C++ fixture's
        // fd3.setBasicBlockRange(bb_f, 0x5000, 0x5000).
        bb_f.write()
            .unwrap()
            .as_any_mut()
            .downcast_mut::<BlockBasic>()
            .expect("basic block")
            .set_initial_range(addr(0x5000), addr(0x5000));
        let mut db3 = CommentDatabaseInternal::new();
        db3.add_comment(comment_type::WARNING, addr(0x5000), addr(0x5500), "noops-walk");
        let mut sorter4 = CommentSorter::new();
        sorter4.setup_function_list(tp, &fd3, &db3, false).unwrap();
        sorter4.setup_block_bounds(idx(&bb_f));
        sorter4.setup_op_stop(None);
        drain_walk(&sorter4, "noops", "bbF-null");
    }
}
