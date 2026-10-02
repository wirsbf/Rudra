// PRINTC-STRUCTURED-IF-CONDITION-0001: covered projection for the locked
// Ghidra 12.0.4 PrintC structured-condition dispatch protocol.
//
// The fixture intentionally drives the public PrintC::emit_block_graph entry
// with real BlockBasic, BlockIf, BlockCondition, and BlockList objects.  It
// observes two dispatches of the same object graph, comment consumption,
// object-state preservation, and a post/fresh modifier-restoration probe.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{
    goto_type, BlockBasic, BlockCondition, BlockGraph, BlockIf, BlockList,
    BlockType, BoolOp, FlowBlock,
};
use rudra::comment::CommentDatabaseInternal;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::printlanguage::PrintLanguage;
use rudra::space::{space_flags, AddrSpace, AddressSpace, SpaceType};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

const ORACLE_COMMIT: &str = "e40ed13014025f82488b1f8f7bca566894ac376b";

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

fn fixture_arch() -> Arc<Architecture> {
    let mut arch = Architecture::new();
    arch.set_commentdb(Arc::new(RwLock::new(CommentDatabaseInternal::new())));
    Arc::new(arch)
}

fn as_block<T>(value: T) -> BlockRef
where
    T: FlowBlock + Send + Sync + 'static,
{
    Arc::new(RwLock::new(value))
}

fn make_basic(index: i32, start: u64) -> BlockRef {
    let ram = ram_space();
    let start_addr = Address::with_space(&ram, start);
    let mut basic = BlockBasic::new(index, start_addr);
    basic.set_initial_range(start_addr, Address::with_space(&ram, start + 0x1f));
    as_block(basic)
}

fn make_if(index: i32, condition: BlockRef, body: BlockRef) -> BlockRef {
    as_block(BlockIf {
        index,
        condition,
        if_body: body,
        else_body: None,
        negated: false,
        goto_target: None,
        goto_type: goto_type::GOTO_GOTO,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    })
}

fn make_condition(index: i32, op_type: BoolOp, first: BlockRef, second: BlockRef) -> BlockRef {
    as_block(BlockCondition {
        index,
        op_type,
        first,
        second,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    })
}

fn make_list(index: i32, children: Vec<BlockRef>) -> BlockRef {
    as_block(BlockList::new(index, children))
}

fn graph_with_root(root: BlockRef) -> BlockGraph {
    let mut graph = BlockGraph::new();
    graph.add_block(root);
    graph
}

fn add_call(fd: &mut Funcdata, block: &BlockRef, off: u64, target: u64) -> PcodeOpRef {
    let ram = ram_space();
    let op = fd.new_op(1, Address::with_space(&ram, off));
    fd.op_set_opcode(&op, OpCode::CPUI_CALL);
    let target_vn = fd.new_code_ref(Address::with_space(&ram, target));
    fd.op_set_input(&op, target_vn, 0);
    fd.op_insert_end(&op, block);
    op
}

fn add_store(
    fd: &mut Funcdata,
    block: &BlockRef,
    off: u64,
    pointer: u64,
    value: u64,
) -> PcodeOpRef {
    let ram = ram_space();
    let op = fd.new_op(3, Address::with_space(&ram, off));
    fd.op_set_opcode(&op, OpCode::CPUI_STORE);
    let space_vn = fd.new_varnode_space(AddressSpace::Ram);
    let pointer_vn = fd.new_constant(8, pointer);
    let value_vn = fd.new_constant(8, value);
    fd.op_set_input(&op, space_vn, 0);
    fd.op_set_input(&op, pointer_vn, 1);
    fd.op_set_input(&op, value_vn, 2);
    fd.op_insert_end(&op, block);
    op
}

fn add_cbranch(
    fd: &mut Funcdata,
    block: &BlockRef,
    off: u64,
    target: u64,
    condition: u64,
) -> PcodeOpRef {
    let ram = ram_space();
    let op = fd.new_op(2, Address::with_space(&ram, off));
    fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
    let target_vn = fd.new_code_ref(Address::with_space(&ram, target));
    let condition_vn = fd.new_constant(1, condition);
    fd.op_set_input(&op, target_vn, 0);
    fd.op_set_input(&op, condition_vn, 1);
    fd.op_insert_end(&op, block);
    op
}

fn add_warning(fd: &Funcdata, op: &PcodeOpRef, text: &str) {
    let addr = op.0.read().unwrap().get_addr();
    fd.warning(text, addr);
}

struct CaseFixture {
    id: &'static str,
    fd: Funcdata,
    root: BlockRef,
    graph: BlockGraph,
    sentinel: BlockRef,
    sentinel_graph: BlockGraph,
    comment_markers: Vec<&'static str>,
}

fn new_fd(name: &str, entry: u64) -> Funcdata {
    let ram = ram_space();
    let mut fd = Funcdata::new(name, Address::with_space(&ram, entry), 0x200);
    fd.set_arch(fixture_arch());
    fd
}

fn make_sentinel(fd: &mut Funcdata, base: u64, index: i32) -> BlockRef {
    let block = make_basic(index, base);
    add_call(fd, &block, base, 0xd00d);
    add_cbranch(fd, &block, base + 4, base + 0x40, 1);
    block
}

fn case_basic_condition() -> CaseFixture {
    let mut fd = new_fd("basic_condition", 0x1000);
    let cond = make_basic(10, 0x1000);
    add_call(&mut fd, &cond, 0x1000, 0x1001);
    add_cbranch(&mut fd, &cond, 0x1004, 0x1080, 1);
    let body = make_basic(11, 0x1010);
    add_store(&mut fd, &body, 0x1010, 0x5010, 0x61);
    add_cbranch(&mut fd, &body, 0x1014, 0x1090, 0);
    let root = make_if(12, cond, body);
    let graph = graph_with_root(root.clone());
    let sentinel = make_sentinel(&mut fd, 0x10c0, 19);
    let sentinel_graph = graph_with_root(sentinel.clone());
    CaseFixture {
        id: "basic_condition",
        fd,
        root,
        graph,
        sentinel,
        sentinel_graph,
        comment_markers: Vec::new(),
    }
}

fn case_direct_blockif_condition() -> CaseFixture {
    let mut fd = new_fd("direct_blockif_condition", 0x2000);
    let inner_cond = make_basic(20, 0x2000);
    add_call(&mut fd, &inner_cond, 0x2000, 0x2001);
    add_cbranch(&mut fd, &inner_cond, 0x2004, 0x2080, 1);
    let inner_body = make_basic(21, 0x2010);
    add_call(&mut fd, &inner_body, 0x2010, 0x2002);
    add_store(&mut fd, &inner_body, 0x2014, 0x5020, 0x62);
    add_cbranch(&mut fd, &inner_body, 0x2018, 0x2090, 0);
    let inner_if = make_if(22, inner_cond, inner_body);
    let outer_body = make_basic(23, 0x2020);
    add_store(&mut fd, &outer_body, 0x2020, 0x5030, 0x63);
    add_cbranch(&mut fd, &outer_body, 0x2024, 0x20a0, 1);
    let root = make_if(24, inner_if, outer_body);
    let graph = graph_with_root(root.clone());
    let sentinel = make_sentinel(&mut fd, 0x20c0, 29);
    let sentinel_graph = graph_with_root(sentinel.clone());
    CaseFixture {
        id: "direct_blockif_condition",
        fd,
        root,
        graph,
        sentinel,
        sentinel_graph,
        comment_markers: Vec::new(),
    }
}

fn case_block_condition() -> CaseFixture {
    let mut fd = new_fd("block_condition", 0x3000);
    let first = make_basic(30, 0x3000);
    add_call(&mut fd, &first, 0x3000, 0x3001);
    add_cbranch(&mut fd, &first, 0x3004, 0x3080, 1);
    let second = make_basic(31, 0x3010);
    add_call(&mut fd, &second, 0x3010, 0x3002);
    add_cbranch(&mut fd, &second, 0x3014, 0x3090, 0);
    let condition = make_condition(32, BoolOp::And, first, second);
    let body = make_basic(33, 0x3020);
    add_store(&mut fd, &body, 0x3020, 0x5040, 0x64);
    add_cbranch(&mut fd, &body, 0x3024, 0x30a0, 1);
    let root = make_if(34, condition, body);
    let graph = graph_with_root(root.clone());
    let sentinel = make_sentinel(&mut fd, 0x30c0, 39);
    let sentinel_graph = graph_with_root(sentinel.clone());
    CaseFixture {
        id: "block_condition",
        fd,
        root,
        graph,
        sentinel,
        sentinel_graph,
        comment_markers: Vec::new(),
    }
}

fn case_getstr_list_shape() -> CaseFixture {
    let mut fd = new_fd("getstr_list_shape", 0x4000);
    let a = make_basic(40, 0x4000);
    add_cbranch(&mut fd, &a, 0x4000, 0x4080, 1);

    let inner_body = make_basic(41, 0x4010);
    let free_call = add_call(&mut fd, &inner_body, 0x4010, 0x4001);
    add_store(&mut fd, &inner_body, 0x4014, 0x5050, 0x65);
    add_cbranch(&mut fd, &inner_body, 0x4018, 0x4090, 0);
    let inner_if = make_if(42, a, inner_body);

    let b = make_basic(43, 0x4020);
    add_cbranch(&mut fd, &b, 0x4020, 0x40a0, 1);
    let c = make_basic(44, 0x4030);
    let c_branch = add_cbranch(&mut fd, &c, 0x4030, 0x40b0, 0);
    let bc = make_condition(45, BoolOp::And, b, c);
    let list = make_list(46, vec![inner_if, bc]);

    let outer_body = make_basic(47, 0x4040);
    add_call(&mut fd, &outer_body, 0x4040, 0x4002);
    let outer_store = add_store(&mut fd, &outer_body, 0x4044, 0x5060, 0x66);
    add_cbranch(&mut fd, &outer_body, 0x4048, 0x40c0, 1);
    let root = make_if(48, list, outer_body);
    let graph = graph_with_root(root.clone());
    let sentinel = make_sentinel(&mut fd, 0x40e0, 49);
    let sentinel_graph = graph_with_root(sentinel.clone());

    add_warning(&fd, &free_call, "INNER_FREE");
    add_warning(&fd, &c_branch, "COND_SECOND");
    add_warning(&fd, &outer_store, "OUTER_STORE");

    CaseFixture {
        id: "getstr_list_shape",
        fd,
        root,
        graph,
        sentinel,
        sentinel_graph,
        comment_markers: vec!["INNER_FREE", "COND_SECOND", "OUTER_STORE"],
    }
}

fn block_type_name(block_type: BlockType) -> &'static str {
    match block_type {
        BlockType::Basic => "Basic",
        BlockType::If => "If",
        BlockType::Condition => "Condition",
        BlockType::List => "List",
        _ => "Other",
    }
}

fn opcode_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_CALL => "CALL",
        OpCode::CPUI_STORE => "STORE",
        OpCode::CPUI_CBRANCH => "CBRANCH",
        _ => "OTHER",
    }
}

fn child_blocks(block: &BlockRef) -> Vec<BlockRef> {
    let guard = block.read().unwrap();
    let any = guard.as_any();
    if let Some(value) = any.downcast_ref::<BlockIf>() {
        let mut result = vec![value.condition.clone(), value.if_body.clone()];
        if let Some(else_body) = &value.else_body {
            result.push(else_body.clone());
        }
        result
    } else if let Some(value) = any.downcast_ref::<BlockCondition>() {
        vec![value.first.clone(), value.second.clone()]
    } else if let Some(value) = any.downcast_ref::<BlockList>() {
        value.children.clone()
    } else {
        Vec::new()
    }
}

fn collect_nodes(block: &BlockRef, ids: &mut HashMap<usize, usize>, order: &mut Vec<BlockRef>) {
    let key = Arc::as_ptr(block) as *const () as usize;
    if ids.contains_key(&key) {
        return;
    }
    let id = order.len();
    ids.insert(key, id);
    order.push(block.clone());
    for child in child_blocks(block) {
        collect_nodes(&child, ids, order);
    }
}

fn tree_snapshot(root: &BlockRef) -> String {
    let mut ids = HashMap::new();
    let mut order = Vec::new();
    collect_nodes(root, &mut ids, &mut order);
    let mut result = String::new();
    for (ordinal, block) in order.iter().enumerate() {
        if ordinal != 0 {
            result.push(';');
        }
        let guard = block.read().unwrap();
        let children = child_blocks(block)
            .iter()
            .map(|child| {
                let key = Arc::as_ptr(child) as *const () as usize;
                ids[&key].to_string()
            })
            .collect::<Vec<_>>()
            .join(",");
        let ops = if guard.get_type() == BlockType::Basic {
            guard
                .get_ops()
                .iter()
                .enumerate()
                .map(|(op_ordinal, op_ref)| {
                    let op = op_ref.0.read().unwrap();
                    format!(
                        "{}@{:x}/{}",
                        opcode_name(op.opcode),
                        op.get_addr().as_u64(),
                        op_ordinal
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        } else {
            String::new()
        };
        let mut edges = Vec::new();
        for slot in 0..guard.size_out() {
            if let Some(edge) = guard.get_out(slot) {
                let key = Arc::as_ptr(&edge.point) as *const () as usize;
                let peer = ids.get(&key).map_or_else(|| "x".to_string(), usize::to_string);
                edges.push(format!("{}>{}/{}/{}", slot, peer, edge.reverse_index, edge.flags));
            }
        }
        write!(
            result,
            "{}:{}:{}:f{:x}:in{}:out{}:ch[{}]:op[{}]:ed[{}]",
            ordinal,
            block_type_name(guard.get_type()),
            guard.get_index(),
            guard.get_flags(),
            guard.size_in(),
            guard.size_out(),
            children,
            ops,
            edges.join(",")
        )
        .unwrap();
    }
    result
}

fn raw_output(printer: &mut PrintC) -> String {
    printer
        .get_emit()
        .as_any_mut()
        .and_then(|any| any.downcast_mut::<EmitNoMarkup>())
        .expect("fixture PrintC must retain EmitNoMarkup")
        .debug_get_output_ref()
        .to_string()
}

fn render_fresh(graph: &BlockGraph, fd: Option<&Funcdata>) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    if let Some(function) = fd {
        printer.setup_function_comments(function);
    }
    printer.emit_block_graph(graph);
    raw_output(&mut printer)
}

fn hex_bytes(value: &str) -> String {
    let mut result = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

fn event_trace(raw: &str, comments: &[&str]) -> String {
    let mut events: Vec<(usize, usize, String)> = Vec::new();
    let mut add_all = |needle: &str, priority: usize, label: String| {
        let mut offset = 0;
        while let Some(relative) = raw[offset..].find(needle) {
            let position = offset + relative;
            events.push((position, priority, label.clone()));
            offset = position + needle.len();
        }
    };
    for marker in comments {
        add_all(
            &format!("/* WARNING: {marker} */"),
            0,
            format!("COMMENT_{marker}"),
        );
    }
    for target in [
        0x1001_u64, 0x2001, 0x2002, 0x3001, 0x3002, 0x4001, 0x4002, 0xd00d,
    ] {
        add_all(&format!("FUN_{target:x}"), 1, format!("CALL_{target:x}"));
    }
    add_all(" = ", 2, "STORE".to_string());
    add_all("if (", 3, "IF".to_string());
    add_all(" && ", 4, "AND".to_string());
    add_all(" || ", 5, "OR".to_string());
    add_all("goto ", 6, "GOTO".to_string());
    events.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
    events
        .into_iter()
        .map(|(_, _, label)| label)
        .collect::<Vec<_>>()
        .join(",")
}

fn comment_observation(raw: &str, comments: &[&str]) -> String {
    comments
        .iter()
        .map(|marker| {
            let needle = format!("/* WARNING: {marker} */");
            format!("{marker}:{}", raw.matches(&needle).count())
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn report_case(fixture: CaseFixture) {
    let tree_before = tree_snapshot(&fixture.root);
    let sentinel_before = tree_snapshot(&fixture.sentinel);

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.setup_function_comments(&fixture.fd);
    printer.emit_block_graph(&fixture.graph);
    let after_first = raw_output(&mut printer);
    let first_len = after_first.len();

    printer.emit_block_graph(&fixture.graph);
    let after_second = raw_output(&mut printer);
    let pass1 = &after_second[..first_len];
    let pass2 = &after_second[first_len..];
    let second_len = after_second.len();

    printer.emit_block_graph(&fixture.sentinel_graph);
    let after_post = raw_output(&mut printer);
    let post = &after_post[second_len..];

    let fresh_post = render_fresh(&fixture.sentinel_graph, None);
    let fresh_root = render_fresh(&fixture.graph, Some(&fixture.fd));
    let tree_after = tree_snapshot(&fixture.root);
    let sentinel_after = tree_snapshot(&fixture.sentinel);

    let comments_first = comment_observation(pass1, &fixture.comment_markers);
    let comments_second = comment_observation(pass2, &fixture.comment_markers);
    let comments_fresh = comment_observation(&fresh_root, &fixture.comment_markers);
    println!(
        "case={}|tree_before_hex={}|tree_after_hex={}|tree_equal={}|sentinel_equal={}|pass1_hex={}|pass2_hex={}|fresh_root_hex={}|post_hex={}|fresh_post_hex={}|post_fresh_equal={}|events1={}|events2={}|events_fresh={}|comments={}>{}>{}",
        fixture.id,
        hex_bytes(&tree_before),
        hex_bytes(&tree_after),
        u8::from(tree_before == tree_after),
        u8::from(sentinel_before == sentinel_after),
        hex_bytes(pass1),
        hex_bytes(pass2),
        hex_bytes(&fresh_root),
        hex_bytes(post),
        hex_bytes(&fresh_post),
        u8::from(post == fresh_post),
        event_trace(pass1, &fixture.comment_markers),
        event_trace(pass2, &fixture.comment_markers),
        event_trace(&fresh_root, &fixture.comment_markers),
        comments_first,
        comments_second,
        comments_fresh,
    );
}

fn main() {
    println!(
        "schema=1|fixture=PRINTC-STRUCTURED-IF-CONDITION-0001|oracle={ORACLE_COMMIT}|overall=MISMATCH|covered_projection=MATCH"
    );
    let mut seen = HashSet::new();
    for fixture in [
        case_basic_condition(),
        case_direct_blockif_condition(),
        case_block_condition(),
        case_getstr_list_shape(),
    ] {
        assert!(seen.insert(fixture.id));
        report_case(fixture);
    }
}
