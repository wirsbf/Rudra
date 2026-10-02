// BLOCKSTRUCT-ORDERBLOCKS-0001: Rugra comparand for the locked Ghidra
// 12.0.4 BlockGraph::orderBlocks (block.hh:430-431) /
// FlowBlock::compareFinalOrder (block.cc:709-730) oracle. Mirrors
// tests/oracle/blockstruct_orderblocks_1204.cc case for case: the same
// synthetic top-level lists (hand-assigned indices, lastOp arms null /
// RETURN / non-RETURN, real BlockGoto and BlockMultiGoto wrappers) run
// through the production BlockGraph::order_blocks and print the post-sort
// list in the shared observation format.

use std::sync::{Arc, RwLock};

use rudra::address::{Address, SeqNum};
use rudra::block::{
    BlockBasic, BlockGoto, BlockGraph, BlockMultiGoto, FlowBlock,
};
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

// FlowBlock::typeToName (block.cc:671-703).
fn type_name(bt: rudra::block::BlockType) -> &'static str {
    match bt {
        rudra::block::BlockType::Plain => "plain",
        rudra::block::BlockType::Basic => "basic",
        rudra::block::BlockType::Graph => "graph",
        rudra::block::BlockType::Copy => "copy",
        rudra::block::BlockType::Goto => "goto",
        rudra::block::BlockType::MultiGoto => "multigoto",
        rudra::block::BlockType::List => "list",
        rudra::block::BlockType::Condition => "condition",
        rudra::block::BlockType::If => "properif",
        rudra::block::BlockType::WhileDo => "whiledo",
        rudra::block::BlockType::DoWhile => "dowhile",
        rudra::block::BlockType::Switch => "switch",
        rudra::block::BlockType::InfLoop => "infloop",
    }
}

fn make_op(opc: OpCode) -> PcodeOpRef {
    PcodeOpRef(Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x1000), 1),
        opc,
    ))))
}

struct Fixture {
    graph: BlockGraph,
    created: Vec<BlockRef>,
}

impl Fixture {
    fn new() -> Self {
        Fixture { graph: BlockGraph::new(), created: Vec::new() }
    }

    /// Plain BlockBasic vertex with a hand-assigned index and lastOp arm:
    /// None = null lastOp (loop/switch/base arm), Some(RETURN) /
    /// Some(other) = the block's own last op (BlockBasic::lastOp,
    /// block.cc:2344 — ops.last()).
    fn make(&mut self, idx: i32, opc: Option<OpCode>) -> BlockRef {
        let bl: BlockRef =
            Arc::new(RwLock::new(BlockBasic::new(idx, Address::new(0x1000))));
        if let Some(o) = opc {
            bl.write().unwrap().add_op(make_op(o));
        }
        self.graph.add_block(bl.clone());
        self.created.push(bl.clone());
        bl
    }

    fn name_of(&self, bl: &BlockRef) -> String {
        for (i, cand) in self.created.iter().enumerate() {
            if Arc::ptr_eq(cand, bl) {
                return format!("b{}", i);
            }
        }
        "b?".to_string()
    }

    fn run(&mut self, case_name: &str) {
        self.graph.order_blocks(); // block.hh:430 production entry
        println!("case {}", case_name);
        for (i, bl) in self.graph.blocks.iter().enumerate() {
            let r = bl.read().unwrap();
            let kind = match r.last_op() {
                None => "-".to_string(),
                Some(op) => {
                    if op.0.read().unwrap().opcode == OpCode::CPUI_RETURN {
                        "R".to_string()
                    } else {
                        "n".to_string()
                    }
                }
            };
            println!(
                "{} {} idx={} type={} lastop={}",
                i,
                self.name_of(bl),
                r.get_index(),
                type_name(r.get_type()),
                kind
            );
        }
        println!("end");
    }
}

fn main() {
    // Case 1: entry (index 0) in the middle, two RETURN-ending blocks ahead
    // of it; non-RETURN members (plain op idx7, null idx4) sort by index.
    {
        let mut f = Fixture::new();
        f.make(5, Some(OpCode::CPUI_RETURN)); // b0 RETURN
        f.make(0, Some(OpCode::CPUI_COPY));   // b1 entry, non-RETURN
        f.make(2, Some(OpCode::CPUI_RETURN)); // b2 RETURN
        f.make(7, Some(OpCode::CPUI_COPY));   // b3 plain
        f.make(4, None);                      // b4 null (loop-like)
        f.run("entry_first_return_last");
    }

    // Case 2: (null, RETURN) / (RETURN, null) arms with an entry that has a
    // NULL lastOp (cc:712 fires before the RETURN arms), plus a non-RETURN
    // op vs null pair that falls to the index key.
    {
        let mut f = Fixture::new();
        f.make(3, None);                      // b0 null
        f.make(1, Some(OpCode::CPUI_RETURN)); // b1 RETURN
        f.make(6, Some(OpCode::CPUI_RETURN)); // b2 RETURN
        f.make(8, Some(OpCode::CPUI_INT_ADD)); // b3 plain
        f.make(0, None);                      // b4 entry, null lastOp
        f.run("null_vs_return_arms");
    }

    // Case 3: real BlockGoto wrapping a RETURN-ending block —
    // BlockGoto::lastOp (block.hh:562) delegates to the wrapped component,
    // so the goto composite sorts to the tail. Ghidra's newBlockGoto
    // removes the wrapped block and appends the wrapper at the END of the
    // list (identifyInternal + addBlock, block.cc:1706-1710); the Rust
    // model installs the same membership directly.
    {
        let mut f = Fixture::new();
        let b0 = f.make(2, Some(OpCode::CPUI_RETURN)); // goto component
        let b1 = f.make(1, Some(OpCode::CPUI_COPY));   // plain sibling
        let t = f.make(0, Some(OpCode::CPUI_COPY));    // entry + goto target
        f.graph.add_edge(b0.clone(), t.clone());
        let goto: BlockRef = Arc::new(RwLock::new(BlockGoto {
            index: 2,
            flags: 0,
            parent: None,
            goto_target: None,
            target_dyn: Some(t.clone()),
            wrapped: Some(b0.clone()),
            goto_type: 0,
            prints_precomputed: false,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }));
        // Ghidra list after newBlockGoto: [b1, t, goto] — b0 removed from
        // its slot, the wrapper appended at the end.
        f.graph.blocks.retain(|b| !Arc::ptr_eq(b, &b0));
        f.graph.add_block(goto.clone());
        f.created.push(goto.clone()); // stable name: b3
        f.run("goto_wrapped_lastop");
    }

    // Case 4: real BlockMultiGoto wrapping a non-RETURN block —
    // BlockMultiGoto::lastOp (block.hh:590) delegates to the wrapped
    // component, so the multigoto composite sorts by index ahead of a
    // RETURN-ending sibling.
    {
        let mut f = Fixture::new();
        let b0 = f.make(1, Some(OpCode::CPUI_COPY)); // multigoto component
        let t1 = f.make(5, Some(OpCode::CPUI_RETURN)); // RETURN sibling
        let t2 = f.make(7, None);                     // null sibling
        f.graph.add_edge(b0.clone(), t1.clone());
        f.graph.add_edge(b0.clone(), t2.clone());
        let mg: BlockRef = Arc::new(RwLock::new(BlockMultiGoto {
            index: 1,
            flags: 0,
            parent: None,
            gotoedges: vec![t2.clone()],
            defaultswitch: false,
            wrapped: Some(b0.clone()),
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }));
        // Ghidra list after newBlockMultiGoto: [t1, t2, mg].
        f.graph.blocks.retain(|b| !Arc::ptr_eq(b, &b0));
        f.graph.add_block(mg.clone());
        f.created.push(mg.clone()); // stable name: b3
        f.run("multigoto_wrapped_lastop");
    }

    // Case 5: single-element list skips the sort (block.hh:431).
    {
        let mut f = Fixture::new();
        f.make(0, Some(OpCode::CPUI_RETURN)); // lone entry/RETURN block
        f.run("single_block_skip");
    }
}
