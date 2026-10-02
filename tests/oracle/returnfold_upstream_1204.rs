// RETURNFOLD-GAPA-UPSTREAM-0001 Rugra comparand — the e2e return-value fold
// chain (ActionMarkExplicit::baseExplicit multi-instance rule coreaction.cc
// :3020-3021 + multipleInteraction/processMultiplier cc:3091/3166 +
// ActionMarkImplied count cc:3434 + PrintC implied inlining: printc.cc:754
// opReturn / printlanguage.cc:526-534 recurse / printc.cc:2703-2705
// emitBlockBasic statement omission) driven through the production
// ActionMarkExplicit::apply, ActionMarkImplied::apply and PrintC block
// emission (emit_block_graph -> emit_block_basic_rpn, rpn_enabled default).
// Case matrix mirrors tests/oracle/returnfold_upstream_1204.cc:
//   s1_fold   single-instance COPY output feeding one RETURN: implied,
//             folded print `return 10;` with no standalone COPY statement,
//             MarkImplied count=1 / MarkExplicit count=0.
//   s2_merged two COPY-written instances merged into one HighVariable:
//             baseExplicit cc:3020-3021 forces both explicit; both assign
//             statements print; MarkExplicit count=2 / MarkImplied count=0.
//   s3_dup3   three RETURN readers exceed max_implied_ref=2 -> cc:3078
//             explicit; one assign + three variable returns.
//   s4_mult2  two RETURN readers == maxref: multlist candidate survives
//             processMultiplier (1 term <= max_term_duplication=2) ->
//             implied; both returns fold.
// `mark` prints both actions' apply return codes — the Rust count-bridge
// delta that Action::perform folds into state.count and returns, mirroring
// the oracle's Action::perform return (perform zeroes the inherited count
// at status_start, action.cc:306/361; the ctor does not).

use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::block::BlockGraph;
use rudra::coreaction::{ActionMarkExplicit, ActionMarkImplied};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

struct Fixture {
    next_pc: u64,
    blocks: Vec<BlockRef>,
}

impl Fixture {
    fn new(base_pc: u64) -> Self {
        Fixture { next_pc: base_pc, blocks: Vec::new() }
    }

    fn make_block(&mut self, fd: &mut Funcdata) -> BlockRef {
        let block = fd.create_new_block();
        let index = self.blocks.len() as i32;
        block.write().unwrap().set_index(index);
        self.blocks.push(block.clone());
        block
    }

    fn alloc_pc(&mut self) -> Address {
        let a = Address::new(self.next_pc);
        self.next_pc += 8;
        a
    }

    /// b = COPY const(value) at the head of blk; returns the written unique
    /// output varnode.
    fn make_copy_assign(&mut self, fd: &mut Funcdata, blk: &BlockRef, value: u64) -> VarnodeRef {
        let op = fd.new_op(1, self.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let out = fd.new_unique_out(4, &op);
        let cvn = fd.new_constant(4, value);
        fd.op_set_input(&op, cvn, 0);
        fd.op_insert_end(&op, blk);
        out
    }

    /// RETURN value at the end of blk (slot 0 holds the placeholder
    /// indirect constant, matching the production post-guardReturns shape).
    fn make_return(&mut self, fd: &mut Funcdata, blk: &BlockRef, value: &VarnodeRef) {
        let op = fd.new_op(2, self.alloc_pc());
        fd.op_set_opcode(&op, OpCode::CPUI_RETURN);
        let ret0 = fd.new_constant(1, 0);
        fd.op_set_input(&op, ret0, 0);
        fd.op_set_input(&op, value.clone(), 1);
        fd.op_insert_end(&op, blk);
    }
}

/// Does text contain the given standalone token? Tokens are maximal
/// alphanumeric runs ("0x10" != "10", "(int)10" yields "10").
fn has_token(text: &str, tok: &str) -> bool {
    let mut clean = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            clean.push(c);
        } else {
            if clean == tok {
                return true;
            }
            clean.clear();
        }
    }
    clean == tok
}

fn classify_arg(text: &str) -> &'static str {
    if has_token(text, "10") {
        "lit10"
    } else if has_token(text, "3") {
        "lit3"
    } else {
        "var"
    }
}

fn summarize(text: &str) -> String {
    let mut kinds: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let body = line.trim_start_matches(' ');
        if body.is_empty() {
            continue;
        }
        if body.starts_with("return") {
            kinds.push(format!("return+{}", classify_arg(body)));
        } else if let Some(p) = body.find(" = ") {
            kinds.push(format!("assign+{}", classify_arg(&body[p + 3..])));
        } else {
            kinds.push("other".to_string());
        }
    }
    kinds.join(";")
}

fn run_scenario(name: &str, fd: &mut Funcdata, f: &Fixture, tracked: &[VarnodeRef]) {
    println!("scen|name={name}");
    // ActionAssignHigh (coreaction.cc:5717)
    fd.set_high_level();
    // ActionMarkExplicit (coreaction.cc:5719). The Rust count-bridge: apply
    // returns the inherited-count delta, which Action::perform folds into
    // state.count and returns — the same number the C++ fixture reads from
    // Action::perform's return (the ctor does not zero count; perform does,
    // action.cc:306/361).
    let mut me = ActionMarkExplicit::new();
    let me_rc = match catch_unwind(AssertUnwindSafe(|| me.apply(fd))) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            println!("exception|phase={name}|what={error}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("exception|phase={name}|what=panic");
            std::process::exit(1);
        }
    };
    // ActionMarkImplied (coreaction.cc:5720).
    let mut mi = ActionMarkImplied::new();
    let mi_rc = match catch_unwind(AssertUnwindSafe(|| mi.apply(fd))) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            println!("exception|phase={name}|what={error}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("exception|phase={name}|what=panic");
            std::process::exit(1);
        }
    };
    for (i, vn) in tracked.iter().enumerate() {
        let r = vn.read().unwrap();
        println!(
            "flag|scen={name}|vn=t{i}|explicit={}|implied={}",
            u8::from(r.is_explicit()),
            u8::from(r.is_implied()),
        );
    }
    println!("mark|scen={name}|me_count={me_rc}|mi_count={mi_rc}");
    io::stdout().flush().expect("flush mark");

    // Print stage: same dispatch the main pipeline uses (rpn_enabled
    // default true -> emit_block_basic_rpn with the printc.cc:2703-2705
    // implied-output statement skip).
    let mut graph = BlockGraph::new();
    for block in &f.blocks {
        graph.add_block(block.clone());
    }
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.emit_block_graph(&graph);
    let emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture must retain EmitNoMarkup");
    let text = emit.debug_get_output_ref().to_owned();
    println!("text|scen={name}|{}", summarize(&text));
}

fn main() {
    println!(
        "schema=1|fixture=RETURNFOLD-GAPA-UPSTREAM-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---------------- s1_fold: single instance, one reader ----------------
    {
        let mut fd = Funcdata::new("rf1", Address::new(0x63000), 0x100);
        let mut f = Fixture::new(0x63010);
        let b1 = f.make_block(&mut fd);
        let t = f.make_copy_assign(&mut fd, &b1, 10);
        f.make_return(&mut fd, &b1, &t);
        run_scenario("s1_fold", &mut fd, &f, &[t]);
    }

    // ------------- s2_merged: two instances in one HighVariable -----------
    {
        let mut fd = Funcdata::new("rf2", Address::new(0x63100), 0x100);
        let mut f = Fixture::new(0x63110);
        let b1 = f.make_block(&mut fd);
        let b2 = f.make_block(&mut fd);
        let t1 = f.make_copy_assign(&mut fd, &b1, 10);
        f.make_return(&mut fd, &b1, &t1);
        let t2 = f.make_copy_assign(&mut fd, &b2, 3);
        f.make_return(&mut fd, &b2, &t2);
        fd.set_high_level();
        // HighVariable::merge(variable.cc:675) — Rugra's merge_internal does
        // not re-point member vn.high (ownership glue note), so the caller
        // re-points t2 at the surviving high exactly as setHigh would.
        let h1 = t1.read().unwrap().high.clone().expect("t1 high");
        let h2 = t2.read().unwrap().high.clone().expect("t2 high");
        h1.write().unwrap().merge(&mut h2.write().unwrap(), None, false);
        t2.write().unwrap().high = Some(h1.clone());
        run_scenario("s2_merged", &mut fd, &f, &[t1, t2]);
    }

    // ------------- s3_dup3: three readers exceed max_implied_ref ----------
    {
        let mut fd = Funcdata::new("rf3", Address::new(0x63200), 0x100);
        let mut f = Fixture::new(0x63210);
        let b0 = f.make_block(&mut fd);
        let b1 = f.make_block(&mut fd);
        let b2 = f.make_block(&mut fd);
        let b3 = f.make_block(&mut fd);
        let t = f.make_copy_assign(&mut fd, &b0, 10);
        f.make_return(&mut fd, &b1, &t);
        f.make_return(&mut fd, &b2, &t);
        f.make_return(&mut fd, &b3, &t);
        run_scenario("s3_dup3", &mut fd, &f, &[t]);
    }

    // ---------- s4_mult2: two readers == maxref, multlist survives ---------
    {
        let mut fd = Funcdata::new("rf4", Address::new(0x63300), 0x100);
        let mut f = Fixture::new(0x63310);
        let b0 = f.make_block(&mut fd);
        let b1 = f.make_block(&mut fd);
        let b2 = f.make_block(&mut fd);
        let t = f.make_copy_assign(&mut fd, &b0, 10);
        f.make_return(&mut fd, &b1, &t);
        f.make_return(&mut fd, &b2, &t);
        run_scenario("s4_mult2", &mut fd, &f, &[t]);
    }

    println!("case_new_constructor|status=UNTESTED|note=checkNewToConstructor (cc:3205-3235, CPUI_NEW + CALLIND special print) not driven; needs NEW call machinery");
    println!("case_addrtied_branches|status=UNTESTED|note=baseExplicit addr-tied SUBPIECE/ZEXT/PIECE sub-branches (cc:3022-3049) need addrtied varnodes + PieceNode/partialroot infra (MERGE-ADDRTIED-CLOSURE-0001; Rugra PcodeOp::partialroot flag absent)");
    println!("case_cover_crossing|status=UNTESTED|note=checkImpliedCover LOAD/STORE/CALL crossing (cc:3384-3412) not driven; Rugra block-level approximations stand (is_possible_alias reserved)");
    println!("case_marking_order|status=UNTESTED|note=Rugra MarkImplied iterates loc order flat vs Ghidra DFS post-order cc:3430-3451; flags and total count argued equal, not pinned by this fixture");
}
