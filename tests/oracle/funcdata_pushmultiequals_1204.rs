//! FUNCDATA-PUSHMULTIEQUALS-0001 Rudra comparand.
//!
//! Mirrors `tests/oracle/funcdata_pushmultiequals_1204.cc` scenario for
//! scenario: three hand-built block graphs sharing the cc:84 shape drive
//! `Funcdata::push_multiequals` (Ghidra funcdata_block.cc:84-171) and print
//! the same canonicalized projection (ops of [m, o, d], first-appearance
//! varnode table, origvn descend list, bank counts).

use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::varnode::varnode_flags;
use rudra::varnode::Varnode;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type Var = Arc<RwLock<Varnode>>;

struct Graph {
    #[allow(dead_code)]
    p1: Block,
    #[allow(dead_code)]
    p2: Block,
    m: Block,
    a: Block,
    o: Block,
    d: Block,
}

fn build_graph(fd: &mut Funcdata) -> Graph {
    let p1 = fd.create_new_block();
    let p2 = fd.create_new_block();
    let m = fd.create_new_block();
    let a = fd.create_new_block();
    let o = fd.create_new_block();
    let d = fd.create_new_block();
    fd.bblocks.add_edge(p1.clone(), m.clone());
    fd.bblocks.add_edge(p2.clone(), m.clone());
    fd.bblocks.add_edge(m.clone(), o.clone()); // o in[0] = m (dead edge slot 0)
    fd.bblocks.add_edge(a.clone(), o.clone()); // o in[1] = a
    fd.bblocks.add_edge(o.clone(), d.clone());
    Graph { p1, p2, m, a, o, d }
}

fn make_phi(
    fd: &mut Funcdata, blk: &Block, in0: &Var, in1: &Var, out_addr: u64, pc: u64,
) -> (PcodeOpRef, Var) {
    let op = fd.new_op(2, Address::new(pc));
    fd.op_set_opcode(&op, OpCode::CPUI_MULTIEQUAL);
    let out = fd.new_varnode(8, Address::new(out_addr));
    fd.op_set_output(&op, out.clone());
    fd.op_set_input(&op, in0.clone(), 0);
    fd.op_set_input(&op, in1.clone(), 1);
    fd.op_insert_end(&op, blk);
    (op, out)
}

fn make_copy(
    fd: &mut Funcdata, blk: &Block, in0: &Var, out_addr: u64, pc: u64,
) -> PcodeOpRef {
    let op = fd.new_op(1, Address::new(pc));
    fd.op_set_opcode(&op, OpCode::CPUI_COPY);
    let out = fd.new_varnode(8, Address::new(out_addr));
    fd.op_set_output(&op, out);
    fd.op_set_input(&op, in0.clone(), 0);
    fd.op_insert_end(&op, blk);
    op
}

fn snapshot(fd: &Funcdata, graph: &Graph, origvn: &Var) -> String {
    let labels = ["m", "o", "d"];
    let blocks = [&graph.m, &graph.o, &graph.d];

    // Pass 1: collect (label, slot, op) in block order.
    let mut tagged_ops: Vec<(String, PcodeOpRef)> = Vec::new();
    for (b, block) in blocks.iter().enumerate() {
        for (slot, op) in block.read().unwrap().get_ops().into_iter().enumerate() {
            let mut tag = String::new();
            let time = op.0.read().unwrap().start.get_time();
            write!(
                &mut tag, "{}:{}:{}/t{}",
                labels[b], slot, op.0.read().unwrap().opcode as i32, time
            )
            .unwrap();
            tagged_ops.push((tag, op));
        }
    }

    // Pass 2: varnode table in first-appearance order (outputs then inputs).
    let mut vars: Vec<Var> = Vec::new();
    let mut var_index: HashMap<usize, usize> = HashMap::new();
    let mut intern = |vn: Var, vars: &mut Vec<Var>, index: &mut HashMap<usize, usize>| {
        let key = Arc::as_ptr(&vn) as usize;
        if let std::collections::hash_map::Entry::Vacant(e) = index.entry(key) {
            e.insert(vars.len());
            vars.push(vn);
        }
    };
    for (_, op) in &tagged_ops {
        let (output, inputs) = {
            let o = op.0.read().unwrap();
            (o.get_out().cloned(), o.inrefs.clone())
        };
        if let Some(vn) = output {
            intern(vn, &mut vars, &mut var_index);
        }
        for vn in inputs {
            intern(vn, &mut vars, &mut var_index);
        }
    }
    let var_name = |vn: &Var| format!("v{}", var_index[&(Arc::as_ptr(vn) as usize)]);

    let mut output = String::new();
    output.push_str("ops[");
    for (index, (tag, op)) in tagged_ops.iter().enumerate() {
        if index != 0 {
            output.push(';');
        }
        let o = op.0.read().unwrap();
        let out_name = o
            .get_out()
            .map(|vn| var_name(vn))
            .unwrap_or_else(|| "_".to_string());
        write!(&mut output, "{tag}/o{out_name}/i").unwrap();
        for (slot, vn) in o.inrefs.iter().enumerate() {
            if slot != 0 {
                output.push(',');
            }
            write!(&mut output, "{}", var_name(vn)).unwrap();
        }
    }
    output.push_str("]vars[");
    for (index, vn) in vars.iter().enumerate() {
        if index != 0 {
            output.push(';');
        }
        let r = vn.read().unwrap();
        write!(
            &mut output,
            "v{index}:c{}/s{}/sp{}/k{}",
            r.create_index,
            r.get_size(),
            r.get_space().space_id(),
            u8::from(r.is_constant()),
        )
        .unwrap();
        write!(&mut output, ":x{}", r.get_offset()).unwrap();
    }
    // origvn descend list as canonical (block,slot) pairs.
    output.push_str("]origdesc=");
    let mut first = true;
    for desc in origvn.read().unwrap().descend_iter() {
        if !first {
            output.push(',');
        }
        first = false;
        let mut found = false;
        for (b, block) in blocks.iter().enumerate() {
            for (slot, op) in block.read().unwrap().get_ops().into_iter().enumerate() {
                if Arc::ptr_eq(&op.0, &desc) {
                    write!(&mut output, "{}:{}", labels[b], slot).unwrap();
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        if !found {
            output.push('?');
        }
    }
    write!(
        &mut output,
        "]counts={},{},{},{}",
        tagged_ops.len(),
        fd.obank.alivelist.len(),
        fd.obank.deadlist.len(),
        fd.vbank.num_varnodes(),
    )
    .unwrap();
    output
}

fn scenario(name: &str, addr: u64, addrtied: bool, reader: bool, phi_same_addr: bool) {
    let mut fd = Funcdata::new(name, Address::new(addr), 0);
    let graph = build_graph(&mut fd);
    let v1 = fd.new_varnode(8, Address::new(0x1000));
    let v2 = fd.new_varnode(8, Address::new(0x1010));
    let w = fd.new_varnode(8, Address::new(0x1020));
    let pc_base = match (addrtied, reader, phi_same_addr) {
        (false, true, false) => 0x3000,  // reader_beyond
        (false, false, false) => 0x3100, // dead_edge_only
        (true, true, true) => 0x3200,    // addrtied_unique
        _ => unreachable!("scenario shape"),
    };
    let (_, origvn) = make_phi(&mut fd, &graph.m, &v1, &v2, 0x2000, pc_base);
    if addrtied {
        // cc:118-122 precondition: addrtied origvn feeding a MULTIEQUAL at
        // the SAME address in outblock -> neednewunique.
        origvn
            .write()
            .unwrap()
            .flags |= varnode_flags::ADDRTIED | varnode_flags::INSERT;
    }
    let ophi_addr = if phi_same_addr { 0x2000 } else { 0x2010 };
    make_phi(&mut fd, &graph.o, &origvn, &w, ophi_addr, pc_base + 0x10);
    if reader {
        make_copy(&mut fd, &graph.d, &origvn, 0x2020, pc_base + 0x20);
    }
    fd.push_multiequals(&graph.m);
    let label = match (addrtied, reader, phi_same_addr) {
        (false, true, false) => "reader_beyond",
        (false, false, false) => "dead_edge_only",
        (true, true, true) => "addrtied_unique",
        _ => unreachable!(),
    };
    println!("{label}|after={}", snapshot(&fd, &graph, &origvn));
}

fn main() {
    scenario("GetStr", 0x36d0, false, true, false);
    scenario("main_free", 0x4970, false, false, false);
    scenario("hugehelp", 0x4a00, true, true, true);
}
