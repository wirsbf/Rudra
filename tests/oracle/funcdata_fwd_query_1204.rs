// FUNCDATA-FWD-QUERY-0001 bilateral fixture — Rust side.
//
// Mirrors tests/oracle/funcdata_fwd_query_1204.cc case for case against the
// locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// Exercises the Funcdata query forwarder family (funcdata.hh inlines):
// begin_loc/end_loc spans, overlap_loc, begin_def/end_def spans,
// find_covered_input/find_covering_input/find_varnode_written, the heritage
// dead-code gate forwarders, start_clean_up, find_op/target, the op
// iterator family, and end_lane_access.
use std::sync::{Arc, RwLock};

use rudra::address::{Address, SeqNum};
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::{varnode_flags, Varnode, VarnodeDefRef, VarnodeLocRef};

fn opcode_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_INT_SUB => "INT_SUB",
        OpCode::CPUI_INT_ADD => "INT_ADD",
        OpCode::CPUI_STORE => "STORE",
        _ => "OTHER",
    }
}

fn storage(vn: &Arc<RwLock<Varnode>>) -> String {
    let v = vn.read().unwrap();
    format!("{}:{:x}:{}", v.address_space.name(), v.get_offset(), v.get_size())
}

fn count_loc<'a, I: Iterator<Item = &'a VarnodeLocRef>>(iter: I) -> usize {
    iter.count()
}

fn count_def<'a, I: Iterator<Item = &'a VarnodeDefRef>>(iter: I) -> usize {
    iter.count()
}

fn main() {
    let mut fd = Funcdata::new("fwd_query", Address::new(0x5000), 0x20);
    let b0: Arc<RwLock<BlockBasic>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(b0.clone());
    let b0_dyn: Arc<RwLock<dyn FlowBlock + Send + Sync>> = b0.clone();

    // Two SSA versions of ram:0x1000 size 8 (defs at 0x5010 / 0x5020).
    let op1 = fd.new_op(1, Address::new(0x5010));
    fd.op_set_opcode(&op1, OpCode::CPUI_INT_SUB);
    fd.op_insert_end(&op1, &b0_dyn);
    fd.op_mark_start_instruction(&op1);
    fd.new_varnode_out_full(8, AddressSpace::Ram, Address::new(0x1000), &op1);
    let op2 = fd.new_op(1, Address::new(0x5020));
    fd.op_set_opcode(&op2, OpCode::CPUI_INT_ADD);
    fd.op_insert_end(&op2, &b0_dyn);
    fd.op_mark_start_instruction(&op2);
    fd.new_varnode_out_full(8, AddressSpace::Ram, Address::new(0x1000), &op2);
    // A STORE op for the beginOp(OpCode) per-list path.
    let store = fd.new_op(3, Address::new(0x5030));
    fd.op_set_opcode(&store, OpCode::CPUI_STORE);
    fd.op_insert_end(&store, &b0_dyn);
    fd.op_mark_start_instruction(&store);
    // Inputs: 4-byte at ram:0x100, 8-byte at ram:0x3000.
    let inp_small = fd.new_varnode(4, Address::new(0x100));
    fd.set_input_varnode(inp_small.clone());
    let inp_big = fd.new_varnode(8, Address::new(0x3000));
    fd.set_input_varnode(inp_big);
    // Free: 8-byte at ram:0x2000.
    fd.new_varnode(8, Address::new(0x2000));

    // case=loc_all: full loc span count + first/last storage.
    {
        let mut count = 0usize;
        let mut first = String::new();
        let mut last = String::new();
        for loc_ref in fd.begin_loc() {
            if count == 0 {
                first = storage(&loc_ref.0);
            }
            last = storage(&loc_ref.0);
            count += 1;
        }
        println!("case=loc_all|count={count}|first={first}|last={last}");
    }

    // case=loc_space: per-space counts (ram vs unique).
    {
        let ram_count = count_loc(fd.begin_loc_space(AddressSpace::Ram));
        let unique_count = count_loc(fd.begin_loc_space(AddressSpace::Unique));
        println!("case=loc_space|ram={ram_count}|unique={unique_count}");
    }

    // case=loc_addr: exact-address span at ram:0x1000 (both SSA versions).
    {
        let count = count_loc(fd.begin_loc_addr(Address::new(0x1000)));
        println!("case=loc_addr|count={count}");
    }

    // case=loc_size_fl: (8, ram:0x1000) by property and (8, ram:0x3000) input.
    {
        let written_c = count_loc(fd.begin_loc_size_fl(
            8,
            Address::new(0x1000),
            varnode_flags::WRITTEN,
        ));
        let input_c = count_loc(fd.begin_loc_size_fl(
            8,
            Address::new(0x3000),
            varnode_flags::INPUT,
        ));
        let free_c =
            count_loc(fd.begin_loc_size_fl(8, Address::new(0x2000), 0));
        println!(
            "case=loc_size_fl|written={written_c}|input={input_c}|free={free_c}"
        );
    }

    // case=loc_pc: definition-bounded spans at ram:0x1000.
    {
        let op1_time = op1.0.read().unwrap().start.time;
        let op2_time = op2.0.read().unwrap().start.time;
        let by5010 = count_loc(fd.begin_loc_pc(
            8,
            Address::new(0x1000),
            Address::new(0x5010),
            u32::MAX,
        ));
        let by5020 = count_loc(fd.begin_loc_pc(
            8,
            Address::new(0x1000),
            Address::new(0x5020),
            u32::MAX,
        ));
        let uniq_hit = count_loc(fd.begin_loc_pc(
            8,
            Address::new(0x1000),
            Address::new(0x5010),
            op1_time,
        ));
        let uniq_miss = count_loc(fd.begin_loc_pc(
            8,
            Address::new(0x1000),
            Address::new(0x5010),
            op2_time,
        ));
        println!(
            "case=loc_pc|by5010={by5010}|by5020={by5020}|uniq_hit={uniq_hit}|uniq_miss={uniq_miss}"
        );
    }

    // case=find_inputs: covered/covering/written.
    {
        let covered = fd
            .find_covered_input(16, Address::new(0xfc))
            .map(|v| storage(&v))
            .unwrap_or_else(|| "null".to_string());
        let covering = fd
            .find_covering_input(2, Address::new(0x101))
            .map(|v| storage(&v))
            .unwrap_or_else(|| "null".to_string());
        let written = fd
            .find_varnode_written(8, Address::new(0x1000), Address::new(0x5010), u32::MAX)
            .map(|v| storage(&v))
            .unwrap_or_else(|| "null".to_string());
        let written_miss = fd
            .find_varnode_written(8, Address::new(0x1000), Address::new(0x9999), u32::MAX)
            .map(|v| storage(&v))
            .unwrap_or_else(|| "null".to_string());
        println!(
            "case=find_inputs|covered={covered}|covering={covering}|written={written}|written_miss={written_miss}"
        );
    }

    // case=overlap_loc: groups of overlapping varnodes at ram:0x1000.
    // The oracle projection prints bounds-pair groups from
    // overlapLoc(iter,bounds); the Rust adapted bank form returns the
    // overlapping varnodes directly, so distinct (offset,size) storages
    // equal the oracle groups and the varnode count equals (bounds-1)/2*2.
    {
        let overlapping = fd.overlap_loc(Address::new(0x1000), 8);
        let mut groups: Vec<(u64, usize)> = Vec::new();
        for vn in &overlapping {
            let v = vn.read().unwrap();
            let key = (v.get_offset(), v.get_size());
            if !groups.contains(&key) {
                groups.push(key);
            }
        }
        let bounds = groups.len() * 2 + 1;
        println!(
            "case=overlap_loc|groups={}|bounds={}",
            groups.len(),
            bounds
        );
    }

    // case=def_iters: def-tree spans by property and at an address.
    {
        let all = fd.begin_def().count();
        let inputs = count_def(fd.begin_def_fl(varnode_flags::INPUT));
        let written = count_def(fd.begin_def_fl(varnode_flags::WRITTEN));
        let frees = count_def(fd.begin_def_fl(0));
        let at_addr =
            count_def(fd.begin_def_addr(varnode_flags::INPUT, Address::new(0x3000)));
        println!(
            "case=def_iters|all={all}|inputs={inputs}|written={written}|frees={frees}|at_addr={at_addr}"
        );
        // beginDef(written, addr) is the illegal combination: the oracle
        // throws LowlevelError (varnode.cc:1913-1914); Rugra panics with
        // the same message (catch mirrors the C++ try/catch).
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let thrown = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut span = fd.begin_def_addr(varnode_flags::WRITTEN, Address::new(0x1000));
            span.next();
        }));
        std::panic::set_hook(previous_hook);
        let message = match thrown {
            Ok(()) => "no-throw".to_string(),
            Err(payload) => payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string()),
        };
        println!("case=def_addr_written_throw|{message}");
    }

    // case=start_cleanup: clean-up index capture.
    {
        let before = fd.get_clean_up_index();
        fd.start_clean_up();
        let at_phase = fd.get_clean_up_index();
        fd.new_varnode(8, Address::new(0x4000));
        let after_more = fd.get_clean_up_index();
        let advanced = (at_phase != after_more) as u8;
        println!(
            "case=start_cleanup|before={before}|at_phase={at_phase}|after_more={after_more}|advanced={advanced}"
        );
    }

    // case=find_op_target: sequence-number and address lookups.
    {
        let op1_seq = op1.0.read().unwrap().start;
        let hit = fd
            .find_op(&op1_seq)
            .map(|op| opcode_name(op.0.read().unwrap().opcode).to_string())
            .unwrap_or_else(|| "null".to_string());
        let miss = fd
            .find_op(&SeqNum::new(Address::new(0x7777), 9))
            .map(|_| "found")
            .unwrap_or("null");
        let tgt = fd
            .target_op(Address::new(0x5010))
            .map(|op| opcode_name(op.0.read().unwrap().opcode).to_string())
            .unwrap_or_else(|| "null".to_string());
        let tgt_miss = fd
            .target_op(Address::new(0x8888))
            .map(|_| "found")
            .unwrap_or("null");
        println!(
            "case=find_op_target|hit={hit}|miss={miss}|target={tgt}|target_miss={tgt_miss}"
        );
    }

    // case=op_iters: opcode-list, alive/dead, all, per-address spans.
    {
        let stores = fd.begin_op_code(OpCode::CPUI_STORE).count();
        let subs = fd.begin_op_code(OpCode::CPUI_INT_SUB).count();
        let alive = fd.begin_op_alive().count();
        let dead = fd.begin_op_dead().count();
        let all = fd.begin_op_all().count();
        let at_addr = fd
            .begin_op_addr(Address::new(0x5010))
            .take_while(|op| !(op.0.read().unwrap().start.addr > Address::new(0x5010)))
            .count();
        println!(
            "case=op_iters|stores={stores}|subs={subs}|alive={alive}|dead={dead}|all={all}|at_addr={at_addr}"
        );
    }

    // case=lane_access_end: empty laned map — begin==end.
    {
        let lanes = fd.end_lane_access().count();
        println!("case=lane_access_end|lanes={lanes}");
    }
}
