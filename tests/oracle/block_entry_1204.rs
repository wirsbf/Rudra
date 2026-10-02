use rudra::address::Address;
use rudra::block::{block_flags, FlowBlock};
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::flow::follow_flow;
use rudra::funcdata::Funcdata;
use std::env;
use std::error::Error;
use std::fs;
use std::sync::{Arc, RwLock};

type DynBlock = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

struct Probe {
    name: &'static str,
    address: u64,
    size: usize,
}

fn parse_u64(value: &str) -> Result<u64, Box<dyn Error>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    Ok(u64::from_str_radix(value, 16)?)
}

fn ordinal_of(blocks: &[DynBlock], needle: &DynBlock) -> i32 {
    blocks
        .iter()
        .position(|block| Arc::ptr_eq(block, needle))
        .map_or(-1, |index| index as i32)
}

fn format_edges(blocks: &[DynBlock], block: &DynBlock, outgoing: bool) -> String {
    let block = block.read().expect("block read lock");
    let count = if outgoing {
        block.size_out()
    } else {
        block.size_in()
    };
    let mut edges = Vec::with_capacity(count);
    for slot in 0..count {
        let edge = if outgoing {
            block.get_out(slot)
        } else {
            block.get_in(slot)
        }
        .expect("edge slot must exist");
        edges.push(format!(
            "{}:{}",
            ordinal_of(blocks, &edge.point),
            edge.reverse_index
        ));
    }
    format!("[{}]", edges.join(","))
}

fn observe(image: &[u8], image_base: u64, probe: Probe) -> Result<(), Box<dyn Error>> {
    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(image, image_base)?;
    let mut function = Funcdata::new(probe.name, Address::new(probe.address), probe.size as i32);
    follow_flow(
        &mut function,
        &mut lifter,
        Address::new(probe.address),
        u64::MAX,
    );

    let blocks = function.bblocks.blocks.clone();
    let entry = function
        .bblocks
        .get_start_block()
        .ok_or("missing official entry block")?;
    let entry_count = blocks
        .iter()
        .filter(|block| block.read().expect("block read lock").is_entry_point())
        .count();

    println!("case={}", probe.name);
    println!(
        "blocks={} entry_ordinal={} entry_count={}",
        blocks.len(),
        ordinal_of(&blocks, &entry),
        entry_count
    );
    for (ordinal, block) in blocks.iter().enumerate() {
        let (index, flags, ops, start, stop) = {
            let block = block.read().expect("block read lock");
            (
                block.get_index(),
                block.get_flags(),
                block.get_ops().len(),
                block.get_start_addr().as_u64() - probe.address,
                block
                    .as_any()
                    .downcast_ref::<rudra::block::BlockBasic>()
                    .map(|basic| basic.get_stop_addr().as_u64() - probe.address)
                    .unwrap_or(0),
            )
        };
        println!(
            "block={} index={} flags={} ops={} start={} stop={} in={} out={}",
            ordinal,
            index,
            flags,
            ops,
            start,
            stop,
            format_edges(&blocks, block, false),
            format_edges(&blocks, block, true)
        );
    }

    if blocks[0].read().expect("block read lock").get_flags() & block_flags::ENTRY_POINT == 0 {
        return Err("list[0] is not the official entry block".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 7 {
        return Err(
            "usage: block_entry_1204 TEXT_IMAGE TEXT_BASE RET_ADDR RET_SIZE LOOP_ADDR LOOP_SIZE"
                .into(),
        );
    }
    let image = fs::read(&args[1])?;
    let image_base = parse_u64(&args[2])?;
    observe(
        &image,
        image_base,
        Probe {
            name: "block_entry_ret_probe",
            address: parse_u64(&args[3])?,
            size: parse_u64(&args[4])? as usize,
        },
    )?;
    observe(
        &image,
        image_base,
        Probe {
            name: "block_entry_loop_probe",
            address: parse_u64(&args[5])?,
            size: parse_u64(&args[6])? as usize,
        },
    )?;
    Ok(())
}
