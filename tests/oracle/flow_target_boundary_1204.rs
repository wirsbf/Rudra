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

struct Probe<'a> {
    name: &'a str,
    image: &'a [u8],
    image_base: u64,
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

fn observe(probe: Probe<'_>) -> Result<(), Box<dyn Error>> {
    let mut lifter = SleighLifter::new();
    lifter.configure_x86_64(probe.image, probe.image_base)?;
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
        let (flags, ops, start, stop) = {
            let block = block.read().expect("block read lock");
            (
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
            "block={} flags={} ops={} start={} stop={} in={} out={}",
            ordinal,
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
    if args.len() != 9 {
        return Err("usage: flow_target_boundary_1204 FIXTURE_TEXT FIXTURE_TEXT_BASE PROBE_ADDR PROBE_SIZE CURL_TEXT CURL_TEXT_BASE GETSTR_ADDR GETSTR_SIZE".into());
    }

    let fixture_image = fs::read(&args[1])?;
    observe(Probe {
        name: "flow_target_boundary_probe",
        image: &fixture_image,
        image_base: parse_u64(&args[2])?,
        address: parse_u64(&args[3])?,
        size: parse_u64(&args[4])? as usize,
    })?;

    let curl_image = fs::read(&args[5])?;
    observe(Probe {
        name: "GetStr",
        image: &curl_image,
        image_base: parse_u64(&args[6])?,
        address: parse_u64(&args[7])?,
        size: parse_u64(&args[8])? as usize,
    })?;
    Ok(())
}
