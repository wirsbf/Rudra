// HERITAGE-SUBPIECE-CONST-1204: Rugra comparand for the locked Ghidra
// 12.0.4 oracle (HERITAGE-GUARD-SUBPIECE-CONST-0001). Mirrors
// tests/oracle/heritage_subpiece_const_1204.cc case for case:
//  - stack_guard_full: the production Heritage::guard_output_overlap_stack
//    (src/heritage.rs, heritage.cc:1322-1375) driven directly on a real
//    Funcdata with one CALL op over the five trigger geometries. The
//    projection prints every op of the call block in insertion order with
//    the SUBPIECE in[1] constants — cc:1336 front (LE 0) and cc:1358 back
//    (LE sizeFront + retSize), plus the cc:1327 insertPoint chain and the
//    write-list entry.
//  - front_back_constant: the exact cc:1336/cc:1358 call shapes through
//    rudra::fspec::justified_contain_range in both endian routings — LE
//    rows take AddressSpace::Stack.is_big_endian() exactly as the fixed
//    src/heritage.rs does, BE rows pass true (helper-level big-endian
//    pinning; the transitional enum space cannot stage a BE stack).

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::fspec::justified_contain_range;
use rudra::funcdata::Funcdata;
use rudra::heritage::Heritage;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<rudra::varnode::Varnode>>;

// Varnode descriptor shared with the C++ oracle:
//   constant -> c<size>(<value>); iop -> IOP;
//   other    -> <hexoffset>:<size>:<I|W|F>{ah}
// Space letters are not printed (the transitional new_varnode_out register
// space divergence is a registered projected-away residual — see the C++
// fixture header).
fn vn_descriptor(vn: Option<&VnRef>) -> String {
    let Some(vn) = vn else {
        return "-".to_string();
    };
    let value = vn.read().unwrap();
    if value.is_constant() {
        return format!("c{}({})", value.size, value.get_offset());
    }
    if value.get_space() == AddressSpace::Iop {
        return "IOP".to_string();
    }
    let state = if value.is_input() {
        'I'
    } else if value.is_written() {
        'W'
    } else {
        'F'
    };
    let flags = if value.is_active_heritage() { "ah" } else { "" };
    format!("{:x}:{}:{}{{{}}}", value.get_offset(), value.size, state, flags)
}

#[derive(Clone, Copy)]
struct SgGeom {
    addr: u64,
    size: i32,
    ret: u64,
    retsz: i32,
    pre_out: bool,
}

// The same five trigger geometries as the C++ oracle, in the same order.
const SG: [SgGeom; 5] = [
    SgGeom { addr: 0x1000, size: 16, ret: 0x1004, retsz: 4, pre_out: false },
    SgGeom { addr: 0x2000, size: 8, ret: 0x2002, retsz: 4, pre_out: false },
    SgGeom { addr: 0x3000, size: 8, ret: 0x3000, retsz: 4, pre_out: false },
    SgGeom { addr: 0x4000, size: 12, ret: 0x4002, retsz: 10, pre_out: false },
    SgGeom { addr: 0x5000, size: 16, ret: 0x5008, retsz: 4, pre_out: true },
];

// Drive the production guard_output_overlap_stack on one geometry and
// print the full op projection of the call block plus the write entry.
fn run_guard_case(index: usize, g: SgGeom) {
    let base = 0x6000 + 0x10 * index as u64;
    let mut fd = Funcdata::new("sg", Address::new(base), 0x20);
    let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
        0,
        Address::new(base),
    )));
    fd.bblocks.add_block(block.clone());
    let call = fd.new_op(1, Address::new(base));
    fd.op_set_opcode(&call, OpCode::CPUI_CALL);
    let target = fd.new_constant(8, 0x4000);
    fd.op_set_input(&call, target, 0);
    fd.op_insert_end(&call, &block);
    if g.pre_out {
        fd.new_varnode_out(g.retsz as usize, Address::new(g.ret), &call);
    }

    let mut write: Vec<VnRef> = Vec::new();
    let mut heritage = Heritage::new();
    heritage.guard_output_overlap_stack(
        &mut fd,
        &call.0,
        Address::new(g.addr),
        g.size,
        Address::new(g.ret),
        g.retsz,
        &mut write,
    );

    let sf = (g.ret - g.addr) as i32;
    let sb = g.size - g.retsz - sf;
    println!(
        "gs geom={index} addr={:x} size={} ret={:x} retsz={} sf={sf} sb={sb}",
        g.addr, g.size, g.ret, g.retsz
    );
    let ops = block.read().unwrap().get_ops();
    for (pos, op) in ops.iter().enumerate() {
        let o = op.0.read().unwrap();
        let mut inputs = String::new();
        for slot in 0..o.num_input() {
            if slot != 0 {
                inputs.push(',');
            }
            inputs.push_str(&vn_descriptor(o.get_in(slot)));
        }
        // Opcode number, not name: mirrors the C++ oracle (Ghidra's
        // get_opname(CPUI_INDIRECT) prints "DELAY_SLOT" while Rugra's
        // name() prints "INDIRECT"; the numeric codes are identical).
        println!(
            "  op{pos} {} in=[{inputs}] out={}",
            o.opcode as i32,
            vn_descriptor(o.output.as_ref())
        );
    }
    if let Some(last) = write.last() {
        println!("  write {}", vn_descriptor(Some(last)));
    }
}

fn main() {
    println!("schema=1|fixture=HERITAGE-SUBPIECE-CONST-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // ---- case 1: production guard_output_overlap_stack ------------------
    println!("case=stack_guard_full");
    for (index, g) in SG.iter().enumerate() {
        run_guard_case(index, *g);
    }

    // ---- case 2: cc:1336/cc:1358 constants in LE and BE routings --------
    println!("case=front_back_constant");
    for (index, g) in SG.iter().enumerate() {
        let sf = (g.ret - g.addr) as i32;
        let sb = g.size - g.retsz - sf;
        let addr_back = g.ret.wrapping_add(g.retsz as u64);
        // The exact cc:1336/cc:1358 call shapes; LE rows take the stack
        // space's endianness exactly as the fixed src/heritage.rs does,
        // BE rows pass true (helper-level big-endian pinning).
        let amt = |op2: u64, sz2: i32, be: bool| {
            justified_contain_range(g.addr, g.size, op2, sz2, false, be)
        };
        println!(
            "  sp geom={index} le front={} back={} be front={} back={}",
            amt(g.addr, sf, AddressSpace::Stack.is_big_endian()),
            amt(addr_back, sb, AddressSpace::Stack.is_big_endian()),
            amt(g.addr, sf, true),
            amt(addr_back, sb, true),
        );
    }
}
