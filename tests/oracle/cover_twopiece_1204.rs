// COVER-TWOPIECE-RESIDUAL-0001: Rudra comparand for the locked Ghidra 12.0.4
// CoverBlock two-piece (wrap-around) oracle.  Mirrors
// tests/oracle/cover_twopiece_1204.cc case for case: Part A drives
// CoverBlock construct/merge/contain/boundary/intersect across every
// one-piece/two-piece quadrant; Part B drives the production
// Varnode::updateCover -> Cover::rebuild path whose join-block MULTIEQUAL
// readers produce the wrap-around state, plus one production Cover::merge.

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::cover::{Cover, CoverBlock, CoverEndpoint};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;
type OpRef = Arc<std::sync::RwLock<PcodeOp>>;

/// Pointer-identity classification mirroring the C++ fixture's `id()`:
/// b (begin sentinel), e (end sentinel), i (input sentinel),
/// 0m (MULTIEQUAL marker: uindex 0 with marker identity), decimal order.
fn id(ep: CoverEndpoint) -> String {
    match ep {
        CoverEndpoint::Begin => "b".to_string(),
        CoverEndpoint::EndMark => "e".to_string(),
        CoverEndpoint::InputMark => "i".to_string(),
        CoverEndpoint::Op { order, multiequal } => {
            if multiequal {
                format!("{}m", order)
            } else {
                order.to_string()
            }
        }
    }
}

fn cbstate(cb: &CoverBlock) -> String {
    format!("{}-{}", id(cb.get_start_id()), id(cb.get_stop_id()))
}

fn b01(v: bool) -> u8 {
    u8::from(v)
}

fn i01(v: i32) -> String {
    v.to_string()
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    ops: Vec<(OpRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            next_offset: 0,
            ops: Vec::new(),
        }
    }

    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
            index,
            Address::new(self.base),
        )));
        self.fd.bblocks.add_block(block.clone());
        block
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn make_op(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> OpRef {
        let pc = Address::new(self.base + self.next_offset);
        self.next_offset += 1;
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        self.ops.push((op.0.clone(), name));
        op.0.clone()
    }

    fn unique_out(&mut self, size: usize, op: &OpRef) -> VnRef {
        self.fd
            .new_unique_out(size, &rudra::op::PcodeOpRef(op.clone()))
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

    fn input(&mut self, offset: u64, size: usize) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.fd.vbank.set_input(vn).expect("fresh input varnode")
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd.op_insert_input(
            &rudra::op::PcodeOpRef(op.clone()),
            vn.clone(),
            slot,
        );
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd
            .op_insert_end(&rudra::op::PcodeOpRef(op.clone()), block);
    }

    fn orders(&self) -> String {
        let mut out = String::from("[");
        let mut first = true;
        for (op, name) in &self.ops {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(&format!("{}={}", name, op.read().unwrap().get_seq_num().get_order()));
        }
        out.push(']');
        out
    }

    fn cover_text(root: &VnRef) -> String {
        let value = root.read().unwrap();
        let Some(cover) = value.cover.as_deref() else {
            return "[null]".to_string();
        };
        cover_state(cover)
    }
}

fn cover_state(cover: &Cover) -> String {
    let mut out = String::from("[");
    let mut first = true;
    for (index, block) in cover.blocks.iter() {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&format!("{}:{}", index, cbstate(block)));
    }
    out.push(']');
    out
}

// ---------------------------------------------------------------------------
// Part A
// ---------------------------------------------------------------------------

struct PartA {
    o2: OpRef,
    o3: OpRef,
    o4: OpRef,
    o5: OpRef,
    o6: OpRef,
}

impl PartA {
    fn new(g: &mut Graph) -> Self {
        let blk = g.make_block(0);
        let o2 = g.make_op("o2", OpCode::CPUI_INT_ADD, 2);
        g.insert_end(&o2, &blk);
        let o3 = g.make_op("o3", OpCode::CPUI_INT_ADD, 2);
        g.insert_end(&o3, &blk);
        let o4 = g.make_op("o4", OpCode::CPUI_INT_ADD, 2);
        g.insert_end(&o4, &blk);
        let o5 = g.make_op("o5", OpCode::CPUI_INT_ADD, 2);
        g.insert_end(&o5, &blk);
        let o6 = g.make_op("o6", OpCode::CPUI_INT_ADD, 2);
        g.insert_end(&o6, &blk);
        PartA { o2, o3, o4, o5, o6 }
    }

    fn order_of(op: &OpRef) -> u32 {
        op.read().unwrap().get_seq_num().get_order()
    }

    /// contain samples at b (uindex 0), each real op order, and e (u32::MAX).
    fn contain_samples(&self, cb: &CoverBlock) -> String {
        let mut out = String::from("[");
        out.push_str(&format!("b:{},", b01(cb.contain(0))));
        for (name, op) in [
            ("2", &self.o2),
            ("3", &self.o3),
            ("4", &self.o4),
            ("5", &self.o5),
            ("6", &self.o6),
        ] {
            out.push_str(&format!("{}:{},", name, b01(cb.contain(Self::order_of(op)))));
        }
        out.push_str(&format!("e:{}", b01(cb.contain(u32::MAX))));
        out.push(']');
        out
    }

    fn boundary_samples(&self, cb: &CoverBlock) -> String {
        let mut out = String::from("[");
        out.push_str(&format!("b:{},", i01(cb.boundary(0))));
        for (name, op) in [
            ("2", &self.o2),
            ("3", &self.o3),
            ("4", &self.o4),
            ("5", &self.o5),
            ("6", &self.o6),
        ] {
            out.push_str(&format!("{}:{},", name, i01(cb.boundary(Self::order_of(op)))));
        }
        out.push_str(&format!("e:{},", i01(cb.boundary(u32::MAX))));
        out.push_str(&format!("i:{}", i01(cb.boundary(0))));
        out.push(']');
        out
    }
}

fn op_endpoint(op: &OpRef) -> CoverEndpoint {
    CoverEndpoint::Op {
        order: PartA::order_of(op),
        multiequal: false,
    }
}

fn run_part_a() {
    {
        let mut g = Graph::new("a1_construct", 0x6000);
        let a = PartA::new(&mut g);
        let mut cb = CoverBlock::new();
        let fresh = cbstate(&cb);
        let empty_fresh = b01(cb.empty());
        cb.set_begin_id(op_endpoint(&a.o3));
        let after_begin = cbstate(&cb);
        cb.set_end_id(op_endpoint(&a.o5));
        let after_end = cbstate(&cb);
        println!(
            "case=a1_construct|orders={}|fresh={}|fresh_empty={}|after_begin={}|after_end={}|contain={}|boundary={}",
            g.orders(), fresh, empty_fresh, after_begin, after_end,
            a.contain_samples(&cb), a.boundary_samples(&cb)
        );
    }
    {
        let mut g = Graph::new("a2_twopiece_construct", 0x6100);
        let a = PartA::new(&mut g);
        let mut cb = CoverBlock::new();
        cb.set_begin_id(op_endpoint(&a.o6));
        cb.set_end_id(op_endpoint(&a.o2));
        println!(
            "case=a2_twopiece_construct|state={}|empty={}|contain={}|boundary={}",
            cbstate(&cb), b01(cb.empty()), a.contain_samples(&cb), a.boundary_samples(&cb)
        );
    }
    {
        let mut g = Graph::new("a3_boundary_sentinels", 0x6200);
        let a = PartA::new(&mut g);
        let mut cb = CoverBlock::new();
        cb.set_begin_id(CoverEndpoint::Begin);
        cb.set_end_id(op_endpoint(&a.o3));
        let begin_start = cbstate(&cb);
        let bb = i01(cb.boundary(0));
        let bi = i01(cb.boundary(0));
        let b3 = i01(cb.boundary(PartA::order_of(&a.o3)));
        let mut input_block = CoverBlock::new();
        input_block.set_begin_id(CoverEndpoint::InputMark);
        input_block.set_end_id(CoverEndpoint::InputMark);
        let input_state = cbstate(&input_block);
        let ib0 = i01(input_block.boundary(0));
        let ib2 = i01(input_block.boundary(0));
        let icontain = b01(input_block.contain(0));
        println!(
            "case=a3_boundary_sentinels|begin_start={}|boundary_b={}|boundary_i={}|boundary_3={}|input_state={}|input_boundary_b={}|input_boundary_i={}|input_contain_b={}",
            begin_start, bb, bi, b3, input_state, ib0, ib2, icontain
        );
    }
    {
        let mut g = Graph::new("a4_merge_disjoint_wrap", 0x6300);
        let a = PartA::new(&mut g);
        let mut x = CoverBlock::new();
        x.set_begin_id(op_endpoint(&a.o3));
        x.set_end_id(op_endpoint(&a.o4));
        let mut y = CoverBlock::new();
        y.set_begin_id(op_endpoint(&a.o6));
        y.set_end_id(op_endpoint(&a.o2));
        x.merge(&y);
        println!(
            "case=a4_merge_disjoint_wrap|merged={}|empty={}|contain={}|boundary={}",
            cbstate(&x), b01(x.empty()), a.contain_samples(&x), a.boundary_samples(&x)
        );
    }
    {
        let mut g = Graph::new("a5_merge_internal4_wrap", 0x6400);
        let a = PartA::new(&mut g);
        let mut x = CoverBlock::new();
        x.set_begin_id(CoverEndpoint::Begin);
        x.set_end_id(op_endpoint(&a.o3));
        let mut y = CoverBlock::new();
        y.set_begin_id(op_endpoint(&a.o4));
        y.set_end_id(CoverEndpoint::EndMark);
        let pre_x = cbstate(&x);
        let pre_y = cbstate(&y);
        x.merge(&y);
        println!(
            "case=a5_merge_internal4_wrap|pre_x={}|pre_y={}|merged={}|empty={}|contain={}",
            pre_x, pre_y, cbstate(&x), b01(x.empty()), a.contain_samples(&x)
        );
    }
    {
        let mut g = Graph::new("a6_merge_setall", 0x6500);
        let a = PartA::new(&mut g);
        let mut x = CoverBlock::new();
        x.set_begin_id(op_endpoint(&a.o3));
        x.set_end_id(CoverEndpoint::EndMark);
        let mut y = CoverBlock::new();
        y.set_begin_id(CoverEndpoint::Begin);
        y.set_end_id(op_endpoint(&a.o5));
        x.merge(&y);
        let set_all = cbstate(&x);
        let set_all_contain = a.contain_samples(&x);
        let mut p = CoverBlock::new();
        p.set_begin_id(op_endpoint(&a.o2));
        p.set_end_id(op_endpoint(&a.o6));
        let mut q = CoverBlock::new();
        q.set_begin_id(op_endpoint(&a.o2));
        q.set_end_id(op_endpoint(&a.o4));
        p.merge(&q);
        println!(
            "case=a6_merge_setall|setall={}|setall_contain={}|equal_start={}",
            set_all, set_all_contain, cbstate(&p)
        );
    }
    {
        let mut g = Graph::new("a7_intersect_quadrants", 0x6600);
        let a = PartA::new(&mut g);
        let mut x1 = CoverBlock::new();
        x1.set_begin_id(op_endpoint(&a.o3));
        x1.set_end_id(op_endpoint(&a.o5));
        let mut y1 = CoverBlock::new();
        y1.set_begin_id(op_endpoint(&a.o4));
        y1.set_end_id(op_endpoint(&a.o6));
        let mut x2 = CoverBlock::new();
        x2.set_begin_id(op_endpoint(&a.o3));
        x2.set_end_id(op_endpoint(&a.o4));
        let mut y2 = CoverBlock::new();
        y2.set_begin_id(op_endpoint(&a.o5));
        y2.set_end_id(op_endpoint(&a.o6));
        let mut x3 = CoverBlock::new();
        x3.set_begin_id(op_endpoint(&a.o3));
        x3.set_end_id(op_endpoint(&a.o4));
        let mut y3 = CoverBlock::new();
        y3.set_begin_id(op_endpoint(&a.o4));
        y3.set_end_id(op_endpoint(&a.o6));
        let mut x4 = CoverBlock::new();
        x4.set_begin_id(op_endpoint(&a.o3));
        x4.set_end_id(op_endpoint(&a.o4));
        let mut y4 = CoverBlock::new();
        y4.set_begin_id(op_endpoint(&a.o6));
        y4.set_end_id(op_endpoint(&a.o2));
        let mut x5 = CoverBlock::new();
        x5.set_begin_id(op_endpoint(&a.o2));
        x5.set_end_id(op_endpoint(&a.o3));
        let mut y5 = CoverBlock::new();
        y5.set_begin_id(op_endpoint(&a.o6));
        y5.set_end_id(op_endpoint(&a.o2));
        let mut x6 = CoverBlock::new();
        x6.set_begin_id(op_endpoint(&a.o5));
        x6.set_end_id(CoverEndpoint::EndMark);
        let mut y6 = CoverBlock::new();
        y6.set_begin_id(op_endpoint(&a.o6));
        y6.set_end_id(op_endpoint(&a.o2));
        let mut x7 = CoverBlock::new();
        x7.set_begin_id(op_endpoint(&a.o6));
        x7.set_end_id(op_endpoint(&a.o2));
        let mut y7 = CoverBlock::new();
        y7.set_begin_id(op_endpoint(&a.o5));
        y7.set_end_id(op_endpoint(&a.o3));
        println!(
            "case=a7_intersect_quadrants|one_one_overlap={}|one_one_disjoint={}|one_one_touch={}|one_two_gap={}|one_two_touch={}|one_two_interval={}|two_two={}",
            i01(x1.intersect_char(&y1)),
            i01(x2.intersect_char(&y2)),
            i01(x3.intersect_char(&y3)),
            i01(x4.intersect_char(&y4)),
            i01(x5.intersect_char(&y5)),
            i01(x6.intersect_char(&y6)),
            i01(x7.intersect_char(&y7))
        );
    }
    {
        let mut g = Graph::new("a8_merge_empty_copy", 0x6700);
        let a = PartA::new(&mut g);
        let mut x = CoverBlock::new();
        let mut y = CoverBlock::new();
        y.set_begin_id(op_endpoint(&a.o6));
        y.set_end_id(op_endpoint(&a.o2));
        x.merge(&y);
        println!(
            "case=a8_merge_empty_copy|merged={}|empty={}|contain={}",
            cbstate(&x), b01(x.empty()), a.contain_samples(&x)
        );
    }
}

// ---------------------------------------------------------------------------
// Part B
// ---------------------------------------------------------------------------

fn run_b1(name: &str, base: u64, with_late_reader: bool) {
    let mut g = Graph::new(name, base);
    let b0 = g.make_block(0);
    let b1 = g.make_block(1);
    g.edge(&b0, &b1);
    let c8 = g.constant(8, 5);
    let c4 = g.constant(4, 7);
    let d = g.make_op("d", OpCode::CPUI_COPY, 1);
    g.set_input(&d, &c8, 0);
    let root = g.unique_out(8, &d);
    g.insert_end(&d, &b1);
    let filler = g.make_op("filler", OpCode::CPUI_INT_ADD, 2);
    g.set_input(&filler, &c4, 0);
    g.set_input(&filler, &c4, 1);
    g.unique_out(4, &filler);
    g.insert_end(&filler, &b1);
    let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 2);
    g.set_input(&m, &root, 0);
    g.set_input(&m, &c4, 1);
    g.unique_out(8, &m);
    g.insert_end(&m, &b1);
    if with_late_reader {
        let r2 = g.make_op("r2", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&r2, &root, 0);
        g.set_input(&r2, &c4, 1);
        g.unique_out(8, &r2);
        g.insert_end(&r2, &b1);
    }
    root.write().unwrap().calc_cover();
    Varnode::update_cover_locked(&root);
    println!(
        "case={}|orders={}|cover={}",
        name,
        g.orders(),
        Graph::cover_text(&root)
    );
}

fn run_b3() {
    let mut g = Graph::new("b3_multiequal_tip_precise", 0x6a00);
    let b0a = g.make_block(0);
    let b0b = g.make_block(1);
    let b1 = g.make_block(2);
    g.edge(&b0a, &b1);
    g.edge(&b0b, &b1);
    let c8 = g.constant(8, 5);
    let c4 = g.constant(4, 7);
    let i0 = g.input(0x30, 4);
    let tdef = g.make_op("tdef", OpCode::CPUI_COPY, 1);
    g.set_input(&tdef, &c8, 0);
    let t1 = g.unique_out(8, &tdef);
    g.insert_end(&tdef, &b0a);
    let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 2);
    g.set_input(&m, &t1, 0);
    g.set_input(&m, &i0, 1);
    g.unique_out(8, &m);
    g.insert_end(&m, &b1);
    let r2 = g.make_op("r2", OpCode::CPUI_INT_ADD, 2);
    g.set_input(&r2, &i0, 0);
    g.set_input(&r2, &c4, 1);
    g.unique_out(8, &r2);
    g.insert_end(&r2, &b1);
    i0.write().unwrap().calc_cover();
    Varnode::update_cover_locked(&i0);
    println!(
        "case=b3_multiequal_tip_precise|orders={}|cover={}",
        g.orders(),
        Graph::cover_text(&i0)
    );
}

fn run_b4() {
    let mut g = Graph::new("b4_merge_wrap_internal", 0x6b00);
    // The MULTIEQUAL lives in a block that must have an in-edge: its slot
    // recursion reads bl.get_in(slot), so the join block cannot be the entry.
    let b_entry = g.make_block(0);
    let b0 = g.make_block(1);
    g.edge(&b_entry, &b0);
    let c8 = g.constant(8, 5);
    let c4 = g.constant(4, 7);
    let da = g.make_op("dA", OpCode::CPUI_COPY, 1);
    g.set_input(&da, &c8, 0);
    let va = g.unique_out(8, &da);
    g.insert_end(&da, &b0);
    let db = g.make_op("dB", OpCode::CPUI_COPY, 1);
    g.set_input(&db, &c8, 0);
    let vb = g.unique_out(8, &db);
    g.insert_end(&db, &b0);
    let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 2);
    g.set_input(&m, &vb, 0);
    g.set_input(&m, &c4, 1);
    g.unique_out(8, &m);
    g.insert_end(&m, &b0);
    va.write().unwrap().calc_cover();
    Varnode::update_cover_locked(&va);
    vb.write().unwrap().calc_cover();
    Varnode::update_cover_locked(&vb);
    let (cover_a, cover_b) = {
        let a_value = va.read().unwrap();
        let b_value = vb.read().unwrap();
        (
            a_value.cover.as_deref().unwrap().clone(),
            b_value.cover.as_deref().unwrap().clone(),
        )
    };
    let cover_a_text = cover_state(&cover_a);
    let cover_b_text = cover_state(&cover_b);
    let mut merged = cover_a.clone();
    merged.merge(&cover_b);
    println!(
        "case=b4_merge_wrap_internal|orders={}|cover_a={}|cover_b={}|merged={}",
        g.orders(),
        cover_a_text,
        cover_b_text,
        cover_state(&merged)
    );
}

fn main() {
    println!("schema=1|fixture=COVER-TWOPIECE-RESIDUAL-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    run_part_a();
    run_b1("b1_wrap_join_multiequal_reader", 0x6800, false);
    run_b1("b2_wrap_then_contained_reader", 0x6900, true);
    run_b3();
    run_b4();
}
