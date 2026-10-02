// DYNHASH-UNIQUE-ANCHOR-0001: Rudra comparand for the locked Ghidra
// 12.0.4 dynamic-hash unique-anchor oracle (tests/oracle/
// dynhash_anchor_1204.cc).
//
// The C++ twin locks the calcHash(Varnode*, method) sub-graph walk and
// uniqueHash(Varnode*) champion selection per case; this fixture mirrors
// case for case (see the twin's header comment for the oracle line
// references).  Ten cases:
//
//   def_single_reader   base up+down edges, def anchor
//   multi_reader_sort   down-edge sort (ToOpEdge ordering)
//   cast_above          up walk crosses the skip CAST; anchor = the
//                       attached reading op
//   cast_below          down walk crosses the skip CAST
//   double_cast_chain   multi-hop skip loop; mid-chain all-skip fallback
//   skip_no_reader      not-attached fallback bit + gather redirection
//   input_root          unwritten input: no up edge
//   const_root          constant offset folded into the CRC
//   champion_collision  all-method collision: champion from method 0,
//                       hash bits from method 3, position 0/1
//   fold_detach         reader folded away: findVarnode detaches
//
// Projections use stable fixture identities (varnode names, hex
// addresses, decoded hash fields) — never Arc pointers or SeqNums.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::dynamic::DynamicHash;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::{varnode_flags, Varnode};

type VarnodeRef = Arc<RwLock<Varnode>>;

struct Fixture {
    varnodes: Vec<VarnodeRef>,
    names: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        Fixture { varnodes: Vec::new(), names: Vec::new() }
    }

    fn remember(&mut self, vn: VarnodeRef, name: &str) {
        self.varnodes.push(vn);
        self.names.push(name.to_string());
    }

    fn name_of(&self, vn: &VarnodeRef) -> String {
        for (i, candidate) in self.varnodes.iter().enumerate() {
            if Arc::ptr_eq(candidate, vn) {
                return self.names[i].clone();
            }
        }
        "?".to_string()
    }

    fn reg_out(
        &mut self,
        fd: &mut Funcdata,
        name: &str,
        size: usize,
        offset: u64,
        op: &rudra::op::PcodeOpRef,
    ) -> VarnodeRef {
        let vn = fd.new_varnode_out_full(
            size,
            AddressSpace::Register,
            Address::new(offset),
            op,
        );
        self.remember(vn.clone(), name);
        vn
    }

    /// Unwritten register-space input varnode (the Funcdata::newVarnode +
    /// setInputVarnode shape: the input flag is what makes multiple
    /// descendants legal, mirroring varnode.cc:332-336).
    fn reg_in(&mut self, fd: &mut Funcdata, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = fd.vbank.create_with_space(size, AddressSpace::Register, offset);
        let vn = fd.set_input_varnode(vn);
        self.remember(vn.clone(), name);
        vn
    }

    /// Register a constant varnode as a fixture identity (const_root's
    /// mint target).
    fn const_root(&mut self, fd: &mut Funcdata, name: &str, size: usize, val: u64) -> VarnodeRef {
        let vn = fd.new_constant(size, val);
        self.remember(vn.clone(), name);
        vn
    }

    /// calc_hash_vn projection: the H and anchor address for each walk
    /// level 0..3.
    fn dh_lines(&mut self, case_id: &str, name: &str, vn: &VarnodeRef) {
        for method in 0..4u32 {
            let mut dhash = DynamicHash::new();
            dhash.calc_hash_vn(vn, method);
            println!(
                "dh|case={case_id}|vn={name}|method={method}|H=0x{:x}|U=0x{:x}",
                dhash.get_hash(),
                dhash.get_address().as_u64()
            );
        }
    }

    /// unique_hash_vn projection: the minted hash plus every decoded
    /// field (method, opcode, slot, not-attached, position, total).
    fn uh_line(&mut self, case_id: &str, name: &str, vn: &VarnodeRef, fd: &Funcdata) -> u64 {
        let mut dhash = DynamicHash::new();
        dhash.unique_hash_vn(vn, fd);
        let h = dhash.get_hash();
        if h == 0 {
            panic!("unique_hash_vn failed");
        }
        println!(
            "uh|case={case_id}|vn={name}|H=0x{:x}|U=0x{:x}|meth={}|opc={}|slot={}|nat={}|pos={}|tot={}",
            h,
            dhash.get_address().as_u64(),
            DynamicHash::get_method_from_hash(h),
            DynamicHash::get_opcode_from_hash(h),
            DynamicHash::get_slot_from_hash(h),
            if DynamicHash::get_is_not_attached(h) { 1 } else { 0 },
            DynamicHash::get_position_from_hash(h),
            DynamicHash::get_total_from_hash(h),
        );
        h
    }

    fn uh_address(&mut self, vn: &VarnodeRef, fd: &Funcdata) -> Address {
        let mut dhash = DynamicHash::new();
        dhash.unique_hash_vn(vn, fd);
        if dhash.get_hash() == 0 {
            panic!("unique_hash_vn failed");
        }
        dhash.get_address()
    }

    /// find_varnode round-trip on the minted hash (name projection).
    fn find_line(&mut self, case_id: &str, name: &str, addr: Address, h: u64, fd: &Funcdata) {
        let mut dhash = DynamicHash::new();
        let got = dhash.find_varnode(fd, addr, h);
        let got_text = match &got {
            Some(vn) => self.name_of(vn),
            None => "none".to_string(),
        };
        println!(
            "find|case={case_id}|vn={name}|got={got_text}|ok={}",
            if got.is_some() { 1 } else { 0 }
        );
    }

    fn find_line_stage(
        &mut self,
        case_id: &str,
        name: &str,
        stage: &str,
        addr: Address,
        h: u64,
        fd: &Funcdata,
    ) {
        let mut dhash = DynamicHash::new();
        let got = dhash.find_varnode(fd, addr, h);
        let got_text = match &got {
            Some(vn) => self.name_of(vn),
            None => "none".to_string(),
        };
        println!(
            "find|case={case_id}|vn={name}|stage={stage}|got={got_text}|ok={}",
            if got.is_some() { 1 } else { 0 }
        );
    }
}

// ---------------------------------------------------------------------------
// def_single_reader
fn run_def_single_reader(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let op1 = fd.new_op(1, Address::new(0x1000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k11 = fd.new_constant(8, 0x11);
    fd.op_set_input(&op1, k11, 0);
    let c = f.reg_out(fd, "c", 8, 0x80, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x1010));
    fd.op_set_opcode(&op2, OpCode::CPUI_COPY);
    fd.op_set_input(&op2, c.clone(), 0);
    let t = f.reg_out(fd, "t", 8, 0x90, &op2);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0x1020));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, t.clone(), 0);
    let k1 = fd.new_constant(8, 1);
    fd.op_set_input(&op3, k1, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();

    f.dh_lines("def_single_reader", "t", &t);
    let h = f.uh_line("def_single_reader", "t", &t, fd);
    let u = f.uh_address(&t, fd);
    f.find_line("def_single_reader", "t", u, h, fd);
}

// ---------------------------------------------------------------------------
// multi_reader_sort (readers created out of address order)
fn run_multi_reader_sort(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let def_t = fd.new_op(1, Address::new(0x2000));
    fd.op_set_opcode(&def_t, OpCode::CPUI_COPY);
    let k22 = fd.new_constant(8, 0x22);
    fd.op_set_input(&def_t, k22, 0);
    let t = f.reg_out(fd, "t", 8, 0x90, &def_t);
    fd.op_insert_end(&def_t, &block);

    let r3 = fd.new_op(2, Address::new(0x2030));
    fd.op_set_opcode(&r3, OpCode::CPUI_INT_OR);
    fd.op_set_input(&r3, t.clone(), 0);
    let k3 = fd.new_constant(8, 3);
    fd.op_set_input(&r3, k3, 1);
    let _ = fd.new_unique_out(8, &r3);
    fd.op_insert_end(&r3, &block);

    let r1 = fd.new_op(2, Address::new(0x2010));
    fd.op_set_opcode(&r1, OpCode::CPUI_INT_AND);
    fd.op_set_input(&r1, t.clone(), 0);
    let k1 = fd.new_constant(8, 1);
    fd.op_set_input(&r1, k1, 1);
    let _ = fd.new_unique_out(8, &r1);
    fd.op_insert_end(&r1, &block);

    let r2 = fd.new_op(2, Address::new(0x2020));
    fd.op_set_opcode(&r2, OpCode::CPUI_INT_XOR);
    let k2a = fd.new_constant(8, 2);
    fd.op_set_input(&r2, k2a, 0);
    fd.op_set_input(&r2, t.clone(), 1);
    let _ = fd.new_unique_out(8, &r2);
    fd.op_insert_end(&r2, &block);

    fd.set_high_level();

    f.dh_lines("multi_reader_sort", "t", &t);
    let h = f.uh_line("multi_reader_sort", "t", &t, fd);
    let u = f.uh_address(&t, fd);
    f.find_line("multi_reader_sort", "t", u, h, fd);
}

// ---------------------------------------------------------------------------
// cast_above (root = CAST output; the CASTFUSE-adjacent shape)
fn run_cast_above(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let op1 = fd.new_op(1, Address::new(0x3000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k5a = fd.new_constant(8, 0x5a);
    fd.op_set_input(&op1, k5a, 0);
    let c0 = f.reg_out(fd, "c0", 8, 0xa0, &op1);
    c0.write().unwrap().set_flags(varnode_flags::EXPLICIT);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x3010));
    fd.op_set_opcode(&op2, OpCode::CPUI_CAST);
    fd.op_set_input(&op2, c0.clone(), 0);
    let tmp = f.reg_out(fd, "tmp", 8, 0xa8, &op2);
    tmp.write().unwrap().set_flags(varnode_flags::IMPLIED);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0x3020));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, tmp.clone(), 0);
    let k2 = fd.new_constant(8, 2);
    fd.op_set_input(&op3, k2, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();

    f.dh_lines("cast_above", "tmp", &tmp);
    let h = f.uh_line("cast_above", "tmp", &tmp, fd);
    let u = f.uh_address(&tmp, fd);
    f.find_line("cast_above", "tmp", u, h, fd);
}

// ---------------------------------------------------------------------------
// cast_below (root read via a CAST feeding a real op)
fn run_cast_below(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let op1 = fd.new_op(1, Address::new(0x4000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k66 = fd.new_constant(8, 0x66);
    fd.op_set_input(&op1, k66, 0);
    let c0 = f.reg_out(fd, "c0", 8, 0xa0, &op1);
    c0.write().unwrap().set_flags(varnode_flags::EXPLICIT);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x4010));
    fd.op_set_opcode(&op2, OpCode::CPUI_CAST);
    fd.op_set_input(&op2, c0.clone(), 0);
    let tmp = f.reg_out(fd, "tmp", 8, 0xa8, &op2);
    tmp.write().unwrap().set_flags(varnode_flags::IMPLIED);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0x4020));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, tmp.clone(), 0);
    let k4 = fd.new_constant(8, 4);
    fd.op_set_input(&op3, k4, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();

    f.dh_lines("cast_below", "c0", &c0);
    let h = f.uh_line("cast_below", "c0", &c0, fd);
    let u = f.uh_address(&c0, fd);
    f.find_line("cast_below", "c0", u, h, fd);
}

// ---------------------------------------------------------------------------
// double_cast_chain (two roots: mid-chain t1 = all-skip fallback, t2 =
// attached reader anchor)
fn run_double_cast_chain(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let op1 = fd.new_op(1, Address::new(0x5000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k55 = fd.new_constant(8, 0x55);
    fd.op_set_input(&op1, k55, 0);
    let c = f.reg_out(fd, "c", 8, 0x80, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x5010));
    fd.op_set_opcode(&op2, OpCode::CPUI_CAST);
    fd.op_set_input(&op2, c.clone(), 0);
    let t1 = f.reg_out(fd, "t1", 8, 0x88, &op2);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(1, Address::new(0x5020));
    fd.op_set_opcode(&op3, OpCode::CPUI_CAST);
    fd.op_set_input(&op3, t1.clone(), 0);
    let t2 = f.reg_out(fd, "t2", 8, 0x90, &op3);
    fd.op_insert_end(&op3, &block);

    let op4 = fd.new_op(2, Address::new(0x5030));
    fd.op_set_opcode(&op4, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op4, t2.clone(), 0);
    let k7 = fd.new_constant(8, 7);
    fd.op_set_input(&op4, k7, 1);
    let _ = fd.new_unique_out(8, &op4);
    fd.op_insert_end(&op4, &block);

    fd.set_high_level();

    f.dh_lines("double_cast_chain", "t1", &t1);
    let h1 = f.uh_line("double_cast_chain", "t1", &t1, fd);
    let u1 = f.uh_address(&t1, fd);
    f.find_line("double_cast_chain", "t1", u1, h1, fd);

    f.dh_lines("double_cast_chain", "t2", &t2);
    let h2 = f.uh_line("double_cast_chain", "t2", &t2, fd);
    let u2 = f.uh_address(&t2, fd);
    f.find_line("double_cast_chain", "t2", u2, h2, fd);
}

// ---------------------------------------------------------------------------
// skip_no_reader (not-attached fallback + gather redirection)
fn run_skip_no_reader(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let op1 = fd.new_op(1, Address::new(0x6000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k77 = fd.new_constant(8, 0x77);
    fd.op_set_input(&op1, k77, 0);
    let c = f.reg_out(fd, "c", 8, 0x80, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0x6010));
    fd.op_set_opcode(&op2, OpCode::CPUI_CAST);
    fd.op_set_input(&op2, c.clone(), 0);
    let tmp = f.reg_out(fd, "tmp", 8, 0x88, &op2);
    fd.op_insert_end(&op2, &block);

    fd.set_high_level();

    f.dh_lines("skip_no_reader", "tmp", &tmp);
    let h = f.uh_line("skip_no_reader", "tmp", &tmp, fd);
    let u = f.uh_address(&tmp, fd);
    f.find_line("skip_no_reader", "tmp", u, h, fd);
}

// ---------------------------------------------------------------------------
// input_root (unwritten input varnode)
fn run_input_root(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let i = f.reg_in(fd, "i", 8, 0xb0);

    let op1 = fd.new_op(2, Address::new(0x7010));
    fd.op_set_opcode(&op1, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op1, i.clone(), 0);
    let k1 = fd.new_constant(8, 1);
    fd.op_set_input(&op1, k1, 1);
    let _ = fd.new_unique_out(8, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(2, Address::new(0x7020));
    fd.op_set_opcode(&op2, OpCode::CPUI_INT_SUB);
    fd.op_set_input(&op2, i.clone(), 0);
    let k2 = fd.new_constant(8, 2);
    fd.op_set_input(&op2, k2, 1);
    let _ = fd.new_unique_out(8, &op2);
    fd.op_insert_end(&op2, &block);

    fd.set_high_level();

    f.dh_lines("input_root", "i", &i);
    let h = f.uh_line("input_root", "i", &i, fd);
    let u = f.uh_address(&i, fd);
    f.find_line("input_root", "i", u, h, fd);
}

// ---------------------------------------------------------------------------
// const_root (constant folded into the CRC)
fn run_const_root(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let k = f.const_root(fd, "k", 4, 0x1337);

    let op1 = fd.new_op(2, Address::new(0x8010));
    fd.op_set_opcode(&op1, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op1, k.clone(), 0);
    let k1 = fd.new_constant(4, 1);
    fd.op_set_input(&op1, k1, 1);
    let _ = fd.new_unique_out(4, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(2, Address::new(0x8020));
    fd.op_set_opcode(&op2, OpCode::CPUI_INT_MULT);
    let k2 = fd.new_constant(4, 2);
    fd.op_set_input(&op2, k2, 0);
    fd.op_set_input(&op2, k.clone(), 1);
    let _ = fd.new_unique_out(4, &op2);
    fd.op_insert_end(&op2, &block);

    fd.set_high_level();

    f.dh_lines("const_root", "k", &k);
    let h = f.uh_line("const_root", "k", &k, fd);
    let u = f.uh_address(&k, fd);
    f.find_line("const_root", "k", u, h, fd);
}

// ---------------------------------------------------------------------------
// champion_collision (all methods collide; position distinguishes t1/t2)
fn run_champion_collision(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let d1 = fd.new_op(1, Address::new(0x9000));
    fd.op_set_opcode(&d1, OpCode::CPUI_COPY);
    let k91 = fd.new_constant(8, 0x91);
    fd.op_set_input(&d1, k91, 0);
    let t1 = f.reg_out(fd, "t1", 8, 0x90, &d1);
    fd.op_insert_end(&d1, &block);

    let d2 = fd.new_op(1, Address::new(0x9000));
    fd.op_set_opcode(&d2, OpCode::CPUI_COPY);
    let k92 = fd.new_constant(8, 0x92);
    fd.op_set_input(&d2, k92, 0);
    let t2 = f.reg_out(fd, "t2", 8, 0x91, &d2);
    fd.op_insert_end(&d2, &block);

    let r1 = fd.new_op(2, Address::new(0x9010));
    fd.op_set_opcode(&r1, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&r1, t1.clone(), 0);
    let k1 = fd.new_constant(8, 1);
    fd.op_set_input(&r1, k1, 1);
    let _ = fd.new_unique_out(8, &r1);
    fd.op_insert_end(&r1, &block);

    let r2 = fd.new_op(2, Address::new(0x9010));
    fd.op_set_opcode(&r2, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&r2, t2.clone(), 0);
    let k2 = fd.new_constant(8, 2);
    fd.op_set_input(&r2, k2, 1);
    let _ = fd.new_unique_out(8, &r2);
    fd.op_insert_end(&r2, &block);

    fd.set_high_level();

    f.dh_lines("champion_collision", "t1", &t1);
    let h1 = f.uh_line("champion_collision", "t1", &t1, fd);
    let u1 = f.uh_address(&t1, fd);
    f.find_line("champion_collision", "t1", u1, h1, fd);

    f.dh_lines("champion_collision", "t2", &t2);
    let h2 = f.uh_line("champion_collision", "t2", &t2, fd);
    let u2 = f.uh_address(&t2, fd);
    f.find_line("champion_collision", "t2", u2, h2, fd);
}

// ---------------------------------------------------------------------------
// fold_detach (mint, round-trip, fold the reader away, detach)
fn run_fold_detach(fd: &mut Funcdata) {
    let mut f = Fixture::new();

    let block = fd.create_new_block();

    let op1 = fd.new_op(1, Address::new(0xa000));
    fd.op_set_opcode(&op1, OpCode::CPUI_COPY);
    let k2a = fd.new_constant(8, 0x2a);
    fd.op_set_input(&op1, k2a, 0);
    let c = f.reg_out(fd, "c", 8, 0x80, &op1);
    fd.op_insert_end(&op1, &block);

    let op2 = fd.new_op(1, Address::new(0xa010));
    fd.op_set_opcode(&op2, OpCode::CPUI_COPY);
    fd.op_set_input(&op2, c.clone(), 0);
    let t = f.reg_out(fd, "t", 8, 0x90, &op2);
    fd.op_insert_end(&op2, &block);

    let op3 = fd.new_op(2, Address::new(0xa020));
    fd.op_set_opcode(&op3, OpCode::CPUI_INT_ADD);
    fd.op_set_input(&op3, t.clone(), 0);
    let k1 = fd.new_constant(8, 1);
    fd.op_set_input(&op3, k1, 1);
    let _ = fd.new_unique_out(8, &op3);
    fd.op_insert_end(&op3, &block);

    fd.set_high_level();

    f.dh_lines("fold_detach", "t", &t);
    let h = f.uh_line("fold_detach", "t", &t, fd);
    let u = f.uh_address(&t, fd);
    f.find_line_stage("fold_detach", "t", "pre", u, h, fd);

    // The fold: op3 re-reads c (RulePropagateCopy's IR effect).  op2 is
    // left alive-but-dead so the fixture varnodes stay valid (no DCE).
    fd.op_set_input(&op3, c.clone(), 0);

    f.find_line_stage("fold_detach", "t", "postfold", u, h, fd);
}

fn main() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_def_single_reader(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_multi_reader_sort(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_cast_above(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_cast_below(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_double_cast_chain(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_skip_no_reader(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_input_root(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_const_root(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_champion_collision(&mut fd);
    fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    run_fold_detach(&mut fd);
}
