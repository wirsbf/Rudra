//! Rudra twin of `tests/oracle/constseq_stringcopy_1204.cc`.
//!
//! WORKPKG-UNMAP-STRFOLD-0006 / CONSTSEQ-STRINGCOPY-0001: drives the real
//! `RuleStringCopy::applyOp` (constseq.cc:954) over the same eight-case
//! family as the locked Ghidra 12.0.4 oracle fixture and prints the
//! identical stable observation format: per case, the rule-call result, the
//! surviving block ops in block order (opcode, inputs, output varnode and
//! type name), the surviving COPY count, and the internal-string readback
//! through the attached StringManager at the STRINGDATA hash constants.
//!
//! Fixture seams (documented divergences from the C++ harness, both
//! behavior-neutral): the stack-space `newVarnode` form is pub(crate) in
//! Rust, so COPY outputs are built with `vbank.create_with_space` plus the
//! explicit `ADDRTIED|MAPPED` flags mirror of the C++ newVarnode symbol
//! tail's observable flag outcome (the flag path itself is locked by the
//! scopelocal_query/db_localscope_map fixtures); and the architecture is
//! the callother_userop_closure fixture bootstrap (same native
//! SleighArchitecture core-type track as the oracle BfdArchitecture, so
//! factory unknown types spell `xunknown{size}` on both sides).

use std::sync::Arc;
use std::sync::RwLock;

use rudra::action::{action_status, Rule};
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::constseq::RuleStringCopy;
use rudra::funcdata::Funcdata;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::stringmanage::StringManager;
use rudra::type_system::datatype::Datatype;
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::type_system::TypeMetatype;
use rudra::userop::{BUILTIN_STRINGDATA, UserOpManage};
use rudra::varmap::ScopeLocal;
use rudra::varnode::varnode_flags;
use rudra::varnode::Varnode;

fn space_name(spc: AddressSpace) -> &'static str {
    match spc {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Overlay => "overlay",
        AddressSpace::Other(_) => "other",
    }
}

/// Ghidra's OpCode::getName() display strings for the opcodes this fixture
/// observes (opcode.cc get_opname table) — CALLOTHER prints "syscall" and
/// INDIRECT prints "[]" in the 12.0.4 table.
fn opcode_name(code: OpCode) -> &'static str {
    match code {
        OpCode::CPUI_COPY => "copy",
        OpCode::CPUI_PTRSUB => "->",
        OpCode::CPUI_PTRADD => "+",
        OpCode::CPUI_INT_ADD => "+",
        OpCode::CPUI_CALLOTHER => "syscall",
        OpCode::CPUI_INDIRECT => "[]",
        OpCode::CPUI_PIECE => "piece",
        _ => "OTHER",
    }
}

/// Stable observation of one varnode (or '-' for null).
fn vn_state(vn: Option<&Arc<RwLock<Varnode>>>) -> String {
    let Some(vn) = vn else { return "-".to_string() };
    let v = vn.read().unwrap();
    if v.is_constant() {
        return format!("const:{}:{:x}", v.get_size(), v.get_offset());
    }
    let spc = v.get_space();
    if spc == AddressSpace::Iop {
        return "iop".to_string();
    }
    if spc == AddressSpace::Unique {
        let def_name = v
            .get_def()
            .map(|d| opcode_name(d.read().unwrap().opcode))
            .unwrap_or("nodef");
        return format!("unique:def={def_name}");
    }
    format!("{}:{:x}:{}", space_name(spc), v.get_offset(), v.get_size())
}

/// Stable observation of one op: block-order index, opcode, input count,
/// per-slot inputs (up to 3), output varnode and output type name.
fn dump_op(seq: usize, op: &PcodeOpRef) {
    let o = op.0.read().unwrap();
    let mut line = format!(
        "op={}|{}|ins={}",
        seq,
        opcode_name(o.opcode),
        o.inrefs.len()
    );
    for i in 0..o.inrefs.len().min(3) {
        line.push_str(&format!("|a{}={}", i, vn_state(o.inrefs.get(i))));
    }
    match o.get_out() {
        Some(out) => {
            let type_name = out
                .read()
                .unwrap()
                .get_type()
                .map(|t| t.get_name().to_string())
                .unwrap_or_else(|| "-".to_string());
            line.push_str(&format!("|out={}|type={}", vn_state(Some(&out)), type_name));
        }
        None => line.push_str("|out=-|type=-"),
    }
    println!("{line}");
}

/// Dump the whole surviving op list of the block plus the COPY count.
fn dump_block(block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
    let ops = block.read().unwrap().get_ops();
    let mut copies = 0;
    for (seq, op) in ops.iter().enumerate() {
        if op.0.read().unwrap().opcode == OpCode::CPUI_COPY {
            copies += 1;
        }
        dump_op(seq, op);
    }
    println!("alive_ops={}|copies={}", ops.len(), copies);
}

/// Read the internal strings back through the manager at every live
/// STRINGDATA CALLOTHER's hash constant (cumulative across cases, exactly
/// like the C++ side).
fn dump_string_readback(fd: &Funcdata) {
    let mut found = false;
    let sm = fd
        .arch
        .as_ref()
        .and_then(|a| a.string_manager.clone());
    let Some(sm) = sm else {
        println!("string_hash=-");
        return;
    };
    for op in fd.obank.iter_alive() {
        let o = op.0.read().unwrap();
        if o.opcode != OpCode::CPUI_CALLOTHER || o.inrefs.len() != 2 {
            continue;
        }
        let Some(in0) = o.inrefs.first() else { continue };
        if in0.read().unwrap().get_offset() != BUILTIN_STRINGDATA as u64 {
            continue;
        }
        let Some(in1) = o.inrefs.get(1) else { continue };
        let hash = in1.read().unwrap().get_offset();
        found = true;
        drop(o);
        let mut is_trunc = false;
        let bytes = sm
            .read()
            .unwrap()
            .get_string_data(Address::new(hash), 1, false, &mut is_trunc);
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        println!(
            "string_hash={}|bytes={}|trunc={}|len={}",
            hash,
            hex,
            if is_trunc { 1 } else { 0 },
            bytes.len()
        );
    }
    if !found {
        println!("string_hash=-");
    }
}

/// Mirror of the callother_userop_closure fixture's XML element helper.
fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut el = Element::new();
    el.set_name(name);
    for (key, value) in attributes {
        el.add_attribute(key, value);
    }
    Arc::new(RwLock::new(el))
}

/// Mirror of the locked BfdArchitecture TypeFactory state the C++ fixture
/// observes (same bootstrap as tests/oracle/callother_userop_closure_1204.rs):
/// the x86-64-gcc.cspec `<size_alignment_map>`, `setup_sizes` defaults, and
/// the `SleighArchitecture::buildCoreTypes` default core set.
fn configure_factory() -> TypeFactory {
    let mut factory = TypeFactory::raw();

    let alignment_map = element("size_alignment_map", &[]);
    for (size, alignment) in [("1", "1"), ("2", "2"), ("4", "4"), ("8", "8"), ("16", "16")] {
        alignment_map
            .write()
            .unwrap()
            .add_child(element("entry", &[("size", size), ("alignment", alignment)]));
    }
    let organization = element("data_organization", &[]);
    organization.write().unwrap().add_child(alignment_map);
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut organization_decoder = TreeDecoder::new(organization, registry);
    factory.decode_data_organization(&mut organization_decoder);

    // sleigh_arch.cc:215-236 order preserved.
    let core_types: &[(&str, usize, TypeMetatype, bool)] = &[
        ("void", 1, TypeMetatype::Void, false),
        ("bool", 1, TypeMetatype::Bool, false),
        ("uint1", 1, TypeMetatype::Uint, false),
        ("uint2", 2, TypeMetatype::Uint, false),
        ("uint4", 4, TypeMetatype::Uint, false),
        ("uint8", 8, TypeMetatype::Uint, false),
        ("int1", 1, TypeMetatype::Int, false),
        ("int2", 2, TypeMetatype::Int, false),
        ("int4", 4, TypeMetatype::Int, false),
        ("int8", 8, TypeMetatype::Int, false),
        ("float4", 4, TypeMetatype::Float, false),
        ("float8", 8, TypeMetatype::Float, false),
        ("float10", 10, TypeMetatype::Float, false),
        ("float16", 16, TypeMetatype::Float, false),
        ("xunknown1", 1, TypeMetatype::Unknown, false),
        ("xunknown2", 2, TypeMetatype::Unknown, false),
        ("xunknown4", 4, TypeMetatype::Unknown, false),
        ("xunknown8", 8, TypeMetatype::Unknown, false),
        ("code", 1, TypeMetatype::Code, false),
        ("char", 1, TypeMetatype::Int, true),
        ("wchar2", 2, TypeMetatype::Int, true),
        ("wchar4", 4, TypeMetatype::Int, true),
    ];
    for (name, size, meta, chartp) in core_types {
        factory
            .set_core_type_result(name, *size, *meta, *chartp)
            .unwrap_or_else(|message| panic!("core registration {name}: {message}"));
    }
    factory.cache_core_types();

    factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });
    factory
}

/// Per-case builder: a fresh basic block plus constant-character COPY
/// construction into typed stack varnodes.
struct Fixture<'a> {
    fd: &'a mut Funcdata,
    block: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    char_type: Arc<Datatype>,
    code_addr: u64,
    copies: Vec<PcodeOpRef>,
}

impl<'a> Fixture<'a> {
    fn new(fd: &'a mut Funcdata, char_type: Arc<Datatype>, base_code_addr: u64) -> Self {
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(base_code_addr)),
        ));
        fd.bblocks.add_block(block.clone());
        Self {
            fd,
            block,
            char_type,
            code_addr: base_code_addr,
            copies: Vec::new(),
        }
    }

    fn make_copy(&mut self, stack_off: u64, ch: u64) -> PcodeOpRef {
        let op = self.fd.new_op(1, Address::new(self.code_addr));
        self.code_addr += 1;
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let const_vn = self.fd.new_constant(1, ch);
        self.fd.op_set_input(&op, const_vn, 0);
        let vn = self
            .fd
            .vbank
            .create_with_space(1, AddressSpace::Stack, stack_off);
        vn.write().unwrap().update_type(self.char_type.clone());
        // Fixture seam: the observable flag outcome of the C++ newVarnode
        // symbol tail over the fixture's addSymbol-installed entry
        // (setSymbolProperties: entry->getAllFlags() & ~typelock =
        // addrtied|mapped for a whole-map static entry).
        vn.write()
            .unwrap()
            .set_flags(varnode_flags::ADDRTIED | varnode_flags::MAPPED);
        self.fd.op_set_output(&op, vn);
        self.fd.op_insert_end(&op, &self.block);
        self.copies.push(op.clone());
        op
    }

    fn make_wide_copy(&mut self, stack_off: u64, ch: u64) -> PcodeOpRef {
        // A 2-byte COPY output: collectCopyOps must reject it (cc:246-247).
        let op = self.fd.new_op(1, Address::new(self.code_addr));
        self.code_addr += 1;
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let const_vn = self.fd.new_constant(2, ch);
        self.fd.op_set_input(&op, const_vn, 0);
        let vn = self
            .fd
            .vbank
            .create_with_space(2, AddressSpace::Stack, stack_off);
        vn.write().unwrap().update_type(self.char_type.clone());
        vn.write()
            .unwrap()
            .set_flags(varnode_flags::ADDRTIED | varnode_flags::MAPPED);
        self.fd.op_set_output(&op, vn);
        self.fd.op_insert_end(&op, &self.block);
        self.copies.push(op.clone());
        op
    }

    fn make_piece(
        &mut self,
        hi: &Arc<RwLock<Varnode>>,
        lo: &Arc<RwLock<Varnode>>,
        out_size: usize,
    ) -> PcodeOpRef {
        let op = self.fd.new_op(2, Address::new(self.code_addr));
        self.code_addr += 1;
        self.fd.op_set_opcode(&op, OpCode::CPUI_PIECE);
        self.fd.op_set_input(&op, hi.clone(), 0);
        self.fd.op_set_input(&op, lo.clone(), 1);
        self.fd.new_unique_out(out_size, &op);
        self.fd.op_insert_end(&op, &self.block);
        op
    }

    fn make_int_add(&mut self, in0: &Arc<RwLock<Varnode>>) -> PcodeOpRef {
        let op = self.fd.new_op(2, Address::new(self.code_addr));
        self.code_addr += 1;
        self.fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
        self.fd.op_set_input(&op, in0.clone(), 0);
        let c = self.fd.new_constant(2, 0x10);
        self.fd.op_set_input(&op, c, 1);
        self.fd.new_unique_out(2, &op);
        self.fd.op_insert_end(&op, &self.block);
        op
    }

    fn run(&mut self, name: &str, root: &PcodeOpRef) {
        let res = RuleStringCopy::new().apply_op(&root.0, self.fd).unwrap();
        let ret = if res == action_status::CHANGE { 1 } else { 0 };
        println!("case={name}|ret={ret}");
        dump_block(&self.block);
        dump_string_readback(self.fd);
    }
}

fn out_of(op: &PcodeOpRef) -> Arc<RwLock<Varnode>> {
    op.0.read()
        .unwrap()
        .output
        .clone()
        .expect("fixture op has an output")
}

fn main() {
    let factory = Arc::new(RwLock::new(configure_factory()));
    let userops = Arc::new(RwLock::new(UserOpManage::new()));

    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(factory.clone());
    architecture.set_userops(userops.clone());
    architecture.set_string_manager(Arc::new(RwLock::new(StringManager::new(2048))));

    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    fd.set_arch(Arc::new(architecture));
    fd.vbank.set_type_factory(factory.clone());

    // The function's local scope with the fixture symbols (the mirror of the
    // C++ side's addSymbol installs on the BfdArchitecture ScopeLocal).
    let mut scope = ScopeLocal::new();
    {
        let mut f = factory.write().unwrap();
        let char_t = f.get_type_char(1).expect("factory char");
        let arr16 = f.get_type_array(16, char_t.clone());
        scope.add_symbol(AddressSpace::Stack, "name_buf", Some(arr16.clone()), 0x2000, None);
        // struct holder_t { char buf[16]; int len; }
        let buf_arr = f.get_type_array(16, char_t.clone());
        let int4 = f
            .get_base(4, TypeMetatype::Int)
            .expect("factory int4");
        f.create_struct("holder_t");
        let holder = f
            .set_fields_sized(
                "holder_t",
                vec![
                    rudra::type_system::datatype::TypeField {
                        name: "buf".to_string(),
                        offset: 0,
                        type_ptr: buf_arr.clone(),
                    },
                    rudra::type_system::datatype::TypeField {
                        name: "len".to_string(),
                        offset: 16,
                        type_ptr: int4.clone(),
                    },
                ],
                20,
                4,
            )
            .expect("holder_t struct");
        scope.add_symbol(AddressSpace::Stack, "holder", Some(holder), 0x2100, None);
        scope.add_symbol(AddressSpace::Stack, "tail_buf", Some(arr16.clone()), 0x2200, None);
        scope.add_symbol(AddressSpace::Stack, "tiny_buf", Some(arr16.clone()), 0x2300, None);
        scope.add_symbol(AddressSpace::Stack, "order_buf", Some(arr16.clone()), 0x2350, None);
        scope.add_symbol(AddressSpace::Stack, "gap_buf", Some(arr16.clone()), 0x2400, None);
        scope.add_symbol(AddressSpace::Stack, "wide_buf", Some(arr16.clone()), 0x2450, None);
        scope.add_symbol(AddressSpace::Stack, "pair_buf", Some(arr16), 0x2500, None);
    }
    fd.scope = Some(scope);

    let char_type = factory
        .read()
        .unwrap()
        .get_type_char(1)
        .expect("factory char");

    println!("fixture=CONSTSEQ-STRINGCOPY-1204");
    println!("architecture={}", fd.arch.as_ref().unwrap().archid);

    // flat_array: char[16] symbol, "Hello\0" at the symbol start (PTRADD(#0)
    // skipped arm, BUILTIN_STRNCPY selection).
    {
        let mut fx = Fixture::new(&mut fd, char_type.clone(), 0x400000);
        for (i, ch) in b"Hello".iter().enumerate() {
            fx.make_copy(0x2000 + i as u64, *ch as u64);
        }
        fx.make_copy(0x2005, 0);
        let root = fx.copies[0].clone();
        fx.run("flat_array", &root);
    }

    // nested_struct: struct { char buf[16]; int len; } with "World\0" at the
    // struct start (struct-level PTRSUB arm).
    {
        let mut fx = Fixture::new(&mut fd, char_type.clone(), 0x400100);
        for (i, ch) in b"World".iter().enumerate() {
            fx.make_copy(0x2100 + i as u64, *ch as u64);
        }
        fx.make_copy(0x2105, 0);
        let root = fx.copies[0].clone();
        fx.run("nested_struct", &root);
    }

    // array_offset_root: "Tail!\0" starting 2 bytes into the array
    // (PTRADD(prev, 2, 1) arm).
    {
        let mut fx = Fixture::new(&mut fd, char_type.clone(), 0x400200);
        for (i, ch) in b"Tail!".iter().enumerate() {
            fx.make_copy(0x2202 + i as u64, *ch as u64);
        }
        fx.make_copy(0x2207, 0);
        let root = fx.copies[0].clone();
        fx.run("array_offset_root", &root);
    }

    // too_short: "Hi\0" (3 ops < MINIMUM_SEQUENCE_LENGTH), ret=0.
    {
        let mut fx = Fixture::new(&mut fd, char_type.clone(), 0x400300);
        fx.make_copy(0x2300, 'H' as u64);
        fx.make_copy(0x2301, 'i' as u64);
        fx.make_copy(0x2302, 0);
        let root = fx.copies[0].clone();
        fx.run("too_short", &root);
    }

    // root_not_first: rule applied on the second COPY (cc:250-251), ret=0.
    {
        let mut fx = Fixture::new(&mut fd, char_type.clone(), 0x400380);
        for (i, ch) in b"Abcd".iter().enumerate() {
            fx.make_copy(0x2350 + i as u64, *ch as u64);
        }
        fx.make_copy(0x2354, 0);
        let root = fx.copies[1].clone();
        fx.run("root_not_first", &root);
    }

    // gap_in_copies: "ABCD" with a 2-byte gap before "E\0" (gap break +
    // unterminated 4-character run).
    {
        let mut fx = Fixture::new(&mut fd, char_type.clone(), 0x400400);
        for (i, ch) in b"ABCD".iter().enumerate() {
            fx.make_copy(0x2400 + i as u64, *ch as u64);
        }
        fx.make_copy(0x2406, 'E' as u64);
        fx.make_copy(0x2407, 0);
        let root = fx.copies[0].clone();
        fx.run("gap_in_copies", &root);
    }

    // wide_copy: a 2-byte COPY output in the sequence (size guard), ret=0.
    {
        let mut fx = Fixture::new(&mut fd, char_type.clone(), 0x400480);
        fx.make_copy(0x2450, 'O' as u64);
        fx.make_copy(0x2451, 'K' as u64);
        fx.make_wide_copy(0x2452, 'X' as u64);
        fx.make_copy(0x2454, 'Y' as u64);
        fx.make_copy(0x2455, 0);
        let root = fx.copies[0].clone();
        fx.run("wide_copy", &root);
    }

    // concat_cascade: "Pair\0" with two chained PIECEs over the first three
    // COPY outputs and a non-PIECE INT_ADD reader of the fourth
    // (removeForward both arms, dead-PIECE cascade, INDIRECT redefinition).
    {
        let mut fx = Fixture::new(&mut fd, char_type.clone(), 0x400500);
        for (i, ch) in b"Pair".iter().enumerate() {
            fx.make_copy(0x2500 + i as u64, *ch as u64);
        }
        fx.make_copy(0x2504, 0);
        let copy0 = out_of(&fx.copies[0]);
        let copy1 = out_of(&fx.copies[1]);
        let copy2 = out_of(&fx.copies[2]);
        let copy3 = out_of(&fx.copies[3]);
        // piece1 = PIECE(copy1, copy0)
        let piece1 = fx.make_piece(&copy1, &copy0, 2);
        // piece2 = PIECE(piece1_out, copy2)
        let piece1_out = out_of(&piece1);
        fx.make_piece(&piece1_out, &copy2, 3);
        // int_add = INT_ADD(copy3, const) — the surviving non-PIECE point.
        fx.make_int_add(&copy3);
        let root = fx.copies[0].clone();
        fx.run("concat_cascade", &root);
    }
}
