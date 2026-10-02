// WORKPKG-UNMAP-TYPEUNION-0003 / CURLCANON-UNIONSTORE-ARBITRATION-0001:
// Rugra comparand for the locked Ghidra 12.0.4 union-store arbitration
// oracle (tests/oracle/typeunion_resolveflow_1204.cc), record for record.
//
// Mirrors the C++ fixture's object graph: the same fixture types (built
// exactly once under the same fixture_rf_* names), the same ops inserted
// into fresh basic blocks of a GetStr-named Funcdata, and the same
// observations through the production entry points:
//
//   - crate::type_system::datatype::{nearest_arrayed_component_forward,
//     nearest_arrayed_component_backward, test_for_array_slack}
//   - crate::unionresolve::{resolve_in_flow, find_resolve}
//   - Datatype::find_truncation over a snapshot of Funcdata::union_map
//   - TypeStruct::score_single_component through resolve_in_flow's
//     Array/Struct arms, including the CALL arm's FuncCallSpecs consult
//     (type.cc:1913-1925) via Funcdata::get_call_specs_of_op
//
// Base types are built through TypeFactory::get_base_named with the
// C++ SleighArchitecture DEFAULT core spellings ("int4", "uint4", "int8",
// "int2"): the C++ fixture's BfdArchitecture has no <coretypes> element
// so buildCoreTypes installs the defaults (sleigh_arch.cc:214-237), while
// the Rust TypeFactory's core table mirrors the Java/headless coreBuiltin
// the canon golden uses. findAdd's named lookup (type.cc:3417-3425) keeps
// these distinct from the core entries on both sides.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::fspec::{protoparam_flags, FuncCallSpecs, FuncProto, ProtoParameter};
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{
    test_for_array_slack, nearest_arrayed_component_backward,
    nearest_arrayed_component_forward, Datatype, TypeField, TypeMetatype,
    UnionResolveMap,
};
use rudra::type_system::typefactory::TypeFactory;
use rudra::unionresolve::{find_resolve, resolve_in_flow};
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<RwLock<Varnode>>;

fn mt_name(m: TypeMetatype) -> &'static str {
    match m {
        TypeMetatype::Int => "int",
        TypeMetatype::Uint => "uint",
        TypeMetatype::Bool => "bool",
        TypeMetatype::Float => "float",
        TypeMetatype::Pointer => "ptr",
        TypeMetatype::Array => "array",
        TypeMetatype::Struct => "struct",
        TypeMetatype::Union => "union",
        TypeMetatype::PartialUnion => "partialunion",
        _ => "unknown",
    }
}

fn field(name: &str, offset: usize, dt: Arc<Datatype>) -> TypeField {
    TypeField {
        name: name.to_string(),
        offset,
        type_ptr: dt,
    }
}

struct FixtureTypes {
    int2: Arc<Datatype>,
    int4: Arc<Datatype>,
    uint4: Arc<Datatype>,
    int8: Arc<Datatype>,
    union_u: Arc<Datatype>,
    union_u2: Arc<Datatype>,
    box_: Arc<Datatype>,
    arr: Arc<Datatype>,
    slack: Arc<Datatype>,
    nest: Arc<Datatype>,
    plain: Arc<Datatype>,
    partial_u2: Arc<Datatype>,
    partial_u: Arc<Datatype>,
    ptr_to_u: Arc<Datatype>,
    ptr_to_int4: Arc<Datatype>,
    ptr_to_box: Arc<Datatype>,
}

impl FixtureTypes {
    fn new(factory: &mut TypeFactory) -> FixtureTypes {
        let int2 = factory
            .get_base_named(2, TypeMetatype::Int, "int2")
            .expect("int2 base");
        let int4 = factory
            .get_base_named(4, TypeMetatype::Int, "int4")
            .expect("int4 base");
        let uint4 = factory
            .get_base_named(4, TypeMetatype::Uint, "uint4")
            .expect("uint4 base");
        let int8 = factory
            .get_base_named(8, TypeMetatype::Int, "int8")
            .expect("int8 base");

        factory.get_type_union("fixture_rf_union");
        let union_u = factory
            .set_union_fields_sized(
                "fixture_rf_union",
                vec![field("a", 0, int4.clone()), field("b", 0, uint4.clone())],
                4,
                4,
            )
            .expect("union U completes");
        factory.get_type_union("fixture_rf_union2");
        let union_u2 = factory
            .set_union_fields_sized(
                "fixture_rf_union2",
                vec![field("c", 0, int2.clone()), field("d", 0, int4.clone())],
                4,
                4,
            )
            .expect("union U2 completes");

        factory.create_struct("fixture_rf_box");
        let box_ = factory
            .set_fields_sized("fixture_rf_box", vec![field("x", 0, int8.clone())], 8, 8)
            .expect("box completes");
        let arr = factory.get_type_array(1, int8.clone());

        factory.create_struct("fixture_rf_slack");
        let int_array2 = factory.get_type_array(2, int4.clone());
        let slack = factory
            .set_fields_sized(
                "fixture_rf_slack",
                vec![
                    field("pad", 0, int4.clone()),
                    field("arr", 4, int_array2),
                    field("tail", 12, int4.clone()),
                ],
                16,
                4,
            )
            .expect("slack completes");
        factory.create_struct("fixture_rf_nest");
        let nest = factory
            .set_fields_sized(
                "fixture_rf_nest",
                vec![field("in", 0, slack.clone()), field("t", 16, int8.clone())],
                24,
                8,
            )
            .expect("nest completes");
        factory.create_struct("fixture_rf_plain");
        let plain = factory
            .set_fields_sized(
                "fixture_rf_plain",
                vec![field("p", 0, int8.clone()), field("q", 8, int8.clone())],
                16,
                8,
            )
            .expect("plain completes");

        let partial_u2 = factory.get_type_partial_union(union_u2.clone(), 0, 2);
        let partial_u = factory.get_type_partial_union(union_u.clone(), 0, 2);
        let ptr_to_u = factory.get_type_pointer(8, union_u.clone(), 1);
        let ptr_to_int4 = factory.get_type_pointer(8, int4.clone(), 1);
        let ptr_to_box = factory.get_type_pointer(8, box_.clone(), 1);

        FixtureTypes {
            int2,
            int4,
            uint4,
            int8,
            union_u,
            union_u2,
            box_,
            arr,
            slack,
            nest,
            plain,
            partial_u2,
            partial_u,
            ptr_to_u,
            ptr_to_int4,
            ptr_to_box,
        }
    }
}

fn emit_walk(label: &str, comp: &rudra::type_system::datatype::ArrayedComponent) {
    match &comp.dtype {
        Some(t) => println!(
            "{}=[{}] newoff={} elSize={}",
            label,
            t.print_raw(),
            comp.newoff,
            comp.elsize
        ),
        None => println!("{}=miss", label),
    }
}

fn run_walk_sweep(ft: &FixtureTypes) {
    emit_walk("walk.fwd.before", &nearest_arrayed_component_forward(&ft.slack, -2));
    emit_walk("walk.fwd.midskip", &nearest_arrayed_component_forward(&ft.slack, 2));
    emit_walk("walk.fwd.nested", &nearest_arrayed_component_forward(&ft.nest, 2));
    emit_walk("walk.fwd.cutoff", &nearest_arrayed_component_forward(&ft.plain, -200));
    emit_walk("walk.bwd.hit", &nearest_arrayed_component_backward(&ft.slack, 6));
    emit_walk("walk.bwd.remain", &nearest_arrayed_component_backward(&ft.nest, 20));
    emit_walk("walk.bwd.cutoff", &nearest_arrayed_component_backward(&ft.slack, 200));

    println!("slack.array={}", test_for_array_slack(ft.arr.as_ref(), 0) as u8);
    println!("slack.fwd={}", test_for_array_slack(ft.slack.as_ref(), -2) as u8);
    println!("slack.bwd={}", test_for_array_slack(ft.slack.as_ref(), 6) as u8);
    println!("slack.nested={}", test_for_array_slack(ft.nest.as_ref(), 20) as u8);
    println!("slack.plain={}", test_for_array_slack(ft.plain.as_ref(), 6) as u8);
    println!("slack.cutoff={}", test_for_array_slack(ft.plain.as_ref(), 200) as u8);
}

struct OpFixture<'a> {
    fd: &'a mut Funcdata,
    block_index: i32,
    pc: u64,
}

impl<'a> OpFixture<'a> {
    fn new(fd: &'a mut Funcdata, base_pc: u64) -> OpFixture<'a> {
        OpFixture {
            fd,
            block_index: 0,
            pc: base_pc,
        }
    }

    fn fresh_block(&mut self) -> BlockRef {
        let index = self.block_index;
        self.block_index += 1;
        let block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            index,
            Address::new(self.pc),
        )));
        self.fd.bblocks.add_block(block.clone());
        block
    }

    fn new_op_in_block(&mut self, inputs: usize) -> PcodeOpRef {
        let pc = self.pc;
        self.pc += 0x10;
        self.fd.new_op(inputs, Address::new(pc))
    }

    // Typed register-space Varnode; `lock` installs the typelock flag
    // (Varnode::updateType(ct,lock,over), varnode.cc:474-487).
    fn typed_reg_vn(
        &mut self,
        ct: &Arc<Datatype>,
        size: usize,
        reg_off: u64,
        lock: bool,
    ) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, reg_off);
        vn.write()
            .unwrap()
            .update_type_lock(ct.clone(), lock, true);
        vn
    }

    // COPY reading `in_vn` at slot 0; the output is a fresh unique
    // Varnode, optionally typelocked to `out_type`.
    fn copy_reading(
        &mut self,
        in_vn: &VnRef,
        out_type: Option<&Arc<Datatype>>,
    ) -> PcodeOpRef {
        let op = self.new_op_in_block(1);
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        self.fd.op_set_input(&op, in_vn.clone(), 0);
        let size = in_vn.read().unwrap().size;
        let out = self.fd.new_unique_out(size, &op);
        if let Some(ct) = out_type {
            out.write().unwrap().update_type_lock(ct.clone(), true, true);
        }
        let block = self.fresh_block();
        self.fd.op_insert_end(&op, &block);
        op
    }

    // Install a FuncCallSpecs on `call_op` with a locked input parameter
    // whose data-type IS `param_type`, and/or a locked output data-type —
    // the state the C++ fixture reaches through FuncProto::setPieces
    // (whose assignParameterStorage provably preserves the 8-byte struct
    // exactly). The Rust side constructs the same observable state
    // directly: a typelocked parameter / locked return type plus the
    // input/output lock bits, with the spec registered on the Funcdata so
    // get_call_specs_of_op finds it by the op identity.
    fn attach_call_specs(
        &mut self,
        call_op: &PcodeOpRef,
        param_type: Option<&Arc<Datatype>>,
        out_type: Option<&Arc<Datatype>>,
        void_type: &Arc<Datatype>,
    ) {
        let mut proto = FuncProto::new(
            "fixture_rf_call".to_string(),
            out_type
                .map(|t| t.clone())
                .unwrap_or_else(|| void_type.clone()),
        );
        if let Some(pt) = param_type {
            let mut p0 =
                ProtoParameter::new("p0".to_string(), pt.clone(), Address::new(0));
            p0.flags |= protoparam_flags::TYPE_LOCKED;
            proto.add_parameter(p0);
        }
        // setPieces locks input, output, and model together
        // (fspec.cc:3849-3851).
        proto.set_input_lock(true);
        proto.set_output_lock(true);
        proto.set_model_lock(true);
        let caller_proto = FuncProto::new(String::new(), void_type.clone());
        let mut fc = FuncCallSpecs::new_for_op(call_op, caller_proto);
        fc.prototype = proto;
        self.fd.add_call_specs(fc);
    }
}

fn run_union_cells(ft: &FixtureTypes, fd: &mut Funcdata) {
    // ---- whole-member arbitration (testSimpleCases COPY arm) ----
    {
        let mut fx = OpFixture::new(fd, 0x5000);
        let vn = fx.typed_reg_vn(&ft.union_u, 4, 0x40, true);
        let op = fx.copy_reading(&vn, None);
        let res = resolve_in_flow(fd, &ft.union_u, &op, 0);
        println!("union.whole.resolve=[{}]", res.print_raw());
        let res = find_resolve(fd, &ft.union_u, &op, 0);
        println!("union.whole.findres=[{}]", res.print_raw());
        let snapshot: UnionResolveMap = fd.union_map.clone();
        let field = ft.union_u.find_truncation(
            0,
            4,
            Some(&op.0.read().unwrap()),
            0,
            Some(&snapshot),
        );
        println!(
            "union.whole.trunc={}",
            if field.is_some() { "hit" } else { "miss" }
        );
    }
    // ---- field-win arbitration (full ScoreUnionFields scoring) ----
    {
        let mut fx = OpFixture::new(fd, 0x6000);
        let vn = fx.typed_reg_vn(&ft.union_u, 4, 0x48, true);
        let op = fx.copy_reading(&vn, Some(&ft.int4));
        let res = resolve_in_flow(fd, &ft.union_u, &op, 0);
        println!("union.field.resolve=[{}]", res.print_raw());
        let res = find_resolve(fd, &ft.union_u, &op, 0);
        println!("union.field.findres=[{}]", res.print_raw());
        let snapshot: UnionResolveMap = fd.union_map.clone();
        match ft.union_u.find_truncation(
            0,
            4,
            Some(&op.0.read().unwrap()),
            0,
            Some(&snapshot),
        ) {
            Some((f, newoff)) => println!("union.field.trunc.hit={} newoff={}", f.name, newoff),
            None => println!("union.field.trunc.hit=miss"),
        }
        let span = ft.union_u.find_truncation(
            0,
            8,
            Some(&op.0.read().unwrap()),
            0,
            Some(&snapshot),
        );
        println!(
            "union.field.trunc.span={}",
            if span.is_some() { "hit" } else { "miss" }
        );
    }
    // ---- pointer-to-union arms (type.cc:1177-1202) ----
    {
        let mut fx = OpFixture::new(fd, 0x7000);
        let vn = fx.typed_reg_vn(&ft.ptr_to_u, 8, 0x50, true);
        let op = fx.copy_reading(&vn, None);
        let res = resolve_in_flow(fd, &ft.ptr_to_u, &op, 0);
        println!("ptr.whole.resolve=[{}]", res.print_raw());
    }
    {
        let mut fx = OpFixture::new(fd, 0x8000);
        let vn = fx.typed_reg_vn(&ft.ptr_to_u, 8, 0x58, true);
        let op = fx.copy_reading(&vn, Some(&ft.ptr_to_int4));
        let res = resolve_in_flow(fd, &ft.ptr_to_u, &op, 0);
        println!("ptr.field.resolve=[{}]", res.print_raw());
    }
}

fn run_score_cells(ft: &FixtureTypes, fd: &mut Funcdata, void_type: &Arc<Datatype>) {
    // box.copy.lock: COPY slot 0 with the OUTPUT typelocked to the parent.
    {
        let mut fx = OpFixture::new(fd, 0x9000);
        let vn = fx.typed_reg_vn(&ft.box_, 8, 0x60, true);
        let op = fx.copy_reading(&vn, Some(&ft.box_));
        let res = resolve_in_flow(fd, &ft.box_, &op, 0);
        println!("box.copy.lock=[{}]", res.print_raw());
    }
    // box.copy.default: unlocked output -> the component.
    {
        let mut fx = OpFixture::new(fd, 0xa000);
        let vn = fx.typed_reg_vn(&ft.box_, 8, 0x68, true);
        let op = fx.copy_reading(&vn, None);
        let res = resolve_in_flow(fd, &ft.box_, &op, 0);
        println!("box.copy.default=[{}]", res.print_raw());
    }
    // box.load.lock: LOAD, address input typelocked pointer-to-parent,
    // slot -1 (the output side).
    {
        let mut fx = OpFixture::new(fd, 0xb000);
        let op = fx.new_op_in_block(2);
        fx.fd.op_set_opcode(&op, OpCode::CPUI_LOAD);
        let space_const = fx.fd.new_constant(1, 0);
        fx.fd.op_set_input(&op, space_const, 0);
        let addr = fx.typed_reg_vn(&ft.ptr_to_box, 8, 0x70, true);
        fx.fd.op_set_input(&op, addr, 1);
        fx.fd.new_unique_out(8, &op);
        let block = fx.fresh_block();
        fx.fd.op_insert_end(&op, &block);
        let res = resolve_in_flow(fd, &ft.box_, &op, -1);
        println!("box.load.lock=[{}]", res.print_raw());
    }
    // box.store.lock: STORE, address input typelocked pointer-to-parent,
    // slot 2 (the value input).
    {
        let mut fx = OpFixture::new(fd, 0xc000);
        let op = fx.new_op_in_block(3);
        fx.fd.op_set_opcode(&op, OpCode::CPUI_STORE);
        let space_const = fx.fd.new_constant(1, 0);
        fx.fd.op_set_input(&op, space_const, 0);
        let addr = fx.typed_reg_vn(&ft.ptr_to_box, 8, 0x78, true);
        fx.fd.op_set_input(&op, addr, 1);
        let value = fx.typed_reg_vn(&ft.box_, 8, 0x80, true);
        fx.fd.op_set_input(&op, value, 2);
        let block = fx.fresh_block();
        fx.fd.op_insert_end(&op, &block);
        let res = resolve_in_flow(fd, &ft.box_, &op, 2);
        println!("box.store.lock=[{}]", res.print_raw());
    }
    // box.call.lock: CALL with the parent at input slot 1 and a REAL
    // FuncCallSpecs whose locked input parameter IS the parent.
    {
        let mut fx = OpFixture::new(fd, 0xd000);
        let op = fx.new_op_in_block(2);
        fx.fd.op_set_opcode(&op, OpCode::CPUI_CALL);
        let target = fx.fd.new_constant(8, 0x1000);
        fx.fd.op_set_input(&op, target, 0);
        let arg = fx.typed_reg_vn(&ft.box_, 8, 0x88, true);
        fx.fd.op_set_input(&op, arg, 1);
        fx.fd.new_unique_out(1, &op);
        let block = fx.fresh_block();
        fx.fd.op_insert_end(&op, &block);
        fx.attach_call_specs(&op, Some(&ft.box_), None, void_type);
        let res = resolve_in_flow(fd, &ft.box_, &op, 1);
        println!("box.call.lock=[{}]", res.print_raw());
    }
    // box.call.default: no call-specs at all (getCallSpecs -> null).
    {
        let mut fx = OpFixture::new(fd, 0xe000);
        let op = fx.new_op_in_block(2);
        fx.fd.op_set_opcode(&op, OpCode::CPUI_CALL);
        let target = fx.fd.new_constant(8, 0x1000);
        fx.fd.op_set_input(&op, target, 0);
        let arg = fx.typed_reg_vn(&ft.box_, 8, 0x90, true);
        fx.fd.op_set_input(&op, arg, 1);
        fx.fd.new_unique_out(1, &op);
        let block = fx.fresh_block();
        fx.fd.op_insert_end(&op, &block);
        let res = resolve_in_flow(fd, &ft.box_, &op, 1);
        println!("box.call.default=[{}]", res.print_raw());
    }
    // box.call.output: CALL writing the parent (slot -1) with a locked
    // output data-type == parent.
    {
        let mut fx = OpFixture::new(fd, 0xf000);
        let op = fx.new_op_in_block(1);
        fx.fd.op_set_opcode(&op, OpCode::CPUI_CALL);
        let target = fx.fd.new_constant(8, 0x1000);
        fx.fd.op_set_input(&op, target, 0);
        let out = fx.fd.new_unique_out(8, &op);
        out.write().unwrap().update_type_lock(ft.box_.clone(), true, true);
        let block = fx.fresh_block();
        fx.fd.op_insert_end(&op, &block);
        fx.attach_call_specs(&op, None, Some(&ft.box_), void_type);
        let res = resolve_in_flow(fd, &ft.box_, &op, -1);
        println!("box.call.output=[{}]", res.print_raw());
    }
    // arr.copy.lock / arr.copy.default: size-1 array parent.
    {
        let mut fx = OpFixture::new(fd, 0x10000);
        let vn = fx.typed_reg_vn(&ft.arr, 8, 0x98, true);
        let op = fx.copy_reading(&vn, Some(&ft.arr));
        let res = resolve_in_flow(fd, &ft.arr, &op, 0);
        println!("arr.copy.lock=[{}]", res.print_raw());
    }
    {
        let mut fx = OpFixture::new(fd, 0x11000);
        let vn = fx.typed_reg_vn(&ft.arr, 8, 0xa0, true);
        let op = fx.copy_reading(&vn, None);
        let res = resolve_in_flow(fd, &ft.arr, &op, 0);
        println!("arr.copy.default=[{}]", res.print_raw());
    }
}

fn run_partial_cells(ft: &FixtureTypes, fd: &mut Funcdata) {
    // pu2.field: partial over a union with a 2-byte field; the implied
    // truncation scores field c and the walk lands on int2 exactly.
    {
        let mut fx = OpFixture::new(fd, 0x12000);
        let vn = fx.typed_reg_vn(&ft.partial_u2, 2, 0xa8, true);
        let op = fx.copy_reading(&vn, Some(&ft.int2));
        let res = resolve_in_flow(fd, &ft.partial_u2, &op, 0);
        println!("pu2.field=[{}]", res.print_raw());
        // pu2.consult: findResolve on the SAME edge reads the cached
        // (union,op,slot) resolution written by the resolveInFlow above.
        let res = find_resolve(fd, &ft.partial_u2, &op, 0);
        println!("pu2.consult=[{}]", res.print_raw());
    }
    // pu4.stripped: partial over a union with only 4-byte fields; the
    // walk falls off the end and returns the stripped twin. The record is
    // name-independent (see the C++ fixture header): the stripped twin's
    // core name is environment-dependent on the C++ side.
    {
        let mut fx = OpFixture::new(fd, 0x13000);
        let vn = fx.typed_reg_vn(&ft.partial_u, 2, 0xb0, true);
        let op = fx.copy_reading(&vn, Some(&ft.int2));
        let res = resolve_in_flow(fd, &ft.partial_u, &op, 0);
        println!(
            "pu4.stripped=size={} mt={}",
            res.get_size(),
            mt_name(res.get_metatype())
        );
    }
}

fn main() {
    // The ORACLE fixture's BfdArchitecture decodes the curl cspec's
    // <data_organization> (x86-64-gcc.cspec:4-24), whose
    // <size_alignment_map> leaves alignMap[0] = -1 (decodeAlignmentMap
    // fills only sizes >= 1, type.cc:4628-4640) — the state that keeps
    // findAdd's size-0 incomplete probes trap-free and preserves
    // alignment = -1 on them, exactly as probe_align measured on the
    // oracle (u_align=-1). The same element is decoded here through the
    // production TypeFactory::decode_data_organization entry (the element
    // tree is built directly through the marshal Element API) so the
    // fixture factory's map is the oracle's map, not the C++ default.
    let mut factory = TypeFactory::new(8);
    {
        let data_organization = {
            let mut root = Element::new();
            root.set_name("data_organization");
            let mut map = Element::new();
            map.set_name("size_alignment_map");
            for (size, alignment) in [(1, 1), (2, 2), (4, 4), (8, 8), (16, 16)] {
                let mut entry = Element::new();
                entry.set_name("entry");
                entry.add_attribute("size", &size.to_string());
                entry.add_attribute("alignment", &alignment.to_string());
                map.add_child(Arc::new(RwLock::new(entry)));
            }
            root.add_child(Arc::new(RwLock::new(map)));
            Arc::new(RwLock::new(root))
        };
        let registry = Arc::new(RwLock::new(IdRegistry::new()));
        let mut decoder = TreeDecoder::new(data_organization, registry);
        factory.decode_data_organization(&mut decoder);
    }
    let ft = FixtureTypes::new(&mut factory);
    let void_type = factory.get_type_void();

    let mut arch = Architecture::new();
    arch.set_types(Arc::new(RwLock::new(factory)));
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    fd.set_arch(Arc::new(arch));

    run_walk_sweep(&ft);
    run_union_cells(&ft, &mut fd);
    run_score_cells(&ft, &mut fd, &void_type);
    run_partial_cells(&ft, &mut fd);
}
