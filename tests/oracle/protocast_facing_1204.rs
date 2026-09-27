// PROTOCAST (CURLCANON-PROTOCAST-INPUTS-0001): Rust side of the locked
// Ghidra 12.0.4 CAST-A facing-type decision fixture
// (protocast_facing_1204.cc). Drives the production arms —
// `ActionSetCasts::{call_input_cast, return_input_cast, store_input_cast}`
// (coreaction.rs mirrors of typeop.cc:295-303 base getInputCast over the
// TypeOpCall/TypeOpReturn/TypeOpStore req-type providers) plus the
// castOutput flipped-role composition (coreaction.cc:2585-2592 via
// TypeOpCall::getOutputLocal typeop.cc:720-735) — and prints the identical
// record stream.
//
// The type universe construction mirrors the oracle fixture: two distinct
// struct objects ("FILE" = the DWARF universe, "_IO_FILE" = the clib
// universe). castStandard compares object identity, never names, so the
// distinct-mint state is the canon golden's provable oracle state.

use std::sync::{Arc, RwLock};

use rugra::address::Address;
use rugra::coreaction::ActionSetCasts;
use rugra::funcdata::Funcdata;
use rugra::fspec::{protoparam_flags, FuncCallSpecs, FuncProto, ProtoParameter};
use rugra::opcodes::OpCode;
use rugra::space::AddressSpace;
use rugra::type_system::datatype::{Datatype, TypeMetatype};
use rugra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rugra::varnode::Varnode;

fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<rugra::marshal::Element>> {
    let mut element = rugra::marshal::Element::new();
    element.set_name(name);
    for (key, value) in attributes {
        element.add_attribute(key, value);
    }
    Arc::new(RwLock::new(element))
}

/// Mirror of the locked BfdArchitecture TypeFactory state (the same
/// configure_factory the TYPEOP-CAST-ARMS fixture pins).
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
    let registry = Arc::new(RwLock::new(rugra::marshal::IdRegistry::new()));
    let mut organization_decoder = rugra::marshal::TreeDecoder::new(organization, registry.clone());
    factory.decode_data_organization(&mut organization_decoder);

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

/// Byte projection of `Datatype::printRaw` shared with the oracle fixture's
/// typeLabel: pointer -> "<pointee> *", named composites keep their name,
/// UNKNOWN bases normalize to `unk<size>`.
fn type_label(datatype: &Datatype) -> String {
    if datatype.get_metatype() == TypeMetatype::Unknown {
        return format!("unk{}", datatype.get_size());
    }
    if let Datatype::Pointer(pointer) = datatype {
        return format!("{} *", type_label(&pointer.ptr_to));
    }
    let name = datatype.get_name().to_string();
    if !name.is_empty() {
        name
    } else {
        format!("unkbyte{}", datatype.get_size())
    }
}

/// The production `attachOwnHigh`: a HighVariable owning the varnode, whose
/// updateType derives the high type from the member instance (variable.cc
/// :400-416 via getTypeRepresentative).
fn attach_own_high(vn: &Arc<RwLock<Varnode>>) {
    let mut guard = vn.write().unwrap();
    let high = Arc::new(RwLock::new(rugra::variable::HighVariable::new(
        guard.get_type().expect("own-high varnode must carry a type"),
    )));
    guard.high = Some(high);
}

/// A locked single-parameter callsite prototype in the setPieces-locked
/// shape (fspec.cc:3843-3852): typelocked+namelocked parameter, input and
/// output locks set — the state the CALLSPEC-COPY fixture pins for the
/// coreaction.cc:2323 fc->copy channel.
fn locked_callsite_proto(
    factory: &Arc<RwLock<TypeFactory>>,
    out_type: Arc<Datatype>,
    param: Option<Arc<Datatype>>,
) -> FuncProto {
    let mut proto = FuncProto::new("fixture_callee".to_string(), out_type.clone());
    proto.output_type_locked = true;
    if let Some(param_type) = param {
        let mut parameter = ProtoParameter::new(
            "fixture_fp".to_string(),
            param_type,
            Address::new(0x1000),
        );
        parameter.flags = protoparam_flags::TYPE_LOCKED | protoparam_flags::NAME_LOCKED;
        proto.add_parameter(parameter);
        proto.set_input_lock(true);
    }
    let _ = factory;
    proto
}

/// Build a CALL op bound to a callsite with the given prototype (the
/// flow.cc:685 setupCallSpecs + coreaction.cc:2323 copy-channel state).
fn build_call_site(
    fd: &mut Funcdata,
    proto: FuncProto,
    pc: u64,
    arg: &Arc<RwLock<Varnode>>,
) -> rugra::op::PcodeOpRef {
    let op = fd.new_op(2, Address::new(pc));
    fd.op_set_opcode(&op, OpCode::CPUI_CALL);
    let owner = Arc::new(RwLock::new(FuncCallSpecs::new(Address::new(pc), proto)));
    // flow.cc:685 qlst.push_back(res): the callspec's lifetime is the
    // Funcdata's callspecs table; the fspec varnode's Weak needs it.
    fd.add_call_specs_owner(owner.clone());
    let fspec_vn = fd.new_varnode_call_specs(&owner);
    fd.op_set_input(&op, fspec_vn, 0);
    fd.op_set_input(&op, arg.clone(), 1);
    op
}

fn main() {
    let factory = Arc::new(RwLock::new(configure_factory()));
    let mut fd = Funcdata::new("protocast_facing", Address::new(0x500000), 0x100);
    fd.vbank.set_type_factory(factory.clone());

    let strategy = rugra::type_system::cast::CastStrategyC::new(4);

    let base = |size: usize, meta: TypeMetatype| -> Arc<Datatype> {
        factory
            .read()
            .unwrap()
            .get_base(size, meta)
            .expect("canonical base type")
    };
    let char_t = factory.read().unwrap().get_type_char(1).expect("char");
    let uint8 = base(8, TypeMetatype::Uint);
    let unknown8 = base(8, TypeMetatype::Unknown);

    let file_dwarf = factory.write().unwrap().create_struct("FILE");
    let file_clib = factory.write().unwrap().create_struct("_IO_FILE");
    let conf_dwarf = factory.write().unwrap().create_struct("Configurable");
    assert!(!Arc::ptr_eq(&file_dwarf, &file_clib), "distinct struct minting failed");

    let pointer = |to: Arc<Datatype>| -> Arc<Datatype> {
        factory.write().unwrap().get_type_pointer(8, to, 1)
    };
    let file_dwarf_ptr = pointer(file_dwarf.clone());
    let file_clib_ptr = pointer(file_clib.clone());
    let conf_dwarf_ptr = pointer(conf_dwarf.clone());
    let char_ptr = pointer(char_t.clone());
    let uint8_ptr = pointer(uint8.clone());
    let file_dwarf_ptr_ptr = pointer(file_dwarf_ptr.clone());
    let file_clib_ptr_ptr = pointer(file_clib_ptr.clone());

    println!("FIXTURE=PROTOCAST-FACING-1204");
    println!("ARCH=x86:LE:64:default:gcc");
    println!(
        "DISTINCT|file_dwarf_ne_file_clib={}",
        if Arc::ptr_eq(&file_dwarf, &file_clib) { 0 } else { 1 }
    );
    println!(
        "DISTINCT|ptr_dwarf_ne_ptr_clib={}",
        if Arc::ptr_eq(&file_dwarf_ptr, &file_clib_ptr) { 0 } else { 1 }
    );

    // A typed free varnode with its own high.
    let typed_vn = |fd: &mut Funcdata, addr: u64, dt: Arc<Datatype>| -> Arc<RwLock<Varnode>> {
        let vn = fd.new_varnode(8, Address::new(addr));
        vn.write().unwrap().v_type = Some(dt);
        attach_own_high(&vn);
        vn
    };

    // ------------------------------------------------------------------
    // Part A — RETURN arm (typeop.cc:901-922 via base getInputCast).
    // ------------------------------------------------------------------
    fd.funcp.return_type = char_ptr.clone();
    let mut ret_distinct_op: Option<rugra::op::PcodeOpRef> = None;
    let mut ret_distinct_mark: Option<Arc<RwLock<Varnode>>> = None;
    let high_type_of = |vn: &Arc<RwLock<Varnode>>| -> Arc<Datatype> {
        vn.read()
            .unwrap()
            .high
            .as_ref()
            .expect("high attached")
            .read()
            .unwrap()
            .get_type()
    };
    fd.funcp.output_type_locked = true;
    {
        let val = typed_vn(&mut fd, 0x40000000, uint8_ptr.clone());
        let op = fd.new_op(2, Address::new(0x500010));
        fd.op_set_opcode(&op, OpCode::CPUI_RETURN);
        let mark = fd.new_varnode(1, Address::new(0x60000000));
        fd.op_set_input(&op, mark.clone(), 0);
        fd.op_set_input(&op, val.clone(), 1);
        ret_distinct_op = Some(op.clone());
        ret_distinct_mark = Some(mark);
        let req = fd.funcp.return_type.clone();
        let cur = high_type_of(&val);
        let result = ActionSetCasts::return_input_cast(&op, 1, &strategy, &fd, &val, 8, &factory);
        println!(
            "DECISION|ret_distinct|req={}|cur={}|result={}",
            type_label(&req),
            type_label(&cur),
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }
    {
        let val = typed_vn(&mut fd, 0x40000010, char_ptr.clone());
        let op = fd.new_op(2, Address::new(0x500020));
        fd.op_set_opcode(&op, OpCode::CPUI_RETURN);
        let mark = fd.new_varnode(1, Address::new(0x60000010));
        fd.op_set_input(&op, mark, 0);
        fd.op_set_input(&op, val.clone(), 1);
        let cur = high_type_of(&val);
        let result = ActionSetCasts::return_input_cast(&op, 1, &strategy, &fd, &val, 8, &factory);
        println!(
            "DECISION|ret_same|cur={}|result={}",
            type_label(&cur),
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }
    {
        fd.funcp.return_type = base(4, TypeMetatype::Int);
        let val = typed_vn(&mut fd, 0x40000020, uint8_ptr.clone());
        let op = fd.new_op(2, Address::new(0x500030));
        fd.op_set_opcode(&op, OpCode::CPUI_RETURN);
        let mark = fd.new_varnode(1, Address::new(0x60000020));
        fd.op_set_input(&op, mark, 0);
        fd.op_set_input(&op, val.clone(), 1);
        let req = fd.funcp.return_type.clone();
        let cur = high_type_of(&val);
        let result = ActionSetCasts::return_input_cast(&op, 1, &strategy, &fd, &val, 8, &factory);
        println!(
            "DECISION|ret_size_mismatch|req={}|cur={}|result={}",
            type_label(&req),
            type_label(&cur),
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
        fd.funcp.return_type = char_ptr.clone();
    }
    {
        let op = ret_distinct_op.expect("ret op constructed");
        let slot0 = {
            let opg = op.0.read().unwrap();
            opg.get_in(0).cloned()
        };
        let result = ActionSetCasts::return_input_cast(&op, 0, &strategy, &fd, &slot0.expect("slot0 wired"), 1, &factory);
        println!(
            "DECISION|ret_slot0|result={}",
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }

    // ------------------------------------------------------------------
    // Part A — CALL arm (typeop.cc:687-718 via base getInputCast).
    // ------------------------------------------------------------------
    {
        let arg = typed_vn(&mut fd, 0x40000100, file_dwarf_ptr.clone());
        let proto = locked_callsite_proto(&factory, char_ptr.clone(), Some(file_clib_ptr.clone()));
        let op = build_call_site(&mut fd, proto, 0x500110, &arg);
        let result = ActionSetCasts::call_input_cast(&op, 1, &strategy, &factory, &fd, &arg, 8);
        println!(
            "DECISION|call_locked_distinct|req={}|cur={}|result={}",
            type_label(&file_clib_ptr),
            type_label(&file_dwarf_ptr),
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }
    {
        let arg = typed_vn(&mut fd, 0x40000110, file_clib_ptr.clone());
        let proto = locked_callsite_proto(&factory, char_ptr.clone(), Some(file_clib_ptr.clone()));
        let op = build_call_site(&mut fd, proto, 0x500120, &arg);
        let result = ActionSetCasts::call_input_cast(&op, 1, &strategy, &factory, &fd, &arg, 8);
        println!(
            "DECISION|call_locked_same|req={}|cur={}|result={}",
            type_label(&file_clib_ptr),
            type_label(&file_clib_ptr),
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }
    {
        let arg = typed_vn(&mut fd, 0x40000120, unknown8.clone());
        let proto = locked_callsite_proto(&factory, char_ptr.clone(), Some(file_clib_ptr.clone()));
        let op = build_call_site(&mut fd, proto, 0x500130, &arg);
        let result = ActionSetCasts::call_input_cast(&op, 1, &strategy, &factory, &fd, &arg, 8);
        println!(
            "DECISION|call_locked_vs_unknown|req={}|cur={}|result={}",
            type_label(&file_clib_ptr),
            type_label(&unknown8),
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }
    {
        // setInternal shape: empty unlocked parameter list, void output.
        let arg = typed_vn(&mut fd, 0x40000130, file_dwarf_ptr.clone());
        let void_t = base(1, TypeMetatype::Void);
        let proto = locked_callsite_proto(&factory, void_t, None);
        let op = build_call_site(&mut fd, proto, 0x500140, &arg);
        let result = ActionSetCasts::call_input_cast(&op, 1, &strategy, &factory, &fd, &arg, 8);
        println!(
            "DECISION|call_unlocked_noparam|cur={}|result={}",
            type_label(&file_dwarf_ptr),
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }
    {
        let arg = typed_vn(&mut fd, 0x40000140, conf_dwarf_ptr.clone());
        let proto = locked_callsite_proto(&factory, char_ptr.clone(), Some(file_dwarf_ptr.clone()));
        let op = build_call_site(&mut fd, proto, 0x500150, &arg);
        let result = ActionSetCasts::call_input_cast(&op, 1, &strategy, &factory, &fd, &arg, 8);
        println!(
            "DECISION|call_conf_vs_file|req={}|cur={}|result={}",
            type_label(&file_dwarf_ptr),
            type_label(&conf_dwarf_ptr),
            result.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }

    // ------------------------------------------------------------------
    // Part A — STORE arm (typeop.cc:520-555).
    // ------------------------------------------------------------------
    {
        let addr = typed_vn(&mut fd, 0x40000200, file_dwarf_ptr_ptr.clone());
        let val = typed_vn(&mut fd, 0x40000210, file_clib_ptr.clone());
        let op = fd.new_op(3, Address::new(0x500210));
        fd.op_set_opcode(&op, OpCode::CPUI_STORE);
        let space_const = fd.new_varnode(8, Address::new(0x60000200));
        fd.op_set_input(&op, space_const, 0);
        fd.op_set_input(&op, addr, 1);
        fd.op_set_input(&op, val, 2);
        let slot2 = ActionSetCasts::store_input_cast(&op, 2, &strategy, &factory, &fd);
        let slot1 = ActionSetCasts::store_input_cast(&op, 1, &strategy, &factory, &fd);
        println!(
            "DECISION|store_distinct|slot2={}|slot1={}",
            slot2.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into()),
            slot1.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }
    {
        let addr = typed_vn(&mut fd, 0x40000220, file_clib_ptr_ptr.clone());
        let val = typed_vn(&mut fd, 0x40000230, file_clib_ptr.clone());
        let op = fd.new_op(3, Address::new(0x500220));
        fd.op_set_opcode(&op, OpCode::CPUI_STORE);
        let space_const = fd.new_varnode(8, Address::new(0x60000220));
        fd.op_set_input(&op, space_const, 0);
        fd.op_set_input(&op, addr, 1);
        fd.op_set_input(&op, val, 2);
        let slot2 = ActionSetCasts::store_input_cast(&op, 2, &strategy, &factory, &fd);
        println!(
            "DECISION|store_same|slot2={}",
            slot2.as_ref().map(|dt| type_label(dt)).unwrap_or_else(|| "NONE".into())
        );
    }

    // ------------------------------------------------------------------
    // Part B — castOutput flipped-role decision (coreaction.cc:2585-2592):
    // token = TypeOpCall::getOutputLocal (typeop.cc:720-735, the callspec's
    // locked non-void output), high = the output varnode's high type, then
    // castStandard(HIGH, token, false, true) — the cast target is the HIGH.
    // ------------------------------------------------------------------
    {
        let out = typed_vn(&mut fd, 0x40000060, conf_dwarf_ptr.clone());
        let proto = locked_callsite_proto(&factory, file_clib_ptr.clone(), None);
        let op = fd.new_op(1, Address::new(0x500060));
        fd.op_set_opcode(&op, OpCode::CPUI_CALL);
        let owner = Arc::new(RwLock::new(FuncCallSpecs::new(Address::new(0x500060), proto)));
        fd.add_call_specs_owner(owner.clone());
        let fspec_vn = fd.new_varnode_call_specs(&owner);
        fd.op_set_input(&op, fspec_vn, 0);
        fd.op_set_output(&op, out.clone());

        let token = {
            let fc = owner.read().unwrap();
            if fc.prototype.output_type_locked
                && fc.prototype.return_type.get_metatype() != TypeMetatype::Void
            {
                fc.prototype.return_type.clone()
            } else {
                unknown8.clone()
            }
        };
        let high = high_type_of(&out);
        if Arc::ptr_eq(&token, &high) {
            println!(
                "OUTCAST|call_out_distinct|token={}|high={}|result=NONE",
                type_label(&token),
                type_label(&high)
            );
        } else {
            let result = strategy
                .cast_standard_full(&high, &token, false, true)
                .map(|_| type_label(&high))
                .unwrap_or_else(|| "NONE".into());
            println!(
                "OUTCAST|call_out_distinct|token={}|high={}|result={}",
                type_label(&token),
                type_label(&high),
                result
            );
        }
    }
    {
        let out = typed_vn(&mut fd, 0x40000070, file_clib_ptr.clone());
        let proto = locked_callsite_proto(&factory, file_clib_ptr.clone(), None);
        let op = fd.new_op(1, Address::new(0x500070));
        fd.op_set_opcode(&op, OpCode::CPUI_CALL);
        let owner = Arc::new(RwLock::new(FuncCallSpecs::new(Address::new(0x500070), proto)));
        fd.add_call_specs_owner(owner.clone());
        let fspec_vn = fd.new_varnode_call_specs(&owner);
        fd.op_set_input(&op, fspec_vn, 0);
        fd.op_set_output(&op, out.clone());

        let token = {
            let fc = owner.read().unwrap();
            if fc.prototype.output_type_locked
                && fc.prototype.return_type.get_metatype() != TypeMetatype::Void
            {
                fc.prototype.return_type.clone()
            } else {
                unknown8.clone()
            }
        };
        let high = high_type_of(&out);
        if Arc::ptr_eq(&token, &high) {
            println!(
                "OUTCAST|call_out_same|token={}|high={}|result=NONE",
                type_label(&token),
                type_label(&high)
            );
        } else {
            let result = strategy
                .cast_standard_full(&high, &token, false, true)
                .map(|_| type_label(&high))
                .unwrap_or_else(|| "NONE".into());
            println!(
                "OUTCAST|call_out_same|token={}|high={}|result={}",
                type_label(&token),
                type_label(&high),
                result
            );
        }
    }

    println!("DONE");
}
