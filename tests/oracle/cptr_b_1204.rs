// B3-COREACTION-CONSTANTPTR-0001 (b): Rugra comparand for the locked
// Ghidra 12.0.4 ActionConstantPtr::apply oracle.
//
// Mirrors tests/oracle/cptr_b_1204.cc record-for-record: the same symbol/
// entry/property table through the production Database paths, the same
// consumer-op shapes (COPY/PTRSUB/INT_ADD/CALL over manually created
// constants), one ActionConstantPtr::apply after set_type_recovery_started,
// and the same observation records (op opcode, per-input space/offset/size/
// spacebase/ptrcheck/type-metatype/charprint, output pointer target, the
// linkSymbolReference answers, the change count).
//
// Case semantics (see the .cc header for the full rationale):
//   w_7180/w_99a8/w_c1d8     invalid-UTF-8 aliases: undefined1 entries,
//                            exact hits -> PTRSUB, &DAT chain.
//   w_ea40/w_11270/w_13ad0   string aliases: char arrays -> PTRSUB with
//                            pointer-to-char output.
//   needexact_mid             mid-entry rejection (cc:1161-1162) with the
//                            post-search setPtrCheck (cc:1208).
//   chararray_mid             the char-array middle exception + the
//                            extra!=0 COPY->INT_ADD(PTRSUB,extra) chain.
//   bounds_low / bitform      cc:1138 / cc:1143 rejections.
//   zero_const / ptrsub_in   cc:1188 / cc:1203-1204 skips (no PtrCheck).
//   intadd_spacebase         the cc:1201 skip.
//   call_locked_ptr /
//   call_locked_notptr /
//   call_no_spec             the cc:1093-1101 CALL arms.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::{Address, Range};
use rudra::arch::Architecture;
use rudra::coreaction::ActionConstantPtr;
use rudra::database::{symbol_flags, Database};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{
    Datatype, TypeArray, TypeBase, TypeMetatype,
};
use rudra::varnode::{addl_flags, varnode_flags, Varnode};

type VarnodeRef = Arc<RwLock<Varnode>>;

fn ghidra_metatype(metatype: TypeMetatype) -> i32 {
    match metatype {
        TypeMetatype::PartialUnion => 0,
        TypeMetatype::PartialStruct => 1,
        TypeMetatype::PartialEnum => 2,
        TypeMetatype::Union => 3,
        TypeMetatype::Struct => 4,
        TypeMetatype::Enum => 5,
        TypeMetatype::Array => 7,
        TypeMetatype::Pointer => 9,
        TypeMetatype::Float => 10,
        TypeMetatype::Code => 11,
        TypeMetatype::Bool => 12,
        TypeMetatype::Uint => 13,
        TypeMetatype::Int => 14,
        TypeMetatype::Unknown => 15,
        TypeMetatype::Spacebase => 16,
        TypeMetatype::Void => 17,
    }
}

fn undefined_type(name: &str, size: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        name.to_string(),
        size,
        TypeMetatype::Unknown,
    )))
}

fn char_type() -> Arc<Datatype> {
    let mut base = TypeBase::new("char".to_string(), 1, TypeMetatype::Int);
    base.flags |= rudra::type_system::datatype::type_flags::CHARTYPE;
    Arc::new(Datatype::Base(base))
}

fn int4_type() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "int4".to_string(),
        4,
        TypeMetatype::Int,
    )))
}

fn array_type(array_of: Arc<Datatype>, num_elements: usize, size: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new(String::new(), size, TypeMetatype::Array),
        array_of,
        num_elements,
    }))
}

fn char_pointer_type() -> Arc<Datatype> {
    // The locked callspec parameter type: char* (pointer size 8, wordsize 1).
    let ptr = rudra::type_system::datatype::TypePointer {
        base: TypeBase::new("char *".to_string(), 8, TypeMetatype::Pointer),
        ptr_to: char_type(),
        wordsize: 1,
    };
    Arc::new(Datatype::Pointer(ptr))
}

struct Fixture {
    fd: Funcdata,
    varnode_names: HashMap<usize, String>,
}

impl Fixture {
    fn varnode_key(vn: &VarnodeRef) -> usize {
        Arc::as_ptr(vn) as usize
    }

    fn varnode_name(&self, vn: &VarnodeRef) -> String {
        match self.varnode_names.get(&Self::varnode_key(vn)) {
            Some(name) => name.clone(),
            // Unregistered varnodes (the rewrite's fresh products) take the
            // space-token fallback, mirroring the C++ side's varnodeName.
            None => Self::varnode_space_token(vn),
        }
    }

    fn remember_varnode(&mut self, vn: VarnodeRef, name: &str) {
        self.varnode_names
            .insert(Self::varnode_key(&vn), name.to_string());
    }

    fn make_constant(&mut self, name: &str, size: usize, value: u64) -> VarnodeRef {
        let vn = self.fd.new_constant(size, value);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_spacebase(&mut self, name: &str) -> VarnodeRef {
        let vn = self.fd.new_spacebase_ptr(AddressSpace::Stack);
        // Ghidra's RSP varnode carries the spacebase flag wherever it is
        // consumed as a base; the fixture pins it explicitly so the cc:1201
        // gate reads the flag in isolation.
        vn.write().unwrap().set_flags(varnode_flags::SPACEBASE);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_op(
        &mut self,
        name: &str,
        opcode: OpCode,
        inputs: usize,
        output_size: usize,
        block: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    ) -> rudra::op::PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(0x4c20));
        self.fd.op_set_opcode(&op, opcode);
        if output_size != 0 {
            let out = self.fd.new_unique_out(output_size, &op);
            self.remember_varnode(out, &format!("{name}_out"));
        }
        self.fd.op_insert_end(&op, block);
        op
    }

    fn set_input(&mut self, op: &rudra::op::PcodeOpRef, vn: VarnodeRef, slot: usize) {
        self.fd.op_set_input(op, vn, slot);
    }

    fn varnode_space_token(vn: &VarnodeRef) -> String {
        vn.read().unwrap().address_space.name().to_string()
    }

    /// One observed op after apply — byte-identical to the C++ dumpOp.
    fn dump_op(&self, case_name: &str, op: &rudra::op::PcodeOpRef) {
        let op_r = op.0.read().unwrap();
        // Numeric opcode (shared enum-value contract with the C++ side;
        // the archive's generated name table is stale).
        let mut line = format!(
            "case={case_name}|op={}|inputs=[",
            op_r.opcode as i32
        );
        let inputs: Vec<Option<VarnodeRef>> =
            (0..op_r.num_input()).map(|i| op_r.get_in(i).cloned()).collect();
        drop(op_r);
        for (i, input) in inputs.iter().enumerate() {
            if i != 0 {
                line.push(',');
            }
            match input {
                None => line.push_str("-{-}"),
                Some(vn) => {
                    let vn_r = vn.read().unwrap();
                    let off_text = if vn_r.address_space.is_unique() {
                        "u".to_string() // unique-space offsets are allocator-order noise
                    } else {
                        format!("0x{:x}", vn_r.get_offset())
                    };
                    line.push_str(&format!(
                        "{}{{sp={},off={},sz={},sb={},pc={}",
                        self.varnode_name(vn),
                        Self::varnode_space_token(vn),
                        off_text,
                        vn_r.get_size(),
                        vn_r.is_spacebase() as i32,
                        ((vn_r.addlflags & addl_flags::PTR_CHECK) != 0) as i32,
                    ));
                    if let Some(dt) = vn_r.get_type() {
                        line.push_str(&format!(
                            ",meta={}",
                            ghidra_metatype(dt.get_metatype())
                        ));
                        if let Datatype::Pointer(tp) = dt.as_ref() {
                            line.push_str(&format!(
                                ",ptro={},char={}",
                                ghidra_metatype(tp.ptr_to.get_metatype()),
                                tp.ptr_to.is_char_print() as i32
                            ));
                        }
                    }
                    line.push('}');
                }
            }
        }
        line.push_str("],output=");
        let out = op.0.read().unwrap().output.clone();
        match out {
            None => line.push('-'),
            Some(outvn) => {
                let out_r = outvn.read().unwrap();
                line.push_str(&format!(
                    "{}{{sz={}",
                    self.varnode_name(&outvn),
                    out_r.get_size()
                ));
                if let Some(dt) = out_r.get_type() {
                    line.push_str(&format!(
                        ",meta={}",
                        ghidra_metatype(dt.get_metatype())
                    ));
                    if let Datatype::Pointer(tp) = dt.as_ref() {
                        line.push_str(&format!(
                            ",ptro={},char={}",
                            ghidra_metatype(tp.ptr_to.get_metatype()),
                            tp.ptr_to.is_char_print() as i32
                        ));
                    }
                }
                line.push('}');
            }
        }
        println!("{line}");
    }
}

fn install_symbols(arch: &mut Architecture) -> Arc<RwLock<Database>> {
    // The driver-shaped .rodata layer: every hugehelp alias address gets a
    // 1-byte DAT entry (undefined1); the string aliases get char arrays.
    let db_arc = Arc::new(RwLock::new(Database::new(false)));
    let global = db_arc.read().unwrap().global_scope_id;
    {
        let mut db = db_arc.write().unwrap();
        db.add_range(
            global,
            Range::new(Address::new(0x7f200000), Address::new(0x7f200fff)).unwrap(),
        );
        db.add_symbol_mapped(global, "DAT_7180", Some(undefined_type("undefined1", 1)),
                             Address::new(0x7180), 1);
        db.add_symbol_mapped(global, "DAT_99a8", Some(undefined_type("undefined1", 1)),
                             Address::new(0x99a8), 1);
        db.add_symbol_mapped(global, "DAT_c1d8", Some(undefined_type("undefined1", 1)),
                             Address::new(0xc1d8), 1);
        db.add_symbol_mapped(global, "s_ea40", Some(array_type(char_type(), 8, 8)),
                             Address::new(0xea40), 8);
        db.add_symbol_mapped(global, "s_11270", Some(array_type(char_type(), 12, 12)),
                             Address::new(0x11270), 12);
        db.add_symbol_mapped(global, "s_13ad0", Some(array_type(char_type(), 6, 6)),
                             Address::new(0x13ad0), 6);
        db.add_symbol_mapped(global, "DAT_exact", Some(undefined_type("undefined16", 16)),
                             Address::new(0x7f200000), 16);
        db.add_symbol_mapped(global, "s_lit", Some(array_type(char_type(), 16, 16)),
                             Address::new(0x7f200100), 16);
        db.add_symbol_mapped(global, "s_call", Some(array_type(char_type(), 8, 8)),
                             Address::new(0x7f200140), 8);
        db.add_symbol_mapped(global, "i_call", Some(int4_type()),
                             Address::new(0x7f200180), 4);
        db.set_property_range(
            symbol_flags::READONLY,
            Range::new(Address::new(0x7f200000), Address::new(0x7f200fff)).unwrap(),
        );
    }
    arch.symboltab = Some(db_arc.clone());
    db_arc
}

fn main() {
    let mut arch = Architecture::new();
    arch.archid = "x86:LE:64:default:gcc".to_string();
    arch.infer_pointers = true;
    arch.infer_ptr_spaces = vec![AddressSpace::Ram];
    let types = arch.ensure_types();
    // The raw shared_default factory starts with an empty alignment map;
    // install the default map (the arch-attach guard's effect,
    // typefactory.rs:2437) before any getBase/findAdd consumer runs, and
    // hand spacebase types the global-scope snapshot (getMap's projection)
    // after the symbol graph exists.
    {
        let mut tf = types.write().unwrap();
        tf.set_default_alignment_map();
    }
    let db_arc = install_symbols(&mut arch);
    types
        .write()
        .unwrap()
        .set_spacebase_scope_source(Some(db_arc));

    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    fd.set_arch(Arc::new(arch));

    let mut fx = Fixture { fd, varnode_names: HashMap::new() };
    let block = fx.fd.create_new_block();

    // --- the six hugehelp alias shapes (COPY consumers, infer_pointers) ---
    let aliases: [(&str, u64); 6] = [
        ("w_7180", 0x7180), ("w_99a8", 0x99a8), ("w_c1d8", 0xc1d8),
        ("w_ea40", 0xea40), ("w_11270", 0x11270), ("w_13ad0", 0x13ad0),
    ];
    let mut alias_ops = Vec::new();
    for (name, addr) in aliases {
        let c = fx.make_constant(name, 8, addr);
        let op = fx.make_op(&format!("{name}_copy"), OpCode::CPUI_COPY, 1, 8, &block);
        fx.set_input(&op, c, 0);
        alias_ops.push(op);
    }

    // --- needexacthit rejection: mid-entry of a non-char entry ---
    let c_mid = fx.make_constant("needexact_mid", 8, 0x7f200008);
    let op_mid = fx.make_op("needexact_mid_copy", OpCode::CPUI_COPY, 1, 8, &block);
    fx.set_input(&op_mid, c_mid, 0);

    // --- char-array middle exception + INT_ADD reuse chain ---
    let c_charmid = fx.make_constant("chararray_mid", 8, 0x7f200108);
    let op_charmid = fx.make_op("chararray_mid_copy", OpCode::CPUI_COPY, 1, 8, &block);
    fx.set_input(&op_charmid, c_charmid, 0);

    // --- pointer range rejection ---
    let c_low = fx.make_constant("bounds_low", 8, 0x100);
    let op_low = fx.make_op("bounds_low_copy", OpCode::CPUI_COPY, 1, 8, &block);
    fx.set_input(&op_low, c_low, 0);

    // --- bit-form rejection (0x1000 is above the lower bound) ---
    let c_bit = fx.make_constant("bitform", 8, 0x1000);
    let op_bit = fx.make_op("bitform_copy", OpCode::CPUI_COPY, 1, 8, &block);
    fx.set_input(&op_bit, c_bit, 0);

    // --- zero constant: skipped before the PtrCheck flag ---
    let c_zero = fx.make_constant("zero_const", 8, 0);
    let op_zero = fx.make_op("zero_const_copy", OpCode::CPUI_COPY, 1, 8, &block);
    fx.set_input(&op_zero, c_zero, 0);

    // --- PTRSUB consumer: skipped before the PtrCheck flag ---
    let c_ptrsub = fx.make_constant("ptrsub_in", 8, 0x7f200000);
    let sb0 = fx.make_spacebase("ptrsub_sb");
    let op_ptrsub = fx.make_op("ptrsub_consumer", OpCode::CPUI_PTRSUB, 2, 8, &block);
    fx.set_input(&op_ptrsub, sb0.clone(), 0);
    fx.set_input(&op_ptrsub, c_ptrsub, 1);

    // --- INT_ADD whose other input is a spacebase: skipped ---
    let c_add = fx.make_constant("intadd_spacebase", 8, 0x7f200000);
    let sb1 = fx.make_spacebase("intadd_sb");
    let op_add = fx.make_op("intadd_consumer", OpCode::CPUI_INT_ADD, 2, 8, &block);
    fx.set_input(&op_add, sb1, 0);
    fx.set_input(&op_add, c_add, 1);

    // --- CALL shapes ---
    let c_callptr = fx.make_constant("call_locked_ptr", 8, 0x7f200140);
    let op_callptr = fx.make_op("call_locked_ptr_call", OpCode::CPUI_CALL, 2, 0, &block);
    let callptr_target = fx.fd.new_constant(8, 0x1000);
    fx.set_input(&op_callptr, callptr_target, 0);
    fx.set_input(&op_callptr, c_callptr.clone(), 1);

    let c_callint = fx.make_constant("call_locked_notptr", 8, 0x7f200180);
    let op_callint = fx.make_op("call_locked_notptr_call", OpCode::CPUI_CALL, 2, 0, &block);
    let callint_target = fx.fd.new_constant(8, 0x1004);
    fx.set_input(&op_callint, callint_target, 0);
    fx.set_input(&op_callint, c_callint, 1);

    let c_callnone = fx.make_constant("call_no_spec", 8, 0x7f200148);
    let op_callnone = fx.make_op("call_no_spec_call", OpCode::CPUI_CALL, 2, 0, &block);
    let callnone_target = fx.fd.new_constant(8, 0x1008);
    fx.set_input(&op_callnone, callnone_target, 0);
    fx.set_input(&op_callnone, c_callnone, 1);

    // Locked callspecs: char* param accepts (cc:1095-1098), int param
    // rejects (cc:1097).
    {
        let charptr = char_pointer_type();
        let void_type = Arc::new(Datatype::Base(TypeBase::new(
            "void".to_string(), 0, TypeMetatype::Void)));
        let mut proto = rudra::fspec::FuncProto::new(String::new(), void_type.clone());
        let mut param = rudra::fspec::ProtoParameter::new(
            "s".to_string(),
            charptr,
            Address::new(0),
        );
        param.flags |= rudra::fspec::protoparam_flags::TYPE_LOCKED;
        proto.parameters.push(param);
        let fc = rudra::fspec::FuncCallSpecs::new_for_op(&op_callptr, proto);
        fx.fd.add_call_specs_owner(Arc::new(RwLock::new(fc)));
    }
    {
        let void_type2 = Arc::new(Datatype::Base(TypeBase::new(
            "void".to_string(), 0, TypeMetatype::Void)));
        let mut proto = rudra::fspec::FuncProto::new(String::new(), void_type2);
        let mut param = rudra::fspec::ProtoParameter::new(
            "n".to_string(),
            int4_type(),
            Address::new(0),
        );
        param.flags |= rudra::fspec::protoparam_flags::TYPE_LOCKED;
        proto.parameters.push(param);
        let fc = rudra::fspec::FuncCallSpecs::new_for_op(&op_callint, proto);
        fx.fd.add_call_specs_owner(Arc::new(RwLock::new(fc)));
    }
    let _ = types;

    // Type recovery must be started (coreaction.cc:1170).
    fx.fd.set_type_recovery_started();

    let mut action = ActionConstantPtr::new();
    let result = action.apply(&mut fx.fd).expect("apply succeeds");
    let count = action.take_count_delta();

    let infer_spaces = fx.fd.arch.as_ref().map(|a| a.infer_ptr_spaces.len()).unwrap_or(0);
    println!("case=setup|arch=x86:LE:64:default:gcc|count={count}|return={result}|infer_spaces={infer_spaces}");

    for (i, (name, _)) in aliases.iter().enumerate() {
        fx.dump_op(name, &alias_ops[i]);
    }
    fx.dump_op("needexact_mid", &op_mid);
    fx.dump_op("chararray_mid", &op_charmid);
    fx.dump_op("bounds_low", &op_low);
    fx.dump_op("bitform", &op_bit);
    fx.dump_op("zero_const", &op_zero);
    fx.dump_op("ptrsub_in", &op_ptrsub);
    fx.dump_op("intadd_spacebase", &op_add);
    fx.dump_op("call_locked_ptr", &op_callptr);
    fx.dump_op("call_locked_notptr", &op_callint);
    fx.dump_op("call_no_spec", &op_callnone);

    // The `&name` channel (linkSymbolReference) reads the merge-created
    // HighVariable — pinned by the a1 query-channel fixture plus the E2E
    // `&DAT_*` rendering rather than this pre-merge action fixture.
}
