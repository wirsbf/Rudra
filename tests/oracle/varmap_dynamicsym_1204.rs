// VARMAP-DYNAMICSYM-0001: Rudra comparand for the locked Ghidra 12.0.4
// dynamic-symbolization oracle (tests/oracle/varmap_dynamicsym_1204.cc).
// Mirrors the C++ fixture case for case: each case builds the same
// SSA-shaped body (register-space temporaries written by p-code ops at
// explicit addresses with unique-space readers, all inserted into a live
// basic block), runs the production ActionNameVars, and dumps the
// per-HighVariable symbol projection (name, data-type, storage, dynamic
// flag, usepoint) plus the per-case scope census.
//
// The census this fixture locks in:
//   - an explicit HighVariable whose storage already holds another
//     high's Symbol at the same usepoint is symbolized through
//     handleSymbolConflict -> buildDynamicSymbol as a DYNAMIC Symbol
//     named by the shared-counter local ring (iVar3/uVar4),
//   - separate usepoints produce two static Symbols (the uselimit gate),
//   - the implied twin is refused by hasName before linkSymbol runs,
//   - an input and an address-tied varnode attach to the existing entry
//     instead of going dynamic,
//   - the unaffected spacebase input is refused outright.

use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::coreaction::ActionNameVars;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varmap::{symbol_category, ScopeLocal};
use rudra::varnode::{varnode_flags, Varnode};

type VarnodeRef = Arc<RwLock<Varnode>>;

fn base_type(name: &str, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, metatype)))
}

/// The gcc cspec localrange window the C++ oracle's Funcdata carries
/// (x86-64-gcc.cspec: stack [0xfffffffffff0bdc1, 0xffffffffffffffff] plus
/// the [8, 39] param range) — ActionRestructureVarnode's flat window does
/// not model the prototype-derived range, so the fixture installs the
/// production window directly the way resetLocalWindow does.
fn install_scope(fd: &mut Funcdata) {
    let mut scope = ScopeLocal::new();
    scope.stack_grows_negative = true;
    scope.stack_direction = 1;
    scope.local_range = vec![
        (0xfffffffffff0bdc1u64, 0xffffffffffffffffu64),
        (8u64, 39u64),
    ];
    fd.scope = Some(scope);
}

struct Fixture {
    fd: Funcdata,
    varnodes: Vec<VarnodeRef>,
    names: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        install_scope(&mut fd);
        Self { fd, varnodes: Vec::new(), names: Vec::new() }
    }

    fn remember(&mut self, vn: VarnodeRef, name: &str) {
        self.varnodes.push(vn);
        self.names.push(name.to_string());
    }

    fn make_block(&mut self) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
        self.fd.bblocks.add_block(block.clone());
        block
    }

    /// A written register temporary: defined by opc(const) at pc, read by
    /// a COPY at use_pc whose output is a fresh unique temp.  Both ops are
    /// inserted into a live basic block so they register in the
    /// address-keyed op walk that DynamicHash::gatherFirstLevelVars uses.
    fn make_written_op(
        &mut self,
        name: &str,
        size: usize,
        offset: u64,
        pc: u64,
        value: u64,
        use_pc: u64,
    ) -> VarnodeRef {
        let op = self.fd.new_op(1, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let input = self.fd.new_constant(size, value);
        self.fd.op_set_input(&op, input, 0);
        let vn = self.fd.new_varnode_out(size, Address::new(offset), &op);
        let use_op = self.fd.new_op(1, Address::new(use_pc));
        self.fd.op_set_opcode(&use_op, OpCode::CPUI_COPY);
        self.fd.op_set_input(&use_op, vn.clone(), 0);
        let _ = self.fd.new_unique_out(size, &use_op);
        let block = self.make_block();
        self.fd.op_insert_end(&op, &block);
        self.fd.op_insert_end(&use_op, &block);
        self.remember(vn.clone(), name);
        vn
    }

    fn make_written(&mut self, name: &str, size: usize, offset: u64, pc: u64, value: u64) -> VarnodeRef {
        self.make_written_op(name, size, offset, pc, value, pc + 0x10)
    }

    /// Written and implied (the ActionMarkImplied output shape).
    fn make_implied(&mut self, name: &str, size: usize, offset: u64, pc: u64, value: u64) -> VarnodeRef {
        let vn = self.make_written(name, size, offset, pc, value);
        vn.write().unwrap().set_flags(varnode_flags::IMPLIED);
        vn
    }

    fn make_input(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        let vn = self.fd.set_input_varnode(vn);
        self.remember(vn.clone(), name);
        vn
    }

    fn make_spacebase_input(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self.make_input(name, size, offset);
        vn.write().unwrap().set_flags(
            varnode_flags::SPACEBASE | varnode_flags::UNAFFECTED | varnode_flags::DIRECTWRITE,
        );
        vn
    }

    /// An address-tied stack varnode inside the local window.
    fn make_addrtied(&mut self, name: &str, size: usize, stack_offset: u64) -> VarnodeRef {
        let op = self.fd.new_op(1, Address::new(0x1400));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let input = self.fd.new_constant(size, 0x2a);
        self.fd.op_set_input(&op, input, 0);
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Stack, stack_offset);
        vn.write().unwrap().set_flags(varnode_flags::ADDRTIED);
        self.fd.op_set_output(&op, vn.clone());
        let use_op = self.fd.new_op(1, Address::new(0x1410));
        self.fd.op_set_opcode(&use_op, OpCode::CPUI_COPY);
        self.fd.op_set_input(&use_op, vn.clone(), 0);
        let _ = self.fd.new_unique_out(size, &use_op);
        let block = self.make_block();
        self.fd.op_insert_end(&op, &block);
        self.fd.op_insert_end(&use_op, &block);
        self.remember(vn.clone(), name);
        vn
    }

    fn set_type(&self, vn: &VarnodeRef, ct: Arc<Datatype>) {
        vn.write().unwrap().v_type = Some(ct);
    }

    /// Ghidra type_metatype numeric values (type.hh:79-99) for the record.
    fn ghidra_metatype(dt: &Datatype) -> i32 {
        match dt.get_metatype() {
            TypeMetatype::Void => 17,
            TypeMetatype::Spacebase => 16,
            TypeMetatype::Unknown => 15,
            TypeMetatype::Int => 14,
            TypeMetatype::Uint => 13,
            TypeMetatype::Bool => 12,
            TypeMetatype::Code => 11,
            TypeMetatype::Float => 10,
            TypeMetatype::Pointer => 9,
            TypeMetatype::Array => 7,
            TypeMetatype::Enum => 5, // Ghidra ENUM_INT/ENUM_UINT family
            TypeMetatype::Struct => 4,
            TypeMetatype::Union => 3,
            TypeMetatype::PartialEnum => 2,
            TypeMetatype::PartialStruct => 1,
            TypeMetatype::PartialUnion => 0,
        }
    }

    fn type_tag(dt: Option<&Arc<Datatype>>) -> String {
        match dt {
            None => "mt=-1,sz=0,pnb=".to_string(),
            Some(dt) => {
                let mut pnb = String::new();
                dt.print_name_base(&mut pnb);
                format!(
                    "mt={},sz={},pnb={}",
                    Self::ghidra_metatype(dt),
                    dt.get_size(),
                    pnb
                )
            }
        }
    }

    fn entry_dump(&self, high_ptr: usize) -> String {
        let sym_idx = self.fd.high_symbols.get(&high_ptr).copied();
        let scope = match self.fd.scope.as_ref() {
            Some(s) => s,
            None => return "name=none".to_string(),
        };
        match sym_idx {
            None => "none".to_string(),
            Some(idx) => {
                let sym = &scope.symbols[idx];
                let usept = match sym.usepoint {
                    None => "invalid".to_string(),
                    Some(u) => format!("{:x}", u),
                };
                format!(
                    "name={},typ={},cat={},spc={},off={:x},esz={},dyn={},usept={}",
                    sym.name,
                    Self::type_tag(sym.dtype.as_ref()),
                    sym.category,
                    if sym.is_dynamic { "none" } else { sym.space.name() },
                    if sym.is_dynamic { 0 } else { sym.start },
                    sym.size,
                    if sym.is_dynamic { 1 } else { 0 },
                    usept
                )
            }
        }
    }

    fn dump(&self, case: &str, stage: &str) {
        // The BEFORE stage omits the varnode flag section: the
        // mapped-at-creation bit comes from Funcdata::newVarnode's
        // setVarnodeProperties scope-ownership query
        // (funcdata_varnode.cc:26-42), outside this fixture's projection.
        let include_varnodes = stage != "before";
        let mut high_dump = String::from("list=[");
        let mut first = true;
        for (vn, name) in self.varnodes.iter().zip(self.names.iter()) {
            let (high_arc, soff) = {
                let vn_r = vn.read().unwrap();
                let high = vn_r.high.clone();
                match &high {
                    Some(h) => {
                        let soff = h.read().unwrap().get_symbol_offset();
                        (Some(h.clone()), soff)
                    }
                    None => (None, -1),
                }
            };
            if !first {
                high_dump.push(';');
            }
            first = false;
            match high_arc {
                Some(h) => {
                    let ptr = Arc::as_ptr(&h) as usize;
                    high_dump.push_str(&format!(
                        "{{{},sym={{{}}},soff={}}}",
                        name,
                        self.entry_dump(ptr),
                        soff
                    ));
                }
                None => high_dump.push_str(&format!("{{{},sym=none,soff=-1}}", name)),
            }
        }
        high_dump.push(']');

        let mut vn_dump = String::from("list=[");
        let mut first = true;
        if !include_varnodes {
            vn_dump = String::new();
        }
        for (vn, name) in self.varnodes.iter().zip(self.names.iter()) {
            let vn_r = vn.read().unwrap();
            if !first {
                vn_dump.push(';');
            }
            first = false;
            vn_dump.push_str(&format!(
                "{{{},mapped={},input={},persist={}}}",
                name,
                if (vn_r.flags & varnode_flags::MAPPED) != 0 { 1 } else { 0 },
                if vn_r.is_input() { 1 } else { 0 },
                if vn_r.is_persist() { 1 } else { 0 },
            ));
        }
        vn_dump.push(']');

        let (static_count, dynamic_count) = match self.fd.scope.as_ref() {
            Some(scope) => (
                scope.symbols.iter().filter(|s| !s.is_dynamic).count(),
                scope.symbols.iter().filter(|s| s.is_dynamic).count(),
            ),
            None => (0, 0),
        };

        if include_varnodes {
            println!(
                "case={}|stage={}|highs=[{}]|varnodes=[{}]|scope(static={},dynamic={})",
                case, stage, high_dump, vn_dump, static_count, dynamic_count
            );
        } else {
            println!(
                "case={}|stage={}|highs=[{}]|scope(static={},dynamic={})",
                case, stage, high_dump, static_count, dynamic_count
            );
        }
    }

    fn run(&mut self, case: &str) {
        self.fd.set_high_level();
        self.dump(case, "before");
        ActionNameVars::new().apply(&mut self.fd).unwrap();
        self.dump(case, "after");
    }
}

// The printc residual shape: two explicit temporaries at the same
// register storage, both written by ops at instruction 0x1000 — the
// second goes dynamic (uVar4) through handleSymbolConflict ->
// buildDynamicSymbol.
fn run_explicit_conflict_dynamic() {
    let mut fixture = Fixture::new();
    let a = fixture.make_written_op("a", 8, 0x80, 0x1000, 0x2a, 0x1010);
    fixture.set_type(&a, base_type("int", 8, TypeMetatype::Int));
    let b = fixture.make_written_op("b", 8, 0x80, 0x1000, 0x1f, 0x1010);
    fixture.set_type(&b, base_type("uint", 8, TypeMetatype::Uint));
    fixture.run("explicit_conflict_dynamic");
}

// Same storage, def ops at different instructions: two static symbols.
fn run_separate_usepoints_two_statics() {
    let mut fixture = Fixture::new();
    let a = fixture.make_written("a", 8, 0x90, 0x1000, 0x2a);
    fixture.set_type(&a, base_type("int", 8, TypeMetatype::Int));
    let b = fixture.make_written("b", 8, 0x90, 0x2000, 0x1f);
    fixture.set_type(&b, base_type("uint", 8, TypeMetatype::Uint));
    fixture.run("separate_usepoints_two_statics");
}

// The implied twin: refused by hasName before linkSymbol runs.
fn run_implied_conflict_rejected() {
    let mut fixture = Fixture::new();
    let a = fixture.make_written_op("a", 8, 0xa0, 0x1000, 0x2a, 0x1010);
    fixture.set_type(&a, base_type("int", 8, TypeMetatype::Int));
    let c = fixture.make_implied("c", 8, 0xa0, 0x1000, 0x1f);
    fixture.set_type(&c, base_type("uint", 8, TypeMetatype::Uint));
    fixture.run("implied_conflict_rejected");
}

// An irregular register INPUT over an unlimited-use Symbol: attach.
fn run_illegal_input_attach() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0xb0);
    fixture.set_type(&x, base_type("int", 8, TypeMetatype::Int));
    {
        let scope = fixture.fd.scope.as_mut().expect("scope installed");
        let idx = scope.add_symbol(
            AddressSpace::Register,
            "base",
            Some(base_type("int", 8, TypeMetatype::Int)),
            0xb0,
            None,
        );
        let _ = idx;
        let _ = symbol_category::NO_CATEGORY;
    }
    fixture.run("illegal_input_attach");
}

// The unaffected spacebase input: hasName refuses it (variable.cc:743).
fn run_spacebase_input_rejected() {
    let mut fixture = Fixture::new();
    let sp = fixture.make_spacebase_input("sp", 8, 0x20);
    fixture.set_type(&sp, base_type("int", 8, TypeMetatype::Int));
    fixture.run("spacebase_input_rejected");
}

// An address-tied stack varnode over another high's ranged stack Symbol:
// the isAddrTied leg attaches; no dynamic Symbol.
fn run_addrtied_attach_conflict() {
    let mut fixture = Fixture::new();
    let s1 = fixture.make_addrtied("s1", 8, 0xffffffffffffff40);
    fixture.set_type(&s1, base_type("int", 8, TypeMetatype::Int));
    // A second addrtied high at the same slot (def at another instruction).
    let op2 = fixture.fd.new_op(1, Address::new(0x1800));
    fixture.fd.op_set_opcode(&op2, OpCode::CPUI_COPY);
    let input2 = fixture.fd.new_constant(8, 0x33);
    fixture.fd.op_set_input(&op2, input2, 0);
    let s2 = fixture
        .fd
        .vbank
        .create_with_space(8, AddressSpace::Stack, 0xffffffffffffff40);
    s2.write().unwrap().set_flags(varnode_flags::ADDRTIED);
    fixture.fd.op_set_output(&op2, s2.clone());
    let use2 = fixture.fd.new_op(1, Address::new(0x1810));
    fixture.fd.op_set_opcode(&use2, OpCode::CPUI_COPY);
    fixture.fd.op_set_input(&use2, s2.clone(), 0);
    let _ = fixture.fd.new_unique_out(8, &use2);
    let block2 = fixture.make_block();
    fixture.fd.op_insert_end(&op2, &block2);
    fixture.fd.op_insert_end(&use2, &block2);
    fixture.remember(s2.clone(), "s2");
    fixture.set_type(&s2, base_type("uint", 8, TypeMetatype::Uint));
    fixture.run("addrtied_attach_conflict");
}

fn main() {
    run_explicit_conflict_dynamic();
    run_separate_usepoints_two_statics();
    run_implied_conflict_rejected();
    run_illegal_input_attach();
    run_spacebase_input_rejected();
    run_addrtied_attach_conflict();
}
