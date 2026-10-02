// VARMAP-GATHEROPEN-GUARD-0001: Rudra comparand for the locked Ghidra 12.0.4
// authoritative gatherOpen/guard oracle.  Mirrors
// tests/oracle/varmap_gatheropen_guard_1204.cc case for case: the same
// default prototype windows (negative-growth 8-byte stack), the same guarded
// LOAD/STORE ops with LoadGuard records in fd.heritage, the same locked /
// category-carrying pre-installed symbols, the same raw stack-pointer reads
// and RETURN value shapes, and the same production call sequence
// (restructure_varnode incl. gatherSymbols re-feed, category clears,
// check_unaliased_return, annotate_raw_stack_ptr) plus a direct
// AliasChecker::gather probe for the deriveBoundaries 511 boundary.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::fspec::ProtoModelFull;
use rudra::funcdata::Funcdata;
use rudra::heritage::LoadGuard;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypePointer};
use rudra::type_system::typefactory::TypeFactory;
use rudra::type_system::TypeMetatype;
use rudra::varmap::{AliasChecker, LocalSymbol, ScopeLocal, symbol_category};

struct GatherOpenScope {
    fd: Funcdata,
    scope: ScopeLocal,
    bb: std::sync::Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
}

impl GatherOpenScope {
    fn new(name: &str, fd_off: u64) -> Self {
        // The default model carries the default windows of a negative-growth
        // 8-byte stack (ProtoModelFull::new mirrors the ProtoModel default
        // constructor, fspec.cc:2339-2353).
        let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
        model.name = "gg_default".to_string();
        let model = Arc::new(model);
        let mut arch = Architecture::new();
        let mut proto_models: BTreeMap<String, Arc<ProtoModelFull>> = BTreeMap::new();
        proto_models.insert("gg_default".to_string(), model.clone());
        arch.proto_models = proto_models;
        arch.defaultfp = Some(model.clone());
        let mut fd = Funcdata::new(name, Address::new(fd_off), 0x20);
        fd.set_arch(Arc::new(arch));
        fd.get_func_proto_mut().set_model(Some(model.clone()));
        let bb = fd.create_new_block();
        let mut scope = ScopeLocal::new();
        scope.reset_local_window(&fd);
        Self { fd, scope, bb }
    }

    /// PcodeOpBank::create starts ops DEAD (op.cc:947); guard validity
    /// (`LoadGuard::isValid`, heritage.hh:169), get_first_return_op and
    /// new_op_before all require live, inserted ops.
    fn insert_op(&mut self, op: &rudra::op::PcodeOpRef) {
        let bb = self.bb.clone();
        self.fd.op_insert(op, &bb, None);
    }

    fn int_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)))
    }
    fn char_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)))
    }
    fn long_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int)))
    }
    fn ptr_to(pt: Arc<Datatype>) -> Arc<Datatype> {
        Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("ptr".into(), 8, TypeMetatype::Pointer),
            ptr_to: pt,
            wordsize: 0,
        }))
    }

    /// A written stack Varnode at `off` holding `ct`, defined by COPY of a
    /// constant — the shape heritage leaves for every stack slot.
    fn stack_copy(&mut self, off: u64, ct: Arc<Datatype>, pc: u64) -> std::sync::Arc<RwLock<rudra::varnode::Varnode>> {
        let op = self.fd.new_op(1, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let cnst = self.fd.new_constant(ct.get_size(), 0x1234);
        self.fd.op_set_input(&op, cnst, 0);
        let vn = self
            .fd
            .vbank
            .create_with_space(ct.get_size(), AddressSpace::Stack, off);
        vn.write().unwrap().v_type = Some(ct);
        self.fd.op_set_output(&op, vn.clone());
        self.insert_op(&op);
        vn
    }

    /// The input stack-pointer Varnode (Rudra's RSP is the Register-space
    /// input at offset 0x20).
    fn spacebase_input(&mut self) -> std::sync::Arc<RwLock<rudra::varnode::Varnode>> {
        let sp = self
            .fd
            .vbank
            .create_with_space(8, AddressSpace::Register, 0x20);
        self.fd.set_input_varnode(sp.clone());
        sp
    }

    /// sp + delta, consumed non-additively (INT_EQUAL) so the sum is an
    /// AliasChecker additive root: the alias source for positive offsets.
    fn spacebase_pointer_add(&mut self, delta: u64, pc: u64) {
        let sp = self.spacebase_input();
        let add = self.fd.new_op(2, Address::new(pc));
        self.fd.op_set_opcode(&add, OpCode::CPUI_INT_ADD);
        self.fd.op_set_input(&add, sp, 0);
        let cnst = self.fd.new_constant(8, delta);
        self.fd.op_set_input(&add, cnst, 1);
        let ptr = self.fd.new_unique(8);
        self.fd.op_set_output(&add, ptr.clone());
        let eq = self.fd.new_op(2, Address::new(pc + 8));
        self.fd.op_set_opcode(&eq, OpCode::CPUI_INT_EQUAL);
        let other = self.fd.new_unique(8);
        self.fd.op_set_input(&eq, other, 1);
        self.fd.op_set_input(&eq, ptr, 0);
        self.insert_op(&add);
        self.insert_op(&eq);
    }

    /// A raw non-additive read of the stack pointer itself (zero-offset
    /// reference) — the annotate_raw_stack_ptr trigger (alias[0] == 0).
    fn raw_stack_ptr_use(&mut self, pc: u64) -> rudra::op::PcodeOpRef {
        let sp = self.spacebase_input();
        let eq = self.fd.new_op(2, Address::new(pc));
        self.fd.op_set_opcode(&eq, OpCode::CPUI_INT_EQUAL);
        let other = self.fd.new_unique(8);
        self.fd.op_set_input(&eq, other, 1);
        self.fd.op_set_input(&eq, sp, 0);
        self.insert_op(&eq);
        eq
    }

    /// A guarded LOAD whose address input is typed as a pointer to `pt`.
    fn guarded_load(&mut self, pt: Arc<Datatype>, outsize: usize, pc: u64) -> rudra::op::PcodeOpRef {
        let op = self.fd.new_op(2, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_LOAD);
        let spaceid = self.fd.new_constant(8, 0);
        self.fd.op_set_input(&op, spaceid, 0);
        let addr = self.fd.new_unique(8);
        addr.write().unwrap().v_type = Some(Self::ptr_to(pt));
        self.fd.op_set_input(&op, addr, 1);
        let out = self.fd.new_unique(outsize);
        self.fd.op_set_output(&op, out);
        self.insert_op(&op);
        op
    }

    /// A guarded STORE whose address input is typed as a pointer to `pt`.
    fn guarded_store(&mut self, pt: Arc<Datatype>, valsize: usize, pc: u64) -> rudra::op::PcodeOpRef {
        let op = self.fd.new_op(3, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_STORE);
        let spaceid = self.fd.new_constant(8, 0);
        self.fd.op_set_input(&op, spaceid, 0);
        let addr = self.fd.new_unique(8);
        addr.write().unwrap().v_type = Some(Self::ptr_to(pt));
        self.fd.op_set_input(&op, addr, 1);
        let val = self.fd.new_constant(valsize, 0x41);
        self.fd.op_set_input(&op, val, 2);
        self.insert_op(&op);
        op
    }

    /// A guarded LOAD whose address input is deliberately UNTYPED — v_type
    /// stays None (the Rust modeling of the oracle newUnique factory
    /// unknown base with no updateType, funcdata_varnode.cc:83-93).  This is
    /// the input shape that drives add_guard's None-ct branch: the factory
    /// unknown base of the address varnode's width stands in for the oracle
    /// value of getIn(1)->getTypeReadFacing (varmap.cc:1009).
    fn untyped_load(&mut self, outsize: usize, pc: u64) -> rudra::op::PcodeOpRef {
        let op = self.fd.new_op(2, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_LOAD);
        let spaceid = self.fd.new_constant(8, 0);
        self.fd.op_set_input(&op, spaceid, 0);
        let addr = self.fd.new_unique(8);
        self.fd.op_set_input(&op, addr, 1);
        let out = self.fd.new_unique(outsize);
        self.fd.op_set_output(&op, out);
        self.insert_op(&op);
        op
    }

    /// A guarded STORE whose address input is deliberately UNTYPED.
    fn untyped_store(&mut self, valsize: usize, pc: u64) -> rudra::op::PcodeOpRef {
        let op = self.fd.new_op(3, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_STORE);
        let spaceid = self.fd.new_constant(8, 0);
        self.fd.op_set_input(&op, spaceid, 0);
        let addr = self.fd.new_unique(8);
        self.fd.op_set_input(&op, addr, 1);
        let val = self.fd.new_constant(valsize, 0x41);
        self.fd.op_set_input(&op, val, 2);
        self.insert_op(&op);
        op
    }

    /// Append a LoadGuard record (the shape Heritage's guard loads/stores
    /// leave behind, heritage.hh:159-161 `set`).
    fn add_guard_record(
        &mut self,
        op: &rudra::op::PcodeOpRef,
        step: i32,
        minimum: u64,
        maximum: u64,
        range_locked: bool,
        is_store: bool,
    ) {
        let mut guard = LoadGuard::new_unanalyzed(&op.0, AddressSpace::Stack, 0);
        guard.step = step;
        guard.minimum_offset = minimum;
        guard.maximum_offset = maximum;
        guard.analysis_state = if range_locked { 2 } else { 1 };
        if is_store {
            self.fd.heritage.store_guard.push(guard);
        } else {
            self.fd.heritage.load_guard.push(guard);
        }
    }

    /// Install a Symbol with explicit lock flags and category (the shape
    /// locked DWARF/localdb symbols present before restructure_varnode).
    fn install_symbol(
        &mut self,
        name: &str,
        ct: Arc<Datatype>,
        off: u64,
        typelock: bool,
        namelock: bool,
        cat: i32,
    ) {
        let mut sym = LocalSymbol::new(name, off, ct.get_size() as i32, Some(ct), symbol_category::NO_CATEGORY);
        sym.typelock = typelock;
        sym.namelock = namelock;
        let idx = self.scope.install_symbol_addmap(sym, &|_, _| 0, None);
        if cat >= 0 {
            let ind = self.scope.get_category_size(cat) as i32;
            self.scope.set_category(idx, cat, ind);
        }
    }

    /// A RETURN op passing `vn` back as the return value (RETURN in(1)).
    fn return_op(&mut self, vn: &std::sync::Arc<RwLock<rudra::varnode::Varnode>>, pc: u64) {
        let op = self.fd.new_op(2, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_RETURN);
        let ind = self.fd.new_constant(8, 0);
        self.fd.op_set_input(&op, ind, 0);
        self.fd.op_set_input(&op, vn.clone(), 1);
        self.insert_op(&op);
    }

    /// Render the scope's symbols as `start:size:typename` in map-entry
    /// order (the scope maptable's rangemap list order — sorted by
    /// (first,last); stable sort keeps insertion order for equal keys, the
    /// std::multiset equivalent-element order), arrays as `element[num]`.
    fn ordered_entry_indices(scope: &ScopeLocal) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..scope.mapentry_log.len()).collect();
        idx.sort_by_key(|&i| (scope.mapentry_log[i].start, scope.mapentry_log[i].size));
        idx
    }

    fn symbols_text(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for i in Self::ordered_entry_indices(&self.scope) {
            let entry = &self.scope.mapentry_log[i];
            let sym = match self.scope.symbols.get(entry.sym) {
                Some(s) => s,
                None => continue,
            };
            let type_name = match sym.dtype.as_deref() {
                Some(Datatype::Array(a)) => {
                    format!("{}[{}]", a.array_of.get_name(), a.num_elements)
                }
                Some(dt) => dt.get_name().to_string(),
                None => "?".to_string(),
            };
            parts.push(format!("{:x}:{}:{}", entry.start, entry.size, type_name));
        }
        parts.join(";")
    }

    /// Render the scope's symbol names in map-entry order.
    fn symbol_names_text(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for i in Self::ordered_entry_indices(&self.scope) {
            let entry = &self.scope.mapentry_log[i];
            if let Some(sym) = self.scope.symbols.get(entry.sym) {
                parts.push(sym.name.clone());
            }
        }
        parts.join(";")
    }

    /// Render the scope's symbols with canonical type tokens — the
    /// untyped-arm comparand projection `start:size:unkA[num]` (element
    /// token then element count for arrays), mirroring
    /// symbols_token_text in the .cc fixture.
    fn symbols_token_text(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for i in Self::ordered_entry_indices(&self.scope) {
            let entry = &self.scope.mapentry_log[i];
            let sym = match self.scope.symbols.get(entry.sym) {
                Some(s) => s,
                None => continue,
            };
            let type_tok = match sym.dtype.as_deref() {
                Some(Datatype::Array(a)) => {
                    format!("{}[{}]", type_token(a.array_of.as_ref()), a.num_elements)
                }
                Some(dt) => type_token(dt),
                None => "null".to_string(),
            };
            parts.push(format!("{:x}:{}:{}", entry.start, entry.size, type_tok));
        }
        parts.join(";")
    }
}

fn pairs_text(pairs: &[(u64, u64)]) -> String {
    pairs
        .iter()
        .map(|&(first, last)| format!("{:x}-{:x}", first, last))
        .collect::<Vec<_>>()
        .join(";")
}

/// Canonical cross-fixture type projection: the Rust factory spells its
/// unknown bases "undefinedN" while the oracle fixture spells them
/// "xunknownN" — both TYPE_UNKNOWN of the same width — so the untyped-arm
/// cases print metatype + element width, never the name.
fn type_token(dt: &Datatype) -> String {
    if dt.get_metatype() == TypeMetatype::Unknown {
        format!("unk{}", dt.get_align_size())
    } else {
        format!("other:{}", dt.get_name())
    }
}

// case=guard_open_hints
fn run_guard_open_hints() {
    let mut t = GatherOpenScope::new("guard_open_hints", 0xa000);
    let locked = t.guarded_load(GatherOpenScope::int_t(), 4, 0x2000);
    t.add_guard_record(&locked, 4, 0xffffffffffffffe0, 0xffffffffffffffff, true, false);
    let unanalyzed = t.guarded_load(GatherOpenScope::int_t(), 4, 0x2010);
    t.add_guard_record(&unanalyzed, 4, 0xffffffffffffffe0, 0xffffffffffffffff, false, false);
    let store = t.guarded_store(GatherOpenScope::char_t(), 1, 0x2020);
    t.add_guard_record(&store, 1, 0xffffffffffffffc0, 0xffffffffffffffff, false, true);
    let rejected = t.guarded_load(GatherOpenScope::int_t(), 8, 0x2030);
    t.add_guard_record(&rejected, 4, 0xfffffffffffffff8, 0xffffffffffffffff, true, false);
    // aliasyes=true mirrors the .cc restructureVarnode(true).
    t.scope.restructure_varnode(&mut t.fd, true);
    println!("case=guard_open_hints|symbols=[{}]", t.symbols_text());
}

// case=gather_symbols_reinput
fn run_gather_symbols_reinput() {
    let mut t = GatherOpenScope::new("gather_symbols_reinput", 0xa100);
    t.install_symbol("locked_local", GatherOpenScope::long_t(), 0xffffffffffffffd0, true, true, -1);
    t.stack_copy(0xffffffffffffffd0, GatherOpenScope::long_t(), 0x2100);
    t.stack_copy(0xffffffffffffffc0, GatherOpenScope::int_t(), 0x2108);
    t.scope.restructure_varnode(&mut t.fd, true);
    println!(
        "case=gather_symbols_reinput|symbols=[{}]|names=[{}]",
        t.symbols_text(),
        t.symbol_names_text()
    );
}

// case=category_clears
fn run_category_clears() {
    let mut t = GatherOpenScope::new("category_clears", 0xa200);
    t.install_symbol("unlocked_param", GatherOpenScope::int_t(), 0x10, false, false, symbol_category::FUNCTION_PARAMETER);
    t.install_symbol("locked_param", GatherOpenScope::int_t(), 0x20, true, true, symbol_category::FUNCTION_PARAMETER);
    t.install_symbol("old_fake", GatherOpenScope::int_t(), 0x30, false, false, symbol_category::FAKE_INPUT);
    t.scope.restructure_varnode(&mut t.fd, true);
    println!("case=category_clears|names=[{}]", t.symbol_names_text());
}

// case=check_unaliased_return
fn run_check_unaliased_return() {
    let mut t = GatherOpenScope::new("check_unaliased_return", 0xa300);
    let retvn = t.stack_copy(0x30, GatherOpenScope::long_t(), 0x2200);
    t.spacebase_pointer_add(0x10, 0x2210);
    t.return_op(&retvn, 0x2220);
    t.scope.restructure_varnode(&mut t.fd, true);
    let marked = pairs_text(&t.scope.local_range);

    let mut t2 = GatherOpenScope::new("check_unaliased_return_aliased", 0xa400);
    let retvn2 = t2.stack_copy(0x30, GatherOpenScope::long_t(), 0x2300);
    t2.spacebase_pointer_add(0x34, 0x2310);
    t2.return_op(&retvn2, 0x2320);
    t2.scope.restructure_varnode(&mut t2.fd, true);
    let unmarked = pairs_text(&t2.scope.local_range);

    println!(
        "case=check_unaliased_return|marked=[{}]|unmarked=[{}]",
        marked, unmarked
    );
}

// case=annotate_raw_stack_ptr
fn run_annotate_raw_stack_ptr() {
    let mut t = GatherOpenScope::new("annotate_raw_stack_ptr", 0xa500);
    t.fd.set_type_recovery_started();
    let eq = t.raw_stack_ptr_use(0x2400);
    t.stack_copy(0xfffffffffffffff8, GatherOpenScope::long_t(), 0x2410);
    t.scope.restructure_varnode(&mut t.fd, true);
    let desc = {
        let eq_op = eq.0.read().unwrap();
        let in0 = eq_op.inrefs[0].clone();
        let in0_v = in0.read().unwrap();
        match in0_v.def.as_ref().and_then(|w| w.upgrade()) {
            Some(def) => {
                let d = def.read().unwrap();
                if d.opcode == OpCode::CPUI_PTRSUB {
                    let c = d.inrefs[1].read().unwrap();
                    format!("ptrsub:{}", c.get_offset())
                } else {
                    "none".to_string()
                }
            }
            None => "none".to_string(),
        }
    };
    println!("case=annotate_raw_stack_ptr|def={}", desc);
}

// case=derive_boundaries
fn run_derive_boundaries() {
    let mut t = GatherOpenScope::new("derive_boundaries", 0xa600);
    t.spacebase_pointer_add(0x200, 0x2500);
    t.spacebase_pointer_add(0x300, 0x2520);
    let mut checker = AliasChecker::new(1);
    checker.gather(&t.fd, true, false);
    let (local, extreme, alias_boundary) = checker.boundaries();
    let probes = {
        let t_ref = &mut t;
        let mut probe = |off: u64| -> u8 {
            let vn = t_ref
                .fd
                .vbank
                .create_with_space(8, AddressSpace::Stack, off);
            let v = vn.read().unwrap();
            if checker.has_local_alias(&v) { 1 } else { 0 }
        };
        format!("{},{},{}", probe(0x1ff), probe(0x200), probe(0xffffffffffff8000))
    };
    let aliases = checker
        .get_aliases()
        .iter()
        .map(|a| format!("{:x}", a))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "case=derive_boundaries|local={:x}|extreme={:x}|aliasboundary={:x}|aliases=[{}]|probes={}",
        local, extreme, alias_boundary, aliases, probes
    );
}

// case=guard_untyped_hints — add_guard's None-ct arm through the production
// path (the .cc fixture's case 7): a range-locked LOAD with step == element
// width keeps the address width (unk8, minItems 15); an unanalyzed LOAD
// whose outSize divides the step re-steps to 4 and re-types to unk4; an
// unanalyzed STORE re-types to unk2 and extends up to the next hint; an
// outSize>step LOAD stays rejected and leaves no trace.
fn run_guard_untyped_hints() {
    let mut t = GatherOpenScope::new("guard_untyped_hints", 0xa700);
    let locked = t.untyped_load(8, 0x2600);
    t.add_guard_record(&locked, 8, 0xffffffffffffff80, 0xffffffffffffffff, true, false);
    let unanalyzed = t.untyped_load(4, 0x2610);
    t.add_guard_record(&unanalyzed, 8, 0xffffffffffffff40, 0xffffffffffffffff, false, false);
    let store = t.untyped_store(2, 0x2620);
    t.add_guard_record(&store, 2, 0xffffffffffffff20, 0xffffffffffffffff, false, true);
    let rejected = t.untyped_load(16, 0x2630);
    t.add_guard_record(&rejected, 8, 0xfffffffffffffff8, 0xffffffffffffffff, true, false);
    t.scope.restructure_varnode(&mut t.fd, true);
    println!("case=guard_untyped_hints|symbols=[{}]", t.symbols_token_text());
}

// case=guard_untyped_dump — the field-by-field None-ct arm comparand (the
// .cc fixture's case 8): the same four untyped guards fed to a hand-built
// MapState (build_map_state mirrors the varmap.cc:1260-1261 construction
// with the param-range subtraction), dumping every collected RangeHint in
// gatherOpen insertion order (loads then stores): start/sstart/size/flags/
// range_type/high_ind/type token.
fn run_guard_untyped_dump() {
    let mut t = GatherOpenScope::new("guard_untyped_dump", 0xa800);
    let locked = t.untyped_load(8, 0x2700);
    t.add_guard_record(&locked, 8, 0xffffffffffffff80, 0xffffffffffffffff, true, false);
    let unanalyzed = t.untyped_load(4, 0x2710);
    t.add_guard_record(&unanalyzed, 8, 0xffffffffffffff40, 0xffffffffffffffff, false, false);
    let store = t.untyped_store(2, 0x2720);
    t.add_guard_record(&store, 2, 0xffffffffffffff20, 0xffffffffffffffff, false, true);
    let rejected = t.untyped_load(16, 0x2730);
    t.add_guard_record(&rejected, 8, 0xfffffffffffffff8, 0xffffffffffffffff, true, false);
    let types = TypeFactory::shared_default();
    let mut state = t.scope.build_map_state(&t.fd, &types);
    for guard in &t.fd.heritage.load_guard {
        state.add_guard(guard, OpCode::CPUI_LOAD, &types);
    }
    for guard in &t.fd.heritage.store_guard {
        state.add_guard(guard, OpCode::CPUI_STORE, &types);
    }
    let parts: Vec<String> = state
        .hints()
        .iter()
        .map(|h| {
            let tok = h
                .dtype
                .as_deref()
                .map(type_token)
                .unwrap_or_else(|| "null".to_string());
            format!(
                "{:x}:{}:{}:{}:{}:{}:{}",
                h.start, h.sstart, h.size, h.flags, h.range_type as i32, h.high_ind, tok
            )
        })
        .collect();
    println!("case=guard_untyped_dump|hints=[{}]", parts.join(";"));
}

// Keep the shared factory alive for the symbol-entry type identity domain.
fn _factory_anchor() -> Arc<RwLock<TypeFactory>> {
    TypeFactory::shared_default()
}

fn main() {
    println!("schema=1|fixture=VARMAP-GATHEROPEN-GUARD-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    run_guard_open_hints();
    run_gather_symbols_reinput();
    run_category_clears();
    run_check_unaliased_return();
    run_annotate_raw_stack_ptr();
    run_derive_boundaries();
    run_guard_untyped_hints();
    run_guard_untyped_dump();
}
