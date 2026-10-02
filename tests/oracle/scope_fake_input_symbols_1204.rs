// VARMAP-FAKEINPUT-0001: Rugra comparand for the locked Ghidra 12.0.4
// authoritative ScopeLocal::fakeInputSymbols oracle.  Mirrors
// tests/oracle/scope_fake_input_symbols_1204.cc case for case: the same
// input Varnode sets (created through the production VarnodeBank
// create/setInput path), the same per-case prototype models carrying the
// paramrange (installed through the Architecture model registry the way
// FuncProto::setScope attaches arch->defaultfp), the same pre-existing
// function_parameter symbols, and the same observation format: every whole
// symbol mapping in (space, first, last) order with
// name/displayName/category/catindex/size/typelock, the
// function_parameter category size, and the warning-header texts.

use std::sync::{Arc, RwLock};

use rudra::address::{Address, Range, RangeList};
use rudra::arch::Architecture;
use rudra::comment::CommentDatabaseInternal;
use rudra::fspec::ProtoModelFull;
use rudra::funcdata::Funcdata;
use rudra::space::AddressSpace;
use rudra::type_system::typefactory::TypeFactory;
use rudra::varmap::{symbol_category, ScopeLocal};
use rudra::varnode::varnode_flags;

struct FakeInputScope {
    arch: Arc<Architecture>,
    fd: Funcdata,
    scope: ScopeLocal,
    types: Arc<RwLock<TypeFactory>>,
}

impl FakeInputScope {
    fn new(model_name: &str, paramrange: &[(u64, u64)]) -> Self {
        let mut arch = Architecture::new();
        arch.commentdb = Some(Arc::new(RwLock::new(CommentDatabaseInternal::new())));
        let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
        model.name = model_name.to_string();
        model.paramrange = RangeList::new();
        for &(first, last) in paramrange {
            if let Some(r) = Range::new(Address::new(first), Address::new(last)) {
                model.paramrange.insert_range(r);
            }
        }
        arch.proto_models.insert(model_name.to_string(), Arc::new(model));
        arch.set_default_model(model_name);
        let arch = Arc::new(arch);

        let mut fd = Funcdata::new(model_name, Address::new(0x9000), 0x20);
        // FuncProto::setScope's model fallback (fspec.cc:3883-3884): the
        // prototype resolves the model by convention name through the
        // Architecture registry.
        fd.funcp.set_model_name(model_name);
        fd.set_arch(arch.clone());

        let scope = ScopeLocal::new();

        FakeInputScope {
            arch,
            fd,
            scope,
            types: TypeFactory::shared_default(),
        }
    }

    /// Create an input varnode through the production
    /// VarnodeBank::create + setInput pair (the bank-level setInput is the
    /// production entry Funcdata::setInputVarnode calls after its overlap
    /// check, so deliberately overlapping inputs can be constructed).
    fn add_input(&mut self, space: AddressSpace, offset: u64, size: usize, typelock: bool) {
        let vn = self.fd.vbank.create_with_space(size, space, offset);
        self.fd.vbank.set_input(vn.clone()).expect("bank-owned free varnode");
        if typelock {
            vn.write().unwrap().flags |= varnode_flags::TYPELOCK;
        }
    }

    /// Pre-existing parameter symbol (category 0) through the production
    /// addSymbol + setCategory APIs.
    fn add_param(&mut self, offset: u64, size: usize) {
        let ct = self
            .types
            .read()
            .unwrap()
            .get_base(size, rudra::type_system::TypeMetatype::Int)
            .expect("fixture int base type");
        let idx = self.scope.add_symbol(AddressSpace::Stack, "", Some(ct), offset, None);
        self.scope.set_category(idx, symbol_category::FUNCTION_PARAMETER, 0);
    }

    /// Render the complete observable post-state in the shared format.
    fn run(&mut self, case_name: &str) {
        self.scope.fake_input_symbols(&self.fd, &self.types);

        // Whole symbol mappings in (space, first, last) order.
        let mut recs: Vec<(u8, u64, u64, &str, &str, i32, u32, i32, bool)> = self
            .scope
            .symbols
            .iter()
            .filter(|sym| !sym.is_dynamic)
            .map(|sym| {
                (
                    sym.space.space_id(),
                    sym.start,
                    sym.start.wrapping_add(sym.size as u64).wrapping_sub(1),
                    sym.name.as_str(),
                    sym.display_name.as_str(),
                    sym.category,
                    sym.cat_index,
                    sym.size,
                    sym.typelock,
                )
            })
            .collect();
        recs.sort();

        let mut out = String::new();
        out.push_str(&format!("case={}|symbols=[", case_name));
        for (i, (spcidx, first, last, name, disp, cat, catidx, size, typelock)) in
            recs.iter().enumerate()
        {
            if i != 0 {
                out.push(';');
            }
            out.push_str(&format!(
                "{}:{}-{}:{}:{}:{}:{}:{}:{}",
                spcidx, first, last, name, disp, cat, catidx, size, if *typelock { 1 } else { 0 }
            ));
        }
        out.push_str(&format!(
            "]|lockedinputs={}",
            self.scope.get_category_size(symbol_category::FUNCTION_PARAMETER)
        ));
        out.push_str("|warnings=[");
        if let Some(cdb) = &self.arch.commentdb {
            let cdb = cdb.read().unwrap();
            let texts: Vec<&str> = cdb.all_comments().map(|c| c.get_text()).collect();
            out.push_str(&texts.join(";"));
        }
        out.push_str("]\n");
        print!("{}", out);
    }
}

// case=range_filter_first_byte_only
fn run_range_filter() {
    let mut t = FakeInputScope::new("range_filter", &[(8, 515)]);
    t.add_input(AddressSpace::Stack, 0xfffffffffffffff0, 8, false); // negative local: filtered
    t.add_input(AddressSpace::Stack, 4, 8, false); // below range: filtered
    t.add_input(AddressSpace::Stack, 512, 8, false); // first byte in range: symbol [512,519]
    t.run("range_filter_first_byte_only");
}

// case=overlap_absorb_507_merges_508 / overlap_standalone_508
fn run_overlap_absorb() {
    {
        let mut t = FakeInputScope::new("overlap_absorb", &[(8, 515)]);
        t.add_input(AddressSpace::Stack, 507, 2, false);
        t.add_input(AddressSpace::Stack, 508, 4, false);
        t.run("overlap_absorb_507_merges_508");
    }
    {
        let mut t = FakeInputScope::new("overlap_standalone", &[(8, 515)]);
        t.add_input(AddressSpace::Stack, 508, 4, false);
        t.run("overlap_standalone_508");
    }
}

// case=adjacent_no_merge
fn run_adjacent_no_merge() {
    let mut t = FakeInputScope::new("adjacent", &[(8, 515)]);
    t.add_input(AddressSpace::Stack, 100, 8, false);
    t.add_input(AddressSpace::Stack, 108, 8, false);
    t.run("adjacent_no_merge");
}

// case=cross_space_break_and_continue
fn run_cross_space() {
    let mut t = FakeInputScope::new("cross_space", &[(8, 515)]);
    t.add_input(AddressSpace::Register, 0x0, 8, false); // earlier space: outer continue
    t.add_input(AddressSpace::Stack, 0x10, 8, false);
    t.add_input(AddressSpace::Join, 0x0, 8, false); // later space: inner-loop break
    t.add_input(AddressSpace::Stack, 0x20, 8, false);
    t.run("cross_space_break_and_continue");
}

// case=typelock_group_skip
fn run_typelock() {
    let mut t = FakeInputScope::new("typelock", &[(8, 515)]);
    t.add_input(AddressSpace::Stack, 0x10, 8, false);
    t.add_input(AddressSpace::Stack, 0x14, 4, true); // typelocked member: group skipped
    t.add_input(AddressSpace::Stack, 0x30, 8, false);
    t.run("typelock_group_skip");
}

// case=lockedinputs_breaker_covered_skip
fn run_locked_breaker() {
    let mut t = FakeInputScope::new("locked_breaker", &[(8, 515)]);
    t.add_input(AddressSpace::Stack, 0x30, 4, false);
    t.add_input(AddressSpace::Stack, 0x38, 8, false);
    t.add_param(0x38, 8);
    t.run("lockedinputs_breaker_covered_skip");
}

// case=lockedinputs_leader_covered_no_skip
fn run_locked_leader_only() {
    let mut t = FakeInputScope::new("locked_leader", &[(8, 515)]);
    t.add_input(AddressSpace::Stack, 0x30, 4, false);
    t.add_input(AddressSpace::Stack, 0x40, 8, false);
    t.add_param(0x30, 8);
    t.run("lockedinputs_leader_covered_no_skip");
}

// case=flipped_wraparound_exception_continue
fn run_flipped_wrap() {
    let mut t = FakeInputScope::new(
        "flipped_wrap",
        &[(0xffffffffffffff00, 0xffffffffffffffff)],
    );
    t.add_input(AddressSpace::Stack, 0xffffffffffffff9c, 8, false); // symbol [..9c,..a3]
    t.add_input(AddressSpace::Stack, 0xfffffffffffffffd, 8, false); // wraps: LowlevelError
    t.run("flipped_wraparound_exception_continue");
}

fn main() {
    print!("schema=1|fixture=VARMAP-FAKEINPUT-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n");
    run_range_filter();
    run_overlap_absorb();
    run_adjacent_no_merge();
    run_cross_space();
    run_typelock();
    run_locked_breaker();
    run_locked_leader_only();
    run_flipped_wrap();
}
