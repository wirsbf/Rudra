// Locked Ghidra 12.0.4 Funcdata::syncVarnodesWithSymbols oracle for
// FUNCDATA-SCOPE-SYNC-0001 (typed-decl chain step 3, Rust side).
//
// Mirrors tests/oracle/scope_sync_1204.cc record-for-record: each case
// builds the same stack-space Varnode body (written via COPY(const) ops plus
// free twins), installs the same ScopeLocal symbols/ranges, runs one
// Funcdata::sync_varnodes_with_symbols call, and dumps every Varnode's
// boolean property set plus its data-type projection.

use std::sync::Arc;

use rudra::address::{Address, RangeList};
use rudra::database::{Symbol as DbSymbol, SymbolEntry};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
use rudra::varmap::ScopeLocal;
use rudra::varnode::{varnode_flags, Varnode};

type VarnodeRef = Arc<std::sync::RwLock<Varnode>>;

fn base_type(name: &str, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, metatype)))
}

fn pointer_to(pointee: Arc<Datatype>, size: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(format!("{} *", pointee.get_name()), size, TypeMetatype::Pointer),
        ptr_to: pointee,
        wordsize: 1,
    }))
}

struct Fixture {
    fd: Funcdata,
    varnodes: Vec<VarnodeRef>,
    names: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        let fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        Self { fd, varnodes: Vec::new(), names: Vec::new() }
    }

    fn remember(&mut self, vn: VarnodeRef, name: &str) {
        self.varnodes.push(vn);
        self.names.push(name.to_string());
    }

    /// Written stack-space varnode: COPY(const) at pc. Created before the
    /// scope symbols so the creation-time properties probe finds nothing.
    /// The initial type is the fixture-level stand-in for Ghidra's factory
    /// unknown type (named "xunknown{size}"); Rugra's canonical factory
    /// names it "undefined{size}" — a pre-existing TypeFactory naming
    /// divergence outside this fixture's contract, normalized here so the
    /// type-projection records stay byte-comparable.
    fn make_written(&mut self, name: &str, size: usize, offset: u64, pc: u64) -> VarnodeRef {
        let op = self.fd.new_op(1, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let input = self.fd.new_constant(size, 0x2a);
        self.fd.op_set_input(&op, input, 0);
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Stack, offset);
        self.fd.op_set_output(&op, vn.clone());
        vn.write().unwrap().v_type = Some(base_type(
            &format!("xunknown{}", size),
            size,
            TypeMetatype::Unknown,
        ));
        self.remember(vn.clone(), name);
        vn
    }

    /// Free stack-space varnode: skipped by the is_free guard.
    fn make_free(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Stack, offset);
        vn.write().unwrap().v_type = Some(base_type(
            &format!("xunknown{}", size),
            size,
            TypeMetatype::Unknown,
        ));
        self.remember(vn.clone(), name);
        vn
    }

    /// addSymbol with an invalid usepoint -> symbol addrtied.
    fn add_symbol_no_usepoint(&mut self, nm: &str, ct: Arc<Datatype>, offset: u64) {
        let scope = self.fd.scope.as_mut().unwrap();
        scope.add_symbol(AddressSpace::Stack, nm, Some(ct), offset, None);
    }

    /// addSymbol with a real usepoint -> no symbol addrtied.
    fn add_symbol_usepoint(&mut self, nm: &str, ct: Arc<Datatype>, offset: u64, pc: u64) {
        let scope = self.fd.scope.as_mut().unwrap();
        scope.add_symbol(AddressSpace::Stack, nm, Some(ct), offset, Some(pc));
    }

    fn set_nolocal_alias(&mut self, nm: &str) {
        let scope = self.fd.scope.as_mut().unwrap();
        let sym = scope.symbols.iter_mut().rev().find(|s| s.name == nm).unwrap();
        sym.unaliased = true;
    }

    fn set_locks(&mut self, nm: &str) {
        let scope = self.fd.scope.as_mut().unwrap();
        let sym = scope.symbols.iter_mut().rev().find(|s| s.name == nm).unwrap();
        sym.typelock = true;
        sym.namelock = true;
    }

    fn set_param_window(&mut self, first: u64, size: u64) {
        let scope = self.fd.scope.as_mut().unwrap();
        scope.min_param_offset = first;
        scope.max_param_offset = first + size - 1;
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
            TypeMetatype::Enum => 5,
            TypeMetatype::Struct => 4,
            TypeMetatype::Union => 3,
            TypeMetatype::PartialEnum => 2,
            TypeMetatype::PartialStruct => 1,
            TypeMetatype::PartialUnion => 0,
        }
    }

    fn type_name(dt: Option<&Arc<Datatype>>) -> String {
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

    fn varnode_dump(&self) -> String {
        let mut out = String::from("list=[");
        let mut first = true;
        for (vn, name) in self.varnodes.iter().zip(self.names.iter()) {
            let vn_r = vn.read().unwrap();
            if !first {
                out.push(';');
            }
            first = false;
            out.push_str(&format!(
                "{{{},mapped={},addrtied={},addrforce={},nolocalalias={},typelock={},namelock={},free={},typ={}}}",
                name,
                if (vn_r.flags & varnode_flags::MAPPED) != 0 { 1 } else { 0 },
                if (vn_r.flags & varnode_flags::ADDRTIED) != 0 { 1 } else { 0 },
                if (vn_r.flags & varnode_flags::ADDRFORCE) != 0 { 1 } else { 0 },
                if (vn_r.flags & varnode_flags::NOLOCALALIAS) != 0 { 1 } else { 0 },
                if (vn_r.flags & varnode_flags::TYPELOCK) != 0 { 1 } else { 0 },
                if (vn_r.flags & varnode_flags::NAMELOCK) != 0 { 1 } else { 0 },
                if vn_r.is_free() { 1 } else { 0 },
                Self::type_name(vn_r.get_type().as_ref()),
            ));
        }
        out.push(']');
        out
    }

    fn dump(&self, case: &str, stage: &str, res: i32) {
        println!(
            "case={}|stage={}|res={}|varnodes=[{}]",
            case,
            stage,
            res,
            self.varnode_dump()
        );
    }

    fn run(&mut self, case: &str, update_datatypes: bool, unmapped_alias_check: bool) {
        self.dump(case, "before", -1);
        let res = self
            .fd
            .sync_varnodes_with_symbols(update_datatypes, unmapped_alias_check);
        self.dump(case, "after", if res { 1 } else { 0 });
    }
}

fn run_type_projection() {
    let mut fixture = Fixture::new();
    fixture.fd.scope = Some(ScopeLocal::new());
    fixture.make_written("ti", 4, 0x300, 0x1000);
    fixture.make_written("tp", 8, 0x308, 0x1010);
    fixture.make_written("tsub", 4, 0x31c, 0x1020);
    fixture.add_symbol_no_usepoint("lvi", base_type("int4", 4, TypeMetatype::Int), 0x300);
    fixture.add_symbol_no_usepoint(
        "lvp",
        pointer_to(base_type("char", 1, TypeMetatype::Int), 8),
        0x308,
    );
    fixture.add_symbol_no_usepoint("lv8", base_type("int8", 8, TypeMetatype::Int), 0x318);
    fixture.run("type_projection", true, true);
}

fn run_unmapped_alias() {
    let mut fixture = Fixture::new();
    let mut scope = ScopeLocal::new();
    // Mirror the x86-64-gcc default local window (cspec localrange+paramrange)
    // that Ghidra's resetLocalWindow installs into the scope range tree, plus
    // the fixture's added 0x200-0x2ff range.
    scope.local_range = vec![
        (0xfffffffffff0bdc0, 0xffffffffffffffff),
        (0, 0x1fe),
        (0x200, 0x2ff),
    ];
    fixture.fd.scope = Some(scope);
    // Creation order mirrors the C++ fixture: vin is created in-scope
    // (mapped|addrtied), vout/vparam under the temporary 0x300-0x5ff range
    // extension plus setAddrForce (full mapped|addrtied|addrforce triple),
    // which is removed before the sync call.
    let vin = fixture.make_written("vin", 4, 0x220, 0x1000);
    let vout = fixture.make_written("vout", 4, 0x400, 0x1010);
    let vparam = fixture.make_written("vparam", 4, 0x502, 0x1020);
    vin.write()
        .unwrap()
        .set_flags(varnode_flags::MAPPED | varnode_flags::ADDRTIED);
    vout.write().unwrap().set_flags(
        varnode_flags::MAPPED | varnode_flags::ADDRTIED | varnode_flags::ADDRFORCE,
    );
    vparam.write().unwrap().set_flags(
        varnode_flags::MAPPED | varnode_flags::ADDRTIED | varnode_flags::ADDRFORCE,
    );
    fixture.set_param_window(0x500, 8);
    fixture.run("unmapped_alias", true, true);
}

fn run_mask_asymmetry() {
    let mut fixture = Fixture::new();
    fixture.fd.scope = Some(ScopeLocal::new());
    // Creation order mirrors the C++ fixture: v_adt/v_nadt/v_nla are created
    // under the temporary 0x300-0x338 range extension plus setAddrForce
    // (mapped|addrtied|addrforce), the later siblings clean.
    let v_adt = fixture.make_written("v_adt", 4, 0x310, 0x1000);
    let v_nadt = fixture.make_written("v_nadt", 4, 0x320, 0x1020);
    let v_nla = fixture.make_written("v_nla", 4, 0x330, 0x1030);
    for vn in [&v_adt, &v_nadt, &v_nla] {
        vn.write().unwrap().set_flags(
            varnode_flags::MAPPED | varnode_flags::ADDRTIED | varnode_flags::ADDRFORCE,
        );
    }
    fixture.make_written("v_adt2", 4, 0x310, 0x1010);
    fixture.make_free("v_free", 4, 0x310);
    fixture.make_written("v_small", 4, 0x34f, 0x1040);
    fixture.add_symbol_no_usepoint("adt", base_type("int4", 4, TypeMetatype::Int), 0x310);
    fixture.add_symbol_usepoint("nadt", base_type("int4", 4, TypeMetatype::Int), 0x320, 0x1000);
    fixture.add_symbol_no_usepoint("nla", base_type("int4", 4, TypeMetatype::Int), 0x330);
    fixture.set_nolocal_alias("nla");
    fixture.add_symbol_no_usepoint("sml", base_type("int2", 2, TypeMetatype::Int), 0x34e);
    fixture.set_locks("sml");
    fixture.add_symbol_no_usepoint("big", base_type("int8", 8, TypeMetatype::Int), 0x350);
    fixture.run("mask_asymmetry", false, true);
}

fn run_typelock_mapentry() {
    let mut fixture = Fixture::new();
    fixture.fd.scope = Some(ScopeLocal::new());
    let v_tl = fixture.make_written("v_tl", 4, 0x310, 0x1000);
    let v_dyn = fixture.make_written("v_dyn", 4, 0x320, 0x1010);
    v_tl.write()
        .unwrap()
        .update_type_lock(base_type("uint4", 4, TypeMetatype::Uint), true, false);
    fixture.add_symbol_no_usepoint("tl", base_type("int4", 4, TypeMetatype::Int), 0x310);
    fixture.set_locks("tl");
    fixture.add_symbol_usepoint("att", base_type("int4", 4, TypeMetatype::Int), 0x320, 0x1010);
    fixture.set_nolocal_alias("att");
    // Mirror vn->setSymbolEntry(att) via linkSymbol: attach a static
    // SymbolEntry bridge so the sync's mapentry branch (mapped bit held
    // fixed) is exercised.
    let att_entry = {
        let symbol = Arc::new(std::sync::RwLock::new(DbSymbol::new(0, "att", "")));
        SymbolEntry::new_static(
            symbol,
            0,
            Address::new(0x320),
            0,
            4,
            RangeList::new(),
        )
    };
    v_dyn
        .write()
        .unwrap()
        .set_symbol_entry(Arc::new(std::sync::RwLock::new(att_entry)));
    fixture.run("typelock_mapentry", true, true);
}

fn main() {
    run_type_projection();
    run_unmapped_alias();
    run_mask_asymmetry();
    run_typelock_mapentry();
}
