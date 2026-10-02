// PRINTC-UNLINKED-REF-0001: Rugra comparand for the locked Ghidra 12.0.4
// local-entry oracle.  Mirrors tests/oracle/varmap_unlinked_locals_1204.cc
// case for case: the same ActionNameVars judgment chain (HighVariable::
// has_name -> Funcdata::link_symbol -> the coreaction.cc:2988-2997 naming
// loop) runs over the same candidate Varnode shapes, and the resulting
// ScopeLocal contents are printed in the shared canonical observation
// format.
//
// The census this fixture locks in: every nameable high (explicit register
// local, irregular input, addrtied stack local, parameter-attach) DOES get
// a ScopeLocal symbol through the production chain, and every high Ghidra
// refuses to name (implied unique temporary, spacebase stack-pointer input)
// gets none.  The E2E "unlinked local" backfill names (uVar_9100-style
// Unique-space offsets, RSP-copy uVar20-style register offsets, cast-shadow
// EAX widths) all fall in the refused classes — the entry chain itself is
// faithful; see the PRINTC-UNLINKED-REF-0001 TODO for the print-side
// routing.

use std::collections::BTreeMap;
use std::sync::Arc;

use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varmap::{symbol_category, ScopeLocal};
use rudra::varnode::varnode_flags;

const BASE: u64 = 0x9000;

fn long_t() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new("long".to_string(), 8, TypeMetatype::Int)))
}

/// Space-name mapping shared with the C++ oracle fixture's
/// FixtureTranslate space catalog.
fn space_name(space: AddressSpace) -> &'static str {
    match space {
        AddressSpace::Const => "const",
        AddressSpace::Unique => "unique",
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Other(_) => "other",
        AddressSpace::Overlay => "overlay",
    }
}

struct CaseFunc {
    fd: Funcdata,
}

impl CaseFunc {
    fn new(name: &str) -> Self {
        let mut fd = Funcdata::new(name, Address::new(BASE), 0x20);
        // The C++ Funcdata ctor (funcdata.cc:69) builds the ScopeLocal
        // localmap and installs the local window from the prototype model's
        // local range.  Rugra's flat Funcdata has no ctor-side scope; the
        // ActionRestructureVarnode production route installs it, so the
        // fixture mirrors the same post-restructure state here.
        let mut scope = ScopeLocal::new();
        scope.stack_grows_negative = true;
        scope.stack_direction = 1;
        // Same single high-address local window as the .cc fixture's
        // localrange XML: [0xffffffffffffff00, 0xffffffffffffffff].
        scope.local_range = vec![(0xffffffffffffff00u64, 0xffffffffffffffffu64)];
        // The prototype's own local window (varmap.cc:555 consults
        // fd->getFuncProto().getLocalRange(), not the union tree) is the
        // same single range, mirroring the .cc fixture's XML decode path.
        scope.proto_local_range = vec![(0xffffffffffffff00u64, 0xffffffffffffffffu64)];
        // Same register catalog as the .cc FixtureTranslate.
        scope.register_names = [
            (0x100u64, 8i32, "SREG1"),
            (0x108, 4, "SREG2"),
        ]
        .into_iter()
        .map(|(o, s, n)| ((o, s), n.to_string()))
        .collect();
        fd.scope = Some(scope);
        CaseFunc { fd }
    }

    /// Build the candidate Varnode the way the .cc fixture does: banked at
    /// the explicit (space, offset), carrying the type and flag set, with a
    /// HighVariable assigned through the production set_high_level route.
    fn candidate(
        &mut self,
        space: AddressSpace,
        offset: u64,
        size: usize,
        flags: u32,
    ) -> Arc<std::sync::RwLock<rudra::varnode::Varnode>> {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, space, offset);
        {
            let mut v = vn.write().unwrap();
            v.v_type = Some(long_t());
            v.set_flags(flags);
        }
        self.fd.set_high_level();
        vn
    }

    /// Drive the ActionNameVars local-entry judgment (coreaction.cc:2961-
    /// 2963) plus the naming loop (cc:2988-2997), then dump the scope in
    /// the shared canonical format.
    fn run_entry(&mut self, case_name: &str, vn: &Arc<std::sync::RwLock<rudra::varnode::Varnode>>) {
        let high_arc = vn.read().unwrap().high.clone().expect("high assigned");
        let hasname = {
            let mut h = high_arc.write().unwrap();
            h.update_flags();
            h.has_name()
        } as i32;
        let mut linked = 0;
        if hasname == 1 {
            if let Some(sym_idx) = self.fd.link_symbol(vn) {
                linked = 1;
                // Split the fd/scope borrows the way ActionNameVars::apply
                // takes the scope out of fd (coreaction.rs mirrors
                // coreaction.cc:2988-2997 with localmap and Funcdata as
                // separate objects).
                let mut scope_taken = self.fd.scope.take();
                if let Some(scope) = scope_taken.as_mut() {
                    if scope.symbols[sym_idx].is_name_undefined() {
                        let mut base: i32 = 1;
                        let guard = vn.read().unwrap();
                        let newname = scope.build_default_name(
                            sym_idx,
                            &mut base,
                            Some(&guard),
                            Some(&self.fd),
                        );
                        drop(guard);
                        if let Some(nm) = newname {
                            scope.rename_symbol(sym_idx, &nm);
                        }
                    }
                }
                self.fd.scope = scope_taken;
            }
        }
        dump_case(case_name, hasname, linked, &self.fd);
    }
}

/// Canonical scope-state dump shared with the C++ oracle fixture.
fn dump_case(case_name: &str, hasname: i32, linked: i32, fd: &Funcdata) {
    println!("case {}: hasName={} linked={}", case_name, hasname, linked);
    let scope = fd.scope.as_ref().expect("scope installed");
    let mut rows: Vec<(String, String, u64, i32, i32, i32, String)> = Vec::new();
    for sym in scope.symbols.iter().filter(|s| !s.is_dynamic) {
        rows.push((
            sym.name.clone(),
            space_name(sym.space).to_string(),
            sym.start,
            sym.size,
            sym.category,
            0,
            match sym.usepoint {
                None => "none".to_string(),
                Some(up) => format!("{:x}", up),
            },
        ));
    }
    for sym in scope.symbols.iter().filter(|s| s.is_dynamic) {
        rows.push((
            sym.name.clone(),
            "dynamic".to_string(),
            0,
            sym.size,
            sym.category,
            1,
            format!("{:x}", sym.usepoint.unwrap_or(0)),
        ));
    }
    rows.sort_by(|a, b| {
        (a.1.clone(), a.2, a.3, a.0.clone()).cmp(&(b.1.clone(), b.2, b.3, b.0.clone()))
    });
    for (name, space, off, size, cat, dyn_, usept) in rows {
        println!(
            "  sym name={} space={} off={:x} size={} cat={} dyn={} usept={}",
            name, space, off, size, cat, dyn_, usept
        );
    }
}

fn main() {
    println!("schema=1|fixture=PRINTC-UNLINKED-REF-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    // The strlen-result shape: explicit register local -> lVar1.
    let mut t = CaseFunc::new("explicit_register_local");
    let vn = t.candidate(AddressSpace::Register, 0x0, 8, varnode_flags::INSERT);
    t.run_entry("explicit_register_local", &vn);

    // The malloc-result shape: implied Unique-space temporary -> refused.
    let mut t = CaseFunc::new("implied_unique_temp");
    let vn = t.candidate(
        AddressSpace::Unique,
        0x9100,
        8,
        varnode_flags::INSERT | varnode_flags::IMPLIED,
    );
    t.run_entry("implied_unique_temp", &vn);

    // The stack-pointer shape: unaffected legal input carrying spacebase ->
    // refused (variable.cc:743).
    let mut t = CaseFunc::new("spacebase_stack_pointer");
    let vn = t.candidate(
        AddressSpace::Register,
        0x0,
        8,
        varnode_flags::INSERT
            | varnode_flags::INPUT
            | varnode_flags::DIRECTWRITE
            | varnode_flags::SPACEBASE
            | varnode_flags::UNAFFECTED,
    );
    t.run_entry("spacebase_stack_pointer", &vn);

    // The in_XXX shape: illegal register input at a catalog register, no
    // vn-level unaffected bit (production in_RDX-style inputs; the
    // unaffected bit would flip the name to unaff_) -> in_SREG1.
    let mut t = CaseFunc::new("irregular_input");
    let vn = t.candidate(
        AddressSpace::Register,
        0x100,
        8,
        varnode_flags::INSERT | varnode_flags::INPUT,
    );
    t.run_entry("irregular_input", &vn);

    // The stack-local shape: address-tied stack Varnode inside the local
    // window -> lStack_b8.
    let mut t = CaseFunc::new("addrtied_stack_local");
    let vn = t.candidate(
        AddressSpace::Stack,
        0xffffffffffffff48,
        8,
        varnode_flags::INSERT | varnode_flags::ADDRTIED,
    );
    t.run_entry("addrtied_stack_local", &vn);

    // The parameter-attach shape: input storage already carrying a
    // category-0 function_parameter symbol -> attach, no new symbol.
    let mut t = CaseFunc::new("formal_param_attach");
    {
        let scope = t.fd.scope.as_mut().expect("scope installed");
        let idx = scope.add_symbol(
            AddressSpace::Register,
            "p0",
            Some(long_t()),
            0x100,
            Some(BASE - 1),
        );
        scope.set_category(idx, symbol_category::FUNCTION_PARAMETER, 0);
    }
    let vn = t.candidate(
        AddressSpace::Register,
        0x100,
        8,
        varnode_flags::INSERT | varnode_flags::INPUT | varnode_flags::UNAFFECTED,
    );
    t.run_entry("formal_param_attach", &vn);

    // Silence unused-import warning for BTreeMap (kept for parity with the
    // register catalog construction).
    let _keep: BTreeMap<(u64, i32), String> = BTreeMap::new();
}
