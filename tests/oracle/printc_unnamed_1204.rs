// PRINTC-UNLINKED-REF-FAMILY slice C: Rugra comparand for the locked
// Ghidra 12.0.4 printc_unnamed_1204 oracle (A35 audit section 5).
//
// Mirrors tests/oracle/printc_unnamed_1204.cc case for case and record for
// record across the three observation surfaces:
//
//   stage=branch — the build_variable_name branch projection through the
//     production ActionRestructureVarnode -> set_high_level ->
//     ActionNameVars chain (the Rust bootstrap that installs the ScopeLocal
//     the C++ Funcdata ctor already carries).
//
//   stage=reach — the symbolization reach five-tuple for the unique-space
//     temporaries of the seven-function shapes (helpf `& 2`, match_url
//     `!= '#'`, implied refusal, explicit register control): has_high /
//     pre-chain has_name gate verdict / post-chain link outcome / final
//     symbol display name.
//
//   stage=print — the print-time fallback truth through the public
//     PrintC::emit_statement entry: what the lhs token of the defining
//     statement becomes when the high carries no symbol.  Ghidra's
//     pushSymbolDetail sym==0 arm prints the space name + printRaw of the
//     HIGH NAME REPRESENTATIVE address (printc.cc:1938-1945); current
//     Rugra prints `uVar_<current-instance-offset>` (printc.rs
//     get_varnode_display_name_inner / push_varnode Unique arms).  The
//     expected divergence is the gap evidence this fixture locks — the
//     runner registers it per line, never excises it.
//
//   stage=uniqid — the creation-order projection: every Unique-space
//     varnode in offset order with (offset, size, def-op SeqNum time,
//     opcode), pinning the ANALYSIS_UNIQUE_START allocation sequence.
//
// Statement text uses the same transport normalization as the C++ side:
// outer whitespace stripped, inner whitespace runs collapsed to single
// spaces.  No other normalization.

use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::coreaction::{ActionNameVars, ActionRestructureVarnode};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::varnode::{varnode_flags, Varnode};

type VarnodeRef = Arc<RwLock<Varnode>>;

const ORACLE_COMMIT: &str = "e40ed13014025f82488b1f8f7bca566894ac376b";

fn int4() -> Arc<rudra::type_system::datatype::Datatype> {
    use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
    Arc::new(Datatype::Base(TypeBase::new(
        "int4".to_string(),
        4,
        TypeMetatype::Int,
    )))
}

fn int8() -> Arc<rudra::type_system::datatype::Datatype> {
    use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
    Arc::new(Datatype::Base(TypeBase::new(
        "int8".to_string(),
        8,
        TypeMetatype::Int,
    )))
}

/// Collapse inner whitespace runs to single spaces and strip the ends —
/// the transport normalization shared with the C++ oracle fixture.
fn normalize_statement(raw: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    for c in raw.chars() {
        if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
            if !out.is_empty() {
                pending = true;
            }
            continue;
        }
        if pending {
            out.push(' ');
            pending = false;
        }
        out.push(c);
    }
    out
}

struct Fixture {
    fd: Funcdata,
}

impl Fixture {
    fn new(case_name: &str, stack_window: bool) -> Self {
        let mut fd = Funcdata::new(case_name, Address::new(0x36d0), 0);
        // The Rust analogue of the C++ Funcdata ctor's ScopeLocal: the
        // production bootstrap that installs the local scope (register
        // catalog included).  The C++ fixture's Funcdata carries this from
        // its ctor; Rugra's flat Funcdata gets it here.
        ActionRestructureVarnode::new().apply(&mut fd).unwrap();
        if stack_window {
            // The local window the C++ GetStr Funcdata's localmap holds
            // after Funcdata::clear -> resetLocalWindow (varmap.cc:432) —
            // observed on the locked oracle: the negative range
            // [0xfffffffffff0bdc1, 0xffffffffffffffff] is in the window
            // (stack_local_neg takes the ScopeLocal Stack branch) while the
            // cspec's positive [8,39] band is NOT (stack_local_pos falls
            // through to the base addrtied branch).
            if let Some(scope) = fd.scope.as_mut() {
                scope.local_range =
                    vec![(0xfffffffffff0bdc1u64, 0xffffffffffffffffu64)];
                scope.proto_local_range = scope.local_range.clone();
            }
        }
        Fixture { fd }
    }

    fn make_written_temp(&mut self, pc: u64, value: u64, size: usize, opc: OpCode, value2: u64) -> VarnodeRef {
        let op = self.fd.new_op(if opc == OpCode::CPUI_COPY { 1 } else { 2 }, Address::new(pc));
        self.fd.op_set_opcode(&op, opc);
        let in0 = self.fd.new_constant(size, value);
        self.fd.op_set_input(&op, in0, 0);
        if opc != OpCode::CPUI_COPY {
            let in1 = self.fd.new_constant(size, value2);
            self.fd.op_set_input(&op, in1, 1);
        }
        let vn = self.fd.new_unique_out(size, &op);
        let use_op = self.fd.new_op(1, Address::new(pc + 0x10));
        self.fd.op_set_opcode(&use_op, OpCode::CPUI_COPY);
        self.fd.op_set_input(&use_op, vn.clone(), 0);
        let _ = self.fd.new_unique_out(size, &use_op);
        vn
    }

    fn make_written_register(&mut self, size: usize, offset: u64, pc: u64) -> VarnodeRef {
        let op = self.fd.new_op(1, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let input = self.fd.new_constant(size, 5);
        self.fd.op_set_input(&op, input, 0);
        let vn = self.fd.new_varnode_out(size, Address::new(offset), &op);
        let use_op = self.fd.new_op(1, Address::new(pc + 0x10));
        self.fd.op_set_opcode(&use_op, OpCode::CPUI_COPY);
        self.fd.op_set_input(&use_op, vn.clone(), 0);
        let _ = self.fd.new_unique_out(size, &use_op);
        vn
    }

    fn make_written_stack(&mut self, size: usize, offset: u64, pc: u64) -> VarnodeRef {
        let op = self.fd.new_op(1, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let input = self.fd.new_constant(size, 5);
        self.fd.op_set_input(&op, input, 0);
        // Stack-space analogue of Funcdata::new_varnode_out (which
        // hardcodes the register space): bank-create with the def attached,
        // then wire the op's output slot the same way.
        let vn = self
            .fd
            .vbank
            .create_def_with_space(size, AddressSpace::Stack, offset, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        let _ = self.fd.assign_high(&vn);
        self.fd.set_varnode_properties(&vn);
        let use_op = self.fd.new_op(1, Address::new(pc + 0x10));
        self.fd.op_set_opcode(&use_op, OpCode::CPUI_COPY);
        self.fd.op_set_input(&use_op, vn.clone(), 0);
        let _ = self.fd.new_unique_out(size, &use_op);
        vn
    }

    fn set_high(&mut self) {
        self.fd.set_high_level();
    }

    fn run_name_vars(&mut self) {
        ActionNameVars::new().apply(&mut self.fd).unwrap();
    }

    /// Pre-chain hasName gate verdict (variable.cc:718-747), computed after
    /// set_high_level but before ActionNameVars.
    fn has_name_gate(&self, vn: &VarnodeRef) -> i32 {
        let high = vn.read().unwrap().high.clone().expect("high assigned");
        let mut h = high.write().unwrap();
        h.update_flags();
        h.has_name() as i32
    }

    fn set_type(&self, vn: &VarnodeRef, ct: Arc<rudra::type_system::datatype::Datatype>) {
        vn.write().unwrap().v_type = Some(ct);
    }

    fn set_flags(&self, vn: &VarnodeRef, flags: u32) {
        vn.write().unwrap().set_flags(flags);
    }

    fn print_branch(&self, case_name: &str, vn: &VarnodeRef, branch_label: &str) {
        let name = self.symbol_display_name(vn);
        println!("case={}|stage=branch|name={}|branch={}", case_name, name, branch_label);
    }

    fn symbol_display_name(&self, vn: &VarnodeRef) -> String {
        let high = vn.read().unwrap().high.clone().expect("high assigned");
        let ptr = Arc::as_ptr(&high) as usize;
        match self.fd.high_symbols.get(&ptr) {
            Some(&idx) => self
                .fd
                .scope
                .as_ref()
                .and_then(|s| s.symbols.get(idx))
                .map(|s| {
                    if s.display_name.is_empty() {
                        s.name.clone()
                    } else {
                        s.display_name.clone()
                    }
                })
                .unwrap_or_else(|| "none".to_string()),
            None => "none".to_string(),
        }
    }

    fn print_reach(&self, case_name: &str, vn: &VarnodeRef, has_name_pre: i32) {
        let high = vn.read().unwrap().high.clone();
        let has_high = high.is_some() as i32;
        let (linked, sym) = match &high {
            Some(h) => {
                let ptr = Arc::as_ptr(h) as usize;
                match self.fd.high_symbols.get(&ptr) {
                    Some(&idx) => (
                        1,
                        self.fd
                            .scope
                            .as_ref()
                            .and_then(|s| s.symbols.get(idx))
                            .map(|s| {
                                if s.display_name.is_empty() {
                                    s.name.clone()
                                } else {
                                    s.display_name.clone()
                                }
                            })
                            .unwrap_or_else(|| "none".to_string()),
                    ),
                    None => (0, "none".to_string()),
                }
            }
            None => (0, "none".to_string()),
        };
        println!(
            "case={}|stage=reach|has_high={}|has_name={}|link={}|sym={}",
            case_name, has_high, has_name_pre, linked, sym
        );
    }

    fn render_lhs_statement(&self, vn: &VarnodeRef) -> String {
        let def = vn.read().unwrap().get_def().expect("written varnode has def");
        let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
        printer.snapshot_local_scope(&self.fd);
        printer.emit_statement(&def.read().unwrap());
        let emit = printer
            .take_emit()
            .into_any()
            .downcast::<EmitNoMarkup>()
            .expect("PrintC returned an unexpected emitter type");
        normalize_statement(emit.debug_get_output_ref())
    }

    fn print_statement(&self, case_name: &str, site: &str, text: &str) {
        println!("case={}|stage=print|site={}|text={}", case_name, site, text);
    }

    fn print_uniqid(&self, case_name: &str) {
        let mut rows: Vec<(u64, usize, Option<u32>, &'static str)> = Vec::new();
        for entry in &self.fd.vbank.loc_tree {
            let vn = entry.0.read().unwrap();
            if vn.get_space() != AddressSpace::Unique {
                continue;
            }
            let def = vn.get_def();
            match &def {
                Some(op) => {
                    let guard = op.read().unwrap();
                    rows.push((vn.get_offset(), vn.get_size(), Some(guard.get_time()), guard.opcode.name()));
                }
                None => rows.push((vn.get_offset(), vn.get_size(), None, "none")),
            }
        }
        rows.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        for (off, size, seq, opname) in rows {
            match seq {
                Some(t) => println!(
                    "case={}|stage=uniqid|off={:x}|size={}|seq={}|op={}",
                    case_name, off, size, t, opname
                ),
                None => println!(
                    "case={}|stage=uniqid|off={:x}|size={}|seq=none|op=none",
                    case_name, off, size
                ),
            }
        }
    }
}

fn main() {
    println!(
        "schema=1|fixture=PRINTC-UNLINKED-REF-FAMILY|slice=C|oracle={}",
        ORACLE_COMMIT
    );

    // ---- stage=branch: the build_variable_name branch projection ----

    {
        let mut t = Fixture::new("stack_local_neg", true);
        let vn = t.make_written_stack(8, 0xffffffffffffff48, 0x1000);
        t.set_flags(&vn, varnode_flags::ADDRTIED);
        t.set_high();
        t.run_name_vars();
        t.print_branch("stack_local_neg", &vn, "stack-form");
    }

    {
        let mut t = Fixture::new("stack_local_pos", true);
        let vn = t.make_written_stack(8, 0x20, 0x1010);
        t.set_flags(&vn, varnode_flags::ADDRTIED);
        t.set_high();
        t.run_name_vars();
        t.print_branch("stack_local_pos", &vn, "stack-form-X");
    }

    {
        let mut t = Fixture::new("zero_flag_counter", false);
        let vn = t.make_written_register(4, 0x40, 0x1020);
        t.set_type(&vn, int4());
        t.set_high();
        t.run_name_vars();
        t.print_branch("zero_flag_counter", &vn, "counter");
    }

    {
        let mut t = Fixture::new("unaff_retaddr_input", false);
        let vn = t
            .fd
            .vbank
            .create_with_space(8, AddressSpace::Register, 0x18);
        let vn = t.fd.set_input_varnode(vn);
        t.set_flags(&vn, varnode_flags::UNAFFECTED | varnode_flags::RETURN_ADDRESS);
        t.set_high();
        t.run_name_vars();
        t.print_branch("unaff_retaddr_input", &vn, "unaff");
    }

    {
        let mut t = Fixture::new("irregular_input", false);
        let vn = t
            .fd
            .vbank
            .create_with_space(8, AddressSpace::Register, 0x08);
        let vn = t.fd.set_input_varnode(vn);
        t.set_type(&vn, int8());
        t.set_high();
        t.run_name_vars();
        t.print_branch("irregular_input", &vn, "in_");
    }

    // ---- stage=print: the unnamed-location fallback truth ----

    {
        let mut t = Fixture::new("symbolless_unique_direct", false);
        let vn = t.make_written_temp(0x1040, 5, 4, OpCode::CPUI_COPY, 0);
        t.set_high();
        let text = t.render_lhs_statement(&vn);
        t.print_statement("symbolless_unique_direct", "a", &text);
        t.print_uniqid("symbolless_unique_direct");
    }

    // ---- stage=reach: the symbolization reach five-tuple ----

    {
        let mut t = Fixture::new("helpf_and2_shape", false);
        let shape = t.make_written_temp(0x1050, 6, 4, OpCode::CPUI_INT_AND, 2);
        let face = t.make_written_temp(0x1070, 5, 4, OpCode::CPUI_COPY, 0);
        t.set_type(&shape, int4());
        t.set_type(&face, int4());
        t.set_high();
        let pre = t.has_name_gate(&shape);
        t.run_name_vars();
        t.print_reach("helpf_and2_shape", &shape, pre);
        let text = t.render_lhs_statement(&face);
        t.print_statement("helpf_and2_shape", "a", &text);
        t.print_uniqid("helpf_and2_shape");
    }

    {
        let mut t = Fixture::new("match_url_hash_shape", false);
        let shape = t.make_written_temp(0x1060, 0x23, 4, OpCode::CPUI_INT_NOTEQUAL, 0x23);
        let face = t.make_written_temp(0x1080, 5, 4, OpCode::CPUI_COPY, 0);
        t.set_type(&shape, int4());
        t.set_type(&face, int4());
        t.set_high();
        let pre = t.has_name_gate(&shape);
        t.run_name_vars();
        t.print_reach("match_url_hash_shape", &shape, pre);
        let text = t.render_lhs_statement(&face);
        t.print_statement("match_url_hash_shape", "a", &text);
        t.print_uniqid("match_url_hash_shape");
    }

    {
        let mut t = Fixture::new("implied_temp_refusal", false);
        let shape = t.make_written_temp(0x1090, 7, 4, OpCode::CPUI_COPY, 0);
        t.set_flags(&shape, varnode_flags::IMPLIED);
        t.set_high();
        let pre = t.has_name_gate(&shape);
        t.run_name_vars();
        t.print_reach("implied_temp_refusal", &shape, pre);
        let text = t.render_lhs_statement(&shape);
        t.print_statement("implied_temp_refusal", "a", &text);
        t.print_uniqid("implied_temp_refusal");
    }

    {
        let mut t = Fixture::new("explicit_register_control", false);
        let face = t.make_written_register(4, 0x40, 0x10a0);
        t.set_type(&face, int4());
        t.set_high();
        let pre = t.has_name_gate(&face);
        t.run_name_vars();
        t.print_reach("explicit_register_control", &face, pre);
        let text = t.render_lhs_statement(&face);
        t.print_statement("explicit_register_control", "a", &text);
        t.print_uniqid("explicit_register_control");
    }

    {
        let mut t = Fixture::new("multi_instance_unnamed", false);
        let ta = t.make_written_temp(0x10b0, 5, 4, OpCode::CPUI_COPY, 0);
        let tb = t.make_written_temp(0x10c0, 6, 4, OpCode::CPUI_COPY, 0);
        t.set_high();
        let ha = ta.read().unwrap().high.clone().expect("high assigned");
        let hb = tb.read().unwrap().high.clone().expect("high assigned");
        {
            let mut b_guard = hb.write().unwrap();
            ha.write().unwrap().merge(&mut b_guard, None, false);
        }
        // merge_internal leaves the moved instances' vn.high pointers on the
        // consumed high; re-point them the way Ghidra's vn->setHigh does
        // inside mergeInternal (variable.cc:640-653).
        let instances: Vec<VarnodeRef> = ha.read().unwrap().instances.clone();
        for inst in instances {
            inst.write().unwrap().high = Some(ha.clone());
        }
        let rep = ha
            .read()
            .unwrap()
            .get_name_representative()
            .map(|rep| rep.read().unwrap().get_offset())
            .unwrap_or(0);
        println!("case=multi_instance_unnamed|stage=rep|rep={:x}", rep);
        let text_a = t.render_lhs_statement(&ta);
        t.print_statement("multi_instance_unnamed", "a", &text_a);
        let text_b = t.render_lhs_statement(&tb);
        t.print_statement("multi_instance_unnamed", "b", &text_b);
        t.print_uniqid("multi_instance_unnamed");
    }
}
