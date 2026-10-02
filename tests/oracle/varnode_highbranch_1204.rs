//! VARNODE-COPYSYMBOL-HIGHBRANCH-0001: Rudra side of the locked 12.0.4
//! oracle fixture for the high!=0 bookkeeping half of
//! `Varnode::copySymbol` (varnode.cc:500-504) and its wiring through
//! `Varnode::copySymbolIfValid` (varnode.cc:510-522) +
//! `PcodeOp::collapseConstantSymbol` (op.cc:503-540).
//!
//! Mirrors `varnode_highbranch_1204.cc` case-for-case (same names, same
//! observation format) against the pinned rudra source with the live
//! src/varnode.rs + src/op.rs overlay:
//!   hb_*: case|has_high|dirty_before|tl_before|hmeta_before|dirty_after|
//!         tl_after|hmeta_after|hsym|hoff|dst_tl|dst_nl|dst_mapentry
//!
//! Equates attach through the public `Varnode::set_symbol_entry` route with
//! `equate_symbol_registry::register_value` marking the symbol as an
//! EquateSymbol carrying its value (the Rust stand-in for the C++ subtype
//! identity that `dynamic_cast<EquateSymbol*>` reads).

use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::{Address, RangeList};
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::database::{Symbol, SymbolEntry};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::ruleaction::RuleCollapseConstants;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varnode::{equate_symbol_registry, varnode_flags, Varnode};
use rudra::variable::high_internal_flags;

fn meta_token(meta: TypeMetatype) -> &'static str {
    match meta {
        TypeMetatype::Unknown => "unknown",
        TypeMetatype::Int => "int",
        _ => "other",
    }
}

// Mirror of the C++ makeEquateSrc: Scope::addEquateSymbol
// (database.cc:1712-1724, dynamic size-1 whole map) attached via
// Varnode::setSymbolEntry (varnode.cc:429), plus the int4 typelock
// (varnode.cc:474-489 updateType(ct,true,false)). Rudra's database::Symbol
// has no equate payload, so the registry records the value the C++ subtype
// would carry.
fn make_equate_src(fd: &mut Funcdata, val: u64, int4: Arc<Datatype>) -> Arc<RwLock<Varnode>> {
    let src = fd.new_constant(4, val);
    let symbol = Arc::new(RwLock::new(Symbol::new(0, "FIXTURE_EQ", "equ")));
    equate_symbol_registry::register_value(&symbol, val);
    let entry = SymbolEntry::new_dynamic(
        symbol,
        varnode_flags::MAPPED,
        1,
        0,
        4,
        RangeList::default(),
    );
    {
        let mut s = src.write().unwrap();
        s.set_symbol_entry(Arc::new(RwLock::new(entry)));
        // Varnode::updateType(int4,true,false): typelock + int type.
        s.v_type = Some(int4);
        s.set_flags(varnode_flags::TYPELOCK);
    }
    src
}

// Mirror of the C++ printCase: pre-clean the destination high's typedirty
// cache via updateType, run the op, then observe the raw typedirty bit, the
// lazy isTypeLock re-derivation, the re-derived type metatype, the attached
// high Symbol (+offset), and the destination-level lock/mapentry state.
fn print_case(
    label: &str,
    dst: &Arc<RwLock<Varnode>>,
    src: &Arc<RwLock<Varnode>>,
    op: fn(&Arc<RwLock<Varnode>>, &Arc<RwLock<Varnode>>),
) {
    let high = dst.read().unwrap().high.clone();
    let has_high = u8::from(high.is_some());
    let (mut dirty_before, mut tl_before, mut hmeta_before) = (0, 0, "none");
    if let Some(high) = &high {
        high.write().unwrap().update_type(); // pre-clean the typedirty bit
        let h = high.read().unwrap();
        dirty_before = u8::from(
            (h.highflags & high_internal_flags::TYPEDIRTY) != 0,
        );
        hmeta_before = meta_token(h.get_type().get_metatype());
        drop(h);
        tl_before = u8::from(high.write().unwrap().is_type_lock());
    }
    op(dst, src);
    let (mut dirty_after, mut tl_after, mut hmeta_after) = (0, 0, "none");
    let mut hsym = String::from("none");
    let mut hoff: i32 = -99;
    if let Some(high) = &dst.read().unwrap().high {
        let h = high.read().unwrap();
        dirty_after = u8::from(
            (h.highflags & high_internal_flags::TYPEDIRTY) != 0,
        );
        drop(h);
        tl_after = u8::from(high.write().unwrap().is_type_lock());
        let h = high.read().unwrap();
        hmeta_after = meta_token(h.get_type().get_metatype());
        if let Some(sym) = h.get_symbol() {
            hsym = sym.read().unwrap().get_name().to_string();
            hoff = h.get_symbol_offset();
        }
    }
    let d = dst.read().unwrap();
    println!(
        "case={label}|has_high={has_high}|dirty_before={dirty_before}|tl_before={tl_before}|hmeta_before={hmeta_before}|dirty_after={dirty_after}|tl_after={tl_after}|hmeta_after={hmeta_after}|hsym={hsym}|hoff={hoff}|dst_tl={}|dst_nl={}|dst_mapentry={}",
        u8::from(d.is_type_lock()),
        u8::from(d.is_name_lock()),
        u8::from(d.get_symbol_entry().is_some()),
    );
}

fn main() {
    let int4 = Arc::new(Datatype::Base(TypeBase::new(
        "int4".to_string(),
        4,
        TypeMetatype::Int,
    )));
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    let arch = Arc::new(architecture);

    let mut fd = Funcdata::new("fx", Address::new(0x1000), 0x20);
    fd.set_arch(arch.clone());
    // highlevel_on: every new_constant destination gets a fresh
    // HighVariable (funcdata_varnode.cc:48-59 via 66-73).
    fd.set_high_level();

    // hb_close_propagates_high: equate value equal to the destination
    // constant (cc:642 exact close) -> the full copySymbol incl. cc:500-504.
    {
        let src = make_equate_src(&mut fd, 0x33333333, int4.clone());
        let dst = fd.new_constant(4, 0x33333333);
        print_case("hb_close_propagates_high", &dst, &src, |d, s| {
            Varnode::copy_symbol_if_valid(d, &s.read().unwrap());
        });
    }

    // hb_not_close_no_high_effects: equate 0x12345678 vs constant 0x33333333
    // -> cc:519 rejects before any copy; the pre-cleaned high stays clean.
    {
        let src = make_equate_src(&mut fd, 0x12345678, int4.clone());
        let dst = fd.new_constant(4, 0x33333333);
        print_case("hb_not_close_no_high_effects", &dst, &src, |d, s| {
            Varnode::copy_symbol_if_valid(d, &s.read().unwrap());
        });
    }

    // hb_copy_null_mapentry_dirty: direct copySymbol from a typelocked
    // source with NO SymbolEntry: cc:501 typeDirty fires, cc:502 guard
    // blocks setSymbol.
    {
        let src = fd.new_constant(4, 0x44444444);
        {
            let mut s = src.write().unwrap();
            s.v_type = Some(int4.clone());
            s.set_flags(varnode_flags::TYPELOCK);
        }
        let dst = fd.new_constant(4, 0x44444444);
        print_case("hb_copy_null_mapentry_dirty", &dst, &src, |d, s| {
            Varnode::copy_symbol_arc(d, &s.read().unwrap());
        });
    }

    // hb_dst_no_high: destination from a Funcdata with highlevel disabled —
    // the field copy runs, the cc:500 outer guard skips the bookkeeping.
    {
        let mut fd2 = Funcdata::new("fx2", Address::new(0x2000), 0x20);
        fd2.set_arch(arch.clone());
        let src = make_equate_src(&mut fd, 0x33333333, int4.clone());
        let dst = fd2.new_constant(4, 0x33333333);
        print_case("hb_dst_no_high", &dst, &src, |d, s| {
            Varnode::copy_symbol_if_valid(d, &s.read().unwrap());
        });
    }

    // hb_op_level_marked_input: RuleCollapseConstants (ruleaction.cc:
    // 3854-3882) -> collapseConstantSymbol (op.cc:503-540) ->
    // copySymbolIfValid on an INT_ADD with the equate marked on input 0.
    {
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
        fd.bblocks.add_block(block.clone());

        let rule = RuleCollapseConstants::new();
        let op = fd.new_op(2, Address::new(0x5000));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
        let in0 = fd.new_constant(4, 0x11111111);
        let in1 = fd.new_constant(4, 0x22222222);
        fd.op_set_input(&op, in0.clone(), 0);
        fd.op_set_input(&op, in1, 1);
        fd.new_unique_out(4, &op);
        fd.op_insert_end(&op, &block);

        let symbol = Arc::new(RwLock::new(Symbol::new(0, "FIXTURE_EQ", "equ")));
        equate_symbol_registry::register_value(&symbol, 0x33333333);
        let entry = SymbolEntry::new_dynamic(
            symbol,
            varnode_flags::MAPPED,
            1,
            0,
            4,
            RangeList::default(),
        );
        in0.write().unwrap().set_symbol_entry(Arc::new(RwLock::new(entry)));

        let apply = rule.apply_op(&op.0, &mut fd).expect("apply_op");
        let guard = op.0.read().unwrap();
        let new_in0 = guard.get_in(0).cloned();
        drop(guard);
        let (in0_symbol, has_high, high_symbol, high_off) = match &new_in0 {
            Some(v) => {
                let symbol = u8::from(v.read().unwrap().get_symbol_entry().is_some());
                let high = v.read().unwrap().high.clone();
                match high {
                    Some(h) => {
                        let h_guard = h.read().unwrap();
                        let name = h_guard
                            .get_symbol()
                            .map(|s| s.read().unwrap().get_name().to_string())
                            .unwrap_or_else(|| "none".to_string());
                        (symbol, 1u8, name, h_guard.get_symbol_offset())
                    }
                    None => (symbol, 0, "none".to_string(), -99),
                }
            }
            None => (0, 0, "none".to_string(), -99),
        };
        let opcode = op.0.read().unwrap().opcode as i32;
        println!(
            "case=hb_op_level_marked_input|apply={apply}|opcode={opcode}|in0_symbol={in0_symbol}|in0_has_high={has_high}|in0_high_symbol={high_symbol}|in0_high_off={high_off}"
        );
    }
}
