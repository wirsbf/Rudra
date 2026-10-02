//! VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001: Rugra side of the locked 12.0.4
//! oracle fixture for the lazy `updateType()` trigger inside
//! `HighVariable::getType` (variable.hh:174) and the const `isTypeLock`
//! re-derivation (variable.hh:222).
//!
//! Mirrors `variable_lazytype_1204.cc` case-for-case (same names, same
//! observation format) against the pinned rugra source with the live
//! src/variable.rs + compile-required adaptation overlay
//! (src/analysis/type_infer.rs, src/coreaction.rs, src/merge.rs):
//!   lt_*: see the .cc header for the per-case field sets.
//!
//! Observation routing notes (asymmetric legs are documented here and
//! registered as residuals in the metadata):
//!   - The const-path calls (`get_type`, `is_type_lock`) run under READ
//!     guards, pinning the shared-reference lazy semantics of variable.hh:
//!     174/222 in production form.
//!   - `Varnode::set_symbol_entry` (varnode.rs port of varnode.cc:429-439)
//!     does not yet call `high->set_symbol` (the cc:437-438 leg), so
//!     lt_finalized_guard drives that leg explicitly, exactly like the
//!     varnode_highbranch_1204 fixture does for the cc:500-504 leg.

use std::sync::{Arc, RwLock};

use rudra::address::{Address, RangeList};
use rudra::arch::Architecture;
use rudra::database::{Symbol, SymbolEntry};
use rudra::funcdata::Funcdata;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varnode::{varnode_flags, Varnode};
use rudra::variable::high_internal_flags;

fn meta_token(meta: TypeMetatype) -> &'static str {
    match meta {
        TypeMetatype::Unknown => "unknown",
        TypeMetatype::Int => "int",
        TypeMetatype::Uint => "uint",
        _ => "other",
    }
}

fn dirty_bit(high: &Arc<RwLock<rudra::variable::HighVariable>>) -> u8 {
    u8::from((high.read().unwrap().highflags & high_internal_flags::TYPEDIRTY) != 0)
}

// A fresh constant destination with an auto-attached HighVariable
// (set_high_level mirrors funcdata_varnode.cc:48-59 via 66-73) whose single
// member is typelocked to `ct` through Varnode::updateTypeLock
// (varnode.cc:474-489).
fn make_locked_dst(
    fd: &mut Funcdata,
    ct: &Arc<Datatype>,
    val: u64,
) -> Arc<RwLock<Varnode>> {
    let dst = fd.new_constant(4, val);
    dst.write().unwrap().update_type_lock(ct.clone(), true, false);
    dst
}

fn main() {
    let int4 = Arc::new(Datatype::Base(TypeBase::new(
        "int4".to_string(),
        4,
        TypeMetatype::Int,
    )));
    let uint4 = Arc::new(Datatype::Base(TypeBase::new(
        "uint4".to_string(),
        4,
        TypeMetatype::Uint,
    )));
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    let arch = Arc::new(architecture);

    let mut fd = Funcdata::new("fx", Address::new(0x1000), 0x20);
    fd.set_arch(arch.clone());
    fd.set_high_level();

    // lt_ctor_dirty_lazy_rederive: ctor-seeded typedirty bit visible; the
    // first const get_type() re-derives int from the typelocked
    // representative (variable.cc:400-416).
    {
        let dst = make_locked_dst(&mut fd, &int4, 0x11111111);
        let high = dst.read().unwrap().high.clone().expect("high attached");
        let dirty_ctor = dirty_bit(&high);
        let h = high.read().unwrap();
        let meta1 = meta_token(h.get_type().get_metatype());
        let meta2 = meta_token(h.get_type().get_metatype());
        let tl = u8::from(h.is_type_lock());
        drop(h);
        println!(
            "case=lt_ctor_dirty_lazy_rederive|dirty_ctor={dirty_ctor}|meta1={meta1}|meta2={meta2}|tl={tl}|hsym=none|hoff=-99"
        );
    }

    // lt_precleaned_external_settype_rederives: pre-clean via explicit
    // update_type, then an external type-set through Varnode::copySymbol
    // (cc:496 type copy + cc:501 typeDirty) flips the bit; the next const
    // get_type() lazily re-derives uint.
    {
        let src = fd.new_constant(4, 0x22222222);
        src.write().unwrap().update_type_lock(uint4.clone(), true, false);
        let dst = make_locked_dst(&mut fd, &int4, 0x22222222);
        let high = dst.read().unwrap().high.clone().expect("high attached");
        high.write().unwrap().update_type(); // pre-clean the typedirty bit
        let dirty_pre = dirty_bit(&high);
        let meta_pre = meta_token(high.read().unwrap().get_type().get_metatype());
        Varnode::copy_symbol_arc(&dst, &src.read().unwrap());
        let dirty_post = dirty_bit(&high);
        let h = high.read().unwrap();
        let meta1 = meta_token(h.get_type().get_metatype());
        let meta2 = meta_token(h.get_type().get_metatype());
        let tl = u8::from(h.is_type_lock());
        drop(h);
        println!(
            "case=lt_precleaned_external_settype_rederives|dirty_pre={dirty_pre}|dirty_post={dirty_post}|meta_pre={meta_pre}|meta1={meta1}|meta2={meta2}|tl={tl}|hsym=none|hoff=-99"
        );
    }

    // lt_instance_isolation: dirtying member A leaves high B's bit clear and
    // its const get_type() type unchanged.
    {
        let src = fd.new_constant(4, 0x33333333);
        src.write().unwrap().update_type_lock(uint4.clone(), true, false);
        let dst_a = make_locked_dst(&mut fd, &int4, 0x33333333);
        let dst_b = make_locked_dst(&mut fd, &int4, 0x44444444);
        let high_a = dst_a.read().unwrap().high.clone().expect("high A");
        let high_b = dst_b.read().unwrap().high.clone().expect("high B");
        high_a.write().unwrap().update_type(); // pre-clean both
        high_b.write().unwrap().update_type();
        let dirty_a_pre = dirty_bit(&high_a);
        let dirty_b_pre = dirty_bit(&high_b);
        Varnode::copy_symbol_arc(&dst_a, &src.read().unwrap());
        let dirty_a_post = dirty_bit(&high_a);
        let dirty_b_post = dirty_bit(&high_b);
        let meta_a = meta_token(high_a.read().unwrap().get_type().get_metatype());
        let meta_b = meta_token(high_b.read().unwrap().get_type().get_metatype());
        println!(
            "case=lt_instance_isolation|dirtyA_pre={dirty_a_pre}|dirtyB_pre={dirty_b_pre}|dirtyA_post={dirty_a_post}|dirtyB_post={dirty_b_post}|metaA={meta_a}|metaB={meta_b}"
        );
    }

    // lt_finalized_guard: finalize_datatype locks the symbol's int4; a
    // manual type_dirty then must NOT leak the uint4 representative through
    // the const get_type() (variable.cc:405-407 finalized short-circuit).
    {
        let dst = make_locked_dst(&mut fd, &uint4, 0x55555555);
        let high = dst.read().unwrap().high.clone().expect("high attached");
        high.write().unwrap().update_type(); // pre-clean
        let dirty_pre = dirty_bit(&high);
        let symbol = Arc::new(RwLock::new(Symbol::new(0, "FIXTURE_TY", "int4")));
        symbol.write().unwrap().dtype = Some(int4.clone());
        let entry = Arc::new(RwLock::new(SymbolEntry::new_dynamic(
            symbol,
            varnode_flags::MAPPED,
            0x1234,
            0,
            4,
            RangeList::default(),
        )));
        dst.write().unwrap().set_symbol_entry(entry);
        // Mirror of the varnode.cc:437-438 setSymbolEntry high leg
        // (unported in varnode.rs set_symbol_entry; see metadata residual).
        high.write().unwrap().set_symbol(&dst);
        high.write().unwrap().finalize_datatype();
        let (hsym, hoff) = {
            let h = high.read().unwrap();
            let name = h
                .get_symbol()
                .map(|s| s.read().unwrap().get_name().to_string())
                .unwrap_or_else(|| "none".to_string());
            (name, h.get_symbol_offset())
        };
        high.write().unwrap().type_dirty();
        let dirty_manual = dirty_bit(&high);
        let h = high.read().unwrap();
        let meta1 = meta_token(h.get_type().get_metatype());
        let meta2 = meta_token(h.get_type().get_metatype());
        let tl = u8::from(h.is_type_lock());
        drop(h);
        println!(
            "case=lt_finalized_guard|dirty_pre={dirty_pre}|hsym={hsym}|hoff={hoff}|dirty_manual={dirty_manual}|meta1={meta1}|meta2={meta2}|tl={tl}"
        );
    }
}
