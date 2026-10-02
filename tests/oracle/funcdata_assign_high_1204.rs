// FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001 fixture — Rust side.
//
// Mirrors tests/oracle/funcdata_assign_high_1204.cc case by case against the
// locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// Funcdata::assign_high is the port of Funcdata::assignHigh
// (funcdata_varnode.cc:48-59); the ten call-site wirings are
// newConstant(:72) / newUnique(:89) / newVarnodeOut(:110) / newUniqueOut(:135)
// / newVarnode(:157) / newVarnodeIop(:182) / newVarnodeSpace(:196) /
// newVarnodeCallSpecs(:212) / newCodeRef(:231) / setHighLevel(:604).
//
// Structural mapping notes (registered in the metadata):
//   * Ghidra 12.0.4 Varnode::getHigh() THROWS LowlevelError("Requesting
//     non-existent high-level", varnode.cc:92) on a high-less Varnode; the
//     oracle fixture reads the raw `high` field, and this side reads the
//     `high: Option` field — identical observation channel.
//   * copySymbol's cc:500-504 high leg lives in the Varnode::copySymbol body
//     in Ghidra (varnode.cc:500-504); Rugra keeps the leg at the call site
//     (funcdata.rs op_set_input house pattern, VARNODE-COPYSYMBOL-FIELDS-0001),
//     so the copysymbol_dirty case runs copy_symbol + the call-site leg.
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::funcdata::funcdata_flags;
use rudra::funcdata::Funcdata;
use rudra::varnode::varnode_flags;
use rudra::variable::high_internal_flags;

type Vn = Arc<RwLock<rudra::varnode::Varnode>>;

fn high_is_some(vn: &Vn) -> bool {
    vn.read().unwrap().high.is_some()
}

fn main() {
    let mut fd = Funcdata::new("fixture", Address::new(0x1000), 0x100);

    // --- A: highlevel_on CLEAR — assign_high must early-out (cc:51) -------
    let off_const = fd.new_constant(4, 0x1111);
    let off_uniq = fd.new_unique(4);
    println!("off_constant:{}", high_is_some(&off_const) as u8);
    println!("off_unique:{}", high_is_some(&off_uniq) as u8);

    // --- B: populate the bank, then set_high_level (cc:595-605) ----------
    // written shape via new_varnode_out (create_def_with_space sets
    // written|coverdirty, and xref sets insert, so has_cover() is true when
    // the assign sweep reaches it).
    let defop = fd.new_op(1, Address::new(0x1020));
    let written_vn = fd.new_varnode_out(8, Address::new(0x310), &defop);
    // input varnode
    let input_free = fd.new_varnode(8, Address::new(0x300));
    let input_vn = fd.set_input_varnode(input_free);
    // iop-space annotation varnode
    let annot_op = fd.new_op(1, Address::new(0x1030));
    let iop_vn = fd.new_varnode_iop(&annot_op);
    // cover of a not-yet-assigned written varnode is None
    let pre_cover_null = written_vn.read().unwrap().cover.is_none();
    let index_baseline = iop_vn.read().unwrap().create_index;

    fd.set_high_level();
    println!("sethigh_flag:{}", ((fd.flags & funcdata_flags::HIGHLEVEL_ON) != 0) as u8);
    println!("sethigh_index:{}", (fd.high_level_index != 0
        && fd.high_level_index > index_baseline) as u8);
    println!("sethigh_const:{}", high_is_some(&off_const) as u8);
    let written_ok = {
        let w = written_vn.read().unwrap();
        let cover_ok = pre_cover_null
            && w.cover.is_some()
            && (w.flags & varnode_flags::COVERDIRTY) != 0;
        (w.high.is_some(), cover_ok)
    };
    println!("sethigh_written:{},cover={}", written_ok.0 as u8, written_ok.1 as u8);
    println!("sethigh_input:{}", high_is_some(&input_vn) as u8);
    println!("sethigh_iop:{}", high_is_some(&iop_vn) as u8);

    let shape = {
        let vn_r = off_const.read().unwrap();
        match &vn_r.high {
            Some(h) => {
                let h_r = h.read().unwrap();
                h_r.instances.len() == 1
                    && Arc::ptr_eq(&h_r.instances[0], &off_const)
                    && vn_r.mergegroup == 0
                    && h_r.num_merge_classes == 1
            }
            None => false,
        }
    };
    println!("sethigh_instances:{}", shape as u8);

    let h_const_before = off_const.read().unwrap().high.clone();
    fd.set_high_level();
    let idem = off_const.read().unwrap().high.as_ref().map(|h| {
        h_const_before.as_ref().is_some_and(|b| Arc::ptr_eq(h, b))
    }).unwrap_or(false);
    println!("sethigh_idem:{}", idem as u8);

    // --- C: highlevel_on SET — the new_* family assigns highs ------------
    let on_const = fd.new_constant(4, 0x2222);
    println!("on_constant:{}", high_is_some(&on_const) as u8);
    let on_uniq = fd.new_unique(4);
    println!("on_unique:{}", high_is_some(&on_uniq) as u8);

    let out_op = fd.new_op(1, Address::new(0x1040));
    let on_vnout = fd.new_varnode_out(8, Address::new(0x320), &out_op);
    let vnout_shape = {
        let vn_r = on_vnout.read().unwrap();
        match &vn_r.high {
            Some(h) => {
                let h_r = h.read().unwrap();
                h_r.instances.len() == 1
                    && Arc::ptr_eq(&h_r.instances[0], &on_vnout)
                    && vn_r.mergegroup == 0
            }
            None => false,
        }
    };
    println!("on_varnodeout:{},shape={}", high_is_some(&on_vnout) as u8, vnout_shape as u8);

    let uout_op = fd.new_op(1, Address::new(0x1050));
    let on_uout = fd.new_unique_out(8, &uout_op);
    println!("on_uniqueout:{}", high_is_some(&on_uout) as u8);

    let iop_op = fd.new_op(1, Address::new(0x1060));
    let on_iop = fd.new_varnode_iop(&iop_op);
    println!("on_iop:{}", high_is_some(&on_iop) as u8);

    let on_space = fd.new_varnode_space(rudra::space::AddressSpace::Ram);
    println!("on_space:{}", high_is_some(&on_space) as u8);

    let on_coderef = fd.new_code_ref(Address::new(0x2000));
    println!("on_coderef:{}", high_is_some(&on_coderef) as u8);

    // --- D: op_set_input constant dedup feeds copySymbol's high leg (R1) --
    let use1 = fd.new_op(1, Address::new(0x1070));
    let use2 = fd.new_op(1, Address::new(0x1080));
    let shared_const = fd.new_constant(4, 0xABCD);
    // First attach: no descendant yet, no dedup, add_descend(use1).
    fd.op_set_input(&use1, shared_const.clone(), 0);
    // Second attach: shared_const now has a descendant -> dedup fires
    // (funcdata_op.cc:108-115): cvn = new_constant(...); cvn.copy_symbol(vn).
    fd.op_set_input(&use2, shared_const.clone(), 0);
    let dedup_vn = use2.0.read().unwrap().inrefs[0].clone();
    let dedup_ok = {
        let d = dedup_vn.read().unwrap();
        let s = shared_const.read().unwrap();
        !Arc::ptr_eq(&dedup_vn, &shared_const)
            && d.is_constant()
            && d.get_offset() == 0xABCD
            && d.high.is_some()
            && d.high.as_ref().map(|h| h.read().unwrap().instances.len() == 1
                && Arc::ptr_eq(&h.read().unwrap().instances[0], &dedup_vn))
                .unwrap_or(false)
            && d.v_type.is_some()
            && d.v_type.as_ref().map(|t| t.get_size() == s.v_type.as_ref().map(|t2| t2.get_size()).unwrap_or(0))
                .unwrap_or(false)
    };
    println!("dedup_high:{}", dedup_ok as u8);

    // --- E: copySymbol typedirty re-arm + symbol guard (varnode.cc:500-504)
    // Rugra keeps cc:500-504 at the call site (op_set_input house pattern),
    // so this side runs copy_symbol + that leg.
    let h_arc = dedup_vn.read().unwrap().high.clone().expect("high after dedup");
    {
        // Test-only: clear the ctor-armed typedirty so the re-arm is observable.
        h_arc.write().unwrap().highflags &= !high_internal_flags::TYPEDIRTY;
    }
    let src_const = fd.new_constant(4, 0xABCD);
    {
        let src = src_const.read().unwrap();
        dedup_vn.write().unwrap().copy_symbol(&src);
    }
    // Call-site leg (funcdata.rs op_set_input, mirroring varnode.cc:500-504):
    // high->typeDirty(); if (mapentry != 0) high->setSymbol(this).
    if let Some(high) = dedup_vn.read().unwrap().get_high().cloned() {
        let has_mapentry = dedup_vn.read().unwrap().mapentry.is_some();
        let mut h = high.write().unwrap();
        h.type_dirty();
        if has_mapentry {
            h.set_symbol(&dedup_vn);
        }
    }
    let rearm = {
        let h = h_arc.read().unwrap();
        (h.highflags & high_internal_flags::TYPEDIRTY) != 0
            && h.symbol.is_none()
    };
    println!("copysymbol_dirty:{}", rearm as u8);
    let symbol_null = h_arc.read().unwrap().symbol.is_none();
    println!("copysymbol_symbol:{}", symbol_null as u8);
}
