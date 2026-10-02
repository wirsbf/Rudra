// FSPEC-SCORE-MERGED-1204: Rugra comparand for the locked Ghidra 12.0.4
// oracle (MIGW-FSPEC wave). Mirrors tests/oracle/fspec_score_merged_1204.cc
// observation for observation:
//  - score_penalty_walk: ScoreProtoModel::do_score penalty walk (hole 16 /
//    duplication 20 / mismatch 20 / 25-mismatch 500 threshold);
//  - param_list_merged_fold_in: ParamListMerged::fold_in adopt/replace/
//    subsumed/different-stacks refusal + finalize resolver observations;
//  - proto_model_merged_fold_in + select_model: ProtoModelMerged::fold_in
//    adoption/extrapop-demotion/inject-refusal/effect+trash intersection
//    (foldIn never touches modellist — decode's push is staged explicitly,
//    mirroring fspec.cc:2918) and selectModel's strict-< first-best walk
//    plus the "No model matches : missing default" refusal at score 500.

use rudra::address::Address;
use rudra::fspec::{
    containment, param_entry_flags, EffectRecord, EffectType, ParamActive, ParamEntry,
    ParamListMerged, ParamListStandard, ProtoModelFull, ProtoModelMerged, ScoreProtoModel,
    TypeClass, VarnodeData, EXTRA_POP_UNKNOWN,
};
use rudra::space::AddressSpace;

fn make_entry(grp: i32, base: u64, size: i32, min_size: i32, alignment: i32) -> ParamEntry {
    let mut e = ParamEntry::new(grp);
    *e.flags_mut() = 0;
    e.set_type_class(TypeClass::General);
    e.set_space(AddressSpace::Ram);
    e.set_base(base);
    e.set_sizes(size, min_size);
    e.set_alignment(alignment);
    e
}

fn stage_list(list: &mut ParamListStandard) {
    let mut effects: Vec<EffectRecord> = Vec::new();
    let _ = &mut effects;
    list.finalize_after_decode(8);
    list.populate_resolver();
}

fn make_input_list() -> ParamListStandard {
    let mut list = ParamListStandard::new();
    let mut effects = Vec::new();
    list.parse_pentry(0, true, false, false, &mut effects, make_entry(0, 0x100, 8, 8, 0))
        .unwrap();
    list.parse_pentry(0, true, false, false, &mut effects, make_entry(1, 0x200, 8, 8, 0))
        .unwrap();
    stage_list(&mut list);
    list
}

fn make_model(
    nm: &str,
    extrapop: i32,
    inject_entry: i32,
    inject_return: i32,
    trash_offset2: u64,
) -> ProtoModelFull {
    let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
    model.name = nm.to_string();
    model.extrapop = extrapop;
    model.input = make_input_list();
    // Output list mirrors the C++ staging (populateResolver included, the
    // fspec.cc:1504 configured state).
    let mut out_effects = Vec::new();
    let mut out = rudra::fspec::ParamListStandardOut::new();
    out.base
        .parse_pentry(0, true, false, false, &mut out_effects, make_entry(0, 0x300, 8, 1, 0))
        .unwrap();
    stage_list(&mut out.base);
    model.output = rudra::fspec::ParamListOutput::standard_with_base(out);
    model.inject_upon_entry = inject_entry;
    model.inject_upon_return = inject_return;

    model.effectlist = vec![
        EffectRecord::new(AddressSpace::Ram, 0x500, 8, EffectType::Unaffected),
        EffectRecord::new(AddressSpace::Ram, 0x600, 8, EffectType::KilledByCall),
        EffectRecord::new(AddressSpace::Ram, 0x700, 8, EffectType::ReturnAddress),
    ];
    model.likelytrash = vec![
        VarnodeData { space: AddressSpace::Ram, offset: 0x500, size: 8 },
        VarnodeData { space: AddressSpace::Ram, offset: trash_offset2, size: 8 },
    ];
    model
}

fn main() {
    println!(
        "schema=1|fixture=FSPEC-SCORE-MERGED-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    // ---- case 1: ScoreProtoModel penalty walk -------------------------
    println!("case=score_penalty_walk");
    {
        let model = make_model("m1", 0, -1, -1, 0x800);
        {
            let mut sm = ScoreProtoModel::new(true, &model, 2);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x100), 8);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x200), 8);
            sm.do_score();
            println!("  walk=exact score={} mismatch={}", sm.get_score(), sm.get_num_mismatch());
        }
        {
            let mut sm = ScoreProtoModel::new(true, &model, 1);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x200), 8);
            sm.do_score();
            println!("  walk=hole0 score={} mismatch={}", sm.get_score(), sm.get_num_mismatch());
        }
        {
            let mut sm = ScoreProtoModel::new(true, &model, 2);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x100), 8);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x100), 8);
            sm.do_score();
            println!("  walk=dup score={} mismatch={}", sm.get_score(), sm.get_num_mismatch());
        }
        {
            let mut sm = ScoreProtoModel::new(true, &model, 4);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x200), 8);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x200), 8);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x900), 8);
            sm.do_score();
            println!("  walk=mixed score={} mismatch={}", sm.get_score(), sm.get_num_mismatch());
        }
        {
            let mut sm = ScoreProtoModel::new(true, &model, 25);
            for i in 0..25 {
                sm.add_parameter(AddressSpace::Ram, Address::new(0x900 + i), 8);
            }
            sm.do_score();
            println!(
                "  walk=mismatch25 score={} mismatch={}",
                sm.get_score(),
                sm.get_num_mismatch()
            );
        }
        {
            let mut sm = ScoreProtoModel::new(false, &model, 1);
            sm.add_parameter(AddressSpace::Ram, Address::new(0x300), 4);
            sm.do_score();
            println!("  walk=output score={} mismatch={}", sm.get_score(), sm.get_num_mismatch());
        }
    }

    // ---- case 2: ParamListMerged::foldIn -------------------------------
    println!("case=param_list_merged_fold_in");
    {
        let mut merged = ParamListMerged::new();
        let mut a = ParamListStandard::new();
        {
            let mut effects = Vec::new();
            a.parse_pentry(0, true, false, false, &mut effects, make_entry(0, 0x100, 8, 4, 0))
                .unwrap();
            stage_list(&mut a);
        }
        let mut b = ParamListStandard::new();
        {
            let mut effects = Vec::new();
            b.parse_pentry(0, true, false, false, &mut effects, make_entry(0, 0x100, 16, 4, 0))
                .unwrap();
            b.parse_pentry(0, true, false, false, &mut effects, make_entry(1, 0x200, 8, 4, 0))
                .unwrap();
            stage_list(&mut b);
        }
        let mut stack_list = ParamListStandard::new();
        {
            let mut effects = Vec::new();
            stack_list
                .parse_pentry(0, true, false, false, &mut effects, make_entry(0, 0x20, 8, 1, 8))
                .unwrap();
            stack_list.set_space_base(Some(AddressSpace::Stack));
            stage_list(&mut stack_list);
        }

        merged.fold_in(&a).unwrap();
        println!(
            "  fold=adopt size={} base=0x{:x}",
            merged.base.get_entry().len(),
            merged.base.get_entry()[0].get_base()
        );
        merged.fold_in(&b).unwrap();
        let entries = merged.base.get_entry();
        println!(
            "  fold=replace size={} front_size={} back_group={}",
            entries.len(),
            entries[0].get_size(),
            entries[entries.len() - 1].get_group()
        );
        merged.fold_in(&a).unwrap();
        println!("  fold=subsumed size={}", merged.base.get_entry().len());
        match merged.fold_in(&stack_list) {
            Ok(()) => println!("  fold=stackconflict UNEXPECTED-OK"),
            Err(e) => println!("  fold=stackconflict err={e}"),
        }
        merged.finalize();
        println!(
            "  fold=finalize char_0x100_16={} char_0x200_8={} char_0x400_8={}",
            merged.base.characterize_as_param(AddressSpace::Ram, 0x100, 16),
            merged.base.characterize_as_param(AddressSpace::Ram, 0x200, 8),
            merged.base.characterize_as_param(AddressSpace::Ram, 0x400, 8),
        );
        let mut slot = -1i32;
        let mut slot_size = -1i32;
        let isparam = merged.base.possible_param_with_slot(
            AddressSpace::Ram,
            Address::new(0x200),
            8,
            &mut slot,
            &mut slot_size,
        );
        println!(
            "  fold=slot isparam={} slot={} slotsize={}",
            if isparam { 1 } else { 0 },
            slot,
            slot_size
        );
        let _ = containment::CONTAINS_JUSTIFIED;
        let _ = param_entry_flags::FORCE_LEFT_JUSTIFY;
    }

    // ---- case 3: ProtoModelMerged::foldIn + selectModel ----------------
    println!("case=proto_model_merged_fold_in");
    println!("case=select_model");
    {
        let m1 = std::sync::Arc::new(make_model("m1", 0, -1, -1, 0x800));
        let m2 = std::sync::Arc::new(make_model("m2", 8, -1, -1, 0x900));
        let m3 = std::sync::Arc::new(make_model("m3", 0, 5, -1, 0x800));

        let mut merged = ProtoModelMerged::new();
        merged.fold_in(&m1).unwrap();
        println!(
            "  pm=first nummodels={} extrapop={} effects={} trash={}",
            merged.num_models(),
            merged.extrapop,
            merged.effectlist.len(),
            merged.likelytrash.len()
        );
        merged.fold_in(&m2).unwrap();
        println!(
            "  pm=second nummodels={} extrapop_unknown={} effects={} trash={}",
            merged.num_models(),
            if merged.extrapop == EXTRA_POP_UNKNOWN { 1 } else { 0 },
            merged.effectlist.len(),
            merged.likelytrash.len()
        );
        match merged.fold_in(&m3) {
            Ok(()) => println!("  pm=injectmismatch UNEXPECTED-OK"),
            Err(e) => println!("  pm=injectmismatch err={e}"),
        }
        // foldIn never touches modellist (decode's push, fspec.cc:2918).
        merged.modellist.push(m1.clone());
        merged.modellist.push(m2.clone());
        println!(
            "  pm=ismerged={} nummodels={} model1={}",
            if merged.is_merged() { 1 } else { 0 },
            merged.num_models(),
            merged.get_model(1).name
        );

        {
            let mut active = ParamActive::new(true);
            active.register_trial_in_space(AddressSpace::Ram, Address::new(0x200), 8);
            active.get_trial_mut(0).mark_active();
            let sel = merged.select_model(&active).unwrap();
            println!("  sel=firstactive model={}", sel.name);
        }
        {
            let mut active = ParamActive::new(true);
            active.register_trial_in_space(AddressSpace::Ram, Address::new(0x100), 8);
            let sel = merged.select_model(&active).unwrap();
            println!("  sel=nosub model={}", sel.name);
        }
        {
            let mut active = ParamActive::new(true);
            for i in 0..25 {
                active.register_trial_in_space(AddressSpace::Ram, Address::new(0x900 + i), 8);
            }
            for i in 0..active.get_num_trials() {
                active.get_trial_mut(i).mark_active();
            }
            match merged.select_model(&active) {
                Ok(m) => println!("  sel=threshold UNEXPECTED-OK model={}", m.name),
                Err(e) => println!("  sel=threshold err={e}"),
            }
        }
    }

    println!("done");
}
