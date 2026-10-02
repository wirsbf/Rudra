#!/usr/bin/env python3
"""
Insert `// Ghidra:` or `// RUDRA-GLUE:` annotations above every flagged fn in
src/coreaction.rs.  Processes bottom-to-top so earlier line numbers stay
stable as comments are inserted.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RS = ROOT / "src" / "coreaction.rs"

# ---------------------------------------------------------------------------
# Mapping: (1-based line, fn_name) -> annotation text (without indent).
# Lines come from result/violations_structured.json key src/coreaction.rs.
# Each annotation is inserted on a new line directly ABOVE the flagged fn.
# ---------------------------------------------------------------------------
A = {
    # --- ActionHeritage ---
    18:  "// Ghidra: coreaction.hh:284 ActionHeritage (constructor mirror)",
    24:  "// Ghidra: coreaction.hh:289 ActionHeritage::apply",
    65:  "// RUDRA-GLUE: Rust Action trait get_name; string \"heritage\" mirrors ctor at coreaction.hh:284",
    # --- ActionDeadCode ---
    85:  "// Ghidra: coreaction.hh:552 ActionDeadCode (constructor mirror)",
    93:  "// Ghidra: coreaction.cc:3556 ActionDeadCode::pushConsumed",
    115: "// Ghidra: coreaction.cc:3576 ActionDeadCode::propagateConsumed",
    172: "// Ghidra: coreaction.cc:3925 ActionDeadCode::apply",
    293: "// RUDRA-GLUE: Rust Action trait get_name; \"deadcode\" mirrors ctor at coreaction.hh:552",
    # --- ActionConstantPtr ---
    304: "// Ghidra: coreaction.hh:188 ActionConstantPtr (constructor mirror)",
    310: "// Ghidra: coreaction.cc:1167 ActionConstantPtr::apply",
    343: "// RUDRA-GLUE: Rust Action trait get_name; \"constantptr\" mirrors ctor at coreaction.hh:188",
    # --- ActionCse (commented out / removed in current Ghidra) ---
    354: "// Ghidra: coreaction.cc:708 ActionCse (historical; apply body commented out in current Ghidra)",
    360: "// Ghidra: coreaction.cc:708 ActionCse::apply (historical; commented out / removed in current Ghidra)",
    433: "// RUDRA-GLUE: Rust Action trait get_name; \"cse\" mirrors the historical ActionCse at coreaction.cc:708",
    # --- ActionRestructureVarnode ---
    453: "// Ghidra: coreaction.hh:854 ActionRestructureVarnode (constructor mirror)",
    459: "// Ghidra: coreaction.cc:2274 ActionRestructureVarnode::apply",
    470: "// RUDRA-GLUE: Rust Action trait get_name; \"restructure_varnode\" mirrors ctor at coreaction.hh:855",
    # --- ActionStart ---
    479: "// Ghidra: coreaction.hh:36 ActionStart (constructor mirror)",
    485: "// Ghidra: coreaction.hh:41 ActionStart::apply",
    489: "// RUDRA-GLUE: Rust Action trait get_name; \"start\" mirrors ctor at coreaction.hh:36",
    # --- ActionMergeRequired ---
    500: "// Ghidra: coreaction.hh:364 ActionMergeRequired (constructor mirror)",
    506: "// Ghidra: coreaction.hh:369 ActionMergeRequired::apply",
    512: "// RUDRA-GLUE: Rust Action trait get_name; \"mergerequired\" mirrors ctor at coreaction.hh:364",
    # --- ActionMergeAdjacent ---
    523: "// Ghidra: coreaction.hh:376 ActionMergeAdjacent (constructor mirror)",
    529: "// Ghidra: coreaction.hh:381 ActionMergeAdjacent::apply",
    535: "// RUDRA-GLUE: Rust Action trait get_name; \"mergeadjacent\" mirrors ctor at coreaction.hh:376",
    # --- ActionMergeCopy ---
    549: "// Ghidra: coreaction.hh:387 ActionMergeCopy (constructor mirror)",
    555: "// Ghidra: coreaction.hh:392 ActionMergeCopy::apply",
    562: "// RUDRA-GLUE: Rust Action trait get_name; \"mergecopy\" mirrors ctor at coreaction.hh:387",
    # --- ActionMergeMultiEntry ---
    573: "// Ghidra: coreaction.hh:398 ActionMergeMultiEntry (constructor mirror)",
    579: "// Ghidra: coreaction.hh:403 ActionMergeMultiEntry::apply",
    585: "// RUDRA-GLUE: Rust Action trait get_name; \"mergemultientry\" mirrors ctor at coreaction.hh:398",
    # --- ActionMergeType ---
    596: "// Ghidra: coreaction.hh:409 ActionMergeType (constructor mirror)",
    602: "// Ghidra: coreaction.hh:414 ActionMergeType::apply",
    608: "// RUDRA-GLUE: Rust Action trait get_name; \"mergetype\" mirrors ctor at coreaction.hh:409",
    # --- ActionSimplify (Rugra-specific; no Ghidra counterpart) ---
    623: "// RUDRA-GLUE: Rugra-specific peephole simplifier; no single Ghidra Action counterpart (Ghidra folds these via Rule pool in ruleaction.cc)",
    629: "// RUDRA-GLUE: Rugra-specific peephole simplifier apply; no single Ghidra counterpart",
    747: "// RUDRA-GLUE: Rust Action trait get_name for Rugra-specific ActionSimplify",
    # --- ActionCopyPropagate (Rugra-specific) ---
    759: "// RUDRA-GLUE: Rugra-specific copy-propagation pass; no direct Ghidra Action counterpart",
    765: "// RUDRA-GLUE: Rugra-specific copy-propagation apply",
    859: "// RUDRA-GLUE: Rust Action trait get_name for Rugra-specific ActionCopyPropagate",
    # --- ActionCallParams helpers + struct (Rugra-specific) ---
    886: "// RUDRA-GLUE: Rugra-specific ABI table (SysV known-callee param count); no Ghidra counterpart (Ghidra uses FuncProto lock instead)",
    960: "// RUDRA-GLUE: Rugra-specific ABI table (SysV known-callee param types)",
    985: "// RUDRA-GLUE: Rugra-specific ABI table (known-callee predicate)",
    1009: "// RUDRA-GLUE: Rugra-specific ABI table (known-callee return type)",
    1048: "// RUDRA-GLUE: Rugra-specific param fill-in pass; no direct Ghidra Action counterpart",
    1054: "// RUDRA-GLUE: Rugra-specific param fill-in apply",
    1281: "// RUDRA-GLUE: Rust Action trait get_name for Rugra-specific ActionCallParams",
    # --- ActionInferParams (Rugra-specific) ---
    1297: "// RUDRA-GLUE: Rugra-specific param inference pass; no direct Ghidra Action counterpart",
    1303: "// RUDRA-GLUE: Rugra-specific param inference apply",
    1607: "// RUDRA-GLUE: Rust Action trait get_name for Rugra-specific ActionInferParams",
    # --- ActionTypeInfer (Rugra-specific) ---
    1621: "// RUDRA-GLUE: Rugra-specific whole-function type inference; no direct Ghidra Action counterpart (Ghidra uses ActionInferTypes instead)",
    1627: "// RUDRA-GLUE: Rugra-specific whole-function type inference apply",
    1897: "// RUDRA-GLUE: Rust Action trait get_name for Rugra-specific ActionTypeInfer",
    # --- type helpers ---
    1902: "// RUDRA-GLUE: helper mirroring TypePointer::getPtrTo (type.hh); used by Rugra type inference",
    1910: "// RUDRA-GLUE: helper mirroring TypeFactory::getTypePointer (type.hh); used by Rugra type inference",
    # --- ActionUnreachable ---
    1931: "// Ghidra: coreaction.hh:493 ActionUnreachable (constructor mirror)",
    1934: "// Ghidra: coreaction.cc:3457 ActionUnreachable::apply",
    1942: "// RUDRA-GLUE: Rust Action trait get_name; \"unreachable\" mirrors ctor at coreaction.hh:493",
    # --- ActionDoNothing ---
    1952: "// Ghidra: coreaction.hh:504 ActionDoNothing (constructor mirror)",
    1955: "// Ghidra: coreaction.cc:3466 ActionDoNothing::apply",
    2024: "// RUDRA-GLUE: Rust Action trait get_name; \"donothing\" mirrors ctor at coreaction.hh:504",
    # --- ActionRedundBranch ---
    2038: "// Ghidra: coreaction.hh:515 ActionRedundBranch (constructor mirror)",
    2041: "// Ghidra: coreaction.cc:3492 ActionRedundBranch::apply",
    2105: "// RUDRA-GLUE: Rust Action trait get_name; \"redundbranch\" mirrors ctor at coreaction.hh:515",
    # --- ActionDeterminedBranch ---
    2116: "// Ghidra: coreaction.hh:526 ActionDeterminedBranch (constructor mirror)",
    2119: "// Ghidra: coreaction.cc:3530 ActionDeterminedBranch::apply",
    2166: "// RUDRA-GLUE: Rust Action trait get_name; \"determinedbranch\" mirrors ctor at coreaction.hh:526",
    # --- ActionHideShadow ---
    2176: "// Ghidra: coreaction.hh:992 ActionHideShadow (constructor mirror)",
    2179: "// Ghidra: coreaction.cc:4831 ActionHideShadow::apply",
    2210: "// RUDRA-GLUE: Rust Action trait get_name; \"hideshadow\" mirrors ctor at coreaction.hh:992",
    # --- ActionSwitchNorm ---
    2220: "// Ghidra: coreaction.hh:609 ActionSwitchNorm (constructor mirror)",
    2223: "// Ghidra: coreaction.cc:4548 ActionSwitchNorm::apply",
    2263: "// RUDRA-GLUE: Rust Action trait get_name; \"switchnorm\" mirrors ctor at coreaction.hh:609",
    # --- ActionNormalizeSetup ---
    2273: "// Ghidra: coreaction.hh:630 ActionNormalizeSetup (constructor mirror)",
    2276: "// Ghidra: coreaction.cc:4567 ActionNormalizeSetup::apply",
    2291: "// RUDRA-GLUE: Rust Action trait get_name; \"normalizesetup\" mirrors ctor at coreaction.hh:630",
    # --- ActionPrototypeWarnings ---
    2304: "// Ghidra: coreaction.hh:1047 ActionPrototypeWarnings (constructor mirror)",
    2307: "// Ghidra: coreaction.cc:4886 ActionPrototypeWarnings::apply",
    2335: "// RUDRA-GLUE: Rust Action trait get_name; \"prototypewarnings\" mirrors ctor at coreaction.hh:1047",
    # --- ActionMarkExplicit ---
    2351: "// Ghidra: coreaction.hh:427 ActionMarkExplicit (constructor mirror)",
    2359: "// Ghidra: coreaction.cc:3007 ActionMarkExplicit::baseExplicit",
    2401: "// Ghidra: coreaction.cc:3237 ActionMarkExplicit::apply",
    2438: "// RUDRA-GLUE: Rust Action trait get_name; \"markexplicit\" mirrors ctor at coreaction.hh:427",
    # --- ActionMarkImplied ---
    2451: "// Ghidra: coreaction.hh:449 ActionMarkImplied (constructor mirror)",
    2457: "// Ghidra: coreaction.cc:3279 ActionMarkImplied::isPossibleAliasStep",
    2502: "// Ghidra: coreaction.cc:3376 ActionMarkImplied::checkImpliedCover",
    2608: "// Ghidra: coreaction.cc:3416 ActionMarkImplied::apply",
    2649: "// RUDRA-GLUE: Rust Action trait get_name; \"markimplied\" mirrors ctor at coreaction.hh:449",
    # --- ActionSetCasts ---
    2664: "// Ghidra: coreaction.hh:330 ActionSetCasts (constructor mirror)",
    2673: "// RUDRA-GLUE: helper mapping OpCode -> TypeMetatype for cast decisions; mirrors OpCode::getMetadata (typeop.cc)",
    2706: "// Ghidra: coreaction.cc:2655 ActionSetCasts::castInput",
    2760: "// Ghidra: coreaction.cc:2722 ActionSetCasts::apply",
    2791: "// RUDRA-GLUE: Rust Action trait get_name; \"setcasts\" mirrors ctor at coreaction.hh:330",
    # --- ActionInferTypes ---
    2812: "// Ghidra: coreaction.hh:960 ActionInferTypes (constructor mirror)",
    2826: "// RUDRA-GLUE: Rugra helper producing a stable u64 key for a Varnode (Rust borrow workaround)",
    2836: "// RUDRA-GLUE: helper mirroring TypeFactory::getTypePointer (type.hh)",
    2850: "// RUDRA-GLUE: helper mirroring TypePointer::getPtrTo (type.hh)",
    2992: "// Ghidra: coreaction.cc:5074 ActionInferTypes::propagateTypeEdge",
    3069: "// RUDRA-GLUE: Rugra driver that folds ActionInferTypes::propagateOneType over the varnode set (coreaction.cc:5400-5405)",
    3219: "// Ghidra: coreaction.cc:5172 ActionInferTypes::propagateOneType",
    3345: "// Ghidra: coreaction.cc:5043 ActionInferTypes::writeBack",
    3368: "// Ghidra: coreaction.cc:5342 ActionInferTypes::propagateAcrossReturns",
    3460: "// RUDRA-GLUE: IntTypes helper; size->Datatype lookup mirroring TypeFactory base-type table",
    3471: "// Ghidra: coreaction.cc:5374 ActionInferTypes::apply",
    3561: "// RUDRA-GLUE: Rust Action trait get_name; \"infertypes\" mirrors ctor at coreaction.hh:960",
    # --- ActionNameVars ---
    3574: "// Ghidra: coreaction.hh:470 ActionNameVars (constructor mirror)",
    3577: "// Ghidra: coreaction.cc:2978 ActionNameVars::apply",
    3601: "// RUDRA-GLUE: Rust Action trait get_name; \"namevars\" mirrors ctor at coreaction.hh:470",
    # --- ActionVarnodeProps ---
    3608: "// Ghidra: coreaction.hh:222 ActionVarnodeProps (constructor mirror)",
    3611: "// Ghidra: coreaction.cc:1282 ActionVarnodeProps::apply",
    3666: "// RUDRA-GLUE: Rust Action trait get_name; \"varnodeprops\" mirrors ctor at coreaction.hh:222",
    # --- ActionRestrictLocal ---
    3680: "// Ghidra: coreaction.hh:813 ActionRestrictLocal (constructor mirror)",
    3683: "// Ghidra: coreaction.cc:1957 ActionRestrictLocal::apply",
    3746: "// RUDRA-GLUE: Rust Action trait get_name; \"restrictlocal\" mirrors ctor at coreaction.hh:813",
    # --- ActionMultiCse ---
    3753: "// Ghidra: coreaction.hh:163 ActionMultiCse (constructor mirror)",
    3757: "// RUDRA-GLUE: Rugra helper chasing COPY chains; Ghidra inlines this within ActionMultiCse::processBlock (coreaction.cc:790-810)",
    3783: "// Ghidra: coreaction.cc:741 ActionMultiCse::preferredOutput",
    3824: "// Ghidra: coreaction.cc:777 ActionMultiCse::findMatch",
    3878: "// Ghidra: coreaction.cc:822 ActionMultiCse::processBlock",
    3945: "// Ghidra: coreaction.cc:879 ActionMultiCse::apply",
    3978: "// RUDRA-GLUE: Rust Action trait get_name; \"multicse\" mirrors ctor at coreaction.hh:163",
    # --- ActionDirectWrite ---
    3999: "// Ghidra: coreaction.hh:243 ActionDirectWrite (constructor mirror)",
    4002: "// Ghidra: coreaction.cc:1350 ActionDirectWrite::apply",
    4067: "// RUDRA-GLUE: Rust Action trait get_name; \"directwrite\" mirrors ctor at coreaction.hh:243",
    # --- ActionConstbase ---
    4078: "// Ghidra: coreaction.hh:259 ActionConstbase (constructor mirror)",
    4081: "// Ghidra: coreaction.cc:678 ActionConstbase::apply",
    4112: "// RUDRA-GLUE: Rust Action trait get_name; \"constbase\" mirrors ctor at coreaction.hh:259",
    # --- ActionInputPrototype ---
    4119: "// Ghidra: coreaction.hh:892 ActionInputPrototype (constructor mirror)",
    4122: "// Ghidra: coreaction.cc:4707 ActionInputPrototype::apply",
    4186: "// RUDRA-GLUE: Rust Action trait get_name; \"inputprototype\" mirrors ctor at coreaction.hh:892",
    # --- ActionOutputPrototype ---
    4193: "// Ghidra: coreaction.hh:903 ActionOutputPrototype (constructor mirror)",
    4196: "// Ghidra: coreaction.cc:4765 ActionOutputPrototype::apply",
    4247: "// RUDRA-GLUE: Rust Action trait get_name; \"outputprototype\" mirrors ctor at coreaction.hh:903",
    # --- ActionPrototypeTypes ---
    4254: "// Ghidra: coreaction.hh:643 ActionPrototypeTypes (constructor mirror)",
    4257: "// Ghidra: coreaction.cc:4609 ActionPrototypeTypes::apply",
    4307: "// RUDRA-GLUE: Rust Action trait get_name; \"prototypetypes\" mirrors ctor at coreaction.hh:643",
    # --- ActionActiveParam ---
    4314: "// Ghidra: coreaction.hh:748 ActionActiveParam (constructor mirror)",
    4317: "// Ghidra: coreaction.cc:1725 ActionActiveParam::apply",
    4357: "// RUDRA-GLUE: Rust Action trait get_name; \"activeparam\" mirrors ctor at coreaction.hh:748",
    # --- ActionActiveReturn ---
    4364: "// Ghidra: coreaction.hh:761 ActionActiveReturn (constructor mirror)",
    4367: "// Ghidra: coreaction.cc:1773 ActionActiveReturn::apply",
    4423: "// RUDRA-GLUE: Rust Action trait get_name; \"activereturn\" mirrors ctor at coreaction.hh:761",
    # --- ActionDefaultParams ---
    4430: "// Ghidra: coreaction.hh:659 ActionDefaultParams (constructor mirror)",
    4433: "// Ghidra: coreaction.cc:2311 ActionDefaultParams::apply",
    4459: "// RUDRA-GLUE: Rust Action trait get_name; \"defaultparams\" mirrors ctor at coreaction.hh:659",
    # --- ActionParamDouble ---
    4466: "// Ghidra: coreaction.hh:730 ActionParamDouble (constructor mirror)",
    4469: "// Ghidra: coreaction.cc:1597 ActionParamDouble::apply",
    4493: "// RUDRA-GLUE: Rust Action trait get_name; \"paramdouble\" mirrors ctor at coreaction.hh:730",
    # --- ActionUnjustifiedParams ---
    4500: "// Ghidra: coreaction.hh:918 ActionUnjustifiedParams (constructor mirror)",
    4503: "// Ghidra: coreaction.cc:4784 ActionUnjustifiedParams::apply",
    4558: "// RUDRA-GLUE: Rust Action trait get_name; \"unjustifiedparams\" mirrors ctor at coreaction.hh:918",
    # --- ActionLikelyTrash ---
    4570: "// Ghidra: coreaction.hh:833 ActionLikelyTrash (constructor mirror)",
    4573: "// Ghidra: coreaction.cc:2140 ActionLikelyTrash::apply",
    4587: "// RUDRA-GLUE: Rust Action trait get_name; \"likelytrash\" mirrors ctor at coreaction.hh:833",
    # --- ActionShadowVar ---
    4601: "// Ghidra: coreaction.hh:177 ActionShadowVar (constructor mirror)",
    4604: "// Ghidra: coreaction.cc:892 ActionShadowVar::apply",
    4737: "// RUDRA-GLUE: Rust Action trait get_name; \"shadowvar\" mirrors ctor at coreaction.hh:177",
    # --- free helper ---
    4742: "// RUDRA-GLUE: Rugra helper bridging PcodeOpRef -> parent BlockBasic ops list (Ghidra reaches this via PcodeOp::parent)",
    # --- ActionFuncLink ---
    4768: "// Ghidra: coreaction.hh:697 ActionFuncLink (constructor mirror)",
    4866: "// Ghidra: coreaction.cc:1474 ActionFuncLink::funcLinkInput",
    4915: "// Ghidra: coreaction.cc:1521 ActionFuncLink::funcLinkOutput",
    4952: "// Ghidra: coreaction.cc:1575 ActionFuncLink::apply",
    4999: "// RUDRA-GLUE: Rust Action trait get_name; \"funclink\" mirrors ctor at coreaction.hh:697",
    # --- ActionFuncLinkOutOnly ---
    5008: "// Ghidra: coreaction.hh:715 ActionFuncLinkOutOnly (constructor mirror)",
    5011: "// Ghidra: coreaction.cc:1588 ActionFuncLinkOutOnly::apply",
    5035: "// RUDRA-GLUE: Rust Action trait get_name; \"funclinkoutonly\" mirrors ctor at coreaction.hh:715",
    # --- ActionDeindirect ---
    5042: "// Ghidra: coreaction.hh:206 ActionDeindirect (constructor mirror)",
    5045: "// Ghidra: coreaction.cc:1219 ActionDeindirect::apply",
    5108: "// RUDRA-GLUE: Rust Action trait get_name; \"deindirect\" mirrors ctor at coreaction.hh:206",
    5116: "// RUDRA-GLUE: Rugra helper factoring out the CALLIND input(0) COPY-chain chase inlined at coreaction.cc:1231-1232",
    5135: "// RUDRA-GLUE: Rugra helper factoring out COPY-chain -> constant chase used by ActionDeindirect",
    # --- ActionStackPtrFlow ---
    5168: "// Ghidra: coreaction.hh:89 ActionStackPtrFlow (constructor mirror)",
    5172: "// Ghidra: coreaction.cc:329 ActionStackPtrFlow::isStackRelative",
    5203: "// Ghidra: coreaction.cc:353 ActionStackPtrFlow::adjustLoad",
    5237: "// Ghidra: coreaction.cc:378 ActionStackPtrFlow::repair",
    5288: "// Ghidra: coreaction.cc:481 ActionStackPtrFlow::apply",
    5365: "// RUDRA-GLUE: Rust Action trait get_name; \"stackptrflow\" mirrors ctor at coreaction.hh:89",
    # --- ActionSpacebase ---
    5379: "// Ghidra: coreaction.hh:272 ActionSpacebase (constructor mirror)",
    5382: "// Ghidra: coreaction.hh:277 ActionSpacebase::apply",
    5386: "// RUDRA-GLUE: Rust Action trait get_name; \"spacebase\" mirrors ctor at coreaction.hh:272",
    # --- ActionSegmentize ---
    5393: "// Ghidra: coreaction.hh:128 ActionSegmentize (constructor mirror)",
    5396: "// Ghidra: coreaction.cc:624 ActionSegmentize::apply",
    5413: "// RUDRA-GLUE: Rust Action trait get_name; \"segmentize\" mirrors ctor at coreaction.hh:128",
    # --- ActionInternalStorage ---
    5420: "// Ghidra: coreaction.hh:1058 ActionInternalStorage (constructor mirror)",
    5423: "// Ghidra: coreaction.cc:4938 ActionInternalStorage::apply",
    5444: "// RUDRA-GLUE: Rust Action trait get_name; \"internalstorage\" mirrors ctor at coreaction.hh:1058",
    # --- ActionExtraPopSetup ---
    5451: "// Ghidra: coreaction.hh:676 ActionExtraPopSetup (constructor mirror)",
    5454: "// Ghidra: coreaction.cc:1436 ActionExtraPopSetup::apply",
    5464: "// RUDRA-GLUE: Rust Action trait get_name; \"extrapopsetup\" mirrors ctor at coreaction.hh:676",
    # --- ActionConditionalConst ---
    5483: "// Ghidra: coreaction.hh:569 ActionConditionalConst (constructor mirror)",
    5486: "// Ghidra: coreaction.cc:4514 ActionConditionalConst::apply",
    5500: "// RUDRA-GLUE: Rust Action trait get_name; \"conditionalconst\" mirrors ctor at coreaction.hh:569",
    # --- ActionDynamicMapping ---
    5507: "// Ghidra: coreaction.hh:1023 ActionDynamicMapping (constructor mirror)",
    5510: "// Ghidra: coreaction.cc:4852 ActionDynamicMapping::apply",
    5513: "// RUDRA-GLUE: Rust Action trait get_name; \"dynamicmapping\" mirrors ctor at coreaction.hh:1023",
    # --- ActionDynamicSymbols ---
    5520: "// Ghidra: coreaction.hh:1034 ActionDynamicSymbols (constructor mirror)",
    5523: "// Ghidra: coreaction.cc:4869 ActionDynamicSymbols::apply",
    5526: "// RUDRA-GLUE: Rust Action trait get_name; \"dynamicsymbols\" mirrors ctor at coreaction.hh:1034",
    # --- ActionMappedLocalSync ---
    5533: "// Ghidra: coreaction.hh:867 ActionMappedLocalSync (constructor mirror)",
    5536: "// Ghidra: coreaction.cc:2297 ActionMappedLocalSync::apply",
    5539: "// RUDRA-GLUE: Rust Action trait get_name; \"mappedlocalsync\" mirrors ctor at coreaction.hh:867",
    # --- ActionLaneDivide ---
    5546: "// Ghidra: coreaction.hh:113 ActionLaneDivide (constructor mirror)",
    5549: "// Ghidra: coreaction.cc:585 ActionLaneDivide::apply",
    5552: "// RUDRA-GLUE: Rust Action trait get_name; \"lanedivide\" mirrors ctor at coreaction.hh:113",
    # --- ActionReturnRecovery (new already has glue) ---
    5570: "// Ghidra: coreaction.cc:1908 ActionReturnRecovery::apply",
    5634: "// RUDRA-GLUE: Rust Action trait get_name; \"returnrecovery\" mirrors ctor at coreaction.hh:799",
    # --- ActionNonzeroMask ---
    5644: "// Ghidra: coreaction.hh:295 ActionNonzeroMask (constructor mirror)",
    5647: "// Ghidra: coreaction.hh:300 ActionNonzeroMask::apply",
    5654: "// RUDRA-GLUE: Rust Action trait get_name; \"nonzeromask\" mirrors ctor at coreaction.hh:295",
    # --- ActionForceGoto ---
    5664: "// Ghidra: coreaction.hh:141 ActionForceGoto (constructor mirror)",
    5667: "// Ghidra: coreaction.cc:671 ActionForceGoto::apply",
    5681: "// RUDRA-GLUE: Rust Action trait get_name; \"forcegoto\" mirrors ctor at coreaction.hh:141",
    # --- ActionStartCleanUp ---
    5712: "// Ghidra: coreaction.hh:60 ActionStartCleanUp (constructor mirror)",
    5718: "// Ghidra: coreaction.hh:65 ActionStartCleanUp::apply",
    5723: "// RUDRA-GLUE: Rust Action trait get_name; \"startcleanup\" mirrors ctor at coreaction.hh:60",
    # --- ActionStartTypes ---
    5740: "// Ghidra: coreaction.hh:76 ActionStartTypes (constructor mirror)",
    5746: "// Ghidra: coreaction.hh:77 ActionStartTypes::reset",
    5751: "// Ghidra: coreaction.hh:82 ActionStartTypes::apply",
    5761: "// RUDRA-GLUE: Rust Action trait get_name; \"starttypes\" mirrors ctor at coreaction.hh:76",
    # --- ActionStop ---
    5775: "// Ghidra: coreaction.hh:48 ActionStop (constructor mirror)",
    5781: "// Ghidra: coreaction.hh:53 ActionStop::apply",
    5786: "// RUDRA-GLUE: Rust Action trait get_name; \"stop\" mirrors ctor at coreaction.hh:48",
    # --- ActionAssignHigh ---
    5803: "// Ghidra: coreaction.hh:341 ActionAssignHigh (constructor mirror)",
    5809: "// Ghidra: coreaction.hh:346 ActionAssignHigh::apply",
    5823: "// RUDRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:341",
    5827: "// RUDRA-GLUE: Rust Action trait get_name; \"assignhigh\" mirrors ctor at coreaction.hh:341",
    # --- ActionDominantCopy ---
    5842: "// Ghidra: coreaction.hh:1003 ActionDominantCopy (constructor mirror)",
    5848: "// Ghidra: coreaction.hh:1008 ActionDominantCopy::apply",
    5856: "// RUDRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:1003",
    5860: "// RUDRA-GLUE: Rust Action trait get_name; \"dominantcopy\" mirrors ctor at coreaction.hh:1003",
    # --- ActionCopyMarker ---
    5874: "// Ghidra: coreaction.hh:1014 ActionCopyMarker (constructor mirror)",
    5880: "// Ghidra: coreaction.hh:1019 ActionCopyMarker::apply",
    5887: "// RUDRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:1014",
    5891: "// RUDRA-GLUE: Rust Action trait get_name; \"copymarker\" mirrors ctor at coreaction.hh:1014",
    # --- ActionMarkIndirectOnly ---
    5907: "// Ghidra: coreaction.hh:352 ActionMarkIndirectOnly (constructor mirror)",
    5916: "// RUDRA-GLUE: Rugra helper factoring out INDIRECT-only-use predicate used by Funcdata::markIndirectOnly() (invoked from coreaction.hh:358)",
    5960: "// Ghidra: coreaction.hh:357 ActionMarkIndirectOnly::apply",
    5985: "// RUDRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:352",
    5989: "// RUDRA-GLUE: Rust Action trait get_name; \"markindirectonly\" mirrors ctor at coreaction.hh:352",
    # --- ActionMapGlobals ---
    6009: "// Ghidra: coreaction.hh:880 ActionMapGlobals (constructor mirror)",
    6015: "// Ghidra: coreaction.hh:885 ActionMapGlobals::apply",
    6054: "// RUDRA-GLUE: Rust Action trait get_flags; mirrors rule_onceperfunc bit set in ctor at coreaction.hh:880",
    6058: "// RUDRA-GLUE: Rust Action trait get_name; \"mapglobals\" mirrors ctor at coreaction.hh:880",
    # --- ActionPreferComplement (blockaction) ---
    6102: "// Ghidra: blockaction.hh:300 ActionPreferComplement (constructor mirror)",
    6118: "// RUDRA-GLUE: Rugra helper factoring out comparison-complement flip logic inlined in ActionPreferComplement::apply (blockaction.cc:2140-2167)",
    6149: "// Ghidra: blockaction.cc:2140 ActionPreferComplement::apply",
    6245: "// RUDRA-GLUE: Rust Action trait get_name; \"prefercomplement\" mirrors ctor at blockaction.hh:302",
    # --- ActionStructureTransform (blockaction) ---
    6277: "// Ghidra: blockaction.hh:272 ActionStructureTransform (constructor mirror)",
    6283: "// Ghidra: blockaction.cc:2110 ActionStructureTransform::apply",
    6525: "// RUDRA-GLUE: Rust Action trait get_name; \"structuretransform\" mirrors ctor at blockaction.hh:272",
    # --- ActionReturnSplit (blockaction) ---
    6555: "// Ghidra: blockaction.hh:337 ActionReturnSplit (constructor mirror)",
    6563: "// Ghidra: blockaction.cc:2241 ActionReturnSplit::isSplittable",
    6596: "// Ghidra: blockaction.cc:2264 ActionReturnSplit::apply",
    6723: "// RUDRA-GLUE: Rust Action trait get_name; \"returnsplit\" mirrors ctor at blockaction.hh:337",
    # --- ActionNodeJoin (blockaction) ---
    6755: "// Ghidra: blockaction.hh:350 ActionNodeJoin (constructor mirror)",
    6761: "// Ghidra: blockaction.cc:2326 ActionNodeJoin::apply",
    6942: "// RUDRA-GLUE: Rust Action trait get_name; \"nodejoin\" mirrors ctor at blockaction.hh:350",
    # --- pipeline builder ---
    6978: "// RUDRA-GLUE: Rugra pipeline builder; mirrors ActionDatabase::buildDefaultGroups (coreaction.cc:5419) but returns a Vec<Box<dyn Action>> for Rust ownership",
}


def main():
    lines = RS.read_text(encoding="utf-8").split("\n")

    # Verify every key matches the recorded fn name & line content.
    # Load violations to cross-check.
    vdata = json.load(open(ROOT / "result" / "violations_structured.json", encoding="utf-8"))
    vios = vdata["src/coreaction.rs"]
    line2fn = {v["line"]: v["fn"] for v in vios}

    if set(A.keys()) != set(line2fn.keys()):
        missing_in_A = set(line2fn.keys()) - set(A.keys())
        extra_in_A = set(A.keys()) - set(line2fn.keys())
        print("MISMATCH:")
        print("  violations not annotated:", sorted(missing_in_A))
        print("  annotations without violation:", sorted(extra_in_A))
        sys.exit(1)

    # Sanity-check that each flagged line still begins (after indent) with
    # `fn <name>` or `pub fn <name>`.
    import re
    FN_RE = re.compile(r"^\s*(pub\s+)?(async\s+)?(unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]")
    mismatches = []
    for ln, fn_name in line2fn.items():
        idx = ln - 1
        if idx >= len(lines):
            mismatches.append((ln, fn_name, "OUT OF RANGE"))
            continue
        m = FN_RE.match(lines[idx])
        if not m or m.group(4) != fn_name:
            mismatches.append((ln, fn_name, lines[idx].rstrip()))
    if mismatches:
        print("LINE/FN MISMATCH (file changed since violations were generated?):")
        for ln, fn, actual in mismatches[:20]:
            print(f"  line {ln} expected fn {fn!r}, got: {actual!r}")
        sys.exit(2)
    print(f"All {len(A)} violation lines verified against current file.")

    # Insert annotations bottom-to-top.
    inserted = 0
    for ln in sorted(A.keys(), reverse=True):
        idx = ln - 1
        target = lines[idx]
        # Compute indentation from the target line.
        stripped = target.lstrip()
        indent = target[: len(target) - len(stripped)]
        comment = indent + A[ln]
        # Skip if the line directly above already contains an equivalent
        # annotation (idempotency).
        if idx - 1 >= 0 and A[ln].split(":", 2)[:2] and A[ln].lstrip() in lines[idx - 1].lstrip():
            continue
        lines.insert(idx, comment)
        inserted += 1

    RS.write_text("\n".join(lines), encoding="utf-8")
    print(f"Inserted {inserted} annotations into {RS}")


if __name__ == "__main__":
    main()
