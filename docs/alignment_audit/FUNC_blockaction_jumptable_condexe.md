# 函数清单:blockaction.cc + jumptable.cc + condexe.cc + block.cc

来源:Ghidra 4 个 .cc(~309 函数)
Rudra 对应:`src/blockaction.rs` + `src/jumptable.rs` + `src/condexe.rs` + `src/block.rs`

## blockaction.cc(67 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L46 | `LoopBody::extendToContainer(...)` | — | 🔍 |
| L119 | `findBase(...)` | `find_base` | 🔍 |
| L150 | `extend(...)` | `extend` | 🔍 |
| L182 | `findExit(...)` | `find_exit` | ⚠️ 2026-07-16 已实现（immed_container 支持，approximate container body marks） |
| L245 | `orderTails()` | `order_tails` | 🔍 |
| L270 | `labelExitEdges(...)` | `label_exit_edges` | 🔍 |
| L327 | `labelContainments(...)` | `label_containments` | ⚠️ INDEX |
| L364 | `emitLikelyEdges(...)` | `emit_likely_edges` | 🔍 |
| L416/L430 | `setExitMarks/clearExitMarks` | `set_exit_marks`/`clear_exit_marks` + `apply_loop_exit_marks` | ✅ 2026-07-16 B5 |
| L446 | `mergeIdenticalHeads(...)` | `merge_identical_heads` | 🔍 |
| L473/L489 | `compare_ends/compare_head` | `compare_ends` | 🔍 |
| L656-L983 | TraceDAG 系列(removeTrace/processExitConflict/insertActive/removeActive/checkOpen/openBranch/checkRetirement/retireBranch/clearVisitCount/initialize/pushBranches) | (tracedag.rs) | 🔍 |
| L1039 | `clearMarks(...)` | `clear_marks` | 🔍 |
| L1052 | `onlyReachableFromRoot(...)` | (clip_extra_roots) | 🔍 |
| L1083 | `markExitsAsGotos(...)` | (clip_extra_roots) | 🔍 |
| L1108 | `clipExtraRoots()` | `clip_extra_roots` | 🔍 |
| L1126 | `labelLoops(...)` | — | 🔍 |
| L1148 | `orderLoopBodies()` | `order_loop_bodies` | ⚠️ INDEX |
| L1193 | `updateLoopBody()` | `update_loop_body` | ✅ 2026-07-16 B5/B6/B7 |
| L1284-L1768 | ruleBlockCat/Or/ProperIf/IfElse/Goto/IfNoExit/WhileDo/DoWhile/InfLoop/Switch/CaseFallthru | `try_rule_*` (all 10) + factory `new_block_*` | ✅ 2026-07-16 B1-B9 (or negateCondition, new_block_condition/if/if_else/inf_loop, collapse_conditions fixpoint, collapse_internal second-pass) |
| L1768 | `collapseInternal(FlowBlock*)` | `collapse_internal(target_idx)` + `apply_rules_to_block` | ✅ 2026-07-16 B9 |
| L1854 | `collapseConditions()` | `collapse_conditions` | ⚠️ INDEX |
| L1877 | `collapseAll()` | `collapse_all` (default 5-step) + `collapse_all_5step` | ✅ 2026-07-16 (5-step default, 30600b1) |
| L1912-L2104 | ConditionalJoin 系列(findDups/checkExitBlock/cutDownMultiequals/setupMultiequals/moveCbranch/match/execute/clear) | — | 🔍 |
| L2110-L2326 | Action 系列(StructureTransform/NormalizeBranches/PreferComplement/BlockStructure/FinalStructure/ReturnSplit/NodeJoin) | `Action*::apply` | ⚠️ 2026-07-16 已实现（structure_loops_first + collapse_loops/collapse_switches + 5-step collapseAll）。NormalizeBranches/FinalStructure wired。 |

**blockaction.cc 统计**:67 函数。大部分已实现（2026-07-16 审核）。findExit⚠️、Action 系列⚠️、EmulateFunction⚠️。buildAddresses✅。collapseAll/collapseInternal/try_rule_*/updateLoopBody 均 ✅。

## jumptable.cc(105 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L39/L50/L62 | `LoadTable::encode/decode/collapseTable` | `LoadTable` | 🔍 |
| L115-L218 | `EmulateFunction::executeLoad/Branch/Branchind/Call/Callind/Callother/setExecuteAddress/getVarnodeValue/setVarnodeValue/fallthruOp/emulatePath` | `EmulateFunction::*` | ⚠️ 2026-07-16 已实现（get_varnode_value/set_varnode_value/emulate_path/execute_op 均有实现，executeOp 不接 addressToByte 是结构性差异） |
| L262-L299 | `JumpValuesRange::truncate/getSize/contains/initializeForReading/next/getValue` | `JumpValuesRange::*` | ⚠️ INDEX 已修 curval(86c8e04) |
| L327-L391 | `JumpValuesRangeDefault::*` | `JumpValuesRangeDefault::*` | ⚠️ INDEX 已修(86c8e04) |
| L391-L426 | `JumpModelTrivial::recoverModel/buildAddresses/buildLabels` | `JumpModelTrivial::*` | 🔍 |
| L426-L556 | `JumpBasic::isprune/ispoint/getStride/backup2Switch/getMaxValue/findDeterminingVarnodes` | `JumpBasic::*` | 🔍 |
| L639/L686 | `GuardRecord::valueMatch/oneOffMatch` | `GuardRecord::value_match`/`one_off_match` | 🔍 |
| L796-L1063 | PathMeld 系列(internalIntersect/meldOps/truncatePaths/set*/append/clear/meld/markPaths/isLoadInPath/getEarliestOp) | `PathMeld::*` | ⚠️ INDEX(meldOps 缺 SeqNum 排序) |
| L1063 | `analyzeGuards(...)` | `analyze_guards` | ⚠️ checkUnrolledGuard 已实现（e954c54），需接入 analyze_guards |
| L1137 | `calcRange(...)` | `calc_range` | ⚠️ INDEX(value_match==2 缺) |
| L1182/L1223/L1258/L1273/L1308/L1324/L1357/L1392 | findSmallestNormal/findNormalized/markFoldableGuards/markModel/flowsOnlyToModel/duplicateVarnodes/checkCommonCbranch/checkUnrolledGuard/foldInOneGuard | 已实现 | ✅ 2026-07-16 checkCommonCbranch + checkUnrolledGuard + findMultiequal（e954c54） |
| L1437 | `recoverModel(...)` | `recover_model` | ⚠️ INDEX |
| L1453 | `buildAddresses(...)` | `build_addresses` | ✅ 2026-07-16 已修(8e11b3b funcptr_align+addressToByte) |
| L1484/L1528/L1577/L1594/L1643 | findUnnormalized/buildLabels/foldInGuards/sanityCheck/clear | `find_unnormalized`/`build_labels`/`sanity_check`/`clear` | ⚠️ INDEX |
| L1656-L1789 | `JumpBasic2::*`(foldInOneGuard/initializeStart/recoverModel/checkNormalDominance/findUnnormalized/clear) | `JumpBasic2`(组合 `base: JumpBasic`) | 🔍 已实现(JumpModel trait 全实现) |
| L1801-L2083 | `JumpBasicOverride::*`(setAddresses/findStartOp/trialNorm/setupTrivial/clearCopySpecific/recoverModel/buildAddresses/buildLabels/clear/encode/decode) | `JumpBasicOverride` | 🔍 已实现 |
| L2113-L2247 | `JumpAssisted::*`(recoverModel/buildAddresses/buildLabels/foldInGuards) | `JumpAssisted` | 🔍 已实现 |
| L2247-L2690 | JumpTable 系列(saveModel/restoreSavedModel/clearSavedModel/recoverModel/sanityCheck/block2Position/isReachable/numIndicesByBlock/isOverride/setOverride/getIndexByBlock/setLastAsDefault/addBlockToSwitch/switchOver/foldInNormalization/trivialSwitchOver/recoverAddresses/recoverMultistage/matchModel/recoverLabels/clear/encode/decode/checkForMultistage) | `JumpTable::*` | ⚠️ INDEX |

**jumptable.cc 统计**:105 函数。JumpBasic2/Override/Assisted 三类均已实现（JumpAssisted::recover_model 保守返回 false 因 JumpAssistOp userop 未移植，匹配 Ghidra 无 jumpassist 二进制的行为）。checkUnrolledGuard 链已完成（e954c54）。

## condexe.cc(15 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L23 | `buildHeritageArray()` | (ConditionalExecution::new) | ⚠️ INDEX(硬编码 4 空间) |
| L43 | `testIBlock()` | `test_iblock` | 🔍 |
| L55 | `findInitPre()` | `find_init_pre` | 🔍 |
| L80 | `verifySameCondition()` | `verify_same_condition` | ⚠️ INDEX |
| L101/L120 | `testMultiRead/testOpRead` | `test_multi_read`/`test_op_read` | 🔍 |
| L320 | `doReplacement(PcodeOp*)` | `do_replacement` | ❌ INDEX(RETURN slot 1) |
| L361 | `testRemovability(PcodeOp*)` | `test_removability` | ⚠️ INDEX |
| L402 | `verify()` | `verify` | 🔍 |
| L448 | `trial(BlockBasic*)` | `trial` | ⚠️ INDEX(directsplit) |
| L457 | `execute()` | `execute` | 🔍 |
| L478 | `ActionConditionalExe::apply(Funcdata&)` | `ActionConditionalExe::apply` | ❌ INDEX |
| L617/L638/L654 | RuleOrPredicate::getOpList/checkSingle/applyOp | `RuleOrPredicate::*` | 🔍 |

**condexe.cc 统计**:15 函数。

## block.cc(122 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L35-L48 | `BlockEdge::encode/decode` | — | 🔍 |
| L73-L709 | FlowBlock 系列(addInEdge/decodeNextInEdge/halfDeleteInEdge/OutEdge/removeInEdge/OutEdge/replaceInEdge/OutEdge/replaceEdgesThru/swapEdges/setOutEdgeFlag/clearOutEdgeFlag/markLabelBumpUp/replaceEdgeMap/replaceUsingMap/negateCondition/setGotoBranch/setDefaultSwitch/isJumpTarget/calcDepth/dominates/restrictedByConditional/hasLoopIn/Out/eliminateInDups/OutDups/findDups/dedup/checkEdges/getInIndex/getOutIndex/printHeader/Tree/ShortHeader/nameToType/typeToName/compareFinalOrder) | `FlowBlock::*`(部分) | 🔍 大量待核 |
| L862-L1439 | BlockGraph 系列(addBook/forceOutputNum/selfIdentify/identifyInternal/clearEdgeFlags/findSpanningTree/findIrreducible/forceFalseEdge/swapBlocks/markCopyBlock/clear/markUnstructured/markLabelBumpUp/scopeBreak/printTree/Raw/RawImpliedGoto/finalTransform/finalizePrinting/encodeBody/decodeBody/decode/addEdge/addLoopEdge/removeEdge/switchEdge/moveOutEdge/removeBlock/removeFromFlow/Split/spliceBlock/setStartBlock/buildCopy/clearVisitCount/calcForwardDominator/buildDomTree/Depth/SubTree/calcLoop/collectReachable/structureLoops/isConsistent) | `BlockGraph::*`(部分) | 🔍 |
| L2258-L2712 | BlockBasic 系列(insert/removeOp/getEntryAddr/getStart/getStop/negateCondition/flipInPlaceTest/Execute/isComplex/encodeBody/decodeBody/printHeader/Raw/RawImpliedGoto/noInterveningStatement/liftVerifyUnroll/setInitialRange/setOrder) | `BlockBasic::*`(部分) | 🔍 |
| L2835-L3704 | Block 子类(Copy/Goto/MultiGoto/List/Condition/If/WhileDo/DoWhile/InfLoop/Switch)的 printHeader/scopeBreak/markUnstructured/encodeBody 等 | `Block*` enum(部分) | 🔍 |

**block.cc 统计**:122 函数。全部 🔍。
