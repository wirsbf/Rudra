# 函数清单:action.cc + coreaction.cc + ruleaction.cc

来源:Ghidra 3 个主管线 .cc(~464 函数)
Rudra 对应:`src/action.rs` + `src/coreaction.rs` + `src/ruleaction.rs`

## action.cc(80 函数)

Action 基类 + ActionGroup + ActionRestartGroup + Rule 基类 + ActionPool + ActionDatabase。

| 行段 | 函数 | 状态 |
|---|---|---|
| L27-L298 | Action 基类(issueWarning/checkStartBreak/turnOnDebug/OffDebug/printStatistics/reset/resetStats/checkActionBreak/print/printState/setBreakPoint/clearBreakPoints/setWarning/disableRule/enableRule/getSubAction/getSubRule/perform) | 🔍 |
| L364-L623 | ActionGroup/RestartGroup(~/.addAction/clearBreakPoints/clone/reset/resetStats/print/printState/getSubAction/getSubRule/apply/turnOnDebug/OffDebug/printStatistics) | 🔍 |
| L623-L719 | Rule 基类(issueWarning/reset/resetStats/turnOnDebug/OffDebug/printStatistics/getOpList) | 🔍 |
| L729-L977 | ActionPool(~/.addRule/print/printState/getSubRule/processOp/apply/clearBreakPoints/clone/reset/resetStats/turnOnDebug/OffDebug/printStatistics) | 🔍 |
| L977-L1146 | ActionDatabase(~/.resetDefaults/getGroup/setCurrent/toggleAction/setGroup/cloneGroup/addToGroup/removeFromGroup/getAction/registerAction/deriveAction) | 🔍 |

**action.cc 统计**:80 函数,全部 🔍。

## coreaction.cc(121 函数)

| 行段 | 函数 | 状态 |
|---|---|---|
| L55-L147 | StackEqn/StackSolver(compare/propagate/duplicate/solve/build) | `StackEqn`/`StackSolver`(coreaction.rs:5295) | 🔍 已实现(build/solve/propagate/duplicate 全有) |
| L261-L498 | ActionStackPtrFlow(analyzeExtraPop/isStackRelative/adjustLoad/repair/checkClog/apply) | ❌ INDEX P1 |
| L509-L585 | ActionLaneDivide(collectLaneSizes/processVarnode/apply) | ⚠️ stub |
| L624-L671 | ActionSegmentize/ForceGoto/Constbase apply | ⚠️ stub |
| L741-L879 | ActionMultiCse(preferredOutput/findMatch/processBlock/apply) + ActionShadowVar | 🔍 |
| L957-L1219 | ActionConstantPtr(searchForSpaceAttribute/selectInferSpace/checkCopy/isPointer/apply) + Deindirect | ❌ INDEX P1 |
| L1282-L1436 | ActionVarnodeProps/DirectWrite/ExtraPopSetup | ❌ INDEX P1 |
| L1474-L1588 | ActionFuncLink(funcLinkInput/Output/apply) + FuncLinkOutOnly | ❌ INDEX P1(SysV 硬编码) |
| L1597-L1836 | ActionParamDouble/ActiveParam/ActiveReturn/ReturnRecovery(buildReturnOutput) | ❌ INDEX P1(stub/重写) |
| L1957-L2311 | ActionRestrictLocal/LikelyTrash/RestructureVarnode/MappedLocalSync/DefaultParams | ❌ INDEX P1 |
| L2349-L2779 | ActionSetCasts(checkPointerIssues/testStructOffset0/tryResolutionAdjustment/isOpIdentical/resolveUnion/castOutput/insertPtrsubZero/castInput/apply) | ❌ INDEX P1 |
| L2779-L3007 | ActionNameVars(lookForBadJumpTables/makeRec/lookForFuncParamNames/linkSpacebaseSymbol/linkSymbols/apply) | ❌ INDEX P1 stub |
| L3007-L3416 | ActionMarkExplicit(baseExplicit/multipleInteraction/processMultiplier/checkNewToConstructor/apply) + MarkImplied | ⚠️ INDEX |
| L3457-L3556 | ActionUnreachable/DoNothing/RedundBranch/DeterminedBranch | 🔍 |
| L3556-L4069 | ActionDeadCode(pushConsumed/propagateConsumed/neverConsumed/markConsumedParameters/gatherConsumedReturn/lastChanceLoad/apply) | ❌ INDEX P1 |
| L4069-L4548 | ActionConditionalConst(clearMarks/collectReachable/flowToAlternatePath/flowTogether/placeCopy/placeMultipleConstants/pushConstant/handlePhiNodes/testAlternatePath/propagateConstant/findConstCompare/apply) | ❌ INDEX P1 stub |
| L4548-L4831 | ActionSwitchNorm/NormalizeSetup + PrototypeTypes(extendInput) + InputPrototype/OutputPrototype/UnjustifiedParams/HideShadow | ❌ INDEX P1 |
| L4852-L4980 | ActionDynamicMapping/Symbols/PrototypeWarnings/InternalStorage | ⚠️ stub |
| L4980-L5419 | ActionInferTypes(propagationDebug/buildLocaltypes/writeBack/propagateTypeEdge/propagateOneType/Ref/SpacebaseRef/canonicalReturnOp/propagateAcrossReturns/apply) + PropagationState | ⚠️ INDEX |
| L5419-L5462 | ActionDatabase::buildDefaultGroups/universalAction | ⚠️ INDEX(双注册问题) |

**coreaction.cc 统计**:121 函数。大多数 INDEX P1 条目实际已实现（2026-07-16 审核：ActionStackPtrFlow checkClog+repair 已实现、ActionInputPrototype/OutputPrototype/UnjustifiedParams 已实现、ActionHideShadow 已实现、ActionSwitchNorm 已实现、ActionDeadCode 已实现含 lastChanceLoad、ActionConditionalConst 10/10 子方法已实现、ActionNormalizeSetup clearInput 已加、ActionMappedLocalSync overlap check 已加）。INDEX P1 标签主要反映"子方法简化"而非"完全缺失"。剩余 gap：ActionConditionalConst apply() 未启用（IR 变异回归）、ActionSetCasts/ActionNameVars 子方法需进一步细化。

## ruleaction.cc(263 函数)

| 行段 | 函数 | 状态 |
|---|---|---|
| L25-L82 | RuleEarlyRemoval/CollectTerms | 🔍 INDEX OK(6 守卫) |
| L180-L1095 | Rules: SelectCse/Piece2Zext/Sext/Bxor2NotEqual/OrMask/AndMask/OrConsume/OrCollapse/AndOrLump/NegateIdentity/ShiftBitops/RightShiftAnd/IntLessEqual/Equality/TermOrder/PullsubMulti/PullsubIndirect/PushMulti/NotDistribute/HighOrderAnd/AndDistribute/LessOne/RangeMeld/FloatRange/AndCommute/AndPiece/AndZext/AndCompare | 🔍 |
| L1800-L2270 | RuleDoubleSub/Shift/ArithShift/ConcatShift/LeftRight/ShiftCompare/LessEqual/LessNotEqual | 🔍 |
| L2372-L2627 | RuleTrivialArith/Bool/ZextEliminate/SlessToLess/ZextSless/BitUndistribute/BooleanUndistribute/Dedup/Negate/BoolZext | 🔍 |
| L3131-L3375 | RuleLogic2Bool/IndirectCollapse/MultiCollapse/Sborrow/Scarry | 🔍 |
| L3444-L3874 | RuleTrivialShift/SignShift/TestSign/IdentityEl/Shift2Mult/ShiftPiece/CollapseConstants/TransformCpool/PropagateCopy | 🔍 |
| L3981-L4333 | Rule2Comp2Mult/CarryElim/Sub2Add/XorCollapse/AddMultCollapse/LoadVarnode/StoreVarnode | ⚠️ INDEX(LoadVarnode/StoreVarnode PARTIAL) |
| L4416-L5523 | RuleSubExtComm/SubCommute/ConcatCommute/ConcatZext/ZextCommute/ZextShiftZext/ShiftAnd/ConcatZero/ConcatLeftShift/SubZext/SubCancel/ShiftSub/HumptyDumpty/DumptyHump/HumptyOr | 🔍 |
| L5424-L5992 | RuleSwitchSingle/CondNegate/BoolNegate/Less2Zero/LessEqual2Zero/SLess2Zero/Equal2Zero/Equal2Constant | 🔍 |
| L5992-L6508 | AddTreeState(clear/initAlternateForm/hasMatchingSubType/checkMultTerm/checkTerm/spanAddTree/calcSubtype/assignPropagatedType/buildMultiples/buildExtra/buildDegenerate/apply/buildTree) | 🔍 |
| L6558-L7172 | RulePtrArith/StructOffset0/PushPtr/PtraddUndo/PtrsubUndo(getConstOffsetBack/getExtraOffset/removeLocalAddRecurse/removeLocalAdds) | 🔍 |
| L7173-L7262 | RuleMultNegOne/AddUnsigned/2Comp2Sub/SubRight | 🔍 INDEX OK(oppool 正确) |
| L7341-L7500 | RulePtrsubCharConstant/ExtensionPush/PieceStructure(determineDatatype/spanningRange/convertZextToPiece/findReplaceZext/separateSymbol)/SubNormal | ⚠️ INDEX(PtrsubCharConstant PARTIAL) |
| L7810-L8505 | RulePositiveDiv/DivTermAdd/DivTermAdd2/DivOpt(findForm/calcDivisor/moveSignBitExtraction/checkFormOverlap)/SignDiv2/DivChain/SignForm/SignForm2 | 🔍 |
| L8553-L8959 | RuleSignNearMult/ModOpt/SignMod2nOpt(checkSignExtraction)/SignMod2Opt/SignMod2nOpt2(checkSignExtForm/checkMultiequalForm) | 🔍 |
| L9007-L9252 | RuleSegment/PtrFlow(trialSetPtrFlow/propagateFlowToDef/Reads/truncatePointer)/NegateNegate | 🔍 INDEX OK |
| L9277-L9553 | RuleConditionalMove(checkBoolean/gatherExpression/constructBool) | ⚠️ INDEX(GLUE-UNJUSTIFIED) |
| L9553-L9857 | RuleFloatCast/IgnoreNan(checkBackForCompare/isAnotherNan/testForComparison)/Unsigned2Float/Int2FloatCollapse | 🔍 |
| L9920-L10270 | RuleFuncPtrEncoding/ThreeWayCompare(testCompareEquivalence/detectThreeWay)/PopcountBoolXor(getBooleanResult) | 🔍 |
| L10427-L10937 | RulePiecePathology(isPathology/tracePathologyForward)/XorSwap/LzcountShiftBool/FloatSign/FloatSignCleanup | ⚠️ INDEX(FloatSignCleanup GLUE-UNJUSTIFIED) |
| L10808-L10937 | RuleOrCompare/ExpandLoad(checkAndAnalysis/modifyAndComparison) | 🔍 |

**ruleaction.cc 统计**:263 函数。整体最干净(INDEX:0 MISMATCH),少量 ⚠️。

**三文件合计**:~464 函数。
