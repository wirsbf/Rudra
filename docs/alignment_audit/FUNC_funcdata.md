# 函数清单:funcdata_op.cc + funcdata.cc + funcdata_varnode.cc + funcdata_block.cc

来源:Ghidra 4 个 funcdata_*.cc(~185 函数)
Rudra 对应:`src/funcdata.rs`

## funcdata_op.cc(47 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L25 | `void opSetOpcode(PcodeOp*, OpCode)` | `op_set_opcode` | 🔍 |
| L37 | `void opMarkHalt(PcodeOp*, uint4 flag)` | — | 🔍 |
| L52 | `void opUnsetOutput(PcodeOp*)` | `op_unset_output` | 🔍 |
| L70 | `void opSetOutput(PcodeOp*, Varnode*)` | `op_set_output` | 🔍 |
| L92 | `void opUnsetInput(PcodeOp*, int4 slot)` | `op_unset_input` | ⚠️ clearInput 隐式(Vec 模型) |
| L104 | `void opSetInput(PcodeOp*, Varnode*, int4 slot)` | `op_set_input` | ✅ 2026-07-16 (4-step: early-out/const dedup/opUnsetInput+erase_descend/addDescend) |
| L131 | `void opSwapInput(PcodeOp*, int4, int4)` | `op_swap_input` | 🔍 |
| L150 | `void opInsert(PcodeOp*, BlockBasic*, iterator)` | — | 🔍 |
| L164 | `void opUninsert(PcodeOp*)` | `op_uninsert` | 🔍 |
| L179 | `void opUnlink(PcodeOp*)` | `op_unlink` | 🔍 |
| L203 | `void opDestroy(PcodeOp*)` | `op_destroy` | 🔍 |
| L228 | `void opDestroyRecursive(PcodeOp*, vector<PcodeOp*>&)` | `op_destroy_recursive` | 🔍 |
| L253 | `void opDestroyRaw(PcodeOp*)` | `op_destroy_raw` | 🔍 |
| L267 | `void opSetAllInput(PcodeOp*, const vector<Varnode*>&)` | `op_set_all_input` | 🔍 |
| L291 | `void opRemoveInput(PcodeOp*, int4)` | `op_remove_input` | 🔍 |
| L308 | `void opInsertInput(PcodeOp*, Varnode*, int4)` | `op_insert_input` | 🔍 |
| L322 | `PcodeOp *newOp(int4, const Address&)` | `new_op` | 🔍 |
| L332 | `PcodeOp *newOp(int4, const SeqNum&)` | `new_op_seq` | 🔍 |
| L345 | `void opInsertBefore(PcodeOp*, PcodeOp*)` | `op_insert_before` | 🔍 Ghidra 跳前导 INDIRECT |
| L373 | `void opInsertAfter(PcodeOp*, PcodeOp*)` | `op_insert_after` | 🔍 Ghidra 跳后置 MULTIEQUAL+INDIRECT target |
| L413 | `void opInsertBegin(PcodeOp*, BlockBasic*)` | `op_insert_begin` | 🔍 Ghidra 跳前导 MULTIEQUAL |
| L435 | `void opInsertEnd(PcodeOp*, BlockBasic*)` | `op_insert_end` | 🔍 Ghidra 跳末尾 flow break |
| L459 | `Varnode *createStackRef(AddrSpace*, uintb, PcodeOp*, Varnode*, bool)` | — | 🔍 |
| L508 | `PcodeOp *opStackStore(AddrSpace*, uintb, PcodeOp*, bool)` | — | 🔍 |
| L541 | `Varnode *opStackLoad(AddrSpace*, uintb, uint4, PcodeOp*, Varnode*, bool)` | — | 🔍 |
| L560 | `Varnode *opBoolNegate(Varnode*, PcodeOp*, bool)` | — | 🔍 |
| L579 | `void opUndoPtradd(PcodeOp*, bool)` | `op_undo_ptradd` | 🔍 |
| L616 | `PcodeOp *cloneOp(const PcodeOp*, const SeqNum&)` | — | 🔍 |
| L632 | `PcodeOp *getFirstReturnOp() const` | — | 🔍 |
| L656 | `PcodeOp *newOpBefore(PcodeOp*, OpCode, Varnode*, Varnode*, Varnode*)` | `new_op_before` | 🔍 |
| L683 | `PcodeOp *newIndirectOp(PcodeOp*, const Address&, int4, uint4)` | `new_indirect_op` | 🔍 |
| L710 | `PcodeOp *newIndirectCreation(PcodeOp*, const Address&, int4, bool)` | `new_indirect_creation` | 🔍 |
| L736 | `void markIndirectCreation(PcodeOp*, bool)` | — | 🔍 |
| L756 | `void followFlow(const Address&, const Address&)` | (flow.rs) | 🔍 |
| L792 | `void truncatedFlow(const Funcdata*, const FlowInfo*)` | — | ➖ Rudra 不做 partial clone(设计决策) |
| L853 | `int4 inlineFlow(Funcdata*, FlowInfo&, PcodeOp*)` | — | ➖ Rudra 不做 inline(设计决策) |
| L929 | `PcodeOp *findPrimaryBranch(iter, iter, bool, bool, bool)` | — | 🔍 |
| L969 | `void overrideFlow(const Address&, uint4)` | (override_rs.rs) | 🔍 |
| L1029 | `bool replaceLessequal(PcodeOp*)` | `replace_lessequal` | 🔍 |
| L1073 | `bool distributeIntMultAdd(PcodeOp*)` | `distribute_int_mult_add` | 🔍 |
| L1132 | `bool collapseIntMultMult(Varnode*)` | — | 🔍 |
| L1161 | `Varnode *buildCopyTemp(Varnode*, PcodeOp*)` | — | 🔍 |
| L1223 | `int4 opFlipInPlaceTest(PcodeOp*, vector<PcodeOp*>&)` | — | 🔍 |
| L1282 | `void opFlipInPlaceExecute(vector<PcodeOp*>&)` | — | 🔍 |
| L1326 | `PcodeOp *cseFindInBlock(PcodeOp*, Varnode*, BlockBasic*, PcodeOp*)` | — | 🔍 |
| L1358 | `PcodeOp *cseElimination(PcodeOp*, PcodeOp*)` | — | 🔍 |
| L1420 | `void cseEliminateList(vector<pair<uintm,PcodeOp*>>&, vector<Varnode*>&)` | — | 🔍 |
| L1459 | `bool moveRespectingCover(PcodeOp*, PcodeOp*)` | — | 🔍 |

**funcdata_op.cc 统计**:47 函数。0 ❌(opSetInput 已修复 2026-07-16), 1 ⚠️(opUnsetInput), 2 ➖。

## funcdata.cc(41 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L34 | `Funcdata::Funcdata(...)` | `Funcdata::new` | 🔍 |
| L84 | `void clear()` | — | 🔍 |
| L119/L135 | `warning/warningHeader` | — | 🔍 |
| L150/L170 | `startProcessing/stopProcessing` | — | 🔍 |
| L182 | `bool startTypeRecovery()` | — | 🔍 |
| L190 | `~Funcdata()` | — | 🔍 |
| L209 | `void printRaw(ostream&) const` | — | 🔍 |
| L230 | `void spacebase()` | `spacebase` | 🔍 |
| L275 | `Varnode *newSpacebasePtr(AddrSpace*)` | — | 🔍 |
| L291 | `Varnode *findSpacebaseInput(AddrSpace*) const` | `find_spacebase_input` | 🔍 |
| L309 | `Varnode *constructSpacebaseInput(AddrSpace*)` | — | 🔍 |
| L332 | `Varnode *constructConstSpacebase(AddrSpace*)` | — | 🔍 |
| L360 | `void spacebaseConstant(PcodeOp*, int4, SymbolEntry*, const Address&, uintb, int4)` | — | 🔍 |
| L464 | `void clearCallSpecs()` | — | 🔍 |
| L475 | `void issueDatatypeWarnings()` | — | 🔍 |
| L484 | `FuncCallSpecs *getCallSpecs(const PcodeOp*) const` | — | 🔍 |
| L504 | `bool compareCallspecs(const FuncCallSpecs*, const FuncCallSpecs*)` | — | 🔍 |
| L516 | `void sortCallSpecs()` | — | 🔍 |
| L524 | `void deleteCallSpecs(PcodeOp*)` | — | 🔍 |
| L545 | `int4 fillinExtrapop()` | — | 🔍 |
| L579/L597 | `printVarnodeTree/printLocalRange` | — | 🔍 |
| L613-L848 | decode/encode 系列(jumpTable/varnode/high/tree/Funcdata) | — | 🔍 |
| L878 | `PcodeEmitFd::dump(...)` | — | 🔍 |
| L917-L1011 | union field 系列(getUnionField/setUnionField/forceFacingType/inheritResolution) | — | 🔍 |
| L1012-L1100 | debug 系列(debugModCheck/Clear/Print/SetRange/CheckRange/PrintRange) | — | ➖ `#ifdef OPACTION_DEBUG` 条件编译,Rudra 不移植 |

## funcdata_varnode.cc(61 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L25 | `setVarnodeProperties(Varnode*) const` | — | 🔍 |
| L48 | `HighVariable *assignHigh(Varnode*)` | — | 🔍 |
| L66 | `Varnode *newConstant(int4, uintb)` | `new_constant` | 🔍 |
| L83 | `Varnode *newUnique(int4, Datatype*)` | `new_unique` | 🔍 |
| L104 | `Varnode *newVarnodeOut(int4, const Address&, PcodeOp*)` | `new_varnode_out` | 🔍 |
| L129 | `Varnode *newUniqueOut(int4, PcodeOp*)` | `new_unique_out` | 🔍 |
| L148 | `Varnode *newVarnode(int4, const Address&, Datatype*)` | `new_varnode` | 🔍 |
| L176 | `Varnode *newVarnodeIop(PcodeOp*)` | `new_varnode_iop` | 🔍 |
| L190 | `Varnode *newVarnodeSpace(AddrSpace*)` | — | 🔍 |
| L205 | `Varnode *newVarnodeCallSpecs(FuncCallSpecs*)` | — | 🔍 |
| L222 | `Varnode *newCodeRef(const Address&)` | — | 🔍 |
| L239 | `Varnode *newVarnode(int4, AddrSpace*, uintb)` | — | 🔍 |
| L252 | `Varnode *cloneVarnode(const Varnode*)` | — | 🔍 |
| L272 | `void destroyVarnode(Varnode*)` | `delete_varnode` | 🔍 |
| L298 | `void checkForLanedRegister(int4, const Address&)` | — | 🔍 |
| L316 | `HighVariable *findHigh(const string&) const` | — | 🔍 |
| L340 | `Varnode *setInputVarnode(Varnode*)` | `set_input_varnode` | ⚠️ Rudra 已补 overlap dedup,缺 ProtoModel 效果 |
| L381 | `void combineInputVarnodes(Varnode*, Varnode*)` | — | 🔍 |
| L462 | `Varnode *newExtendedConstant(int4, uint8*, PcodeOp*)` | `new_extended_constant` | 🔍 |
| L494 | `void adjustInputVarnodes(const Address&, int4)` | — | 🔍 |
| L543 | `bool descend2Undef(Varnode*)` | — | 🔍 |
| L585 | `void initActiveOutput()` | — | 🔍 |
| L595 | `void setHighLevel()` | `set_high_level` | 🔍 |
| L614 | `void transferVarnodeProperties(Varnode*, Varnode*, int4)` | — | 🔍 |
| L635 | `bool fillinReadOnly(Varnode*)` | — | 🔍 |
| L717 | `bool replaceVolatile(Varnode*)` | — | 🔍 |
| L771 | `bool checkIndirectUse(Varnode*)` | — | 🔍 |
| L815 | `void markIndirectOnly()` | — | 🔍 |
| L832 | `void clearDeadVarnodes()` | — | 🔍 |
| L856 | `void calcNZMask()` | — | 🔍 |
| L938 | `bool syncVarnodesWithSymbols(const ScopeLocal*, bool, bool)` | `sync_varnodes_with_symbols` | 🔍 |
| L997 | `Symbol *handleSymbolConflict(SymbolEntry*, Varnode*)` | — | 🔍 |
| L1048 | `bool syncVarnodesWithSymbol(iter&, uint4, Datatype*)` | — | 🔍 |
| L1104/L1120 | `remapSymbol/remapSymbolDynamic` | — | 🔍 |
| L1132 | `void linkProtoPartial(Varnode*)` | — | 🔍 |
| L1156 | `Symbol *linkSymbol(Varnode*)` | — | 🔍 |
| L1193 | `Symbol *linkSymbolReference(Varnode*)` | — | 🔍 |
| L1218/L1257 | `findLinkedVarnode(s)` | — | 🔍 |
| L1283 | `void buildDynamicSymbol(Varnode*)` | — | 🔍 |
| L1314/L1347 | `attemptDynamicMapping(Late)` | — | 🔍 |
| L1413 | `Varnode *getInternalString(uint1*, int4, Datatype*, PcodeOp*)` | — | 🔍 |
| L1442 | `bool testForReturnAddress(Varnode*)` | — | 🔍 |
| L1474 | `void totalReplace(Varnode*, Varnode*)` | `total_replace` | 🔍 |
| L1496 | `void totalReplaceConstant(Varnode*, uintb)` | — | 🔍 |
| L1540 | `void splitUses(Varnode*)` | — | 🔍 |
| L1573 | `Address findDisjointCover(Varnode*, int4&)` | — | 🔍 |
| L1606 | `void coverVarnodes(SymbolEntry*, vector<Varnode*>&)` | — | 🔍 |
| L1637 | `bool applyUnionFacet(SymbolEntry*, DynamicHash&)` | — | 🔍 |
| L1653 | `void mapGlobals()` | — | 🔍 |
| L1723 | `void prepareThisPointer()` | — | 🔍 |
| L1756 | `bool checkCallDoubleUse(...)` | — | 🔍 |
| L1805 | `bool onlyOpUse(...)` | — | 🔍 |
| L1917 | `bool ancestorOpUse(int4, const Varnode*, const PcodeOp*, ParamTrial&, int4, uint4) const` | — | 🔍 |
| L1997-L2194 | AncestorRealistic 类(checkConditionalExe/enterNode/uponPop/execute) | — | 🔍 |

## funcdata_block.cc(36 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L28 | `printBlockTree` | — | 🔍 |
| L35 | `clearBlocks` | — | 🔍 |
| L43 | `clearJumpTables` | — | 🔍 |
| L65 | `removeJumpTable` | — | 🔍 |
| L85 | `pushMultiequals(BlockBasic*)` | — | 🔍 |
| L178 | `opZeroMulti(PcodeOp*)` | — | 🔍 |
| L196/L221 | `branchRemoveInternal/removeBranch` | — | 🔍 |
| L234 | `descendantsOutside(Varnode*)` | — | 🔍 |
| L255 | `blockRemoveInternal(BlockBasic*, bool)` | — | 🔍 |
| L328 | `removeDoNothingBlock(BlockBasic*)` | — | 🔍 |
| L347 | `removeUnreachableBlocks(bool, bool)` | — | 🔍 |
| L404 | `pushBranch(BlockBasic*, int4, BlockBasic*)` | — | 🔍 |
| L427/L446/L464 | linkJumpTable/findJumpTable/installJumpTable | — | 🔍 |
| L492/L555/L640 | stageJumpTable/earlyJumpTableFail/recoverJumpTable | — | 🔍 |
| L679 | `switchOverJumpTables(const FlowInfo&)` | — | 🔍 |
| L688 | `installSwitchDefaults()` | — | 🔍 |
| L705 | `structureReset()` | — | 🔍 |
| L752 | `forceGoto(const Address&, const Address&)` | — | 🔍 |
| L790 | `nodeJoinCreateBlock(...)` | — | 🔍 |
| L835/L856 | `nodeSplitBlockEdge/nodeSplit` | — | 🔍 |
| L892 | `removeFromFlowSplit(BlockBasic*, bool)` | — | 🔍 |
| L908/L919 | `switchEdge/spliceBlockBasic` | — | 🔍 |
| L962-L1058 | CloneBlockOps 类(buildOpClone/buildVarnodeOutput/cloneBlock/cloneExpression/patchInputs) | — | 🔍 |

**funcdata 系列总计**:~185 函数。1 ❌, 2 ⚠️, 大量 🔍。
