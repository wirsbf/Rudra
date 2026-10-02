# 函数清单:heritage.cc + merge.cc + varmap.cc

来源:Ghidra 3 个核心算法 .cc(~170 函数)
Rudra 对应:`src/heritage.rs` + `src/merge.rs` + `src/varmap.rs`

## heritage.cc(72 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L34 | `LocationMap::add(Address, int4, int4, int4&)` | — | 🔍 |
| L77 | `LocationMap::find(const Address&)` | — | 🔍 |
| L91 | `LocationMap::findPass(const Address&) const` | — | 🔍 |
| L109 | `TaskList::add(Address, int4, uint4)` | — | 🔍 |
| L133 | `TaskList::insert(iterator, Address, int4, uint4)` | — | 🔍 |
| L142 | `PriorityQueue::reset(int4)` | — | 🔍 |
| L154 | `PriorityQueue::insert(FlowBlock*, int4)` | — | 🔍 |
| L166 | `FlowBlock *PriorityQueue::extract()` | — | 🔍 |
| L180 | `HeritageInfo::HeritageInfo(AddrSpace*)` | `HeritageInfo::new` | ⚠️ INDEX P0 |
| L206 | `HeritageInfo::reset()` | — | 🔍 |
| L219 | `Heritage::Heritage(Funcdata*)` | `Heritage::new` | 🔍 |
| L227 | `clearInfoList()` | — | 🔍 |
| L245 | `removeRevisitedMarkers(...)` | — | 🔍 |
| L308 | `collect(MemRange&, vector<Varnode*>&, ...)` | — | 🔍 |
| L359 | `callOpIndirectEffect(...)` | — | 🔍 |
| L383 | `normalizeReadSize(...)` | — | 🔍 |
| L417 | `normalizeWriteSize(...)` | — | 🔍 |
| L508 | `concatPieces(...)` | — | 🔍 |
| L564 | `splitPieces(...)` | — | 🔍 |
| L619 | `findAddressForces(...)` | — | 🔍 |
| L675 | `propagateCopyAway(PcodeOp*)` | — | 🔍 |
| L696 | `handleNewLoadCopies()` | — | 🔍 |
| L741 | `LoadGuard::establishRange(ValueSetRead&)` | — | 🔍 |
| L788 | `LoadGuard::finalizeRange(ValueSetRead&)` | — | 🔍 |
| L819 | `LoadGuard::isGuarded(const Address&) const` | — | 🔍 |
| L835 | `analyzeNewLoadGuards()` | — | 🔍 |
| L910/L927 | `generateLoadGuard/generateStoreGuard` | — | 🔍 |
| L945 | `protectFreeStores(...)` | — | 🔍 |
| L987 | `discoverIndexedStackPointers(...)` | `discover_and_guard_stack_stores_fd` | ✅ 2026-07-16 BFS from RSP input, handles STORE/LOAD/ADD/SUB/COPY/MULTIEQUAL/INDIRECT, StackNode 已实现 |
| L1112 | `reprocessFreeStores(...)` | — | 🔍 |
| L1157 | `guard(...)` | — | 🔍 |
| L1211-L1392 | guardCallOverlappingInput/guardOutputOverlap*/tryOutputOverlapGuard*/tryOutputStackGuard | — | 🔍 |
| L1444 | `guardCalls(...)` | `guard_calls` | ⚠️ INDEX P0 stub |
| L1539 | `guardStores(...)` | `guard_stores` | ⚠️ INDEX P0 |
| L1571 | `guardLoads(...)` | `guard_loads` | ⚠️ INDEX P0 |
| L1610 | `guardReturnsOverlapping(...)` | — | 🔍 |
| L1653 | `guardReturns(...)` | `guard_returns` | ⚠️ INDEX P0 stub |
| L1705-L1891 | refinement 系列(buildRefinement/splitByRefinement/refineRead/Write/Input/remove13Refinement/refinement) | — | 🔍 |
| L1953 | `guardInput(...)` | — | 🔍 |
| L2048 | `clearStackPlaceholders(HeritageInfo*)` | — | 🔍 |
| L2068-L2282 | join 系列(splitJoinLevel/Read/Write/floatExtension*/processJoins) | — | 🔍 |
| L2317 | `buildADT()` | — | 🔍 |
| L2395 | `visitIncr(FlowBlock*, FlowBlock*)` | — | 🔍 |
| L2440 | `calcMultiequals(const vector<Varnode*>&)` | — | 🔍 |
| L2480 | `renameRecurse(BlockBasic*, VariableStack&)` | `visit_rename_direct` | ⚠️ INDEX P0 已修(commit 7eea43c),但 op_set_input 不清 descend → semantic #3 可能死代码 |
| L2572 | `bumpDeadcodeDelay(AddrSpace*)` | — | 🔍 |
| L2588 | `rename()` | `rename` | 🔍 |
| L2600 | `placeMultiequals()` | `place_multiequals` | ✅ 2026-07-16 ADT (build_adt + visit_incr + calc_multiequals) 已实现 |
| L2664 | `buildInfoList()` | `build_info_list` | ✅ 2026-07-16 |
| L2677 | `heritage()` | `heritage` | ⚠️ 2026-07-16 主流程已实现。剩余 TODO: clearStackPlaceholders ✅, reprocessFreeStores ✅, analyzeNewLoadGuards ✅(conservative stub), handleNewLoadCopies ✅, PreferSplitManager ✅(wired). discoverIndexedStackPointers ✅. heritage() 零 TODO（d9ad7ab）。 |
| L2776 | `getStoreGuard(PcodeOp*) const` | `get_store_guard` | 🔍 |
| L2793 | `numHeritagePasses(AddrSpace*) const` | `num_heritage_passes` | ⚠️ INDEX P0 |
| L2805 | `seenDeadCode(AddrSpace*)` | `seen_dead_code` | ⚠️ INDEX P0 |
| L2817 | `getDeadCodeDelay(AddrSpace*) const` | `get_dead_code_delay` | ⚠️ INDEX P0 |
| L2829 | `setDeadCodeDelay(AddrSpace*, int4)` | `set_dead_code_delay` | ⚠️ INDEX P0 |
| L2843 | `deadRemovalAllowed(AddrSpace*) const` | `dead_removal_allowed` | ✅ 2026-07-16 (pass > deadcodedelay) |
| L2857 | `deadRemovalAllowedSeen(AddrSpace*)` | — | 🔍 |
| L2869 | `clear()` | `clear` | ⚠️ INDEX P0 |

**heritage.cc 统计**:72 函数。heritage() 零 TODO（2026-07-16）。buildVariableName⚠️、gatherInternal⚠️（已实现，缺细化）。placeMultiequals ✅、discoverIndexedStackPointers ✅。

## merge.cc(49 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L24/L43 | `BlockVarnode::set/findFront` | — | 🔍 |
| L63/L78 | `StackAffectingOps::populate/affectsTest` | — | 🔍 |
| L102-L255 | `mergeTestRequired/Adjacent/Speculative/Must/Basic` | `merge_test_*` | 🔍 |
| L272 | `mergeLinear(vector<HighVariable*>&)` | `merge_linear` | 🔍 |
| L301/L326/L359 | `mergeRangeMust/mergeOpcode/mergeByDatatype` | `merge_*` | 🔍 |
| L411/L443 | `allocateCopyTrim/snipReads` | — | 🔍 |
| L489 | `eliminateIntersect(...)` | `eliminate_intersect` | 🔍 |
| L581/L609 | `unifyAddress/mergeAddrTied` | `unify_address`/`merge_addr_tied` | 🔍 |
| L656/L692 | `trimOpOutput/Input` | `trim_op_*` | 🔍 |
| L719 | `mergeOp(PcodeOp*)` | `merge_op` | 🔍 |
| L783 | `collectInputs(...)` | `collect_inputs` | 🔍 |
| L811/L846 | `snipOutputInterference/mergeIndirect` | `snip_output_interference`/`merge_indirect` | 🔍 |
| L889/L908 | `mergeMarker/mergeMultiEntry` | `merge_marker`/`merge_multi_entry` | 🔍 |
| L967/L983 | `groupPartials/mergeAdjacent` | `group_partials`/`merge_adjacent` | 🔍 |
| L1021 | `findSingleCopy(...)` | — | 🔍 |
| L1045 | `compareCopyByInVarnode(...)` | `compare_copy_by_in_varnode` | 🔍 |
| L1070 | `hideShadows(HighVariable*)` | `hide_shadows_of` | 🔍 |
| L1112/L1151 | `checkCopyPair/buildDominantCopy` | `check_copy_pair`/`build_dominant_copy` | 🔍 |
| L1249/L1271 | `markRedundantCopies/shadowedVarnode` | `mark_redundant_copies`/`shadowed_varnode` | 🔍 |
| L1295/L1316 | `findAllIntoCopies/processHighDominantCopy` | `find_all_into_copies`/`process_high_dominant_copy` | 🔍 |
| L1345/L1374 | `processHighRedundantCopy/groupPartialRoot` | `process_high_redundant_copy` | 🔍 |
| L1415 | `processCopyTrims()` | `process_copy_trims` | 🔍 |
| L1444 | `markInternalCopies()` | `mark_internal_copies` | 🔍 |
| L1549 | `registerProtoPartialRoot(Varnode*)` | — | 🔍 |
| L1565 | `merge(HighVariable*, HighVariable*, bool)` | `merge_force`/`merge_speculative` | 🔍 |
| L1580 | `clear()` | `clear` | 🔍 |
| L1595 | `markImplied(Varnode*)` | `mark_implied` | 🔍 |
| L1616 | `inflateTest(Varnode*, HighVariable*)` | `inflate_test` | 🔍 |
| L1657 | `mergeTest(HighVariable*, vector<HighVariable*>&)` | `merge_test` (Vec, 非 list) | ⚠️ INDEX: cited merge.cc:1657 但实际是 size/space check |
| L1676 | `verifyHighCovers()` | — | 🔍 |

**merge.cc 统计**:49 函数。⚠️ merge_test(INDEX)。

## varmap.cc(51 函数)

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L30-L321 | `RangeHint::isConstAbsorbable/reconcile/contain/preferred/attemptJoin/absorb/merge/compare` | `RangeHint::*` | 🔍 INDEX OK |
| L341 | `ScopeLocal::ScopeLocal(...)` | `ScopeLocal::new` | 🔍 |
| L357 | `collectNameRecs()` | — | 🔍 |
| L386 | `annotateRawStackPtr()` | — | 🔍 |
| L414 | `checkUnaliasedReturn(...)` | — | 🔍 |
| L432 | `resetLocalWindow()` | — | 🔍 |
| L462-L494 | encode/decode/isUnmappedUnaliased | — | 🔍 |
| L510 | `markNotMapped(AddrSpace*, uintb, int4, bool)` | `mark_not_mapped` | 🔍 |
| L548 | `buildVariableName(const Address&, const Address&, Datatype*, int4&, uint4) const` | `build_variable_name` | ⚠️ 2026-07-16 已实现（缺 printNameBase/&base/makeNameUnique，基本功能到位） |
| L587 | `adjustFit(RangeHint&) const` | `adjust_fit` | ⚠️ INDEX |
| L617 | `createEntry(const RangeHint&)` | `create_entry` | ⚠️ INDEX |
| L633 | `AliasChecker::deriveBoundaries(const FuncProto&)` | `derive_boundaries` | ⚠️ INDEX |
| L660 | `AliasChecker::gatherInternal() const` | `gather_internal` | ⚠️ 2026-07-16 已实现（direction 已修 220c14c，边界分支以 Rust 索引重写） |
| L692 | `AliasChecker::gather(const Funcdata*, AddrSpace*, bool)` | — | 🔍 |
| L711 | `AliasChecker::hasLocalAlias(Varnode*) const` | `has_local_alias` | ⚠️ INDEX P0 已修(direction) |
| L726 | `AliasChecker::sortAlias() const` | `sort_aliases` | 🔍 |
| L741 | `AliasChecker::gatherAdditiveBase(...)` | `gather_additive_base` | 🔍 |
| L817 | `AliasChecker::gatherOffset(Varnode*)` | `gather_offset` | 🔍 |
| L864/L881 | `MapState::MapClassObject/~MapState` | `MapState::new` | 🔍 |
| L896 | `addRange(uintb, Datatype*, uint4, RangeType, int4)` | `add_range` | 🔍 |
| L926 | `addFixedType(uintb, Datatype*, uint4, TypeFactory*)` | `add_fixed_type` | 🔍 |
| L960 | `reconcileDatatypes()` | — | 🔍 |
| L1003 | `addGuard(const LoadGuard&, OpCode, TypeFactory*)` | — | 🔍 |
| L1044 | `gatherSymbols(const EntryMap*)` | `gather_symbols`(Rudra 用 gather_spacebase 替代) | ⚠️ INDEX |
| L1063 | `initialize()` | `initialize` | 🔍 |
| L1088 | `isReadActive(Varnode*)` | `is_read_active` | 🔍 |
| L1124 | `gatherVarnodes(const Funcdata&)` | `gather_varnodes` | 🔍 |
| L1211 | `gatherOpen(const Funcdata&)` | `gather_open` | ⚠️ INDEX |
| L1256 | `restructureVarnode(bool aliasyes)` | `restructure_varnode` | ⚠️ INDEX |
| L1294 | `restructure(MapState&)` | `restructure` | ⚠️ INDEX(unsigned vs signed) |
| L1332 | `markUnaliased(const vector<uintb>&)` | `mark_unaliased` | ⚠️ INDEX |
| L1392 | `fakeInputSymbols()` | `fake_input_symbols` | ⚠️ INDEX |
| L1457/L1485 | `remapSymbol(s)Dynamic` | — | 🔍 |
| L1507 | `recoverNameRecommendationsForSymbols()` | — | 🔍 |
| L1574 | `applyTypeRecommendations()` | — | 🔍 |
| L1590 | `addTypeRecommendation(...)` | — | 🔍 |
| L1600 | `addRecommendName(Symbol*)` | — | 🔍 |

**varmap.cc 统计**:51 函数。⚠️ build_variable_name (已实现, 缺细化), 其他 ⚠️ 待逐行验证。
