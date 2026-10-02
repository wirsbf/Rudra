# 函数清单:cover.cc + rangeutil.cc

来源:Ghidra 2 个 .cc(~85 函数)
Rudra 对应:`src/cover.rs` + `src/rangeutil.rs`

## cover.cc(23 函数)

CoverBlock + Cover + PcodeOpSet。

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L29 | `uintm CoverBlock::getUIndex(const PcodeOp*)` | — | 🔍 |
| L59 | `int4 CoverBlock::intersect(const CoverBlock&) const` | — | 🔍 |
| L107 | `bool CoverBlock::contain(const PcodeOp*) const` | — | 🔍 |
| L129 | `int4 CoverBlock::boundary(const PcodeOp*) const` | — | 🔍 |
| L147 | `void CoverBlock::merge(const CoverBlock&)` | — | 🔍 |
| L188 | `void CoverBlock::print(ostream&) const` | — | 🔍 |
| L223 | `int4 Cover::compareTo(const Cover&) const` | — | 🔍 |
| L253 | `const CoverBlock &Cover::getCoverBlock(int4) const` | — | 🔍 |
| L269 | `int4 Cover::intersect(const Cover&) const` | — | 🔍 |
| L307 | `void Cover::intersectList(vector<int4>&, const Cover&, int4) const` | — | 🔍 |
| L342 | `bool Cover::intersect(const PcodeOpSet&, Varnode*) const` | — | 🔍 |
| L392 | `int4 Cover::intersectByBlock(int4, const Cover&) const` | — | 🔍 |
| L413 | `bool Cover::contain(const PcodeOp*, int4 max) const` | — | 🔍 |
| L441 | `int4 Cover::containVarnodeDef(const Varnode*) const` | — | 🔍 |
| L465 | `void Cover::merge(const Cover&)` | — | 🔍 |
| L477 | `void Cover::rebuild(const Varnode*)` | — | 🔍 |
| L501 | `void Cover::addDefPoint(const Varnode*)` | — | 🔍 |
| L524 | `void Cover::addRefRecurse(const FlowBlock*)` | — | 🔍 |
| L565 | `void Cover::addRefPoint(const PcodeOp*, const Varnode*)` | — | 🔍 |
| L615 | `void Cover::print(ostream&) const` | — | 🔍 |
| L627 | `void PcodeOpSet::finalize()` | — | 🔍 |
| L646 | `bool PcodeOpSet::compareByBlock(const PcodeOp*, const PcodeOp*)` | — | 🔍 |

**cover.cc 统计**:23 函数。全部 🔍。**注意**:Rudra 的 cover 是简化版(merge.rs:2409 compute_varnode_covers 用 def_order-last_use 近似),需要核对是否对齐 Ghidra 的 CoverBlock 精确范围模型。

## rangeutil.cc(~62 函数)

CircleRange + ValueSet + ValueSetRead + WidenerFull/None + ValueSetSolver。

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L25 | `CircleRange::normalize()` | — | 🔍 |
| L38 | `complement()` | — | 🔍 |
| L63 | `convertToBoolean()` | — | 🔍 |
| L103 | `newStride(...)` | — | 🔍 |
| L143 | `newDomain(...)` | — | 🔍 |
| L179 | `CircleRange(lft, rgt, size, stp)` | `CircleRange::new` | 🔍 |
| L191 | `CircleRange(bool val)` | `CircleRange::from_bool` | 🔍 |
| L205 | `CircleRange(val, size)` | — | 🔍 |
| L219/L233/L245/L256/L280 | setRange(×2)/setFull/getSize/getMaxInfo | — | 🔍 |
| L301/L334 | contains(CircleRange)/(uintb val) | `contains_val` | 🔍 |
| L360/L454 | circleUnion/minimalContainer | — | 🔍 |
| L533/L549 | invert/intersect | — | 🔍 |
| L672/L707 | setNZMask/setStride | `set_nz_mask` | 🔍 |
| L728 | `pullBackUnary(OpCode, int4, int4)` | `pull_back_unary` | 🔍 |
| L807 | `pullBackBinary(OpCode, uintb, int4, int4, int4)` | `pull_back_binary` | 🔍 |
| L1022 | `pullBack(PcodeOp*, Varnode**, bool)` | `pull_back` | 🔍 |
| L1093/L1180/L1381 | pushForwardUnary/Binary/Trinary | — | 🔍 |
| L1395/L1424 | widen/translate2Op | — | 🔍 |
| L1470 | `printRaw(ostream&) const` | — | 🔍 |
| L1503-L1821 | ValueSet(setVarnode/addEquation/computeTypeCode/iterate/getLandMark/printRaw) + ValueSetRead(setPcodeOp/addEquation/compute/printRaw) | — | 🔍 |
| L1833-L1896 | WidenerFull/None(determineIterationReset/checkFreeze/doWidening) | — | 🔍 |
| L1910-L2588 | ValueSetSolver(ValueSetEdge/newValueSet/partitionSurround/component/visit/establishTopologicalOrder/generateTrueEquation/FalseEquation/applyConstraints/constraintsFromPath/CBranch/generateConstraints/checkRelativeConstant/generateRelativeConstraint/establishValueSets/solve/dumpValueSets) | — | 🔍 |

**rangeutil.cc 统计**:~62 函数。全部 🔍。**注意**:ValueSetSolver 是 value-set 分析(LoadGuard 用),Rudra 的 LoadGuard.establishRange/finalizeRange 是 stub(INDEX P0),所以 ValueSetSolver 可能整个 ➖。

**两文件合计**:~85 函数。
