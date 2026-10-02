# 函数清单:varnode.cc + op.cc

来源:Ghidra `varnode.cc`(~2053 行,~86 函数)+ `op.cc`(~48 函数)
Rudra 对应:`src/varnode.rs` + `src/op.rs`

## varnode.cc

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L34 | `bool VarnodeCompareLocDef::operator()(const Varnode*, const Varnode*) const` | — | 🔍 |
| L60 | `bool VarnodeCompareDefLoc::operator()(const Varnode*, const Varnode*) const` | — | 🔍 |
| L88 | `HighVariable *Varnode::getHigh() const` | — | 🔍 |
| L105 | `int4 Varnode::contains(const Varnode &op) const` | — | 🔍 |
| L121 | `bool Varnode::intersects(const Varnode &op) const` | — | 🔍 |
| L140 | `bool Varnode::intersects(const Address &op2loc, int4 op2size) const` | — | 🔍 |
| L155 | `int4 Varnode::characterizeOverlap(const Varnode &op) const` | — | 🔍 |
| L178 | `int4 Varnode::overlap(const Varnode &op) const` | — | 🔍 |
| L197 | `int4 Varnode::overlapJoin(const Varnode &op) const` | — | 🔍 |
| L217 | `int4 Varnode::overlap(const Address &op2loc, int4 op2size) const` | — | 🔍 |
| L233 | `void Varnode::updateCover() const` | — | 🔍 |
| L244 | `void Varnode::clearCover() const` | — | 🔍 |
| L254 | `void Varnode::calcCover() const` | — | 🔍 |
| L269 | `void Varnode::printCover(ostream&) const` | — | 🔍 |
| L282 | `void Varnode::printInfo(ostream&) const` | — | 🔍 |
| L316 | `void Varnode::eraseDescend(PcodeOp *op)` | `erase_descend` | ✅ 2026-07-16 (COVERDIRTY 已设) |
| L330 | `void Varnode::addDescend(PcodeOp *op)` | `add_descend` | ✅ 2026-07-16 (COVERDIRTY 已设) |
| L344 | `void Varnode::destroyDescend()` | — | 🔍 |
| L352 | `void Varnode::setFlags(uint4 fl) const` | — | 🔍 |
| L365 | `void Varnode::clearFlags(uint4 fl) const` | — | 🔍 |
| L378 | `void Varnode::clearSymbolLinks()` | — | 🔍 |
| L394 | `void Varnode::setDef(PcodeOp *op)` | — | 🔍 |
| L410 | `bool Varnode::setSymbolProperties(SymbolEntry*)` | — | 🔍 |
| L429 | `void Varnode::setSymbolEntry(SymbolEntry*)` | — | 🔍 |
| L446 | `void Varnode::setSymbolReference(SymbolEntry*, int4 off)` | — | 🔍 |
| L456 | `bool Varnode::updateType(Datatype*)` | — | 🔍 |
| L474 | `bool Varnode::updateType(Datatype*, bool lock, bool override)` | — | 🔍 |
| L493 | `void Varnode::copySymbol(const Varnode*)` | `copy_symbol` | 🔍 |
| L510 | `void Varnode::copySymbolIfValid(const Varnode*)` | — | 🔍 |
| L533 | `bool Varnode::operator<(const Varnode &op2) const` | — | 🔍 |
| L556 | `bool Varnode::operator==(const Varnode &op2) const` | — | 🔍 |
| L578 | `Varnode::Varnode(int4 s, const Address &m, Datatype *dt)` | — | 🔍 |
| L610 | `Varnode::~Varnode()` | — | 🔍 |
| L626 | `Datatype *Varnode::getTypeDefFacing() const` | — | 🔍 |
| L639 | `Datatype *Varnode::getTypeReadFacing(const PcodeOp*) const` | — | 🔍 |
| L651 | `Datatype *Varnode::getHighTypeDefFacing() const` | — | 🔍 |
| L665 | `Datatype *Varnode::getHighTypeReadFacing(const PcodeOp*) const` | — | 🔍 |
| L676 | `PcodeOp *Varnode::loneDescend() const` | `lone_descend` | 🔍 |
| L696 | `Address Varnode::getUsePoint(const Funcdata&) const` | — | 🔍 |
| L711 | `int4 Varnode::printRawNoMarkup(ostream&) const` | — | 🔍 |
| L741 | `void Varnode::printRaw(ostream&) const` | — | 🔍 |
| L761 | `void Varnode::printRawHeritage(ostream&, int4 depth) const` | — | 🔍 |
| L799 | `bool Varnode::isConstantExtended(uint8 *val) const` | `is_constant_extended` | 🔍 |
| L854 | `bool Varnode::isEventualConstant(int4, int4) const` | — | 🔍 |
| L900 | `Datatype *Varnode::getLocalType(bool &blockup) const` | — | 🔍 |
| L942 | `bool Varnode::isBooleanValue(bool) const` | `is_boolean_value` | 🔍 |
| L958 | `bool Varnode::isZeroExtended(int4 baseSize) const` | — | 🔍 |
| L977 | `bool Varnode::copyShadow(const Varnode*) const` | — | 🔍 |
| L1006 | `bool Varnode::findSubpieceShadow(int4, const Varnode*, int4) const` | — | 🔍 |
| L1062 | `bool Varnode::findPieceShadow(int4, const Varnode*) const` | — | 🔍 |
| L1102 | `bool Varnode::partialCopyShadow(const Varnode*, int4) const` | — | 🔍 |
| L1137 | `Datatype *Varnode::getStructuredType() const` | — | 🔍 |
| L1153 | `int4 Varnode::termOrder(const Varnode*) const` | — | 🔍 |
| L1182 | `void Varnode::encode(Encoder&) const` | — | 🔍 |
| L1207 | `void Varnode::printRaw(ostream&, const Varnode*)` (static) | — | 🔍 |
| L1218 | `VarnodeBank::VarnodeBank(AddrSpaceManager*)` | — | 🔍 |
| L1230 | `void VarnodeBank::clear()` | — | 🔍 |
| L1250 | `Varnode *VarnodeBank::create(int4 s, const Address&, Datatype*)` | `create` | 🔍 |
| L1265 | `Varnode *VarnodeBank::createUnique(int4 s, Datatype*)` | `create_unique` | 🔍 |
| L1276 | `void VarnodeBank::destroy(Varnode*)` | `destroy_varnode` | 🔍 |
| L1291 | `Varnode *VarnodeBank::xref(Varnode*)` | — | 🔍 |
| L1316 | `void VarnodeBank::makeFree(Varnode*)` | — | 🔍 |
| L1332 | `void VarnodeBank::replace(Varnode *old, Varnode *new)` | — | 🔍 |
| L1358 | `Varnode *VarnodeBank::setInput(Varnode*)` | `set_input` | 🔍 |
| L1380 | `Varnode *VarnodeBank::setDef(Varnode*, PcodeOp*)` | `set_def` | 🔍 |
| L1411 | `Varnode *VarnodeBank::createDef(int4, const Address&, Datatype*, PcodeOp*)` | — | 🔍 |
| L1426 | `Varnode *VarnodeBank::createDefUnique(int4, Datatype*, PcodeOp*)` | — | 🔍 |
| L1440 | `Varnode *VarnodeBank::find(int4, const Address&, const Address&, uintm) const` | — | 🔍 |
| L1465 | `Varnode *VarnodeBank::findInput(int4, const Address&) const` | — | 🔍 |
| L1485 | `Varnode *VarnodeBank::findCoveredInput(int4, const Address&) const` | — | 🔍 |
| L1513 | `Varnode *VarnodeBank::findCoveringInput(int4, const Address&) const` | — | 🔍 |
| L1536 | `bool VarnodeBank::hasInputIntersection(int4, const Address&) const` | — | 🔍 |
| L1560 | `VarnodeLocSet::const_iterator VarnodeBank::beginLoc(AddrSpace*) const` | — | 🔍 |
| L1571 | `VarnodeLocSet::const_iterator VarnodeBank::endLoc(AddrSpace*) const` | — | 🔍 |
| L1582 | `VarnodeLocSet::const_iterator VarnodeBank::beginLoc(const Address&) const` | — | 🔍 |
| L1593 | `VarnodeLocSet::const_iterator VarnodeBank::endLoc(const Address&) const` | — | 🔍 |
| L1610 | `VarnodeLocSet::const_iterator VarnodeBank::beginLoc(int4, const Address&) const` | — | 🔍 |
| L1625 | `VarnodeLocSet::const_iterator VarnodeBank::endLoc(int4, const Address&) const` | — | 🔍 |
| L1645 | `VarnodeLocSet::const_iterator VarnodeBank::beginLoc(int4, const Address&, uint4 fl) const` | — | 🔍 |
| L1693 | `VarnodeLocSet::const_iterator VarnodeBank::endLoc(int4, const Address&, uint4 fl) const` | — | 🔍 |
| L1732 | `VarnodeLocSet::const_iterator VarnodeBank::beginLoc(int4, const Address&, const Address&, uintm) const` | — | 🔍 |
| L1762 | `VarnodeLocSet::const_iterator VarnodeBank::endLoc(int4, const Address&, const Address&, uintm) const` | — | 🔍 |
| L1791 | `uint4 VarnodeBank::overlapLoc(iterator, vector<iterator>&) const` | — | 🔍 |
| L1831 | `VarnodeDefSet::const_iterator VarnodeBank::beginDef(uint4 fl) const` | — | 🔍 |
| L1869 | `VarnodeDefSet::const_iterator VarnodeBank::endDef(uint4 fl) const` | — | 🔍 |
| L1908 | `VarnodeDefSet::const_iterator VarnodeBank::beginDef(uint4 fl, const Address&) const` | — | 🔍 |
| L1942 | `VarnodeDefSet::const_iterator VarnodeBank::endDef(uint4 fl, const Address&) const` | — | 🔍 |
| L1971 | `void VarnodeBank::verifyIntegrity() const` (#ifdef VARBANK_DEBUG) | — | ➖ `#ifdef VARBANK_DEBUG` 条件编译,Rudra 不移植 |
| L2014 | `bool contiguous_test(Varnode*, Varnode*)` | — | 🔍 |
| L2045 | `Varnode *findContiguousWhole(Funcdata&, Varnode*, Varnode*)` | — | 🔍 |

**varnode.cc 统计**:~86 函数。0 ⚠️ (eraseDescend/addDescend COVERDIRTY 已设 2026-07-16),大量 🔍 待逐行验证。

## op.cc

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L33 | `IopSpace::IopSpace(AddrSpaceManager*, const Translate*, int4)` | — | 🔍 |
| L41 | `void IopSpace::printRaw(ostream&, uintb) const` | — | 🔍 |
| L61 | `void IopSpace::decode(Decoder&)` | — | 🔍 |
| L71 | `PcodeOp::PcodeOp(int4 s, const SeqNum &sq)` | — | 🔍 |
| L93 | `int4 PcodeOp::getRepeatSlot(const Varnode*, int4, list<PcodeOp*>::const_iterator) const` | — | 🔍 |
| L115 | `bool PcodeOp::isCollapsible() const` | — | 🔍 |
| L130 | `uintm PcodeOp::getCseHash() const` | — | 🔍 |
| L153 | `bool PcodeOp::isCseMatch(const PcodeOp*) const` | — | 🔍 |
| L178 | `bool PcodeOp::isMoveable(const PcodeOp *point) const` | — | 🔍 |
| L276 | `void PcodeOp::setOpcode(TypeOp*)` | — | 🔍 |
| L290 | `void PcodeOp::setNumInputs(int4)` | — | 🔍 |
| L301 | `void PcodeOp::removeInput(int4 slot)` | — | 🔍 |
| L311 | `void PcodeOp::insertInput(int4 slot)` | — | 🔍 |
| L323 | `PcodeOp *PcodeOp::nextOp() const` | — | 🔍 |
| L344 | `PcodeOp *PcodeOp::previousOp() const` | — | 🔍 |
| L360 | `PcodeOp *PcodeOp::target() const` | — | 🔍 |
| L376 | `void PcodeOp::printDebug(ostream&) const` | — | 🔍 |
| L389 | `void PcodeOp::encode(Encoder&) const` | — | 🔍 |
| L450 | `uintb PcodeOp::collapse(bool &markedInput) const` | — | 🔍 |
| L478 | `uintb PcodeOp::executeSimple(uintb *in, bool &evalError) const` | — | 🔍 |
| L503 | `void PcodeOp::collapseConstantSymbol(Varnode*) const` | — | 🔍 |
| L547 | `uintb PcodeOp::getNZMaskLocal(bool cliploop) const` | — | 🔍 |
| L778 | `int4 PcodeOp::compareOrder(const PcodeOp*) const` | — | 🔍 |
| L801 | `bool PieceNode::isLeaf(Varnode*, Varnode*, int4)` | — | 🔍 |
| L824 | `Varnode *PieceNode::findRoot(Varnode*)` | — | 🔍 |
| L865 | `void PieceNode::gatherPieces(vector<PieceNode>&, Varnode*, PcodeOp*, int4, int4)` | — | 🔍 |
| L881 | `void PcodeOpBank::addToCodeList(PcodeOp*)` | — | 🔍 |
| L905 | `void PcodeOpBank::removeFromCodeList(PcodeOp*)` | — | 🔍 |
| L926 | `void PcodeOpBank::clearCodeLists()` | — | 🔍 |
| L941 | `PcodeOp *PcodeOpBank::create(int4, const Address&)` | — | 🔍 |
| L957 | `PcodeOp *PcodeOpBank::create(int4, const SeqNum&)` | — | 🔍 |
| L971 | `void PcodeOpBank::destroyDead()` | — | 🔍 |
| L989 | `void PcodeOpBank::destroy(PcodeOp*)` | — | 🔍 |
| L1005 | `void PcodeOpBank::changeOpcode(PcodeOp*, TypeOp*)` | — | 🔍 |
| L1017 | `void PcodeOpBank::markAlive(PcodeOp*)` | — | 🔍 |
| L1028 | `void PcodeOpBank::markDead(PcodeOp*)` | — | 🔍 |
| L1039 | `void PcodeOpBank::insertAfterDead(PcodeOp*, PcodeOp*)` | — | 🔍 |
| L1056 | `void PcodeOpBank::moveSequenceDead(PcodeOp*, PcodeOp*, PcodeOp*)` | — | 🔍 |
| L1071 | `void PcodeOpBank::markIncidentalCopy(PcodeOp*, PcodeOp*)` | — | 🔍 |
| L1089 | `PcodeOp *PcodeOpBank::target(const Address&) const` | — | 🔍 |
| L1099 | `PcodeOp *PcodeOpBank::findOp(const SeqNum&) const` | — | 🔍 |
| L1110 | `PcodeOp *PcodeOpBank::fallthru(const PcodeOp*) const` | — | 🔍 |
| L1146 | `PcodeOpTree::const_iterator PcodeOpBank::begin(const Address&) const` | — | 🔍 |
| L1152 | `PcodeOpTree::const_iterator PcodeOpBank::end(const Address&) const` | — | 🔍 |
| L1158 | `list<PcodeOp*>::const_iterator PcodeOpBank::begin(OpCode) const` | — | 🔍 |
| L1176 | `list<PcodeOp*>::const_iterator PcodeOpBank::end(OpCode) const` | — | 🔍 |
| L1194 | `void PcodeOpBank::clear()` | — | 🔍 |

**op.cc 统计**:~48 函数,全部 🔍。
