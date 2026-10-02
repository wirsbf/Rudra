# 函数清单:address.cc + space.cc

来源:Ghidra `address.cc`(~836 行,~51 函数)+ `space.cc`(~33 函数)
Rudra 对应:`src/address.rs` + `src/space.rs`

## address.cc

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L32 | `operator<<(s, SeqNum)` | — | 🔍 |
| L47 | `operator<<(s, Address)` | — | 🔍 |
| L54 | `SeqNum::SeqNum(mach_extreme ex)` | — | 🔍 |
| L60 | `SeqNum::encode(Encoder&) const` | — | 🔍 |
| L69 | `SeqNum SeqNum::decode(Decoder&)` | — | 🔍 |
| L91 | `Address::Address(mach_extreme ex)` | — | 🔍 |
| L110 | `bool Address::containedBy(int4 sz, const Address &op2, int4 sz2) const` | — | 🔍 |
| L131 | `int4 Address::justifiedContain(int4 sz, const Address &op2, int4 sz2, bool forceleft) const` | — | 🔍 |
| L153 | `int4 Address::overlap(int4 skip, const Address &op, int4 size) const` | — | 🔍 |
| L173 | `bool Address::isContiguous(int4 sz, const Address &loaddr, int4 losz) const` | — | 🔍 |
| L191 | `void Address::renormalize(int4 size)` | — | 🔍 |
| L205 | `Address Address::decode(Decoder&)` | — | 🔍 |
| L226 | `Address Address::decode(Decoder&, int4 &size)` | — | 🔍 |
| L236 | `Range::Range(const RangeProperties&, const AddrSpaceManager*)` | — | 🔍 |
| L265 | `Address Range::getLastAddrOpen(const AddrSpaceManager*) const` | — | 🔍 |
| L283 | `void Range::printBounds(ostream&) const` | — | 🔍 |
| L292 | `void Range::encode(Encoder&) const` | — | 🔍 |
| L304 | `void Range::decode(Decoder&)` | — | 🔍 |
| L316 | `void Range::decodeFromAttributes(Decoder&)` | — | 🔍 |
| L354 | `void RangeProperties::decode(Decoder&)` | — | 🔍 |
| L383 | `void RangeList::insertRange(AddrSpace*, uintb first, uintb last)` | — | 🔍 |
| L417 | `void RangeList::removeRange(AddrSpace*, uintb first, uintb last)` | — | 🔍 |
| L451 | `void RangeList::merge(const RangeList &op2)` | — | 🔍 |
| L468 | `bool RangeList::inRange(const Address &addr, int4 size) const` | — | 🔍 |
| L491 | `const Range *RangeList::getRange(AddrSpace*, uintb offset) const` | — | 🔍 |
| L512 | `uintb RangeList::longestFit(const Address&, uintb maxsize) const` | — | 🔍 |
| L540 | `const Range *RangeList::getFirstRange() const` | — | 🔍 |
| L548 | `const Range *RangeList::getLastRange() const` | — | 🔍 |
| L562 | `const Range *RangeList::getLastSignedRange(AddrSpace*) const` | — | 🔍 |
| L588 | `void RangeList::printBounds(ostream&) const` | — | 🔍 |
| L604 | `void RangeList::encode(Encoder&) const` | — | 🔍 |
| L618 | `void RangeList::decode(Decoder&)` | — | 🔍 |
| L641 | `bool signbit_negative(uintb val, int4 size)` | — | 🔍 |
| L654 | `uintb uintb_negate(uintb in, int4 size)` | — | 🔍 |
| L666 | `uintb sign_extend(uintb in, int4 sizein, int4 sizeout)` | — | 🔍 |
| L681 | `void byte_swap(intb &val, int4 size)` | — | 🔍 |
| L698 | `uintb byte_swap(uintb val, int4 size)` | — | 🔍 |
| L714 | `int4 leastsigbit_set(uintb val)` | — | 🔍 |
| L735 | `int4 mostsigbit_set(uintb val)` | — | 🔍 |
| L756 | `int4 popcount(uintb val)` | — | 🔍 |
| L773 | `int4 count_leading_zeros(uintb val)` | — | 🔍 |
| L800 | `uintb coveringmask(uintb val)` | — | 🔍 |
| L818 | `int4 bit_transitions(uintb val, int4 sz)` | — | 🔍 |

**address.cc 统计**:43 函数,全部 🔍 待核对。

## space.cc

| 行 | Ghidra 函数 | Rudra | 状态 |
|---|---|---|---|
| L34 | `void AddrSpace::calcScaleMask()` | — | 🔍 |
| L58 | `AddrSpace::AddrSpace(AddrSpaceManager*, const Translate*, spacetype, const string&, bool, uint4, uint4, int4, uint4, int4, int4)` | — | 🔍 |
| L88 | `AddrSpace::AddrSpace(AddrSpaceManager*, const Translate*, spacetype)` | — | 🔍 |
| L105 | `void AddrSpace::truncateSpace(uint4 newsize)` | — | 🔍 |
| L126 | `int4 AddrSpace::overlapJoin(uintb offset, int4 size, AddrSpace*, uintb, int4) const` | — | 🔍 |
| L143 | `void AddrSpace::encodeAttributes(Encoder&, uintb offset) const` | — | 🔍 |
| L156 | `void AddrSpace::encodeAttributes(Encoder&, uintb offset, int4 size) const` | — | 🔍 |
| L169 | `uintb AddrSpace::decodeAttributes(Decoder&, uint4 &size) const` | — | 🔍 |
| L194 | `void AddrSpace::printOffset(ostream&, uintb offset) const` | — | 🔍 |
| L206 | `void AddrSpace::printRaw(ostream&, uintb offset) const` | — | 🔍 |
| L255 | `uintb AddrSpace::read(const string&, int4 &size) const` | — | 🔍 |
| L304 | `void AddrSpace::decodeBasicAttributes(Decoder&)` | — | 🔍 |
| L339 | `void AddrSpace::decode(Decoder&)` | — | 🔍 |
| L356 | `ConstantSpace::ConstantSpace(AddrSpaceManager*, const Translate*)` | — | 🔍 |
| L364 | `int4 ConstantSpace::overlapJoin(...) const` | — | 🔍 |
| L372 | `void ConstantSpace::printRaw(ostream&, uintb) const` | — | 🔍 |
| L380 | `void ConstantSpace::decode(Decoder&)` | — | 🔍 |
| L396 | `OtherSpace::OtherSpace(AddrSpaceManager*, const Translate*, int4)` | — | 🔍 |
| L403 | `OtherSpace::OtherSpace(AddrSpaceManager*, const Translate*)` | — | 🔍 |
| L410 | `void OtherSpace::printRaw(ostream&, uintb) const` | — | 🔍 |
| L427 | `UniqueSpace::UniqueSpace(AddrSpaceManager*, const Translate*, int4, uint4)` | — | 🔍 |
| L433 | `UniqueSpace::UniqueSpace(AddrSpaceManager*, const Translate*)` | — | 🔍 |
| L446 | `JoinSpace::JoinSpace(AddrSpaceManager*, const Translate*, int4)` | — | 🔍 |
| L454 | `int4 JoinSpace::overlapJoin(...) const` | — | 🔍 |
| L502 | `void JoinSpace::encodeAttributes(Encoder&, uintb) const` | — | 🔍 |
| L527 | `void JoinSpace::encodeAttributes(Encoder&, uintb, int4) const` | — | 🔍 |
| L539 | `uintb JoinSpace::decodeAttributes(Decoder&, uint4&) const` | — | 🔍 |
| L590 | `void JoinSpace::printRaw(ostream&, uintb) const` | — | 🔍 |
| L611 | `uintb JoinSpace::read(const string&, int4&) const` | — | 🔍 |
| L646 | `void JoinSpace::decode(Decoder&)` | — | 🔍 |
| L654 | `OverlaySpace::OverlaySpace(AddrSpaceManager*, const Translate*)` | — | 🔍 |
| L661 | `void OverlaySpace::decode(Decoder&)` | — | 🔍 |

**space.cc 统计**:32 函数,全部 🔍 待核对。

**注意**:Rudra 的 `AddressSpace` 是简化模型(枚举而非完整 AddrSpace 类),很多 Ghidra AddrSpace 方法可能 ➖(用替代实现)。核对时要判断每个方法是否在 Rudra 简化模型下有意义。
