# `address.rs` API Reference

**状态**: 接口描述可用；Ghidra 12.0.4 对齐级别 L2
**源代码路径**: `src/address.rs`

> 2026-08-11 锁定审计：当前仅保存数值 offset，无法表达
> AddrSpace 身份、架构宽度/字宽环绕仍未表达。SeqNum 的不可变
> `(Address,time)` 身份与可变 block `order` 已于 2026-08-13 分离，并由
> 锁定 12.0.4 fixture 验证 block 重排不会破坏集合身份。
> 详见 `docs/alignment_audit/CORE_FOUNDATIONS_2026-08-11.md`。
>
> 2026-08-12 ANN-N 仅补 provenance：标量 `new` 是缺少 AddrSpace 参数的
> Rust 兼容层胶水；`as_u64` 对应锁定 oracle 的 inline `Address::getOffset`。
> 本次未改变行为或模块状态。
>
> 2026-08-17 ADDRESS-0001 阶段一：`Address` 增 `space: Option<SpaceTag>`
> 兼容字段（intern 线程域 tag → 强句柄表），保持 `Copy` 因此 55 个消费
> 文件零改动。比较链按 address.hh:356/375 重写：`Eq`=(tag,offset)、
> `Ord`=None 先行（≡null-base，address.hh:377）→space index（:389）→
> offset（:391）→tag tiebreak；`Hash` 随 `Eq`。None↔None 保持 offset-only
> （现存铸造点全部产出 None，行为零变化，E2E stdout 逐字节相同）；`Some`
> 时 `offset/next/prev` 经 `wrapOffset`（address.hh:423/433）、`overlap`
> 启用同空间+constant 排除+wrap（address.cc:153-165）。新桥接
> `with_space/get_space/from_space_address/to_space_address` 与
> `is_invalid`（address.hh:285 null-base 镜像）。分阶段路线与消费面清单见
> `docs/alignment_docs/ADDRESS_SPACE_PHASES.md`。模块保持 L2
> （consumer 迁移未做，双侧 fixture `address_space_phase1_1204` 覆盖
> 比较语义投影：None 兼容回退/空间序/tag 身份/wrap+overlap）。

## 模块说明 (Module Doc)

Address representation and manipulation

This module corresponds to Ghidra's `address.hh` and provides core address
types used throughout the decompiler.

# Core Types

- [`Address`] - A memory address in a specific address space
- [`SeqNum`] - P-code operation key with immutable `(Address, time)` identity and
  a separately mutable basic-block execution order
- [`Range`] - An address range (first, last)
- [`RangeList`] - A collection of non-overlapping address ranges

## 导出的公共 API (Public API)

### `pub struct Address { offset: u64, space: Option<SpaceTag> }`

Memory address type（ADDRESS-0001 阶段一形态）

Represents a virtual memory address in the target binary: an offset plus an
optional interned address-space tag mirroring Ghidra's `AddrSpace *base`
(address.hh:61). The transitional `None` form is the legacy spaceless
address; it orders before every tagged space (Ghidra null-`base` rule,
address.hh:377) and equals only another `None` with the same offset.

Corresponds to Ghidra's `Address` class in `address.hh`

### `pub struct SpaceTag(NonZeroU32)`

Copyable interned identity of an `AddrSpace` handle（阶段一过渡 adapter；
Ghidra 存裸指针）。tag 相等 ⟺ 同一 `AddrSpace` 分配（指针身份）。表为
thread-local（`AddrSpace` 是 `Rc<RefCell>` 单线程句柄，SPACE-0001 残差）。

### `pub const fn new(addr: u64) -> Self`

Create a new address（legacy spaceless form, `space = None`）

### `pub fn with_space(spc: &AddrSpace, off: u64) -> Self`

Create a space-carrying address（对应 address.hh:270 inline
`Address(AddrSpace *id,uintb off)`；space 经 intern 表换取 Copy tag）

### `pub fn get_space(&self) -> Option<AddrSpace>`

The address space handle, or `None` for a legacy spaceless address
（对应 address.hh:323 `getSpace`，NULL-if-invalid）

### `pub fn from_space_address(sa: &SpaceAddress) -> Self`

Bridge from the space-carrying `SpaceAddress`：real space→tagged，null
base→legacy `None`（保持 offset）。`m_maximal` 哨兵 panic——legacy 无极值
形态，静默映射会将其排序从最后翻到最前。

### `pub fn to_space_address(&self) -> SpaceAddress`

Bridge to `SpaceAddress`：tagged→`SpaceAddress::new`，`None`→
`from_offset`（null base/invalid，同 offset）。

### `pub const fn as_u64(&self) -> u64`

Get the raw address value

### `pub fn offset(&self, offset: i64) -> Self`

Add an offset to the address（address.hh:423 `operator+`：tagged 经空间
`wrapOffset` 环绕；legacy plain-wrap 保持阶段一前行为）

### `pub fn overlap(&self, skip: i64, op: Address, size: i32) -> i32`

If `self + skip` falls in `[op, op+size)` return the relative offset else
-1（address.cc:153-165：双侧 tagged 时同空间必需、constant 排除、wrap
距离；legacy 参与者保持 offset-only 行为）

### `pub fn is_invalid(&self) -> bool`

Is this a Ghidra-invalid (null-`base`) address（address.hh:285）。For the
legacy type that is exactly the spaceless form: every pre-existing
construction site mints Ghidra-invalid addresses; `to_space_address` maps
`None` to the null-base `SpaceAddress::from_offset`.

### `pub fn is_null(&self) -> bool`

Check if address is null (0x0)

### `pub fn is_aligned(&self, alignment: u64) -> bool`

Check if address is aligned to the given boundary

### `pub fn next(&self) -> Self`

Get the next address

### `pub fn prev(&self) -> Self`

Get the previous address

### `pub struct SeqNum`

Sequence number for P-code operations within a single instruction

When a machine instruction translates to multiple P-code ops,
they are numbered sequentially using SeqNum.

Corresponds to Ghidra's `SeqNum` class in `address.hh`

### `pub fn new(addr: Address, time: u32) -> Self`

Create a sequence number with immutable creation time. `order` is
deterministically initialized to `time` until block insertion assigns it.

### `pub fn next(&self) -> Self`

Get the next sequence number at the same address

### `pub fn get_addr(&self) -> Address`

Get the address

### `pub fn get_time(&self) -> u32`

Get the immutable operation creation identity used by Eq/Ord/Hash and bank lookup.

### `pub fn same_identity(&self, other: &Self) -> bool`

Exact Ghidra `SeqNum::operator==` semantic: compare only globally unique
`time`, even when addresses differ. Rust `Eq` instead follows `(Address,time)`
so it remains consistent with `Ord`/`Hash`; ordered bank keys match Ghidra's
`operator<`.

### `pub fn get_order(&self) -> u32`

Get the mutable execution order inside a basic block.

### `pub fn set_order(&mut self, order: u32)`

Set block execution order without changing identity.

### `pub fn decode(s: &str) -> Option<Self>`

Decode identity from string format "addr:time".

### `pub fn encode(&self) -> String`

Encode identity as "addr:time"; mutable block order is omitted.

Ghidra's copy constructor copies only Address/time and leaves `order`
uninitialized; Rust `Copy` necessarily copies all fields. The mapped
`PcodeOpBank::create_seq` path constructs a fresh op from the copied SeqNum,
so copied-order observability remains explicitly `MISMATCH` outside that path.

### `pub struct Range`

Address range (inclusive first and last addresses)

Corresponds to Ghidra's `Range` class in `address.hh`

### `pub fn new(first: Address, last: Address) -> Option<Self>`

Create a new range

Returns `None` if first > last

### `pub fn get_first(&self) -> Address`

Get the first address

### `pub fn get_last(&self) -> Address`

Get the last address

### `pub fn get_first_addr(&self) -> Address`

Get the first address (Ghidra naming)

### `pub fn get_last_addr(&self) -> Address`

Get the last address (Ghidra naming)

### `pub fn get_last_addr_open(&self) -> Address`

Get the last address + 1 (open end)

### `pub fn contains(&self, addr: Address) -> bool`

Check if an address is contained in this range

### `pub fn size(&self) -> u64`

Get the size of the range in bytes

### `pub fn overlaps(&self, other: &Range) -> bool`

Check if this range overlaps with another

### `pub fn is_adjacent(&self, other: &Range) -> bool`

Check if this range is adjacent to another

### `pub fn print_bounds(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result`

Print bounds (for debugging)

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format "first-last"

### `pub fn decode_from_attributes(first: &str, last: &str) -> Option<Self>`

Decode from attributes (XML-style)

### `pub fn encode(&self) -> String`

Encode to string format "first-last"

### `pub struct RangeProperties`

Partially parsed `<range>` / `<register>` state used before dynamic address
spaces and register storage are available. The public projection contains
`space_name`, `first`, `last`, `is_register`, and `seen_last`.

Corresponds to Ghidra's `RangeProperties` in `address.hh:215-225`.

### `pub fn new() -> Self`

Create empty properties with an empty space name, zero endpoints, and both
booleans clear.

### `pub fn decode(&mut self, decoder: &mut dyn Decoder) -> anyhow::Result<()>`

Open the next element, require locked element ID 12 (`range`) or 14
(`register`), then traverse attributes in source order. Locked attribute IDs
20/27/28/14 update `space_name`/`first`/`last`/register name respectively;
unknown attributes are ignored without stopping traversal. `seen_last` is set
only after `last` is read and `is_register` only after `name` is read.

The method intentionally preserves pre-existing fields, applies mutations in
place, does not roll them back on error, and closes the element without
traversing its children. This mirrors `RangeProperties::decode` rather than
performing dynamic `AddrSpace` or register resolution; that application step
remains dependent on the address-space foundation.

### `pub struct RangeList`

List of non-overlapping address ranges

Corresponds to Ghidra's `RangeList` class in `address.hh`

### `pub fn new() -> Self`

Create a new empty range list

### `pub fn insert_range(&mut self, new_range: Range)`

Insert a range into the list, merging overlapping ranges

### `pub fn remove_range(&mut self, to_remove: Range)`

Remove a range from the list

### `pub fn in_range(&self, addr: Address) -> bool`

Check if an address is in any range in the list

### `pub fn num_ranges(&self) -> usize`

Get the number of ranges in the list

### `pub fn empty(&self) -> bool`

Check if the list is empty

### `pub fn ranges(&self) -> &[Range]`

Get all ranges

### `pub fn begin(&self) -> std::slice::Iter<'_, Range>`

Get iterator to beginning

### `pub fn end(&self) -> std::slice::Iter<'_, Range>`

Get iterator to end

### `pub fn merge(&mut self, other: &RangeList)`

Merge another RangeList into this one

### `pub fn clear(&mut self)`

Clear all ranges

### `pub fn longest_fit(&self, addr: Address) -> Option<&Range>`

Find the longest fit for an address

### `pub fn print_bounds(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result`

Print bounds of all ranges

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format (comma-separated ranges)

### `pub fn encode(&self) -> String`

Encode to string format (comma-separated ranges)


## 2026-06-26：bit 助手（address.cc:641-745）

新增与 Ghidra 一致的位级自由函数（解锁 RuleSlessToLess/RuleDoubleShift 等）：
- `signbit_negative(val, size)` — address.cc:641，符号位是否置位（负）
- `calc_mask(size)` — address.hh:577，给定字节数的全1掩码
- `leastsigbit_set(val)` — address.cc:714，最低有效位置位索引（-1 若 0）
- `mostsigbit_set(val)` — address.cc:735，最高有效位置位索引

测试：address::tests +4。

## 2026-06-26（续）：functional_equality

- `functional_equality(vn1, vn2) -> bool`（expression.cc:520, level-0:404）：判断两 varnode 是否持相同值（同指针或同常量）。深层 functionalEqualityLevel 待补。解锁 RuleEquality。

## 2026-06-27：coveringmask / minimalmask

- `coveringmask(val: u64) -> u64`（address.cc:760）：返回覆盖 val 所有置位位的掩码 = `(1 << (msb+1)) - 1`。val==0 返回 0。解锁 JumpBasic::get_max_value（INT_AND 掩码分析）。
- `minimalmask(val: u64) -> u64`：coveringmask 别名，匹配 jumptable.cc 的 minimalmask 用法。

### 2026-09-22（sb-foldinnorm）：minimalmask 修正为真身

- 上述"coveringmask 别名"为误植（CR-CH 条件③暴露）。Ghidra `minimalmask`（address.hh:525-534 inline，
  非 address.cc 的 coveringmask）是**整字节掩码阶梯选择器**：val>0xffffffff→~0；val>0xffff→0xffffffff；
  val>0xff→0xffff；否则 0xff。与 coveringmask 系统性不同（minimalmask ≥ coveringmask 恒成立：
  minimalmask(0x7ff)=0xffff vs coveringmask(0x7ff)=0x7ff；minimalmask(0)=0xff vs coveringmask(0)=0）。
- 已改为 1:1 移植地址阶梯；三个消费方语义随之修正（调用点本身早已正确）：
  - `ActionDeadCode::mark_consumed_parameters`（coreaction.rs:447，cc:3856）：未锁定原型的 CALL 入参
    consume 从 nzmask 的覆盖幂掩码改为整字节掩码（consumed 变大 → 参数位截断/清零面收窄）；
  - `ActionDeadCode::gather_consumed_return`（coreaction.rs:470，cc:3884）：RETURN 值 consume 同上；
  - `JumpTable::fold_in_normalization` 的 `switch_var_consume`（jumptable.rs:5014，cc:2581）：
    switch 变量 consumed 位升为整字节 → ActionDeadCode BRANCHIND 臂（coreaction.rs:629）对
    switch 变量的截断/清零与 oracle 对齐。
- 单测 `test_minimalmask` 改钉阶梯边界（0/0xff/0x100/0xffff/0x10000/0xffffffff/0x1_0000_0000）。


### 2026-06-27（会话2 续）：count_leading_zeros

- `count_leading_zeros(val) -> i32` — `count_leading_zeros`（address.cc:773）：64 位前导零计数，val==0 返回 64。用 Rust `leading_zeros` 精确等价。被 RuleDivOpt::findForm 用于计算 numerand 的有效位数（xsize = 64 - clz(nz_mask)）。
<!-- annotation-pass: 2026-07-04 -->
 

### 2026-08-15：ADDRESS-0001 space-aware Address/Range/RangeList（Ghidra address.hh/address.cc）

旧标量 `Address(u64)`/`Range`/`RangeList` 保留为 offset-only adapter（varnode.rs/funcdata.rs 等
39 个消费方按 VARNODE-0001/FUNCDATA wave 顺序后继切换），新增携带 `Option<AddrSpace>` 句柄的
1:1 移植（`SpaceBase` 三态枚举 = Ghidra 裸 `AddrSpace *base`：null/真实空间/`~0` m_maximal 哨兵）：

- `SpaceAddress`（address.hh:59）：
  - 构造族：`invalid()`（address.hh:263，base=null、offset 规范化为 0）、`minimal()`（address.cc:91
    m_minimal，与 invalid 同位）、`maximal()`（address.cc:99 `~0` 哨兵 + offset `~0`）、
    `new(spc, off)`（address.hh:270）、`from_offset`（legacy 桥；无空间即 invalid —— **`ram:0`
    不再等同 null**）。
  - 判定：`is_invalid`（address.hh:285，仅 null 为 invalid，maximal 不算）、`is_constant`/
    `is_join`（address.hh:455/461）、`is_big_endian`（address.hh:298）、`get_addr_size`
    （address.hh:292）、`get_space`（address.hh:323，maximal 返回 None —— Ghidra 返回不可解引用
    的 `~0` 伪指针）、`get_offset`（address.hh:329）、`get_shortcut`（address.hh:336）。
  - 比较：`PartialEq`/`Ord` 按 address.hh:356/375-393 逐分支移植（base 指针相等才比 offset；
    不同空间按 space index；null 最小、`~0` 哨兵最大；同 index 不同对象的 Rc 身份 tiebreak 保持
    Ord/Eq 契约）。`Hash` 与 `==` 一致。
  - 算术：`add`/`sub`（address.hh:423/433，offset 经真实空间 `wrap_offset`（space.hh:383）按
    addrsize/wordsize 环绕；invalid/maximal 上 Ghidra 解引用非空间为 UB，Rust 防御性 plain-wrap）。
  - 包含/重叠：`contained_by`（address.cc:110）、`justified_contain`（address.cc:131，BE 从最高
    字节起算 `off1-off2`，`forceleft` 强制 LE；uintb 差经 int4 截断）、`overlap`（address.cc:153，
    同空间 + 非 const + `wrapOffset` 环绕距离）、`overlap_join`（address.hh:445 → space.cc:126
    `AddrSpace::overlapJoin`，ConstantSpace 恒 -1）、`is_contiguous`（address.cc:173，BE/LE 方向）。
  - 打印：`print_raw`（address.hh:305，invalid → "invalid_addr"，否则 space `print_raw`
    space.cc:206）、`Display` = operator<<。
- `SpaceRange`（address.hh:173）：`new`（address.hh:185，无校验）、`from_properties`
  （address.cc:236 非寄存器路径：`Undefined space: X` / `Illegal range tag` 逐字；寄存器名解析依赖
  Translate register 表 = SPACE-0001 残差，显式报错不绕过）、`get_first_addr`/`get_last_addr`/
  `get_last_addr_open`（address.cc:265，**忠实保留 Ghidra quirk**：末空间之后
  `getNextSpaceInOrder` 返回 `~0` 哨兵而该函数只查 null，故结果 = maximal-base + offset 0，
  非 `m_maximal`）、`contains`（address.hh:490，空间指针不等即 false）、`print_bounds`
  （address.cc:283，`ram: 7f-9c`）、`Ord`（address.hh:202，index→first）。
- `SpaceRangeList`（address.hh:232，`Vec` 保持 `set<Range>` 序）：`insert_range`（address.cc:383，
  **仅合并严格重叠**，相邻不合并，绝不跨空间误并）、`remove_range`（address.cc:417，头/尾分裂
  重插）、`merge`（address.cc:451）、`in_range`（address.cc:468，invalid 恒 true）、`get_range`
  （address.cc:491）、`longest_fit`（address.cc:512，同空间链式累计）、`get_first_range`/
  `get_last_range`/`get_last_signed_range`（address.cc:540/548/562，最高位置符号中点二分）、
  `print_bounds`（address.cc:588，空表输出 "all"）。

Oracle 证据：`tests/oracle/address_space_handle_1204.{cc,rs}` + 
`tools/run_address_space_handle_oracle.sh`（锁定 12.0.4 oracle，7 case 逐字节 MATCH，含
getLastAddrOpen 末空间 quirk 与 wrap/justified/跨空间排序/RangeProperties 错误路径）。
未移植残留（2026-08-24 更新：`SpaceAddress::encode/decode` 已随 TYPEOP-FSPEC-SPACE-0001
切片1以 tree/XML 属性编解码形态落地，见下节）：`Address::read`（绑 MARSHAL-XML-TEXT-0001）、`renormalize` 与
join-record/`resolveConstant` 统一（JoinDB 未入 SpaceRegistry，留给 resolver/join 后继原子）、
SeqNum 空间化（随 varnode 消费方迁移）。

### 2026-08-24：TYPEOP-FSPEC-SPACE-0001 切片1（Ghidra address.cc:25/205/226 + address.hh:469-486 + pcoderaw.cc:107-130）

`SpaceAddress` 补齐编解码面（此前的 encode/decode 残差由本切片以 tree/XML 属性编解码
形态落地；`Address::read` 仍留 MARSHAL-XML-TEXT-0001）：

- `elem_addr()`（address.cc:25 `ELEM_ADDR = ElementId("addr",11)`）：`<addr>` 元素 id
  构造器（RUDRA-GLUE 模式同 pcodeparse.rs 的重复声明）。
- `SpaceAddress::encode(encoder)` / `encode_with_size(encoder, size)`
  （address.hh:469-486）：open `<addr>` → 非空 base 委托空间的
  `encode_attributes`/`encode_attributes_with_size`（space.cc:143/156）→ close；
  null base 不写属性（m_maximal 哨兵在 C++ 解引用 `~0` 伪指针为 UB，Rust 同样不写）。
- `SpaceAddress::decode(decoder, registry)` / `decode_with_size`（address.cc:205/226 经
  pcoderaw.cc:33 `VarnodeData::decodeFromAttributes`；S1 修正：该函数定义在 :33，
  rewind :44、重走 :45）：属性游标找 `space` →
  registry 按名解析（`XmlDecode::readSpace`/marshal.cc:400-409 语义，未知名
  `Err("Unknown address space name: X")`）→ `rewind_attributes` → 空间的
  `decode_attributes(decoder, registry, size)`（space.cc:169；2026-08-24 起签名带
  registry，Join piece 解码需 `getManager()->getSpaceByName`，MARSHAL-XML-TEXT-0001）
  重走属性取 offset（缺 offset
  `Err("Address is missing offset")`）；`name`（寄存器形）依赖 Translate register 表
  （SPACE-0001 残差）显式报错；无 `space` 属性的 `<addr/>` 得 invalid 地址（C++ 的
  offset 未初始化在 Rust 规范化为 0）。

Oracle 证据：与 space.md 同一条目——`tests/oracle/fspec_space_identity_1204.{cc,rs}` +
`tools/run_fspec_space_identity_oracle.sh`（5 case 逐字节 MATCH，encode/decode case 覆盖
fspec invalid/valid-entry 投影、ram 自往返、按名 resolve、未知名与空 `<addr/>` 路径）。
2026-08-24 起 Join 编解码另见 `tests/oracle/marshal_packed_join_1204.*`
（MARSHAL-XML-TEXT-0001）。
<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
