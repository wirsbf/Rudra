# `space.rs` API Reference

**状态**: 接口描述可用；Ghidra 12.0.4 对齐级别 L2
**源代码路径**: `src/space.rs`

## 2026-09-22：SUBFLOW-SUBPIECE-WIDTH-0001 — Register addr_size 8→4

`AddressSpace::addr_size()` 的 Register 臂由 8 改为 4。依据：oracle
`Heritage::normalizeReadSize/normalizeWriteSize`（heritage.cc:393/445/466）以
`newConstant(addr.getAddrSize(), ...)` 构造 SUBPIECE 偏移常量，寄存器空间范围
（`in(0)=n:register:8:8`）的 oracle 投影输出为 `c:0:4`/`c:4:4` —— next_url 全语料
2668/2668 SUBPIECE 尾常量均为宽 4，证明 x86-64 oracle 的 register space
addressSize=4。原注释"ram/register/stack 按 x86-64 production 8/8/8 建模"对
register 是错误假设。`addr_size()` 全部 17 个消费方（heritage/funcdata/
coreaction/fspec/ruleaction/translate/constseq/pcodeparse/printc）随之取 4，
与 oracle `getAddrSize()` 语义一致；ADDRESS-0001（enum→registry per-spec
size）仍为后续正式载体。

## 2026-08-28：dead-code/heritage space flags

`does_deadcode` 现在按锁定构造器 flags 仅对 Const、Iop/FSPEC 投影和专用 OTHER
返回 false；Join 只关闭 heritage，仍参与 dead-code。专用 OTHER 使用固定 id/index，
自定义 `Other(id)` 不再被误当作 OTHER space。动态 AddrSpace manager/FSPEC 对象身份
仍是明确残差。

> 固定枚举尚不能保存 Ghidra 架构动态 space index/type/name/
> address-size/wordsize/endianness/flags；跨空间 Address/Varnode 键因此不完整。

## 模块说明 (Module Doc)

Address space definitions

This module corresponds to Ghidra's `space.hh` and defines the various
address spaces used in the decompiler.

# Address Spaces

Ghidra uses multiple address spaces to represent different types of storage:
- **RAM**: Normal memory
- **Register**: CPU registers
- **Unique**: Temporary/intermediate values (SSA temporaries)
- **Const**: Constant values
- **Stack**: Stack space
- **Other**: Custom/architecture-specific spaces

## 导出的公共 API (Public API)

### `pub type SpaceId = u8`

Address space identifier

### `pub const SPACEID_RAM: SpaceId = 0`

*暂无代码注释*

### `pub const SPACEID_REGISTER: SpaceId = 1`

*暂无代码注释*

### `pub const SPACEID_UNIQUE: SpaceId = 2`

*暂无代码注释*

### `pub const SPACEID_CONST: SpaceId = 3`

*暂无代码注释*

### `pub const SPACEID_STACK: SpaceId = 4`

*暂无代码注释*

### `pub const SPACEID_JOIN: SpaceId = 5`

*暂无代码注释*

### `pub const SPACEID_OVERLAY: SpaceId = 6`

*暂无代码注释*

### `pub enum AddressSpace`

Address space in which a varnode resides

Corresponds to Ghidra's AddrSpace hierarchy in `space.hh`

Ghidra uses multiple address spaces to represent different types of storage:
- RAM: Normal memory
- Register: CPU registers
- Unique: Temporary/intermediate values
- Const: Constant values
- Stack: Stack space
- Other: Custom address spaces

### `pub fn space_id(&self) -> SpaceId`

Get the space ID

### `pub fn from_id(id: SpaceId) -> Self`

Create from space ID

### `pub fn is_register(&self) -> bool`

Check if this is a register space

### `pub fn is_unique(&self) -> bool`

Check if this is a temporary/unique space

### `pub fn is_const(&self) -> bool`

Check if this is a constant space

### `pub fn is_ram(&self) -> bool`

Check if this is RAM space

### `pub fn is_stack(&self) -> bool`

Check if this is stack space

### `pub fn is_big_endian(&self) -> bool`

Check if this is a big-endian space

### `pub fn word_size(&self) -> usize`

Get the word size for this space (in bytes). Faithful to `AddrSpace::getWordSize`
(space.hh:340): every hardwired space is wordsize 1 (ConstantSpace space.cc:357,
OtherSpace space.cc:397, UniqueSpace space.cc:428, JoinSpace space.cc:447, IopSpace
op.cc:36) and the x86-64 spec spaces (ram/register/stack) are wordsize 1. Spec
spaces with wordsize>1 project only through the registry handle
(`AddrSpace::get_word_size`).

### `pub fn addr_size(&self) -> usize`

Get the address size for this space (in bytes). Faithful to
`AddrSpace::getAddrSize` (space.hh:348) over the constructors that build each
space kind: const/OTHER/iop = 8 (sizeof(uintb)/sizeof(void *), space.cc:357/397,
op.cc:36), unique = `UniqueSpace::SIZE` = 4 (space.cc:418/428), join =
sizeof(uintm) = 4 (types.h:27, space.cc:447); ram/register/stack/overlay carry
the architecture spec values, modeled with the x86-64 production sizes
(8/8/8; an overlay copies its base space, space.cc:670). Locked by
`tests/oracle/space_printraw_wordsize_1204` (SPACE-PRINTRAW-WORDSIZE-0001).

### `pub fn name(&self) -> &'static str`

Get the name of this space

### `pub struct ConstantSpace`

Constant space (for constant values)

Corresponds to Ghidra's `ConstantSpace` in space.hh

### `pub fn new() -> Self`

Create a new constant space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string

### `pub fn overlap_join(&self, _offset: u64, _size: usize) -> bool`

Check if this overlaps with a join space

### `pub fn print_raw(&self) -> String`

Print raw representation

### `pub struct UniqueSpace`

Unique space (for SSA temporaries)

Corresponds to Ghidra's `UniqueSpace` in space.hh

### `pub fn new() -> Self`

Create a new unique space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn allocate(&mut self, size: usize) -> u64`

Allocate a new unique offset

### `pub fn reset(&mut self)`

Reset the allocator

### `pub struct OtherSpace`

Other/custom address space

Corresponds to Ghidra's `OtherSpace` in space.hh

### `pub fn new(id: SpaceId, name: String) -> Self`

Create a new other space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn print_raw(&self) -> String`

Print raw representation

### `pub struct JoinSpace`

Join space (for combining multiple spaces)

Corresponds to Ghidra's `JoinSpace` in space.hh

### `pub struct JoinPiece`

A piece of a join

### `pub fn new(pieces: Vec<JoinPiece>) -> Self`

Create a new join space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn size(&self) -> usize`

Get the total size of the join

### `pub fn num_pieces(&self) -> usize`

Get the number of pieces

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format

### `pub fn decode_attributes(attrs: &[(&str, &str)]) -> Option<Self>`

Decode from attributes (XML-style)

### `pub fn encode_attributes(&self) -> Vec<(String, String)>`

Encode to attributes (XML-style)

### `pub fn overlap_join(&self, offset: u64, size: usize) -> bool`

Check if this overlaps with another join

### `pub fn print_raw(&self) -> String`

Print raw representation

### `pub fn read(&self, _offset: u64, _size: usize) -> Vec<u8>`

Read value from the joined pieces

### `pub struct OverlaySpace`

Overlay space (for overlaying another space)

Corresponds to Ghidra's `OverlaySpace` in space.hh

### `pub fn new(id: SpaceId, base_space: AddressSpace, name: String) -> Self`

Create a new overlay space

### `pub fn space(&self) -> AddressSpace`

Get the space type

### `pub fn base(&self) -> AddressSpace`

Get the base space

### `pub fn decode(s: &str) -> Option<Self>`

Decode from string format "id:base_space_id:name"


### 2026-07-01：Iop 地址空间（Ghidra IPTR_IOP）
- 新增 `AddressSpace::Iop` 变体 + `SPACEID_IOP=7` + `is_iop()`。Ghidra `IPTR_IOP`（space.hh:35）用于让 varnode 引用另一个 PcodeOp（INDIRECT creation 的 iop 输入）。是 `new_varnode_iop` + `get_op_from_const` 的前置。
<!-- annotation-pass: 2026-07-04 -->

<!-- sleigh-fix: 1783218732.6904683 -->
 

### 2026-07-05: AddressSpace delay/deadcodedelay/is_heritaged
- `get_delay`(space.hh): 锁定 x86-64 oracle 值（2026-09-22 RCA-2 修正）：ram=1、
  stack=**1**（architecture.cc:565 `addSpacebase` 合成为 `ptrdata.space->getDelay()+1`，
  ptrdata=栈指针寄存器（register 空间，delay 0，architecture.cc:1004
  `translate->getRegister`），**不是** basespace(ram)+1；SpacebaseSpace 将该 dl 同时
  作 delay/deadcodedelay 转发 AddrSpace，translate.cc:57-59）、unique/register=0
  （x86-64.sla space 表）。oracle HeritageInfo 实测 `stack delay=1`。
  - 历史 1（MAINDIFF-UNIQLEAK-0001，2026-08-25）：此前 Rugra 硬编码 Ram=0/Stack=1，
    ram 提前一个 pass 被 heritage 是真缺陷（已修正 ram=1）；但当时依据“oracle 首个
    stack pass 在 pass 2”把 Stack 拔到 2 是误读——该 pass 号按 mainloop 轮计数，
    恰对应 heritage delay=1。
  - 历史 2（RCA-2，2026-09-22）：Stack=2 使 stack 首次 heritage/占位符解析推迟一遍
    （freePlaceholderSlot→maxpass 翻转与 ActionActiveParam build 各晚 1 遍，oracle
    build@pass2 vs rugra build@pass3），并经 ParamList::calcDelay 抬高
    getMaxInputDelay（2 vs 1，initActiveInput 侧 maxdelay_in）。单行回改 1 即把
    maxdelay_in 与翻转相位同时拉回 oracle（充分性实验见
    /dev/shm/rugra-tests/sb-integration/RCA2_MAXPASS.md §4.3/§5）。
- `get_deadcode_delay`: = get_delay（SpacebaseSpace 构造 `dl, dl` 同源）。
- `is_heritaged`: Const/Iop/Join 不 heritaged。
 
 


### 2026-08-15：SPACE-0001 architecture-owned AddrSpace registry（Ghidra space.cc/translate.cc AddrSpaceManager）

固定枚举 `AddressSpace` 保留为过渡 adapter（消费方未迁移），新增 1:1 移植的架构动态注册表：

- `SpaceType`（space.hh:30 `spacetype`）：Constant/Processor/SpaceBase/Internal/Fspec/Iop/Join。
- `space_flags`（space.hh:85-98）：big_endian/heritaged/does_deadcode/…/has_nearpointers 共 12 位。
- `AddrSpace`（space.hh:82）：`Rc<RefCell<AddrSpaceInner>>` 共享句柄（Ghidra 裸指针 + refcount 语义），
  携带 type/name/index/addressSize/wordsize/flags/highest/pointerBounds/shortcut/delay/deadcodedelay/refcount
  与 SpacebaseState（contain/hasbaseregister/isNegativeStack/baseloc/baseOrig，translate.hh:173-178）。
  `None`（`Option<AddrSpace>`）对应 Ghidra null `AddrSpace*`（Address::Address() 的 invalid 态）。
- 派生空间构造器：`new_space`（space.cc:58 全参 ctor）、`new_constant_space`（space.cc:356）、
  `new_other_space`（space.cc:396，硬编码 index 1）、`new_unique_space`（space.cc:427）、
  `new_join_space`（space.cc:446）、`new_iop_space`（op.cc:33）、`new_fspec_space`（fspec.cc:2116）、
  `new_spacebase_space`（translate.cc:57）、`new_overlay_space`（space.cc:654/661 decode 体语义）。
- 访问器/算法：`calc_scale_mask`（space.cc:34）、`wrap_offset`（space.hh:383）、`truncate_space`（space.cc:105）、
  `set_flags`/`clear_flags`（space.hh:264/270）、谓词族（is_heritaged/does_deadcode/has_physical/…）、
  静态换算 `address_to_byte` 族（space.hh:514-543）、`compare_by_index`（space.hh:549）、
  `calc_mask`（address.hh:499/address.cc:633 表）。
- `SpaceRegistry`（translate.hh:220 AddrSpaceManager，resolver/join 半部仍留在 translate.rs 旧 manager）：
  `insert_space`（translate.cc:352，含逐类型校验/重复拒绝/baselist 部分增长/refcount）、
  `assign_shortcut`（translate.cc:517，碰撞推进 + >26 后 'z' 复用不更新表）、
  `get_space_by_name`/`get_space_by_shortcut`/`get_space`/`num_spaces`/`get_next_space_in_order`
  （空槽跳过 + 端哨兵）、`set_default_code_space`/`set_default_data_space`、`add_spacebase_pointer`
  （translate.cc:460 → setBaseRegister translate.cc:86，BE 截断偏移上移）、`copy_spaces`（translate.cc:443，
  共享句柄 refcount+1）、`set_deadcode_delay`/`truncate_space`/`mark_near_pointers`/`set_reverse_justified`/
  `set_infer_ptr_bounds`、缓存槽访问器族（get_constant_space 等，translate.hh:448-530）。
- 错误通道：`Result<_, String>` 携带 Ghidra LowlevelError 逐字消息（如
  "const space must be assigned index 0"、"Space X was assigned as id duplicating: Y"）。

Oracle 证据：`tests/oracle/space_registry_1204.{cc,rs}` + `tools/run_space_registry_oracle.sh`
（锁定 12.0.4 oracle，8 case 逐字节 MATCH）。未移植残留：per-space `read/printRaw/encode/decode`
属性编解码（MARSHAL/TRANSLATE 原子）、`resolveConstant` 与 join-record 半部（留在旧 enum manager，
待 ADDRESS-0001 统一切换）。

**2026-08-27 unsigned scale 边界**：`AddrSpace::address_to_byte`
（space.hh:514-516）的 `uintb * uint4` 是固定 64 位无符号模 2^64 运算；Rust
现显式使用 `wrapping_mul`，消除 debug/release overflow 差异。
`ptrsub_output_token_1204` 的 normal、wrap_zero、wrap_nonzero、max_product、
zero_wordsize 五条 scale projection 双侧 MATCH。该证据只覆盖 unsigned 静态
换算；`address_to_byte_int`、per-space decode/resolveConstant/join 与旧/新地址
模型迁移仍未覆盖，space 模块保持 L2。父级 24-record fixture 中 raw
ActionSetCasts `result=0,count=1` 与 selected ActionInferTypes canonical output
identity=1 现均为 MATCH；fixture overall 仍因 Rust-only count bridge `NO_ORACLE`
及完整 action/type 闭包的 MISMATCH/UNTESTED 而保持 MISMATCH。这不改变五条 scale
子投影的 MATCH 判定。

### 2026-08-15：ADDRESS-0001 配合新增（Ghidra space.cc printRaw/overlapJoin）

`AddrSpace` 句柄新增两方法（供 `SpaceAddress::print_raw`/`overlap_join` 派发）：

- `print_raw(offset)`（space.cc:206 `AddrSpace::printRaw`）：>4 字节空间对小 offset 收缩打印
  宽度（>>32==0 → 4 字节、>>48==0 → 6 字节），offset 经 `byteToAddress` 缩放到可编址单位后
  以 `setw(2*sz)` 补零 hex 打印，wordsize>1 且 off-cut 时追加 `+cut`（十进制）。
  `ConstantSpace::printRaw`（space.cc:372）与 `OtherSpace::printRaw`（space.cc:410）覆盖为
  无填充 hex —— 派发按 type==Constant / is_other_space 标志（仅生产 OTHER 置位）。
- `overlap_join(offset, size, point_space, point_off, point_skip)`（space.cc:126）：空间指针不等
  恒 -1；距离经 `wrapOffset` 环绕；`>= size` → -1。`ConstantSpace::overlapJoin`（space.cc:364）
  恒 -1；JoinSpace 覆盖需要 join-record 数据库（残差）。
- `identity_ptr()`（RUDRA-GLUE）：共享记录地址，供 Address/Range 的 Ord 身份 tiebreak，
  对应 Ghidra 裸指针比较。

Oracle 证据：`tests/oracle/address_space_handle_1204.{cc,rs}`（锁定 12.0.4，7 case 逐字节 MATCH，
printRaw 覆盖 const/ram/register 路径与 wordsize 换算）。SPACE-0001 残差中
`resolveConstant`/join-record 统一**未**在本 wave 完成（JoinDB 仍在 translate.rs 旧 manager），
登记为 ADDRESS 后继原子。

### 2026-08-17：SPACE-PRINTRAW-WORDSIZE-0001（Ghidra space.cc:206-222 + space.hh:348）

可达性复核结论：printRaw 的 wordsize>1 分支在当前 x86-64 生产闭包不可达
（x86-64.sla 的 ram/register 均 wordsize=1，硬编码空间 const/OTHER/unique/join/iop
亦 wordsize=1），但 registry `AddrSpace::print_raw` 的 wordsize>1 实现
（`byteToAddress` 缩放 + `+cut` 后缀）已在位；本轮以锁定 oracle fixture 逐字节验证。
legacy 平面枚举 `AddressSpace::addr_size()` 原恒 8，与 Ghidra 构造真值在
unique（`UniqueSpace::SIZE`=4，space.cc:418/428）与 join（sizeof(uintm)=4，types.h:27、
space.cc:447）分歧，本轮按构造器真值建模（const/OTHER/iop/overlay=8、unique/join=4、
x86-64 ram/register/stack=8）；受影响调用面（heritage.rs deadcode 警告宽度、
translate.rs `addr_mask_for`、pcodeparse.rs `addressOf` 的 unique 角落）随枚举修正
自动对齐，E2E C 输出零影响（流经空间 ram/register/stack/const 尺寸不变）。

Oracle 证据：`tests/oracle/space_printraw_wordsize_1204.{cc,rs}`（锁定 12.0.4，
5 case 61 行逐字节 MATCH：addrsize 投影 9 空间 + legacy 9 映射、wordsize 1/2/4
打印含收缩规则/`+cut` 后缀/setw 最小宽度语义、const/OTHER 覆盖）。
runner：`tools/run_space_printraw_wordsize_oracle.sh`。

残差（登记后续原子，不在本 TODO write-set）：
- `JoinSpace::printRaw`（space.cc:590）的花括号 pieces 形式未派发（需要 join-record
  数据库经 manager 解析，registry 句柄无 manager 回链）；
- `IopSpace::printRaw`（op.cc:41）的 op/block 信息形式未派发（需要 PcodeOp/BlockBasic
  下钻）；registry `print_raw` 对这两类空间走通用 hex 分支。
- `heritage.rs:1918` deadcode 警告内联复刻 printRaw 未含 wordsize>1 缩放/`+cut`
  （wordsize>1 空间在当前闭包不可达，触发前需迁移到 `space.print_raw` 调用）。

### 2026-08-17：SPACE-PRINTRAW-SPECIAL-0001（Ghidra space.cc:590-609 JoinSpace::printRaw + translate.cc:671-762 join 半部）

上一节登记的 JoinSpace/IopSpace printRaw 残差收尾（SPACE-PRINTRAW 集成 c484715 的
P3 残差）。registry 侧新增 Ghidra `AddrSpaceManager` join 半部的 1:1 对应物（模块
`space::manager_join`）：

- `manager_join::JoinRecord`（translate.hh:196）：pieces（`SpaceVarnodeData` 句柄，
  对应 Ghidra `VarnodeData.space: AddrSpace*`）+ unified；`less_than`（translate.cc:172
  `operator<`：先 unified.size，再 pieces 字典序——空间 index、offset、size 降序
  （pcoderaw.hh:64 `VarnodeData::operator<` 的 BIG sizes come first），短前缀更小）。
- `manager_join::JoinRecordTables`（translate.hh:233-235）：`join_allocate` +
  `split_set`（`operator<` 排序的去重面）+ `split_list`（按 unified.offset 升序的
  地址索引面）；`find_add_join`（translate.cc:671-715：四条逐字 LowlevelError 校验、
  逻辑尺寸/尺寸和、split_set 去重、16 字节对齐 roundsize 分配）与 `find_join`
  （translate.cc:746-762：split_list 二分，未命中 panic `"Unlinked join address"`）。
- `AddrSpaceInner.manager_join_tables`（space.hh:118 `AddrSpace::manage` 的 join 半）：
  `insert_space` 注册 Join 空间时接线（Rugra 构造器不收 manager，insertSpace 即关联
  点；校验前接线，与 Ghidra 构造即持有 manager 的可观察序一致）。`SpaceRegistry`
  持有共享表并提供 `find_add_join`/`find_join` 桥（translate.hh:270/271）。
- `AddrSpace::print_raw` 派发新增 `SpaceType::Join → print_raw_join`（space.cc:590）：
  `getManager()->findJoin` 解析 offset 回 pieces，逐 piece 调其自身空间的 printRaw
  （`vdat.space->printRaw(s,vdat.offset)`），逗号分隔花括号包裹；num==1（float
  extension）时循环累加的 `szsum` 被 `rec->getUnified().size`（逻辑尺寸）覆盖后以
  `:szsum` 追加（space.cc:604-606 的丢弃怪癖逐字保留）；未链接 offset 与未注册
  join 空间均映射为同一确定性 panic（Ghidra 的 null-manager 状态不可构造）。
- IopSpace 半侧（op.cc:41）：派发臂以残差注释形式在位（`SpaceType::Iop`），
  但两种终态形式都因 legacy 无空间地址模型阻塞：`SeqNum.addr`（非分支 SeqNum
  形式）与 `BlockBasic::start_addr`（block.rs，flow.rs:1918 赋标量形态）均是无
  空间句柄的 `Address(u64)`，`pc.printRaw` 的宽度/wordsize 缩放与
  `getShortcut()` 均不可导出。登记残差 `SPACE-IOP-PRINTRAW-0001`（阻塞链
  ADDRESS-0001；`src/address.rs` 现由 CSPEC-RANGEPROPS-0001 租约中），落地前
  派发臂内联回落 base printRaw 形式，且不引用 op.rs 侧未来落位函数
  （`op::IopSpace::print_raw`，同为残差 stub），保持 space.rs 独立编译、不破坏
  按旧 base 钉住仅 overlay space.rs 的既有 runner。

Oracle 证据：`tests/oracle/space_printraw_special_1204.{cc,rs}`（锁定 12.0.4，
3 case 11 行逐字节 MATCH：2-piece/3-piece/1-piece float-extension pieces 形式、
wordsize-2 piece 递归（缩放 + `+cut` 出现在花括号内）、findAddJoin 去重与
16 字节对齐分配序列 0x0/0x10/0x20/0x30/0x40、未链接地址 `Unlinked join address`
异常）。runner：`tools/run_space_printraw_special_oracle.sh`（base 102c476 +
space.rs/op.rs overlay）。IopSpace 形式按上述残差不在本 fixture 内。

### 2026-08-15：EXTERNAL-STUB-SUPPORT-0001 构造期 decode 注册（Ghidra translate.cc:254/281 + space.cc:87/304/339）

`AddrSpace` 句柄新增 decode 期构造与属性解码面，`SpaceRegistry` 新增（impl 于
`src/translate.rs`，因 marshal 常量在那侧）构造期注册入口：

- `new_for_decode(space_type)`（space.cc:87 部分构造器）：type + `heritaged|does_deadcode`
  起始 flags、wordsize 1、shortcut `' '`；name/size/index/delay 留空待
  `decode_basic_attributes` 填（C++ 未初始化成员的 Rust 零值对应）。
- `new_other_space_for_decode`（space.cc:403）/`new_unique_space_for_decode`（space.cc:433）/
  `new_spacebase_space_for_decode`（translate.cc:73，置 `programspecific`，contain 悬空至
  `set_contain`）/`new_overlay_space_for_decode`（space.cc:654，置 `overlay`）。
- `decode_basic_attributes(decoder)`（space.cc:304-337）：先重置 deadcodedelay=-1，遍历
  name/index/size/wordsize/bigendian/delay/deadcodedelay/physical 属性，缺省
  deadcodedelay=delay，末尾 `calcScaleMask`。
- `decode(decoder)`（space.cc:339 基类）：open → decodeBasicAttributes → close，服务于
  `<space>`/`<space_unique>`/`<space_other>`（三者无 decode 覆盖）。
- `set_contain(base)`（RUDRA-GLUE setter）：对应 C++ decode 体直接写
  `SpacebaseSpace::contain`/`OverlaySpace::baseSpace` 私有成员。
- `EXTERNAL_SPACE_NAME`（"EXTERNAL"）与 `new_external_space(ind, endian)`（RUDRA-GLUE）：
  12.0.4 decompiler `spacetype` **无** IPTR_EXTERNAL（space.hh:30-38 止于 IPTR_JOIN）、
  packed 协议拒编组 Java TYPE_EXTERNAL（PackedEncode.java:186）。EXTERNAL 工件在 Ghidra
  平台侧：Java `GenericAddressSpace("EXTERNAL", 32, TYPE_EXTERNAL, 0)`（AddressSpace.java:80）
  + ELF importer 在默认空间造人工 EXTERNAL 内存块（ElfProgramBuilder.java:1532-1556，
  0x1000 对齐 linkage 块、每 UND import 8 字节）。Rugra 按该 Java 定义构造（Processor 型、
  addrsize 4），供 registry 命名注册。

`src/translate.rs` 侧：

- `SpaceRegistry::decode_space(decoder)`（translate.cc:254-275）：element id 分派 → 部分构造器
  → decode；`<space_base>`/`<space_overlay>` 的 contain/base 引用按 `Decoder::readSpace`
  （marshal.cc:400-409）语义经 manager 名字解析，未知名 `Err("Unknown address space name: X")`。
- `SpaceRegistry::decode_spaces(decoder)`（translate.cc:281-303）：先插 ConstantSpace；读
  `<spaces defaultspace=...>`；逐子元素 decode+insert；按**名字**查默认空间（缺失
  `Err("Bad 'defaultspace' attribute: X")`）并 `set_default_code_space`。
- 新增 ATTRIB_NAME(14)/ATTRIB_INDEX(10)/ATTRIB_BASE(89) 常量（marshal.cc:1241/1237、
  space.cc:21）；decode 路径用运行时具名 `AttributeId`（const 版无法保留 name，见
  `named_attrib_id` RUDRA-GLUE）。

Oracle 证据：`tests/oracle/external_stub_1204.{cc,rs}` + `tools/run_external_stub_oracle.sh`
（锁定 12.0.4，7 case 逐字节 MATCH：canonical decodeSpaces 注册+defaultspace、overlay 标记
overlaybase、spacebase contain 解析、readSpace 未知名错误、bad defaultspace 错误、EXTERNAL
命名空间注册+重名拒绝、deadcodedelay 缺省=delay）。driver 侧 stub 投影（48 个
EXTERNAL-block import 的 `void free(void *__ptr)` halt_baddata 声明段）在
`examples/curl_decompile.rs`，由 124 语料端到端差分验证（EXTERNAL-stub 计数变化），不属本
fixture 范围。

### 2026-08-24：TYPEOP-FSPEC-SPACE-0001 切片1（Ghidra fspec.cc:2107-2171 / op.cc:24 / translate.cc:373 / space.cc:143-189）

fspec 空间接通为**真实 registry 空间**（此前 D0 只能以 Iop 地址 + typed Weak 暂存对象身份），
带完整的 print/encode/decode/lookup 行为与 C++ 指针解引用的 Rust 对应物：

- `FSPEC_SPACE_NAME`（"fspec"，fspec.cc:2107 `FspecSpace::NAME`）与 `IOP_SPACE_NAME`
  （"iop"，op.cc:24 `IopSpace::NAME`）保留名常量；`insert_space` 的 Fspec 分支
  （translate.cc:373-379）改用常量并**在校验前**接线 `fspec_table` 管理器回链（与 JoinSpace
  的 `manager_join_tables` 同一注入点语义，Ghidra 构造器自带 manager）。
- `FspecEntry` / `FspecEntryTable`（RUDRA-GLUE）：Ghidra 的 fspec offset **就是**
  `FuncCallSpecs *`（fspec.hh:344-346），printRaw/encodeAttributes 直接解引用
  （fspec.cc:2125）。Rust 以 registry 侧 offset→(name(fspec.hh:1647),
  entryaddress(fspec.hh:1648)) 侧表等价替代，经 `AddrSpaceInner.fspec_table` Weak 回链
  被空间读取。注册口 `SpaceRegistry::register_fspec_entry(offset, name, entry)`；未注册
  offset 的解引用在 C++ 是野指针 UB，Rust 按 unlinked-join 先例确定性 panic
  （"Unresolved fspec address"）。切片2 将把注册挪到 Funcdata callspec bank。
- `AddrSpace::encode_attributes` / `encode_attributes_with_size`（space.cc:143/156 基类）：
  基类写 space 名 + offset(+size)；IopSpace 覆盖只写 "iop" 丢 offset（op.hh:49-50）；
  FspecSpace 覆盖投影穿过 callspec（fspec.cc:2124-2151）——invalid entry 只写字面
  "fspec"（无 offset/size），valid entry 写**entry** 空间名 + entry offset(+size)，
  即编码形态永不携带 fspec offset 本身。JoinSpace piece 编组未移植（MARSHAL-XML-TEXT-0001，
  显式 panic 不静默错码）。
- `AddrSpace::decode_attributes(decoder, &mut size)`（space.cc:169-189）：按名取
  offset/size、跳过其余属性，缺 offset 返回 `Err("Address is missing offset")`；
  JoinSpace piece 解码未移植（MARSHAL-XML-TEXT-0001，显式 panic）。
- `print_raw` Fspec 分支（fspec.cc:2153-2164）：name 非空直印 name；否则
  "func_" + entry 空间自身 printRaw（invalid entry → `Address::printRaw` 的
  "invalid_addr"，address.hh:305-311）。
- `AddrSpace::decode` 四个 never-decode 守卫按 C++ 覆盖 panic：Constant
  （space.cc:380）、Fspec（fspec.cc:2166 "Should never decode fspec space from
  stream"）、Iop（op.cc:61）、Join（space.cc:646）。
- `attrib_space()/attrib_offset()/attrib_size()`（marshal.cc:1247/1243/1246 锁定 id
  20/16/19 的运行时具名 AttributeId；RUDRA-GLUE 模式同 translate.rs/pcodeparse.rs）。

Oracle 证据：`tests/oracle/fspec_space_identity_1204.{cc,rs}` +
`tools/run_fspec_space_identity_oracle.sh`（锁定 12.0.4，5 case 逐字节 MATCH：注册/查找/
shortcut 'f'/重复与错型拒绝（含 Ghidra insertSpace 抛出前替换 fspecspace 缓存槽的真实
行为）、同 offset CONST/STACK/FSPEC/IOP/JOIN 判别（==/</map 序/overlap/containedBy/
wraparound）、4 种 printRaw 形态、encode 投影（invalid→`space="fspec"` 且 decode 抛
"Address is missing offset"；valid→entry 空间+offset 且 decode 结果≠原地址）+ 按名
resolve + 未知名/空 `<addr/>` 拒绝路径、Range 跨空间 contains/overlapJoin、fspec/iop
never-decode 守卫）。残留（coverage 表 UNTESTED）：PackedEncode::writeSpace 特殊空间字节
与 PackedDecode readSpace 拒绝（MARSHAL-XML-TEXT-0001）、IopSpace::printRaw
（SPACE-IOP-PRINTRAW-0001）、varnode/funcdata 消费侧迁移（本 TODO 切片2）。

### 2026-08-24：MARSHAL-XML-TEXT-0001（Ghidra space.cc:502-531/539-588 JoinSpace piece 编解码）

R5 复核登记的两项残差落地（fixture `tests/oracle/marshal_packed_join_1204.*`）：

- `AddrSpace::encode_attributes` / `encode_attributes_with_size` 的 Join 分支不再
  panic：`encode_attributes_join`（space.cc:502-519）= `getManager()->findJoin(offset)`
  （"Record must already exist" 契约；unlinked → `LowlevelError("Unlinked join
  address")` panic）→ `writeSpace(ATTRIB_SPACE, this)`（经 Encoder 虚分派，
  XML 写名/packed 写 0x61 特殊字节）→ 每片（最显著在前）写
  `writeStringIndexed(ATTRIB_PIECE, i, "{name}:0x{off:x}:{size}")`（hex 操纵子
  印 offset、dec 还原印 size）→ piece 数 > MAX_PIECES(=64, space.hh:233) 抛
  "Exceeded maximum pieces in one join address" → 单片 join 追加
  ATTRIB_LOGICALSIZE=unified.size。3-arg 形态忽略 size 直接委托（space.cc:527-531）。
- 基类路径与 fspec valid-entry 路径的 `writeString(space名)` 全部换成
  `encoder.write_space(...)`（space.cc:146 / fspec.cc:2130 的 writeSpace 虚调用；
  Iop 两形态仍写字面量 "iop" 字符串，op.hh:49-50 原文如此）。
- `AddrSpace::decode_attributes(decoder, spc_manager, &mut size)` 新增
  `spc_manager: &SpaceRegistry` 参数（Ghidra 的空间经 `getManager()`（space.hh:118）
  自持 manager；Rust 空间只带 join 表反链，故按调用显式传同一对象）。Join 分支
  `decode_attributes_join`（space.cc:539-588）：属性 id 游标循环——ATTRIB_LOGICALSIZE
  (id 92)→`readUnsignedInteger` 存 logicalsize；ATTRIB_UNKNOWN→
  `getIndexedAttributeId(ATTRIB_PIECE)` 重释（XML 名后缀 1-based；packed 恒
  UNKNOWN 因 header 已带 94+i）；id < 94 跳过；pos = id-94，pos > 64 跳过（不读
  值）；pieces 按 pos 增长就位（洞留零片）；片串无 `:` = 寄存器名形态（SPACE-0001
  残差，显式 Err）；一 `:` 恰好 = `{空间名}:{offset}:{size}`，缺第二个 `:` 抛
  "join address piece attribute is malformed"，数字经 `cpp_stream_unsigned`
  流式自动进制；末尾 `findAddJoin(pieces, logicalsize)`（dedup 命中返回原
  unified offset）+ size 出参=unified.size。
- `attrib_logicalsize()/attrib_piece()`（space.cc:24/30 锁定 id 92/94）与
  `MAX_PIECES = 64`（space.hh:233）新增。

Oracle 证据：`tests/oracle/marshal_packed_join_1204.{cc,rs}` +
`tools/run_marshal_packed_join_oracle.sh`（锁定 12.0.4，packed 特殊空间字节/
readSpace 拒绝路径/packed+XML 双形态 join 往返/边界（unlinked、malformed、
超限 piece、dedup、float 扩展 logicalsize）逐字节 MATCH）。残留（coverage 表
UNTESTED）：寄存器名 piece 形态（SPACE-0001）、未知名 piece 空间的 C++ null-space
UB-邻接行为（Rust 在查名点拒绝）。

## `get_index` / `from_index` / `spec_space_name`（MAIN-POSTSTRUCT-SPIN-0001，2026-08-27）

- `pub fn get_index`（Ghidra: space.hh:332 `AddrSpace::getIndex` 内联）：
  锁定 x86-64 语料空间表索引。来源：translator `.sla` `<spaces>` 序
  （const=0, OTHER=1, unique=2, ram=3, register=4，活翻译器
  `SleighCtx::space_info` 探测）+ `Architecture::restoreFromSpec` 追加
  fspec=5/iop=6/join=7（architecture.cc:632-634）+ `addSpacebase` 追加
  stack=8（architecture.cc:1013→566-568）。消费者：
  `Override::insertDeadcodeDelay`/`hasDeadcodeDelay`（override.cc:79-105）
  与 `Heritage::getInfo`（heritage.hh:257）。Overlay 无实例存储报告 -1
  （语料内无 deadcode/heritage 消费者接受 Overlay，洞不可观测）。
- `pub fn from_index`（RUDRA-GLUE）：`AddrSpaceManager::getSpace(i)`
  （translate.hh:559-561）的逆查替身，`Funcdata::start_processing` 用其把
  `Override::applyDeadCodeDelay` 的索引项解析回空间。索引 5（fspec）无枚举
  变体；`bumpDeadcodeDelay` 的种类门保证 fspec 永远装不上 override，洞
  不可观测。
- `pub fn spec_space_name`（RUDRA-GLUE）：按索引给空间名
  （override.cc:51-56 消息路径用 `getSpace(i)->getName()`；SLEIGH `.sla`
  名为大写 "OTHER"，与 `AddressSpace::name` 的小写 debug 形态不同）。

## `from_spec_name`（TRUNCSPACE-COREACT2-R2-0001，2026-09-27）

- `pub fn from_spec_name(name: &str) -> Option<AddressSpace>`（RUDRA-GLUE）：
  `AddrSpaceManager::getSpaceByName`（translate.cc:590-597）的枚举模型反表——
  活跃 translator 空间表中的锁定 spec 名（`spec_space_name` 的逆）解析为枚举
  变体。"fspec" 无枚举变体（fspec 空间经 `SPACEID_*` 句柄到达）、动态/overlay
  名模型未知 → `None`（Ghidra: null）。消费端：`Architecture::truncate_space`
  （translate.cc:776-783 按名截断命令的未知名 LowlevelError 判定）。截断空间
  管道其余件（`AddrSpace::truncate_space` space.cc:105-112、
  `SpaceRegistry::truncate_space`、`get_spacebase`/`get_spacebase_full`
  translate.cc:110-124）在本车道前已 1:1。

## `JoinDatabase::find_add_join`（SQLCENSUS-STACKSLOT-GROUP-0001 第一波，2026-09-28）

- `pub fn find_add_join(&mut self, pieces: Vec<VarnodeData>) -> u64`：
  `AddrSpaceManager::findAddJoin`（translate.cc:671-715）的忠实枚举空间孪生 —
  按片序列（space/offset/size）dedup 命中即返回既有 `unified.offset`；
  否则 `roundsize = (totalsize + 15) & ~0xf` 逐 16 字节槽推进
  `join_allocate` 计数器（translate.hh:233）分配 join 空间 offset 并登记
  记录。旧行为（`add_join` 以 records.len() 为 offset、无 dedup、无粒度）
  保留为委托别名。Ghidra 的 splitset 有序去重在oracle 侧只用于身份查询
  （不迭代），线性等值扫描观察等价；splitlist 的 offset 分配序
  （消费方 find_join 所见）与创建序一致，双侧同构。
- 双侧证据（sqlite3_vmprintf，oracle fixture oracle_probe_834 @
  ghidra 12.0.4 e40ed130）：oracle 的 RDX:RAX 双 trial 输出 join whole
  位于 join:0x0（首个 findAddJoin 分配），16 字节粒度推进；修复后
  Rugra 的 11 处 CALL join 全部 dedup 到同一 join:0x0 地址。
