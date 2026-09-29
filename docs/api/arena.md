# `arena.rs` — Arena Core API

**源代码路径**: `src/arena.rs`

**设计权威**: `docs/alignment_docs/ARENA_DESIGN.md`（§1-§2、§8 红线八条）。
本文档同时是 **W0 出口 API 冻结记录**（票 `PERF-ARENA-CORE-0001`，campaign
`PERF-ARENA-MIGRATION-0001`）：下列公开面即 W1 类型翻转车道（`PERF-ARENA-FLIP-0001`）
的 codemod 目标；冻结后任何签名/语义变更需 campaign 总票升级评审。

**Ghidra 对照**: 本模块为 Rust 容器基础设施，oracle 无 1:1 文件对应物——它重建的是
oracle 的**对象图形态**（`new` 分配 + 裸指针交叉引用 + Funcdata 属主 + bank 里的
`std::list`/`std::map` 结构），引用锚点：

- `op.hh:289` `PcodeOpBank`（7 条 `list<PcodeOp*>`：deadlist/alivelist/storelist/
  loadlist/returnlist/useroplist/deadandgone）
- `op.hh:127-129` `PcodeOp` 的三个存储迭代器（basiciter/insertiter/codeiter——
  O(1) erase 的机制本体）
- `op.cc:941/989/1017/1028/1039/1056` `PcodeOpBank::create/destroy/markAlive/
  markDead/insertAfterDead/moveSequenceDead`（生命周期与链手术原语）
- `varnode.hh:365` `VarnodeBank`（两棵排序树，无 alive/dead 列表——与 op 不同）
- `varnode.cc:34-79` `VarnodeCompareLocDef` / `VarnodeCompareDefLoc`（树比较器逐字段）
- `address.hh:154/375` `SeqNum::operator<` / `Address::operator<`（键序投影源）
- `varnode.hh:149` `Varnode::descend`（显式维护的读者表，R4 纪律）

## 文档状态

- **状态**: 已核对（当前有效，W0 交付时点）
- **可信度**: 高（序语义经 oracle 对照差分 fuzz 单测锁定，见下）
- **适用范围**: 通用 arena 机制层。OpArena/VnArena/BlockArena 的**领域字段**
  （OpData/VnData/BlockData）属 W1 容器层，不在本文件

---

## 红线（实现已内建，评审必读）

1. **槽物理序不进任何 API**。`Arena` 无任何迭代方法；`slots`/`gens` 私有。
   一切可迭代序走镜像结构：`IdList` 链序 / `KeyedTree`（BTreeMap）键序 /
   `Vec<BlockId>` 向量序。
2. **删除保序**。`IdList::unlink`/`splice_after` 是 O(1) 链手术，与
   `std::list::erase/splice` 同构；无任何 swap-remove。
3. **gen 悬垂守卫**。`Arena::remove` 后槽 gen+1；旧句柄 `get/get_mut/contains`
   一律返回 `None`/`false`，绝不静默别名新对象。`clear` 对占用槽 gen+1，
   清空后任何历史句柄全部失效。
4. **descend/inrefs 维护纪律不可由"陈旧句柄→None"代偿**（设计 §5 R4）：
   oracle 在 op destroy 时**显式擦除** descend 条目；W1 必须逐条移植擦除位点，
   `descend_consistent` 是调试断言谓词。

## 冻结的公开 API（W1 codemod 目标）

### 1. 类型化 id（8B，= oracle 指针宽）

```rust
pub struct OpId    { /* idx: u32, gen: u32 */ }
pub struct VnId    { /* idx: u32, gen: u32 */ }
pub struct BlockId { /* idx: u32, gen: u32 */ }
pub struct HighId  { /* idx: u32, gen: u32 */ }
```

`derive(Clone, Copy, PartialEq, Eq, Hash, Debug)`。身份语义 = oracle 指针判等
（idx+gen 全等；地址复用的"伪同对象"构造性不存在）。**跨类型不互通**（newtype）。

```rust
pub trait ArenaId: Copy + Eq + Debug {
    const SENTINEL: Self;                       // idx==0：哨兵/链尾，永不出厂
    fn from_parts(idx: u32, gen: u32) -> Self;  // 仅 arena 内部 + iop 打包用
    fn idx(self) -> u32;
    fn gen(self) -> u32;
    fn is_sentinel(self) -> bool;               // idx == 0
    fn to_bits(self) -> u64;                    // iop 常量偏移打包（§2.5 编码替换）
    fn from_bits(bits: u64) -> Self;            // get_op_from_const 镜像
}
```

### 2. 槽存储 `Arena<T, Id>`

```rust
pub struct Arena<T, Id: ArenaId> { /* 私有: slots, gens, free_head, live */ }

impl<T, Id: ArenaId> Arena<T, Id> {
    pub fn new() -> Self;                       // 保留哨兵槽 0
    pub fn with_capacity(cap: usize) -> Self;
    pub fn insert(&mut self, value: T) -> Id;   // O(1)；free-list LIFO 复用（确定性）
    pub fn remove(&mut self, id: Id) -> Option<T>; // O(1)；gen+1；见红线 3
    pub fn get(&self, id: Id) -> Option<&T>;    // bounds + gen 比较（~1-2ns）
    pub fn get_mut(&mut self, id: Id) -> Option<&mut T>;
    pub fn contains(&self, id: Id) -> bool;
    pub fn len(&self) -> usize;                 // 活跃计数，非序
    pub fn is_empty(&self) -> bool;
    pub fn clear(&mut self);                    // 占用槽 gen+1 + free-list 升序重建
}
impl<T, Id: ArenaId> Default for Arena<T, Id>
```

契约：**无迭代方法**（红线 1）。`insert` 后调用方须保证元素内嵌 `Links` 为
detached（全零字段即 detached——`OpId::SENTINEL` 的 idx/gen 都是 0）。
`remove` 前必须先从所有链 unlink（删一个仍在链上的元素 = 链损坏，同 oracle
绕过 `PcodeOpBank::destroy` 直接 delete 的后果）。

### 3. 侵入式 id 双向链 `IdList<L>` + `Linked`

```rust
pub struct Links<Id: ArenaId> { pub prev: Id, pub next: Id }
impl<Id: ArenaId> Links<Id> {
    pub const fn detached() -> Self;            // prev=next=SENTINEL
    pub fn is_detached(&self) -> bool;
}

pub trait Linked {                              // 每 chain 一个零大小 marker
    type Elem;
    type Id: ArenaId;
    fn prev(e: &Self::Elem) -> Self::Id;
    fn next(e: &Self::Elem) -> Self::Id;
    fn set_prev(e: &mut Self::Elem, id: Self::Id);
    fn set_next(e: &mut Self::Elem, id: Self::Id);
}

pub struct IdList<L: Linked> { /* head, tail, len（私有） */ }
impl<L: Linked> IdList<L> {
    pub const fn new() -> Self;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn head(&self) -> Option<L::Id>;
    pub fn tail(&self) -> Option<L::Id>;
    pub fn contains(&self, arena: &Arena<L::Elem, L::Id>, id: L::Id) -> bool;
    pub fn push_back(&mut self, arena: &mut Arena<..>, id: L::Id);      // op.cc:947
    pub fn push_front(&mut self, arena: &mut Arena<..>, id: L::Id);
    pub fn insert_after(&mut self, arena: &mut Arena<..>, pos: L::Id, id: L::Id);
    pub fn insert_before(&mut self, arena: &mut Arena<..>, pos: L::Id, id: L::Id);
    pub fn unlink(&mut self, arena: &mut Arena<..>, id: L::Id);         // op.cc:1031
    pub fn splice_after(&mut self, arena: &mut Arena<..>, pos: L::Id,
                        first: L::Id, last: L::Id);                     // op.cc:1056
    pub fn clear(&mut self, arena: &mut Arena<..>);
    pub fn iter<'a>(&'a self, arena: &'a Arena<..>) -> IdListIter<'a, L>;
    pub fn iter_from<'a>(&'a self, arena: &'a Arena<..>, start: L::Id) -> IdListIter<'a, L>;
    pub fn iter_items<'a>(&'a self, arena: &'a Arena<..>)
        -> impl Iterator<Item = (&'a L::Elem, L::Id)> + 'a;
}
impl<L: Linked> Default for IdList<L>

pub struct IdListIter<'a, L: Linked> { /* .. */ }
impl Iterator for IdListIter<'_, L> { type Item = L::Id; }
impl FusedIterator for IdListIter<'_, L>
// 注意: 无 ExactSizeIterator（iter_from 的剩余数未知，不撒谎）
```

操作语义（与 `std::list` 逐一同构，全部 O(1) 除 clear O(n)）：

| 方法 | oracle 形态 | 语义契约 |
|---|---|---|
| `push_back` | `list.insert(list.end(), op)`（op.cc:947/1022/1033） | 尾插；id 须 detached |
| `push_front` | `list.push_front` | 头插 |
| `insert_after(pos, id)` | `insert(++previter, op)`（op.cc:1045-1047） | pos=SENT ⇒ 头插；pos 须为本链成员 |
| `insert_before(pos, id)` | `insert(iter, op)` | pos=SENT ⇒ 尾插（before end()） |
| `unlink(id)` | `list.erase(iter)`（op.cc:1020/1031/996/1044） | **保序删除**；id 须为本链成员；结果 detached |
| `splice_after(pos, first, last)` | `splice(previter, list, first, last+1)`（op.cc:1064） | 区间 `[first..=last]` 原样移到 pos 之后（pos=SENT ⇒ 移到头）；pos 不得在区间内；已在位 ⇒ no-op（op.cc:1063 守卫逐字保留） |
| `clear` | `list.clear()`（op.cc:929-932） | 全部摘下（各自 detached） |

**共享链字段纪律（freeze 契约核心）**：alivelist/deadlist 共用**同一** prev/next
字段（oracle 单一 `insertiter`，op.hh:128，指向当前所在链）。oracle 信任
"erase 的迭代器属于被 erase 的链"——由 bank 方法每次转移都做
erase-旧+insert-新维持。镜像侧同一纪律：**只能从实际持有元素的链 unlink**。
W1 bank 层必须在每个转移位点 debug-assert 生命周期旗标↔链一致
（如 `mark_alive` 断言 `op.is_dead()`，对应 oracle `destroy` 的
`if (!op->isDead()) throw`，op.cc:992-993 形态）。本模块的 `contains`
能精确捕捉 detached/双重 unlink（debug 断言），但无法区分"另一条共享字段的链
的成员"——与 oracle 同等信任级别，非更弱。

### 4. 树键类型（POD 投影，= 存储迭代器）

```rust
pub struct SpaceOff { pub space: u32, pub offset: u64 }   // Address::operator< 投影
// 编码: 0=null 空间(排最前), u32::MAX=~0 哨兵(排最后), 其余= AddrSpace::getIndex()+1

pub struct SeqNumKey { pub pc: SpaceOff, pub uniq: u64 }  // map<SeqNum,PcodeOp*> 键
// Ord = (pc, uniq)，order 字段不入键（address.hh:154-158 逐字）

pub enum VnDefState {                                     // 旗标投影（变体序是承重的!）
    Input,                                                // input=0x08 (varnode.hh:82)
    Written { def_pc: SpaceOff, def_uniq: u64 },          // written=0x10 (:83)，def SeqNum 反规范化
    Free { create_index: u32 },                           // free，create_index 决胜
}
impl VnDefState {
    pub fn from_flags(flags: u32, def_seq: SeqNumKey, create_index: u32) -> VnDefState;
    pub fn rank(&self) -> u8;                             // input(0) < written(1) < free(2)
}
// 变体序复刻 varnode.cc:43 的 (f-1) 无符号回绕序: input < written < free

pub struct VnLocKey { pub addr: SpaceOff, pub size: i32, pub state: VnDefState }
// Ord(derive) ≡ VarnodeCompareLocDef (varnode.cc:34-53): addr→size→旗标→
//   written:defSeq / free:createIndex

pub struct VnDefKey { pub state: VnDefState, pub addr: SpaceOff, pub size: i32 }
// Ord(手写) ≡ VarnodeCompareDefLoc (varnode.cc:60-79): 旗标→written:defSeq(相等
//   则**落到 addr**)→addr→size→free:createIndex(在 addr/size **之后**)

pub type KeyedTree<K, Id> = BTreeMap<K, Id>;              // op.hh:280 形态
```

**槽内键副本纪律**：元素存自己当前键的副本；树删除用该副本（= 存储迭代器），
键重算只允许在 oracle 擦除+重插的同一位点（`xref`/`setDef`/`setInput`/
`makeFree`）。键唯一由构造保证（def SeqNum / create_index 唯一），重复键 =
bug，debug-assert。范围查询（beginLoc/beginDef 9 重载族）用 pub 字段直接构造
前缀界（见测试 `vn_loc_range_query_prefix_pattern` 的模式）。

### 5. R4 不变式谓词

```rust
pub fn descend_consistent<TOp, TVn>(
    ops: &Arena<TOp, OpId>, vns: &Arena<TVn, VnId>, vn: VnId,
    descend: impl Fn(&TVn) -> &[OpId],
    inrefs: impl Fn(&TOp) -> &[Option<VnId>],
) -> bool;
```

vn.descend 中每个 OpId 须可解析且其 inrefs 含该 vn。W1 destroy 位点在
debug 构建调用；漏擦在 id 形态下**可见**（get→None），这是比 oracle Weak
升级失败代偿更严格的守卫。

## W1 集成契约（冻结）

1. **OpArena** = `Arena<OpData, OpId>` + 7× `IdList<InsL/BasicL/CodeL>` +
   `optree: BTreeMap<SeqNumKey, OpId>` + `uniqid: u64`。
   `OpData` 的链字段可用平面字段（`ins_prev/ins_next`）或 `Links<OpId>`
   （布局相同），`Linked` 两种都支持。
2. **VnArena** = `Arena<VnData, VnId>` + `loc_tree: KeyedTree<VnLocKey, VnId>` +
   `def_tree: KeyedTree<VnDefKey, VnId>` + `loc_key/def_key` 槽内副本字段。
3. **BlockArena/BlockGraph** = `Arena<BlockData, BlockId>` + `Vec<BlockId>`
   图向量；BlockEdge 值化 12B Copy 不进 arena（设计 D2）。
4. **iop 常量编码** = `OpId::to_bits/from_bits`（替换 `Arc::as_ptr` 编码，
   funcdata.rs:4745-4754；打包值不出现在 C 输出——与 oracle `PcodeOp*` 强转
   偏移同性质，op.hh:249）。
5. **借用模式**（设计 §3 P1-P6）：读= `fd.op(id)`（`get` + P1 固有方法）；
   分域拆借= op_arena/vn_arena/block_arena 不同字段天然可并借；同域双对象=
   W1 加 `ops_mut2(a, b)` helper（P4，split_at_mut 思路，互斥 debug 断言）。
   **禁止** RefCell/UnsafeCell/桥接 enum（设计 §3.3 否决记录）。

## 验证（W0 交付时点）

- 序语义差分单测：`list_fuzz_matches_std_list_model`（4000 随机操作 vs
  VecDeque std::list 模型逐位对照）、`opcc_lifecycle_replay`（op.cc
  create/markAlive/markDead/insertAfterDead/moveSequenceDead/destroy 脚本重放，
  手推期望序）、`opcc_lifecycle_fuzz_vs_model`（6000 随机生命周期 vs 三链模型
  + 旗标↔链一致性）、`vn_keys_differential_vs_oracle_comparator`（400 记录
  全对偶 × 两比较器 vs varnode.cc 逐字转写）、`vn_keys_btreemap_order_invariance`
  （BTreeMap 迭代序 = oracle 比较器序，插入序无关）。
- gen 悬垂守卫/哨兵槽/clear 单调性/位打包 roundtrip 单测全绿。
- 契约违反 debug 断言测试（双 unlink/重复入链/splice 位点在区间内/非连续
  区间）全绿（debug_assertions 门控）。
- microbench：`micro_arena_vs_box_arc_alloc_throughput`、
  `micro_unlink_vs_retain_markdead_form`（数字见车道终报，stderr 打印）。

## 已知限制（诚实记录）

- **gen 回绕**：单槽 2^32 次 remove+insert 后 gen 回绕到旧值（ABA 理论窗口）；
  与 slotmap crate 同级，实际不可达（oracle 裸指针形态下同类窗口为 UB 邻域）。
- **跨链误用**：unlink 到不持有元素的共享字段链，debug 断言不可见（见共享
  链字段纪律）；由 W1 生命周期旗标断言守卫（= oracle insertiter 纪律机器化）。
- **`SpaceOff::from_space_index(u32::MAX-1, _)`** 与 upper_sentinel 编码冲突
  （真实 AddrSpace index 是小整数，实际不可达；W1 投影函数内 debug-assert）。
